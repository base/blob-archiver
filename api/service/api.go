package service

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	m "github.com/base/blob-archiver/api/metrics"
	"github.com/base/blob-archiver/api/version"
	"github.com/base/blob-archiver/common/storage"
	opmetrics "github.com/ethereum-optimism/optimism/op-service/metrics"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto/kzg4844"
	"github.com/ethereum/go-ethereum/log"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

type httpError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e httpError) write(w http.ResponseWriter) {
	w.WriteHeader(e.Code)
	_ = json.NewEncoder(w).Encode(e)
}

func (e httpError) Error() string {
	return e.Message
}

const (
	jsonAcceptType = "application/json"
	sszAcceptType  = "application/octet-stream"
	serverTimeout  = 60 * time.Second
)

var (
	errUnknownBlock = &httpError{
		Code:    http.StatusNotFound,
		Message: "Block not found",
	}
	errServerError = &httpError{
		Code:    http.StatusInternalServerError,
		Message: "Internal server error",
	}
)

func newBlockIdError(input string) *httpError {
	return &httpError{
		Code:    http.StatusBadRequest,
		Message: fmt.Sprintf("invalid block id: %s", input),
	}
}

func newIndicesError(input string) *httpError {
	return &httpError{
		Code:    http.StatusBadRequest,
		Message: fmt.Sprintf("invalid index input: %s", input),
	}
}

func newOutOfRangeError(input uint64, blobCount int) *httpError {
	return &httpError{
		Code:    http.StatusBadRequest,
		Message: fmt.Sprintf("invalid index: %d block contains %d blobs", input, blobCount),
	}
}

type API struct {
	dataStoreClient storage.DataStoreReader
	beaconClient    client.BeaconBlockHeadersProvider
	router          *chi.Mux
	logger          log.Logger
	metrics         m.Metricer
}

func NewAPI(dataStoreClient storage.DataStoreReader, beaconClient client.BeaconBlockHeadersProvider, metrics m.Metricer, logger log.Logger) *API {
	result := &API{
		dataStoreClient: dataStoreClient,
		beaconClient:    beaconClient,
		router:          chi.NewRouter(),
		logger:          logger,
		metrics:         metrics,
	}

	r := result.router
	r.Use(middleware.Logger)
	r.Use(middleware.Timeout(serverTimeout))
	r.Use(middleware.Recoverer)
	r.Use(middleware.Heartbeat("/healthz"))
	r.Use(middleware.Compress(5, jsonAcceptType, sszAcceptType))

	recorder := opmetrics.NewPromHTTPRecorder(metrics.Registry(), m.MetricsNamespace)
	r.Use(func(handler http.Handler) http.Handler {
		return opmetrics.NewHTTPRecordingMiddleware(recorder, handler)
	})

	r.Get("/eth/v1/beacon/blob_sidecars/{id}", result.blobSidecarHandler)
	r.Get("/eth/v1/beacon/blobs/{id}", result.blobsHandler)
	r.Get("/eth/v1/node/version", result.versionHandler)

	return result
}

func isHash(s string) bool {
	if len(s) != 66 || !strings.HasPrefix(s, "0x") {
		return false
	}

	_, err := hexutil.Decode(s)
	return err == nil
}

func isSlot(id string) bool {
	_, err := strconv.ParseUint(id, 10, 64)
	return err == nil
}

func isKnownIdentifier(id string) bool {
	return slices.Contains([]string{"genesis", "finalized", "head"}, id)
}

// versionHandler implements the /eth/v1/node/version endpoint.
func (a *API) versionHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", jsonAcceptType)
	w.WriteHeader(http.StatusOK)
	err := json.NewEncoder(w).Encode(version.APIVersion)
	if err != nil {
		a.logger.Error("unable to encode version to JSON", "err", err)
		errServerError.write(w)
	}
}

// toBeaconBlockHash converts a string that can be a slot, hash or identifier to a beacon block hash.
func (a *API) toBeaconBlockHash(id string) (common.Hash, *httpError) {
	if isHash(id) {
		a.metrics.RecordBlockIdType(m.BlockIdTypeHash)
		return common.HexToHash(id), nil
	} else if isSlot(id) || isKnownIdentifier(id) {
		a.metrics.RecordBlockIdType(m.BlockIdTypeBeacon)
		result, err := a.beaconClient.BeaconBlockHeader(context.Background(), &api.BeaconBlockHeaderOpts{
			Common: api.CommonOpts{},
			Block:  id,
		})

		if err != nil {
			var apiErr *api.Error
			if errors.As(err, &apiErr) && apiErr.StatusCode == 404 {
				return common.Hash{}, errUnknownBlock
			}

			return common.Hash{}, errServerError
		}

		return common.Hash(result.Data.Root), nil
	} else {
		a.metrics.RecordBlockIdType(m.BlockIdTypeInvalid)
		return common.Hash{}, newBlockIdError(id)
	}
}

// blobSidecarHandler implements the /eth/v1/beacon/blob_sidecars/{id} endpoint, using the underlying DataStoreReader
// to fetch blobs instead of the beacon node. This allows clients to fetch expired blobs.
func (a *API) blobSidecarHandler(w http.ResponseWriter, r *http.Request) {
	param := chi.URLParam(r, "id")
	beaconBlockHash, err := a.toBeaconBlockHash(param)
	if err != nil {
		err.write(w)
		return
	}

	result, storageErr := a.dataStoreClient.ReadBlob(r.Context(), beaconBlockHash)
	if storageErr != nil {
		if errors.Is(storageErr, storage.ErrNotFound) {
			errUnknownBlock.write(w)
		} else {
			a.logger.Info("unexpected error fetching blobs", "err", storageErr, "beaconBlockHash", beaconBlockHash.String(), "param", param)
			errServerError.write(w)
		}
		return
	}

	blobSidecars := result.BlobSidecars

	filteredBlobSidecars, err := filterBlobs(blobSidecars.Data, r.URL.Query()["indices"])
	if err != nil {
		err.write(w)
		return
	}

	blobSidecars.Data = filteredBlobSidecars
	responseType := r.Header.Get("Accept")

	if responseType == sszAcceptType {
		w.Header().Set("Content-Type", sszAcceptType)
		res, err := blobSidecars.MarshalSSZ()
		if err != nil {
			a.logger.Error("unable to marshal blob sidecars to SSZ", "err", err)
			errServerError.write(w)
			return
		}

		_, err = w.Write(res)

		if err != nil {
			a.logger.Error("unable to write ssz response", "err", err)
			errServerError.write(w)
			return
		}
	} else {
		w.Header().Set("Content-Type", jsonAcceptType)
		err := json.NewEncoder(w).Encode(blobSidecars)
		if err != nil {
			a.logger.Error("unable to encode blob sidecars to JSON", "err", err)
			errServerError.write(w)
			return
		}
	}
}

// filterBlobs filters the blobs based on the indices query provided.
// If no indices are provided, all blobs are returned. If invalid indices are provided, an error is returned.
func filterBlobs(blobs []*deneb.BlobSidecar, _indices []string) ([]*deneb.BlobSidecar, *httpError) {
	var indices []string
	if len(_indices) == 0 {
		return blobs, nil
	} else if len(_indices) == 1 {
		indices = strings.Split(_indices[0], ",")
	} else {
		indices = _indices
	}

	indicesMap := map[deneb.BlobIndex]struct{}{}
	for _, index := range indices {
		parsedInt, err := strconv.ParseUint(index, 10, 64)
		if err != nil {
			return nil, newIndicesError(index)
		}

		if parsedInt >= uint64(len(blobs)) {
			return nil, newOutOfRangeError(parsedInt, len(blobs))
		}

		blobIndex := deneb.BlobIndex(parsedInt)
		indicesMap[blobIndex] = struct{}{}
	}

	filteredBlobs := make([]*deneb.BlobSidecar, 0)
	for _, blob := range blobs {
		if _, ok := indicesMap[blob.Index]; ok {
			filteredBlobs = append(filteredBlobs, blob)
		}
	}

	return filteredBlobs, nil
}

// filterBlobsByVersionedHashes filters sidecars by versioned hashes query parameter.
// Returns the filtered sidecars in the order they were requested, or all sidecars if no hashes provided.
func filterBlobsByVersionedHashes(sidecars []*deneb.BlobSidecar, _versionedHashes []string) ([]*deneb.BlobSidecar, *httpError) {
	var versionedHashes []string
	if len(_versionedHashes) == 0 {
		return sidecars, nil
	} else if len(_versionedHashes) == 1 {
		versionedHashes = strings.Split(_versionedHashes[0], ",")
	} else {
		versionedHashes = _versionedHashes
	}

	// Build map of commitment hash -> sidecar for quick lookup
	// CalcBlobHashV1 requires a sha256 hasher instance
	hasher := sha256.New()
	hashToSidecar := make(map[[32]byte]*deneb.BlobSidecar)
	for _, sidecar := range sidecars {
		hasher.Reset()
		commitment := kzg4844.Commitment(sidecar.KZGCommitment)
		vh := kzg4844.CalcBlobHashV1(hasher, &commitment)
		hashToSidecar[vh] = sidecar
	}

	// Return sidecars in the order of requested hashes
	filteredBlobs := make([]*deneb.BlobSidecar, 0, len(versionedHashes))
	for _, hashStr := range versionedHashes {
		hash := common.HexToHash(hashStr)
		var versionedHash [32]byte
		copy(versionedHash[:], hash[:])

		if sidecar, ok := hashToSidecar[versionedHash]; ok {
			filteredBlobs = append(filteredBlobs, sidecar)
		}
	}

	return filteredBlobs, nil
}

// sidecarsToBlobs converts blob sidecars to a Blobs response by extracting only the blob data
func sidecarsToBlobs(sidecars []*deneb.BlobSidecar) v1.Blobs {
	blobs := make(v1.Blobs, len(sidecars))
	for i, sidecar := range sidecars {
		blobs[i] = &sidecar.Blob
	}
	return blobs
}

// blobsHandler implements the /eth/v1/beacon/blobs/{id} endpoint, using the underlying DataStoreReader
// to fetch blobs instead of the beacon node. This endpoint serves blobs without KZG proofs.
// Filtering by versioned_hashes query parameter is supported (per EIP-4844).
func (a *API) blobsHandler(w http.ResponseWriter, r *http.Request) {
	param := chi.URLParam(r, "id")
	beaconBlockHash, err := a.toBeaconBlockHash(param)
	if err != nil {
		err.write(w)
		return
	}

	result, storageErr := a.dataStoreClient.ReadBlob(r.Context(), beaconBlockHash)
	if storageErr != nil {
		if errors.Is(storageErr, storage.ErrNotFound) {
			errUnknownBlock.write(w)
		} else {
			a.logger.Info("unexpected error fetching blobs", "err", storageErr, "beaconBlockHash", beaconBlockHash.String(), "param", param)
			errServerError.write(w)
		}
		return
	}

	sidecars := result.BlobSidecars.Data

	// Filter by versioned_hashes query parameter (not indices)
	filteredSidecars, err := filterBlobsByVersionedHashes(sidecars, r.URL.Query()["versioned_hashes"])
	if err != nil {
		err.write(w)
		return
	}

	// Convert sidecars to blobs
	blobs := sidecarsToBlobs(filteredSidecars)
	responseType := r.Header.Get("Accept")

	if responseType == sszAcceptType {
		w.Header().Set("Content-Type", sszAcceptType)
		res, err := blobs.MarshalSSZ()
		if err != nil {
			a.logger.Error("unable to marshal blobs to SSZ", "err", err)
			errServerError.write(w)
			return
		}

		_, err = w.Write(res)

		if err != nil {
			a.logger.Error("unable to write ssz response", "err", err)
			errServerError.write(w)
			return
		}
	} else {
		w.Header().Set("Content-Type", jsonAcceptType)
		err := json.NewEncoder(w).Encode(blobs)
		if err != nil {
			a.logger.Error("unable to encode blobs to JSON", "err", err)
			errServerError.write(w)
			return
		}
	}
}
