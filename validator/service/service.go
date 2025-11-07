package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"sync/atomic"

	client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/base/blob-archiver/common/storage"
	"github.com/base/blob-archiver/validator/flags"
	gokzg4844 "github.com/crate-crypto/go-kzg-4844"
	"github.com/ethereum-optimism/optimism/op-service/retry"
	"github.com/ethereum/go-ethereum/log"
)

var ErrAlreadyStopped = errors.New("already stopped")

const (
	// finalized l1 offset
	finalizedL1Offset = 64
	// Known log for any validation errors
	validationErrorLog = "validation error"
	// Number of attempts to fetch blobs from blob-api and beacon-node
	retryAttempts = 10
)

var (
	formatSettingToHeader = map[string]Format{
		"json": FormatJson,
		"ssz":  FormatSSZ,
	}
)

func NewValidator(l log.Logger, headerClient client.BeaconBlockHeadersProvider, beaconAPI BlobSidecarClient, blobAPI BlobSidecarClient, app context.CancelCauseFunc, cfg flags.ValidatorConfig) *ValidatorService {
	return &ValidatorService{
		log:          l,
		headerClient: headerClient,
		beaconAPI:    beaconAPI,
		blobAPI:      blobAPI,
		closeApp:     app,
		cfg:          cfg,
	}
}

type ValidatorService struct {
	stopped      atomic.Bool
	log          log.Logger
	headerClient client.BeaconBlockHeadersProvider
	beaconAPI    BlobSidecarClient
	blobAPI      BlobSidecarClient
	closeApp     context.CancelCauseFunc
	cfg          flags.ValidatorConfig
}

// Start starts the validator service. This will fetch the current range of blocks to validate and start the validation
// process.
func (a *ValidatorService) Start(ctx context.Context) error {
	header, err := retry.Do(ctx, retryAttempts, retry.Exponential(), func() (*api.Response[*v1.BeaconBlockHeader], error) {
		return a.headerClient.BeaconBlockHeader(ctx, &api.BeaconBlockHeaderOpts{
			Block: "head",
		})
	})

	if err != nil {
		return fmt.Errorf("failed to get beacon block header: %w", err)
	}

	end := header.Data.Header.Message.Slot - finalizedL1Offset
	start := end - phase0.Slot(a.cfg.NumBlocks)

	go a.checkBlobs(ctx, start, end)

	return nil
}

// Stops the validator service.
func (a *ValidatorService) Stop(ctx context.Context) error {
	if a.stopped.Load() {
		return ErrAlreadyStopped
	}

	a.log.Info("Stopping validator")
	a.stopped.Store(true)

	return nil
}

func (a *ValidatorService) Stopped() bool {
	return a.stopped.Load()
}

// CheckBlobResult contains the summary of the blob checks
type CheckBlobResult struct {
	// ErrorFetching contains the list of slots for which the blob-api or beacon-node returned an error
	ErrorFetching []string
	// MismatchedStatus contains the list of slots for which the status code from the blob-api and beacon-node did not match
	MismatchedStatus []string
	// MismatchedData contains the list of slots for which the data from the blob-api and beacon-node did not match
	MismatchedData []string
}

// shouldRetry returns true if the status code is one of the retryable status codes
func shouldRetry(status int) bool {
	switch status {
	case http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout, http.StatusTooManyRequests:
		return true
	default:
		return false
	}
}

// verifyKZGProofs validates that the KZG proofs in the blob sidecars are valid for the blob data.
// Returns nil if all proofs are valid, error otherwise.
func verifyKZGProofs(sidecars []*deneb.BlobSidecar) error {
	kzgCtx, err := gokzg4844.NewContext4096Secure()
	if err != nil {
		return fmt.Errorf("failed to create KZG context: %w", err)
	}

	for i, sidecar := range sidecars {
		kzgBlob := (*gokzg4844.Blob)(&sidecar.Blob)
		commitment := gokzg4844.KZGCommitment(sidecar.KZGCommitment)
		proof := gokzg4844.KZGProof(sidecar.KZGProof)

		// Verify the KZG proof - returns error if invalid
		err := kzgCtx.VerifyBlobKZGProof(kzgBlob, commitment, proof)
		if err != nil {
			return fmt.Errorf("KZG proof verification failed for sidecar %d: %w", i, err)
		}
	}

	return nil
}

// fetchWithRetries fetches the sidecar and handles retryable error cases (5xx status codes + 429 + connection errors)
func fetchWithRetries(ctx context.Context, endpoint BlobSidecarClient, id string, format Format) (int, storage.BlobSidecars, error) {
	return retry.Do2(ctx, retryAttempts, retry.Exponential(), func() (int, storage.BlobSidecars, error) {
		status, resp, err := endpoint.FetchSidecars(id, format)

		if err == nil && status != http.StatusOK && shouldRetry(status) {
			err = fmt.Errorf("retryable status code: %d", status)
		}

		return status, resp, err
	})
}

// checkBlobs iterates all blocks in the range start:end and checks that the blobs from the beacon-node and blob-api
// are identical, when encoded in both JSON and SSZ.
func (a *ValidatorService) checkBlobs(ctx context.Context, start phase0.Slot, end phase0.Slot) CheckBlobResult {
	var result CheckBlobResult

	for slot := start; slot <= end; slot++ {
		for _, setting := range a.cfg.ValidateFormats {
			format := formatSettingToHeader[setting]

			id := strconv.FormatUint(uint64(slot), 10)

			l := a.log.New("format", format, "slot", slot)

			blobStatus, blobResponse, blobError := fetchWithRetries(ctx, a.blobAPI, id, format)

			if blobError != nil {
				result.ErrorFetching = append(result.ErrorFetching, id)
				l.Error(validationErrorLog, "reason", "error-blob-api", "error", blobError, "status", blobStatus)
				continue
			}

			beaconStatus, beaconResponse, beaconErr := fetchWithRetries(ctx, a.beaconAPI, id, format)

			if beaconErr != nil {
				result.ErrorFetching = append(result.ErrorFetching, id)
				l.Error(validationErrorLog, "reason", "error-beacon-api", "error", beaconErr, "status", beaconStatus)
				continue
			}

			if beaconStatus != blobStatus {
				result.MismatchedStatus = append(result.MismatchedStatus, id)
				l.Error(validationErrorLog, "reason", "status-code-mismatch", "beaconStatus", beaconStatus, "blobStatus", blobStatus)
				continue
			}

			if beaconStatus != http.StatusOK {
				// This can happen if the slot has been missed
				l.Info("matching error status", "beaconStatus", beaconStatus, "blobStatus", blobStatus)
				continue

			}

			if !reflect.DeepEqual(beaconResponse, blobResponse) {
				// Data mismatch detected - first check if sidecar counts match
				if len(beaconResponse.Data) != len(blobResponse.Data) {
					// Different number of sidecars - this is a real error
					result.MismatchedData = append(result.MismatchedData, id)
					l.Error(validationErrorLog, "reason", "response-mismatch", "beaconCount", len(beaconResponse.Data), "blobApiCount", len(blobResponse.Data))
					continue
				}

				// Same number of sidecars - verify if the blob API's KZG proofs are valid
				// This handles cases where the beacon node returns zeroed out KZG proofs post-Fulu
				if err := verifyKZGProofs(blobResponse.Data); err != nil {
					// Blob API has invalid KZG proofs - this is a real error
					result.MismatchedData = append(result.MismatchedData, id)
					l.Error(validationErrorLog, "reason", "response-mismatch", "kzgVerification", "failed", "error", err)
				} else {
					// Blob API's KZG proofs are valid - now check if only KZG fields differ
					// Create a copy of blobResponse with beacon's KZG proofs
					normalizedBlobResponse := storage.BlobSidecars{Data: make([]*deneb.BlobSidecar, len(blobResponse.Data))}
					for i, sidecar := range blobResponse.Data {
						normalized := *sidecar // shallow copy
						// Copy KZG fields from beacon response
						normalized.KZGProof = beaconResponse.Data[i].KZGProof
						normalized.KZGCommitment = beaconResponse.Data[i].KZGCommitment
						normalized.KZGCommitmentInclusionProof = beaconResponse.Data[i].KZGCommitmentInclusionProof
						normalizedBlobResponse.Data[i] = &normalized
					}

					// Compare again with normalized KZG values
					if !reflect.DeepEqual(beaconResponse, normalizedBlobResponse) {
						// Other fields differ - this is a real error
						result.MismatchedData = append(result.MismatchedData, id)
						l.Error(validationErrorLog, "reason", "response-mismatch", "kzgVerification", "passed", "note", "blob data differs beyond KZG fields")
					}
				}
			} else {
				l.Info("completed blob check", "blobs", len(beaconResponse.Data))
			}
		}

		// Check if we should stop validation otherwise continue
		select {
		case <-ctx.Done():
			return result
		default:
			continue
		}
	}

	// Validation is complete, shutdown the app
	a.closeApp(nil)

	return result
}
