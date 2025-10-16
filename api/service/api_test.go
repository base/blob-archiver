package service

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/attestantio/go-eth2-client/api"
	v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/base/blob-archiver/api/metrics"
	"github.com/base/blob-archiver/common/beacon/beacontest"
	"github.com/base/blob-archiver/common/blobtest"
	"github.com/base/blob-archiver/common/storage"
	"github.com/ethereum-optimism/optimism/op-service/eth"
	"github.com/ethereum-optimism/optimism/op-service/testlog"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto/kzg4844"
	"github.com/ethereum/go-ethereum/log"
	"github.com/stretchr/testify/require"
)

func TestIsHash(t *testing.T) {
	require.True(t, isHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"))
	// Invalid hex character, ending with z
	require.False(t, isHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdez"))
	// Missing 0x prefix
	require.False(t, isHash("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"))

	require.False(t, isHash("genesis"))
	require.False(t, isHash("finalized"))
	require.False(t, isHash("123"))     // slot
	require.False(t, isHash("unknown")) // incorrect input
}

func TestIsSlot(t *testing.T) {
	require.True(t, isSlot("123"))
	require.False(t, isSlot("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"))
	require.False(t, isSlot("genesis"))
	require.False(t, isSlot("finalized"))
	require.False(t, isSlot("unknown"))
}

func TestIsNamedIdentifier(t *testing.T) {
	require.True(t, isKnownIdentifier("genesis"))
	require.True(t, isKnownIdentifier("finalized"))
	require.False(t, isKnownIdentifier("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"))
	require.False(t, isKnownIdentifier("123"))
	require.False(t, isKnownIdentifier("unknown"))
}

func setup(t *testing.T) (*API, *storage.FileStorage, *beacontest.StubBeaconClient, func()) {
	logger := testlog.Logger(t, log.LvlInfo)
	tempDir, err := os.MkdirTemp("", "test")
	require.NoError(t, err)
	fs := storage.NewFileStorage(tempDir, logger)
	beacon := beacontest.NewEmptyStubBeaconClient()
	m := metrics.NewMetrics()
	a := NewAPI(fs, beacon, m, logger)
	return a, fs, beacon, func() {
		require.NoError(t, os.RemoveAll(tempDir))
	}
}

func TestAPIService(t *testing.T) {
	a, fs, beaconClient, cleanup := setup(t)
	defer cleanup()

	rootOne := common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
	rootTwo := common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890222222")
	rootThree := common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890333333")

	blockOne := storage.BlobData{
		Header: storage.Header{
			BeaconBlockHash: rootOne,
		},
		BlobSidecars: storage.BlobSidecars{
			Data: blobtest.NewBlobSidecars(t, 2, nil),
		},
	}

	blockTwo := storage.BlobData{
		Header: storage.Header{
			BeaconBlockHash: rootTwo,
		},
		BlobSidecars: storage.BlobSidecars{
			Data: blobtest.NewBlobSidecars(t, 2, nil),
		},
	}

	// Pectra Block
	blockThree := storage.BlobData{
		Header: storage.Header{
			BeaconBlockHash: rootThree,
		},
		BlobSidecars: storage.BlobSidecars{
			Data: blobtest.NewBlobSidecars(t, 8, nil), // More than 6 blobs
		},
	}

	err := fs.WriteBlob(context.Background(), blockOne)
	require.NoError(t, err)

	err = fs.WriteBlob(context.Background(), blockTwo)
	require.NoError(t, err)

	err = fs.WriteBlob(context.Background(), blockThree)
	require.NoError(t, err)

	beaconClient.Headers["finalized"] = &v1.BeaconBlockHeader{
		Root: phase0.Root(rootOne),
	}

	beaconClient.Headers["head"] = &v1.BeaconBlockHeader{
		Root: phase0.Root(rootTwo),
	}

	beaconClient.Headers["1234"] = &v1.BeaconBlockHeader{
		Root: phase0.Root(rootTwo),
	}

	tests := []struct {
		name       string
		path       string
		status     int
		expected   *storage.BlobSidecars
		errMessage string
	}{
		{
			name:     "fetch root one",
			path:     fmt.Sprintf("/eth/v1/beacon/blob_sidecars/%s", rootOne),
			status:   200,
			expected: &blockOne.BlobSidecars,
		},
		{
			name:     "fetch root two",
			path:     fmt.Sprintf("/eth/v1/beacon/blob_sidecars/%s", rootTwo),
			status:   200,
			expected: &blockTwo.BlobSidecars,
		},
		{
			name:       "fetch unknown",
			path:       "/eth/v1/beacon/blob_sidecars/0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abc111",
			status:     404,
			errMessage: "Block not found",
		},
		{
			name:     "fetch head",
			path:     "/eth/v1/beacon/blob_sidecars/head",
			status:   200,
			expected: &blockTwo.BlobSidecars,
		},
		{
			name:     "fetch finalized",
			path:     "/eth/v1/beacon/blob_sidecars/finalized",
			status:   200,
			expected: &blockOne.BlobSidecars,
		},
		{
			name:     "fetch slot 1234",
			path:     "/eth/v1/beacon/blob_sidecars/1234",
			status:   200,
			expected: &blockTwo.BlobSidecars,
		},
		{
			name:   "indices only returns requested indices",
			path:   "/eth/v1/beacon/blob_sidecars/1234?indices=1",
			status: 200,
			expected: &storage.BlobSidecars{
				Data: []*deneb.BlobSidecar{
					blockTwo.BlobSidecars.Data[1],
				},
			},
		},
		{
			name:   "deduplicates indices",
			path:   "/eth/v1/beacon/blob_sidecars/1234?indices=1,1,1",
			status: 200,
			expected: &storage.BlobSidecars{
				Data: []*deneb.BlobSidecar{
					blockTwo.BlobSidecars.Data[1],
				},
			},
		},
		{
			name:   "multi indices",
			path:   "/eth/v1/beacon/blob_sidecars/1234?indices=0&indices=1",
			status: 200,
			expected: &storage.BlobSidecars{
				Data: blockTwo.BlobSidecars.Data,
			},
		},
		{
			name:   "multi indices comma separated list",
			path:   "/eth/v1/beacon/blob_sidecars/1234?indices=0,1",
			status: 200,
			expected: &storage.BlobSidecars{
				Data: blockTwo.BlobSidecars.Data,
			},
		},
		{
			name:       "only index out of bounds returns empty array",
			path:       "/eth/v1/beacon/blob_sidecars/1234?indices=3",
			status:     400,
			errMessage: "invalid index: 3 block contains 2 blobs",
		},
		{
			name:       "any index out of bounds returns error",
			path:       "/eth/v1/beacon/blob_sidecars/1234?indices=1,10",
			status:     400,
			errMessage: "invalid index: 10 block contains 2 blobs",
		},
		{
			name:       "only index out of bounds (boundary condition) returns error",
			path:       "/eth/v1/beacon/blob_sidecars/1234?indices=2",
			status:     400,
			errMessage: "invalid index: 2 block contains 2 blobs",
		},
		{
			name:       "negative index returns error",
			path:       "/eth/v1/beacon/blob_sidecars/1234?indices=-2",
			status:     400,
			errMessage: "invalid index input: -2",
		},
		{
			name:       "no 0x on hash",
			path:       "/eth/v1/beacon/blob_sidecars/1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			status:     400,
			errMessage: "invalid block id: 1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
		},
		{
			name:       "invalid hash",
			path:       "/eth/v1/beacon/blob_sidecars/0x1234567890abcdef123",
			status:     400,
			errMessage: "invalid block id: 0x1234567890abcdef123",
		},
		{
			name:       "invalid named identifier",
			path:       "/eth/v1/beacon/blob_sidecars/foobar",
			status:     400,
			errMessage: "invalid block id: foobar",
		},
		{
			name:   "invalid no parameter specified",
			path:   "/eth/v1/beacon/blob_sidecars/",
			status: 404,
		},
		{
			name:   "unknown route",
			path:   "/eth/v1/",
			status: 404,
		},
		{
			name:   "pectra: query all blobs",
			path:   fmt.Sprintf("/eth/v1/beacon/blob_sidecars/%s", rootThree),
			status: 200,
			expected: &storage.BlobSidecars{
				Data: blockThree.BlobSidecars.Data,
			},
		},
		{
			name:   "pectra: query blob greater than 6",
			path:   fmt.Sprintf("/eth/v1/beacon/blob_sidecars/%s?indices=7", rootThree),
			status: 200,
			expected: &storage.BlobSidecars{
				Data: []*deneb.BlobSidecar{
					blockThree.BlobSidecars.Data[7],
				},
			},
		},
	}

	responseFormat := []string{"application/json", "application/octet-stream"}

	for _, test := range tests {
		for _, rf := range responseFormat {
			for _, compress := range []bool{true, false} {
				testName := fmt.Sprintf("%s-%s", test.name, rf)
				if compress {
					testName = fmt.Sprintf("%s-%s", testName, "gzip")
				}

				t.Run(testName, func(t *testing.T) {
					request := httptest.NewRequest("GET", test.path, nil)
					request.Header.Set("Accept", rf)

					if compress {
						request.Header.Set("Accept-Encoding", "gzip")
					}

					response := httptest.NewRecorder()

					a.router.ServeHTTP(response, request)

					require.Equal(t, test.status, response.Code)

					if test.status == 200 && test.expected != nil {
						var data []byte
						if compress {
							reader, err := gzip.NewReader(response.Body)
							require.NoError(t, err)

							data, err = io.ReadAll(reader)
							require.NoError(t, err)
						} else {
							data = response.Body.Bytes()
						}

						blobSidecars := storage.BlobSidecars{}

						if rf == "application/octet-stream" {
							res := api.BlobSidecars{}
							err = res.UnmarshalSSZ(data)
							blobSidecars.Data = res.Sidecars
						} else {
							err = json.Unmarshal(data, &blobSidecars)
						}

						require.NoError(t, err)
						require.Equal(t, *test.expected, blobSidecars)
					} else if test.status != 200 && rf == "application/json" && test.errMessage != "" {
						var e httpError
						err := json.Unmarshal(response.Body.Bytes(), &e)
						require.NoError(t, err)
						require.Equal(t, test.status, e.Code)
						require.Equal(t, test.errMessage, e.Message)
					}
				})
			}
		}
	}
}

func TestVersionHandler(t *testing.T) {
	a, _, _, cleanup := setup(t)
	defer cleanup()

	request := httptest.NewRequest("GET", "/eth/v1/node/version", nil)
	response := httptest.NewRecorder()

	a.router.ServeHTTP(response, request)

	require.Equal(t, 200, response.Code)
	require.Equal(t, "application/json", response.Header().Get("Content-Type"))
	var v eth.APIVersionResponse
	err := json.Unmarshal(response.Body.Bytes(), &v)
	require.NoError(t, err)
	require.Equal(t, "Blob Archiver API/unknown", v.Data.Version)
}

func TestHealthHandler(t *testing.T) {
	a, _, _, cleanup := setup(t)
	defer cleanup()

	request := httptest.NewRequest("GET", "/healthz", nil)
	response := httptest.NewRecorder()

	a.router.ServeHTTP(response, request)

	require.Equal(t, 200, response.Code)
}

func TestBlobsHandlerJSON(t *testing.T) {
	a, fs, _, cleanup := setup(t)
	defer cleanup()

	// Pre-populate storage with blob sidecars
	testBlobs := blobtest.NewBlobSidecars(t, 3, nil)
	data := storage.BlobData{
		Header: storage.Header{
			BeaconBlockHash: blobtest.Five,
		},
		BlobSidecars: storage.BlobSidecars{
			Data: testBlobs,
		},
	}
	err := fs.WriteBlob(context.Background(), data)
	require.NoError(t, err)

	// Request blobs endpoint with JSON encoding
	request := httptest.NewRequest("GET", "/eth/v1/beacon/blobs/"+blobtest.Five.String(), nil)
	request.Header.Set("Accept", "application/json")
	response := httptest.NewRecorder()

	a.router.ServeHTTP(response, request)

	require.Equal(t, 200, response.Code)
	require.Equal(t, "application/json", response.Header().Get("Content-Type"))

	var blobs v1.Blobs
	err = json.Unmarshal(response.Body.Bytes(), &blobs)
	require.NoError(t, err)
	require.Equal(t, len(testBlobs), len(blobs))

	// Verify blob data matches
	for i, blob := range blobs {
		require.Equal(t, testBlobs[i].Blob, *blob)
	}
}

func TestBlobsHandlerSSZ(t *testing.T) {
	a, fs, _, cleanup := setup(t)
	defer cleanup()

	// Pre-populate storage with blob sidecars
	testBlobs := blobtest.NewBlobSidecars(t, 2, nil)
	data := storage.BlobData{
		Header: storage.Header{
			BeaconBlockHash: blobtest.One,
		},
		BlobSidecars: storage.BlobSidecars{
			Data: testBlobs,
		},
	}
	err := fs.WriteBlob(context.Background(), data)
	require.NoError(t, err)

	// Request blobs endpoint with SSZ encoding
	request := httptest.NewRequest("GET", "/eth/v1/beacon/blobs/"+blobtest.One.String(), nil)
	request.Header.Set("Accept", "application/octet-stream")
	response := httptest.NewRecorder()

	a.router.ServeHTTP(response, request)

	require.Equal(t, 200, response.Code)
	require.Equal(t, "application/octet-stream", response.Header().Get("Content-Type"))

	// Unmarshal SSZ response
	blobs := v1.Blobs{}
	err = blobs.UnmarshalSSZ(response.Body.Bytes())
	require.NoError(t, err)
	require.Equal(t, len(testBlobs), len(blobs))
}

func TestBlobsHandlerWithVersionedHashes(t *testing.T) {
	a, fs, _, cleanup := setup(t)
	defer cleanup()

	// Pre-populate storage with blob sidecars
	testBlobs := blobtest.NewBlobSidecars(t, 5, nil)
	data := storage.BlobData{
		Header: storage.Header{
			BeaconBlockHash: blobtest.Four,
		},
		BlobSidecars: storage.BlobSidecars{
			Data: testBlobs,
		},
	}
	err := fs.WriteBlob(context.Background(), data)
	require.NoError(t, err)

	// Compute versioned hashes from commitments
	hasher := sha256.New()
	commitment0 := kzg4844.Commitment(testBlobs[0].KZGCommitment)
	vh0 := kzg4844.CalcBlobHashV1(hasher, &commitment0)

	hasher.Reset()
	commitment2 := kzg4844.Commitment(testBlobs[2].KZGCommitment)
	vh2 := kzg4844.CalcBlobHashV1(hasher, &commitment2)

	// Request blobs endpoint with versioned_hashes filter
	request := httptest.NewRequest("GET", fmt.Sprintf("/eth/v1/beacon/blobs/%s?versioned_hashes=%s&versioned_hashes=%s", blobtest.Four.String(), common.Hash(vh0).Hex(), common.Hash(vh2).Hex()), nil)
	request.Header.Set("Accept", "application/json")
	response := httptest.NewRecorder()

	a.router.ServeHTTP(response, request)

	require.Equal(t, 200, response.Code)

	var blobs v1.Blobs
	err = json.Unmarshal(response.Body.Bytes(), &blobs)
	require.NoError(t, err)
	require.Equal(t, 2, len(blobs))
}

func TestBlobsHandlerNotFound(t *testing.T) {
	a, _, _, cleanup := setup(t)
	defer cleanup()

	// Request blobs endpoint for non-existent block
	request := httptest.NewRequest("GET", "/eth/v1/beacon/blobs/"+blobtest.Seven.String(), nil)
	request.Header.Set("Accept", "application/json")
	response := httptest.NewRecorder()

	a.router.ServeHTTP(response, request)

	require.Equal(t, 404, response.Code)
}
