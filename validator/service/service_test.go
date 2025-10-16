package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"testing"

	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/base/blob-archiver/common/beacon/beacontest"
	"github.com/base/blob-archiver/common/blobtest"
	"github.com/base/blob-archiver/common/storage"
	"github.com/base/blob-archiver/validator/flags"
	"github.com/ethereum-optimism/optimism/op-service/testlog"
	"github.com/ethereum/go-ethereum/log"
	"github.com/stretchr/testify/require"
)

var (
	blockOne = strconv.FormatUint(blobtest.StartSlot+1, 10)
)

type response struct {
	data       storage.BlobSidecars
	err        error
	statusCode int
}

type stubBlobSidecarClient struct {
	data map[string]response
}

// setResponses configures the stub to return the same data as the beacon client for all FetchSidecars invocations
func (s *stubBlobSidecarClient) setResponses(sbc *beacontest.StubBeaconClient) {
	for k, v := range sbc.SidecarsByBlock {
		s.data[k] = response{
			data:       storage.BlobSidecars{Data: v},
			err:        nil,
			statusCode: 200,
		}
	}
}

// setResponse overrides a single FetchSidecars response
func (s *stubBlobSidecarClient) setResponse(id string, statusCode int, data storage.BlobSidecars, err error) {
	s.data[id] = response{
		data:       data,
		err:        err,
		statusCode: statusCode,
	}
}

func (s *stubBlobSidecarClient) FetchSidecars(id string, format Format) (int, storage.BlobSidecars, error) {
	response, ok := s.data[id]
	if !ok {
		return 0, storage.BlobSidecars{}, fmt.Errorf("not found")
	}
	return response.statusCode, response.data, response.err
}

func setup(t *testing.T) (*ValidatorService, *beacontest.StubBeaconClient, *stubBlobSidecarClient, *stubBlobSidecarClient) {
	l := testlog.Logger(t, log.LvlInfo)
	headerClient := beacontest.NewDefaultStubBeaconClient(t)
	cancel := func(error) {}

	beacon := &stubBlobSidecarClient{
		data: make(map[string]response),
	}
	blob := &stubBlobSidecarClient{
		data: make(map[string]response),
	}

	return NewValidator(l, headerClient, beacon, blob, cancel, flags.ValidatorConfig{
		ValidateFormats: []string{"json", "ssz"},
		NumBlocks:       600,
	}), headerClient, beacon, blob
}

func TestValidatorService_OnFetchError(t *testing.T) {
	validator, _, _, _ := setup(t)

	result := validator.checkBlobs(context.Background(), phase0.Slot(blobtest.StartSlot), phase0.Slot(blobtest.StartSlot+1))

	// Expect an error for both SSZ and JSON
	startSlot := strconv.FormatUint(blobtest.StartSlot, 10)
	endSlot := strconv.FormatUint(blobtest.StartSlot+1, 10)
	require.Equal(t, result.ErrorFetching, []string{startSlot, startSlot, endSlot, endSlot})
	require.Empty(t, result.MismatchedStatus)
	require.Empty(t, result.MismatchedData)
}

func TestValidatorService_AllMatch(t *testing.T) {
	validator, headers, beacon, blob := setup(t)

	// Set the beacon + blob APIs to return the same data
	beacon.setResponses(headers)
	blob.setResponses(headers)

	result := validator.checkBlobs(context.Background(), phase0.Slot(blobtest.StartSlot), phase0.Slot(blobtest.EndSlot))

	require.Empty(t, result.MismatchedStatus)
	require.Empty(t, result.MismatchedData)
	require.Empty(t, result.ErrorFetching)
}

func TestValidatorService_MismatchedStatus(t *testing.T) {
	validator, headers, beacon, blob := setup(t)

	// Set the blob API to return a 404 for blob=1
	beacon.setResponses(headers)
	blob.setResponses(headers)
	blob.setResponse(blockOne, 404, storage.BlobSidecars{}, nil)

	result := validator.checkBlobs(context.Background(), phase0.Slot(blobtest.StartSlot), phase0.Slot(blobtest.EndSlot))

	require.Empty(t, result.MismatchedData)
	require.Empty(t, result.ErrorFetching)
	require.Len(t, result.MismatchedStatus, 2)
	// The first mismatch is the JSON format, the second is the SSZ format
	require.Equal(t, result.MismatchedStatus, []string{blockOne, blockOne})
}

func TestValidatorService_CompletelyDifferentBlobData(t *testing.T) {
	validator, headers, beacon, blob := setup(t)

	// Modify the blobs for block 1 to be new random data
	beacon.setResponses(headers)
	blob.setResponses(headers)
	blob.setResponse(blockOne, 200, storage.BlobSidecars{
		Data: blobtest.NewBlobSidecars(t, 1, nil),
	}, nil)

	result := validator.checkBlobs(context.Background(), phase0.Slot(blobtest.StartSlot), phase0.Slot(blobtest.EndSlot))

	require.Empty(t, result.MismatchedStatus)
	require.Empty(t, result.ErrorFetching)
	require.Len(t, result.MismatchedData, 2)
	// The first mismatch is the JSON format, the second is the SSZ format
	require.Equal(t, result.MismatchedData, []string{blockOne, blockOne})
}

func TestValidatorService_MistmatchedBlobFields(t *testing.T) {
	tests := []struct {
		name         string
		modification func(i *[]*deneb.BlobSidecar)
	}{
		{
			name: "mismatched index",
			modification: func(i *[]*deneb.BlobSidecar) {
				(*i)[0].Index = deneb.BlobIndex(9)
			},
		},
		{
			name: "mismatched blob",
			modification: func(i *[]*deneb.BlobSidecar) {
				(*i)[0].Blob = deneb.Blob{0, 0, 0}
			},
		},
		{
			name: "mismatched kzg commitment",
			modification: func(i *[]*deneb.BlobSidecar) {
				(*i)[0].KZGCommitment = deneb.KZGCommitment{0, 0, 0}
			},
		},
		{
			name: "mismatched kzg proof",
			modification: func(i *[]*deneb.BlobSidecar) {
				(*i)[0].KZGProof = deneb.KZGProof{0, 0, 0}
			},
		},
		{
			name: "mismatched signed block header",
			modification: func(i *[]*deneb.BlobSidecar) {
				(*i)[0].SignedBlockHeader = nil
			},
		},
		{
			name: "mismatched kzg commitment inclusion proof",
			modification: func(i *[]*deneb.BlobSidecar) {
				(*i)[0].KZGCommitmentInclusionProof = deneb.KZGCommitmentInclusionProof{{1, 2, 9}}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			validator, headers, beacon, blob := setup(t)

			// Modify the blobs for block 1 to be new random data
			beacon.setResponses(headers)
			blob.setResponses(headers)

			// Deep copy the blob data
			d, err := json.Marshal(headers.SidecarsByBlock[blockOne])
			require.NoError(t, err)
			var c []*deneb.BlobSidecar
			err = json.Unmarshal(d, &c)
			require.NoError(t, err)

			test.modification(&c)

			blob.setResponse(blockOne, 200, storage.BlobSidecars{
				Data: c,
			}, nil)

			result := validator.checkBlobs(context.Background(), phase0.Slot(blobtest.StartSlot), phase0.Slot(blobtest.EndSlot))

			require.Empty(t, result.MismatchedStatus)
			require.Empty(t, result.ErrorFetching)
			require.Len(t, result.MismatchedData, 2)
			// The first mismatch is the JSON format, the second is the SSZ format
			require.Equal(t, result.MismatchedData, []string{blockOne, blockOne})
		})
	}
}
