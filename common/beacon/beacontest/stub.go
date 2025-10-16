package beacontest

import (
	"context"
	"fmt"
	"strconv"
	"testing"

	"github.com/attestantio/go-eth2-client/api"
	v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/base/blob-archiver/common/blobtest"
	"github.com/ethereum/go-ethereum/common"
)

type StubBeaconClient struct {
	Headers         map[string]*v1.BeaconBlockHeader
	SidecarsByBlock map[string][]*deneb.BlobSidecar
	FailBlobs       bool
}

func (s *StubBeaconClient) BeaconBlockHeader(ctx context.Context, opts *api.BeaconBlockHeaderOpts) (*api.Response[*v1.BeaconBlockHeader], error) {
	header, found := s.Headers[opts.Block]
	if !found {
		return nil, fmt.Errorf("block not found")
	}
	return &api.Response[*v1.BeaconBlockHeader]{
		Data: header,
	}, nil
}

func (s *StubBeaconClient) BlobSidecars(ctx context.Context, opts *api.BlobSidecarsOpts) (*api.Response[[]*deneb.BlobSidecar], error) {
	blobs, found := s.SidecarsByBlock[opts.Block]
	if !found {
		return nil, fmt.Errorf("block not found")
	}
	return &api.Response[[]*deneb.BlobSidecar]{
		Data: blobs,
	}, nil
}

// Blobs implements the BlobsProvider interface, converting sidecars to blobs
func (s *StubBeaconClient) Blobs(ctx context.Context, opts *api.BlobsOpts) (*api.Response[v1.Blobs], error) {
	if s.FailBlobs {
		return nil, fmt.Errorf("blobs endpoint unavailable")
	}

	sidecars, found := s.SidecarsByBlock[opts.Block]
	if !found {
		return nil, fmt.Errorf("block not found")
	}

	blobs := make(v1.Blobs, len(sidecars))
	for i, sidecar := range sidecars {
		blobs[i] = &sidecar.Blob
	}

	return &api.Response[v1.Blobs]{
		Data: blobs,
	}, nil
}

func NewEmptyStubBeaconClient() *StubBeaconClient {
	return &StubBeaconClient{
		Headers:         make(map[string]*v1.BeaconBlockHeader),
		SidecarsByBlock: make(map[string][]*deneb.BlobSidecar),
	}
}

func NewDefaultStubBeaconClient(t *testing.T) *StubBeaconClient {
	makeHeader := func(slot uint64, hash, parent common.Hash) *v1.BeaconBlockHeader {
		return &v1.BeaconBlockHeader{
			Root: phase0.Root(hash),
			Header: &phase0.SignedBeaconBlockHeader{
				Message: &phase0.BeaconBlockHeader{
					Slot:       phase0.Slot(slot),
					ParentRoot: phase0.Root(parent),
				},
			},
		}
	}

	startSlot := blobtest.StartSlot

	// Create headers first so they can be used for blobs
	originHeader := makeHeader(startSlot, blobtest.OriginBlock, common.Hash{9, 9, 9})
	oneHeader := makeHeader(startSlot+1, blobtest.One, blobtest.OriginBlock)
	twoHeader := makeHeader(startSlot+2, blobtest.Two, blobtest.One)
	threeHeader := makeHeader(startSlot+3, blobtest.Three, blobtest.Two)
	fourHeader := makeHeader(startSlot+4, blobtest.Four, blobtest.Three)
	fiveHeader := makeHeader(startSlot+5, blobtest.Five, blobtest.Four)

	// Create blobs with valid headers
	originBlobs := blobtest.NewBlobSidecars(t, 1, originHeader.Header)
	oneBlobs := blobtest.NewBlobSidecars(t, 2, oneHeader.Header)
	twoBlobs := blobtest.NewBlobSidecars(t, 0, twoHeader.Header)
	threeBlobs := blobtest.NewBlobSidecars(t, 4, threeHeader.Header)
	fourBlobs := blobtest.NewBlobSidecars(t, 5, fourHeader.Header)
	fiveBlobs := blobtest.NewBlobSidecars(t, 6, fiveHeader.Header)

	return &StubBeaconClient{
		Headers: map[string]*v1.BeaconBlockHeader{
			// Lookup by hash
			blobtest.OriginBlock.String(): originHeader,
			blobtest.One.String():         oneHeader,
			blobtest.Two.String():         twoHeader,
			blobtest.Three.String():       threeHeader,
			blobtest.Four.String():        fourHeader,
			blobtest.Five.String():        fiveHeader,

			// Lookup by identifier
			"head":      makeHeader(startSlot+5, blobtest.Five, blobtest.Four),
			"finalized": makeHeader(startSlot+3, blobtest.Three, blobtest.Two),

			// Lookup by slot
			strconv.FormatUint(startSlot, 10):   makeHeader(startSlot, blobtest.OriginBlock, common.Hash{9, 9, 9}),
			strconv.FormatUint(startSlot+1, 10): makeHeader(startSlot+1, blobtest.One, blobtest.OriginBlock),
			strconv.FormatUint(startSlot+2, 10): makeHeader(startSlot+2, blobtest.Two, blobtest.One),
			strconv.FormatUint(startSlot+3, 10): makeHeader(startSlot+3, blobtest.Three, blobtest.Two),
			strconv.FormatUint(startSlot+4, 10): makeHeader(startSlot+4, blobtest.Four, blobtest.Three),
			strconv.FormatUint(startSlot+5, 10): makeHeader(startSlot+5, blobtest.Five, blobtest.Four),
		},
		SidecarsByBlock: map[string][]*deneb.BlobSidecar{
			// Lookup by hash
			blobtest.OriginBlock.String(): originBlobs,
			blobtest.One.String():         oneBlobs,
			blobtest.Two.String():         twoBlobs,
			blobtest.Three.String():       threeBlobs,
			blobtest.Four.String():        fourBlobs,
			blobtest.Five.String():        fiveBlobs,

			// Lookup by identifier
			"head":      fiveBlobs,
			"finalized": threeBlobs,

			// Lookup by slot
			strconv.FormatUint(startSlot, 10):   originBlobs,
			strconv.FormatUint(startSlot+1, 10): oneBlobs,
			strconv.FormatUint(startSlot+2, 10): twoBlobs,
			strconv.FormatUint(startSlot+3, 10): threeBlobs,
			strconv.FormatUint(startSlot+4, 10): fourBlobs,
			strconv.FormatUint(startSlot+5, 10): fiveBlobs,
		},
	}
}
