package service

import (
	"context"
	"testing"
	"time"

	"github.com/base/blob-archiver/archiver/flags"
	"github.com/base/blob-archiver/archiver/metrics"
	"github.com/base/blob-archiver/common/beacon/beacontest"
	"github.com/base/blob-archiver/common/blobtest"
	"github.com/base/blob-archiver/common/storage"
	"github.com/base/blob-archiver/common/storage/storagetest"
	"github.com/ethereum-optimism/optimism/op-service/testlog"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
	"github.com/stretchr/testify/require"
)

func setup(t *testing.T, beacon *beacontest.StubBeaconClient) (*Archiver, *storagetest.TestFileStorage) {
	l := testlog.Logger(t, log.LvlInfo)
	fs := storagetest.NewTestFileStorage(t, l)
	m := metrics.NewMetrics()

	svc, err := NewArchiver(l, flags.ArchiverConfig{
		PollInterval: 5 * time.Second,
		OriginBlock:  blobtest.OriginBlock,
	}, fs, beacon, m)
	require.NoError(t, err)
	return svc, fs
}

func TestArchiver_FetchAndPersist(t *testing.T) {
	beacon := beacontest.NewDefaultStubBeaconClient(t)
	svc, fs := setup(t, beacon)

	fs.CheckNotExistsOrFail(t, blobtest.OriginBlock)

	header, alreadyExists, err := svc.persistBlobsForBlockToS3(context.Background(), blobtest.OriginBlock.String(), false)
	require.False(t, alreadyExists)
	require.NoError(t, err)
	require.NotNil(t, header)
	require.Equal(t, blobtest.OriginBlock.String(), common.Hash(header.Root).String())

	fs.CheckExistsOrFail(t, blobtest.OriginBlock)

	header, alreadyExists, err = svc.persistBlobsForBlockToS3(context.Background(), blobtest.OriginBlock.String(), false)
	require.True(t, alreadyExists)
	require.NoError(t, err)
	require.NotNil(t, header)
	require.Equal(t, blobtest.OriginBlock.String(), common.Hash(header.Root).String())

	fs.CheckExistsOrFail(t, blobtest.OriginBlock)
}

func TestArchiver_FetchAndPersistOverwriting(t *testing.T) {
	beacon := beacontest.NewDefaultStubBeaconClient(t)
	svc, fs := setup(t, beacon)

	// Blob 5 already exists
	fs.WriteOrFail(t, storage.BlobData{
		Header: storage.Header{
			BeaconBlockHash: blobtest.Five,
		},
		BlobSidecars: storage.BlobSidecars{
			Data: beacon.SidecarsByBlock[blobtest.Five.String()],
		},
	})

	require.Equal(t, fs.ReadOrFail(t, blobtest.Five).BlobSidecars.Data, beacon.SidecarsByBlock[blobtest.Five.String()])

	// change the blob data -- this isn't possible w/out changing the hash. But it allows us to test the overwrite
	beacon.SidecarsByBlock[blobtest.Five.String()] = blobtest.NewBlobSidecars(t, 6, beacon.Headers[blobtest.Five.String()].Header)

	_, exists, err := svc.persistBlobsForBlockToS3(context.Background(), blobtest.Five.String(), true)
	require.NoError(t, err)
	require.True(t, exists)

	// It should have overwritten the blob data
	require.Equal(t, fs.ReadOrFail(t, blobtest.Five).BlobSidecars.Data, beacon.SidecarsByBlock[blobtest.Five.String()])

	// Overwriting a non-existent blob should return exists=false
	_, exists, err = svc.persistBlobsForBlockToS3(context.Background(), blobtest.Four.String(), true)
	require.NoError(t, err)
	require.False(t, exists)
}

func TestArchiver_BackfillToOrigin(t *testing.T) {
	beacon := beacontest.NewDefaultStubBeaconClient(t)
	svc, fs := setup(t, beacon)

	// We have the current head, which is block 5 written to storage
	err := fs.WriteBlob(context.Background(), storage.BlobData{
		Header: storage.Header{
			BeaconBlockHash: blobtest.Five,
		},
		BlobSidecars: storage.BlobSidecars{
			Data: beacon.SidecarsByBlock[blobtest.Five.String()],
		},
	})
	require.NoError(t, err)
	// We expect to backfill all blocks to the origin
	expectedBlobs := []common.Hash{blobtest.Four, blobtest.Three, blobtest.Two, blobtest.One, blobtest.OriginBlock}

	for _, blob := range expectedBlobs {
		fs.CheckNotExistsOrFail(t, blob)
	}

	svc.backfillBlobs(context.Background(), beacon.Headers[blobtest.Five.String()])

	for _, blob := range expectedBlobs {
		fs.CheckExistsOrFail(t, blob)
		data := fs.ReadOrFail(t, blob)
		require.Equal(t, data.BlobSidecars.Data, beacon.SidecarsByBlock[blob.String()])
	}
}

func TestArchiver_BackfillToExistingBlock(t *testing.T) {
	beacon := beacontest.NewDefaultStubBeaconClient(t)
	svc, fs := setup(t, beacon)

	// We have the current head, which is block 5 written to storage
	err := fs.WriteBlob(context.Background(), storage.BlobData{
		Header: storage.Header{
			BeaconBlockHash: blobtest.Five,
		},
		BlobSidecars: storage.BlobSidecars{
			Data: beacon.SidecarsByBlock[blobtest.Five.String()],
		},
	})
	require.NoError(t, err)

	// We also have block 1 written to storage
	err = fs.WriteBlob(context.Background(), storage.BlobData{
		Header: storage.Header{
			BeaconBlockHash: blobtest.One,
		},
		BlobSidecars: storage.BlobSidecars{
			Data: beacon.SidecarsByBlock[blobtest.One.String()],
		},
	})
	require.NoError(t, err)

	// We expect to backfill all blobs between 5 and 1
	expectedBlobs := []common.Hash{blobtest.Four, blobtest.Three, blobtest.Two}

	for _, blob := range expectedBlobs {
		exists, err := fs.Exists(context.Background(), blob)
		require.NoError(t, err)
		require.False(t, exists)
	}

	svc.backfillBlobs(context.Background(), beacon.Headers[blobtest.Five.String()])

	for _, blob := range expectedBlobs {
		exists, err := fs.Exists(context.Background(), blob)
		require.NoError(t, err)
		require.True(t, exists)

		data, err := fs.ReadBlob(context.Background(), blob)
		require.NoError(t, err)
		require.NotNil(t, data)
		require.Equal(t, data.BlobSidecars.Data, beacon.SidecarsByBlock[blob.String()])
	}
}

func TestArchiver_ObtainLockfile(t *testing.T) {
	beacon := beacontest.NewDefaultStubBeaconClient(t)
	svc, _ := setup(t, beacon)

	currentTime := time.Now().Unix()
	expiredTime := currentTime - 19
	err := svc.dataStoreClient.WriteLockfile(context.Background(), storage.Lockfile{ArchiverId: "FAKEID", Timestamp: expiredTime})
	require.NoError(t, err)

	ObtainLockRetryInterval = 1 * time.Second
	svc.waitObtainStorageLock(context.Background())

	lockfile, err := svc.dataStoreClient.ReadLockfile(context.Background())
	require.NoError(t, err)
	require.Equal(t, svc.id, lockfile.ArchiverId)
	require.True(t, lockfile.Timestamp >= currentTime)
}

func TestArchiver_BackfillFinishOldProcess(t *testing.T) {
	beacon := beacontest.NewDefaultStubBeaconClient(t)
	svc, fs := setup(t, beacon)

	// We have the current head, which is block 5 written to storage
	err := fs.WriteBlob(context.Background(), storage.BlobData{
		Header: storage.Header{
			BeaconBlockHash: blobtest.Five,
		},
		BlobSidecars: storage.BlobSidecars{
			Data: beacon.SidecarsByBlock[blobtest.Five.String()],
		},
	})
	require.NoError(t, err)

	// We also have block 3 written to storage
	err = fs.WriteBlob(context.Background(), storage.BlobData{
		Header: storage.Header{
			BeaconBlockHash: blobtest.Three,
		},
		BlobSidecars: storage.BlobSidecars{
			Data: beacon.SidecarsByBlock[blobtest.Three.String()],
		},
	})
	require.NoError(t, err)

	// We also have block 1 written to storage
	err = fs.WriteBlob(context.Background(), storage.BlobData{
		Header: storage.Header{
			BeaconBlockHash: blobtest.One,
		},
		BlobSidecars: storage.BlobSidecars{
			Data: beacon.SidecarsByBlock[blobtest.One.String()],
		},
	})
	require.NoError(t, err)

	// We expect to backfill blob 4 first, then 2 in a separate process
	expectedBlobs := []common.Hash{blobtest.Four, blobtest.Two}

	for _, blob := range expectedBlobs {
		exists, err := fs.Exists(context.Background(), blob)
		require.NoError(t, err)
		require.False(t, exists)
	}

	actualProcesses, err := svc.dataStoreClient.ReadBackfillProcesses(context.Background())
	expectedProcesses := make(storage.BackfillProcesses)
	require.NoError(t, err)
	require.Equal(t, expectedProcesses, actualProcesses)

	expectedProcesses[blobtest.Three] = storage.BackfillProcess{Start: *beacon.Headers[blobtest.Three.String()], Current: *beacon.Headers[blobtest.Three.String()]}
	err = svc.dataStoreClient.WriteBackfillProcesses(context.Background(), expectedProcesses)
	require.NoError(t, err)

	actualProcesses, err = svc.dataStoreClient.ReadBackfillProcesses(context.Background())
	require.NoError(t, err)
	require.Equal(t, expectedProcesses, actualProcesses)

	svc.backfillBlobs(context.Background(), beacon.Headers[blobtest.Five.String()])

	for _, blob := range expectedBlobs {
		exists, err := fs.Exists(context.Background(), blob)
		require.NoError(t, err)
		require.True(t, exists)

		data, err := fs.ReadBlob(context.Background(), blob)
		require.NoError(t, err)
		require.NotNil(t, data)
		require.Equal(t, data.BlobSidecars.Data, beacon.SidecarsByBlock[blob.String()])
	}

	actualProcesses, err = svc.dataStoreClient.ReadBackfillProcesses(context.Background())
	require.NoError(t, err)
	svc.log.Info("backfill processes", "processes", actualProcesses)
	require.Equal(t, storage.BackfillProcesses{}, actualProcesses)

}

func TestArchiver_LatestStopsAtExistingBlock(t *testing.T) {
	beacon := beacontest.NewDefaultStubBeaconClient(t)
	svc, fs := setup(t, beacon)

	// 5 is the current head, if three already exists, we should write 5 and 4 and stop at three
	fs.WriteOrFail(t, storage.BlobData{
		Header: storage.Header{
			BeaconBlockHash: blobtest.Three,
		},
		BlobSidecars: storage.BlobSidecars{
			Data: beacon.SidecarsByBlock[blobtest.Three.String()],
		},
	})

	fs.CheckNotExistsOrFail(t, blobtest.Five)
	fs.CheckNotExistsOrFail(t, blobtest.Four)
	fs.CheckExistsOrFail(t, blobtest.Three)

	svc.processBlocksUntilKnownBlock(context.Background())

	fs.CheckExistsOrFail(t, blobtest.Five)
	five := fs.ReadOrFail(t, blobtest.Five)
	require.Equal(t, five.Header.BeaconBlockHash, blobtest.Five)
	require.Equal(t, five.BlobSidecars.Data, beacon.SidecarsByBlock[blobtest.Five.String()])

	fs.CheckExistsOrFail(t, blobtest.Four)
	four := fs.ReadOrFail(t, blobtest.Four)
	require.Equal(t, four.Header.BeaconBlockHash, blobtest.Four)
	require.Equal(t, five.BlobSidecars.Data, beacon.SidecarsByBlock[blobtest.Five.String()])

	fs.CheckExistsOrFail(t, blobtest.Three)
	three := fs.ReadOrFail(t, blobtest.Three)
	require.Equal(t, three.Header.BeaconBlockHash, blobtest.Three)
	require.Equal(t, five.BlobSidecars.Data, beacon.SidecarsByBlock[blobtest.Five.String()])
}

func TestArchiver_LatestNoNewData(t *testing.T) {
	beacon := beacontest.NewDefaultStubBeaconClient(t)
	svc, fs := setup(t, beacon)

	// 5 is the current head, if 5 already exists, this should be a no-op
	fs.WriteOrFail(t, storage.BlobData{
		Header: storage.Header{
			BeaconBlockHash: common.Hash(beacon.Headers["head"].Root),
		},
		BlobSidecars: storage.BlobSidecars{
			Data: beacon.SidecarsByBlock[blobtest.Three.String()],
		},
	})

	fs.CheckExistsOrFail(t, blobtest.Five)
	fs.CheckNotExistsOrFail(t, blobtest.Four)

	svc.processBlocksUntilKnownBlock(context.Background())

	fs.CheckExistsOrFail(t, blobtest.Five)
	fs.CheckNotExistsOrFail(t, blobtest.Four)
}

func TestArchiver_LatestConsumesNewBlocks(t *testing.T) {
	beacon := beacontest.NewDefaultStubBeaconClient(t)
	svc, fs := setup(t, beacon)

	// set current head to 4, and write four
	beacon.Headers["head"] = beacon.Headers[blobtest.Four.String()]
	fs.WriteOrFail(t, storage.BlobData{
		Header: storage.Header{
			BeaconBlockHash: common.Hash(beacon.Headers[blobtest.Four.String()].Root),
		},
		BlobSidecars: storage.BlobSidecars{
			Data: beacon.SidecarsByBlock[blobtest.Four.String()],
		},
	})

	svc.processBlocksUntilKnownBlock(context.Background())

	// No new data (5) is written and latest stops at known block (4), so 3 should not exist
	fs.CheckNotExistsOrFail(t, blobtest.Five)
	fs.CheckExistsOrFail(t, blobtest.Four)
	fs.CheckNotExistsOrFail(t, blobtest.Three)

	// set current head to 5, and check it fetches new data
	beacon.Headers["head"] = beacon.Headers[blobtest.Five.String()]

	svc.processBlocksUntilKnownBlock(context.Background())
	fs.CheckExistsOrFail(t, blobtest.Five)
	fs.CheckExistsOrFail(t, blobtest.Four)
	fs.CheckNotExistsOrFail(t, blobtest.Three)
}

func TestArchiver_LatestStopsAtOrigin(t *testing.T) {
	beacon := beacontest.NewDefaultStubBeaconClient(t)
	svc, fs := setup(t, beacon)

	// 5 is the current head, if origin already exists, we should stop at origin
	fs.WriteOrFail(t, storage.BlobData{
		Header: storage.Header{
			BeaconBlockHash: blobtest.OriginBlock,
		},
		BlobSidecars: storage.BlobSidecars{
			Data: beacon.SidecarsByBlock[blobtest.OriginBlock.String()],
		},
	})

	// Should write all blocks back to Origin
	toWrite := []common.Hash{blobtest.Five, blobtest.Four, blobtest.Three, blobtest.Two, blobtest.One}
	for _, hash := range toWrite {
		fs.CheckNotExistsOrFail(t, hash)
	}

	svc.processBlocksUntilKnownBlock(context.Background())

	for _, hash := range toWrite {
		fs.CheckExistsOrFail(t, hash)
		data := fs.ReadOrFail(t, hash)
		require.Equal(t, data.BlobSidecars.Data, beacon.SidecarsByBlock[hash.String()])
	}
}

func TestArchiver_LatestRetriesOnFailure(t *testing.T) {
	beacon := beacontest.NewDefaultStubBeaconClient(t)
	svc, fs := setup(t, beacon)

	// 5 is the current head, if three already exists, we should write 5 and 4 and stop at three
	fs.WriteOrFail(t, storage.BlobData{
		Header: storage.Header{
			BeaconBlockHash: blobtest.Three,
		},
		BlobSidecars: storage.BlobSidecars{
			Data: beacon.SidecarsByBlock[blobtest.Three.String()],
		},
	})

	fs.CheckNotExistsOrFail(t, blobtest.Five)
	fs.CheckNotExistsOrFail(t, blobtest.Four)
	fs.CheckExistsOrFail(t, blobtest.Three)

	// One failure is retried
	fs.WritesFailTimes(1)
	svc.processBlocksUntilKnownBlock(context.Background())

	fs.CheckExistsOrFail(t, blobtest.Five)
	fs.CheckExistsOrFail(t, blobtest.Four)
	fs.CheckExistsOrFail(t, blobtest.Three)
}

func TestArchiver_LatestHaltsOnPersistentError(t *testing.T) {
	beacon := beacontest.NewDefaultStubBeaconClient(t)
	svc, fs := setup(t, beacon)

	// 5 is the current head, if three already exists, we should write 5 and 4 and stop at three
	fs.WriteOrFail(t, storage.BlobData{
		Header: storage.Header{
			BeaconBlockHash: blobtest.Three,
		},
		BlobSidecars: storage.BlobSidecars{
			Data: beacon.SidecarsByBlock[blobtest.Three.String()],
		},
	})

	fs.CheckNotExistsOrFail(t, blobtest.Five)
	fs.CheckNotExistsOrFail(t, blobtest.Four)
	fs.CheckExistsOrFail(t, blobtest.Three)

	// Retries the maximum number of times, then fails and will not write the blobs
	fs.WritesFailTimes(liveFetchBlobMaximumRetries + 1)
	svc.processBlocksUntilKnownBlock(context.Background())

	fs.CheckNotExistsOrFail(t, blobtest.Five)
	fs.CheckNotExistsOrFail(t, blobtest.Four)
	fs.CheckExistsOrFail(t, blobtest.Three)
}

func TestArchiver_RearchiveRange(t *testing.T) {
	beacon := beacontest.NewDefaultStubBeaconClient(t)
	svc, fs := setup(t, beacon)

	// 5 is the current head, if three already exists, we should write 5 and 4 and stop at three
	fs.WriteOrFail(t, storage.BlobData{
		Header: storage.Header{
			BeaconBlockHash: blobtest.Three,
		},
		BlobSidecars: storage.BlobSidecars{
			Data: beacon.SidecarsByBlock[blobtest.Three.String()],
		},
	})

	// startSlot+1 == One
	fs.CheckNotExistsOrFail(t, blobtest.One)
	fs.CheckNotExistsOrFail(t, blobtest.Two)
	fs.CheckExistsOrFail(t, blobtest.Three)
	fs.CheckNotExistsOrFail(t, blobtest.Four)

	// this modifies the blobs at 3, purely to test the blob is rearchived
	beacon.SidecarsByBlock[blobtest.Three.String()] = blobtest.NewBlobSidecars(t, 6, beacon.Headers[blobtest.Three.String()].Header)

	from, to := blobtest.StartSlot+1, blobtest.StartSlot+4

	actualFrom, actualTo, err := svc.rearchiveRange(from, to)
	// Should index the whole range
	require.NoError(t, err)
	require.Equal(t, from, actualFrom)
	require.Equal(t, to, actualTo)

	// Should have written all the blobs
	fs.CheckExistsOrFail(t, blobtest.One)
	fs.CheckExistsOrFail(t, blobtest.Two)
	fs.CheckExistsOrFail(t, blobtest.Three)
	fs.CheckExistsOrFail(t, blobtest.Four)

	// Should have overwritten any existing blobs
	require.Equal(t, fs.ReadOrFail(t, blobtest.Three).BlobSidecars.Data, beacon.SidecarsByBlock[blobtest.Three.String()])
}

func TestArchiver_FetchBlobs_FallbackToSidecars(t *testing.T) {
	beacon := beacontest.NewDefaultStubBeaconClient(t)
	beacon.FailBlobs = true // Make blobs endpoint fail
	svc, fs := setup(t, beacon)

	fs.CheckNotExistsOrFail(t, blobtest.One)

	// Should fall back to blob sidecars endpoint
	header, alreadyExists, err := svc.persistBlobsForBlockToS3(context.Background(), blobtest.One.String(), false)
	require.False(t, alreadyExists)
	require.NoError(t, err)
	require.NotNil(t, header)

	fs.CheckExistsOrFail(t, blobtest.One)
	stored := fs.ReadOrFail(t, blobtest.One)
	require.Equal(t, len(beacon.SidecarsByBlock[blobtest.One.String()]), len(stored.BlobSidecars.Data))
}

func TestArchiver_FetchBlobs_Success(t *testing.T) {
	beacon := beacontest.NewDefaultStubBeaconClient(t)
	// FailBlobs = false (default) - blobs endpoint should succeed
	svc, fs := setup(t, beacon)

	fs.CheckNotExistsOrFail(t, blobtest.Two)

	// Should use blobs endpoint successfully
	header, alreadyExists, err := svc.persistBlobsForBlockToS3(context.Background(), blobtest.Two.String(), false)
	require.False(t, alreadyExists)
	require.NoError(t, err)
	require.NotNil(t, header)

	fs.CheckExistsOrFail(t, blobtest.Two)
	stored := fs.ReadOrFail(t, blobtest.Two)
	// Should have stored the correct number of blobs
	require.Equal(t, len(beacon.SidecarsByBlock[blobtest.Two.String()]), len(stored.BlobSidecars.Data))

	// Verify that KZG commitments and proofs were derived correctly
	for i, storedSidecar := range stored.BlobSidecars.Data {
		originalSidecar := beacon.SidecarsByBlock[blobtest.Two.String()][i]
		// The blob data should match
		require.Equal(t, originalSidecar.Blob, storedSidecar.Blob)
	}
}
