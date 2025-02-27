package service

import (
	"context"
	"errors"
	"strconv"
	"time"

	client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/base/blob-archiver/archiver/flags"
	"github.com/base/blob-archiver/archiver/metrics"
	"github.com/base/blob-archiver/common/storage"
	"github.com/ethereum-optimism/optimism/op-service/retry"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
	"github.com/google/uuid"
)

const (
	liveFetchBlobMaximumRetries    = 10
	startupFetchBlobMaximumRetries = 3
	rearchiveMaximumRetries        = 3
	backfillErrorRetryInterval     = 5 * time.Second
)

type BeaconClient interface {
	client.BlobSidecarsProvider
	client.BeaconBlockHeadersProvider
}

func NewArchiver(l log.Logger, cfg flags.ArchiverConfig, dataStoreClient storage.DataStore, client BeaconClient, m metrics.Metricer) (*Archiver, error) {
	return &Archiver{
		log:             l,
		cfg:             cfg,
		dataStoreClient: dataStoreClient,
		metrics:         m,
		beaconClient:    client,
		stopCh:          make(chan struct{}),
		id:              uuid.New().String(),
	}, nil
}

type Archiver struct {
	log             log.Logger
	cfg             flags.ArchiverConfig
	dataStoreClient storage.DataStore
	beaconClient    BeaconClient
	metrics         metrics.Metricer
	stopCh          chan struct{}
	id              string
}

// Start starts archiving blobs. It begins polling the beacon node for the latest blocks and persisting blobs for
// them. Concurrently it'll also begin a backfill process (see backfillBlobs) to store all blobs from the current head
// to the previously stored blocks. This ensures that during restarts or outages of an archiver, any gaps will be
// filled in.
func (a *Archiver) Start(ctx context.Context) error {
	currentBlock, _, err := retry.Do2(ctx, startupFetchBlobMaximumRetries, retry.Exponential(), func() (*v1.BeaconBlockHeader, bool, error) {
		return a.persistBlobsForBlock(ctx, "head", false)
	})

	if err != nil {
		a.log.Error("failed to seed archiver with initial block", "err", err)
		return err
	}

	a.waitObtainStorageLock(ctx)

	go a.backfillBlobs(ctx, currentBlock)

	return a.trackLatestBlocks(ctx)
}

// Stops the archiver service.
func (a *Archiver) Stop(ctx context.Context) error {
	close(a.stopCh)
	return nil
}

// persistBlobsForBlock fetches the blobs for a given block and persists them to S3. It returns the block header
// and a boolean indicating whether the blobs already existed in S3 and any errors that occur.
// If the blobs are already stored, it will not overwrite the data. Currently, the archiver does not
// perform any validation of the blobs, it assumes a trusted beacon node. See:
// https://github.com/base/blob-archiver/issues/4.
func (a *Archiver) persistBlobsForBlock(ctx context.Context, blockIdentifier string, overwrite bool) (*v1.BeaconBlockHeader, bool, error) {
	currentHeader, err := a.beaconClient.BeaconBlockHeader(ctx, &api.BeaconBlockHeaderOpts{
		Block: blockIdentifier,
	})

	if err != nil {
		a.log.Error("failed to fetch latest beacon block header", "err", err)
		return nil, false, err
	}

	exists, err := a.dataStoreClient.Exists(ctx, common.Hash(currentHeader.Data.Root))
	if err != nil {
		a.log.Error("failed to check if blob exists", "err", err)
		return nil, false, err
	}

	if exists && !overwrite {
		a.log.Debug("blob already exists", "hash", currentHeader.Data.Root)
		return currentHeader.Data, true, nil
	}

	blobSidecars, err := a.beaconClient.BlobSidecars(ctx, &api.BlobSidecarsOpts{
		Block: currentHeader.Data.Root.String(),
	})

	if err != nil {
		a.log.Error("failed to fetch blob sidecars", "err", err)
		return nil, false, err
	}

	a.log.Debug("fetched blob sidecars", "count", len(blobSidecars.Data))

	blobData := storage.BlobData{
		Header: storage.Header{
			BeaconBlockHash: common.Hash(currentHeader.Data.Root),
		},
		BlobSidecars: storage.BlobSidecars{Data: blobSidecars.Data},
	}

	// The blob that is being written has not been validated. It is assumed that the beacon node is trusted.
	err = a.dataStoreClient.WriteBlob(ctx, blobData)

	if err != nil {
		a.log.Error("failed to write blob", "err", err)
		return nil, false, err
	}

	a.metrics.RecordStoredBlobs(len(blobSidecars.Data))

	return currentHeader.Data, exists, nil
}

const LockUpdateInterval = 10 * time.Second
const LockTimeout = int64(20) // 20 seconds
var ObtainLockRetryInterval = 10 * time.Second

func (a *Archiver) waitObtainStorageLock(ctx context.Context) {
	lockfile, err := a.dataStoreClient.ReadLockfile(ctx)
	if err != nil {
		a.log.Crit("failed to read lockfile", "err", err)
	}

	currentTime := time.Now().Unix()
	emptyLockfile := storage.Lockfile{}
	if lockfile != emptyLockfile {
		for lockfile.ArchiverId != a.id && lockfile.Timestamp+LockTimeout > currentTime {
			// Loop until the timestamp read from storage is expired
			a.log.Info("waiting for storage lock timestamp to expire",
				"timestamp", strconv.FormatInt(lockfile.Timestamp, 10),
				"currentTime", strconv.FormatInt(currentTime, 10),
			)
			time.Sleep(ObtainLockRetryInterval)
			lockfile, err = a.dataStoreClient.ReadLockfile(ctx)
			if err != nil {
				a.log.Crit("failed to read lockfile", "err", err)
			}
			currentTime = time.Now().Unix()
		}
	}

	err = a.dataStoreClient.WriteLockfile(ctx, storage.Lockfile{ArchiverId: a.id, Timestamp: currentTime})
	if err != nil {
		a.log.Crit("failed to write to lockfile: %v", err)
	}
	a.log.Info("obtained storage lock")

	go func() {
		// Retain storage lock by continually updating the stored timestamp
		ticker := time.NewTicker(LockUpdateInterval)
		for {
			select {
			case <-ticker.C:
				currentTime := time.Now().Unix()
				err := a.dataStoreClient.WriteLockfile(ctx, storage.Lockfile{ArchiverId: a.id, Timestamp: currentTime})
				if err != nil {
					a.log.Error("failed to update lockfile timestamp", "err", err)
				}
			case <-ctx.Done():
				ticker.Stop()
				return
			}
		}
	}()
}

// backfillBlobs will persist all blobs from the provided beacon block header, to either the last block that was persisted
// to the archivers storage or the origin block in the configuration. This is used to ensure that any gaps can be filled.
// If an error is encountered persisting a block, it will retry after waiting for a period of time.
func (a *Archiver) backfillBlobs(ctx context.Context, latest *v1.BeaconBlockHeader) {
	// Add backfill process that starts at latest slot, then loop through all backfill processes
	backfillProcesses, err := a.dataStoreClient.ReadBackfillProcesses(ctx)
	if err != nil {
		a.log.Crit("failed to read backfill_processes", "err", err)
	}
	backfillProcesses[common.Hash(latest.Root)] = storage.BackfillProcess{Start: *latest, Current: *latest}
	_ = a.dataStoreClient.WriteBackfillProcesses(ctx, backfillProcesses)

	backfillLoop := func(start *v1.BeaconBlockHeader, current *v1.BeaconBlockHeader) {
		curr, alreadyExists, err := current, false, error(nil)
		count := 0
		a.log.Info("backfill process initiated",
			"currHash", curr.Root.String(),
			"currSlot", curr.Header.Message.Slot,
			"startHash", start.Root.String(),
			"startSlot", start.Header.Message.Slot,
		)

		defer func() {
			a.log.Info("backfill process complete",
				"endHash", curr.Root.String(),
				"endSlot", curr.Header.Message.Slot,
				"startHash", start.Root.String(),
				"startSlot", start.Header.Message.Slot,
			)
			delete(backfillProcesses, common.Hash(start.Root))
			_ = a.dataStoreClient.WriteBackfillProcesses(ctx, backfillProcesses)
		}()

		for !alreadyExists {
			previous := curr

			if common.Hash(curr.Root) == a.cfg.OriginBlock {
				a.log.Info("reached origin block", "hash", curr.Root.String())
				return
			}

			curr, alreadyExists, err = a.persistBlobsForBlock(ctx, previous.Header.Message.ParentRoot.String(), false)
			if err != nil {
				a.log.Error("failed to persist blobs for block, will retry", "err", err, "hash", previous.Header.Message.ParentRoot.String())
				// Revert back to block we failed to fetch
				curr = previous
				time.Sleep(backfillErrorRetryInterval)
				continue
			}

			if !alreadyExists {
				a.metrics.RecordProcessedBlock(metrics.BlockSourceBackfill)
			}

			count++
			if count%10 == 0 {
				backfillProcesses[common.Hash(start.Root)] = storage.BackfillProcess{Start: *start, Current: *curr}
				_ = a.dataStoreClient.WriteBackfillProcesses(ctx, backfillProcesses)
			}
		}
	}

	for _, process := range backfillProcesses {
		backfillLoop(&process.Start, &process.Current)
	}
}

// trackLatestBlocks will poll the beacon node for the latest blocks and persist blobs for them.
func (a *Archiver) trackLatestBlocks(ctx context.Context) error {
	t := time.NewTicker(a.cfg.PollInterval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-a.stopCh:
			return nil
		case <-t.C:
			a.processBlocksUntilKnownBlock(ctx)
		}
	}
}

// processBlocksUntilKnownBlock will fetch and persist blobs for blocks until it finds a block that has been stored before.
// In the case of a reorg, it will fetch the new head and then walk back the chain, storing all blobs until it finds a
// known block -- that already exists in the archivers' storage.
func (a *Archiver) processBlocksUntilKnownBlock(ctx context.Context) {
	a.log.Debug("refreshing live data")

	var start *v1.BeaconBlockHeader
	currentBlockId := "head"

	for {
		current, alreadyExisted, err := retry.Do2(ctx, liveFetchBlobMaximumRetries, retry.Exponential(), func() (*v1.BeaconBlockHeader, bool, error) {
			return a.persistBlobsForBlock(ctx, currentBlockId, false)
		})

		if err != nil {
			a.log.Error("failed to update live blobs for block", "err", err, "blockId", currentBlockId)
			return
		}

		if start == nil {
			start = current
		}

		if !alreadyExisted {
			a.metrics.RecordProcessedBlock(metrics.BlockSourceLive)
		} else {
			a.log.Debug("blob already exists", "hash", current.Root.String())
			break
		}

		currentBlockId = current.Header.Message.ParentRoot.String()
	}

	a.log.Info("live data refreshed", "startHash", start.Root.String(), "endHash", currentBlockId)
}

// rearchiveRange will rearchive all blocks in the range from the given start to end. It returns the start and end of the
// range that was successfully rearchived. On any persistent errors, it will halt archiving and return the range of blocks
// that were rearchived and the error that halted the process.
func (a *Archiver) rearchiveRange(from uint64, to uint64) (uint64, uint64, error) {
	for i := from; i <= to; i++ {
		id := strconv.FormatUint(i, 10)

		l := a.log.New("slot", id)

		l.Info("rearchiving block")

		rewritten, err := retry.Do(context.Background(), rearchiveMaximumRetries, retry.Exponential(), func() (bool, error) {
			_, _, e := a.persistBlobsForBlock(context.Background(), id, true)

			// If the block is not found, we can assume that the slot has been skipped
			if e != nil {
				var apiErr *api.Error
				if errors.As(e, &apiErr) && apiErr.StatusCode == 404 {
					return false, nil
				}

				return false, e
			}

			return true, nil
		})

		if err != nil {
			return from, i, err
		}

		if !rewritten {
			l.Info("block not found during reachiving", "slot", id)
		}

		a.metrics.RecordProcessedBlock(metrics.BlockSourceRearchive)
	}

	return from, to, nil
}
