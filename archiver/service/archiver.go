package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/base/blob-archiver/archiver/flags"
	"github.com/base/blob-archiver/archiver/metrics"
	"github.com/base/blob-archiver/common/storage"
	gokzg4844 "github.com/crate-crypto/go-kzg-4844"
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

// Backoff applied while the beacon node reports a block's blobs as unavailable (see blobsUnavailableError). Data
// columns for a late-imported block typically arrive within a few minutes, so the archiver waits for them in place
// rather than skipping the block, which would risk never archiving it.
var (
	unavailableBlobsInitialBackoff = 10 * time.Second
	unavailableBlobsMaxBackoff     = 5 * time.Minute
)

// blobsUnavailableError is returned when the beacon node knows the block but does not (yet) hold its blob data.
//
// Post-Fulu, blobs are reconstructed from data columns. A block that reaches the node late (for example via req/resp
// during a fork-choice flip rather than via gossip in-slot) can sit for minutes with no columns before they arrive.
// During that window Lighthouse answers /eth/v1/beacon/blobs with a 400 reporting zero data columns found (and a
// misleading hint to run as a supernode). The block is canonical and does have blobs, so callers must not record it
// as blob-less or skip it; they should wait and try again (see persistBlobsWhenAvailable).
type blobsUnavailableError struct {
	header *v1.BeaconBlockHeader
	err    error
}

func (e *blobsUnavailableError) Error() string {
	return fmt.Sprintf("blobs unavailable for block %s: %v", e.header.Root.String(), e.err)
}

func (e *blobsUnavailableError) Unwrap() error {
	return e.err
}

// isBlobsUnavailableResponse reports whether err is a beacon node response indicating that no blob data exists
// for the block, as opposed to a transient or custody-related failure.
func isBlobsUnavailableResponse(err error) bool {
	var apiErr *api.Error
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusBadRequest {
		return false
	}

	msg := string(apiErr.Data)

	return strings.Contains(msg, "Insufficient data columns") && strings.Contains(msg, "only 0 were found")
}

// blobsToSidecars converts blobs to blob sidecars by computing KZG commitments and proofs from the blob data.
// The blobs and commitments are ordered identically (by KZG commitment order in the block).
// The header information is included from the provided header.
func blobsToSidecars(blobs v1.Blobs, header *v1.BeaconBlockHeader) ([]*deneb.BlobSidecar, error) {
	kzgCtx, err := gokzg4844.NewContext4096Secure()
	if err != nil {
		return nil, err
	}

	sidecars := make([]*deneb.BlobSidecar, len(blobs))
	for i, blob := range blobs {
		// Cast to gokzg4844.Blob for KZG operations
		kzgBlob := (*gokzg4844.Blob)(blob)

		// Compute KZG commitment from blob data
		commitment, err := kzgCtx.BlobToKZGCommitment(kzgBlob, 0)
		if err != nil {
			return nil, err
		}

		// Compute KZG proof from blob data and commitment
		proof, err := kzgCtx.ComputeBlobKZGProof(kzgBlob, commitment, 0)
		if err != nil {
			return nil, err
		}

		sidecars[i] = &deneb.BlobSidecar{
			Index:             deneb.BlobIndex(i),
			Blob:              *blob,
			KZGCommitment:     deneb.KZGCommitment(commitment),
			KZGProof:          deneb.KZGProof(proof),
			SignedBlockHeader: header.Header,
		}
	}
	return sidecars, nil
}

type BeaconClient interface {
	client.BlobSidecarsProvider
	client.BeaconBlockHeadersProvider
	client.BlobsProvider
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
	currentBlock, err := a.seedInitialBlock(ctx)
	if err != nil {
		a.log.Error("failed to seed archiver with initial block", "err", err)
		return err
	}

	a.waitObtainStorageLock(ctx)

	go a.backfillBlobs(ctx, currentBlock)

	return a.trackLatestBlocks(ctx)
}

// seedInitialBlock archives the current head and returns its header, which anchors the backfill process. The head is
// the block most likely to still be missing data columns on the beacon node; in that case startup waits for them
// rather than failing.
func (a *Archiver) seedInitialBlock(ctx context.Context) (*v1.BeaconBlockHeader, error) {
	currentBlock, _, err := retry.Do2(ctx, startupFetchBlobMaximumRetries, retry.Exponential(), func() (*v1.BeaconBlockHeader, bool, error) {
		return a.persistBlobsWhenAvailable(ctx, "head", false)
	})

	return currentBlock, err
}

// Stops the archiver service.
func (a *Archiver) Stop(ctx context.Context) error {
	close(a.stopCh)
	return nil
}

// persistBlobsForBlockToS3 fetches the blobs for a given block and persists them to S3. It returns the block header
// and a boolean indicating whether the blobs already existed in S3 and any errors that occur.
// If the blobs are already stored, it will not overwrite the data. Currently, the archiver does not
// perform any validation of the blobs, it assumes a trusted beacon node. See:
// https://github.com/base/blob-archiver/issues/4.
//
// The function prefers the /eth/v1/beacon/blob_sidecars endpoint but falls back to /eth/v1/beacon/blobs
// if the blob sidecars endpoint fails. This avoids recomputing KZG commitments and proofs when they're
// available from the beacon node.
func (a *Archiver) persistBlobsForBlockToS3(ctx context.Context, blockIdentifier string, overwrite bool) (*v1.BeaconBlockHeader, bool, error) {
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

	// Try the blob sidecars endpoint first to get commitments and proofs directly
	var blobSidecarData []*deneb.BlobSidecar
	blobSidecarsResp, err := a.beaconClient.BlobSidecars(ctx, &api.BlobSidecarsOpts{
		Block: currentHeader.Data.Root.String(),
	})

	if err == nil && blobSidecarsResp != nil && blobSidecarsResp.Data != nil {
		// Successfully fetched blob sidecars with KZG commitments and proofs
		a.log.Debug("fetched blob sidecars from blob_sidecars endpoint", "count", len(blobSidecarsResp.Data))
		blobSidecarData = blobSidecarsResp.Data
	} else {
		// Fall back to blobs endpoint and compute commitments and proofs
		if err != nil {
			a.log.Debug("blob sidecars endpoint failed, falling back to blobs", "err", err)
		}

		blobs, fallbackErr := a.beaconClient.Blobs(ctx, &api.BlobsOpts{
			Block: currentHeader.Data.Root.String(),
		})

		if fallbackErr != nil {
			if isBlobsUnavailableResponse(fallbackErr) {
				a.log.Debug("beacon node reports no blob data for block", "err", fallbackErr, "hash", currentHeader.Data.Root.String())
				return nil, false, &blobsUnavailableError{header: currentHeader.Data, err: fallbackErr}
			}

			a.log.Error("failed to fetch blobs", "err", fallbackErr)
			return nil, false, fallbackErr
		}

		if blobs == nil || blobs.Data == nil {
			a.log.Error("blobs endpoint returned nil data")
			return nil, false, errors.New("blobs endpoint returned nil data")
		}

		a.log.Debug("fetched blobs from blobs endpoint, computing KZG commitments and proofs", "count", len(blobs.Data))

		var computeErr error
		blobSidecarData, computeErr = blobsToSidecars(blobs.Data, currentHeader.Data)
		if computeErr != nil {
			a.log.Error("failed to compute KZG commitments and proofs for blobs", "err", computeErr)
			return nil, false, computeErr
		}
	}

	a.log.Debug("fetched blob sidecars", "count", len(blobSidecarData))

	blobData := storage.BlobData{
		Header: storage.Header{
			BeaconBlockHash: common.Hash(currentHeader.Data.Root),
		},
		BlobSidecars: storage.BlobSidecars{Data: blobSidecarData},
	}

	// The blob that is being written has not been validated. It is assumed that the beacon node is trusted.
	err = a.dataStoreClient.WriteBlob(ctx, blobData)

	if err != nil {
		a.log.Error("failed to write blob", "err", err)
		return nil, false, err
	}

	a.metrics.RecordStoredBlobs(len(blobSidecarData))

	return currentHeader.Data, exists, nil
}

// persistBlobsWhenAvailable wraps persistBlobsForBlockToS3 and, while the beacon node reports the block's blobs as
// unavailable, waits with exponential backoff (capped at unavailableBlobsMaxBackoff) and tries again. It only
// returns once the block is archived, the error is of another kind, or the archiver is stopped.
func (a *Archiver) persistBlobsWhenAvailable(ctx context.Context, blockIdentifier string, overwrite bool) (*v1.BeaconBlockHeader, bool, error) {
	backoff := unavailableBlobsInitialBackoff

	for {
		header, alreadyExists, err := a.persistBlobsForBlockToS3(ctx, blockIdentifier, overwrite)

		var unavailable *blobsUnavailableError
		if !errors.As(err, &unavailable) {
			return header, alreadyExists, err
		}

		a.log.Warn("beacon node has no blob data for block yet, waiting",
			"hash", unavailable.header.Root.String(),
			"slot", unavailable.header.Header.Message.Slot,
			"retryIn", backoff,
		)

		select {
		case <-ctx.Done():
			return nil, false, ctx.Err()
		case <-a.stopCh:
			return nil, false, errors.New("archiver stopped while waiting for blobs")
		case <-time.After(backoff):
		}

		backoff = min(backoff*2, unavailableBlobsMaxBackoff)
	}
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

			curr, alreadyExists, err = a.persistBlobsWhenAvailable(ctx, previous.Header.Message.ParentRoot.String(), false)
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
			return a.persistBlobsWhenAvailable(ctx, currentBlockId, false)
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
			_, _, e := a.persistBlobsForBlockToS3(context.Background(), id, true)

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
