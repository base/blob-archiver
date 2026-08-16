package storage

import (
	"context"
	"encoding/json"
	"os"
	"path"
	"strconv"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
)

type FileStorage struct {
	log       log.Logger
	directory string
}

func NewFileStorage(dir string, l log.Logger) *FileStorage {
	if err := os.MkdirAll(dir, 0755); err != nil {
		l.Crit("failed to create file storage directory", "dir", dir, "err", err)
	}

	storage := &FileStorage{
		log:       l,
		directory: dir,
	}

	_, err := storage.ReadBackfillProcesses(context.Background())
	if err == ErrNotFound {
		storage.log.Info("creating empty backfill_processes file")
		err = storage.WriteBackfillProcesses(context.Background(), BackfillProcesses{})
		if err != nil {
			storage.log.Crit("failed to create empty backfill_processes file", "err", err)
		}
	}

	_, err = storage.ReadLockfile(context.Background())
	if err == ErrNotFound {
		storage.log.Info("creating empty lockfile file")
		err = storage.WriteLockfile(context.Background(), Lockfile{})
		if err != nil {
			storage.log.Crit("failed to create empty lockfile file", "err", err)
		}
	}

	return storage
}

func (s *FileStorage) Exists(_ context.Context, hash common.Hash) (bool, error) {
	_, err := os.Stat(s.fileName(hash))
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (s *FileStorage) ReadBlob(_ context.Context, hash common.Hash) (BlobData, error) {
	data, err := os.ReadFile(s.fileName(hash))
	if err != nil {
		if os.IsNotExist(err) {
			return BlobData{}, ErrNotFound
		}

		return BlobData{}, err
	}
	var result BlobData
	err = json.Unmarshal(data, &result)
	if err != nil {
		s.log.Warn("error decoding blob", "err", err, "hash", hash.String())
		return BlobData{}, ErrMarshaling
	}
	return result, nil
}

func (s *FileStorage) ReadBackfillProcesses(ctx context.Context) (BackfillProcesses, error) {
	BackfillMu.Lock()
	defer BackfillMu.Unlock()

	data, err := os.ReadFile(path.Join(s.directory, "backfill_processes"))
	if err != nil {
		if os.IsNotExist(err) {
			return BackfillProcesses{}, ErrNotFound
		}

		return BackfillProcesses{}, err
	}
	var result BackfillProcesses
	err = json.Unmarshal(data, &result)
	if err != nil {
		s.log.Warn("error decoding backfill_processes", "err", err)
		return BackfillProcesses{}, ErrMarshaling
	}
	return result, nil
}

func (s *FileStorage) ReadLockfile(ctx context.Context) (Lockfile, error) {
	data, err := os.ReadFile(path.Join(s.directory, "lockfile"))
	if err != nil {
		if os.IsNotExist(err) {
			return Lockfile{}, ErrNotFound
		}

		return Lockfile{}, err
	}
	var result Lockfile
	err = json.Unmarshal(data, &result)
	if err != nil {
		s.log.Warn("error decoding lockfile", "err", err)
		return Lockfile{}, ErrMarshaling
	}
	return result, nil
}

func (s *FileStorage) WriteBackfillProcesses(_ context.Context, data BackfillProcesses) error {
	BackfillMu.Lock()
	defer BackfillMu.Unlock()

	b, err := json.Marshal(data)
	if err != nil {
		s.log.Warn("error encoding backfill_processes", "err", err)
		return ErrMarshaling
	}
	err = os.WriteFile(path.Join(s.directory, "backfill_processes"), b, 0644)
	if err != nil {
		s.log.Warn("error writing backfill_processes", "err", err)
		return err
	}

	s.log.Info("wrote backfill_processes")
	return nil
}

func (s *FileStorage) WriteLockfile(_ context.Context, data Lockfile) error {
	b, err := json.Marshal(data)
	if err != nil {
		s.log.Warn("error encoding lockfile", "err", err)
		return ErrMarshaling
	}
	err = os.WriteFile(path.Join(s.directory, "lockfile"), b, 0644)
	if err != nil {
		s.log.Warn("error writing lockfile", "err", err)
		return err
	}

	s.log.Info("wrote to lockfile", "archiverId", data.ArchiverId, "timestamp", strconv.FormatInt(data.Timestamp, 10))
	return nil
}

func (s *FileStorage) WriteBlob(_ context.Context, data BlobData) error {
	b, err := json.Marshal(data)
	if err != nil {
		s.log.Warn("error encoding blob", "err", err)
		return ErrMarshaling
	}
	err = os.WriteFile(s.fileName(data.Header.BeaconBlockHash), b, 0644)
	if err != nil {
		s.log.Warn("error writing blob", "err", err)
		return err
	}

	s.log.Info("wrote blob", "hash", data.Header.BeaconBlockHash.String())
	return nil
}

func (s *FileStorage) fileName(hash common.Hash) string {
	return path.Join(s.directory, hash.String())
}
