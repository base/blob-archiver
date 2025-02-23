package storage

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/ethereum-optimism/optimism/op-service/testlog"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
	"github.com/stretchr/testify/require"
)

func setup(t *testing.T) (*FileStorage, func()) {
	logger := testlog.Logger(t, log.LvlInfo)
	tempDir, err := os.MkdirTemp("", "test")
	require.NoError(t, err)
	fs := NewFileStorage(tempDir, logger)
	return fs, func() {
		require.NoError(t, os.RemoveAll(tempDir))
	}
}

func runTestExists(t *testing.T, s DataStore) {
	id := common.Hash{1, 2, 3}

	exists, err := s.Exists(context.Background(), id)
	require.NoError(t, err)
	require.False(t, exists)

	err = s.WriteBlob(context.Background(), BlobData{
		Header: Header{
			BeaconBlockHash: id,
		},
		BlobSidecars: BlobSidecars{},
	})
	require.NoError(t, err)

	exists, err = s.Exists(context.Background(), id)
	require.NoError(t, err)
	require.True(t, exists)
}

func TestExists(t *testing.T) {
	fs, cleanup := setup(t)
	defer cleanup()

	runTestExists(t, fs)
}

func runTestRead(t *testing.T, s DataStore) {
	id := common.Hash{1, 2, 3}

	_, err := s.ReadBlob(context.Background(), id)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrNotFound))

	err = s.WriteBlob(context.Background(), BlobData{
		Header: Header{
			BeaconBlockHash: id,
		},
		BlobSidecars: BlobSidecars{},
	})
	require.NoError(t, err)

	data, err := s.ReadBlob(context.Background(), id)
	require.NoError(t, err)
	require.Equal(t, id, data.Header.BeaconBlockHash)
}

func TestRead(t *testing.T) {
	fs, cleanup := setup(t)
	defer cleanup()

	runTestRead(t, fs)
}

func TestBrokenStorage(t *testing.T) {
	fs, cleanup := setup(t)

	id := common.Hash{1, 2, 3}

	// Delete the directory to simulate broken storage
	cleanup()

	_, err := fs.ReadBlob(context.Background(), id)
	require.Error(t, err)

	exists, err := fs.Exists(context.Background(), id)
	require.False(t, exists)
	require.NoError(t, err) // No error should be returned, as in this test we've just deleted the directory

	err = fs.WriteBlob(context.Background(), BlobData{
		Header: Header{
			BeaconBlockHash: id,
		},
		BlobSidecars: BlobSidecars{},
	})
	require.Error(t, err)
}

func TestReadInvalidData(t *testing.T) {
	fs, cleanup := setup(t)
	defer cleanup()

	id := common.Hash{1, 2, 3}

	err := os.WriteFile(fs.fileName(id), []byte("invalid json"), 0644)
	require.NoError(t, err)

	_, err = fs.ReadBlob(context.Background(), id)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrMarshaling))
}
