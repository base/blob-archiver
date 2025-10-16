package blobtest

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	gokzg4844 "github.com/crate-crypto/go-kzg-4844"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
)

// BLS12-381 field modulus (as a big-endian byte array)
// This is the prime field modulus used by BLS12-381
// In decimal: 52435875175126190479447740508185965837690552500527637822603658699938581184513
var fieldModulus = [32]byte{
	0x73, 0xed, 0xa7, 0x53, 0x29, 0xd7, 0xd4, 0x69, 0x5e, 0x7f, 0x6e, 0x0f, 0xf9, 0xd7, 0xfb, 0xd8,
	0xc4, 0xb9, 0x35, 0x6d, 0x47, 0x19, 0xb7, 0x01, 0x8b, 0x0c, 0x6c, 0x6f, 0xd9, 0x52, 0x53, 0x73,
}

var (
	OriginBlock = common.Hash{9, 9, 9, 9, 9}
	One         = common.Hash{1}
	Two         = common.Hash{2}
	Three       = common.Hash{3}
	Four        = common.Hash{4}
	Five        = common.Hash{5}
	Six         = common.Hash{6}
	Seven       = common.Hash{7}

	StartSlot = uint64(10)
	EndSlot   = uint64(15)
)

func RandBytes(t *testing.T, size uint) []byte {
	randomBytes := make([]byte, size)
	_, err := rand.Read(randomBytes)
	require.NoError(t, err)
	return randomBytes
}

// NewBlobSidecars creates blob sidecars with valid KZG commitments and proofs.
// This generates blob data that respects BLS12-381 field constraints: each 32-byte
// chunk must be less than the field modulus to be a valid field element.
// The blob data is cryptographically valid and will work with KZG operations.
// If signedHeader is provided, it will be used for all sidecars; otherwise an empty header is created.
func NewBlobSidecars(t *testing.T, count uint, signedHeader *phase0.SignedBeaconBlockHeader) []*deneb.BlobSidecar {
	kzgCtx, err := gokzg4844.NewContext4096Secure()
	require.NoError(t, err)

	// BLS12-381 field modulus as a big.Int
	fieldModulusBig := new(big.Int).SetBytes(fieldModulus[:])

	// Use provided header or create empty one
	if signedHeader == nil {
		signedHeader = &phase0.SignedBeaconBlockHeader{
			Message: &phase0.BeaconBlockHeader{},
		}
	}

	result := make([]*deneb.BlobSidecar, count)
	for i := uint(0); i < count; i++ {
		var blob deneb.Blob

		// Generate blob data where each 32-byte field element is less than the field modulus
		// This ensures valid KZG operations
		for j := 0; j < len(blob); j += 32 {
			// Generate random bytes for this field element
			randomBytes := RandBytes(t, 32)

			// Convert to big.Int and reduce modulo field modulus
			randomBig := new(big.Int).SetBytes(randomBytes)
			reduced := new(big.Int).Mod(randomBig, fieldModulusBig)

			// Convert back to 32-byte representation (zero-padded)
			reducedBytes := reduced.Bytes()
			if len(reducedBytes) < 32 {
				// Pad with leading zeros
				paddedBytes := make([]byte, 32)
				copy(paddedBytes[32-len(reducedBytes):], reducedBytes)
				copy(blob[j:j+32], paddedBytes[:])
			} else {
				copy(blob[j:j+32], reducedBytes[:32])
			}
		}

		// Now compute KZG commitment from this valid blob data
		kzgBlob := (*gokzg4844.Blob)(&blob)
		commitment, err := kzgCtx.BlobToKZGCommitment(kzgBlob, 0)
		require.NoError(t, err, "failed to compute KZG commitment for blob %d", i)

		// Compute KZG proof
		proof, err := kzgCtx.ComputeBlobKZGProof(kzgBlob, commitment, 0)
		require.NoError(t, err, "failed to compute KZG proof for blob %d", i)

		result[i] = &deneb.BlobSidecar{
			Index:             deneb.BlobIndex(i),
			Blob:              blob,
			KZGCommitment:     deneb.KZGCommitment(commitment),
			KZGProof:          deneb.KZGProof(proof),
			SignedBlockHeader: signedHeader,
		}
	}
	return result
}
