package proof

import (
	"bytes"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// TestTxMerkleProofRoundTrip tests that TxMerkleProof encode/decode form a
// valid round-trip.
func TestTxMerkleProofRoundTrip(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		// Generate random nodes (up to MerkleProofMaxNodes).
		numNodes := rapid.IntRange(0, MerkleProofMaxNodes).Draw(t, "num_nodes")

		nodes := make([]chainhash.Hash, numNodes)
		for i := 0; i < numNodes; i++ {
			var hash chainhash.Hash
			copy(hash[:], rapid.SliceOfN(
				rapid.Byte(), 32, 32,
			).Draw(t, "hash"))
			nodes[i] = hash
		}

		// Bits length should match nodes length.
		bits := make([]bool, numNodes)
		for i := 0; i < numNodes; i++ {
			bits[i] = rapid.Bool().Draw(t, "bit")
		}

		original := TxMerkleProof{
			Nodes: nodes,
			Bits:  bits,
		}

		// Encode.
		var buf bytes.Buffer
		err := original.Encode(&buf)
		require.NoError(t, err)

		// Decode.
		var decoded TxMerkleProof
		err = decoded.Decode(bytes.NewReader(buf.Bytes()))
		require.NoError(t, err)

		// Compare.
		require.Equal(t, original.Nodes, decoded.Nodes)
		require.Equal(t, original.Bits, decoded.Bits)
	})
}

// TestTapscriptProofRoundTrip tests that TapscriptProof encode/decode form a
// valid round-trip.
func TestTapscriptProofRoundTrip(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		// TapscriptProof has optional preimages and a bip86 flag.
		bip86 := rapid.Bool().Draw(t, "bip86")

		original := TapscriptProof{
			TapPreimage1: nil, // Complex to generate validly.
			TapPreimage2: nil,
			Bip86:        bip86,
		}

		// Encode.
		var buf bytes.Buffer
		err := original.Encode(&buf)
		require.NoError(t, err)

		// Decode.
		var decoded TapscriptProof
		err = decoded.Decode(bytes.NewReader(buf.Bytes()))
		require.NoError(t, err)

		// Compare.
		require.Equal(t, original.Bip86, decoded.Bip86)
	})
}

// TestProofRoundTripWithTestData tests that Proof encode/decode form a valid
// round-trip using the RandProof test helper with real test data. This is a
// property test over a fixed set of generated proofs.
func TestProofRoundTripWithTestData(t *testing.T) {
	t.Parallel()

	// Load test blocks (needed to generate valid proofs).
	testBlocks := readTestData(t)
	oddTxBlock := testBlocks[0]

	// Run multiple iterations with different random proofs.
	for i := 0; i < 20; i++ {
		genesis := asset.RandGenesis(t, asset.Type(i%2))
		scriptKey := test.RandPubKey(t)
		original := RandProof(t, genesis, scriptKey, oddTxBlock, 0, 1)

		// Encode.
		var buf bytes.Buffer
		err := original.Encode(&buf)
		require.NoError(t, err)
		originalBytes := buf.Bytes()

		// Decode.
		var decoded Proof
		err = decoded.Decode(bytes.NewReader(originalBytes))
		require.NoError(t, err)

		// Re-encode and compare bytes.
		var buf2 bytes.Buffer
		err = decoded.Encode(&buf2)
		require.NoError(t, err)

		require.Equal(t, originalBytes, buf2.Bytes(),
			"round-trip bytes mismatch for iteration %d", i)
	}
}
