package mssmt_test

import (
	"bytes"
	"testing"

	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// TestBitPackingRoundTrip tests that bit packing and unpacking form a
// round-trip for arbitrary bit slices. Note that UnpackBits always returns
// a slice whose length is a multiple of 8, so we compare only the prefix
// corresponding to the original input length.
func TestBitPackingRoundTrip(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		bits := rapid.SliceOf(rapid.Bool()).Draw(t, "bits")

		packed := mssmt.PackBits(bits)
		unpacked := mssmt.UnpackBits(packed)

		// The unpacked slice is padded to a multiple of 8 bits.
		// Verify the prefix matches the original.
		require.GreaterOrEqual(t, len(unpacked), len(bits))
		require.Equal(t, bits, unpacked[:len(bits)])

		// Verify the padding bits are all false.
		for _, bit := range unpacked[len(bits):] {
			require.False(t, bit)
		}
	})
}

// TestCompressedProofRoundTrip tests that CompressedProof encode/decode
// form a valid round-trip.
func TestCompressedProofRoundTrip(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		// Generate a random compressed proof with up to 256 nodes.
		numNodes := rapid.IntRange(0, 256).Draw(t, "num_nodes")

		nodes := make([]mssmt.Node, numNodes)
		for i := 0; i < numNodes; i++ {
			var hash [32]byte
			copy(hash[:], rapid.SliceOfN(
				rapid.Byte(), 32, 32,
			).Draw(t, "hash"))

			sum := rapid.Uint64().Draw(t, "sum")
			nodes[i] = mssmt.NewComputedNode(
				mssmt.NodeHash(hash), sum,
			)
		}

		// Bits must be exactly MaxTreeLevels (256) for decode.
		bits := make([]bool, mssmt.MaxTreeLevels)
		for i := 0; i < mssmt.MaxTreeLevels; i++ {
			bits[i] = rapid.Bool().Draw(t, "bit")
		}

		original := &mssmt.CompressedProof{
			Nodes: nodes,
			Bits:  bits,
		}

		// Encode.
		var buf bytes.Buffer
		err := original.Encode(&buf)
		require.NoError(t, err)

		// Decode.
		var decoded mssmt.CompressedProof
		err = decoded.Decode(bytes.NewReader(buf.Bytes()))
		require.NoError(t, err)

		// Compare.
		require.Equal(t, len(original.Nodes), len(decoded.Nodes))
		for i, node := range original.Nodes {
			require.True(t, mssmt.IsEqualNode(node, decoded.Nodes[i]))
		}
		require.Equal(t, original.Bits, decoded.Bits)
	})
}
