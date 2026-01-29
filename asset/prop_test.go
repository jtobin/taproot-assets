package asset

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// TestAssetEncodingRoundTrip tests that Asset encode/decode form a valid
// round-trip for randomly generated assets. The invariant tested is that
// re-encoding a decoded asset produces identical bytes.
func TestAssetEncodingRoundTrip(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		original := AssetGen.Draw(t, "asset")

		// Encode.
		var buf bytes.Buffer
		err := original.Encode(&buf)
		require.NoError(t, err)
		originalBytes := buf.Bytes()

		// Decode.
		var decoded Asset
		err = decoded.Decode(bytes.NewReader(originalBytes))
		require.NoError(t, err)

		// Re-encode the decoded asset.
		var buf2 bytes.Buffer
		err = decoded.Encode(&buf2)
		require.NoError(t, err)

		// Compare bytes: decode(encode(x)).encode() == encode(x)
		require.Equal(t, originalBytes, buf2.Bytes())
	})
}

// TestGenesisEncodingRoundTrip tests that Genesis encode/decode form a valid
// round-trip.
func TestGenesisEncodingRoundTrip(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		original := GenesisGen.Draw(t, "genesis")

		// Encode.
		var buf bytes.Buffer
		var tlvBuf [8]byte
		err := GenesisEncoder(&buf, &original, &tlvBuf)
		require.NoError(t, err)

		// Decode.
		var decoded Genesis
		err = GenesisDecoder(
			bytes.NewReader(buf.Bytes()), &decoded, &tlvBuf, 0,
		)
		require.NoError(t, err)

		// Compare.
		require.Equal(t, original, decoded)
	})
}

// TestWitnessEncodingRoundTrip tests that Witness encode/decode form a valid
// round-trip.
func TestWitnessEncodingRoundTrip(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		original := WitnessGen.Draw(t, "witness")

		// Encode.
		var buf bytes.Buffer
		err := original.Encode(&buf)
		require.NoError(t, err)

		// Decode.
		var decoded Witness
		err = decoded.Decode(bytes.NewReader(buf.Bytes()))
		require.NoError(t, err)

		// Compare PrevID.
		if original.PrevID == nil {
			require.Nil(t, decoded.PrevID)
		} else {
			require.NotNil(t, decoded.PrevID)
			require.Equal(t, *original.PrevID, *decoded.PrevID)
		}

		// Compare TxWitness.
		require.Equal(t, len(original.TxWitness), len(decoded.TxWitness))
		for i := range original.TxWitness {
			require.Equal(t, original.TxWitness[i], decoded.TxWitness[i])
		}
	})
}
