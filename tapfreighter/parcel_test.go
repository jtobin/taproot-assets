package tapfreighter

import (
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/stretchr/testify/require"
)

// genTestScriptKey builds a deterministic asset.ScriptKey for use in tests
// from a single byte of entropy.
func genTestScriptKey(t *testing.T, seed byte) asset.ScriptKey {
	t.Helper()

	priv, _ := btcec.PrivKeyFromBytes(append(
		make([]byte, 31), seed,
	))
	return asset.ScriptKey{PubKey: priv.PubKey()}
}

// TestLookupScriptKeyLocalOverride exercises the override lookup helper used
// by the chain porter's isLocalKey closure to short-circuit the addr-book
// lookup when a parcel carries explicit ScriptKeyLocalOverrides. The cases
// cover the three observable behaviours: nil map, hit (true/false values),
// and miss against a non-empty map.
func TestLookupScriptKeyLocalOverride(t *testing.T) {
	t.Parallel()

	keyA := genTestScriptKey(t, 0x01)
	keyB := genTestScriptKey(t, 0x02)
	keyMissing := genTestScriptKey(t, 0x03)

	overrides := map[asset.SerializedKey]bool{
		asset.ToSerialized(keyA.PubKey): true,
		asset.ToSerialized(keyB.PubKey): false,
	}

	t.Run("nil_map", func(t *testing.T) {
		t.Parallel()
		v, ok := lookupScriptKeyLocalOverride(nil, keyA)
		require.False(t, ok, "nil map must report miss")
		require.False(t, v)
	})

	t.Run("hit_true", func(t *testing.T) {
		t.Parallel()
		v, ok := lookupScriptKeyLocalOverride(overrides, keyA)
		require.True(t, ok)
		require.True(t, v)
	})

	t.Run("hit_false", func(t *testing.T) {
		t.Parallel()
		v, ok := lookupScriptKeyLocalOverride(overrides, keyB)
		require.True(t, ok)
		require.False(t, v,
			"explicit false override must be reported as such")
	})

	t.Run("miss_falls_through", func(t *testing.T) {
		t.Parallel()
		v, ok := lookupScriptKeyLocalOverride(overrides, keyMissing)
		require.False(t, ok,
			"missing key must report miss so caller falls back")
		require.False(t, v)
	})
}
