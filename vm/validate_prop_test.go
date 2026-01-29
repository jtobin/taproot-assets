package vm

import (
	"errors"
	"testing"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// requireErrorKind asserts that err is a VM Error with the given kind.
func requireErrorKind(t require.TestingT, err error, kind ErrorKind) {
	var vmErr Error
	require.True(t, errors.As(err, &vmErr), "expected vm.Error, got %T", err)
	require.Equal(t, kind, vmErr.Kind)
}

// TestMatchesPrevGenesis_SameGenesis tests that assets with the same genesis
// ID always match.
func TestMatchesPrevGenesis_SameGenesis(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		genesis := asset.GenesisGen.Draw(t, "genesis")
		scriptKey := asset.ScriptKeyGen.Draw(t, "scriptKey")

		prevAsset := asset.AssetGenWithValues(t, genesis, nil, scriptKey)

		// Same genesis ID should always match.
		result := MatchesPrevGenesis(
			genesis.ID(), nil, genesis.Tag, prevAsset,
		)
		require.True(t, result)
	})
}

// TestMatchesPrevGenesis_DifferentGenesis tests that assets with different
// genesis IDs and no group key don't match.
func TestMatchesPrevGenesis_DifferentGenesis(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		genesis1 := asset.GenesisGen.Draw(t, "genesis1")
		genesis2 := asset.GenesisGen.Draw(t, "genesis2")

		// Ensure different genesis IDs.
		if genesis1.ID() == genesis2.ID() {
			return // Skip this iteration
		}

		scriptKey := asset.ScriptKeyGen.Draw(t, "scriptKey")
		prevAsset := asset.AssetGenWithValues(t, genesis1, nil, scriptKey)

		// Different genesis ID without group key should not match.
		result := MatchesPrevGenesis(
			genesis2.ID(), nil, genesis2.Tag, prevAsset,
		)
		require.False(t, result)
	})
}

// TestMatchesAssetParams_TypeMismatch tests that assets with different types
// are rejected.
func TestMatchesAssetParams_TypeMismatch(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		genesis := asset.GenesisGen.Draw(t, "genesis")
		scriptKey := asset.ScriptKeyGen.Draw(t, "scriptKey")

		prevAsset := asset.AssetGenWithValues(t, genesis, nil, scriptKey)

		// Create new asset with opposite type.
		var newType asset.Type
		if prevAsset.Type == asset.Normal {
			newType = asset.Collectible
		} else {
			newType = asset.Normal
		}

		newGenesis := genesis
		newGenesis.Type = newType
		newAsset := asset.AssetGenWithValues(t, newGenesis, nil, scriptKey)

		// Create a witness pointing to the prev asset.
		witness := &asset.Witness{
			PrevID: &asset.PrevID{
				ID:        genesis.ID(),
				ScriptKey: asset.ToSerialized(scriptKey.PubKey),
			},
		}

		err := MatchesAssetParams(newAsset, prevAsset, witness)
		requireErrorKind(t, err, ErrTypeMismatch)
	})
}

// TestMatchesAssetParams_ScriptKeyMismatch tests that a witness with wrong
// script key is rejected.
func TestMatchesAssetParams_ScriptKeyMismatch(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		genesis := asset.GenesisGen.Draw(t, "genesis")
		scriptKey1 := asset.ScriptKeyGen.Draw(t, "scriptKey1")
		scriptKey2 := asset.ScriptKeyGen.Draw(t, "scriptKey2")

		// Ensure different script keys.
		if asset.ToSerialized(scriptKey1.PubKey) ==
			asset.ToSerialized(scriptKey2.PubKey) {

			return
		}

		prevAsset := asset.AssetGenWithValues(t, genesis, nil, scriptKey1)
		newAsset := asset.AssetGenWithValues(t, genesis, nil, scriptKey1)

		// Witness points to wrong script key.
		witness := &asset.Witness{
			PrevID: &asset.PrevID{
				ID:        genesis.ID(),
				ScriptKey: asset.ToSerialized(scriptKey2.PubKey),
			},
		}

		err := MatchesAssetParams(newAsset, prevAsset, witness)
		requireErrorKind(t, err, ErrScriptKeyMismatch)
	})
}

// TestMatchesAssetParams_ValidTransition tests that valid state transitions
// pass validation.
func TestMatchesAssetParams_ValidTransition(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		genesis := asset.GenesisGen.Draw(t, "genesis")
		scriptKey := asset.ScriptKeyGen.Draw(t, "scriptKey")

		prevAsset := asset.AssetGenWithValues(t, genesis, nil, scriptKey)
		newAsset := asset.AssetGenWithValues(t, genesis, nil, scriptKey)

		// Witness correctly references prev asset.
		witness := &asset.Witness{
			PrevID: &asset.PrevID{
				ID:        genesis.ID(),
				ScriptKey: asset.ToSerialized(scriptKey.PubKey),
			},
		}

		err := MatchesAssetParams(newAsset, prevAsset, witness)
		require.NoError(t, err)
	})
}
