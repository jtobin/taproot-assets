package commitment

import (
	"testing"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// TestValidateAssetCommitmentInputs_SingleAsset tests that a single asset
// always passes validation.
func TestValidateAssetCommitmentInputs_SingleAsset(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		a := asset.AssetGen.Draw(t, "asset")
		err := ValidateAssetCommitmentInputs([]*asset.Asset{&a})
		require.NoError(t, err)
	})
}

// TestValidateAssetCommitmentInputs_RejectsEmpty tests that empty input
// is rejected.
func TestValidateAssetCommitmentInputs_RejectsEmpty(t *testing.T) {
	t.Parallel()

	err := ValidateAssetCommitmentInputs([]*asset.Asset{})
	require.ErrorIs(t, err, ErrNoAssets)

	err = ValidateAssetCommitmentInputs(nil)
	require.ErrorIs(t, err, ErrNoAssets)
}

// TestValidateAssetCommitmentInputs_SameGenesis tests that assets with the
// same genesis (no group key) pass validation.
func TestValidateAssetCommitmentInputs_SameGenesis(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		genesis := asset.GenesisGen.Draw(t, "genesis")

		// Generate 2-4 assets with same genesis but different keys.
		numAssets := rapid.IntRange(2, 4).Draw(t, "numAssets")
		assets := make([]*asset.Asset, numAssets)

		for i := 0; i < numAssets; i++ {
			scriptKey := asset.ScriptKeyGen.Draw(t, "scriptKey")
			assets[i] = asset.AssetGenWithValues(
				t, genesis, nil, scriptKey,
			)
		}

		err := ValidateAssetCommitmentInputs(assets)
		require.NoError(t, err)
	})
}

// TestValidateAssetCommitmentInputs_RejectsMismatchedGenesis tests that
// assets with different genesis IDs (and no group key) are rejected.
func TestValidateAssetCommitmentInputs_RejectsMismatchedGenesis(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		genesis1 := asset.GenesisGen.Draw(t, "genesis1")
		genesis2 := asset.GenesisGen.Draw(t, "genesis2")

		// Skip if same genesis ID.
		if genesis1.ID() == genesis2.ID() {
			return
		}

		// Ensure same type to isolate the genesis check.
		genesis2.Type = genesis1.Type

		scriptKey1 := asset.ScriptKeyGen.Draw(t, "scriptKey1")
		scriptKey2 := asset.ScriptKeyGen.Draw(t, "scriptKey2")

		a1 := asset.AssetGenWithValues(t, genesis1, nil, scriptKey1)
		a2 := asset.AssetGenWithValues(t, genesis2, nil, scriptKey2)

		err := ValidateAssetCommitmentInputs([]*asset.Asset{a1, a2})
		require.ErrorIs(t, err, ErrAssetGenesisMismatch)
	})
}

// TestValidateAssetCommitmentInputs_RejectsTypeMismatch tests that assets
// with different types are rejected.
func TestValidateAssetCommitmentInputs_RejectsTypeMismatch(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		genesis := asset.GenesisGen.Draw(t, "genesis")

		scriptKey1 := asset.ScriptKeyGen.Draw(t, "scriptKey1")
		scriptKey2 := asset.ScriptKeyGen.Draw(t, "scriptKey2")

		// Create first asset.
		a1 := asset.AssetGenWithValues(t, genesis, nil, scriptKey1)

		// Create second asset with different type.
		genesis2 := genesis
		if genesis.Type == asset.Normal {
			genesis2.Type = asset.Collectible
		} else {
			genesis2.Type = asset.Normal
		}
		a2 := asset.AssetGenWithValues(t, genesis2, nil, scriptKey2)

		err := ValidateAssetCommitmentInputs([]*asset.Asset{a1, a2})
		require.ErrorIs(t, err, ErrAssetTypeMismatch)
	})
}

// TestValidateAssetCommitmentInputs_RejectsDuplicateScriptKey tests that
// assets with duplicate script keys are rejected.
func TestValidateAssetCommitmentInputs_RejectsDuplicateScriptKey(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		genesis := asset.GenesisGen.Draw(t, "genesis")
		scriptKey := asset.ScriptKeyGen.Draw(t, "scriptKey")

		// Two assets with same script key.
		a1 := asset.AssetGenWithValues(t, genesis, nil, scriptKey)
		a2 := asset.AssetGenWithValues(t, genesis, nil, scriptKey)

		// Different amounts to make them distinct objects.
		a1.Amount = 100
		a2.Amount = 200

		err := ValidateAssetCommitmentInputs([]*asset.Asset{a1, a2})
		require.ErrorIs(t, err, ErrAssetDuplicateScriptKey)
	})
}
