package tapgarden

import (
	"testing"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// genValidAssetName generates a valid asset name (non-empty, reasonable size).
func genValidAssetName(t *rapid.T) string {
	// Asset names must be non-empty and have reasonable length.
	length := rapid.IntRange(1, 64).Draw(t, "nameLength")
	chars := rapid.SliceOfN(
		rapid.ByteRange('a', 'z'), length, length,
	).Draw(t, "nameChars")
	return string(chars)
}

// genValidMeta generates valid (possibly nil) metadata.
func genValidMeta(t *rapid.T) *proof.MetaReveal {
	hasData := rapid.Bool().Draw(t, "hasMeta")
	if !hasData {
		return nil
	}

	dataLen := rapid.IntRange(0, 100).Draw(t, "metaLen")
	data := rapid.SliceOfN(rapid.Byte(), dataLen, dataLen).Draw(t, "metaData")

	return &proof.MetaReveal{
		Data: data,
	}
}

// TestValidateSeedling_ValidInputs tests that valid seedlings pass validation.
func TestValidateSeedling_ValidInputs(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		// Generate a valid asset type (Normal or Collectible).
		assetTypeInt := rapid.IntRange(0, 1).Draw(t, "assetType")
		assetType := asset.Type(assetTypeInt)

		// Generate a valid amount (non-zero).
		amount := rapid.Uint64Min(1).Draw(t, "amount")

		seedling := &Seedling{
			AssetName: genValidAssetName(t),
			AssetType: assetType,
			Amount:    amount,
			Meta:      genValidMeta(t),
		}

		err := ValidateSeedling(seedling)
		require.NoError(t, err)
	})
}

// TestValidateSeedling_RejectsZeroAmount tests that seedlings with zero
// amount are rejected.
func TestValidateSeedling_RejectsZeroAmount(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		assetTypeInt := rapid.IntRange(0, 1).Draw(t, "assetType")
		assetType := asset.Type(assetTypeInt)

		seedling := &Seedling{
			AssetName: genValidAssetName(t),
			AssetType: assetType,
			Amount:    0, // Invalid: zero amount
			Meta:      genValidMeta(t),
		}

		err := ValidateSeedling(seedling)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidAssetAmt)
	})
}

// TestValidateSeedling_RejectsInvalidAssetType tests that seedlings with
// invalid asset types are rejected.
func TestValidateSeedling_RejectsInvalidAssetType(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		// Generate an invalid asset type (>= 2).
		invalidType := asset.Type(rapid.IntRange(2, 255).Draw(t, "type"))

		seedling := &Seedling{
			AssetName: genValidAssetName(t),
			AssetType: invalidType,
			Amount:    rapid.Uint64Min(1).Draw(t, "amount"),
			Meta:      genValidMeta(t),
		}

		err := ValidateSeedling(seedling)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidAssetType)
	})
}

// TestValidateSeedling_RejectsEmptyName tests that seedlings with empty names
// are rejected.
func TestValidateSeedling_RejectsEmptyName(t *testing.T) {
	t.Parallel()

	seedling := &Seedling{
		AssetName: "", // Invalid: empty name
		AssetType: asset.Normal,
		Amount:    1000,
	}

	err := ValidateSeedling(seedling)
	require.Error(t, err)
}

// TestValidateSeedling_RejectsInvalidTapscriptRoot tests that seedlings with
// invalid tapscript root sizes are rejected.
func TestValidateSeedling_RejectsInvalidTapscriptRoot(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		// Generate an invalid tapscript root size (not 0 or 32).
		invalidSizes := []int{1, 16, 31, 33, 64}
		sizeIdx := rapid.IntRange(0, len(invalidSizes)-1).Draw(t, "idx")
		size := invalidSizes[sizeIdx]

		tapscriptRoot := rapid.SliceOfN(
			rapid.Byte(), size, size,
		).Draw(t, "root")

		seedling := &Seedling{
			AssetName:          genValidAssetName(t),
			AssetType:          asset.Normal,
			Amount:             1000,
			GroupTapscriptRoot: tapscriptRoot,
		}

		err := ValidateSeedling(seedling)
		require.Error(t, err)
	})
}

// TestValidateSeedling_AcceptsValidTapscriptRoot tests that seedlings with
// valid tapscript root sizes (0 or 32 bytes) are accepted.
func TestValidateSeedling_AcceptsValidTapscriptRoot(t *testing.T) {
	t.Parallel()

	// Test with empty tapscript root.
	seedling := &Seedling{
		AssetName:          "test-asset",
		AssetType:          asset.Normal,
		Amount:             1000,
		GroupTapscriptRoot: nil,
	}
	err := ValidateSeedling(seedling)
	require.NoError(t, err)

	// Test with 32-byte tapscript root.
	seedling.GroupTapscriptRoot = make([]byte, 32)
	err = ValidateSeedling(seedling)
	require.NoError(t, err)
}
