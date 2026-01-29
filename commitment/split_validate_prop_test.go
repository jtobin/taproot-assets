package commitment

import (
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// genSerializedKey generates a random serialized public key.
func genSerializedKey(t *rapid.T) asset.SerializedKey {
	privKeyBytes := rapid.SliceOfN(rapid.Byte(), 32, 32).Draw(t, "privKey")
	privKey, _ := btcec.PrivKeyFromBytes(privKeyBytes)
	return asset.ToSerialized(privKey.PubKey())
}

// genAssetID generates a random asset ID.
func genAssetID(t *rapid.T) asset.ID {
	var id asset.ID
	copy(id[:], rapid.SliceOfN(rapid.Byte(), 32, 32).Draw(t, "assetID"))
	return id
}

// genSplitLocator generates a split locator with the given amount.
func genSplitLocator(t *rapid.T, amount uint64, outputIdx uint32) *SplitLocator {
	return &SplitLocator{
		OutputIndex: outputIdx,
		AssetID:     genAssetID(t),
		ScriptKey:   genSerializedKey(t),
		Amount:      amount,
	}
}

// genSplitInput generates a split commitment input with the given amount.
func genSplitInput(t *rapid.T, amount uint64, assetType asset.Type) SplitCommitmentInput {
	return SplitCommitmentInput{
		Asset: &asset.Asset{
			Amount: amount,
			Genesis: asset.Genesis{
				Type: assetType,
			},
		},
		OutPoint: wire.OutPoint{
			Index: rapid.Uint32().Draw(t, "outIdx"),
		},
	}
}

// TestValidateSplitAmounts_Conservation tests that valid splits (where
// input equals output) pass validation.
func TestValidateSplitAmounts_Conservation(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		// Generate an input amount.
		inputAmt := rapid.Uint64Range(1, 1_000_000).Draw(t, "inputAmt")

		// Generate a root amount (0 to inputAmt).
		rootAmt := rapid.Uint64Range(0, inputAmt).Draw(t, "rootAmt")
		externalAmt := inputAmt - rootAmt

		// Create inputs and locators.
		inputs := []SplitCommitmentInput{
			genSplitInput(t, inputAmt, asset.Normal),
		}
		rootLocator := genSplitLocator(t, rootAmt, 0)

		// Set NUMS key if root amount is 0.
		if rootAmt == 0 {
			rootLocator.ScriptKey = asset.NUMSCompressedKey
		}

		externalLocators := []*SplitLocator{
			genSplitLocator(t, externalAmt, 1),
		}

		// Validation should pass.
		err := ValidateSplitAmounts(inputs, rootLocator, externalLocators)
		require.NoError(t, err)
	})
}

// TestValidateSplitAmounts_RejectsInflation tests that splits where
// output exceeds input are rejected.
func TestValidateSplitAmounts_RejectsInflation(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		// Generate an input amount.
		inputAmt := rapid.Uint64Range(1, 1_000_000).Draw(t, "inputAmt")

		// Generate an output that exceeds input.
		outputAmt := inputAmt + rapid.Uint64Range(1, 1000).Draw(t, "excess")

		inputs := []SplitCommitmentInput{
			genSplitInput(t, inputAmt, asset.Normal),
		}
		rootLocator := genSplitLocator(t, 0, 0)
		rootLocator.ScriptKey = asset.NUMSCompressedKey

		externalLocators := []*SplitLocator{
			genSplitLocator(t, outputAmt, 1),
		}

		// Validation should fail.
		err := ValidateSplitAmounts(inputs, rootLocator, externalLocators)
		require.ErrorIs(t, err, ErrInvalidSplitAmount)
	})
}

// TestValidateRootLocator_NUMSKeyConstraint tests the NUMS key constraints.
func TestValidateRootLocator_NUMSKeyConstraint(t *testing.T) {
	t.Parallel()

	// Zero amount with random key should fail.
	t.Run("zero_amount_random_key", func(t *testing.T) {
		rapid.Check(t, func(t *rapid.T) {
			root := genSplitLocator(t, 0, 0)
			// Random key, not NUMS.
			err := ValidateRootLocator(root)
			require.ErrorIs(t, err, ErrInvalidScriptKey)
		})
	})

	// Zero amount with NUMS key should pass.
	t.Run("zero_amount_nums_key", func(t *testing.T) {
		root := &SplitLocator{
			Amount:    0,
			ScriptKey: asset.NUMSCompressedKey,
		}
		err := ValidateRootLocator(root)
		require.NoError(t, err)
	})

	// Non-zero amount with NUMS key should fail.
	t.Run("nonzero_amount_nums_key", func(t *testing.T) {
		rapid.Check(t, func(t *rapid.T) {
			amt := rapid.Uint64Min(1).Draw(t, "amt")
			root := &SplitLocator{
				Amount:    amt,
				ScriptKey: asset.NUMSCompressedKey,
			}
			err := ValidateRootLocator(root)
			require.ErrorIs(t, err, ErrNonZeroSplitAmount)
		})
	})

	// Non-zero amount with random key should pass.
	t.Run("nonzero_amount_random_key", func(t *testing.T) {
		rapid.Check(t, func(t *rapid.T) {
			amt := rapid.Uint64Min(1).Draw(t, "amt")
			root := genSplitLocator(t, amt, 0)
			err := ValidateRootLocator(root)
			require.NoError(t, err)
		})
	})
}

// TestValidateExternalLocators_RejectsZeroAmount tests that external
// locators with zero amount are rejected.
func TestValidateExternalLocators_RejectsZeroAmount(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		// Create some valid locators.
		numValid := rapid.IntRange(0, 3).Draw(t, "numValid")
		locators := make([]*SplitLocator, numValid+1)

		for i := 0; i < numValid; i++ {
			amt := rapid.Uint64Min(1).Draw(t, "amt")
			locators[i] = genSplitLocator(t, amt, uint32(i))
		}

		// Add a zero-amount locator.
		locators[numValid] = genSplitLocator(t, 0, uint32(numValid))

		err := ValidateExternalLocators(locators)
		require.ErrorIs(t, err, ErrZeroSplitAmount)
	})
}

// TestValidateSplitLocatorIndices_RejectsDuplicates tests that duplicate
// output indices are rejected.
func TestValidateSplitLocatorIndices_RejectsDuplicates(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		idx := rapid.Uint32Range(0, 100).Draw(t, "idx")

		root := genSplitLocator(t, 100, idx)
		external := []*SplitLocator{
			genSplitLocator(t, 50, idx), // Same index as root
		}

		err := ValidateSplitLocatorIndices(root, external)
		require.ErrorIs(t, err, ErrDuplicateSplitOutputIndex)
	})
}

// TestValidateCollectibleSplit tests collectible-specific constraints.
func TestValidateCollectibleSplit(t *testing.T) {
	t.Parallel()

	// Non-zero root amount should fail.
	t.Run("nonzero_root", func(t *testing.T) {
		rapid.Check(t, func(t *rapid.T) {
			amt := rapid.Uint64Min(1).Draw(t, "amt")
			root := genSplitLocator(t, amt, 0)
			external := []*SplitLocator{genSplitLocator(t, 1, 1)}

			err := ValidateCollectibleSplit(root, external)
			require.ErrorIs(t, err, ErrNonZeroSplitAmount)
		})
	})

	// Multiple external locators should fail.
	t.Run("multiple_external", func(t *testing.T) {
		root := &SplitLocator{Amount: 0, OutputIndex: 0}
		external := []*SplitLocator{
			{Amount: 1, OutputIndex: 1},
			{Amount: 1, OutputIndex: 2},
		}

		err := ValidateCollectibleSplit(root, external)
		require.ErrorIs(t, err, ErrInvalidSplitLocatorCount)
	})

	// Valid collectible split should pass.
	t.Run("valid", func(t *testing.T) {
		root := &SplitLocator{Amount: 0, OutputIndex: 0}
		external := []*SplitLocator{{Amount: 1, OutputIndex: 1}}

		err := ValidateCollectibleSplit(root, external)
		require.NoError(t, err)
	})
}

// TestValidateSplitCommitmentParams_IntegratedValidation tests the full
// validation function.
func TestValidateSplitCommitmentParams_IntegratedValidation(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		// Generate a valid split for normal asset.
		inputAmt := rapid.Uint64Range(2, 1_000_000).Draw(t, "inputAmt")
		rootAmt := rapid.Uint64Range(1, inputAmt-1).Draw(t, "rootAmt")
		externalAmt := inputAmt - rootAmt

		inputs := []SplitCommitmentInput{
			genSplitInput(t, inputAmt, asset.Normal),
		}
		rootLocator := genSplitLocator(t, rootAmt, 0)
		externalLocators := []*SplitLocator{
			genSplitLocator(t, externalAmt, 1),
		}

		err := ValidateSplitCommitmentParams(inputs, rootLocator, externalLocators)
		require.NoError(t, err)
	})
}
