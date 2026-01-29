package commitment

import (
	"github.com/lightninglabs/taproot-assets/asset"
)

// ValidateSplitAmounts checks that the sum of split locator amounts equals
// the total input amount. This enforces the fundamental conservation invariant
// that prevents asset inflation.
func ValidateSplitAmounts(inputs []SplitCommitmentInput,
	rootLocator *SplitLocator,
	externalLocators []*SplitLocator) error {

	// Calculate sum total input amounts.
	totalInputAmount := uint64(0)
	for idx := range inputs {
		totalInputAmount += inputs[idx].Asset.Amount
	}

	// Calculate sum total output amounts.
	totalOutputAmount := rootLocator.Amount
	for _, loc := range externalLocators {
		totalOutputAmount += loc.Amount
	}

	// The amounts must match exactly.
	if totalInputAmount != totalOutputAmount {
		return ErrInvalidSplitAmount
	}

	return nil
}

// ValidateRootLocator checks the NUMS key constraints for a root locator:
// - If amount is 0, the script key must be the NUMS (unspendable) key
// - If the script key is NUMS, the amount must be 0
func ValidateRootLocator(root *SplitLocator) error {
	// Zero amount requires NUMS key.
	if root.Amount == 0 && root.ScriptKey != asset.NUMSCompressedKey {
		return ErrInvalidScriptKey
	}

	// NUMS key requires zero amount.
	if root.Amount != 0 && root.ScriptKey == asset.NUMSCompressedKey {
		return ErrNonZeroSplitAmount
	}

	return nil
}

// ValidateExternalLocators checks that external (non-root) locators have
// non-zero amounts.
func ValidateExternalLocators(locators []*SplitLocator) error {
	for _, loc := range locators {
		if loc.Amount == 0 {
			return ErrZeroSplitAmount
		}
	}
	return nil
}

// ValidateSplitLocatorIndices checks that all split locators have unique
// output indices.
func ValidateSplitLocatorIndices(rootLocator *SplitLocator,
	externalLocators []*SplitLocator) error {

	seen := make(map[uint32]struct{})
	seen[rootLocator.OutputIndex] = struct{}{}

	for _, loc := range externalLocators {
		if _, ok := seen[loc.OutputIndex]; ok {
			return ErrDuplicateSplitOutputIndex
		}
		seen[loc.OutputIndex] = struct{}{}
	}

	return nil
}

// ValidateCollectibleSplit checks collectible-specific split constraints:
// - Root amount must be 0 (fully spent)
// - Exactly one external locator
func ValidateCollectibleSplit(rootLocator *SplitLocator,
	externalLocators []*SplitLocator) error {

	if rootLocator.Amount != 0 {
		return ErrNonZeroSplitAmount
	}

	if len(externalLocators) != 1 {
		return ErrInvalidSplitLocatorCount
	}

	return nil
}

// ValidateSplitCommitmentParams performs all stateless validation on split
// commitment parameters before tree construction. This is useful for early
// error detection and property testing.
func ValidateSplitCommitmentParams(inputs []SplitCommitmentInput,
	rootLocator *SplitLocator,
	externalLocators []*SplitLocator) error {

	if len(inputs) == 0 {
		return ErrInvalidSplitLocator
	}

	if len(externalLocators) == 0 {
		return ErrInvalidSplitLocator
	}

	// Validate root locator NUMS key constraints.
	if err := ValidateRootLocator(rootLocator); err != nil {
		return err
	}

	// Validate external locators have non-zero amounts.
	if err := ValidateExternalLocators(externalLocators); err != nil {
		return err
	}

	// Validate unique output indices.
	if err := ValidateSplitLocatorIndices(rootLocator, externalLocators); err != nil {
		return err
	}

	// Validate amount conservation.
	if err := ValidateSplitAmounts(inputs, rootLocator, externalLocators); err != nil {
		return err
	}

	// Validate collectible-specific constraints if applicable.
	if inputs[0].Asset.Type == asset.Collectible {
		if err := ValidateCollectibleSplit(rootLocator, externalLocators); err != nil {
			return err
		}
	}

	return nil
}
