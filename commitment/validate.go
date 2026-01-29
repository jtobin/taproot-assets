package commitment

import (
	"github.com/lightninglabs/taproot-assets/asset"
)

// ValidateAssetCommitmentInputs performs stateless validation on a set of
// assets before constructing an asset commitment. This checks:
// - At least one asset is provided
// - All assets share the same Type
// - All assets share the same GroupKey OR Genesis.ID (if no group key)
// - All assets have unique AssetCommitmentKeys (no duplicate script keys)
//
// This function is useful for early validation and property testing.
func ValidateAssetCommitmentInputs(assets []*asset.Asset) error {
	if len(assets) == 0 {
		return ErrNoAssets
	}

	// Extract expected values from the first asset.
	firstAsset := assets[0]
	expectedAssetType := firstAsset.Type
	expectedAssetID := firstAsset.Genesis.ID()
	expectedGroupKey := firstAsset.GroupKey

	// Track seen commitment keys for duplicate detection.
	seen := make(map[[32]byte]struct{}, len(assets))

	for idx := range assets {
		a := assets[idx]

		// Check type consistency.
		if a.Type != expectedAssetType {
			return ErrAssetTypeMismatch
		}

		// Check genesis/group key consistency.
		switch {
		case !expectedGroupKey.IsSameGroup(a.GroupKey):
			return ErrAssetGroupKeyMismatch

		case expectedGroupKey == nil:
			if expectedAssetID != a.Genesis.ID() {
				return ErrAssetGenesisMismatch
			}
		}

		// Check for duplicate script keys.
		key := a.AssetCommitmentKey()
		if _, ok := seen[key]; ok {
			return ErrAssetDuplicateScriptKey
		}
		seen[key] = struct{}{}
	}

	return nil
}
