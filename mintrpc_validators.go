package taprootassets

import (
	"errors"
	"fmt"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
)

var (
	// ErrNilAsset is returned when a mint request has a nil asset.
	ErrNilAsset = errors.New("asset cannot be nil")

	// ErrInvalidGroupConfig is returned when group field combinations
	// are invalid.
	ErrInvalidGroupConfig = errors.New("invalid group configuration")

	// ErrDecimalDisplayForCollectible is returned when decimal display
	// is set for a collectible asset.
	ErrDecimalDisplayForCollectible = errors.New(
		"decimal display not allowed for collectibles")
)

// ValidateMintAssetRequest performs stateless validation on a mint request.
// This validates field constraints and combinations without requiring
// database access.
func ValidateMintAssetRequest(req *mintrpc.MintAssetRequest) error {
	if req == nil {
		return ErrNilRequest
	}
	if req.Asset == nil {
		return ErrNilAsset
	}

	// Validate asset name.
	if err := asset.ValidateAssetName(req.Asset.Name); err != nil {
		return fmt.Errorf("invalid asset name: %w", err)
	}

	// Validate group field combinations.
	if err := validateGroupConfig(req); err != nil {
		return err
	}

	// Decimal display not allowed for collectibles.
	if req.Asset.AssetType == taprpc.AssetType_COLLECTIBLE {
		if req.Asset.DecimalDisplay > 0 {
			return ErrDecimalDisplayForCollectible
		}
	}

	// Validate tapscript root size (must be 0 or 32 bytes).
	rootLen := len(req.Asset.GroupTapscriptRoot)
	if rootLen != 0 && rootLen != 32 {
		return fmt.Errorf("group tapscript root must be 0 or 32 bytes, "+
			"got %d", rootLen)
	}

	return nil
}

// validateGroupConfig checks that group-related fields have valid
// combinations.
func validateGroupConfig(req *mintrpc.MintAssetRequest) error {
	a := req.Asset

	// Cannot set both NewGroupedAsset and GroupedAsset.
	if a.NewGroupedAsset && a.GroupedAsset {
		return fmt.Errorf("%w: cannot set both new_grouped_asset and "+
			"grouped_asset", ErrInvalidGroupConfig)
	}

	// NewGroupedAsset cannot have group key or anchor.
	if a.NewGroupedAsset {
		if len(a.GroupKey) > 0 || a.GroupAnchor != "" {
			return fmt.Errorf("%w: new_grouped_asset cannot specify "+
				"group_key or group_anchor", ErrInvalidGroupConfig)
		}
	}

	// GroupedAsset requires exactly one of group_key or group_anchor.
	if a.GroupedAsset {
		hasKey := len(a.GroupKey) > 0
		hasAnchor := a.GroupAnchor != ""

		if !hasKey && !hasAnchor {
			return fmt.Errorf("%w: grouped_asset requires "+
				"group_key or group_anchor", ErrInvalidGroupConfig)
		}
		if hasKey && hasAnchor {
			return fmt.Errorf("%w: grouped_asset cannot specify both "+
				"group_key and group_anchor", ErrInvalidGroupConfig)
		}
	}

	return nil
}
