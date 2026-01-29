package taprootassets

import (
	"testing"

	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// TestValidateMintAssetRequest_NilRequest tests that nil requests are rejected.
func TestValidateMintAssetRequest_NilRequest(t *testing.T) {
	t.Parallel()

	err := ValidateMintAssetRequest(nil)
	require.ErrorIs(t, err, ErrNilRequest)
}

// TestValidateMintAssetRequest_NilAsset tests that requests with nil asset
// are rejected.
func TestValidateMintAssetRequest_NilAsset(t *testing.T) {
	t.Parallel()

	err := ValidateMintAssetRequest(&mintrpc.MintAssetRequest{
		Asset: nil,
	})
	require.ErrorIs(t, err, ErrNilAsset)
}

// TestValidateMintAssetRequest_RejectsBothGroupFlags tests that setting both
// NewGroupedAsset and GroupedAsset is rejected.
func TestValidateMintAssetRequest_RejectsBothGroupFlags(t *testing.T) {
	t.Parallel()

	req := &mintrpc.MintAssetRequest{
		Asset: &mintrpc.MintAsset{
			Name:            "test-asset",
			NewGroupedAsset: true,
			GroupedAsset:    true,
		},
	}
	err := ValidateMintAssetRequest(req)
	require.ErrorIs(t, err, ErrInvalidGroupConfig)
}

// TestValidateMintAssetRequest_RejectsNewGroupWithKey tests that
// NewGroupedAsset with group_key is rejected.
func TestValidateMintAssetRequest_RejectsNewGroupWithKey(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		keyLen := rapid.IntRange(1, 64).Draw(t, "keyLen")
		groupKey := rapid.SliceOfN(
			rapid.Byte(), keyLen, keyLen,
		).Draw(t, "groupKey")

		req := &mintrpc.MintAssetRequest{
			Asset: &mintrpc.MintAsset{
				Name:            "test-asset",
				NewGroupedAsset: true,
				GroupKey:        groupKey,
			},
		}
		err := ValidateMintAssetRequest(req)
		require.ErrorIs(t, err, ErrInvalidGroupConfig)
	})
}

// TestValidateMintAssetRequest_RejectsNewGroupWithAnchor tests that
// NewGroupedAsset with group_anchor is rejected.
func TestValidateMintAssetRequest_RejectsNewGroupWithAnchor(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		anchor := rapid.StringMatching(`[a-z]{1,20}`).Draw(t, "anchor")

		req := &mintrpc.MintAssetRequest{
			Asset: &mintrpc.MintAsset{
				Name:            "test-asset",
				NewGroupedAsset: true,
				GroupAnchor:     anchor,
			},
		}
		err := ValidateMintAssetRequest(req)
		require.ErrorIs(t, err, ErrInvalidGroupConfig)
	})
}

// TestValidateMintAssetRequest_RejectsGroupedWithoutRef tests that
// GroupedAsset without group_key or group_anchor is rejected.
func TestValidateMintAssetRequest_RejectsGroupedWithoutRef(t *testing.T) {
	t.Parallel()

	req := &mintrpc.MintAssetRequest{
		Asset: &mintrpc.MintAsset{
			Name:         "test-asset",
			GroupedAsset: true,
		},
	}
	err := ValidateMintAssetRequest(req)
	require.ErrorIs(t, err, ErrInvalidGroupConfig)
}

// TestValidateMintAssetRequest_RejectsGroupedWithBothRefs tests that
// GroupedAsset with both group_key and group_anchor is rejected.
func TestValidateMintAssetRequest_RejectsGroupedWithBothRefs(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		keyLen := rapid.IntRange(1, 64).Draw(t, "keyLen")
		groupKey := rapid.SliceOfN(
			rapid.Byte(), keyLen, keyLen,
		).Draw(t, "groupKey")
		anchor := rapid.StringMatching(`[a-z]{1,20}`).Draw(t, "anchor")

		req := &mintrpc.MintAssetRequest{
			Asset: &mintrpc.MintAsset{
				Name:         "test-asset",
				GroupedAsset: true,
				GroupKey:     groupKey,
				GroupAnchor:  anchor,
			},
		}
		err := ValidateMintAssetRequest(req)
		require.ErrorIs(t, err, ErrInvalidGroupConfig)
	})
}

// TestValidateMintAssetRequest_RejectsCollectibleDecimalDisplay tests that
// collectibles with decimal display > 0 are rejected.
func TestValidateMintAssetRequest_RejectsCollectibleDecimalDisplay(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		decDisplay := rapid.Uint32Range(1, 12).Draw(t, "decimal")

		req := &mintrpc.MintAssetRequest{
			Asset: &mintrpc.MintAsset{
				Name:           "test-collectible",
				AssetType:      taprpc.AssetType_COLLECTIBLE,
				DecimalDisplay: decDisplay,
			},
		}
		err := ValidateMintAssetRequest(req)
		require.ErrorIs(t, err, ErrDecimalDisplayForCollectible)
	})
}

// TestValidateMintAssetRequest_RejectsInvalidTapscriptRootSize tests that
// tapscript roots with invalid sizes (not 0 or 32 bytes) are rejected.
func TestValidateMintAssetRequest_RejectsInvalidTapscriptRootSize(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		// Invalid sizes: anything other than 0 or 32.
		invalidSize := rapid.SampledFrom(
			[]int{1, 16, 31, 33, 64, 100},
		).Draw(t, "size")
		root := rapid.SliceOfN(
			rapid.Byte(), invalidSize, invalidSize,
		).Draw(t, "root")

		req := &mintrpc.MintAssetRequest{
			Asset: &mintrpc.MintAsset{
				Name:               "test-asset",
				NewGroupedAsset:    true,
				GroupTapscriptRoot: root,
			},
		}
		err := ValidateMintAssetRequest(req)
		require.Error(t, err)
		require.Contains(t, err.Error(), "tapscript root")
	})
}

// TestValidateMintAssetRequest_RejectsTapscriptRootWithoutNewGrouped tests
// that tapscript root requires NewGroupedAsset flag.
func TestValidateMintAssetRequest_RejectsTapscriptRootWithoutNewGrouped(t *testing.T) {
	t.Parallel()

	req := &mintrpc.MintAssetRequest{
		Asset: &mintrpc.MintAsset{
			Name:               "test-asset",
			GroupTapscriptRoot: make([]byte, 32),
		},
	}
	err := ValidateMintAssetRequest(req)
	require.ErrorIs(t, err, ErrInvalidGroupConfig)
}

// TestValidateMintAssetRequest_RejectsGroupInternalKeyWithoutNewGrouped tests
// that group internal key requires NewGroupedAsset flag.
func TestValidateMintAssetRequest_RejectsGroupInternalKeyWithoutNewGrouped(t *testing.T) {
	t.Parallel()

	req := &mintrpc.MintAssetRequest{
		Asset: &mintrpc.MintAsset{
			Name:             "test-asset",
			GroupInternalKey: &taprpc.KeyDescriptor{},
		},
	}
	err := ValidateMintAssetRequest(req)
	require.ErrorIs(t, err, ErrInvalidGroupConfig)
}

// TestValidateMintAssetRequest_RejectsGroupKeyWithoutGroupedFlag tests that
// group_key requires GroupedAsset flag.
func TestValidateMintAssetRequest_RejectsGroupKeyWithoutGroupedFlag(t *testing.T) {
	t.Parallel()

	req := &mintrpc.MintAssetRequest{
		Asset: &mintrpc.MintAsset{
			Name:     "test-asset",
			GroupKey: make([]byte, 33),
		},
	}
	err := ValidateMintAssetRequest(req)
	require.ErrorIs(t, err, ErrInvalidGroupConfig)
}

// TestValidateMintAssetRequest_RejectsGroupAnchorWithoutGroupedFlag tests that
// group_anchor requires GroupedAsset flag.
func TestValidateMintAssetRequest_RejectsGroupAnchorWithoutGroupedFlag(t *testing.T) {
	t.Parallel()

	req := &mintrpc.MintAssetRequest{
		Asset: &mintrpc.MintAsset{
			Name:        "test-asset",
			GroupAnchor: "anchor",
		},
	}
	err := ValidateMintAssetRequest(req)
	require.ErrorIs(t, err, ErrInvalidGroupConfig)
}

// TestValidateMintAssetRequest_RejectsBothExternalAndInternalKey tests that
// external_group_key and group_internal_key are mutually exclusive.
func TestValidateMintAssetRequest_RejectsBothExternalAndInternalKey(t *testing.T) {
	t.Parallel()

	req := &mintrpc.MintAssetRequest{
		Asset: &mintrpc.MintAsset{
			Name:             "test-asset",
			NewGroupedAsset:  true,
			ExternalGroupKey: &taprpc.ExternalKey{},
			GroupInternalKey: &taprpc.KeyDescriptor{},
		},
	}
	err := ValidateMintAssetRequest(req)
	require.ErrorIs(t, err, ErrInvalidGroupConfig)
}

// TestValidateMintAssetRequest_AcceptsValidTapscriptRoot tests that tapscript
// roots with valid sizes (0 or 32 bytes) are accepted when NewGroupedAsset is
// set.
func TestValidateMintAssetRequest_AcceptsValidTapscriptRoot(t *testing.T) {
	t.Parallel()

	// Empty root should be accepted.
	req := &mintrpc.MintAssetRequest{
		Asset: &mintrpc.MintAsset{
			Name:               "test-asset",
			NewGroupedAsset:    true,
			GroupTapscriptRoot: nil,
		},
	}
	err := ValidateMintAssetRequest(req)
	require.NoError(t, err)

	// Zero-length root should be accepted.
	req.Asset.GroupTapscriptRoot = []byte{}
	err = ValidateMintAssetRequest(req)
	require.NoError(t, err)

	// 32-byte root should be accepted.
	req.Asset.GroupTapscriptRoot = make([]byte, 32)
	err = ValidateMintAssetRequest(req)
	require.NoError(t, err)
}

// TestValidateMintAssetRequest_AcceptsValidGroupedWithKey tests that
// GroupedAsset with only group_key is accepted.
func TestValidateMintAssetRequest_AcceptsValidGroupedWithKey(t *testing.T) {
	t.Parallel()

	req := &mintrpc.MintAssetRequest{
		Asset: &mintrpc.MintAsset{
			Name:         "test-asset",
			GroupedAsset: true,
			GroupKey:     make([]byte, 33),
		},
	}
	err := ValidateMintAssetRequest(req)
	require.NoError(t, err)
}

// TestValidateMintAssetRequest_AcceptsValidGroupedWithAnchor tests that
// GroupedAsset with only group_anchor is accepted.
func TestValidateMintAssetRequest_AcceptsValidGroupedWithAnchor(t *testing.T) {
	t.Parallel()

	req := &mintrpc.MintAssetRequest{
		Asset: &mintrpc.MintAsset{
			Name:         "test-asset",
			GroupedAsset: true,
			GroupAnchor:  "anchor-asset",
		},
	}
	err := ValidateMintAssetRequest(req)
	require.NoError(t, err)
}

// TestValidateMintAssetRequest_AcceptsValidNewGrouped tests that
// NewGroupedAsset without group_key or group_anchor is accepted.
func TestValidateMintAssetRequest_AcceptsValidNewGrouped(t *testing.T) {
	t.Parallel()

	req := &mintrpc.MintAssetRequest{
		Asset: &mintrpc.MintAsset{
			Name:            "test-asset",
			NewGroupedAsset: true,
		},
	}
	err := ValidateMintAssetRequest(req)
	require.NoError(t, err)
}

// TestValidateMintAssetRequest_AcceptsCollectibleZeroDecimal tests that
// collectibles with decimal display = 0 are accepted.
func TestValidateMintAssetRequest_AcceptsCollectibleZeroDecimal(t *testing.T) {
	t.Parallel()

	req := &mintrpc.MintAssetRequest{
		Asset: &mintrpc.MintAsset{
			Name:           "test-collectible",
			AssetType:      taprpc.AssetType_COLLECTIBLE,
			DecimalDisplay: 0,
		},
	}
	err := ValidateMintAssetRequest(req)
	require.NoError(t, err)
}

// TestValidateMintAssetRequest_AcceptsNormalWithDecimal tests that normal
// assets with decimal display are accepted.
func TestValidateMintAssetRequest_AcceptsNormalWithDecimal(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		decDisplay := rapid.Uint32Range(0, 12).Draw(t, "decimal")

		req := &mintrpc.MintAssetRequest{
			Asset: &mintrpc.MintAsset{
				Name:           "test-normal",
				AssetType:      taprpc.AssetType_NORMAL,
				DecimalDisplay: decDisplay,
			},
		}
		err := ValidateMintAssetRequest(req)
		require.NoError(t, err)
	})
}
