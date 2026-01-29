package taprootassets

import (
	unirpc "github.com/lightninglabs/taproot-assets/taprpc/universerpc"
	"github.com/lightninglabs/taproot-assets/universe"
)

// ParsedAssetProof contains validated, parsed proof request data.
type ParsedAssetProof struct {
	// UniverseID identifies the universe this proof belongs to.
	UniverseID universe.Identifier

	// LeafKey is the key used to look up the proof in the universe.
	LeafKey universe.LeafKey

	// AssetLeaf contains the proof leaf data.
	AssetLeaf *universe.Leaf
}

// ValidateAssetProofRequest performs stateless validation and parsing of an
// asset proof insertion request. It extracts the universe ID, leaf key, and
// asset leaf from the RPC request, and validates proof type consistency.
func ValidateAssetProofRequest(req *unirpc.AssetProof) (
	*ParsedAssetProof, error) {

	universeID, leafKey, err := UnmarshalUniverseKey(req.Key)
	if err != nil {
		return nil, err
	}

	assetLeaf, err := UnmarshalAssetLeaf(req.AssetLeaf)
	if err != nil {
		return nil, err
	}

	// If universe proof type is unspecified, infer it from the asset.
	if universeID.ProofType == universe.ProofTypeUnspecified {
		universeID.ProofType, err = universe.NewProofTypeFromAsset(
			assetLeaf.Asset,
		)
		if err != nil {
			return nil, err
		}
	}

	// Validate that the proof type is consistent with the asset.
	err = universe.ValidateProofUniverseType(assetLeaf.Asset, universeID)
	if err != nil {
		return nil, err
	}

	return &ParsedAssetProof{
		UniverseID: universeID,
		LeafKey:    leafKey,
		AssetLeaf:  assetLeaf,
	}, nil
}

// ParsedSyncRequest contains validated sync parameters.
type ParsedSyncRequest struct {
	// SyncMode specifies how the sync should be performed.
	SyncMode universe.SyncType

	// SyncTargets specifies which universes to sync (empty means all).
	SyncTargets []universe.Identifier
}

// ParseSyncRequest validates and parses a universe sync request.
func ParseSyncRequest(req *unirpc.SyncRequest) (*ParsedSyncRequest, error) {
	syncMode, err := UnmarshalUniverseSyncType(req.SyncMode)
	if err != nil {
		return nil, err
	}

	syncTargets, err := UnmarshalSyncTargets(req.SyncTargets)
	if err != nil {
		return nil, err
	}

	return &ParsedSyncRequest{
		SyncMode:    syncMode,
		SyncTargets: syncTargets,
	}, nil
}
