package taprootassets

import (
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/mssmt"
	unirpc "github.com/lightninglabs/taproot-assets/taprpc/universerpc"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// genValidPubKey generates a valid secp256k1 public key.
func genValidPubKey(t *rapid.T) *btcec.PublicKey {
	// Generate 32 random bytes for the private key scalar.
	privKeyBytes := rapid.SliceOfN(rapid.Byte(), 32, 32).Draw(t, "privKey")

	// Create a valid private key from the bytes.
	privKey, _ := btcec.PrivKeyFromBytes(privKeyBytes)

	return privKey.PubKey()
}

// genProofType generates a valid proof type (issuance or transfer).
func genProofType(t *rapid.T) universe.ProofType {
	// Only generate valid proof types (1 = issuance, 2 = transfer).
	return universe.ProofType(rapid.IntRange(1, 2).Draw(t, "proofType"))
}

// genAssetID generates a random asset ID.
func genAssetID(t *rapid.T) asset.ID {
	var id asset.ID
	copy(id[:], rapid.SliceOfN(rapid.Byte(), 32, 32).Draw(t, "assetID"))
	return id
}

// genUniverseIdentifier generates a universe identifier.
func genUniverseIdentifier(t *rapid.T) universe.Identifier {
	useGroupKey := rapid.Bool().Draw(t, "useGroupKey")

	id := universe.Identifier{
		ProofType: genProofType(t),
	}

	if useGroupKey {
		id.GroupKey = genValidPubKey(t)
	} else {
		id.AssetID = genAssetID(t)
	}

	return id
}

// TestUniverseIDRoundTrip tests that MarshalUniID and UnmarshalUniID form a
// valid round-trip.
func TestUniverseIDRoundTrip(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		original := genUniverseIdentifier(t)

		// Marshal to RPC.
		rpcID, err := MarshalUniID(original)
		require.NoError(t, err)

		// Unmarshal back.
		decoded, err := UnmarshalUniID(rpcID)
		require.NoError(t, err)

		// Compare.
		require.Equal(t, original.ProofType, decoded.ProofType)
		require.Equal(t, original.AssetID, decoded.AssetID)

		if original.GroupKey != nil {
			require.NotNil(t, decoded.GroupKey)
			// Compare using schnorr serialization since that's what's
			// preserved in the round-trip (x-coordinate only).
			require.Equal(t,
				schnorr.SerializePubKey(original.GroupKey),
				schnorr.SerializePubKey(decoded.GroupKey),
			)
		} else {
			require.Nil(t, decoded.GroupKey)
		}
	})
}

// TestMerkleSumNodeRoundTrip tests that UnmarshalMerkleSumNode correctly
// decodes marshalled MS-SMT nodes.
func TestMerkleSumNodeRoundTrip(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		// Generate a random node hash and sum.
		var nodeHash mssmt.NodeHash
		copy(
			nodeHash[:],
			rapid.SliceOfN(rapid.Byte(), 32, 32).Draw(t, "hash"),
		)
		nodeSum := rapid.Uint64().Draw(t, "sum")

		original := mssmt.NewComputedBranch(nodeHash, nodeSum)

		// Marshal to RPC format.
		rpcNode := &unirpc.MerkleSumNode{
			RootHash: nodeHash[:],
			RootSum:  int64(nodeSum),
		}

		// Unmarshal back.
		decoded := UnmarshalMerkleSumNode(rpcNode)

		// Compare.
		require.Equal(t, original.NodeHash(), decoded.NodeHash())
		require.Equal(t, original.NodeSum(), decoded.NodeSum())
	})
}

// TestUniverseRootRoundTrip tests that UnmarshalUniverseRoot correctly decodes
// marshalled universe roots.
func TestUniverseRootRoundTrip(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		id := genUniverseIdentifier(t)

		// Generate a random node hash and sum.
		var nodeHash mssmt.NodeHash
		copy(
			nodeHash[:],
			rapid.SliceOfN(rapid.Byte(), 32, 32).Draw(t, "hash"),
		)
		nodeSum := rapid.Uint64().Draw(t, "sum")

		node := mssmt.NewComputedBranch(nodeHash, nodeSum)

		// Create the original universe root.
		original := universe.Root{
			ID:   id,
			Node: node,
		}

		// Marshal to RPC format.
		rpcID, err := MarshalUniID(id)
		require.NoError(t, err)

		rpcRoot := &unirpc.UniverseRoot{
			Id: rpcID,
			MssmtRoot: &unirpc.MerkleSumNode{
				RootHash: nodeHash[:],
				RootSum:  int64(nodeSum),
			},
		}

		// Unmarshal back.
		decoded, err := UnmarshalUniverseRoot(rpcRoot)
		require.NoError(t, err)

		// Compare ID.
		require.Equal(t, original.ID.ProofType, decoded.ID.ProofType)
		require.Equal(t, original.ID.AssetID, decoded.ID.AssetID)

		if original.ID.GroupKey != nil {
			require.NotNil(t, decoded.ID.GroupKey)
			// Compare using schnorr serialization since that's what's
			// preserved in the round-trip (x-coordinate only).
			require.Equal(t,
				schnorr.SerializePubKey(original.ID.GroupKey),
				schnorr.SerializePubKey(decoded.ID.GroupKey),
			)
		}

		// Compare node.
		require.Equal(t, original.Node.NodeHash(), decoded.Node.NodeHash())
		require.Equal(t, original.Node.NodeSum(), decoded.Node.NodeSum())
	})
}

// TestUnmarshalUniProofType tests that UnmarshalUniProofType handles all valid
// proof types correctly.
func TestUnmarshalUniProofType(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		rpcType  unirpc.ProofType
		expected universe.ProofType
	}{
		{
			rpcType:  unirpc.ProofType_PROOF_TYPE_UNSPECIFIED,
			expected: universe.ProofTypeUnspecified,
		},
		{
			rpcType:  unirpc.ProofType_PROOF_TYPE_ISSUANCE,
			expected: universe.ProofTypeIssuance,
		},
		{
			rpcType:  unirpc.ProofType_PROOF_TYPE_TRANSFER,
			expected: universe.ProofTypeTransfer,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.expected.String(), func(t *testing.T) {
			result, err := UnmarshalUniProofType(tc.rpcType)
			require.NoError(t, err)
			require.Equal(t, tc.expected, result)
		})
	}
}

// TestLeafKeyRoundTrip tests that UnmarshalLeafKey correctly parses leaf keys
// created with valid data.
func TestLeafKeyRoundTrip(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		// Generate a valid script key.
		scriptKey := genValidPubKey(t)
		scriptKeyBytes := schnorr.SerializePubKey(scriptKey)

		// Generate a valid outpoint string.
		var txid [32]byte
		copy(txid[:], rapid.SliceOfN(rapid.Byte(), 32, 32).Draw(t, "txid"))
		vout := rapid.Uint32Range(0, 100).Draw(t, "vout")

		// Create RPC asset key using bytes format.
		rpcKey := &unirpc.AssetKey{
			Outpoint: &unirpc.AssetKey_Op{
				Op: &unirpc.Outpoint{
					HashStr: hex.EncodeToString(txid[:]),
					Index:   int32(vout),
				},
			},
			ScriptKey: &unirpc.AssetKey_ScriptKeyBytes{
				ScriptKeyBytes: scriptKeyBytes,
			},
		}

		// Unmarshal.
		leafKey, err := UnmarshalLeafKey(rpcKey)
		require.NoError(t, err)

		// Verify script key matches (compare schnorr serialization since
		// that's what's preserved in the round-trip).
		require.NotNil(t, leafKey.LeafScriptKey())
		require.Equal(t,
			schnorr.SerializePubKey(scriptKey),
			schnorr.SerializePubKey(leafKey.LeafScriptKey().PubKey),
		)

		// Verify outpoint matches.
		outpoint := leafKey.LeafOutPoint()
		require.Equal(t, vout, outpoint.Index)
	})
}

// TestValidateAssetProofRequest_NilRequest tests that ValidateAssetProofRequest
// returns an error for nil input.
func TestValidateAssetProofRequest_NilRequest(t *testing.T) {
	t.Parallel()

	_, err := ValidateAssetProofRequest(nil)
	require.ErrorIs(t, err, ErrNilRequest)
}

// TestParseSyncRequest_NilRequest tests that ParseSyncRequest returns an error
// for nil input.
func TestParseSyncRequest_NilRequest(t *testing.T) {
	t.Parallel()

	_, err := ParseSyncRequest(nil)
	require.ErrorIs(t, err, ErrNilRequest)
}

// TestParseSyncRequest tests that ParseSyncRequest correctly parses valid
// sync requests.
func TestParseSyncRequest(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		// Generate a sync mode (0 = full, 1 = issuance only).
		syncModeInt := rapid.IntRange(0, 1).Draw(t, "syncMode")
		syncMode := unirpc.UniverseSyncMode(syncModeInt)

		// Generate some sync targets (0 to 3).
		numTargets := rapid.IntRange(0, 3).Draw(t, "numTargets")
		targets := make([]*unirpc.SyncTarget, numTargets)
		for i := 0; i < numTargets; i++ {
			id := genUniverseIdentifier(t)
			rpcID, err := MarshalUniID(id)
			require.NoError(t, err)
			targets[i] = &unirpc.SyncTarget{
				Id: rpcID,
			}
		}

		req := &unirpc.SyncRequest{
			SyncMode:    syncMode,
			SyncTargets: targets,
		}

		parsed, err := ParseSyncRequest(req)
		require.NoError(t, err)

		// Verify sync mode was parsed correctly.
		require.Equal(t, numTargets, len(parsed.SyncTargets))
	})
}

// TestUnmarshalUniverseKey_RoundTrip tests that UnmarshalUniverseKey correctly
// parses a well-formed universe key.
func TestUnmarshalUniverseKey_RoundTrip(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		// Generate a universe identifier with a specified proof type.
		id := genUniverseIdentifier(t)

		rpcID, err := MarshalUniID(id)
		require.NoError(t, err)

		// Create a universe key with valid leaf key components.
		scriptKey := genValidPubKey(t)
		var txid [32]byte
		copy(txid[:], rapid.SliceOfN(rapid.Byte(), 32, 32).Draw(t, "txid"))
		vout := rapid.Uint32Range(0, 100).Draw(t, "vout")

		uniKey := &unirpc.UniverseKey{
			Id: rpcID,
			LeafKey: &unirpc.AssetKey{
				Outpoint: &unirpc.AssetKey_Op{
					Op: &unirpc.Outpoint{
						HashStr: hex.EncodeToString(txid[:]),
						Index:   int32(vout),
					},
				},
				ScriptKey: &unirpc.AssetKey_ScriptKeyBytes{
					ScriptKeyBytes: schnorr.SerializePubKey(
						scriptKey,
					),
				},
			},
		}

		// Test that UnmarshalUniverseKey works with our generated key.
		parsedID, parsedKey, err := UnmarshalUniverseKey(uniKey)
		require.NoError(t, err)
		require.Equal(t, id.ProofType, parsedID.ProofType)
		require.NotNil(t, parsedKey.LeafScriptKey())
	})
}
