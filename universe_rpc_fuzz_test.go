package taprootassets

import (
	"testing"

	"google.golang.org/protobuf/proto"

	unirpc "github.com/lightninglabs/taproot-assets/taprpc/universerpc"
)

// FuzzUnmarshalUniverseKey tests that UnmarshalUniverseKey never panics
// on arbitrary protobuf input.
func FuzzUnmarshalUniverseKey(f *testing.F) {
	// Add seed corpus.
	f.Add([]byte{})
	f.Add([]byte{0x0a, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		var req unirpc.UniverseKey
		if err := proto.Unmarshal(data, &req); err != nil {
			return // Invalid protobuf, skip
		}
		// Must not panic - we don't care about the result.
		_, _, _ = UnmarshalUniverseKey(&req)
	})
}

// FuzzUnmarshalAssetLeaf tests that UnmarshalAssetLeaf never panics
// on arbitrary protobuf input.
func FuzzUnmarshalAssetLeaf(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x0a, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		var req unirpc.AssetLeaf
		if err := proto.Unmarshal(data, &req); err != nil {
			return
		}
		_, _ = UnmarshalAssetLeaf(&req)
	})
}

// FuzzUnmarshalLeafKey tests that UnmarshalLeafKey never panics
// on arbitrary protobuf input.
func FuzzUnmarshalLeafKey(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x0a, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		var req unirpc.AssetKey
		if err := proto.Unmarshal(data, &req); err != nil {
			return
		}
		_, _ = UnmarshalLeafKey(&req)
	})
}

// FuzzUnmarshalUniID tests that UnmarshalUniID never panics
// on arbitrary protobuf input.
func FuzzUnmarshalUniID(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x0a, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		var req unirpc.ID
		if err := proto.Unmarshal(data, &req); err != nil {
			return
		}
		_, _ = UnmarshalUniID(&req)
	})
}

// FuzzValidateAssetProofRequest tests that ValidateAssetProofRequest never
// panics on arbitrary protobuf input.
func FuzzValidateAssetProofRequest(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x0a, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		var req unirpc.AssetProof
		if err := proto.Unmarshal(data, &req); err != nil {
			return
		}
		_, _ = ValidateAssetProofRequest(&req)
	})
}

// FuzzParseSyncRequest tests that ParseSyncRequest never panics
// on arbitrary protobuf input.
func FuzzParseSyncRequest(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x0a, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		var req unirpc.SyncRequest
		if err := proto.Unmarshal(data, &req); err != nil {
			return
		}
		_, _ = ParseSyncRequest(&req)
	})
}
