package taprootassets

import (
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
)

// FuzzMintAssetRequest tests that MintAsset validation never panics
// on arbitrary protobuf input.
func FuzzMintAssetRequest(f *testing.F) {
	// Add seed corpus.
	f.Add([]byte{})
	f.Add([]byte{0x0a, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		var req mintrpc.MintAssetRequest
		if err := proto.Unmarshal(data, &req); err != nil {
			return // Invalid protobuf, skip
		}

		// Validate parsing functions don't panic.
		if req.Asset != nil {
			_ = asset.ValidateAssetName(req.Asset.Name)
		}

		// Validator must not panic.
		_ = ValidateMintAssetRequest(&req)
	})
}
