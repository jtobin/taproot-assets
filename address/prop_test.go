package address

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/stretchr/testify/require"
)

// TestAddressEncodingRoundTrip tests that Tap address encode/decode form a
// valid round-trip using the randAddress test helper with real test data.
func TestAddressEncodingRoundTrip(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		groupPubKey bool
		sibling     bool
		assetType   asset.Type
	}{
		{
			name:        "normal asset, no group, no sibling",
			groupPubKey: false,
			sibling:     false,
			assetType:   asset.Normal,
		},
		{
			name:        "normal asset, with group, no sibling",
			groupPubKey: true,
			sibling:     false,
			assetType:   asset.Normal,
		},
		{
			name:        "normal asset, no group, with sibling",
			groupPubKey: false,
			sibling:     true,
			assetType:   asset.Normal,
		},
		{
			name:        "normal asset, with group, with sibling",
			groupPubKey: true,
			sibling:     true,
			assetType:   asset.Normal,
		},
		{
			name:        "collectible, no group, no sibling",
			groupPubKey: false,
			sibling:     false,
			assetType:   asset.Collectible,
		},
		{
			name:        "collectible, with group, no sibling",
			groupPubKey: true,
			sibling:     false,
			assetType:   asset.Collectible,
		},
	}

	networks := []*ChainParams{&MainNetTap, &TestNet3Tap, &SigNetTap}

	for _, network := range networks {
		for _, tc := range testCases {
			tc := tc
			name := network.Name + "/" + tc.name

			t.Run(name, func(t *testing.T) {
				// Run multiple iterations to cover more random
				// data.
				for i := 0; i < 10; i++ {
					addr, err := randAddress(
						t, network, nil,
						tc.groupPubKey, tc.sibling,
						nil, tc.assetType, nil,
					)
					require.NoError(t, err)

					// Test TLV round-trip (Encode/Decode).
					var buf bytes.Buffer
					err = addr.Encode(&buf)
					require.NoError(t, err)
					originalBytes := buf.Bytes()

					var decoded Tap
					decoded.ChainParams = network
					err = decoded.Decode(
						bytes.NewReader(originalBytes),
					)
					require.NoError(t, err)

					// Re-encode and compare bytes.
					var buf2 bytes.Buffer
					err = decoded.Encode(&buf2)
					require.NoError(t, err)

					require.Equal(t, originalBytes, buf2.Bytes())

					// Test bech32m round-trip.
					encodedStr, err := addr.EncodeAddress()
					require.NoError(t, err)

					decodedAddr, err := DecodeAddress(
						encodedStr, network,
					)
					require.NoError(t, err)

					// Re-encode and compare strings.
					reEncodedStr, err := decodedAddr.EncodeAddress()
					require.NoError(t, err)

					require.Equal(t, encodedStr, reEncodedStr)
				}
			})
		}
	}
}

// TestAddressVersionRoundTrip tests that all address versions encode and
// decode correctly.
func TestAddressVersionRoundTrip(t *testing.T) {
	t.Parallel()

	versions := []Version{V0, V1, V2}

	for _, v := range versions {
		v := v

		t.Run(fmt.Sprintf("version_%d", v), func(t *testing.T) {
			for i := 0; i < 5; i++ {
				addr, err := randAddress(
					t, &MainNetTap, &v,
					true, false,
					nil, asset.Normal, nil,
				)
				require.NoError(t, err)
				require.Equal(t, v, addr.Version)

				// Test encoding preserves version.
				encodedStr, err := addr.EncodeAddress()
				require.NoError(t, err)

				decodedAddr, err := DecodeAddress(
					encodedStr, &MainNetTap,
				)
				require.NoError(t, err)

				require.Equal(t, v, decodedAddr.Version)
			}
		})
	}
}
