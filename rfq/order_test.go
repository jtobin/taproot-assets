package rfq

import (
	"context"
	"testing"
	"time"

	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/route"
	"github.com/stretchr/testify/require"
)

// TestNewAssetSalePolicyFillCap tests that NewAssetSalePolicy caps
// MaxOutboundAssetAmount when a fill quantity is present and
// derives MinOutboundAssetAmount correctly.
func TestNewAssetSalePolicyFillCap(t *testing.T) {
	t.Parallel()

	spec := asset.NewSpecifierFromId(asset.ID{0x01})
	peer := route.Vertex{0x0A}
	rate := rfqmsg.NewAssetRate(
		rfqmath.NewBigIntFixedPoint(100, 0),
		time.Now().Add(time.Hour),
	)

	tests := []struct {
		name      string
		maxAmt    uint64
		fill      fn.Option[uint64]
		execPol   fn.Option[rfqmsg.ExecutionPolicy]
		expectMax uint64
		expectMin uint64
	}{
		{
			name:      "no fill no FOK",
			maxAmt:    100,
			fill:      fn.None[uint64](),
			execPol:   fn.None[rfqmsg.ExecutionPolicy](),
			expectMax: 100,
			expectMin: 0,
		},
		{
			name:      "fill < max caps to fill",
			maxAmt:    100,
			fill:      fn.Some[uint64](60),
			execPol:   fn.None[rfqmsg.ExecutionPolicy](),
			expectMax: 60,
			expectMin: 60,
		},
		{
			name:      "fill > max uses request max",
			maxAmt:    100,
			fill:      fn.Some[uint64](200),
			execPol:   fn.None[rfqmsg.ExecutionPolicy](),
			expectMax: 100,
			expectMin: 100,
		},
		{
			name:      "fill == max uses request max",
			maxAmt:    100,
			fill:      fn.Some[uint64](100),
			execPol:   fn.None[rfqmsg.ExecutionPolicy](),
			expectMax: 100,
			expectMin: 100,
		},
		{
			name:   "no fill FOK sets floor to max",
			maxAmt: 100,
			fill:   fn.None[uint64](),
			execPol: fn.Some(
				rfqmsg.ExecutionPolicyFOK,
			),
			expectMax: 100,
			expectMin: 100,
		},
		{
			name:   "fill == max FOK",
			maxAmt: 100,
			fill:   fn.Some[uint64](100),
			execPol: fn.Some(
				rfqmsg.ExecutionPolicyFOK,
			),
			expectMax: 100,
			expectMin: 100,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			buyReq := &rfqmsg.BuyRequest{
				Peer:            peer,
				AssetSpecifier:  spec,
				AssetMaxAmt:     tc.maxAmt,
				ExecutionPolicy: tc.execPol,
			}

			accept := rfqmsg.BuyAccept{
				Peer:              peer,
				Request:           *buyReq,
				AssetRate:         rate,
				AcceptedMaxAmount: tc.fill,
			}

			policy := NewAssetSalePolicy(
				accept, false, nil,
			)
			require.Equal(
				t, tc.expectMax,
				policy.MaxOutboundAssetAmount,
			)
			require.Equal(
				t, tc.expectMin,
				policy.MinOutboundAssetAmount,
			)
		})
	}
}

// TestNewAssetPurchasePolicyFillCap tests that
// NewAssetPurchasePolicy caps PaymentMaxAmt and derives
// PaymentMinAmt when a fill quantity is present.
func TestNewAssetPurchasePolicyFillCap(t *testing.T) {
	t.Parallel()

	spec := asset.NewSpecifierFromId(asset.ID{0x01})
	peer := route.Vertex{0x0A}
	rate := rfqmsg.NewAssetRate(
		rfqmath.NewBigIntFixedPoint(100, 0),
		time.Now().Add(time.Hour),
	)

	tests := []struct {
		name      string
		maxAmt    lnwire.MilliSatoshi
		fill      fn.Option[uint64]
		execPol   fn.Option[rfqmsg.ExecutionPolicy]
		expectMax lnwire.MilliSatoshi
		expectMin lnwire.MilliSatoshi
	}{
		{
			name:      "no fill no FOK",
			maxAmt:    1000,
			fill:      fn.None[uint64](),
			execPol:   fn.None[rfqmsg.ExecutionPolicy](),
			expectMax: 1000,
			expectMin: 0,
		},
		{
			name:      "fill < max caps to fill",
			maxAmt:    1000,
			fill:      fn.Some[uint64](600),
			execPol:   fn.None[rfqmsg.ExecutionPolicy](),
			expectMax: 600,
			expectMin: 600,
		},
		{
			name:      "fill > max uses request max",
			maxAmt:    1000,
			fill:      fn.Some[uint64](2000),
			execPol:   fn.None[rfqmsg.ExecutionPolicy](),
			expectMax: 1000,
			expectMin: 1000,
		},
		{
			name:      "fill == max uses request max",
			maxAmt:    1000,
			fill:      fn.Some[uint64](1000),
			execPol:   fn.None[rfqmsg.ExecutionPolicy](),
			expectMax: 1000,
			expectMin: 1000,
		},
		{
			name:   "no fill FOK sets floor to max",
			maxAmt: 1000,
			fill:   fn.None[uint64](),
			execPol: fn.Some(
				rfqmsg.ExecutionPolicyFOK,
			),
			expectMax: 1000,
			expectMin: 1000,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sellReq := &rfqmsg.SellRequest{
				Peer:            peer,
				AssetSpecifier:  spec,
				PaymentMaxAmt:   tc.maxAmt,
				ExecutionPolicy: tc.execPol,
			}

			accept := rfqmsg.SellAccept{
				Peer:              peer,
				Request:           *sellReq,
				AssetRate:         rate,
				AcceptedMaxAmount: tc.fill,
			}

			policy := NewAssetPurchasePolicy(accept)
			require.Equal(
				t, tc.expectMax, policy.PaymentMaxAmt,
			)
			require.Equal(
				t, tc.expectMin, policy.PaymentMinAmt,
			)
		})
	}
}

// TestSalePolicyFloorCompliance tests that the floor check in
// AssetSalePolicy.CheckHtlcCompliance correctly accepts and
// rejects HTLCs relative to the negotiated minimum.
func TestSalePolicyFloorCompliance(t *testing.T) {
	t.Parallel()

	spec := asset.NewSpecifierFromId(asset.ID{0x01})
	peer := route.Vertex{0x0A}

	// Rate: 100_000_000 units per BTC → 1 unit = 1000 msat.
	// Tolerance = 1000 + 1 = 1001 msat.
	askRate := rfqmath.NewBigIntFixedPoint(100_000_000, 0)
	rate := rfqmsg.NewAssetRate(
		askRate, time.Now().Add(time.Hour),
	)

	// Policy: max 100 units, fill (floor) 50 units.
	// 50 units = 50_000 msat.
	buyReq := &rfqmsg.BuyRequest{
		Peer:           peer,
		AssetSpecifier: spec,
		AssetMaxAmt:    100,
	}
	accept := rfqmsg.BuyAccept{
		Peer:              peer,
		Request:           *buyReq,
		AssetRate:         rate,
		AcceptedMaxAmount: fn.Some[uint64](50),
	}
	policy := NewAssetSalePolicy(accept, false, nil)

	require.Equal(t, uint64(50), policy.MinOutboundAssetAmount)
	require.Equal(t, uint64(50), policy.MaxOutboundAssetAmount)

	ctx := context.Background()

	// Floor = 50 units = 50_000 msat.
	// Tolerance = 1 unit (1000 msat) + 1 = 1001 msat.
	// Boundary: 50_000 - 1001 = 48_999 passes,
	//           48_998 is rejected.
	tests := []struct {
		name    string
		outMsat lnwire.MilliSatoshi
		wantErr bool
	}{
		{
			name:    "at floor passes",
			outMsat: 50_000,
			wantErr: false,
		},
		{
			name:    "well below floor rejected",
			outMsat: 10_000,
			wantErr: true,
		},
		{
			name: "within tolerance passes",
			outMsat: 50_000 - 1,
			wantErr: false,
		},
		{
			name: "at exact tolerance boundary " +
				"passes",
			outMsat: 48_999,
			wantErr: false,
		},
		{
			name:    "beyond tolerance rejected",
			outMsat: 48_998,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			htlc := lndclient.InterceptedHtlc{
				OutgoingChannelID: lnwire.NewShortChanIDFromInt( //nolint:lll
					policy.Scid(),
				),
				AmountOutMsat: tc.outMsat,
			}

			err := policy.CheckHtlcCompliance(
				ctx, htlc, nil,
			)
			if tc.wantErr {
				require.Error(t, err)
				require.Contains(
					t, err.Error(),
					"less than the policy "+
						"minimum",
				)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestSalePolicyNoFloor verifies that when no fill and no FOK
// are present, the floor check is skipped entirely.
func TestSalePolicyNoFloor(t *testing.T) {
	t.Parallel()

	spec := asset.NewSpecifierFromId(asset.ID{0x01})
	peer := route.Vertex{0x0A}

	askRate := rfqmath.NewBigIntFixedPoint(100_000_000, 0)
	rate := rfqmsg.NewAssetRate(
		askRate, time.Now().Add(time.Hour),
	)

	buyReq := &rfqmsg.BuyRequest{
		Peer:           peer,
		AssetSpecifier: spec,
		AssetMaxAmt:    100,
	}
	accept := rfqmsg.BuyAccept{
		Peer:    peer,
		Request: *buyReq,
		AssetRate: rate,
	}
	policy := NewAssetSalePolicy(accept, false, nil)

	require.Equal(t, uint64(0), policy.MinOutboundAssetAmount)

	// A tiny HTLC should pass — no floor enforced.
	htlc := lndclient.InterceptedHtlc{
		OutgoingChannelID: lnwire.NewShortChanIDFromInt(
			policy.Scid(),
		),
		AmountOutMsat: 1,
	}
	err := policy.CheckHtlcCompliance(
		context.Background(), htlc, nil,
	)
	require.NoError(t, err)
}

// TestPurchasePolicyFloorCompliance tests that the floor check in
// AssetPurchasePolicy.CheckHtlcCompliance correctly accepts and
// rejects HTLCs relative to the negotiated minimum.
func TestPurchasePolicyFloorCompliance(t *testing.T) {
	t.Parallel()

	spec := asset.NewSpecifierFromId(asset.ID{0x01})
	peer := route.Vertex{0x0A}

	// Rate: 100_000_000 units per BTC → 1 unit = 1000 msat.
	// Tolerance = 1000 + 1 = 1001 msat.
	bidRate := rfqmath.NewBigIntFixedPoint(100_000_000, 0)
	rate := rfqmsg.NewAssetRate(
		bidRate, time.Now().Add(time.Hour),
	)

	// Policy: max 100_000 msat, fill (floor) 50_000 msat.
	sellReq := &rfqmsg.SellRequest{
		Peer:           peer,
		AssetSpecifier: spec,
		PaymentMaxAmt:  100_000,
	}
	accept := rfqmsg.SellAccept{
		Peer:              peer,
		Request:           *sellReq,
		AssetRate:         rate,
		AcceptedMaxAmount: fn.Some[uint64](50_000),
	}
	policy := NewAssetPurchasePolicy(accept)

	require.Equal(
		t, lnwire.MilliSatoshi(50_000),
		policy.PaymentMinAmt,
	)
	require.Equal(
		t, lnwire.MilliSatoshi(50_000),
		policy.PaymentMaxAmt,
	)

	ctx := context.Background()

	// Build a minimal HTLC custom record carrying the
	// accepted quote ID and enough asset balance to pass the
	// inbound amount check. We need enough units that the
	// inbound msat covers the outbound msat. At the rate
	// of 1000 msat/unit, 100 units = 100_000 msat, which
	// is enough for all test cases.
	assetBalance := rfqmsg.NewAssetBalance(
		asset.ID{0x01}, 100,
	)
	htlcRecord := rfqmsg.NewHtlc(
		[]*rfqmsg.AssetBalance{assetBalance},
		fn.Some(accept.ID),
		fn.None[[]rfqmsg.ID](),
	)
	customRecords, err := lnwire.ParseCustomRecords(
		htlcRecord.Bytes(),
	)
	require.NoError(t, err)

	// Floor = 50_000 msat.
	// Tolerance = 1 unit (1000 msat) + 1 = 1001 msat.
	// Boundary: 50_000 - 1001 = 48_999 passes,
	//           48_998 is rejected.
	tests := []struct {
		name    string
		outMsat lnwire.MilliSatoshi
		wantErr bool
		errMsg  string
	}{
		{
			name:    "at floor passes",
			outMsat: 50_000,
			wantErr: false,
		},
		{
			name:    "well below floor rejected",
			outMsat: 10_000,
			wantErr: true,
			errMsg:  "less than the policy minimum",
		},
		{
			name: "within tolerance passes",
			outMsat: 50_000 - 1,
			wantErr: false,
		},
		{
			name: "at exact tolerance boundary " +
				"passes",
			outMsat: 48_999,
			wantErr: false,
		},
		{
			name:    "beyond tolerance rejected",
			outMsat: 48_998,
			wantErr: true,
			errMsg:  "less than the policy minimum",
		},
	}

	// checker always says the asset matches the specifier.
	checker := rfqmsg.SpecifierChecker(
		func(_ context.Context, _ asset.Specifier,
			_ asset.ID) (bool, error) {

			return true, nil
		},
	)

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			htlc := lndclient.InterceptedHtlc{
				InWireCustomRecords: customRecords,
				AmountOutMsat:       tc.outMsat,
			}

			err := policy.CheckHtlcCompliance(
				ctx, htlc, checker,
			)
			if tc.wantErr {
				require.Error(t, err)
				require.Contains(
					t, err.Error(),
					tc.errMsg,
				)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

