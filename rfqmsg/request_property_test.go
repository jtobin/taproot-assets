package rfqmsg

import (
	"bytes"
	"testing"
	"time"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/route"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// optionalUint64Gen draws an fn.Option[uint64] that is None half the
// time and Some(v) otherwise, where v is drawn from [0, bound].
func optionalUint64Gen(bound uint64) *rapid.Generator[fn.Option[uint64]] {
	return rapid.Custom(func(t *rapid.T) fn.Option[uint64] {
		if rapid.Bool().Draw(t, "present") {
			v := rapid.Uint64Range(0, bound).Draw(
				t, "value",
			)
			return fn.Some(v)
		}
		return fn.None[uint64]()
	})
}

// optionalMsatGen draws an fn.Option[lnwire.MilliSatoshi] that is
// None half the time and Some(v) otherwise, where v <= bound.
func optionalMsatGen(
	bound uint64) *rapid.Generator[fn.Option[lnwire.MilliSatoshi]] {

	return rapid.Custom(
		func(t *rapid.T) fn.Option[lnwire.MilliSatoshi] {
			if rapid.Bool().Draw(t, "present") {
				v := rapid.Uint64Range(0, bound).Draw(
					t, "value",
				)
				return fn.Some(
					lnwire.MilliSatoshi(v),
				)
			}
			return fn.None[lnwire.MilliSatoshi]()
		},
	)
}

// fixedPointGen draws a BigIntFixedPoint with coefficient in [1,1e12]
// and scale in [0,11].
func fixedPointGen() *rapid.Generator[rfqmath.BigIntFixedPoint] {
	return rapid.Custom(
		func(t *rapid.T) rfqmath.BigIntFixedPoint {
			coeff := rapid.Uint64Range(1, 1_000_000_000_000).
				Draw(t, "coeff")
			scale := rapid.Uint8Range(0, 11).Draw(t, "scale")
			return rfqmath.NewBigIntFixedPoint(
				coeff, scale,
			)
		},
	)
}

// optionalFixedPointGen draws an optional BigIntFixedPoint, None half
// the time.
func optionalFixedPointGen() *rapid.Generator[fn.Option[rfqmath.BigIntFixedPoint]] {
	return rapid.Custom(
		func(t *rapid.T) fn.Option[rfqmath.BigIntFixedPoint] {
			if rapid.Bool().Draw(t, "present") {
				return fn.Some(
					fixedPointGen().Draw(t, "fp"),
				)
			}
			return fn.None[rfqmath.BigIntFixedPoint]()
		},
	)
}

// assetIDGen draws a random 32-byte asset.ID.
func assetIDGen() *rapid.Generator[asset.ID] {
	return rapid.Custom(func(t *rapid.T) asset.ID {
		var id asset.ID
		for i := range id {
			id[i] = rapid.Byte().Draw(t, "byte")
		}
		return id
	})
}

// peerGen draws a random 33-byte route.Vertex.
func peerGen() *rapid.Generator[route.Vertex] {
	return rapid.Custom(func(t *rapid.T) route.Vertex {
		var v route.Vertex
		for i := range v {
			v[i] = rapid.Byte().Draw(t, "byte")
		}
		return v
	})
}

// TestBuyRequestWireRoundtripProperty checks that any valid
// BuyRequest survives a wire encode/decode roundtrip.
func TestBuyRequestWireRoundtripProperty(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		peer := peerGen().Draw(t, "peer")
		id := assetIDGen().Draw(t, "id")
		spec := asset.NewSpecifierFromId(id)

		maxAmt := rapid.Uint64Range(1, 1_000_000).Draw(
			t, "maxAmt",
		)
		minAmt := optionalUint64Gen(maxAmt).Draw(
			t, "minAmt",
		)
		rateLimit := optionalFixedPointGen().Draw(
			t, "rateLimit",
		)

		req, err := NewBuyRequest(
			peer, spec, maxAmt, minAmt,
			rateLimit, fn.None[AssetRate](), "",
		)
		require.NoError(t, err)

		wireMsg, err := req.ToWire()
		require.NoError(t, err)

		var msgData requestWireMsgData
		err = msgData.Decode(
			bytes.NewReader(wireMsg.Data),
		)
		require.NoError(t, err)

		decoded, err := NewBuyRequestFromWire(
			wireMsg, msgData,
		)
		require.NoError(t, err)

		// Max amount must be preserved.
		require.Equal(t, maxAmt, decoded.AssetMaxAmt)

		// Min amount must match.
		requireOptEq(t, minAmt, decoded.AssetMinAmt)

		// Rate limit must match via Cmp.
		requireOptFpEq(
			t, rateLimit, decoded.AssetRateLimit,
		)
	})
}

// TestSellRequestWireRoundtripProperty checks that any valid
// SellRequest survives a wire encode/decode roundtrip.
func TestSellRequestWireRoundtripProperty(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		peer := peerGen().Draw(t, "peer")
		id := assetIDGen().Draw(t, "id")
		spec := asset.NewSpecifierFromId(id)

		maxAmt := rapid.Uint64Range(1, 1_000_000).Draw(
			t, "maxAmt",
		)
		minAmt := optionalMsatGen(maxAmt).Draw(
			t, "minAmt",
		)
		rateLimit := optionalFixedPointGen().Draw(
			t, "rateLimit",
		)

		req, err := NewSellRequest(
			peer, spec,
			lnwire.MilliSatoshi(maxAmt), minAmt,
			rateLimit, fn.None[AssetRate](), "",
		)
		require.NoError(t, err)

		wireMsg, err := req.ToWire()
		require.NoError(t, err)

		var msgData requestWireMsgData
		err = msgData.Decode(
			bytes.NewReader(wireMsg.Data),
		)
		require.NoError(t, err)

		decoded, err := NewSellRequestFromWire(
			wireMsg, msgData,
		)
		require.NoError(t, err)

		require.Equal(
			t, lnwire.MilliSatoshi(maxAmt),
			decoded.PaymentMaxAmt,
		)

		requireOptMsatEq(
			t, minAmt, decoded.PaymentMinAmt,
		)

		requireOptFpEq(
			t, rateLimit, decoded.AssetRateLimit,
		)
	})
}

// TestMinMaxConstraintProperty verifies that Validate accepts
// min <= max and rejects min > max for both buy and sell requests.
func TestMinMaxConstraintProperty(t *testing.T) {
	t.Parallel()

	t.Run("buy_valid", func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(t *rapid.T) {
			maxAmt := rapid.Uint64Range(1, 1_000_000).
				Draw(t, "max")
			minAmt := rapid.Uint64Range(0, maxAmt).
				Draw(t, "min")

			req := &BuyRequest{
				Version: V1,
				AssetSpecifier: asset.NewSpecifierFromId(
					asset.ID{1},
				),
				AssetMaxAmt: maxAmt,
				AssetMinAmt: fn.Some(minAmt),
				AssetRateLimit: fn.None[rfqmath.BigIntFixedPoint](),
				AssetRateHint: fn.None[AssetRate](),
			}
			require.NoError(t, req.Validate())
		})
	})

	t.Run("buy_invalid", func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(t *rapid.T) {
			maxAmt := rapid.Uint64Range(
				0, 1_000_000-1,
			).Draw(t, "max")
			minAmt := rapid.Uint64Range(
				maxAmt+1, 1_000_000,
			).Draw(t, "min")

			req := &BuyRequest{
				Version: V1,
				AssetSpecifier: asset.NewSpecifierFromId(
					asset.ID{1},
				),
				AssetMaxAmt: maxAmt,
				AssetMinAmt: fn.Some(minAmt),
				AssetRateLimit: fn.None[rfqmath.BigIntFixedPoint](),
				AssetRateHint: fn.None[AssetRate](),
			}
			require.Error(t, req.Validate())
		})
	})

	t.Run("sell_valid", func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(t *rapid.T) {
			maxAmt := rapid.Uint64Range(1, 1_000_000).
				Draw(t, "max")
			minAmt := rapid.Uint64Range(0, maxAmt).
				Draw(t, "min")

			req := &SellRequest{
				Version: V1,
				AssetSpecifier: asset.NewSpecifierFromId(
					asset.ID{1},
				),
				PaymentMaxAmt: lnwire.MilliSatoshi(
					maxAmt,
				),
				PaymentMinAmt: fn.Some(
					lnwire.MilliSatoshi(minAmt),
				),
				AssetRateLimit: fn.None[rfqmath.BigIntFixedPoint](),
				AssetRateHint: fn.None[AssetRate](),
			}
			require.NoError(t, req.Validate())
		})
	})

	t.Run("sell_invalid", func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(t *rapid.T) {
			maxAmt := rapid.Uint64Range(
				0, 1_000_000-1,
			).Draw(t, "max")
			minAmt := rapid.Uint64Range(
				maxAmt+1, 1_000_000,
			).Draw(t, "min")

			req := &SellRequest{
				Version: V1,
				AssetSpecifier: asset.NewSpecifierFromId(
					asset.ID{1},
				),
				PaymentMaxAmt: lnwire.MilliSatoshi(
					maxAmt,
				),
				PaymentMinAmt: fn.Some(
					lnwire.MilliSatoshi(minAmt),
				),
				AssetRateLimit: fn.None[rfqmath.BigIntFixedPoint](),
				AssetRateHint: fn.None[AssetRate](),
			}
			require.Error(t, req.Validate())
		})
	})
}

// TestRateBoundEnforcementProperty verifies that rate bound
// comparison follows the correct direction semantics:
//   - Buy: accepted >= limit passes, accepted < limit fails.
//   - Sell: accepted <= limit passes, accepted > limit fails.
func TestRateBoundEnforcementProperty(t *testing.T) {
	t.Parallel()

	t.Run("buy", func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(t *rapid.T) {
			accepted := fixedPointGen().Draw(
				t, "accepted",
			)
			limit := fixedPointGen().Draw(t, "limit")
			cmp := accepted.Cmp(limit)

			// Buy: accepted must be >= limit.
			if cmp >= 0 {
				require.False(
					t, accepted.Cmp(limit) < 0,
					"buy pass: accepted=%v limit=%v",
					accepted, limit,
				)
			} else {
				require.True(
					t, accepted.Cmp(limit) < 0,
					"buy fail: accepted=%v limit=%v",
					accepted, limit,
				)
			}
		})
	})

	t.Run("sell", func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(t *rapid.T) {
			accepted := fixedPointGen().Draw(
				t, "accepted",
			)
			limit := fixedPointGen().Draw(t, "limit")
			cmp := accepted.Cmp(limit)

			// Sell: accepted must be <= limit.
			if cmp <= 0 {
				require.False(
					t, accepted.Cmp(limit) > 0,
					"sell pass: accepted=%v limit=%v",
					accepted, limit,
				)
			} else {
				require.True(
					t, accepted.Cmp(limit) > 0,
					"sell fail: accepted=%v limit=%v",
					accepted, limit,
				)
			}
		})
	})
}

// TestBuyRequestRoundtripWithHintProperty verifies that a BuyRequest
// with all fields (including AssetRateHint) survives a roundtrip.
func TestBuyRequestRoundtripWithHintProperty(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		peer := peerGen().Draw(t, "peer")
		id := assetIDGen().Draw(t, "id")
		spec := asset.NewSpecifierFromId(id)

		maxAmt := rapid.Uint64Range(1, 1_000_000).Draw(
			t, "maxAmt",
		)
		minAmt := optionalUint64Gen(maxAmt).Draw(
			t, "minAmt",
		)
		rateLimit := optionalFixedPointGen().Draw(
			t, "rateLimit",
		)

		// Always include a rate hint so we test the full
		// field set.
		expiry := time.Now().Add(5 * time.Minute).UTC()
		fp := fixedPointGen().Draw(t, "hintRate")
		hint := fn.Some(NewAssetRate(fp, expiry))

		req, err := NewBuyRequest(
			peer, spec, maxAmt, minAmt,
			rateLimit, hint, "",
		)
		require.NoError(t, err)

		wireMsg, err := req.ToWire()
		require.NoError(t, err)

		var msgData requestWireMsgData
		err = msgData.Decode(
			bytes.NewReader(wireMsg.Data),
		)
		require.NoError(t, err)

		decoded, err := NewBuyRequestFromWire(
			wireMsg, msgData,
		)
		require.NoError(t, err)

		require.Equal(t, maxAmt, decoded.AssetMaxAmt)
		requireOptEq(t, minAmt, decoded.AssetMinAmt)
		requireOptFpEq(
			t, rateLimit, decoded.AssetRateLimit,
		)
		require.True(t, decoded.AssetRateHint.IsSome())
	})
}

// --- helpers ---

// requireOptEq asserts two fn.Option[uint64] values are equal.
func requireOptEq(t require.TestingT,
	want, got fn.Option[uint64]) {

	t.(*rapid.T).Helper()

	if want.IsNone() {
		require.True(t, got.IsNone())
		return
	}

	require.True(t, got.IsSome())

	wantVal := want.UnwrapOr(0)
	gotVal := got.UnwrapOr(0)
	require.Equal(t, wantVal, gotVal)
}

// requireOptMsatEq asserts two fn.Option[lnwire.MilliSatoshi]
// values are equal.
func requireOptMsatEq(t require.TestingT,
	want, got fn.Option[lnwire.MilliSatoshi]) {

	t.(*rapid.T).Helper()

	if want.IsNone() {
		require.True(t, got.IsNone())
		return
	}

	require.True(t, got.IsSome())

	wantVal := want.UnwrapOr(0)
	gotVal := got.UnwrapOr(0)
	require.Equal(t, wantVal, gotVal)
}

// requireOptFpEq asserts two optional BigIntFixedPoint values are
// equal via Cmp.
func requireOptFpEq(t require.TestingT,
	want, got fn.Option[rfqmath.BigIntFixedPoint]) {

	if want.IsNone() {
		require.True(t, got.IsNone())
		return
	}

	require.True(t, got.IsSome())

	wantVal := want.UnwrapOr(
		rfqmath.NewBigIntFixedPoint(0, 0),
	)
	gotVal := got.UnwrapOr(
		rfqmath.NewBigIntFixedPoint(0, 0),
	)
	require.Equal(t, 0, gotVal.Cmp(wantVal))
}
