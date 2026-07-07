package supplycommit

import (
	"context"
	"testing"

	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/tapreorg"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/stretchr/testify/mock"
)

// mockAnchoringRegistrar mocks the re-org watcher's registration
// surface.
type mockAnchoringRegistrar struct {
	mock.Mock
}

func (m *mockAnchoringRegistrar) Register(ctx context.Context,
	spec tapreorg.RegistrationSpec, phase1 func(context.Context,
		tapreorg.RegistryTx, tapreorg.AnchoringID) error,
) (tapreorg.AnchoringID, error) {

	args := m.Called(ctx, spec, phase1)
	return args.Get(0).(tapreorg.AnchoringID), args.Error(1)
}

func (m *mockAnchoringRegistrar) Anchorings(ctx context.Context,
	site tapreorg.SiteID) ([]*tapreorg.Anchoring, error) {

	args := m.Called(ctx, site)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*tapreorg.Anchoring), args.Error(1)
}

// expectFetchState arranges the durable record the resting state
// re-derives from.
func (h *supplyCommitTestHarness) expectFetchState(state State,
	transition lfn.Option[SupplyStateTransition]) {

	h.t.Helper()
	h.mockStateLog.On(
		"FetchState", mock.Anything, mock.Anything,
	).Return(state, transition, nil).Once()
}

// TestSupplyCommitBroadcastRestingTick exercises the anchoring path's
// resting broadcast state: the re-org watcher finalizes the transition
// out-of-band, and a tick makes the machine re-derive its position
// from the durable record.
func TestSupplyCommitBroadcastRestingTick(t *testing.T) {
	t.Parallel()

	testScriptKey := test.RandPubKey(t)
	randGroupKey := test.RandPubKey(t)
	defaultAssetSpec := asset.NewSpecifierOptionalGroupPubKey(
		testAssetID, randGroupKey,
	)
	mintEvent := newTestMintEvent(t, testScriptKey, randOutPoint(t))

	// Without a watcher configured, the legacy machine has no
	// business receiving ticks in the broadcast state.
	t.Run("legacy_tick_errors", func(t *testing.T) {
		h := newSupplyCommitTestHarness(t, &harnessCfg{
			initialState: &CommitBroadcastState{},
			assetSpec:    defaultAssetSpec,
		})
		h.start()
		defer h.stopAndAssert()

		h.assertHandlesInvalidEvent(
			&CommitTickEvent{}, ErrInvalidStateTransition,
		)
	})

	// While the durable record still says broadcast, the machine
	// keeps resting.
	t.Run("still_pending_rests", func(t *testing.T) {
		registrar := &mockAnchoringRegistrar{}
		h := newSupplyCommitTestHarness(t, &harnessCfg{
			initialState:     &CommitBroadcastState{},
			assetSpec:        defaultAssetSpec,
			anchoringWatcher: registrar,
		})
		h.start()
		defer h.stopAndAssert()

		h.expectFetchState(
			&CommitBroadcastState{},
			lfn.None[SupplyStateTransition](),
		)

		h.sendEvent(&CommitTickEvent{})
		h.assertStateTransitions(&CommitBroadcastState{})

		registrar.AssertExpectations(t)
	})

	// Once the watcher has finalized the transition with nothing
	// dangling, a tick brings the machine to rest in the default
	// state.
	t.Run("finalized_rests_default", func(t *testing.T) {
		registrar := &mockAnchoringRegistrar{}
		h := newSupplyCommitTestHarness(t, &harnessCfg{
			initialState:     &CommitBroadcastState{},
			assetSpec:        defaultAssetSpec,
			anchoringWatcher: registrar,
		})
		h.start()
		defer h.stopAndAssert()

		h.expectFetchState(
			&DefaultState{}, lfn.None[SupplyStateTransition](),
		)

		h.sendEvent(&CommitTickEvent{})
		h.assertStateTransitions(&DefaultState{})

		registrar.AssertExpectations(t)
	})

	// When the watcher's finalizer bound dangling updates into a
	// fresh pending transition, a tick adopts it and rolls straight
	// into the next commitment cycle, ending at rest in the broadcast
	// state with a freshly registered anchoring.
	t.Run("finalized_with_dangling_starts_cycle", func(t *testing.T) {
		registrar := &mockAnchoringRegistrar{}
		h := newSupplyCommitTestHarness(t, &harnessCfg{
			initialState:     &CommitBroadcastState{},
			assetSpec:        defaultAssetSpec,
			anchoringWatcher: registrar,
		})
		h.start()
		defer h.stopAndAssert()

		h.expectFetchState(
			&UpdatesPendingState{},
			lfn.Some(SupplyStateTransition{
				PendingUpdates: []SupplyUpdateEvent{
					mintEvent,
				},
			}),
		)
		h.expectFreezePendingTransition()

		// The cascade runs the full commitment cycle; on the
		// anchoring path broadcast registers with the watcher
		// instead of a conf subscription. The commitment fetch
		// provides a real pre-commitment, and the funding mock
		// preserves the transaction's essential inputs, so the
		// registered trigger set is the one production would build.
		h.expectTreeFetches()
		preCommitTx := wire.NewMsgTx(2)
		preCommitTx.AddTxOut(&wire.TxOut{
			Value:    1_000,
			PkScript: test.RandBytes(34),
		})
		preCommitKey, _ := test.RandKeyDesc(t)
		preCommit := PreCommitment{
			MintingTxn:  preCommitTx,
			OutIdx:      0,
			InternalKey: preCommitKey,
			GroupPubKey: *randGroupKey,
		}
		h.mockCommits.On(
			"UnspentPrecommits", mock.Anything, mock.Anything,
			mock.Anything,
		).Return(
			lfn.Ok[PreCommits]([]PreCommitment{preCommit}),
		).Once()
		h.mockCommits.On(
			"SupplyCommit", mock.Anything, mock.Anything,
		).Return(
			lfn.Ok(lfn.None[RootCommitment]()),
		).Once()
		h.expectKeyDerivationAndImport()
		h.expectFeeEstimation()

		// Unlike the shared funding mock, preserve the packet's
		// inputs and append a wallet fee input.
		fundPsbtFunc := fundPsbtMockFn(func(
			ctx context.Context, packet *psbt.Packet,
			minConfs uint32, feeRate chainfee.SatPerKWeight,
			changeIdx int32,
		) (*tapsend.FundedPsbt, error) {

			fundedTx := packet.UnsignedTx.Copy()
			fundedTx.AddTxIn(
				&wire.TxIn{
					PreviousOutPoint: randOutPoint(h.t),
				},
			)

			fundedPsbt, _ := psbt.NewFromUnsignedTx(fundedTx)
			return &tapsend.FundedPsbt{
				Pkt: fundedPsbt, ChangeOutputIndex: -1,
			}, nil
		})
		h.mockWallet.On(
			"FundPsbt", mock.Anything, mock.Anything,
			mock.Anything, mock.Anything, mock.Anything,
		).Return(fundPsbtFunc, nil).Once()

		h.expectPsbtSigning()
		h.expectInsertSignedCommitTx()
		h.expectAssetLookup()
		h.mockDaemon.On(
			"BroadcastTransaction", mock.Anything, mock.Anything,
		).Return(nil).Once()

		registrar.On("Anchorings", mock.Anything, SupplySiteID).
			Return([]*tapreorg.Anchoring{}, nil).Once()
		registrar.On(
			"Register", mock.Anything,
			mock.MatchedBy(func(
				spec tapreorg.RegistrationSpec) bool {

				// The trigger set must be exactly the
				// essential input: the pre-commitment
				// outpoint, with its script — the wallet
				// fee input is excluded.
				pts := spec.Triggers.OutPoints()
				return len(pts) == 1 &&
					pts[0].OutPoint == preCommit.OutPoint()
			}),
			mock.Anything,
		).Return(tapreorg.AnchoringID(1), nil).Once()

		h.sendEvent(&CommitTickEvent{})
		h.assertStateTransitions(
			&UpdatesPendingState{},
			&CommitTreeCreateState{},
			&CommitTxCreateState{},
			&CommitTxSignState{},
			&CommitBroadcastState{},
			&CommitBroadcastState{},
		)

		registrar.AssertExpectations(t)
	})
}

// TestSupplyCommitUpdatesPendingRederive exercises the re-derivation
// of the pending batch from the durable record: a machine resumed from
// disk rests in UpdatesPendingState with no in-memory updates, and a
// tick must commit the durable batch, not an empty one.
func TestSupplyCommitUpdatesPendingRederive(t *testing.T) {
	t.Parallel()

	testScriptKey := test.RandPubKey(t)
	randGroupKey := test.RandPubKey(t)
	defaultAssetSpec := asset.NewSpecifierOptionalGroupPubKey(
		testAssetID, randGroupKey,
	)
	mintEvent := newTestMintEvent(t, testScriptKey, randOutPoint(t))

	// A resumed machine re-derives the batch and runs the legacy
	// cycle (no watcher configured here).
	t.Run("resumed_empty_rederives", func(t *testing.T) {
		h := newSupplyCommitTestHarness(t, &harnessCfg{
			initialState: &UpdatesPendingState{},
			assetSpec:    defaultAssetSpec,
		})
		h.start()
		defer h.stopAndAssert()

		h.expectFetchState(
			&UpdatesPendingState{},
			lfn.Some(SupplyStateTransition{
				PendingUpdates: []SupplyUpdateEvent{
					mintEvent,
				},
			}),
		)
		h.expectFreezePendingTransition()
		h.expectFullCommitmentCycleMocks(true)

		h.sendEvent(&CommitTickEvent{})
		h.assertStateTransitions(
			&CommitTreeCreateState{},
			&CommitTxCreateState{},
			&CommitTxSignState{},
			&CommitBroadcastState{},
			&CommitBroadcastState{},
		)
	})

	// With nothing to commit anywhere, ticking is vacuous: the
	// machine returns to rest instead of committing an empty batch.
	t.Run("vacuous_tick_rests_default", func(t *testing.T) {
		h := newSupplyCommitTestHarness(t, &harnessCfg{
			initialState: &UpdatesPendingState{},
			assetSpec:    defaultAssetSpec,
		})
		h.start()
		defer h.stopAndAssert()

		h.expectFetchState(
			&UpdatesPendingState{},
			lfn.None[SupplyStateTransition](),
		)
		h.expectCommitState()

		h.sendEvent(&CommitTickEvent{})
		h.assertStateTransitions(&DefaultState{})
	})
}
