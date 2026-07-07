package tapdb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/tapreorg"
	"github.com/lightningnetwork/lnd/clock"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// newReorgStore builds a registry store over a fresh test database,
// with a test clock.
func newReorgStore(t testing.TB) (*ReorgRegistryStore, *clock.TestClock) {
	db := NewTestDB(t)
	testClock := clock.NewTestClock(time.Unix(1_000_000, 0))

	executor := NewTransactionExecutor(
		db, func(tx *sql.Tx) *sqlc.Queries {
			return db.WithTx(tx)
		},
	)

	return NewReorgRegistryStore(executor, testClock), testClock
}

// testOutPoint returns a deterministic outpoint.
func testOutPoint(seed byte, index uint32) wire.OutPoint {
	var op wire.OutPoint
	op.Hash[0] = seed
	op.Index = index

	return op
}

// testTriggerSet returns a trigger set over the given outpoints.
func testTriggerSet(t require.TestingT, ops ...wire.OutPoint) tapreorg.TriggerSet {
	points := make([]tapreorg.TriggerOutPoint, len(ops))
	for i, op := range ops {
		points[i] = tapreorg.TriggerOutPoint{
			OutPoint:   op,
			PkScript:   []byte{0x51},
			HeightHint: 100,
		}
	}

	triggers, err := tapreorg.NewTriggerSet(points)
	require.NoError(t, err)

	return triggers
}

// testSpec returns a valid registration spec over the given trigger
// outpoints.
func testSpec(t require.TestingT, site tapreorg.SiteID,
	ops ...wire.OutPoint) tapreorg.RegistrationSpec {

	return tapreorg.RegistrationSpec{
		Site:      site,
		Triggers:  testTriggerSet(t, ops...),
		MatchData: tapreorg.VersionedBlob{Version: 1},
		Payload:   tapreorg.VersionedBlob{Version: 1},
		Threshold: 6,
	}
}

// testWitness returns a witness whose transaction spends the given
// outpoints, located at the given height. The seed varies the
// transaction (and therefore its txid).
func testWitness(t require.TestingT, seed byte, height uint32,
	spends ...wire.OutPoint) tapreorg.Witness {

	tx := wire.NewMsgTx(2)
	for i := range spends {
		tx.AddTxIn(wire.NewTxIn(&spends[i], nil, nil))
	}
	tx.AddTxOut(wire.NewTxOut(int64(seed)+1_000, []byte{0x51, seed}))

	var blockHash chainhash.Hash
	blockHash[0] = seed

	w, err := tapreorg.NewWitness(tx, blockHash, height, 1)
	require.NoError(t, err)

	return w
}

// testEffect returns an effect bound to the given anchoring.
func testEffect(id tapreorg.AnchoringID, kind string) tapreorg.OutboxEffect {
	return tapreorg.OutboxEffect{
		Kind:      tapreorg.EffectKind(kind),
		Anchoring: fn.Some(id),
		Payload:   tapreorg.VersionedBlob{Version: 1, Data: []byte(kind)},
	}
}

// TestReorgRegistryLifecycle drives one anchoring through
// registration, sensing, failed and successful delivery, outbox
// dispatch and burial.
func TestReorgRegistryLifecycle(t *testing.T) {
	t.Parallel()

	store, testClock := newReorgStore(t)
	ctx := context.Background()

	op := testOutPoint(1, 0)
	spec := testSpec(t, "porter", op)

	// Registration runs the phase-1 write in the same transaction;
	// the effect it enqueues proves the handle works.
	id, err := store.Register(
		ctx, spec, 500,
		func(ctx context.Context, tx tapreorg.RegistryTx,
			newID tapreorg.AnchoringID) error {

			return tx.EnqueueEffect(
				ctx, testEffect(newID, "phase1"),
			)
		},
	)
	require.NoError(t, err)

	anchoring, err := store.GetAnchoring(ctx, id)
	require.NoError(t, err)
	require.Equal(t, tapreorg.SiteID("porter"), anchoring.Site)
	require.True(t, tapreorg.PhaseEqual(
		tapreorg.Unwitnessed{}, anchoring.Phase,
	))
	require.True(t, tapreorg.PhaseEqual(
		tapreorg.Unwitnessed{}, anchoring.DeliveredPhase,
	))
	require.Equal(t, 1, anchoring.Triggers.Len())
	require.True(t, anchoring.Triggers.Contains(op))

	// Converged: nothing pending.
	pending, err := store.PendingDeliveries(ctx, testClock.Now())
	require.NoError(t, err)
	require.Empty(t, pending)

	// A satisfying candidate confirms; sensing records it and
	// derives Witnessed.
	w := testWitness(t, 7, 600, op)
	require.NoError(t, store.UpsertCandidate(
		ctx, id, tapreorg.CandidateSpend{
			Verdict:        tapreorg.VerdictSatisfies,
			W:              w,
			OnChain:        true,
			SpentOutPoints: []wire.OutPoint{op},
		},
	))

	view, err := store.ChainView(ctx, id)
	require.NoError(t, err)
	witnessed := tapreorg.DerivePhase(view)
	require.IsType(t, tapreorg.Witnessed{}, witnessed)
	require.NoError(t, store.SetPhase(ctx, id, witnessed))

	pending, err = store.PendingDeliveries(ctx, testClock.Now())
	require.NoError(t, err)
	require.Len(t, pending, 1)
	require.Equal(t, id, pending[0].ID)

	// Delivering a phase sensing has moved past is stale.
	err = store.Deliver(ctx, id, tapreorg.Buried{W: w}, nil)
	require.ErrorIs(t, err, tapreorg.ErrStaleDelivery)

	// A failing handler rolls the delivery back.
	handlerErr := errors.New("site failure")
	err = store.Deliver(
		ctx, id, witnessed,
		func(context.Context, tapreorg.RegistryTx,
			*tapreorg.Anchoring) error {

			return handlerErr
		},
	)
	require.ErrorIs(t, err, handlerErr)

	// Failure bookkeeping backs the delivery off.
	nextAttempt := testClock.Now().Add(time.Minute)
	require.NoError(t, store.RecordDeliveryFailure(
		ctx, id, handlerErr, nextAttempt, false,
	))

	pending, err = store.PendingDeliveries(ctx, testClock.Now())
	require.NoError(t, err)
	require.Empty(t, pending)

	testClock.SetTime(testClock.Now().Add(2 * time.Minute))
	pending, err = store.PendingDeliveries(ctx, testClock.Now())
	require.NoError(t, err)
	require.Len(t, pending, 1)
	require.EqualValues(t, 1, pending[0].DeliveryAttempts)

	// Successful delivery: handler effect enqueued, bookkeeping
	// reset, site converged.
	err = store.Deliver(
		ctx, id, witnessed,
		func(ctx context.Context, tx tapreorg.RegistryTx,
			_ *tapreorg.Anchoring) error {

			return tx.EnqueueEffect(ctx, testEffect(id, "conf"))
		},
	)
	require.NoError(t, err)

	anchoring, err = store.GetAnchoring(ctx, id)
	require.NoError(t, err)
	require.True(t, tapreorg.PhaseEqual(
		witnessed, anchoring.DeliveredPhase,
	))
	require.Zero(t, anchoring.DeliveryAttempts)

	pending, err = store.PendingDeliveries(ctx, testClock.Now())
	require.NoError(t, err)
	require.Empty(t, pending)

	// Both effects are pending dispatch; dispatch one, fail the
	// other, then dispatch it after its backoff.
	effects, err := store.PendingEffects(ctx, testClock.Now(), 10)
	require.NoError(t, err)
	require.Len(t, effects, 2)

	require.NoError(t, store.MarkEffectDispatched(ctx, effects[0].ID))

	dispatchErr := errors.New("universe unreachable")
	retryAt := testClock.Now().Add(time.Minute)
	require.NoError(t, store.RecordEffectFailure(
		ctx, effects[1].ID, dispatchErr, retryAt,
	))

	effects, err = store.PendingEffects(ctx, testClock.Now(), 10)
	require.NoError(t, err)
	require.Empty(t, effects)

	testClock.SetTime(testClock.Now().Add(2 * time.Minute))
	effects, err = store.PendingEffects(ctx, testClock.Now(), 10)
	require.NoError(t, err)
	require.Len(t, effects, 1)
	require.EqualValues(t, 1, effects[0].Attempts)
	require.NoError(t, store.MarkEffectDispatched(ctx, effects[0].ID))

	// Burial: the notifier certifies the candidate at threshold
	// depth; the certified view derives Buried, whose terminal
	// delivery drops the anchoring from the live set.
	require.NoError(t, store.UpsertCandidate(
		ctx, id, tapreorg.CandidateSpend{
			Verdict:        tapreorg.VerdictSatisfies,
			W:              w,
			OnChain:        true,
			ActCertified:   true,
			SpentOutPoints: []wire.OutPoint{op},
		},
	))
	view, err = store.ChainView(ctx, id)
	require.NoError(t, err)
	buried := tapreorg.DerivePhase(view)
	require.IsType(t, tapreorg.Buried{}, buried)
	require.NoError(t, store.SetPhase(ctx, id, buried))
	require.NoError(t, store.Deliver(ctx, id, buried, nil))

	live, err := store.LiveAnchorings(ctx)
	require.NoError(t, err)
	require.Empty(t, live)

	// Unknown IDs surface as not-found.
	_, err = store.GetAnchoring(ctx, id+999)
	require.ErrorIs(t, err, tapreorg.ErrAnchoringNotFound)
}

// TestReorgRegistryHandlerAtomicity asserts the registry never
// advances past a failed handler: the handler's own writes (an
// enqueued effect) roll back with the delivery.
func TestReorgRegistryHandlerAtomicity(t *testing.T) {
	t.Parallel()

	store, testClock := newReorgStore(t)
	ctx := context.Background()

	op := testOutPoint(2, 0)
	id, err := store.Register(ctx, testSpec(t, "porter", op), 500, nil)
	require.NoError(t, err)

	w := testWitness(t, 3, 600, op)
	require.NoError(t, store.UpsertCandidate(
		ctx, id, tapreorg.CandidateSpend{
			Verdict:        tapreorg.VerdictSatisfies,
			W:              w,
			OnChain:        true,
			SpentOutPoints: []wire.OutPoint{op},
		},
	))
	witnessed := tapreorg.Witnessed{W: w}
	require.NoError(t, store.SetPhase(ctx, id, witnessed))

	// The handler enqueues an effect and then fails: neither the
	// delivery nor the effect may survive.
	boom := errors.New("boom")
	err = store.Deliver(
		ctx, id, witnessed,
		func(ctx context.Context, tx tapreorg.RegistryTx,
			_ *tapreorg.Anchoring) error {

			err := tx.EnqueueEffect(ctx, testEffect(id, "leak"))
			require.NoError(t, err)

			return boom
		},
	)
	require.ErrorIs(t, err, boom)

	anchoring, err := store.GetAnchoring(ctx, id)
	require.NoError(t, err)
	require.True(t, tapreorg.PhaseEqual(
		tapreorg.Unwitnessed{}, anchoring.DeliveredPhase,
	))

	effects, err := store.PendingEffects(ctx, testClock.Now(), 10)
	require.NoError(t, err)
	require.Empty(t, effects)
}

// TestReorgRegistryDependencies exercises automatic edge derivation,
// the withdrawal guard, cascade foreclosure on abandonment, and the
// child's resulting derivation.
func TestReorgRegistryDependencies(t *testing.T) {
	t.Parallel()

	store, _ := newReorgStore(t)
	ctx := context.Background()

	// The parent anchors at witness wP; the child spends wP's
	// output 0.
	parentOp := testOutPoint(4, 0)
	parentID, err := store.Register(
		ctx, testSpec(t, "minter", parentOp), 500, nil,
	)
	require.NoError(t, err)

	wP := testWitness(t, 5, 600, parentOp)
	require.NoError(t, store.UpsertCandidate(
		ctx, parentID, tapreorg.CandidateSpend{
			Verdict:        tapreorg.VerdictSatisfies,
			W:              wP,
			OnChain:        true,
			SpentOutPoints: []wire.OutPoint{parentOp},
		},
	))
	require.NoError(t, store.SetPhase(
		ctx, parentID, tapreorg.Witnessed{W: wP},
	))

	childOp := wire.OutPoint{Hash: wP.TxHash(), Index: 0}
	childID, err := store.Register(
		ctx, testSpec(t, "porter", childOp), 601, nil,
	)
	require.NoError(t, err)

	// The edge was derived automatically, pinned to wP.
	edges, err := store.DependencyEdges(ctx, parentID)
	require.NoError(t, err)
	require.Len(t, edges, 1)
	require.Equal(t, childID, edges[0].Child)
	require.Equal(t, wP.TxHash(), edges[0].ParentWitnessTxHash)
	require.True(t, edges[0].Foreclosure.IsNone())

	// A parent with live dependents cannot be withdrawn.
	err = store.Withdraw(ctx, parentID, nil)
	require.ErrorIs(t, err, tapreorg.ErrLiveDependents)

	// A foreign spend of the parent's trigger buries; the parent
	// abandons, and its delivery forecloses the child's edge in
	// the same transaction.
	wF := testWitness(t, 6, 610, parentOp)
	abandoned := tapreorg.Abandoned{Cause: tapreorg.ForeignBurial{
		Spend: tapreorg.ForeignSpend{SpentOutPoint: parentOp, W: wF},
	}}
	require.NoError(t, store.SetPhase(ctx, parentID, abandoned))
	require.NoError(t, store.Deliver(ctx, parentID, abandoned, nil))

	edges, err = store.DependencyEdges(ctx, parentID)
	require.NoError(t, err)
	require.Len(t, edges, 1)
	fc := edges[0].Foreclosure.UnwrapToPtr()
	require.NotNil(t, fc)
	require.True(t, fc.OnChain)
	require.Equal(t, wF.TxHash(), fc.W.TxHash())

	// The child's chain view carries the staged foreclosure, but
	// while uncertified it carries no force: the child abandons
	// only when the notifier certifies the foreclosing transaction
	// at the child's own threshold.
	view, err := store.ChainView(ctx, childID)
	require.NoError(t, err)
	require.True(t, view.Foreclosure.IsSome())

	shallow := tapreorg.DerivePhase(view)
	require.True(t, tapreorg.PhaseEqual(tapreorg.Unwitnessed{}, shallow))

	// Certification of the foreclosing transaction resolves the
	// child, attributed to the parent.
	require.NoError(t, store.StageForeclosure(
		ctx, childID, parentID, tapreorg.ForeclosureEvent{
			Parent:       parentID,
			W:            wF,
			OnChain:      true,
			ActCertified: true,
		},
	))
	view, err = store.ChainView(ctx, childID)
	require.NoError(t, err)

	childPhase := tapreorg.DerivePhase(view)
	childAbandoned, ok := childPhase.(tapreorg.Abandoned)
	require.True(t, ok)
	cause, ok := childAbandoned.Cause.(tapreorg.Foreclosed)
	require.True(t, ok)
	require.Equal(t, parentID, cause.Parent)
	require.Equal(t, wF.TxHash(), cause.W.TxHash())

	// Terminal anchorings cannot be withdrawn.
	require.NoError(t, store.SetPhase(ctx, childID, childPhase))
	err = store.Withdraw(ctx, childID, nil)
	require.ErrorIs(t, err, tapreorg.ErrTerminalPhase)
	err = store.Withdraw(ctx, parentID, nil)
	require.ErrorIs(t, err, tapreorg.ErrTerminalPhase)

	// A live, dependent-free anchoring withdraws cleanly, sensed
	// and delivered advancing together.
	loneID, err := store.Register(
		ctx, testSpec(t, "porter", testOutPoint(9, 1)), 700, nil,
	)
	require.NoError(t, err)
	require.NoError(t, store.Withdraw(
		ctx, loneID,
		func(ctx context.Context,
			tx tapreorg.RegistryTx) error {

			return tx.EnqueueEffect(
				ctx, testEffect(loneID, "undo"),
			)
		},
	))

	lone, err := store.GetAnchoring(ctx, loneID)
	require.NoError(t, err)
	require.True(t, tapreorg.PhaseEqual(tapreorg.Withdrawn{}, lone.Phase))
	require.True(t, tapreorg.PhaseEqual(
		tapreorg.Withdrawn{}, lone.DeliveredPhase,
	))
}

// TestReorgRegistryRapid is a model-based test of the pending-
// delivery invariant: after arbitrary interleavings of registration,
// phase changes, deliveries, failures and clock advances, the set of
// pending deliveries reported by the store is exactly the model's
// {id : phase != delivered && nextAttempt <= now}.
func TestReorgRegistryRapid(t *testing.T) {
	t.Parallel()

	// The store is shared across rapid iterations (a fresh database
	// costs seconds of migrations), so every comparison below is
	// scoped to the iteration's own anchoring IDs. Leaked state
	// from prior iterations is invisible to the assertions; the
	// cost is that shrunk counterexamples may depend on accumulated
	// rows.
	store, testClock := newReorgStore(t)

	rapid.Check(t, func(rt *rapid.T) {
		ctx := context.Background()

		type modelAnchoring struct {
			phase     tapreorg.Phase
			delivered tapreorg.Phase
			nextAt    time.Time
			op        wire.OutPoint
			seq       byte
		}
		model := make(map[tapreorg.AnchoringID]*modelAnchoring)
		ids := make([]tapreorg.AnchoringID, 0)

		var seed byte
		numOps := rapid.IntRange(5, 25).Draw(rt, "numOps")
		for i := 0; i < numOps; i++ {
			opKind := rapid.IntRange(0, 3).Draw(
				rt, fmt.Sprintf("op%d", i),
			)

			// Without anchorings, only registration applies.
			if len(ids) == 0 {
				opKind = 0
			}

			switch opKind {
			// Register a new anchoring.
			case 0:
				seed++
				op := testOutPoint(seed, uint32(seed))
				id, err := store.Register(
					ctx, testSpec(rt, "site", op), 500,
					nil,
				)
				require.NoError(rt, err)

				model[id] = &modelAnchoring{
					phase:     tapreorg.Unwitnessed{},
					delivered: tapreorg.Unwitnessed{},
					nextAt:    time.Unix(0, 0),
					op:        op,
					seq:       seed,
				}
				ids = append(ids, id)

			// Sense a new phase (a fresh witness each time, so
			// rewitness forces redelivery).
			case 1:
				id := ids[rapid.IntRange(0, len(ids)-1).Draw(
					rt, fmt.Sprintf("op%d.id", i),
				)]
				m := model[id]
				if tapreorg.IsTerminal(m.phase) {
					continue
				}

				m.seq += 100
				w := testWitness(
					rt, m.seq,
					uint32(600+i), m.op,
				)
				var phase tapreorg.Phase = tapreorg.Witnessed{
					W: w,
				}
				if rapid.Bool().Draw(
					rt, fmt.Sprintf("op%d.unwit", i),
				) {

					phase = tapreorg.Unwitnessed{}
				}

				require.NoError(rt, store.SetPhase(
					ctx, id, phase,
				))
				m.phase = phase

				// A new sensed phase resets the previous
				// objective's failure bookkeeping.
				m.nextAt = time.Unix(0, 0)

			// Attempt delivery of the sensed phase.
			case 2:
				id := ids[rapid.IntRange(0, len(ids)-1).Draw(
					rt, fmt.Sprintf("op%d.id", i),
				)]
				m := model[id]

				fail := rapid.Bool().Draw(
					rt, fmt.Sprintf("op%d.fail", i),
				)
				if fail {
					boom := errors.New("boom")
					err := store.Deliver(
						ctx, id, m.phase,
						func(context.Context,
							tapreorg.RegistryTx,
							*tapreorg.Anchoring,
						) error {

							return boom
						},
					)
					if !tapreorg.PhaseEqual(
						m.phase, m.delivered,
					) {

						require.ErrorIs(rt, err, boom)
					} else {
						// Already converged: the
						// handler never runs.
						require.NoError(rt, err)
						continue
					}

					next := testClock.Now().Add(
						time.Minute,
					)
					require.NoError(
						rt,
						store.RecordDeliveryFailure(
							ctx, id, boom, next,
							false,
						),
					)
					m.nextAt = next

					continue
				}

				err := store.Deliver(ctx, id, m.phase, nil)
				require.NoError(rt, err)
				m.delivered = m.phase
				m.nextAt = time.Unix(0, 0)

			// Advance the clock past pending backoffs.
			case 3:
				testClock.SetTime(testClock.Now().Add(
					2 * time.Minute,
				))
			}

			// The invariant: pending deliveries are exactly the
			// model's lagging, unbacked-off anchorings.
			now := testClock.Now()
			pending, err := store.PendingDeliveries(ctx, now)
			require.NoError(rt, err)

			got := make(map[tapreorg.AnchoringID]bool)
			for _, p := range pending {
				// Scope to this iteration's anchorings; the
				// shared database may hold rows from prior
				// iterations.
				if _, ours := model[p.ID]; ours {
					got[p.ID] = true
				}
			}

			want := make(map[tapreorg.AnchoringID]bool)
			for id, m := range model {
				lagging := !tapreorg.PhaseEqual(
					m.phase, m.delivered,
				)
				if lagging && !m.nextAt.After(now) {
					want[id] = true
				}
			}

			require.Equal(rt, want, got)
		}
	})
}

// TestReorgRegistrySeedCandidate exercises the seeded-registration
// path: a spec that provides a SeedCandidate stores it in the
// registration transaction, the anchoring's chain view reflects the
// seed, and phase derivation immediately observes Witnessed. This is
// the shape a genesis-shaped receive uses to stake on a proof file's
// tip anchor tx, which is already known confirmed at registration.
func TestReorgRegistrySeedCandidate(t *testing.T) {
	t.Parallel()

	store, _ := newReorgStore(t)
	ctx := context.Background()

	// Build the seed's witness and block context. The tx's input
	// is a wallet UTXO from the caller's world; the seeded-
	// registration path does not watch it — the tx IS the
	// witnessing spender, and the anchoring's chain view records
	// the tx directly without a trigger set.
	fundingOp := testOutPoint(0x11, 0)
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(&fundingOp, nil, nil))
	tx.AddTxOut(wire.NewTxOut(1_000, []byte{0x51, 0xaa}))
	var blockHash chainhash.Hash
	blockHash[0] = 0xaa
	witness, err := tapreorg.NewWitness(tx, blockHash, 600, 1)
	require.NoError(t, err)

	header := &wire.BlockHeader{Timestamp: time.Unix(1, 0)}
	merkle := &proof.TxMerkleProof{
		Bits:  []bool{false},
		Nodes: []chainhash.Hash{},
	}

	spec := tapreorg.RegistrationSpec{
		Site:      "receiver",
		Triggers:  tapreorg.TriggerSet{},
		MatchData: tapreorg.VersionedBlob{Version: 1},
		Payload:   tapreorg.VersionedBlob{Version: 1},
		Threshold: 6,
		SeedCandidate: &tapreorg.CandidateSpend{
			W:           witness,
			Verdict:     tapreorg.VerdictSatisfies,
			OnChain:     true,
			BlockHeader: header,
			MerkleProof: merkle,
		},
	}

	id, err := store.Register(ctx, spec, 500, nil)
	require.NoError(t, err)

	// The seed is durable in the registration transaction.
	view, err := store.ChainView(ctx, id)
	require.NoError(t, err)
	require.Len(t, view.Spends, 1)
	require.Equal(t, witness.TxHash(), view.Spends[0].W.TxHash())
	require.True(t, view.Spends[0].OnChain)
	require.NotNil(t, view.Spends[0].BlockHeader)
	require.NotNil(t, view.Spends[0].MerkleProof)

	// Phase derivation immediately reports Witnessed.
	phase := tapreorg.DerivePhase(view)
	require.IsType(t, tapreorg.Witnessed{}, phase)
}

// TestReorgRegistrySeedCandidateValidation asserts the value-level
// checks on a seeded spec: on-chain, with a block header and merkle
// proof.
func TestReorgRegistrySeedCandidateValidation(t *testing.T) {
	t.Parallel()

	tx := wire.NewMsgTx(2)
	tx.AddTxOut(wire.NewTxOut(1_000, []byte{0x51, 0xbb}))
	var blockHash chainhash.Hash
	blockHash[0] = 0xbb
	witness, err := tapreorg.NewWitness(tx, blockHash, 700, 0)
	require.NoError(t, err)

	base := tapreorg.RegistrationSpec{
		Site:      "receiver",
		MatchData: tapreorg.VersionedBlob{Version: 1},
		Payload:   tapreorg.VersionedBlob{Version: 1},
		Threshold: 6,
	}

	// Empty triggers with no seed → ErrEmptyTriggerSet.
	err = base.Validate()
	require.ErrorIs(t, err, tapreorg.ErrEmptyTriggerSet)

	// Seed not on-chain.
	spec := base
	spec.SeedCandidate = &tapreorg.CandidateSpend{
		W:       witness,
		Verdict: tapreorg.VerdictSatisfies,
		OnChain: false,
	}
	require.ErrorContains(t, spec.Validate(), "on-chain")

	// Seed on-chain but missing block header.
	spec.SeedCandidate.OnChain = true
	require.ErrorContains(t, spec.Validate(), "block header")

	// Header set, merkle proof missing.
	spec.SeedCandidate.BlockHeader = &wire.BlockHeader{}
	require.ErrorContains(t, spec.Validate(), "merkle proof")

	// Full valid seed.
	spec.SeedCandidate.MerkleProof = &proof.TxMerkleProof{}
	require.NoError(t, spec.Validate())
}

// TestReorgRegistryLookupByMatchKey asserts the indexed identity
// lookup: registrations with a MatchKey are stored under (site,
// match_key), a second Register with the same key hits the unique
// constraint, and LookupByMatchKey returns the anchoring in O(1). An
// empty match key disables the check.
func TestReorgRegistryLookupByMatchKey(t *testing.T) {
	t.Parallel()

	store, _ := newReorgStore(t)
	ctx := context.Background()

	spec := testSpec(t, "porter", testOutPoint(1, 0))
	spec.MatchKey = []byte("txid-1")

	id, err := store.Register(ctx, spec, 500, nil)
	require.NoError(t, err)

	// Round-trip through GetAnchoring surfaces the key.
	anchoring, err := store.GetAnchoring(ctx, id)
	require.NoError(t, err)
	require.Equal(t, spec.MatchKey, anchoring.MatchKey)

	// Indexed lookup returns the same anchoring.
	found, err := store.LookupByMatchKey(ctx, "porter", spec.MatchKey)
	require.NoError(t, err)
	require.NotNil(t, found)
	require.Equal(t, id, found.ID)

	// Miss returns (nil, nil).
	miss, err := store.LookupByMatchKey(ctx, "porter", []byte("nope"))
	require.NoError(t, err)
	require.Nil(t, miss)

	// Empty key returns (nil, nil) without hitting the index.
	miss, err = store.LookupByMatchKey(ctx, "porter", nil)
	require.NoError(t, err)
	require.Nil(t, miss)

	// Registering the same site + match_key again hits the unique
	// partial index.
	dup := testSpec(t, "porter", testOutPoint(2, 0))
	dup.MatchKey = spec.MatchKey
	_, err = store.Register(ctx, dup, 500, nil)
	require.Error(t, err)

	// A registration with the same key at a DIFFERENT site is fine:
	// the index is per-site.
	crossSite := testSpec(t, "custody", testOutPoint(3, 0))
	crossSite.MatchKey = spec.MatchKey
	_, err = store.Register(ctx, crossSite, 500, nil)
	require.NoError(t, err)

	// Two registrations at the same site with NULL match_key coexist:
	// the unique index excludes null keys.
	free1 := testSpec(t, "porter", testOutPoint(4, 0))
	_, err = store.Register(ctx, free1, 500, nil)
	require.NoError(t, err)
	free2 := testSpec(t, "porter", testOutPoint(5, 0))
	_, err = store.Register(ctx, free2, 500, nil)
	require.NoError(t, err)
}

// TestReorgRegistryDeliveryFreshAggregate pins the reviewer #2
// contract: the anchoring aggregate handed to the delivery handler is
// assembled INSIDE the delivery transaction, so candidate enrichment
// that landed between the caller's scan and Deliver's tx is visible.
// Without this, handlers that read Spends[i].BlockHeader / MerkleProof
// (the mint site's witness context, the porter's witness context)
// could see stale evidence and spuriously fail.
func TestReorgRegistryDeliveryFreshAggregate(t *testing.T) {
	t.Parallel()

	store, _ := newReorgStore(t)
	ctx := context.Background()

	op := testOutPoint(42, 0)
	id, err := store.Register(
		ctx, testSpec(t, "porter", op), 500, nil,
	)
	require.NoError(t, err)

	// A satisfying candidate lands WITHOUT block enrichment — the
	// initial state at witness delivery time.
	w := testWitness(t, 9, 600, op)
	require.NoError(t, store.UpsertCandidate(
		ctx, id, tapreorg.CandidateSpend{
			Verdict:        tapreorg.VerdictSatisfies,
			W:              w,
			OnChain:        true,
			SpentOutPoints: []wire.OutPoint{op},
		},
	))

	view, err := store.ChainView(ctx, id)
	require.NoError(t, err)
	witnessed := tapreorg.DerivePhase(view)
	require.IsType(t, tapreorg.Witnessed{}, witnessed)
	require.NoError(t, store.SetPhase(ctx, id, witnessed))

	// Snapshot the anchoring at scan time: no block header, no
	// merkle proof.
	scanned, err := store.GetAnchoring(ctx, id)
	require.NoError(t, err)
	require.Len(t, scanned.Spends, 1)
	require.Nil(t, scanned.Spends[0].BlockHeader)
	require.Nil(t, scanned.Spends[0].MerkleProof)

	// Sensing enriches the candidate between scan and Deliver.
	header := wire.BlockHeader{Version: 42}
	merkle := proof.TxMerkleProof{Bits: []bool{true}}
	enriched := scanned.Spends[0]
	enriched.BlockHeader = &header
	enriched.MerkleProof = &merkle
	require.NoError(t, store.UpsertCandidate(ctx, id, enriched))

	// Deliver: the handler must observe the fresh (enriched) view,
	// not the scanned (stale) view.
	err = store.Deliver(
		ctx, id, witnessed,
		func(_ context.Context, _ tapreorg.RegistryTx,
			fresh *tapreorg.Anchoring) error {

			require.Len(t, fresh.Spends, 1)
			require.NotNil(
				t, fresh.Spends[0].BlockHeader,
				"handler saw stale headerless spend",
			)
			require.NotNil(
				t, fresh.Spends[0].MerkleProof,
				"handler saw stale merkle-less spend",
			)
			require.Equal(
				t, header.Version,
				fresh.Spends[0].BlockHeader.Version,
			)

			return nil
		},
	)
	require.NoError(t, err)
}
