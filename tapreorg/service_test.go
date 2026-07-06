package tapreorg_test

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/tapdb"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/tapreorg"
	"github.com/lightninglabs/taproot-assets/tapreorg/chainsim"
	"github.com/lightningnetwork/lnd/clock"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

const (
	testSiteID    tapreorg.SiteID = "test-site"
	testThreshold uint32          = 3

	// The settle timeout is generous because the shared rapid
	// harness saturates SQLite (synchronous=full + fullfsync makes
	// every commit an F_FULLFSYNC on macOS); genuine convergence
	// under low load takes milliseconds.
	settleTimeout = 30 * time.Second
	settleTick    = 10 * time.Millisecond
)

// testSite is a convergent site: each handler records the delivered
// phase as the site's applied state, from whatever state it was in.
// Match data is a concatenation of satisfying txids.
type testSite struct {
	id tapreorg.SiteID

	mu        sync.Mutex
	evalCount map[chainhash.Hash]int
	applied   map[tapreorg.AnchoringID]tapreorg.Phase
	history   map[tapreorg.AnchoringID][]string

	failing atomic.Bool
}

func newTestSite(id tapreorg.SiteID) *testSite {
	return &testSite{
		id:        id,
		evalCount: make(map[chainhash.Hash]int),
		applied:   make(map[tapreorg.AnchoringID]tapreorg.Phase),
		history:   make(map[tapreorg.AnchoringID][]string),
	}
}

func (s *testSite) ID() tapreorg.SiteID {
	return s.id
}

func (s *testSite) EvaluateCandidate(match tapreorg.VersionedBlob,
	spendingTx *wire.MsgTx) (tapreorg.Verdict, error) {

	txid := spendingTx.TxHash()

	s.mu.Lock()
	s.evalCount[txid]++
	s.mu.Unlock()

	for i := 0; i+32 <= len(match.Data); i += 32 {
		if bytes.Equal(match.Data[i:i+32], txid[:]) {
			return tapreorg.VerdictSatisfies, nil
		}
	}

	return tapreorg.VerdictForeign, nil
}

// apply is the shared convergent handler body.
func (s *testSite) apply(name string, anchoring *tapreorg.Anchoring) error {
	if s.failing.Load() {
		return fmt.Errorf("site %v is failing", s.id)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.applied[anchoring.ID] = anchoring.Phase
	s.history[anchoring.ID] = append(s.history[anchoring.ID], name)

	return nil
}

func (s *testSite) OnWitnessed(ctx context.Context, tx tapreorg.RegistryTx,
	a *tapreorg.Anchoring) error {

	return s.apply("witnessed", a)
}

func (s *testSite) OnUnwitnessed(ctx context.Context, tx tapreorg.RegistryTx,
	a *tapreorg.Anchoring) error {

	return s.apply("unwitnessed", a)
}

func (s *testSite) OnConflicted(ctx context.Context, tx tapreorg.RegistryTx,
	a *tapreorg.Anchoring) error {

	return s.apply("conflicted", a)
}

func (s *testSite) OnBuried(ctx context.Context, tx tapreorg.RegistryTx,
	a *tapreorg.Anchoring) error {

	return s.apply("buried", a)
}

func (s *testSite) OnAbandoned(ctx context.Context, tx tapreorg.RegistryTx,
	a *tapreorg.Anchoring) error {

	return s.apply("abandoned", a)
}

// appliedPhase returns the site's applied state for an anchoring.
func (s *testSite) appliedPhase(id tapreorg.AnchoringID) tapreorg.Phase {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.applied[id]
}

// evaluations returns how often the predicate ran for a candidate.
func (s *testSite) evaluations(txid chainhash.Hash) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.evalCount[txid]
}

// harness wires a chainsim, a real SQLite-backed registry, a test
// site and the watcher together.
type harness struct {
	t *testing.T

	sim     *chainsim.Chain
	store   *tapdb.ReorgRegistryStore
	rawDB   *sql.DB
	dbPath  string
	site    *testSite
	watcher *tapreorg.Watcher

	effects atomic.Int32

	txSeq atomic.Uint32
}

func newHarness(t *testing.T) *harness {
	dbPath := filepath.Join(t.TempDir(), "harness.db")
	db := tapdb.NewTestSqliteDbHandleFromPath(t, dbPath)
	executor := tapdb.NewTransactionExecutor(
		db, func(tx *sql.Tx) *sqlc.Queries {
			return db.WithTx(tx)
		},
	)

	h := &harness{
		t:      t,
		sim:    chainsim.New(),
		rawDB:  db.DB,
		dbPath: dbPath,
		store: tapdb.NewReorgRegistryStore(
			executor, clock.NewDefaultClock(),
		),
		site: newTestSite(testSiteID),
	}
	h.watcher = h.newWatcher()

	return h
}

// newWatcher builds a watcher over the harness's sim and store, with
// aggressive timing for tests.
func (h *harness) newWatcher() *tapreorg.Watcher {
	w := tapreorg.NewWatcher(&tapreorg.WatcherConfig{
		Notifier:               h.sim,
		Registry:               h.store,
		InitialDeliveryBackoff: 10 * time.Millisecond,
		MaxDeliveryBackoff:     40 * time.Millisecond,
		StuckAfterAttempts:     2,
		ScanInterval:           20 * time.Millisecond,
	})
	require.NoError(h.t, w.RegisterSite(h.site))
	require.NoError(h.t, w.RegisterEffectHandler(
		"test", func(context.Context, fn.Option[tapreorg.AnchoringID],
			tapreorg.VersionedBlob) error {

			h.effects.Add(1)
			return nil
		},
	))

	return w
}

// start starts the watcher and registers cleanup.
func (h *harness) start() {
	require.NoError(h.t, h.watcher.Start())
	h.t.Cleanup(func() {
		require.NoError(h.t, h.watcher.Stop())
	})
}

// restart stops the current watcher and brings up a fresh instance
// over the same store and sim: process death and recovery. A start
// that fails on transient database contention is retried with a
// fresh instance (a failed Start consumes the instance's startOnce).
func (h *harness) restart() {
	require.NoError(h.t, h.watcher.Stop())

	var err error
	for attempt := 0; attempt < 50; attempt++ {
		h.watcher = h.newWatcher()
		err = h.watcher.Start()
		if !errors.Is(err, tapdb.ErrRetriesExceeded) {
			break
		}
		require.NoError(h.t, h.watcher.Stop())
		time.Sleep(settleTick)
	}
	require.NoError(h.t, err)
}

// flushPool evicts idle pool connections. Under heavy concurrent
// load, modernc/sqlite pool connections can end up pinned to an old
// WAL snapshot and serve stale reads for a long time (bounded in
// production by the pool's connection max lifetime); evicting idle
// connections forces fresh snapshots. This is a workaround for a
// pre-existing tapdb infrastructure wart the harness's read pressure
// exposes, not for watcher behavior.
func (h *harness) flushPool() {
	h.rawDB.SetMaxIdleConns(0)
	h.rawDB.SetMaxIdleConns(25)
}

// spendTx builds a transaction spending the given outpoints, unique
// per call.
func (h *harness) spendTx(ops ...wire.OutPoint) *wire.MsgTx {
	tx := wire.NewMsgTx(2)
	for i := range ops {
		tx.AddTxIn(wire.NewTxIn(&ops[i], nil, nil))
	}
	seq := h.txSeq.Add(1)
	tx.AddTxOut(wire.NewTxOut(int64(seq), []byte{0x51}))

	return tx
}

// register stakes an anchoring over the given trigger outpoints,
// whose satisfying forms are the given transactions.
func (h *harness) register(threshold uint32, satisfying []*wire.MsgTx,
	triggers ...wire.OutPoint) tapreorg.AnchoringID {

	points := make([]tapreorg.TriggerOutPoint, len(triggers))
	for i, op := range triggers {
		points[i] = tapreorg.TriggerOutPoint{
			OutPoint:   op,
			PkScript:   []byte{0x51},
			HeightHint: 1,
		}
	}
	triggerSet, err := tapreorg.NewTriggerSet(points)
	require.NoError(h.t, err)

	var matchData []byte
	for _, tx := range satisfying {
		txid := tx.TxHash()
		matchData = append(matchData, txid[:]...)
	}

	spec := tapreorg.RegistrationSpec{
		Site:     testSiteID,
		Triggers: triggerSet,
		MatchData: tapreorg.VersionedBlob{
			Version: 1,
			Data:    matchData,
		},
		Payload:   tapreorg.VersionedBlob{Version: 1},
		Threshold: threshold,
	}
	phase1 := func(ctx context.Context, tx tapreorg.RegistryTx,
		newID tapreorg.AnchoringID) error {

		return tx.EnqueueEffect(ctx, tapreorg.OutboxEffect{
			Kind:      "test",
			Anchoring: fn.Some(newID),
			Payload: tapreorg.VersionedBlob{
				Version: 1,
			},
		})
	}

	// Registration is retried through transient database
	// contention: the harness's polling load can exhaust SQLite's
	// busy-retry budget, which is a load artifact, not a defect.
	var id tapreorg.AnchoringID
	for attempt := 0; attempt < 50; attempt++ {
		id, err = h.watcher.Register( //nolint:contextcheck
			context.Background(), spec, phase1,
		)
		if !errors.Is(err, tapdb.ErrRetriesExceeded) {
			break
		}
		time.Sleep(settleTick)
	}
	require.NoError(h.t, err)

	// The returned id names a committed row; verify it becomes
	// readable, tolerating transient contention and evicting
	// pinned pool snapshots along the way.
	readBackDeadline := time.Now().Add(10 * time.Second)
	for {
		_, err = h.store.GetAnchoring(context.Background(), id)
		if err == nil {
			break
		}
		if time.Now().After(readBackDeadline) {
			h.t.Fatalf("registered anchoring %d never became "+
				"readable: %v", id, err)
		}
		h.flushPool()
		time.Sleep(settleTick)
	}

	return id
}

// settleWhere waits until the anchoring satisfies the condition.
func (h *harness) settleWhere(id tapreorg.AnchoringID,
	cond func(*tapreorg.Anchoring) bool) {

	h.t.Helper()

	require.Eventually(h.t, func() bool {
		anchoring, err := h.store.GetAnchoring(
			context.Background(), id,
		)
		if err != nil {
			return false
		}

		return cond(anchoring)
	}, settleTimeout, settleTick)
}

// settleConverged waits until the anchoring's sensed phase matches
// want, the site has durably acknowledged it, and the site's applied
// state agrees.
func (h *harness) settleConverged(id tapreorg.AnchoringID,
	want tapreorg.Phase) {

	h.t.Helper()

	h.settleWhere(id, func(a *tapreorg.Anchoring) bool {
		if !tapreorg.PhaseEqual(a.Phase, want) {
			return false
		}
		if !tapreorg.PhaseEqual(a.DeliveredPhase, want) {
			return false
		}

		// The registration itself delivered Unwitnessed without
		// a handler call, so the site's applied state is only
		// checked once some phase change has been delivered.
		if tapreorg.PhaseEqual(want, tapreorg.Unwitnessed{}) {
			return true
		}
		applied := h.site.appliedPhase(id)

		return applied != nil && tapreorg.PhaseEqual(applied, want)
	})
}

// txHeightOf reports a transaction's current chain height for
// diagnostics, -1 when absent.
func txHeightOf(sim *chainsim.Chain, tx *wire.MsgTx) int {
	if height, ok := sim.TxHeight(tx.TxHash()); ok {
		return int(height)
	}

	return -1
}

// phaseKind names a phase variant for coarse assertions.
func phaseKind(p tapreorg.Phase) string {
	switch p.(type) {
	case tapreorg.Unwitnessed:
		return "unwitnessed"
	case tapreorg.Witnessed:
		return "witnessed"
	case tapreorg.Conflicted:
		return "conflicted"
	case tapreorg.Buried:
		return "buried"
	case tapreorg.Abandoned:
		return "abandoned"
	case tapreorg.Withdrawn:
		return "withdrawn"
	default:
		return fmt.Sprintf("unknown<%T>", p)
	}
}

// TestWatcherHappyPath drives one anchoring from registration through
// witnessing to burial, checking the outbox and predicate economy on
// the way.
func TestWatcherHappyPath(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.start()

	op := wire.OutPoint{Hash: chainhash.Hash{1}, Index: 0}
	satTx := h.spendTx(op)
	id := h.register(testThreshold, []*wire.MsgTx{satTx}, op)

	// Registered, nothing on chain: unwitnessed and converged, and
	// the phase-1 effect dispatched.
	h.settleConverged(id, tapreorg.Unwitnessed{})
	require.Eventually(t, func() bool {
		return h.effects.Load() == 1
	}, settleTimeout, settleTick)

	// The satisfying spend confirms: witnessed.
	h.sim.MineBlock(satTx)
	h.settleWhere(id, func(a *tapreorg.Anchoring) bool {
		w, ok := a.Phase.(tapreorg.Witnessed)
		if !ok || w.W.TxHash() != satTx.TxHash() {
			return false
		}

		return tapreorg.PhaseEqual(a.DeliveredPhase, a.Phase)
	})

	// Burial at threshold: act-confirmed, sensing ends.
	h.sim.MineBlocks(int(testThreshold) - 1)
	h.settleWhere(id, func(a *tapreorg.Anchoring) bool {
		b, ok := a.Phase.(tapreorg.Buried)
		if !ok || b.W.TxHash() != satTx.TxHash() {
			return false
		}

		return tapreorg.PhaseEqual(a.DeliveredPhase, a.Phase)
	})
	require.Equal(t, "buried", phaseKind(h.site.appliedPhase(id)))

	live, err := h.store.LiveAnchorings(context.Background())
	require.NoError(t, err)
	require.Empty(t, live)

	// The pure predicate ran exactly once for the candidate.
	require.Equal(t, 1, h.site.evaluations(satTx.TxHash()))
}

// TestWatcherConflictAbandon drives the adverse side: a foreign spend
// conflicts at potency, recovers when it reorgs out, and abandons at
// act depth when it returns and buries.
func TestWatcherConflictAbandon(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.start()

	op := wire.OutPoint{Hash: chainhash.Hash{2}, Index: 0}
	satTx := h.spendTx(op)
	foreignTx := h.spendTx(op)
	id := h.register(testThreshold, []*wire.MsgTx{satTx}, op)

	// A foreign spend confirms: conflicted, soft action only.
	h.sim.MineBlock(foreignTx)
	h.settleWhere(id, func(a *tapreorg.Anchoring) bool {
		return phaseKind(a.Phase) == "conflicted" &&
			tapreorg.PhaseEqual(a.DeliveredPhase, a.Phase)
	})

	// The foreign spend reorgs out with no successor: back to
	// unwitnessed. Excluded middle honoured — the registry never
	// asserts a stale conflict.
	h.sim.Reorg(1, nil)
	h.settleConverged(id, tapreorg.Unwitnessed{})
	require.Equal(
		t, "unwitnessed", phaseKind(h.site.appliedPhase(id)),
	)

	// The foreign spend returns and buries: the chain has decided
	// against us; compensation runs.
	h.sim.MineBlock(foreignTx)
	h.sim.MineBlocks(int(testThreshold) - 1)
	h.settleWhere(id, func(a *tapreorg.Anchoring) bool {
		abandoned, ok := a.Phase.(tapreorg.Abandoned)
		if !ok {
			return false
		}
		cause, ok := abandoned.Cause.(tapreorg.ForeignBurial)
		if !ok || cause.Spend.W.TxHash() != foreignTx.TxHash() {
			return false
		}

		return tapreorg.PhaseEqual(a.DeliveredPhase, a.Phase)
	})
	require.Equal(t, "abandoned", phaseKind(h.site.appliedPhase(id)))
}

// TestWatcherRewitness drives the form-change case: a different
// satisfying transaction (an RBF-style replacement) wins after a
// reorg, and the anchoring rewitnesses rather than conflicting.
func TestWatcherRewitness(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.start()

	op := wire.OutPoint{Hash: chainhash.Hash{3}, Index: 0}
	formA := h.spendTx(op)
	formB := h.spendTx(op)
	id := h.register(testThreshold, []*wire.MsgTx{formA, formB}, op)

	h.sim.MineBlock(formA)
	h.settleWhere(id, func(a *tapreorg.Anchoring) bool {
		w, ok := a.Phase.(tapreorg.Witnessed)
		return ok && w.W.TxHash() == formA.TxHash() &&
			tapreorg.PhaseEqual(a.DeliveredPhase, a.Phase)
	})

	// The reorg replaces form A with form B in one step.
	h.sim.Reorg(1, []*wire.MsgTx{formB})
	h.settleWhere(id, func(a *tapreorg.Anchoring) bool {
		w, ok := a.Phase.(tapreorg.Witnessed)
		return ok && w.W.TxHash() == formB.TxHash() &&
			tapreorg.PhaseEqual(a.DeliveredPhase, a.Phase)
	})

	// Burial follows the winning form.
	h.sim.MineBlocks(int(testThreshold) - 1)
	h.settleWhere(id, func(a *tapreorg.Anchoring) bool {
		b, ok := a.Phase.(tapreorg.Buried)
		return ok && b.W.TxHash() == formB.TxHash() &&
			tapreorg.PhaseEqual(a.DeliveredPhase, a.Phase)
	})
}

// TestWatcherCascade drives dependency foreclosure: a child anchoring
// whose triggers were created by a parent's witness abandons, by
// cascade, when the parent's premises die at act depth.
func TestWatcherCascade(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.start()

	parentOp := wire.OutPoint{Hash: chainhash.Hash{4}, Index: 0}
	satParent := h.spendTx(parentOp)
	parentID := h.register(
		testThreshold, []*wire.MsgTx{satParent}, parentOp,
	)

	h.sim.MineBlock(satParent)
	h.settleWhere(parentID, func(a *tapreorg.Anchoring) bool {
		return phaseKind(a.Phase) == "witnessed"
	})

	// The child spends the parent witness's output 0; the edge is
	// derived automatically at registration.
	childOp := wire.OutPoint{Hash: satParent.TxHash(), Index: 0}
	satChild := h.spendTx(childOp)
	childID := h.register(testThreshold, []*wire.MsgTx{satChild}, childOp)

	h.sim.MineBlock(satChild)
	h.settleWhere(childID, func(a *tapreorg.Anchoring) bool {
		return phaseKind(a.Phase) == "witnessed"
	})

	// The chain discards both and a foreign spend claims the
	// parent's trigger. The child's own witness is gone (its
	// outpoint no longer exists), and no direct evidence about the
	// child can ever arrive again.
	foreignParent := h.spendTx(parentOp)
	h.sim.Reorg(2, []*wire.MsgTx{foreignParent}, nil)

	h.settleWhere(childID, func(a *tapreorg.Anchoring) bool {
		return phaseKind(a.Phase) == "unwitnessed"
	})

	// The foreign spend buries: the parent abandons directly, and
	// the child follows by cascade, attributed to the parent.
	h.sim.MineBlocks(int(testThreshold))

	h.settleWhere(parentID, func(a *tapreorg.Anchoring) bool {
		return phaseKind(a.Phase) == "abandoned" &&
			tapreorg.PhaseEqual(a.DeliveredPhase, a.Phase)
	})
	h.settleWhere(childID, func(a *tapreorg.Anchoring) bool {
		abandoned, ok := a.Phase.(tapreorg.Abandoned)
		if !ok {
			return false
		}
		cause, ok := abandoned.Cause.(tapreorg.Foreclosed)
		if !ok || cause.Parent != parentID {
			return false
		}

		return tapreorg.PhaseEqual(a.DeliveredPhase, a.Phase)
	})
}

// TestWatcherRestart kills the watcher mid-flight, moves the chain
// while it is down, and asserts a fresh instance converges from the
// registry alone.
func TestWatcherRestart(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.start()

	op := wire.OutPoint{Hash: chainhash.Hash{5}, Index: 0}
	satTx := h.spendTx(op)
	id := h.register(testThreshold, []*wire.MsgTx{satTx}, op)

	h.sim.MineBlock(satTx)
	h.settleWhere(id, func(a *tapreorg.Anchoring) bool {
		return phaseKind(a.Phase) == "witnessed" &&
			tapreorg.PhaseEqual(a.DeliveredPhase, a.Phase)
	})

	// Down across the burial boundary.
	require.NoError(t, h.watcher.Stop())
	h.sim.MineBlocks(int(testThreshold) - 1)

	h.watcher = h.newWatcher()
	require.NoError(t, h.watcher.Start())

	h.settleWhere(id, func(a *tapreorg.Anchoring) bool {
		b, ok := a.Phase.(tapreorg.Buried)
		return ok && b.W.TxHash() == satTx.TxHash() &&
			tapreorg.PhaseEqual(a.DeliveredPhase, a.Phase)
	})
	require.Equal(t, "buried", phaseKind(h.site.appliedPhase(id)))
}

// TestWatcherStuckDelivery wedges the site and asserts that sensing
// keeps tracking the chain while delivery is stuck (and visible as
// such), and that convergence resumes when the site heals.
func TestWatcherStuckDelivery(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.start()

	op := wire.OutPoint{Hash: chainhash.Hash{6}, Index: 0}
	satTx := h.spendTx(op)
	id := h.register(testThreshold, []*wire.MsgTx{satTx}, op)
	h.settleConverged(id, tapreorg.Unwitnessed{})

	h.site.failing.Store(true)

	// Sensing tracks the chain to burial while the site fails; the
	// delivered phase stays behind and the anchoring goes stuck.
	h.sim.MineBlock(satTx)
	h.sim.MineBlocks(int(testThreshold) - 1)

	h.settleWhere(id, func(a *tapreorg.Anchoring) bool {
		return phaseKind(a.Phase) == "buried" && a.Stuck &&
			tapreorg.PhaseEqual(
				a.DeliveredPhase, tapreorg.Unwitnessed{},
			)
	})

	// The site heals; the perpetual retry converges it. Coalescing
	// means the site sees only the latest phase: burial, without
	// the witnessed step it missed.
	h.site.failing.Store(false)
	h.settleWhere(id, func(a *tapreorg.Anchoring) bool {
		return phaseKind(a.Phase) == "buried" && !a.Stuck &&
			tapreorg.PhaseEqual(a.DeliveredPhase, a.Phase)
	})
	require.Equal(t, "buried", phaseKind(h.site.appliedPhase(id)))
}

// TestWatcherRapid is the randomized torture: arbitrary interleavings
// of mining, re-orgs, quiet blocks and restarts against one anchoring
// per iteration, with the expected phase computed from the simulated
// chain by an independent oracle, and terminal absorption pinned.
//
// The harness (database, sim, watcher) is shared across iterations
// for speed; each iteration uses fresh outpoints and candidates, so
// prior iterations' anchorings cannot influence its assertions.
func TestWatcherRapid(t *testing.T) {
	h := newHarness(t)
	h.start()

	var iteration uint32
	rapid.Check(t, func(rt *rapid.T) {
		iteration++

		var opHash chainhash.Hash
		opHash[0] = byte(iteration)
		opHash[1] = byte(iteration >> 8)
		opHash[31] = 0xee
		op := wire.OutPoint{Hash: opHash, Index: 0}

		formA := h.spendTx(op)
		formB := h.spendTx(op)
		foreign := h.spendTx(op)
		candidates := []*wire.MsgTx{formA, formB, foreign}

		threshold := uint32(rapid.IntRange(2, 4).Draw(rt, "threshold"))
		id := h.register(
			threshold, []*wire.MsgTx{formA, formB}, op,
		)

		// onChainSpender reports which candidate currently spends
		// the trigger on the sim chain, if any.
		onChainSpender := func() (*wire.MsgTx, uint32, bool) {
			for _, tx := range candidates {
				if height, ok := h.sim.TxHeight(
					tx.TxHash(),
				); ok {

					return tx, height, true
				}
			}

			return nil, 0, false
		}

		// oracle computes the expected phase kind (and witness,
		// when applicable) from the sim chain directly.
		oracle := func() (string, chainhash.Hash) {
			spender, height, ok := onChainSpender()
			if !ok {
				return "unwitnessed", chainhash.Hash{}
			}

			depth := h.sim.BestHeight() - height + 1
			satisfying := spender.TxHash() != foreign.TxHash()

			switch {
			case satisfying && depth >= threshold:
				return "buried", spender.TxHash()
			case satisfying:
				return "witnessed", spender.TxHash()
			case depth >= threshold:
				return "abandoned", chainhash.Hash{}
			default:
				return "conflicted", chainhash.Hash{}
			}
		}

		// Once the registry reaches a terminal phase, it must
		// never leave it, whatever the chain does.
		var pinned tapreorg.Phase

		// The chain may make a terminal phase sensible only
		// transiently (act depth reached, then erased by a
		// reorg deeper than the threshold — explicitly
		// unrecoverable by design). Whether sensing observed
		// the transient is a race both sides of which are
		// legitimate, so the oracle accepts any terminal the
		// chain ever made sensible, keyed by kind and deciding
		// transaction.
		possibleTerminals := make(map[string]bool)

		terminalKey := func(p tapreorg.Phase) string {
			switch phase := p.(type) {
			case tapreorg.Buried:
				return "buried:" + phase.W.TxHash().String()

			case tapreorg.Abandoned:
				burial, ok := phase.Cause.(tapreorg.ForeignBurial)
				if !ok {
					return "abandoned:foreclosed"
				}
				txid := burial.Spend.W.TxHash()

				return "abandoned:" + txid.String()

			default:
				return ""
			}
		}

		// recordPossible captures the current chain state's
		// terminal reading, if any; called after every action.
		recordPossible := func() {
			kind, witness := oracle()
			switch kind {
			case "buried":
				possibleTerminals["buried:"+
					witness.String()] = true

			case "abandoned":
				txid := foreign.TxHash()
				possibleTerminals["abandoned:"+
					txid.String()] = true
			}
		}

		converged := func(a *tapreorg.Anchoring) bool {
			if pinned != nil {
				return tapreorg.PhaseEqual(
					a.Phase, pinned,
				) && tapreorg.PhaseEqual(
					a.DeliveredPhase, pinned,
				)
			}

			if !tapreorg.PhaseEqual(
				a.DeliveredPhase, a.Phase,
			) {

				return false
			}

			// A terminal registry phase is acceptable exactly
			// when the chain made it sensible at some point;
			// it pins from here on.
			if tapreorg.IsTerminal(a.Phase) {
				if !possibleTerminals[terminalKey(a.Phase)] {
					return false
				}
				pinned = a.Phase

				return true
			}

			wantKind, wantWitness := oracle()
			if phaseKind(a.Phase) != wantKind {
				return false
			}
			if w, ok := a.Phase.(tapreorg.Witnessed); ok &&
				w.W.TxHash() != wantWitness {

				return false
			}

			return true
		}

		settle := func() {
			deadline := time.Now().Add(settleTimeout)
			flushAt := time.Now().Add(settleTimeout / 3)
			for time.Now().Before(deadline) {
				// A stalled settle may be reading through
				// pinned pool snapshots; evict them.
				if time.Now().After(flushAt) {
					h.flushPool()
					flushAt = time.Now().Add(
						settleTimeout / 3,
					)
				}

				a, err := h.store.GetAnchoring(
					context.Background(), id,
				)
				if err != nil {
					// Under heavy concurrent load the
					// WAL-mode read can transiently
					// miss a just-committed row or
					// exhaust the busy-retry budget;
					// the poll simply retries, and a
					// persistent condition still
					// times out below. Anything else
					// is a real failure.
					transient := errors.Is(
						err,
						tapreorg.ErrAnchoringNotFound,
					) || errors.Is(
						err,
						tapdb.ErrRetriesExceeded,
					)
					require.True(rt, transient,
						"unexpected error: %v", err)
					time.Sleep(settleTick)
					continue
				}
				if converged(a) {
					return
				}

				time.Sleep(settleTick)
			}

			a, getErr := h.store.GetAnchoring(
				context.Background(), id,
			)
			var state, spends string
			if a != nil {
				state = fmt.Sprintf(
					"phase=%v delivered=%v stuck=%v",
					a.Phase, a.DeliveredPhase, a.Stuck,
				)
				for _, sp := range a.Spends {
					spends += fmt.Sprintf(
						" [%v on=%v cert=%v @%d]",
						sp.W.TxHash(), sp.OnChain,
						sp.ActCertified,
						sp.W.Height(),
					)
				}
			} else {
				state = fmt.Sprintf("unreadable: %v", getErr)
			}
			var total, maxID, exists int
			_ = h.rawDB.QueryRow(
				"SELECT count(*), coalesce(max(id), 0) "+
					"FROM reorg_anchorings",
			).Scan(&total, &maxID)
			_ = h.rawDB.QueryRow(
				"SELECT count(*) FROM reorg_anchorings "+
					"WHERE id = ?", int64(id),
			).Scan(&exists)

			// The same reads through a brand-new handle on
			// the same file distinguish pool-connection
			// snapshot pinning from genuine data loss.
			var fTotal, fMax, fExists int
			freshDB, freshErr := sql.Open("sqlite", h.dbPath)
			if freshErr == nil {
				_ = freshDB.QueryRow(
					"SELECT count(*), "+
						"coalesce(max(id), 0) "+
						"FROM reorg_anchorings",
				).Scan(&fTotal, &fMax)
				_ = freshDB.QueryRow(
					"SELECT count(*) "+
						"FROM reorg_anchorings "+
						"WHERE id = ?", int64(id),
				).Scan(&fExists)
				_ = freshDB.Close()
			}

			wantKind, wantWitness := oracle()
			rt.Fatalf("never settled: id=%d raw(total=%d "+
				"max=%d exists=%d) fresh(total=%d max=%d "+
				"exists=%d) registry %s; oracle "+
				"kind=%v witness=%v; pinned=%v; best=%d; "+
				"formA@%v formB@%v foreign@%v; spends:%s",
				id, total, maxID, exists, fTotal, fMax,
				fExists, state,
				wantKind, wantWitness, pinned,
				h.sim.BestHeight(),
				txHeightOf(h.sim, formA),
				txHeightOf(h.sim, formB),
				txHeightOf(h.sim, foreign), spends)
		}

		settle()

		numActions := rapid.IntRange(2, 8).Draw(rt, "numActions")
		for i := 0; i < numActions; i++ {
			label := fmt.Sprintf("action%d", i)

			switch rapid.IntRange(0, 4).Draw(rt, label) {
			// Quiet block.
			case 0:
				h.sim.MineBlocks(1)

			// Mine a candidate, if the trigger is unspent on
			// the current chain (the whole-set rule is a
			// property of one chain); a quiet block
			// otherwise.
			case 1:
				if _, _, spent := onChainSpender(); spent {
					h.sim.MineBlocks(1)
					break
				}
				pick := rapid.IntRange(0, 2).Draw(
					rt, label+".pick",
				)
				h.sim.MineBlock(candidates[pick])

			// Reorg, optionally substituting a different
			// candidate for whatever fell out. A fresh chain
			// has nothing to reorg; mine instead.
			case 2:
				depth := rapid.IntRange(1, 3).Draw(
					rt, label+".depth",
				)
				if depth > h.sim.Length() {
					depth = h.sim.Length()
				}
				if depth == 0 {
					h.sim.MineBlocks(1)
					recordPossible()
					settle()
					continue
				}
				replacement := make(
					[][]*wire.MsgTx, depth,
				)

				h.sim.Reorg(depth, replacement...)
				if _, _, spent := onChainSpender(); !spent &&
					rapid.Bool().Draw(
						rt, label+".substitute",
					) {

					pick := rapid.IntRange(0, 2).Draw(
						rt, label+".pick",
					)
					h.sim.MineBlock(candidates[pick])
				}

			// Bury whatever stands.
			case 3:
				h.sim.MineBlocks(int(threshold))

			// Process death and recovery.
			case 4:
				h.restart()
			}

			recordPossible()
			settle()
		}

		// Bound the shared harness's live set: production
		// anchorings terminate, and a monotonically growing
		// sensor population is a harness artifact that only
		// stresses the database. Withdrawal is refused exactly
		// when the anchoring already terminated on its own;
		// transient contention is retried.
		for attempt := 0; attempt < 50; attempt++ {
			err := h.watcher.Withdraw(
				context.Background(), id, nil,
			)
			if errors.Is(err, tapdb.ErrRetriesExceeded) {
				time.Sleep(settleTick)
				continue
			}
			if err != nil {
				require.ErrorIs(
					rt, err, tapreorg.ErrTerminalPhase,
				)
			}
			break
		}
	})
}
