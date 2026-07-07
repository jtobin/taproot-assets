package tapreorg

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/clock"
)

const (
	// DefaultTimeout is the default timeout used for RPC and database
	// operations issued by the watcher.
	DefaultTimeout = 30 * time.Second

	// DefaultInitialDeliveryBackoff is the default backoff after a
	// first failed delivery or dispatch attempt.
	DefaultInitialDeliveryBackoff = 30 * time.Second

	// DefaultMaxDeliveryBackoff caps the exponential delivery and
	// dispatch backoff.
	DefaultMaxDeliveryBackoff = 10 * time.Minute

	// DefaultStuckAfterAttempts is the number of consecutive
	// delivery failures after which an anchoring is flagged stuck.
	// Retries continue past it, at the capped backoff, forever.
	DefaultStuckAfterAttempts = 10

	// DefaultScanInterval is the default cadence of the delivery
	// and outbox reconciliation scans. Scans also run immediately
	// when sensing changes a phase, so this is a floor on recovery
	// latency, not on delivery latency.
	DefaultScanInterval = time.Minute

	// outboxBatchSize bounds how many effects one dispatch pass
	// claims.
	outboxBatchSize = 32
)

// EffectHandler dispatches one kind of outbox effect. Handlers must
// be idempotent: an effect can be dispatched more than once if the
// process dies between the dispatch and the bookkeeping write. The
// anchoring the effect was enqueued for, if any, is passed along.
type EffectHandler func(ctx context.Context,
	anchoring fn.Option[AnchoringID], payload VersionedBlob) error

// WatcherConfig houses the watcher's dependencies and policy knobs.
type WatcherConfig struct {
	// Notifier is the chain-sensing surface.
	Notifier ChainNotifier

	// Registry is the durable anchoring store.
	Registry Registry

	// InitialDeliveryBackoff, MaxDeliveryBackoff and
	// StuckAfterAttempts set the delivery failure policy.
	InitialDeliveryBackoff time.Duration
	MaxDeliveryBackoff     time.Duration
	StuckAfterAttempts     uint32

	// ScanInterval is the cadence of the delivery and outbox
	// reconciliation scans.
	ScanInterval time.Duration

	// Clock is the time source for backoff bookkeeping.
	Clock clock.Clock

	// ErrChan reports critical errors to the main server.
	ErrChan chan<- error
}

// fillDefaults populates zero-valued policy knobs.
func (c *WatcherConfig) fillDefaults() {
	if c.InitialDeliveryBackoff == 0 {
		c.InitialDeliveryBackoff = DefaultInitialDeliveryBackoff
	}
	if c.MaxDeliveryBackoff == 0 {
		c.MaxDeliveryBackoff = DefaultMaxDeliveryBackoff
	}
	if c.StuckAfterAttempts == 0 {
		c.StuckAfterAttempts = DefaultStuckAfterAttempts
	}
	if c.ScanInterval == 0 {
		c.ScanInterval = DefaultScanInterval
	}
	if c.Clock == nil {
		c.Clock = clock.NewDefaultClock()
	}
}

// Watcher is the daemon's single organ for reconciling speculative
// local state with chain history: it senses the chain into per-
// anchoring chain views, derives phases as a pure function of those
// views, and converges sites to the derived phases through handlers
// that run atomically with the registry advance.
type Watcher struct {
	startOnce sync.Once
	stopOnce  sync.Once

	cfg *WatcherConfig

	sites          map[SiteID]Site
	effectHandlers map[EffectKind]EffectHandler
	listeners      []DeliveryListener

	bestHeight atomic.Uint32

	// events funnels all sensing inputs into the sensing loop.
	events chan any

	// deliveryKick and outboxKick wake the respective loops ahead
	// of their scan tickers.
	deliveryKick chan struct{}
	outboxKick   chan struct{}

	// sensors is owned by the sensing loop.
	sensors map[AnchoringID]*sensor

	*fn.ContextGuard
}

// NewWatcher creates a new watcher from the given config. Sites and
// effect handlers are registered before Start.
func NewWatcher(cfg *WatcherConfig) *Watcher {
	cfg.fillDefaults()

	return &Watcher{
		cfg:            cfg,
		sites:          make(map[SiteID]Site),
		effectHandlers: make(map[EffectKind]EffectHandler),
		events:         make(chan any),
		deliveryKick:   make(chan struct{}, 1),
		outboxKick:     make(chan struct{}, 1),
		sensors:        make(map[AnchoringID]*sensor),
		ContextGuard: &fn.ContextGuard{
			DefaultTimeout: DefaultTimeout,
			Quit:           make(chan struct{}),
		},
	}
}

// RegisterSite installs a site implementation. All sites must be
// registered before Start, so that restart reconciliation can route
// replayed deliveries.
func (w *Watcher) RegisterSite(site Site) error {
	if _, ok := w.sites[site.ID()]; ok {
		return fmt.Errorf("site %v already registered", site.ID())
	}
	w.sites[site.ID()] = site

	return nil
}

// DeliveryListener observes successful deliveries, invoked after the
// delivery transaction commits. Latency path only: the registry
// remains the durable delivery record, and a missed notification is
// recovered by reading it.
type DeliveryListener func(id AnchoringID, site SiteID, phase Phase)

// RegisterDeliveryListener installs a delivery listener. All
// listeners are registered before Start.
func (w *Watcher) RegisterDeliveryListener(listener DeliveryListener) {
	w.listeners = append(w.listeners, listener)
}

// RegisterEffectHandler installs the dispatch handler for one effect
// kind. All handlers are registered before Start.
func (w *Watcher) RegisterEffectHandler(kind EffectKind,
	handler EffectHandler) error {

	if _, ok := w.effectHandlers[kind]; ok {
		return fmt.Errorf("effect handler %v already registered",
			kind)
	}
	w.effectHandlers[kind] = handler

	return nil
}

// Start brings the watcher up: it re-establishes sensing for every
// live anchoring in the registry and launches the sensing, delivery
// and outbox loops. Sites do nothing special at startup; the delivery
// scan replays whatever their delivered phase lags.
func (w *Watcher) Start() error {
	var startErr error
	w.startOnce.Do(func() {
		log.Info("Starting re-org watcher")

		ctx, cancel := w.WithCtxQuitNoTimeout()
		defer cancel()

		height, err := w.cfg.Notifier.CurrentHeight(ctx)
		if err != nil {
			startErr = fmt.Errorf("unable to get current "+
				"height: %w", err)
			return
		}
		w.bestHeight.Store(height)

		live, err := w.cfg.Registry.LiveAnchorings(ctx)
		if err != nil {
			startErr = fmt.Errorf("unable to load live "+
				"anchorings: %w", err)
			return
		}

		w.Wg.Add(3)
		go w.sensingLoop(live)
		go w.deliveryLoop()
		go w.outboxLoop()
	})

	return startErr
}

// Stop signals the watcher to exit and waits for its loops.
func (w *Watcher) Stop() error {
	w.stopOnce.Do(func() {
		log.Info("Stopping re-org watcher")

		close(w.Quit)
		w.Wg.Wait()
	})

	return nil
}

// Register stakes a new anchoring: the registry insert, dependency-
// edge derivation and the site's phase-1 write commit in one
// transaction, and sensing begins immediately after. The site must
// have been registered with the watcher.
func (w *Watcher) Register(ctx context.Context, spec RegistrationSpec,
	phase1 func(context.Context, RegistryTx,
		AnchoringID) error) (AnchoringID, error) {

	if _, ok := w.sites[spec.Site]; !ok {
		return 0, fmt.Errorf("unknown site %v", spec.Site)
	}

	id, err := w.cfg.Registry.Register(
		ctx, spec, w.bestHeight.Load(), phase1,
	)
	if err != nil {
		return 0, err
	}

	if err := w.sendEvent(ctx, evSense{id: id}); err != nil {
		return 0, err
	}

	return id, nil
}

// Withdraw revokes a live stake: the site's withdrawal write and the
// terminal registry advance commit in one transaction, and sensing
// stops.
func (w *Watcher) Withdraw(ctx context.Context, id AnchoringID,
	onWithdraw func(context.Context, RegistryTx) error) error {

	if err := w.cfg.Registry.Withdraw(ctx, id, onWithdraw); err != nil {
		return err
	}

	return w.sendEvent(ctx, evStopSensing{id: id})
}

// Anchoring reads one anchoring, live or terminal, from the registry.
func (w *Watcher) Anchoring(ctx context.Context,
	id AnchoringID) (*Anchoring, error) {

	return w.cfg.Registry.GetAnchoring(ctx, id)
}

// Anchorings reads the live anchorings registered by one site.
func (w *Watcher) Anchorings(ctx context.Context,
	site SiteID) ([]*Anchoring, error) {

	live, err := w.cfg.Registry.LiveAnchorings(ctx)
	if err != nil {
		return nil, err
	}

	out := make([]*Anchoring, 0, len(live))
	for _, anchoring := range live {
		if anchoring.Site == site {
			out = append(out, anchoring)
		}
	}

	return out, nil
}

// LookupByMatchKey reads a site's anchoring by its per-site identity
// key. See Registrar.LookupByMatchKey for the contract.
func (w *Watcher) LookupByMatchKey(ctx context.Context, site SiteID,
	matchKey []byte) (*Anchoring, error) {

	return w.cfg.Registry.LookupByMatchKey(ctx, site, matchKey)
}

// AllAnchorings reads one site's anchorings across every phase,
// settled ones included. Identity lookups — a resumed subsystem
// re-finding its stake, a registration deduplicating by payload —
// must span the full history: an anchoring leaves the live set the
// moment it is buried, which is precisely when a restarted consumer
// comes looking for it.
func (w *Watcher) AllAnchorings(ctx context.Context,
	site SiteID) ([]*Anchoring, error) {

	all, err := w.cfg.Registry.AllAnchorings(ctx)
	if err != nil {
		return nil, err
	}

	out := make([]*Anchoring, 0, len(all))
	for _, anchoring := range all {
		if anchoring.Site == site {
			out = append(out, anchoring)
		}
	}

	return out, nil
}

// sendEvent delivers an event to the sensing loop, respecting
// shutdown and the caller's context.
func (w *Watcher) sendEvent(ctx context.Context, event any) error {
	select {
	case w.events <- event:
		return nil

	case <-ctx.Done():
		return ctx.Err()

	case <-w.Quit:
		return fmt.Errorf("watcher shutting down")
	}
}

// Internal sensing events.
type (
	// evSense (re-)establishes sensing for an anchoring and
	// re-derives its phase.
	evSense struct {
		id AnchoringID
	}

	// evStopSensing tears down sensing for an anchoring.
	evStopSensing struct {
		id AnchoringID
	}

	// evSpendDetail reports a confirmed spend of a trigger
	// outpoint.
	evSpendDetail struct {
		id     AnchoringID
		op     wire.OutPoint
		detail *chainntnfs.SpendDetail
	}

	// evSpendReorg reports that the previously reported spend of a
	// trigger outpoint was re-organized out.
	evSpendReorg struct {
		id AnchoringID
		op wire.OutPoint
	}

	// evCandidateConf reports a candidate transaction's (re-)
	// confirmation, with its full location.
	evCandidateConf struct {
		id   AnchoringID
		txid chainhash.Hash
		conf *chainntnfs.TxConfirmation
	}

	// evCandidateActConf reports the notifier certifying a
	// candidate at the anchoring's threshold depth.
	evCandidateActConf struct {
		id   AnchoringID
		txid chainhash.Hash
		conf *chainntnfs.TxConfirmation
	}

	// evForeclosureActConf reports the notifier certifying a
	// foreclosing transaction at the child anchoring's threshold
	// depth.
	evForeclosureActConf struct {
		child  AnchoringID
		parent AnchoringID
		conf   *chainntnfs.TxConfirmation
	}

	// evCandidateReorg reports that a candidate transaction was
	// re-organized out.
	evCandidateReorg struct {
		id   AnchoringID
		txid chainhash.Hash
	}

	// evBlock reports a new best height.
	evBlock struct {
		height uint32
	}
)

// pendingCandidate is a discovered spender awaiting its precise
// location from the candidate confirmation subscription.
type pendingCandidate struct {
	tx      *wire.MsgTx
	verdict Verdict
}

// sensor is the sensing loop's bookkeeping for one live anchoring.
type sensor struct {
	anchoring *Anchoring

	// cancel tears down every subscription of this sensor.
	cancel context.CancelFunc

	// ctx is the subscription context.
	ctx context.Context

	// candidateSubs tracks which candidate txids have a live
	// location subscription (one confirmation, reorg-aware).
	candidateSubs map[chainhash.Hash]struct{}

	// actSubs tracks which candidate txids have a live
	// certification subscription (threshold confirmations).
	actSubs map[chainhash.Hash]struct{}

	// foreclosureSubs tracks which foreclosing txids have a live
	// certification subscription.
	foreclosureSubs map[chainhash.Hash]struct{}

	// pending holds discovered spenders not yet located.
	pending map[chainhash.Hash]*pendingCandidate
}

// sensingLoop owns all chain subscriptions and the registry's sensed
// state. It never calls a site handler and is never blocked by one.
func (w *Watcher) sensingLoop(initial []*Anchoring) {
	defer w.Wg.Done()

	ctx, cancel := w.WithCtxQuitNoTimeout()
	defer cancel()

	epochChan, epochErr, err := w.cfg.Notifier.RegisterBlockEpochNtfn(ctx)
	if err != nil {
		w.reportErr(fmt.Errorf("unable to register block epochs: "+
			"%w", err))
		return
	}

	// Re-establish sensing for everything live, then re-derive:
	// events missed while down are recovered by the notifier's
	// historical dispatch, and phase is a function of view, so one
	// derivation pass makes the registry current.
	for _, anchoring := range initial {
		if err := w.startSensor(ctx, anchoring); err != nil {
			w.reportErr(err)
			continue
		}
		w.rederive(ctx, anchoring.ID)
	}

	// The reconciliation sweep is the safety net for transient
	// failures anywhere on the sensing path: a live anchoring
	// without a sensor (a failed registration hand-off, a failed
	// startup load) is re-adopted on the next tick rather than
	// staying orphaned until restart.
	ticker := time.NewTicker(w.cfg.ScanInterval)
	defer ticker.Stop()

	for {
		select {
		case event := <-w.events:
			w.handleSensingEvent(ctx, event)

		case <-ticker.C:
			w.reconcileSensors(ctx)

		case height, ok := <-epochChan:
			if !ok {
				return
			}
			w.bestHeight.Store(uint32(height))

			// Depth is a function of best height: every live
			// anchoring may have crossed a threshold.
			for id := range w.sensors {
				w.rederive(ctx, id)
			}

		case err := <-epochErr:
			if err != nil && !fn.IsCanceled(err) &&
				!fn.IsRpcErr(
					err,
					chainntnfs.ErrChainNotifierShuttingDown,
				) {

				w.reportErr(fmt.Errorf("block epoch "+
					"stream: %w", err))
			}

			return

		case <-w.Quit:
			return
		}
	}
}

// witnessEnrichment extracts the including block's header and the
// transaction's merkle inclusion proof from a confirmation event, so
// handlers can rebuild proofs without network access.
func witnessEnrichment(
	conf *chainntnfs.TxConfirmation) (*wire.BlockHeader,
	*proof.TxMerkleProof) {

	if conf.Block == nil {
		return nil, nil
	}

	header := conf.Block.Header
	merkle, err := proof.NewTxMerkleProof(
		conf.Block.Transactions, int(conf.TxIndex),
	)
	if err != nil {
		log.Errorf("Unable to build merkle proof from conf "+
			"block: %v", err)
		return &header, nil
	}

	return &header, merkle
}

// verifyLocation reports whether a transaction recorded at (height,
// blockHash) is part of the dominant chain right now. Chain events
// arrive on channels with no mutual ordering guarantee (a candidate's
// confirmation and its loss signal travel on separate channels, and a
// rebuilt sensor can be preceded by a prior generation's queued
// events), so location-bearing events are verified against the chain
// itself before they are recorded, and loss signals before they flip
// anything. The chain is the source of truth; events are only hints.
func (w *Watcher) verifyLocation(ctx context.Context, height uint32,
	blockHash chainhash.Hash) (bool, error) {

	hash, err := w.cfg.Notifier.GetBlockHash(ctx, int64(height))
	if err != nil {
		return false, err
	}

	return hash == blockHash, nil
}

// resense drops an anchoring's sensor so the reconciliation sweep
// re-adopts it: subscriptions are re-established and the notifier's
// historical dispatch regenerates whatever facts a failed write
// discarded. The chain is the source of truth, so no sensing failure
// is unrecoverable — this is the uniform self-healing path for
// transient failures anywhere in a sensor's pipeline.
func (w *Watcher) resense(id AnchoringID) {
	w.stopSensor(id)
}

// reconcileSensors adopts live anchorings that have no sensor —
// however they came to be missed. Sensing must never depend on any
// single hand-off succeeding.
func (w *Watcher) reconcileSensors(ctx context.Context) {
	live, err := w.cfg.Registry.LiveAnchorings(ctx)
	if err != nil {
		w.reportErr(fmt.Errorf("unable to reconcile sensors: %w",
			err))
		return
	}

	for _, anchoring := range live {
		if _, ok := w.sensors[anchoring.ID]; ok {
			continue
		}

		log.Infof("Anchoring %d (site=%v): adopted by "+
			"reconciliation sweep", anchoring.ID, anchoring.Site)

		if err := w.startSensor(ctx, anchoring); err != nil {
			w.reportErr(err)
			continue
		}
		w.rederive(ctx, anchoring.ID)
	}
}

// handleSensingEvent processes one sensing input.
func (w *Watcher) handleSensingEvent(ctx context.Context, event any) {
	switch ev := event.(type) {
	case evSense:
		anchoring, err := w.cfg.Registry.GetAnchoring(ctx, ev.id)
		if err != nil {
			w.reportErr(fmt.Errorf("unable to load anchoring "+
				"%d: %w", ev.id, err))
			return
		}
		if err := w.startSensor(ctx, anchoring); err != nil {
			w.reportErr(err)
			return
		}
		w.rederive(ctx, ev.id)

	case evStopSensing:
		w.stopSensor(ev.id)

	case evSpendDetail:
		w.handleSpendDetail(ctx, ev)

	case evSpendReorg:
		// The spend subscription's re-org signal names no
		// transaction, and attributing it to the last reported
		// spender races with the replacement's own spend
		// detail: acting on it can mark the *new* spender
		// off-chain. Every discovered candidate carries its own
		// confirmation subscription whose re-org channel is the
		// sound per-candidate loss signal, so this signal's only
		// job is keeping the spend stream alive; it is
		// deliberately not acted upon.

	case evCandidateConf:
		w.handleCandidateConf(ctx, ev)

	case evCandidateActConf:
		w.handleCandidateActConf(ctx, ev)

	case evForeclosureActConf:
		w.handleForeclosureActConf(ctx, ev)

	case evCandidateReorg:
		w.markCandidateOffChain(ctx, ev.id, ev.txid)

	default:
		w.reportErr(fmt.Errorf("unknown sensing event %T", event))
	}
}

// startSensor opens the spend subscriptions for an anchoring's
// trigger set and the confirmation subscriptions for its known
// candidates.
func (w *Watcher) startSensor(ctx context.Context,
	anchoring *Anchoring) error {

	if _, ok := w.sensors[anchoring.ID]; ok {
		return nil
	}
	if IsTerminal(anchoring.Phase) {
		return nil
	}

	sensorCtx, cancel := context.WithCancel(ctx)
	s := &sensor{
		anchoring:       anchoring,
		cancel:          cancel,
		ctx:             sensorCtx,
		candidateSubs:   make(map[chainhash.Hash]struct{}),
		actSubs:         make(map[chainhash.Hash]struct{}),
		foreclosureSubs: make(map[chainhash.Hash]struct{}),
		pending:         make(map[chainhash.Hash]*pendingCandidate),
	}
	w.sensors[anchoring.ID] = s

	// Startup reconciliation: notifications missed while down are
	// recovered by historical dispatch only for transactions still
	// in the chain — a candidate recorded on-chain that fell out
	// while we were down would otherwise stay on-chain forever.
	// Verify each recorded location against the dominant chain.
	for i := range anchoring.Spends {
		candidate := anchoring.Spends[i]
		if !candidate.OnChain {
			continue
		}

		hash, err := w.cfg.Notifier.GetBlockHash(
			ctx, int64(candidate.W.Height()),
		)
		if err == nil && hash == candidate.W.BlockHash() {
			continue
		}

		candidate.OnChain = false
		err = w.cfg.Registry.UpsertCandidate(
			ctx, anchoring.ID, candidate,
		)
		if err != nil {
			w.stopSensor(anchoring.ID)
			return fmt.Errorf("anchoring %d: unable to "+
				"reconcile candidate %v: %w", anchoring.ID,
				candidate.W.TxHash(), err)
		}
		anchoring.Spends[i] = candidate
	}

	for _, trigger := range anchoring.Triggers.OutPoints() {
		if err := w.watchTrigger(s, trigger); err != nil {
			w.stopSensor(anchoring.ID)
			return fmt.Errorf("anchoring %d: %w", anchoring.ID,
				err)
		}
	}

	// Known candidates re-subscribe so their re-confirmations and
	// re-orgs keep flowing after a restart.
	for _, candidate := range anchoring.Spends {
		err := w.watchCandidate(s, candidate.W.TxHash(),
			candidate.W.Tx(), candidate.W.Height())
		if err != nil {
			w.stopSensor(anchoring.ID)
			return fmt.Errorf("anchoring %d: %w", anchoring.ID,
				err)
		}
	}

	return nil
}

// stopSensor cancels an anchoring's subscriptions and forgets it.
func (w *Watcher) stopSensor(id AnchoringID) {
	s, ok := w.sensors[id]
	if !ok {
		return
	}
	s.cancel()
	delete(w.sensors, id)
}

// watchTrigger opens the spend subscription for one trigger outpoint
// and forwards its events into the sensing loop.
func (w *Watcher) watchTrigger(s *sensor, trigger TriggerOutPoint) error {
	op := trigger.OutPoint
	reOrgChan := make(chan struct{}, 1)

	spendChan, errChan, err := w.cfg.Notifier.RegisterSpendNtfn(
		s.ctx, &op, trigger.PkScript, trigger.HeightHint, reOrgChan,
	)
	if err != nil {
		return fmt.Errorf("unable to register spend ntfn for %v: %w",
			op, err)
	}

	id := s.anchoring.ID
	w.Wg.Add(1)
	go func() {
		defer w.Wg.Done()

		for {
			select {
			case detail, ok := <-spendChan:
				if !ok {
					return
				}
				w.forwardEvent(s.ctx, evSpendDetail{
					id: id, op: op, detail: detail,
				})

			case <-reOrgChan:
				w.forwardEvent(s.ctx, evSpendReorg{
					id: id, op: op,
				})

			case err := <-errChan:
				w.reportSubErr(err, "spend", op.String())
				return

			case <-s.ctx.Done():
				return

			case <-w.Quit:
				return
			}
		}
	}()

	return nil
}

// watchCandidate opens the location and certification subscriptions
// for one candidate transaction and forwards their events into the
// sensing loop. The location subscription (one confirmation,
// reorg-aware) is the canonical locator: it supplies the block hash
// and transaction index the spend detail lacks, and its re-org
// channel is the per-candidate loss signal. The certification
// subscription (threshold confirmations) is the only source of
// act-tier truth: the notifier fires it exactly when the candidate
// genuinely holds the threshold depth on the dominant chain.
func (w *Watcher) watchCandidate(s *sensor, txid chainhash.Hash,
	tx *wire.MsgTx, heightHint uint32) error {

	if _, ok := s.candidateSubs[txid]; ok {
		return nil
	}

	if heightHint == 0 {
		heightHint = s.anchoring.CreatedHeight
	}

	id := s.anchoring.ID

	reOrgChan := make(chan struct{}, 1)
	confEvent, errChan, err := w.cfg.Notifier.RegisterConfirmationsNtfn(
		s.ctx, &txid, tx.TxOut[0].PkScript, 1, heightHint, true,
		reOrgChan,
	)
	if err != nil {
		return fmt.Errorf("unable to register conf ntfn for %v: %w",
			txid, err)
	}

	s.candidateSubs[txid] = struct{}{}

	w.Wg.Add(1)
	go func() {
		defer w.Wg.Done()
		defer confEvent.Cancel()

		for {
			select {
			case conf, ok := <-confEvent.Confirmed:
				if !ok {
					return
				}
				w.forwardEvent(s.ctx, evCandidateConf{
					id: id, txid: txid, conf: conf,
				})

			case <-reOrgChan:
				w.forwardEvent(s.ctx, evCandidateReorg{
					id: id, txid: txid,
				})

			case err := <-errChan:
				w.reportSubErr(err, "conf", txid.String())
				return

			case <-s.ctx.Done():
				return

			case <-w.Quit:
				return
			}
		}
	}()

	// At a threshold of one, the location subscription's event is
	// itself the certification; no second subscription is needed.
	if s.anchoring.Threshold <= 1 {
		return nil
	}

	actEvent, actErrChan, err := w.cfg.Notifier.RegisterConfirmationsNtfn(
		s.ctx, &txid, tx.TxOut[0].PkScript, s.anchoring.Threshold,
		heightHint, true, nil,
	)
	if err != nil {
		return fmt.Errorf("unable to register act conf ntfn for "+
			"%v: %w", txid, err)
	}

	s.actSubs[txid] = struct{}{}

	w.Wg.Add(1)
	go func() {
		defer w.Wg.Done()
		defer actEvent.Cancel()

		for {
			select {
			case conf, ok := <-actEvent.Confirmed:
				if !ok {
					return
				}
				w.forwardEvent(s.ctx, evCandidateActConf{
					id: id, txid: txid, conf: conf,
				})

			case err := <-actErrChan:
				w.reportSubErr(err, "act conf", txid.String())
				return

			case <-s.ctx.Done():
				return

			case <-w.Quit:
				return
			}
		}
	}()

	return nil
}

// watchForeclosure opens the certification subscription for a staged
// foreclosing transaction at the child's threshold depth.
func (w *Watcher) watchForeclosure(s *sensor, parent AnchoringID,
	foreclosing Witness) error {

	txid := foreclosing.TxHash()
	if _, ok := s.foreclosureSubs[txid]; ok {
		return nil
	}

	tx := foreclosing.Tx()
	confEvent, errChan, err := w.cfg.Notifier.RegisterConfirmationsNtfn(
		s.ctx, &txid, tx.TxOut[0].PkScript, s.anchoring.Threshold,
		foreclosing.Height(), true, nil,
	)
	if err != nil {
		return fmt.Errorf("unable to register foreclosure conf "+
			"ntfn for %v: %w", txid, err)
	}

	s.foreclosureSubs[txid] = struct{}{}

	child := s.anchoring.ID
	w.Wg.Add(1)
	go func() {
		defer w.Wg.Done()
		defer confEvent.Cancel()

		for {
			select {
			case conf, ok := <-confEvent.Confirmed:
				if !ok {
					return
				}
				w.forwardEvent(s.ctx, evForeclosureActConf{
					child:  child,
					parent: parent,
					conf:   conf,
				})

			case err := <-errChan:
				w.reportSubErr(
					err, "foreclosure conf",
					txid.String(),
				)
				return

			case <-s.ctx.Done():
				return

			case <-w.Quit:
				return
			}
		}
	}()

	return nil
}

// forwardEvent pushes a subscription event into the sensing loop,
// giving up on sensor teardown or shutdown.
func (w *Watcher) forwardEvent(sensorCtx context.Context, event any) {
	select {
	case w.events <- event:
	case <-sensorCtx.Done():
	case <-w.Quit:
	}
}

// handleSpendDetail processes a confirmed spend of a trigger
// outpoint: evaluate the site predicate once for a newly discovered
// spender, and ensure the candidate's confirmation subscription is
// open.
func (w *Watcher) handleSpendDetail(ctx context.Context, ev evSpendDetail) {
	s, ok := w.sensors[ev.id]
	if !ok {
		return
	}

	detail := ev.detail
	if detail.SpenderTxHash == nil || detail.SpendingTx == nil {
		w.reportErr(fmt.Errorf("anchoring %d: malformed spend "+
			"detail for %v", ev.id, ev.op))
		return
	}
	txid := *detail.SpenderTxHash

	// A known candidate: its verdict is already recorded, and its
	// confirmation subscription (opened below if missing) delivers
	// location changes.
	known := false
	for _, candidate := range s.anchoring.Spends {
		if candidate.W.TxHash() == txid {
			known = true
			break
		}
	}
	if _, ok := s.pending[txid]; ok {
		known = true
	}

	if !known {
		site, ok := w.sites[s.anchoring.Site]
		if !ok {
			w.reportErr(fmt.Errorf("anchoring %d: no site %v "+
				"registered", ev.id, s.anchoring.Site))
			return
		}

		verdict, err := site.EvaluateCandidate(
			s.anchoring.MatchData, detail.SpendingTx,
		)
		if err != nil {
			// A predicate error is a code defect (a decode
			// failure), not a chain condition: surface it
			// loudly and leave the candidate unevaluated;
			// the spend subscription will re-deliver it on
			// restart once the defect is fixed.
			w.reportErr(fmt.Errorf("anchoring %d: predicate "+
				"failed on candidate %v: %w", ev.id, txid,
				err))
			return
		}

		s.pending[txid] = &pendingCandidate{
			tx:      detail.SpendingTx.Copy(),
			verdict: verdict,
		}
	}

	var height uint32
	if detail.SpendingHeight > 0 {
		height = uint32(detail.SpendingHeight)
	}
	err := w.watchCandidate(s, txid, detail.SpendingTx, height)
	if err != nil {
		w.reportErr(fmt.Errorf("anchoring %d: %w", ev.id, err))
		w.resense(ev.id)
	}
}

// handleCandidateConf records a candidate's full location in the
// registry and re-derives.
func (w *Watcher) handleCandidateConf(ctx context.Context,
	ev evCandidateConf) {

	s, ok := w.sensors[ev.id]
	if !ok {
		return
	}

	conf := ev.conf
	if conf.BlockHash == nil || conf.Tx == nil {
		w.reportErr(fmt.Errorf("anchoring %d: malformed conf for "+
			"%v", ev.id, ev.txid))
		return
	}

	witness, err := NewWitness(
		conf.Tx, *conf.BlockHash, conf.BlockHeight, conf.TxIndex,
	)
	if err != nil {
		w.reportErr(fmt.Errorf("anchoring %d: %w", ev.id, err))
		return
	}

	// The verdict comes from the pending record for a new
	// candidate, or from the recorded chain view for a
	// re-confirming one.
	var (
		verdict Verdict
		found   bool
	)
	if pending, ok := s.pending[ev.txid]; ok {
		verdict, found = pending.verdict, true
		delete(s.pending, ev.txid)
	} else {
		for _, candidate := range s.anchoring.Spends {
			if candidate.W.TxHash() == ev.txid {
				verdict, found = candidate.Verdict, true
				break
			}
		}
	}
	if !found {
		// A confirmation for a transaction we never evaluated:
		// nothing sound to record.
		w.reportErr(fmt.Errorf("anchoring %d: conf for unknown "+
			"candidate %v", ev.id, ev.txid))
		return
	}

	// A confirmation may be stale by the time it is processed (the
	// chain moved on, or the event predates a sensor rebuild);
	// verify the location before recording it as on-chain. A stale
	// confirmation is simply dropped: whatever the chain holds now
	// produces its own events.
	onChain, err := w.verifyLocation(
		ctx, witness.Height(), witness.BlockHash(),
	)
	if err != nil {
		w.reportErr(fmt.Errorf("anchoring %d: unable to verify "+
			"candidate %v: %w", ev.id, ev.txid, err))
		w.resense(ev.id)
		return
	}
	if !onChain {
		log.Debugf("Anchoring %d: dropping stale confirmation of "+
			"%v at height %d", ev.id, ev.txid, witness.Height())
		return
	}

	// The trigger outpoints this candidate spends, recomputed from
	// the transaction itself.
	var spent []wire.OutPoint
	for _, txIn := range conf.Tx.TxIn {
		if s.anchoring.Triggers.Contains(txIn.PreviousOutPoint) {
			spent = append(spent, txIn.PreviousOutPoint)
		}
	}

	header, merkle := witnessEnrichment(conf)
	err = w.cfg.Registry.UpsertCandidate(ctx, ev.id, CandidateSpend{
		Verdict: verdict,
		W:       witness,
		OnChain: true,
		// At a threshold of one, the first confirmation is
		// itself the act certification.
		ActCertified:   s.anchoring.Threshold <= 1,
		BlockHeader:    header,
		MerkleProof:    merkle,
		SpentOutPoints: spent,
	})
	if err != nil {
		w.reportErr(fmt.Errorf("anchoring %d: unable to record "+
			"candidate %v: %w", ev.id, ev.txid, err))
		w.resense(ev.id)
		return
	}

	w.rederive(ctx, ev.id)
}

// handleCandidateActConf records a notifier certification of a
// candidate at the anchoring's threshold depth and re-derives. The
// certification is trusted absolutely: the notifier only fires it
// for a transaction genuinely at that depth on the dominant chain.
func (w *Watcher) handleCandidateActConf(ctx context.Context,
	ev evCandidateActConf) {

	s, ok := w.sensors[ev.id]
	if !ok {
		return
	}

	conf := ev.conf
	if conf.BlockHash == nil || conf.Tx == nil {
		w.reportErr(fmt.Errorf("anchoring %d: malformed act conf "+
			"for %v", ev.id, ev.txid))
		return
	}

	witness, err := NewWitness(
		conf.Tx, *conf.BlockHash, conf.BlockHeight, conf.TxIndex,
	)
	if err != nil {
		w.reportErr(fmt.Errorf("anchoring %d: %w", ev.id, err))
		return
	}

	var (
		verdict Verdict
		found   bool
	)
	if pending, ok := s.pending[ev.txid]; ok {
		verdict, found = pending.verdict, true
	} else {
		for _, candidate := range s.anchoring.Spends {
			if candidate.W.TxHash() == ev.txid {
				verdict, found = candidate.Verdict, true
				break
			}
		}
	}
	if !found {
		w.reportErr(fmt.Errorf("anchoring %d: act conf for "+
			"unknown candidate %v", ev.id, ev.txid))
		return
	}

	var spent []wire.OutPoint
	for _, txIn := range conf.Tx.TxIn {
		if s.anchoring.Triggers.Contains(txIn.PreviousOutPoint) {
			spent = append(spent, txIn.PreviousOutPoint)
		}
	}

	// The certification itself is an attestation of a crossing that
	// genuinely happened, and stands even if the chain has since
	// moved (stickiness by design); only the on-chain flag is
	// subject to verification.
	onChain, err := w.verifyLocation(
		ctx, witness.Height(), witness.BlockHash(),
	)
	if err != nil {
		w.reportErr(fmt.Errorf("anchoring %d: unable to verify "+
			"act conf of %v: %w", ev.id, ev.txid, err))
		w.resense(ev.id)
		return
	}

	header, merkle := witnessEnrichment(conf)
	err = w.cfg.Registry.UpsertCandidate(ctx, ev.id, CandidateSpend{
		Verdict:        verdict,
		W:              witness,
		OnChain:        onChain,
		ActCertified:   true,
		BlockHeader:    header,
		MerkleProof:    merkle,
		SpentOutPoints: spent,
	})
	if err != nil {
		w.reportErr(fmt.Errorf("anchoring %d: unable to certify "+
			"candidate %v: %w", ev.id, ev.txid, err))
		w.resense(ev.id)
		return
	}

	w.rederive(ctx, ev.id)
}

// handleForeclosureActConf records a notifier certification of a
// foreclosing transaction at the child's threshold depth and
// re-derives the child.
func (w *Watcher) handleForeclosureActConf(ctx context.Context,
	ev evForeclosureActConf) {

	if _, ok := w.sensors[ev.child]; !ok {
		return
	}

	conf := ev.conf
	if conf.BlockHash == nil || conf.Tx == nil {
		w.reportErr(fmt.Errorf("anchoring %d: malformed "+
			"foreclosure conf", ev.child))
		return
	}

	witness, err := NewWitness(
		conf.Tx, *conf.BlockHash, conf.BlockHeight, conf.TxIndex,
	)
	if err != nil {
		w.reportErr(fmt.Errorf("anchoring %d: %w", ev.child, err))
		return
	}

	onChain, err := w.verifyLocation(
		ctx, witness.Height(), witness.BlockHash(),
	)
	if err != nil {
		w.reportErr(fmt.Errorf("anchoring %d: unable to verify "+
			"foreclosure conf: %w", ev.child, err))
		w.resense(ev.child)
		return
	}

	err = w.cfg.Registry.StageForeclosure(
		ctx, ev.child, ev.parent, ForeclosureEvent{
			Parent:       ev.parent,
			W:            witness,
			OnChain:      onChain,
			ActCertified: true,
		},
	)
	if err != nil {
		w.reportErr(fmt.Errorf("anchoring %d: unable to certify "+
			"foreclosure: %w", ev.child, err))
		w.resense(ev.child)
		return
	}

	w.rederive(ctx, ev.child)
}

// markCandidateOffChain flips a recorded candidate off-chain and
// re-derives.
func (w *Watcher) markCandidateOffChain(ctx context.Context,
	id AnchoringID, txid chainhash.Hash) {

	s, ok := w.sensors[id]
	if !ok {
		return
	}

	for _, candidate := range s.anchoring.Spends {
		if candidate.W.TxHash() != txid || !candidate.OnChain {
			continue
		}

		// A loss signal may itself be stale (reordered past the
		// confirmation that superseded it); flip the candidate
		// off-chain only if its recorded location really is gone
		// from the dominant chain.
		stillThere, err := w.verifyLocation(
			ctx, candidate.W.Height(), candidate.W.BlockHash(),
		)
		if err != nil {
			w.reportErr(fmt.Errorf("anchoring %d: unable to "+
				"verify loss of %v: %w", id, txid, err))
			w.resense(id)
			return
		}
		if stillThere {
			log.Debugf("Anchoring %d: dropping stale loss "+
				"signal for %v", id, txid)
			return
		}

		candidate.OnChain = false
		err = w.cfg.Registry.UpsertCandidate(ctx, id, candidate)
		if err != nil {
			w.reportErr(fmt.Errorf("anchoring %d: unable to "+
				"mark candidate %v off-chain: %w", id, txid,
				err))
			w.resense(id)
			return
		}

		w.rederive(ctx, id)
		return
	}
}

// rederive recomputes an anchoring's phase from its chain view,
// persists a change, keeps dependents' staged foreclosures current,
// and kicks the delivery loop.
func (w *Watcher) rederive(ctx context.Context, id AnchoringID) {
	s, ok := w.sensors[id]
	if !ok {
		return
	}

	view, err := w.cfg.Registry.ChainView(ctx, id)
	if err != nil {
		w.reportErr(fmt.Errorf("anchoring %d: unable to load "+
			"chain view: %w", id, err))
		w.resense(id)
		return
	}

	derived := DerivePhase(view)

	// A staged but uncertified foreclosure needs its certification
	// subscription: the child abandons only when the notifier
	// certifies the foreclosing transaction at the child's own
	// threshold.
	if fc := view.Foreclosure.UnwrapToPtr(); fc != nil &&
		!fc.ActCertified {

		if err := w.watchForeclosure(s, fc.Parent, fc.W); err != nil {
			w.reportErr(fmt.Errorf("anchoring %d: %w", id, err))
		}
	}

	// Refresh the sensor's cached aggregate: candidates may have
	// changed even when the phase did not.
	fresh, err := w.cfg.Registry.GetAnchoring(ctx, id)
	if err != nil {
		w.reportErr(fmt.Errorf("anchoring %d: unable to reload: "+
			"%w", id, err))
		w.resense(id)
		return
	}
	s.anchoring = fresh

	// Terminal sensed phases are absorbing: act-level finality is
	// exactly the point past which the chain's later opinion no
	// longer counts. A reorg deeper than the threshold after the
	// registry has sensed Buried or Abandoned does not reopen the
	// question; sensing simply ends.
	if IsTerminal(fresh.Phase) {
		w.stopSensor(id)
		return
	}

	if PhaseEqual(derived, fresh.Phase) {
		return
	}

	if err := w.cfg.Registry.SetPhase(ctx, id, derived); err != nil {
		w.reportErr(fmt.Errorf("anchoring %d: unable to set "+
			"phase: %w", id, err))
		w.resense(id)
		return
	}
	s.anchoring.Phase = derived

	log.Infof("Anchoring %d (site=%v): phase %v -> %v", id,
		fresh.Site, fresh.Phase, derived)

	if IsTerminal(derived) {
		w.stopSensor(id)
	}

	w.restageDependentForeclosures(ctx, id, derived)
	w.kick(w.deliveryKick)
}

// restageDependentForeclosures keeps the staged foreclosure evidence
// on this anchoring's dependents consistent with its current phase: a
// witness in a different form than an edge depends on stages
// foreclosure; the depended-upon form clears it; loss of the witness
// downgrades staged evidence to off-chain. Terminal abandonment is
// handled by delivery, inside its transaction.
func (w *Watcher) restageDependentForeclosures(ctx context.Context,
	id AnchoringID, phase Phase) {

	edges, err := w.cfg.Registry.DependencyEdges(ctx, id)
	if err != nil {
		w.reportErr(fmt.Errorf("anchoring %d: unable to load "+
			"dependency edges: %w", id, err))
		return
	}
	if len(edges) == 0 {
		return
	}

	var witness *Witness
	switch p := phase.(type) {
	case Witnessed:
		witness = &p.W
	case Buried:
		witness = &p.W
	}

	for _, edge := range edges {
		var err error
		switch {
		// The parent is witnessed in the very form the child
		// depends on: no foreclosure.
		case witness != nil &&
			witness.TxHash() == edge.ParentWitnessTxHash:

			err = w.cfg.Registry.ClearForeclosure(
				ctx, edge.Child, id,
			)

		// The parent is witnessed in a different form: the
		// depended-upon outputs are gone while that form
		// stands.
		case witness != nil:
			err = w.cfg.Registry.StageForeclosure(
				ctx, edge.Child, id, ForeclosureEvent{
					Parent:  id,
					W:       *witness,
					OnChain: true,
				},
			)

		// The parent is not witnessed at all: any staged
		// foreclosing evidence is itself off-chain.
		default:
			staged := edge.Foreclosure.UnwrapToPtr()
			if staged == nil || !staged.OnChain {
				continue
			}
			staged.OnChain = false
			err = w.cfg.Registry.StageForeclosure(
				ctx, edge.Child, id, *staged,
			)
		}
		if err != nil {
			w.reportErr(fmt.Errorf("anchoring %d: unable to "+
				"restage foreclosure on %d: %w", id,
				edge.Child, err))
			w.resense(edge.Child)
			continue
		}

		w.rederive(ctx, edge.Child)
	}
}

// deliveryLoop converges sites to sensed phases: it scans for
// anchorings whose delivered phase lags, runs the site handler
// atomically with the registry advance, and applies the failure
// policy. Deliveries run one at a time.
func (w *Watcher) deliveryLoop() {
	defer w.Wg.Done()

	ctx, cancel := w.WithCtxQuitNoTimeout()
	defer cancel()

	ticker := time.NewTicker(w.cfg.ScanInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
		case <-w.deliveryKick:
		case <-w.Quit:
			return
		}

		w.deliverPending(ctx)
	}
}

// deliverPending runs one delivery pass.
func (w *Watcher) deliverPending(ctx context.Context) {
	pending, err := w.cfg.Registry.PendingDeliveries(
		ctx, w.cfg.Clock.Now(),
	)
	if err != nil {
		w.reportErr(fmt.Errorf("unable to scan pending "+
			"deliveries: %w", err))
		return
	}

	for _, anchoring := range pending {
		select {
		case <-w.Quit:
			return
		default:
		}

		w.deliverOne(ctx, anchoring)
	}
}

// deliverOne attempts one delivery and applies the failure policy.
func (w *Watcher) deliverOne(ctx context.Context, anchoring *Anchoring) {
	site, ok := w.sites[anchoring.Site]
	if !ok {
		// No site implementation for a persisted anchoring is a
		// wiring defect; record it through the normal failure
		// path so it is visible and retried once fixed.
		w.failDelivery(ctx, anchoring, fmt.Errorf("no site %v "+
			"registered", anchoring.Site))
		return
	}

	target := anchoring.Phase
	err := w.cfg.Registry.Deliver(
		ctx, anchoring.ID, target,
		func(ctx context.Context, tx RegistryTx,
			fresh *Anchoring) error {

			return dispatchPhase(ctx, site, tx, fresh, target)
		},
	)
	switch {
	// Sensing moved on mid-flight; the rescan will pick up the new
	// phase.
	case errors.Is(err, ErrStaleDelivery):
		w.kick(w.deliveryKick)
		return

	case err != nil:
		w.failDelivery(ctx, anchoring, err)
		return
	}

	log.Infof("Anchoring %d (site=%v): delivered %v", anchoring.ID,
		anchoring.Site, target)

	for _, listener := range w.listeners {
		listener(anchoring.ID, anchoring.Site, target)
	}

	// Handlers may have enqueued effects.
	w.kick(w.outboxKick)

	if !IsTerminal(target) {
		return
	}

	// Terminal delivery ends sensing. An abandonment also
	// foreclosed its dependents' edges (inside the delivery
	// transaction); their phases re-derive now, parent-first by
	// construction.
	if err := w.sendEvent(ctx, evStopSensing{id: anchoring.ID}); err != nil {
		return
	}
	if _, ok := target.(Abandoned); ok {
		edges, err := w.cfg.Registry.DependencyEdges(
			ctx, anchoring.ID,
		)
		if err != nil {
			w.reportErr(err)
			return
		}
		for _, edge := range edges {
			err := w.sendEvent(ctx, evSense{id: edge.Child})
			if err != nil {
				return
			}
		}
	}
}

// failDelivery records a failed delivery attempt with exponential
// backoff, flagging the anchoring stuck once attempts pass the
// threshold. Retries never stop; stuck is a visibility condition, not
// an end state.
func (w *Watcher) failDelivery(ctx context.Context, anchoring *Anchoring,
	deliveryErr error) {

	attempts := anchoring.DeliveryAttempts + 1
	stuck := attempts >= w.cfg.StuckAfterAttempts

	backoff := w.cfg.InitialDeliveryBackoff
	for i := uint32(1); i < attempts && backoff < w.cfg.MaxDeliveryBackoff; i++ {
		backoff *= 2
	}
	if backoff > w.cfg.MaxDeliveryBackoff {
		backoff = w.cfg.MaxDeliveryBackoff
	}

	log.Errorf("Anchoring %d (site=%v): delivery of %v failed "+
		"(attempt %d, stuck=%v): %v", anchoring.ID, anchoring.Site,
		anchoring.Phase, attempts, stuck, deliveryErr)

	err := w.cfg.Registry.RecordDeliveryFailure(
		ctx, anchoring.ID, deliveryErr,
		w.cfg.Clock.Now().Add(backoff), stuck,
	)
	if err != nil {
		w.reportErr(fmt.Errorf("anchoring %d: unable to record "+
			"delivery failure: %w", anchoring.ID, err))
	}
}

// dispatchPhase routes a delivery to the site handler for the target
// phase.
func dispatchPhase(ctx context.Context, site Site, tx RegistryTx,
	anchoring *Anchoring, target Phase) error {

	switch target.(type) {
	case Unwitnessed:
		return site.OnUnwitnessed(ctx, tx, anchoring)

	case Witnessed:
		return site.OnWitnessed(ctx, tx, anchoring)

	case Conflicted:
		return site.OnConflicted(ctx, tx, anchoring)

	case Buried:
		return site.OnBuried(ctx, tx, anchoring)

	case Abandoned:
		return site.OnAbandoned(ctx, tx, anchoring)

	case Withdrawn:
		// Withdrawal is site-initiated; sensed and delivered
		// advance together at withdrawal time, so no delivery
		// ever targets it.
		return fmt.Errorf("withdrawn is never delivered")

	default:
		return fmt.Errorf("unknown phase %T", target)
	}
}

// outboxLoop dispatches enqueued external effects, idempotently and
// with backoff.
func (w *Watcher) outboxLoop() {
	defer w.Wg.Done()

	ctx, cancel := w.WithCtxQuitNoTimeout()
	defer cancel()

	ticker := time.NewTicker(w.cfg.ScanInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
		case <-w.outboxKick:
		case <-w.Quit:
			return
		}

		w.dispatchEffects(ctx)
	}
}

// dispatchEffects runs one outbox pass.
func (w *Watcher) dispatchEffects(ctx context.Context) {
	for {
		effects, err := w.cfg.Registry.PendingEffects(
			ctx, w.cfg.Clock.Now(), outboxBatchSize,
		)
		if err != nil {
			w.reportErr(fmt.Errorf("unable to scan outbox: %w",
				err))
			return
		}
		if len(effects) == 0 {
			return
		}

		for _, effect := range effects {
			select {
			case <-w.Quit:
				return
			default:
			}

			w.dispatchOne(ctx, effect)
		}

		if len(effects) < outboxBatchSize {
			return
		}
	}
}

// dispatchOne dispatches a single effect and applies the failure
// policy.
func (w *Watcher) dispatchOne(ctx context.Context, effect *StoredEffect) {
	var dispatchErr error
	handler, ok := w.effectHandlers[effect.Effect.Kind]
	if !ok {
		dispatchErr = fmt.Errorf("no handler for effect kind %v",
			effect.Effect.Kind)
	} else {
		dispatchErr = handler(
			ctx, effect.Effect.Anchoring, effect.Effect.Payload,
		)
	}

	if dispatchErr == nil {
		err := w.cfg.Registry.MarkEffectDispatched(ctx, effect.ID)
		if err != nil {
			w.reportErr(fmt.Errorf("unable to mark effect %d "+
				"dispatched: %w", effect.ID, err))
		}
		return
	}

	attempts := effect.Attempts + 1
	backoff := w.cfg.InitialDeliveryBackoff
	for i := uint32(1); i < attempts && backoff < w.cfg.MaxDeliveryBackoff; i++ {
		backoff *= 2
	}
	if backoff > w.cfg.MaxDeliveryBackoff {
		backoff = w.cfg.MaxDeliveryBackoff
	}

	log.Errorf("Effect %d (kind=%v): dispatch failed (attempt %d): %v",
		effect.ID, effect.Effect.Kind, attempts, dispatchErr)

	err := w.cfg.Registry.RecordEffectFailure(
		ctx, effect.ID, dispatchErr, w.cfg.Clock.Now().Add(backoff),
	)
	if err != nil {
		w.reportErr(fmt.Errorf("unable to record effect %d "+
			"failure: %w", effect.ID, err))
	}
}

// kick wakes a loop ahead of its ticker.
func (w *Watcher) kick(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

// reportSubErr reports a subscription stream error unless it is a
// benign shutdown artifact.
func (w *Watcher) reportSubErr(err error, kind, subject string) {
	if err == nil || fn.IsCanceled(err) ||
		fn.IsRpcErr(err, chainntnfs.ErrChainNotifierShuttingDown) {

		return
	}

	w.reportErr(fmt.Errorf("%s subscription for %s: %w", kind, subject,
		err))
}

// reportErr reports a critical error to the main server.
func (w *Watcher) reportErr(err error) {
	log.Errorf("Watcher error: %v", err)

	select {
	case w.cfg.ErrChan <- err:
	case <-w.Quit:
	default:
	}
}
