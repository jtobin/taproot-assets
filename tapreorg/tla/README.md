# Anchoring watcher — TLA+ models

Three models of the anchoring watcher, checked with TLC:
exhaustive safety over bounded instances, liveness under fairness,
and a characterization of the out-of-contract boundary.

- `AnchoringWatcher.tla` — a single anchoring's sensing and
  delivery discipline, safety and liveness. Instance module
  `MC.tla`, configs `MC_*.cfg`.
- `AnchoringCascade.tla` — two anchorings joined by a dependency
  edge pinned to a parent witness form, the foreclosure cascade,
  and the transactional outbox; safety and liveness. Instance
  module `MC2.tla`, configs `MC2_*.cfg`.
- `AnchoringFleet.tla` — the cascade generalized to any number of
  anchorings, an arbitrary edge set, per-outpoint transaction
  sources, and transactions touching several anchorings at once;
  safety only. Instance module `MC3.tla`, configs `MC3_*.cfg`.

## The single-anchoring model

Against an environment of bounded-depth reorgs, torn notification
streams (events emitted truthfully but processed arbitrarily late,
duplicated, dropped, or lost to restarts), the following hold over
the full state space of the configured instance:

- `CertifiedOnChain` — a recorded act certification always locates
  a block on the dominant chain. The strongest single invariant;
  the two below are consequences.
- `NoFalseBurial` — a sensed `Buried` phase names a satisfying
  transaction actually at its recorded location on the dominant
  chain.
- `NoFalseAbandon` — dually, for `Abandoned` via foreign burial.
- `SensedTerminalAbsorbing` — a terminal sensed phase never
  changes, under any interleaving.
- `DeliveredTerminalAbsorbing` — likewise for the delivered phase.
- `ViewMonotone` — candidates are never deleted and certification
  is sticky across upserts.

Two configurations are expected to fail, and do:

- `MC_boundary.cfg` — with `StabilityDepth = Threshold` the chain
  may reorg a block that held threshold depth; `CertifiedOnChain`
  breaks in 6 states. This is the precise shape of the documented
  out-of-scope case ("a reorg deeper than the configured threshold
  is outside the watcher's finality guarantee").
- `MC_tear.cfg` — the pre-certification design, which derived act
  finality from the recorded on-chain flag plus a separately
  streamed best height (removed in commit 7b240705), modeled as
  `BuggyBuried`. TLC finds a 9-state trace: a candidate confirms
  at height 1, reorgs out, re-mines at height 2; an epoch reports
  best height 2; depth arithmetic over the stale recorded location
  yields 2 confirmations and certifies a burial at a location no
  longer on the chain. The certification-based derivation holds in
  the identical environment.

Six single-anchoring reachability probes confirm the model is not
vacuously safe: burial, abandonment, conflict, terminal delivery,
the witnessed-to-unwitnessed downgrade, and a stale on-chain flag
(recorded on-chain, actually reorged out, loss unprocessed) are
all reachable. Every probe in this suite, here and below, is
expected to be VIOLATED; one that passes indicates a faithfulness
bug in the model.

### Correspondence with the implementation

- `PhaseOf` mirrors `DerivePhase` (derive.go): certified witness,
  then certified foreign, then live witness, then any live foreign
  as `Conflicted`, else `Unwitnessed`; contradictory
  certifications fall through to the potency tier. `CHOOSE` stands
  in for the canonical preference order, whose determinism and
  order-invariance belong to the pure-kernel tier (rapid tests,
  prospective Lean development), not this model.
- `ProcessConf`, `ProcessAct`, `ProcessLoss` mirror
  `handleCandidateConf`, `handleCandidateActConf` and
  `markCandidateOffChain` (service.go): each verifies the event's
  location against the dominant chain (`LocOnChain` ~
  `verifyLocation`) before touching durable state; stale events
  are dropped. Certification stickiness mirrors the registry's
  `act_certified OR EXCLUDED.act_certified` upsert.
- `Deliver` is atomic because `Registry.Deliver` re-checks inside
  the delivery transaction that the sensed phase still equals the
  target and advances the delivered phase in that transaction; a
  stale target is discarded (`ErrStaleDelivery`).
- Sensing actions are guarded on the sensed phase being live:
  `rederive` stops the sensor at a terminal phase and the
  reconciliation sweep re-adopts only live anchorings.
- `Drop` and `Restart` model broken streams and daemon restarts:
  in-flight events vanish, durable state survives. The notifier's
  historical dispatch is modeled by emission preconditions being
  re-satisfiable at any time from chain state.

### Abstractions (what the model does not capture)

- The spend-detail step is folded into confirmation events; the
  verdict is a static function of the transaction (the predicate
  is pure and evaluated once, so this loses nothing for safety).
  The in-memory pending-candidate map is likewise elided.
- At most one transaction per block, so same-height tie-breaking
  in the preference order is not exercised here.
- Registration happens at genesis, and `Withdrawn` is not modeled.
  Dependency edges, foreclosure, and the outbox belong to the
  cascade model below.
- The registry transaction layer is one atomic step; SQL-level
  behavior is trusted per the transactional discipline.

The chain contract is explicit: `Reorg` never truncates a block
that ever held more than `StabilityDepth` confirmations.
`StabilityDepth = Threshold - 1` states exactly "a transaction
with threshold confirmations is permanent"; the boundary config
weakens it by one block.

## The cascade and outbox

`AnchoringCascade.tla` models a parent anchoring P (satisfying
forms s1 and s2, foreign partial spender f1) and a child C (one
satisfying spender c1 of an s1 output), joined by an edge pinned
to form s1, plus the outbox. Three instances: `MC2_repl.cfg`
(s1, s2, c1 — replacement foreclosure via the restage path),
`MC2_foreign.cfg` (s1, f1, c1 — foreign-abandonment foreclosure
via delivery settlement), and `MC2_full.cfg` (the union).

Invariants checked, beyond the single-anchoring set applied to
both anchorings:

- `CertifiedFcOnChain` — certified foreclosing evidence always
  locates a block on the dominant chain.
- `NoFalseForeclosure` — a foreclosure abandonment names a
  foreclosing transaction genuinely on the dominant chain, and the
  depended-upon form is genuinely absent.
- `CascadeExclusive` / `DeliveredCascadeExclusive` — a certified
  foreclosure never coexists with the parent act-final in the very
  form the child depends on, at either tier.
- `PerformedEnqueued` — no external effect reaches the world
  without a durable enqueue.
- `MaterializeOnce` — release and compensation are mutually
  exclusive per anchoring, ever.
- `GatedEffects` — an act-gated release exists only for a
  delivered burial whose evidence stands on the dominant chain;
  compensation only for a delivered abandonment.
- `FcFrozenSticky` (action property) — a certified foreclosure is
  never touched again, by restage, settlement, or event write.

### Cascade correspondence notes

- `Restage` models both `restageEdge` call sites (the parent's
  rederive and the child's adoption) as one always-enabled action:
  the staging is a pure function of the parent's current phase, so
  a lost or delayed restage is just a run in which the action
  fires later. Safety must hold under arbitrary interleaving of
  it, and does.
- `DeliverP` folds `settleDependentEdges` into the delivery step:
  the code runs settlement inside the delivery transaction, which
  is what justifies the atomic model. The asymmetry is preserved:
  the foreign-abandonment foreclosure path exists only via
  settlement, since `restageEdge` stages parent witness forms
  only.
- `EmitFcAct` over-approximates `watchForeclosure`: a certifiable
  foreclosure event may fire for any foreclosing-capable
  transaction genuinely at threshold depth, without requiring the
  subscription-registration history. Strictly more adversarial,
  so the green runs subsume the disciplined behavior.
- Abstractions: both anchorings share one threshold; the child has
  no foreign spender of its own (child-local conflict mechanics
  are covered by the single-anchoring model); effects are enqueued
  on terminal deliveries only; registration and the edge exist
  from genesis; no `Withdraw`; C has no dependents of its own (no
  deeper cascade).

### Cascade results

All three instances pass all invariants and action properties;
see the run log below for sizes. Seven reachability probes
(`MC2_reach_*.cfg`) are each violated as required: staging,
certification, the off-chain downgrade, child foreclosure, child
burial, and both performed-effect paths are all reachable.

`MC2_boundary.cfg` (`StabilityDepth = Threshold`) violates
`CascadeExclusive` in 10 states: s1 certifies and P senses Buried;
a depth-2 reorg erases s1; s2 reaches threshold depth on the new
chain; the foreclosure certification verifies against the current
chain and freezes — a sticky parent burial in s1 now coexists
with a certified foreclosure by s2. That is precisely what a
beyond-threshold reorg costs at the cascade tier.

## Liveness

The single-anchoring and cascade modules carry a `LiveSpec`
(`MC_live.cfg`, `MC2_live_*.cfg`) checking, under fairness:

- `Convergence` / `CascadeConvergence` — the delivered phase
  eventually always equals the sensed phase.
- `SensedTruth` — a live anchoring's durable view converges to
  the dominant chain's truth (scoped to live anchorings; terminal
  ones stop sensing by design).
- `EffectsDispatched` — every durably enqueued effect is
  eventually performed: the at-least-once half of the outbox
  contract.

The liveness configs also re-check the safety invariants, since
`LiveSpec` extends the transition relation with the refresh
composites described next. The fleet module is safety-only.

### Fairness modeling

The environment needs no fairness: mining and reorg budgets are
finite, so every behavior's chain quiesces structurally.

The notifier's liveness contract — each live subscription
eventually delivers a truthful notification which is eventually
processed — is modeled as per-transaction refresh/certify
composites: atomic emit-verify-record steps whose effect equals
processing a just-emitted event against the current chain, under
weak fairness. WF over a composite is sound because a productive
refresh stays enabled until it (or the equivalent async path)
lands. The async queue machinery remains in the liveness spec,
fully adversarial and unfaired: drops, restarts, stale events and
duplicates interleave freely.

The direct alternative — per-stream strong fairness over the
queue actions themselves — states the same contract without the
composite, but its tableau is beyond TLC's reach even on tiny
instances (a 17k-state graph made no progress in an hour; the
composite formulation checks in seconds).

Weak fairness on `Deliver`/`Dispatch` is the retry discipline:
the model has no permanently failing site handler, so WF is
exactly "retries never stop and eventually succeed" — a handler
failing forever is the stuck-delivery operational surface, out of
scope. Weak fairness on `Restage` is the adoption sweep re-running
the pure staging function until it lands.

Liveness instances use `AlwaysConsume = TRUE` (processing consumes
its event); duplicate delivery of stale events is covered by the
safety runs, which keep the nondeterministic keep-or-consume
semantics.

## The out-of-contract boundary

`traces/` holds counterexample traces as artifacts; from the
boundary configurations:

- `boundary_single.txt` (6 states) — a deep reorg displaces a
  certified candidate location (`CertifiedOnChain`).
- `boundary_cascade.txt` (10 states) — a sticky parent burial coexists
  with a certified foreclosure after a deep reorg
  (`CascadeExclusive`).
- `tear.txt` (9 states) — the pre-certification design
  certifies a burial from a stale location plus a streamed height
  (`BuggyNoFalseBurial`).

The complementary result is the discipline runs (`MC_discipline`,
`MC2_discipline`): with deep reorgs permitted
(`StabilityDepth = Threshold`), the chain-truth invariants fail as
above, but terminal absorption, view monotonicity,
frozen-foreclosure stickiness, outbox exclusivity
(`MaterializeOnce`) and durable-enqueue (`PerformedEnqueued`) all
still hold. A beyond-threshold reorg costs the watcher agreement
with the chain — never internal consistency, never a retraction,
and never a double materialization. That is the precise formal
content of "certification is sticky; a deeper reorg is the
out-of-scope case, not a retraction."

## Sweeper-integration seams

`AnchoringFleet.tla` generalizes the cascade module to any number
of anchorings, an arbitrary edge set, per-outpoint transaction
sources, and transactions touching several anchorings at once.
Two instances live in `MC3.tla`; a third (the split-sweep
instance) rides on the single-anchoring module.

- **Dual-child replacement cascade** (`MC3_dualchild.cfg`):
  parent realizable as s1 or s2, one child pinned to each form.
  The full safety suite holds, including the delivered-tier
  cross-exclusivity per edge (`DeliveredCrossExclusive`, which
  the fleet phase supports by retaining the foreclosing edge's
  parent and form, as the Go `Foreclosed` cause does). Two
  probes: `NeverMixedOutcome` pins outcome coexistence (winning
  child buried, losing child foreclosed — its shortest witness
  reaches the foreclosure through the over-approximated
  certification event, so it deliberately claims nothing about
  settlement), and `NeverMixedSettlement` pins the mixed terminal
  settlement itself as an action-level witness in which both
  settlement arms perform observable work: a single
  parent-delivery transition, with both forms previously observed
  for P, stages the previously unstaged losing edge on s2 and
  clears stale staging from the winning edge in that very step
  (`traces/mixed_settlement.txt`; the stale staging is supplied
  by a restage against a stale on-chain flag, a torn-stream
  interleaving in its own right).
- **Split-sweep realization** (`MC_split.cfg`): the registered
  whole-set claim s1 against a rebatched realization — partial
  spenders f1 and f2 consuming the trigger set in separate
  transactions. All watcher invariants hold; the claim is
  nevertheless abandoned by direct foreign burial
  (`traces/split_sweep.txt`, 7 states). This is the policy seam
  made concrete: a sweep that succeeded in pieces abandons a
  claim registered at whole-set granularity, with the watcher
  blameless. The design's rule — outpoints realizable separately
  belong to separate anchorings — is therefore a binding
  obligation on the sweeper site's registration granularity, not
  advice.
- **Duplicate registration** (`MC3_dupreg.cfg`): two anchorings
  over one trigger set, as would result from registering per
  transaction attempt instead of per logical claim. Every
  per-anchoring invariant holds — and the
  `NeverDoubleRelease` probe shows one chain outcome releasing
  act-gated effects twice, once per registration
  (`traces/duplicate_registration.txt`, 8 states: a single
  certification notification, processed once per anchoring,
  buries both). Materialization exclusivity is per anchoring by
  design; registering once per logical claim (attempts as
  candidates of one anchoring — the correct answer to the
  aux_sweeper replacement TODO) is the integration's obligation.

The two cautionary traces are deliberately not invariant
violations: they demonstrate that registration granularity is a
site-tier obligation the core cannot enforce, and show precisely
what its violation costs.

Fleet limitations, explicit: the predicate (`PredOK`) and the
threshold are global, so a batched transaction cannot be
satisfying for one anchoring and predicate-rejected by another
(verdicts still diverge across anchorings through trigger-set
coverage), and parent and child cannot carry different
thresholds. Edges are static from genesis — conservative for
safety, and faithful for children that declare their depended
form at registration, but not a reachability witness for the
derive-edges-later registry path.

Not modeled, deliberately: fee rules, mempool policy, unbounded
replacement chains (the watcher consumes none of these), and the
site-tier properties that need the per-site handlers from the
follow-up PR — predicate correctness over replacements,
registration-broadcast crash ordering, proof-material sourcing
discipline, and idempotency-key choice. Those should be verified
against the real site code, seeded by this model's assumption
ledger.

## Running

The flake in this directory runs the whole battery with the
correct expectation per configuration — suites must hold, probes
and counterexample configurations must be violated — so a green
run means everything behaved, including the reachability floor:

    nix run .              # quick: probes + fast suites (~10 min)
    nix run . -- probes    # all expected-violated runs (~2 min)
    nix run . -- safety    # every exhaustive safety suite (~1.5 h)
    nix run . -- liveness  # the three liveness suites (~20 min)
    nix run . -- all       # everything (~2 h)

`nix flake check` runs the probe battery. `nix develop` provides
`tlc` and the `watcher-tlc` runner for ad-hoc work.

For manual runs, TLC is available via `nix-shell -p tlaplus`:

    tlc -deadlock -workers auto -config MC_safety.cfg MC
    tlc -deadlock -workers auto -config MC2_full.cfg MC2

Substitute any other `.cfg` for the other runs. `-deadlock`
disables deadlock reporting: the bounded instances quiesce by
design when their mining and event budgets are exhausted. Runs
above roughly twenty million distinct states need an explicit
`-Xmx4g` (the flake runner applies it everywhere).

## Run log

Times are from a laptop; state counts are TLC's distinct-state
figures. Probe, boundary, and counterexample runs finish in
seconds throughout.

Single anchoring, `MC_safety.cfg` (threshold 2, chain length 4,
six mineable blocks, two in-flight events): ~72M states
generated, ~8.7M distinct, depth 30, about six minutes.

Cascade (chain length 4, five mineable blocks, two in-flight
events), all invariants and action properties holding:

- `MC2_repl.cfg`: ~19.9M states generated, ~2.3M distinct,
  2min 07s.
- `MC2_foreign.cfg`: ~8.5M states generated, ~1.0M distinct,
  1min 09s.
- `MC2_full.cfg`: ~70.0M states generated, ~7.9M distinct,
  depth 28, 12min 45s.

Liveness (chain length 3, four blocks):

- `MC_live.cfg`: ~2.5M states generated, ~275k distinct, temporal
  check included, 23s.
- `MC2_live_repl.cfg`: 11min 08s; `MC2_live_foreign.cfg`:
  4min 45s. Both green, safety cross-checks included.

Discipline runs (deep reorgs permitted):

- `MC_discipline.cfg`: ~189.8M states generated, ~22.0M distinct,
  12min 47s — absorption and monotonicity hold out of contract.
- `MC2_discipline.cfg` (four blocks — sufficient for the
  deep-reorg recertification cycle): ~18.8M states generated,
  ~2.1M distinct, 2min 30s — absorption, monotonicity,
  frozen-foreclosure stickiness, outbox exclusivity and
  durable-enqueue all hold out of contract.

Integration seams:

- `MC3_dualchild.cfg`: ~220.2M states generated, ~20.2M distinct,
  26min 50s (run with an explicit `-Xmx4g`; the default heap gets
  the JVM killed under memory pressure at this size).
- `MC_split.cfg`: ~115.8M states generated, ~14.2M distinct,
  6min 58s.
- `MC3_dupreg.cfg`: seconds.
