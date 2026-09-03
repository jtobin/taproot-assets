---------------------- MODULE AnchoringWatcher ----------------------
(* Model of the anchoring watcher (tapreorg): a single
   anchoring, no dependency edges; safety, and liveness under the
   fairness assumptions documented at LiveSpec below.

   Correspondence with the implementation (see README.md for the
   full mapping and the abstractions it rests on):

     - PhaseOf          ~ DerivePhase           (derive.go)
     - ProcessConf      ~ handleCandidateConf   (service.go)
     - ProcessAct       ~ handleCandidateActConf
     - ProcessLoss      ~ markCandidateOffChain
     - LocOnChain       ~ verifyLocation
     - Deliver          ~ deliverOne + Registry.Deliver's
                          transactional stale-target recheck, which
                          is what justifies modeling delivery as one
                          atomic step
     - Restart / Drop   ~ daemon restart, sensor rebuild, broken
                          streams: in-flight events vanish; the
                          notifier's historical dispatch is modeled
                          by emission preconditions being
                          re-satisfiable at any time

   Environment contract:

     - Emission preconditions are evaluated at emission time
       (truthful notifier), but events are processed arbitrarily
       later, possibly duplicated, possibly never: the torn-stream
       model.
     - The chain never reorgs a block that ever held more than
       StabilityDepth confirmations. StabilityDepth = Threshold - 1
       is the in-contract configuration; StabilityDepth >= Threshold
       is the explicitly out-of-scope deep-reorg case (see
       MC_boundary.cfg).

   The Buggy* definitions model the pre-certification design that
   derived act finality from an on-chain flag plus a separately
   streamed best height (removed in commit 7b240705); MC_tear.cfg
   reproduces its failure. *)

EXTENDS Integers, Sequences, FiniteSets, TLC

CONSTANTS
    Txs,            \* candidate spending transactions
    Triggers,       \* the anchoring's trigger outpoints
    SpendsOf,       \* [Txs -> SUBSET Triggers]: outpoints spent
    PredOK,         \* [Txs -> BOOLEAN]: site predicate verdict
    Threshold,      \* act-confirmation depth
    StabilityDepth, \* chain contract: max reorgable ever-held depth
    MaxLen,         \* bound: chain length
    MaxBlocks,      \* bound: total blocks ever mined
    MaxPending,     \* bound: in-flight events
    EnableEpochs,   \* enable the buggy-derivation epoch stream
    AlwaysConsume   \* processing always consumes its event; used
                    \* by liveness configs (duplicate delivery of a
                    \* stale event is covered by the safety runs)

NoTx == "none"

VARIABLES
    chain,      \* Seq([id: block id, tx: Txs \cup {NoTx}])
    nextId,     \* next fresh block id (id ~ block hash)
    maxLen,     \* maximum chain length ever reached
    cands,      \* durable registry view: tx -> [h, b, on, cert]
    delivered,  \* durable delivered phase
    pending,    \* in-flight notification events
    seenHeight  \* buggy tier only: separately streamed best height

vars == <<chain, nextId, maxLen, cands, delivered, pending,
          seenHeight>>

----------------------------------------------------------------------
(* Chain helpers. Block ids are minted once, so an id determines a
   unique (height, tx) binding; LocOnChain is verifyLocation. *)

Heights == 1..Len(chain)
TxAt(h) == chain[h].tx
OnChainTxs == {TxAt(h) : h \in Heights} \ {NoTx}
HeightOf(t) == CHOOSE h \in Heights : TxAt(h) = t
Confs(t) == Len(chain) - HeightOf(t) + 1
SpentOutpoints == UNION {SpendsOf[t] : t \in OnChainTxs}
LocOnChain(h, b) == h \in Heights /\ chain[h].id = b

Max(a, b) == IF a >= b THEN a ELSE b

(* The whole-set rule plus the site predicate, evaluated exactly
   once per transaction (the predicate is pure): only a spender of
   the entire trigger set can satisfy; a partial spender is foreign
   by construction. *)
VerdictOf(t) ==
    IF SpendsOf[t] = Triggers /\ PredOK[t] THEN "sat" ELSE "foreign"

----------------------------------------------------------------------
(* Phases, mirroring phase.go. Withdrawn is site-initiated and
   out of scope here. *)

Unwitnessed == [tag |-> "unwitnessed"]
Witnessed(t, h, b) ==
    [tag |-> "witnessed", tx |-> t, h |-> h, b |-> b]
Conflicted(S) == [tag |-> "conflicted", spends |-> S]
Buried(t, h, b) == [tag |-> "buried", tx |-> t, h |-> h, b |-> b]
AbandonedBy(t, h, b) ==
    [tag |-> "abandoned", tx |-> t, h |-> h, b |-> b]

IsTerminal(p) == p.tag \in {"buried", "abandoned"}

----------------------------------------------------------------------
(* Phase derivation, mirroring DerivePhase's evidence ranking:
   certified witness > certified foreign > live witness > any live
   foreign (Conflicted) > Unwitnessed, with contradictory
   certifications withheld (falling through to the potency tier).
   CHOOSE stands in for the canonical preference order, whose
   properties belong to the pure-kernel tier, not this model. *)

CertSat ==
    {t \in DOMAIN cands : cands[t].cert /\ VerdictOf(t) = "sat"}
CertFor ==
    {t \in DOMAIN cands : cands[t].cert /\ VerdictOf(t) = "foreign"}
LiveSat ==
    {t \in DOMAIN cands : cands[t].on /\ VerdictOf(t) = "sat"}
LiveFor ==
    {t \in DOMAIN cands : cands[t].on /\ VerdictOf(t) = "foreign"}

PhaseOf ==
    IF CertSat # {} /\ CertFor = {} THEN
        LET t == CHOOSE x \in CertSat : TRUE
        IN Buried(t, cands[t].h, cands[t].b)
    ELSE IF CertFor # {} /\ CertSat = {} THEN
        LET t == CHOOSE x \in CertFor : TRUE
        IN AbandonedBy(t, cands[t].h, cands[t].b)
    ELSE IF LiveSat # {} /\ LiveFor = {} THEN
        LET t == CHOOSE x \in LiveSat : TRUE
        IN Witnessed(t, cands[t].h, cands[t].b)
    ELSE IF LiveFor # {} THEN
        Conflicted(LiveFor)
    ELSE
        Unwitnessed

(* Terminal sensed phases end sensing (rederive stops the sensor,
   the sweep re-adopts only live anchorings), so every sensing
   action is guarded on Live. *)
Live == ~IsTerminal(PhaseOf)

----------------------------------------------------------------------
(* Environment: chain evolution under the stability contract. *)

MineableTxs ==
    {t \in Txs : t \notin OnChainTxs
                 /\ SpendsOf[t] \cap SpentOutpoints = {}}

Extend ==
    /\ Len(chain) < MaxLen
    /\ nextId <= MaxBlocks
    /\ \E t \in MineableTxs \cup {NoTx} :
        chain' = Append(chain, [id |-> nextId, tx |-> t])
    /\ nextId' = nextId + 1
    /\ maxLen' = Max(maxLen, Len(chain) + 1)
    /\ UNCHANGED <<cands, delivered, pending, seenHeight>>

(* A reorg may truncate any suffix that never held more than
   StabilityDepth confirmations; extension then rebuilds. The
   intermediate shorter chain is observable (a shorter-but-heavier
   chain), which verifyLocation handles. *)
Reorg ==
    \E d \in 1..Len(chain) :
        /\ Len(chain) - d >= maxLen - StabilityDepth
        /\ chain' = SubSeq(chain, 1, Len(chain) - d)
        /\ UNCHANGED <<nextId, maxLen, cands, delivered, pending,
                       seenHeight>>

----------------------------------------------------------------------
(* Environment: notifier emissions. Preconditions hold at emission
   time (the notifier is truthful); processing happens arbitrarily
   later. Every model transaction spends a trigger outpoint, so the
   spend subscription covers all of Txs. *)

CanEmit == Cardinality(pending) < MaxPending

(* Emissions are parameterized per transaction so that liveness
   fairness can be asserted per stream rather than being
   satisfiable by firings on the wrong transaction. *)
EmitConfTx(t) ==
    /\ Live /\ CanEmit
    /\ t \in OnChainTxs
    /\ pending' = pending \cup
        {[k |-> "conf", tx |-> t, h |-> HeightOf(t),
          b |-> chain[HeightOf(t)].id]}
    /\ UNCHANGED <<chain, nextId, maxLen, cands, delivered,
                   seenHeight>>

EmitConf == \E t \in Txs : EmitConfTx(t)

(* The certification contract: a threshold-depth confirmation fires
   only for a transaction genuinely holding that depth on the
   dominant chain at emission time. *)
EmitActTx(t) ==
    /\ Live /\ CanEmit
    /\ t \in OnChainTxs
    /\ Confs(t) >= Threshold
    /\ pending' = pending \cup
        {[k |-> "act", tx |-> t, h |-> HeightOf(t),
          b |-> chain[HeightOf(t)].id]}
    /\ UNCHANGED <<chain, nextId, maxLen, cands, delivered,
                   seenHeight>>

EmitAct == \E t \in Txs : EmitActTx(t)

(* The spend subscription's reorg channel: fires when a previously
   reported spender leaves the dominant chain. *)
EmitLossTx(t) ==
    /\ Live /\ CanEmit
    /\ t \in DOMAIN cands
    /\ t \notin OnChainTxs
    /\ pending' = pending \cup {[k |-> "loss", tx |-> t]}
    /\ UNCHANGED <<chain, nextId, maxLen, cands, delivered,
                   seenHeight>>

EmitLoss == \E t \in Txs : EmitLossTx(t)

EmitEpoch ==
    /\ EnableEpochs /\ Live /\ CanEmit
    /\ pending' = pending \cup {[k |-> "epoch", n |-> Len(chain)]}
    /\ UNCHANGED <<chain, nextId, maxLen, cands, delivered,
                   seenHeight>>

----------------------------------------------------------------------
(* Watcher: event processing. Dispose leaves the event pending on
   one branch, which models duplicate delivery of the same stale
   event; Drop and Restart model losing events outright. *)

Dispose(e) ==
    IF AlwaysConsume
    THEN pending' = pending \ {e}
    ELSE pending' \in {pending, pending \ {e}}

(* handleCandidateConf: verify the location against the dominant
   chain; a stale confirmation is dropped, a fresh one records the
   candidate on-chain at its location. Certification is sticky
   across upserts (the registry ORs act_certified); a threshold of
   one makes the first confirmation itself the certification. *)
ProcessConfTx(t) ==
    /\ Live
    /\ \E e \in pending :
        /\ e.k = "conf" /\ e.tx = t
        /\ IF LocOnChain(e.h, e.b)
           THEN cands' =
               ((e.tx :> [h |-> e.h, b |-> e.b, on |-> TRUE,
                          cert |-> \/ (e.tx \in DOMAIN cands
                                       /\ cands[e.tx].cert)
                                   \/ Threshold <= 1])
                @@ cands)
           ELSE cands' = cands
        /\ Dispose(e)
    /\ UNCHANGED <<chain, nextId, maxLen, delivered, seenHeight>>

ProcessConf == \E t \in Txs : ProcessConfTx(t)

(* handleCandidateActConf: a certification whose location the
   dominant chain has already displaced is dropped (resense), never
   recorded; a verified one records the candidate certified. *)
ProcessActTx(t) ==
    /\ Live
    /\ \E e \in pending :
        /\ e.k = "act" /\ e.tx = t
        /\ IF LocOnChain(e.h, e.b)
           THEN cands' =
               ((e.tx :> [h |-> e.h, b |-> e.b, on |-> TRUE,
                          cert |-> TRUE])
                @@ cands)
           ELSE cands' = cands
        /\ Dispose(e)
    /\ UNCHANGED <<chain, nextId, maxLen, delivered, seenHeight>>

ProcessAct == \E t \in Txs : ProcessActTx(t)

(* markCandidateOffChain: flip a candidate off-chain only if its
   recorded location really is gone from the dominant chain; a
   stale loss signal is dropped. *)
ProcessLossTx(t) ==
    /\ Live
    /\ \E e \in pending :
        /\ e.k = "loss" /\ e.tx = t
        /\ IF /\ e.tx \in DOMAIN cands
              /\ cands[e.tx].on
              /\ ~LocOnChain(cands[e.tx].h, cands[e.tx].b)
           THEN cands' = [cands EXCEPT ![e.tx].on = FALSE]
           ELSE cands' = cands
        /\ Dispose(e)
    /\ UNCHANGED <<chain, nextId, maxLen, delivered, seenHeight>>

ProcessLoss == \E t \in Txs : ProcessLossTx(t)

ProcessEpoch ==
    /\ EnableEpochs /\ Live
    /\ \E e \in pending :
        /\ e.k = "epoch"
        /\ seenHeight' = Max(seenHeight, e.n)
        /\ Dispose(e)
    /\ UNCHANGED <<chain, nextId, maxLen, cands, delivered>>

(* A broken stream loses an in-flight event; a restart loses all of
   them. Durable state survives; historical dispatch on re-adoption
   is modeled by emissions being re-enabled whenever their
   preconditions hold. *)
Drop ==
    /\ \E e \in pending : pending' = pending \ {e}
    /\ UNCHANGED <<chain, nextId, maxLen, cands, delivered,
                   seenHeight>>

Restart ==
    /\ pending # {}
    /\ pending' = {}
    /\ UNCHANGED <<chain, nextId, maxLen, cands, delivered,
                   seenHeight>>

----------------------------------------------------------------------
(* Delivery: Registry.Deliver re-checks inside the transaction that
   the sensed phase still equals the target and advances the
   delivered phase atomically; a stale target is discarded. That
   recheck is exactly what makes this one atomic action a faithful
   model of the delivery loop. *)

Deliver ==
    /\ delivered # PhaseOf
    /\ delivered' = PhaseOf
    /\ UNCHANGED <<chain, nextId, maxLen, cands, pending,
                   seenHeight>>

----------------------------------------------------------------------

Init ==
    /\ chain = <<>>
    /\ nextId = 1
    /\ maxLen = 0
    /\ cands = [t \in {} |-> [h |-> 0, b |-> 0, on |-> FALSE,
                              cert |-> FALSE]]
    /\ delivered = Unwitnessed
    /\ pending = {}
    /\ seenHeight = 0

Next ==
    \/ Extend \/ Reorg
    \/ EmitConf \/ EmitAct \/ EmitLoss \/ EmitEpoch
    \/ ProcessConf \/ ProcessAct \/ ProcessLoss \/ ProcessEpoch
    \/ Drop \/ Restart
    \/ Deliver

Spec == Init /\ [][Next]_vars

----------------------------------------------------------------------
(* Safety properties. *)

TypeOK ==
    /\ chain \in Seq([id : 1..MaxBlocks, tx : Txs \cup {NoTx}])
    /\ nextId \in 1..(MaxBlocks + 1)
    /\ maxLen \in 0..MaxLen
    /\ DOMAIN cands \subseteq Txs
    /\ \A t \in DOMAIN cands :
        cands[t] \in [h : 1..MaxLen, b : 1..MaxBlocks,
                      on : BOOLEAN, cert : BOOLEAN]
    /\ seenHeight \in 0..MaxLen

(* A recorded certification always locates a block on the dominant
   chain: the strongest single invariant, from which the two below
   follow. Holds under the stability contract
   (StabilityDepth < Threshold); expected to fail under
   MC_boundary.cfg. *)
CertifiedOnChain ==
    \A t \in DOMAIN cands :
        cands[t].cert => LocOnChain(cands[t].h, cands[t].b)

NoFalseBurial ==
    PhaseOf.tag = "buried" =>
        /\ LocOnChain(PhaseOf.h, PhaseOf.b)
        /\ TxAt(PhaseOf.h) = PhaseOf.tx
        /\ VerdictOf(PhaseOf.tx) = "sat"

NoFalseAbandon ==
    PhaseOf.tag = "abandoned" =>
        /\ LocOnChain(PhaseOf.h, PhaseOf.b)
        /\ TxAt(PhaseOf.h) = PhaseOf.tx
        /\ VerdictOf(PhaseOf.tx) = "foreign"

(* Action properties: terminal phases are absorbing at both tiers,
   candidates are never deleted, and certification is sticky. *)
SensedTerminalAbsorbing ==
    [][IsTerminal(PhaseOf) => PhaseOf' = PhaseOf]_vars

DeliveredTerminalAbsorbing ==
    [][IsTerminal(delivered) => delivered' = delivered]_vars

ViewMonotone ==
    [][\A t \in DOMAIN cands :
        /\ t \in DOMAIN cands'
        /\ (cands[t].cert => cands'[t].cert)]_vars

----------------------------------------------------------------------
(* Liveness. The environment quiesces structurally
   (mining and reorg budgets are finite), so no fairness is
   assumed of the chain.

   The notifier's liveness contract — each live subscription
   eventually delivers a truthful notification which is eventually
   processed — is modeled as per-transaction refresh composites:
   one atomic emit-verify-record step whose effect is exactly
   processing a just-emitted event against the current chain. The
   composites carry weak fairness, which is sound because a
   productive refresh remains enabled until it (or the equivalent
   async path) lands. The entire async queue machinery remains in
   the liveness spec, fully adversarial and unfaired: drops,
   restarts, stale events and duplicates still interleave freely.
   (Per-stream strong fairness over the queue actions states the
   same contract without the composite, but its tableau is beyond
   TLC's reach even on tiny instances.)

   Delivery carries weak fairness: the retry discipline. The model
   has no permanently failing site handler, so WF is exactly
   "retries never stop and eventually succeed"; a handler failing
   forever is the stuck-delivery operational surface, out of
   scope. *)

RefreshTx(t) ==
    /\ Live
    /\ IF t \in OnChainTxs
       THEN cands' =
           ((t :> [h |-> HeightOf(t), b |-> chain[HeightOf(t)].id,
                   on |-> TRUE,
                   cert |-> \/ (t \in DOMAIN cands
                                /\ cands[t].cert)
                            \/ Threshold <= 1])
            @@ cands)
       ELSE IF /\ t \in DOMAIN cands
               /\ cands[t].on
               /\ ~LocOnChain(cands[t].h, cands[t].b)
       THEN cands' = [cands EXCEPT ![t].on = FALSE]
       ELSE cands' = cands
    /\ UNCHANGED <<chain, nextId, maxLen, delivered, pending,
                   seenHeight>>

CertifyTx(t) ==
    /\ Live
    /\ t \in OnChainTxs
    /\ Confs(t) >= Threshold
    /\ cands' =
        ((t :> [h |-> HeightOf(t), b |-> chain[HeightOf(t)].id,
                on |-> TRUE, cert |-> TRUE])
         @@ cands)
    /\ UNCHANGED <<chain, nextId, maxLen, delivered, pending,
                   seenHeight>>

LiveNext ==
    \/ Next
    \/ \E t \in Txs : RefreshTx(t) \/ CertifyTx(t)

Fairness ==
    /\ \A t \in Txs :
        /\ WF_vars(RefreshTx(t))
        /\ WF_vars(CertifyTx(t))
    /\ WF_vars(Deliver)

LiveSpec == Init /\ [][LiveNext]_vars /\ Fairness

(* The delivered phase converges to the sensed phase. *)
Convergence == <>[](delivered = PhaseOf)

(* A live anchoring's durable view converges to the chain's truth:
   recorded on-chain flags eventually agree with the dominant
   chain, at fresh locations. Scoped to live anchorings because a
   terminal anchoring stops sensing by design, freezing whatever
   incidental staleness other candidates' rows carry. *)
ViewAccurate ==
    \A t \in DOMAIN cands :
        /\ cands[t].on <=> t \in OnChainTxs
        /\ cands[t].on => LocOnChain(cands[t].h, cands[t].b)

SensedTruth == <>[](~IsTerminal(PhaseOf) => ViewAccurate)

----------------------------------------------------------------------
(* The pre-certification design: act finality from the recorded
   on-chain flag plus a separately streamed best height. The two
   inputs tear; MC_tear.cfg exhibits the resulting false burial. *)

BuggyBuried ==
    \E t \in LiveSat : seenHeight - cands[t].h + 1 >= Threshold

BuggyNoFalseBurial ==
    BuggyBuried =>
        \E t \in LiveSat :
            /\ seenHeight - cands[t].h + 1 >= Threshold
            /\ LocOnChain(cands[t].h, cands[t].b)

======================================================================
