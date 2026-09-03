---------------------- MODULE AnchoringCascade ----------------------
(* Model of the anchoring watcher cascade: two anchorings — a
   parent P and a child C — joined by one dependency edge pinned to
   a specific parent witness form, plus the transactional outbox;
   safety, and liveness under the fairness assumptions documented
   at LiveSpec below. Single-anchoring mechanics are covered by
   AnchoringWatcher.tla.

   New correspondence (see README.md):

     - Restage           ~ restageEdge, invoked from the parent's
                           rederive (restageDependentForeclosures)
                           and the child's adoption
                           (reconcileForeclosures). It is a pure
                           function of the parent's current phase,
                           so it is modeled as an always-enabled
                           action: a lost or delayed restage is a
                           run in which the action simply fires
                           later, and adoption healing is a run in
                           which it fires again.
     - ProcessFcAct      ~ handleForeclosureActConf: verify the
                           certifying location, then stage the
                           foreclosure certified; the registry's
                           row guard freezes an already-certified
                           edge.
     - DeliverP          ~ deliverOne + Registry.Deliver: terminal
                           delivery settles dependent edges and
                           enqueues site effects in the same
                           transaction. Abandonment forecloses
                           every edge with the cause witness;
                           burial clears edges pinned to the buried
                           form and forecloses the rest.
     - Dispatch          ~ the outbox loop: at-least-once dispatch
                           of enqueued effects; set semantics is
                           the idempotent-handler abstraction.

   The foreign-abandonment foreclosure path exists only via
   delivery settlement (restageEdge stages parent witness forms
   only); the model preserves this asymmetry. *)

EXTENDS Integers, Sequences, FiniteSets, TLC

CONSTANTS
    Txs,            \* candidate spending transactions in play
    ParentTriggers, \* P's trigger outpoints
    ChildTriggers,  \* C's trigger outpoints (outputs of the
                    \* depended-upon parent form)
    SpendsOf,       \* [tx -> SUBSET outpoints]
    PredOK,         \* [tx -> BOOLEAN]: site predicate verdict
    AnchorOf,       \* [tx -> {"P", "C"}]: which anchoring a
                    \* spender belongs to
    DependedForm,   \* the parent witness form C's triggers are
                    \* outputs of
    Threshold,      \* act depth, both anchorings (the code allows
                    \* per-anchoring thresholds; equal here)
    StabilityDepth, \* chain contract, as in AnchoringWatcher
    MaxLen, MaxBlocks, MaxPending,
    AlwaysConsume   \* processing always consumes its event; used
                    \* by liveness configs

NoTx == "none"

(* The unstaged edge, as a uniform record so that TLC can compare
   it with staged evidence; the non-flag fields are inert. *)
NoFc == [staged |-> FALSE, tx |-> NoTx, h |-> 1, b |-> 1,
         on |-> FALSE, cert |-> FALSE]

VARIABLES
    chain, nextId, maxLen,  \* environment, as in AnchoringWatcher
    cands,       \* unified registry view: tx -> [h, b, on, cert]
    fc,          \* the C->P edge's staged foreclosure: NoFc or
                 \* [tx, h, b, on, cert]
    deliveredP, deliveredC,
    outbox,      \* durably enqueued external effects
    performed,   \* effects actually dispatched to the world
    pending      \* in-flight notification events

vars == <<chain, nextId, maxLen, cands, fc, deliveredP, deliveredC,
          outbox, performed, pending>>

----------------------------------------------------------------------
(* Chain helpers, as in AnchoringWatcher. *)

Heights == 1..Len(chain)
TxAt(h) == chain[h].tx
OnChainTxs == {TxAt(h) : h \in Heights} \ {NoTx}
HeightOf(t) == CHOOSE h \in Heights : TxAt(h) = t
Confs(t) == Len(chain) - HeightOf(t) + 1
SpentOutpoints == UNION {SpendsOf[t] : t \in OnChainTxs}
LocOnChain(h, b) == h \in Heights /\ chain[h].id = b

Max(a, b) == IF a >= b THEN a ELSE b

TriggersOf(a) == IF a = "P" THEN ParentTriggers ELSE ChildTriggers

VerdictOf(t) ==
    IF SpendsOf[t] = TriggersOf(AnchorOf[t]) /\ PredOK[t]
    THEN "sat" ELSE "foreign"

(* Parent-side spenders other than the depended form: realized in
   any of these forms, the parent can no longer supply C's
   triggers. *)
ForeclosingTxs ==
    {t \in Txs : AnchorOf[t] = "P" /\ t # DependedForm}

----------------------------------------------------------------------
(* Phases. Abandoned records its cause: a directly buried foreign
   spend, or foreclosure through the edge. *)

Unwitnessed == [tag |-> "unwitnessed"]
Witnessed(t, h, b) ==
    [tag |-> "witnessed", tx |-> t, h |-> h, b |-> b]
Conflicted(S) == [tag |-> "conflicted", spends |-> S]
Buried(t, h, b) == [tag |-> "buried", tx |-> t, h |-> h, b |-> b]
AbandonedBy(t, h, b) ==
    [tag |-> "abandoned", cause |-> "foreign",
     tx |-> t, h |-> h, b |-> b]
AbandonedFc(t, h, b) ==
    [tag |-> "abandoned", cause |-> "foreclosed",
     tx |-> t, h |-> h, b |-> b]

IsTerminal(p) == p.tag \in {"buried", "abandoned"}

FcFrozen == fc.staged /\ fc.cert

----------------------------------------------------------------------
(* Derivation, mirroring DerivePhase's full ranking: certified
   witness, certified foreign, certified foreclosure, live witness,
   any live foreign (Conflicted), Unwitnessed. Contradictory direct
   certifications fall through to the foreclosure tier and below,
   as in derive.go. *)

CertSat(a) == {t \in DOMAIN cands :
    AnchorOf[t] = a /\ cands[t].cert /\ VerdictOf(t) = "sat"}
CertFor(a) == {t \in DOMAIN cands :
    AnchorOf[t] = a /\ cands[t].cert /\ VerdictOf(t) = "foreign"}
LiveSat(a) == {t \in DOMAIN cands :
    AnchorOf[t] = a /\ cands[t].on /\ VerdictOf(t) = "sat"}
LiveFor(a) == {t \in DOMAIN cands :
    AnchorOf[t] = a /\ cands[t].on /\ VerdictOf(t) = "foreign"}

DerivedPhase(a, fcert) ==
    IF CertSat(a) # {} /\ CertFor(a) = {} THEN
        LET t == CHOOSE x \in CertSat(a) : TRUE
        IN Buried(t, cands[t].h, cands[t].b)
    ELSE IF CertFor(a) # {} /\ CertSat(a) = {} THEN
        LET t == CHOOSE x \in CertFor(a) : TRUE
        IN AbandonedBy(t, cands[t].h, cands[t].b)
    ELSE IF fcert.staged THEN
        AbandonedFc(fcert.tx, fcert.h, fcert.b)
    ELSE IF LiveSat(a) # {} /\ LiveFor(a) = {} THEN
        LET t == CHOOSE x \in LiveSat(a) : TRUE
        IN Witnessed(t, cands[t].h, cands[t].b)
    ELSE IF LiveFor(a) # {} THEN
        Conflicted(LiveFor(a))
    ELSE
        Unwitnessed

PhaseOfP == DerivedPhase("P", NoFc)
PhaseOfC == DerivedPhase("C", IF FcFrozen THEN fc ELSE NoFc)

PhaseAnch(a) == IF a = "P" THEN PhaseOfP ELSE PhaseOfC
LiveAnch(a) == ~IsTerminal(PhaseAnch(a))

----------------------------------------------------------------------
(* Environment: chain evolution. A child spender commits to
   outputs of the depended parent form, so it is mineable only
   while that form is on the dominant chain; suffix truncation then
   automatically removes descendants with their ancestor. *)

MineableTxs ==
    {t \in Txs :
        /\ t \notin OnChainTxs
        /\ SpendsOf[t] \cap SpentOutpoints = {}
        /\ (AnchorOf[t] = "C" => DependedForm \in OnChainTxs)}

Extend ==
    /\ Len(chain) < MaxLen
    /\ nextId <= MaxBlocks
    /\ \E t \in MineableTxs \cup {NoTx} :
        chain' = Append(chain, [id |-> nextId, tx |-> t])
    /\ nextId' = nextId + 1
    /\ maxLen' = Max(maxLen, Len(chain) + 1)
    /\ UNCHANGED <<cands, fc, deliveredP, deliveredC, outbox,
                   performed, pending>>

Reorg ==
    \E d \in 1..Len(chain) :
        /\ Len(chain) - d >= maxLen - StabilityDepth
        /\ chain' = SubSeq(chain, 1, Len(chain) - d)
        /\ UNCHANGED <<nextId, maxLen, cands, fc, deliveredP,
                       deliveredC, outbox, performed, pending>>

----------------------------------------------------------------------
(* Notifier emissions, truthful at emission time. *)

CanEmit == Cardinality(pending) < MaxPending

(* Emissions parameterized per transaction, for per-stream
   liveness fairness. *)
EmitConfTx(t) ==
    /\ CanEmit
    /\ t \in OnChainTxs
    /\ LiveAnch(AnchorOf[t])
    /\ pending' = pending \cup
        {[k |-> "conf", tx |-> t, h |-> HeightOf(t),
          b |-> chain[HeightOf(t)].id]}
    /\ UNCHANGED <<chain, nextId, maxLen, cands, fc, deliveredP,
                   deliveredC, outbox, performed>>

EmitConf == \E t \in Txs : EmitConfTx(t)

EmitActTx(t) ==
    /\ CanEmit
    /\ t \in OnChainTxs
    /\ LiveAnch(AnchorOf[t])
    /\ Confs(t) >= Threshold
    /\ pending' = pending \cup
        {[k |-> "act", tx |-> t, h |-> HeightOf(t),
          b |-> chain[HeightOf(t)].id]}
    /\ UNCHANGED <<chain, nextId, maxLen, cands, fc, deliveredP,
                   deliveredC, outbox, performed>>

EmitAct == \E t \in Txs : EmitActTx(t)

EmitLossTx(t) ==
    /\ CanEmit
    /\ t \in DOMAIN cands
    /\ LiveAnch(AnchorOf[t])
    /\ t \notin OnChainTxs
    /\ pending' = pending \cup {[k |-> "loss", tx |-> t]}
    /\ UNCHANGED <<chain, nextId, maxLen, cands, fc, deliveredP,
                   deliveredC, outbox, performed>>

EmitLoss == \E t \in Txs : EmitLossTx(t)

(* The foreclosure certification subscription (watchForeclosure):
   a confirmation notification on a foreclosing transaction at the
   child's threshold. Modeled for any foreclosing-capable
   transaction genuinely at depth — a superset of the
   subscription-existence discipline in the code, hence strictly
   more adversarial. *)
EmitFcActTx(t) ==
    /\ CanEmit /\ LiveAnch("C")
    /\ t \in ForeclosingTxs \cap OnChainTxs
    /\ Confs(t) >= Threshold
    /\ pending' = pending \cup
        {[k |-> "fcact", tx |-> t, h |-> HeightOf(t),
          b |-> chain[HeightOf(t)].id]}
    /\ UNCHANGED <<chain, nextId, maxLen, cands, fc, deliveredP,
                   deliveredC, outbox, performed>>

EmitFcAct == \E t \in Txs : EmitFcActTx(t)

----------------------------------------------------------------------
(* Watcher: event processing, as in AnchoringWatcher, routed by the
   spender's anchoring. *)

Dispose(e) ==
    IF AlwaysConsume
    THEN pending' = pending \ {e}
    ELSE pending' \in {pending, pending \ {e}}

ProcessConfTx(t) ==
    \E e \in pending :
        /\ e.k = "conf" /\ e.tx = t
        /\ LiveAnch(AnchorOf[e.tx])
        /\ IF LocOnChain(e.h, e.b)
           THEN cands' =
               ((e.tx :> [h |-> e.h, b |-> e.b, on |-> TRUE,
                          cert |-> \/ (e.tx \in DOMAIN cands
                                       /\ cands[e.tx].cert)
                                   \/ Threshold <= 1])
                @@ cands)
           ELSE cands' = cands
        /\ Dispose(e)
        /\ UNCHANGED <<chain, nextId, maxLen, fc, deliveredP,
                       deliveredC, outbox, performed>>

ProcessConf == \E t \in Txs : ProcessConfTx(t)

ProcessActTx(t) ==
    \E e \in pending :
        /\ e.k = "act" /\ e.tx = t
        /\ LiveAnch(AnchorOf[e.tx])
        /\ IF LocOnChain(e.h, e.b)
           THEN cands' =
               ((e.tx :> [h |-> e.h, b |-> e.b, on |-> TRUE,
                          cert |-> TRUE])
                @@ cands)
           ELSE cands' = cands
        /\ Dispose(e)
        /\ UNCHANGED <<chain, nextId, maxLen, fc, deliveredP,
                       deliveredC, outbox, performed>>

ProcessAct == \E t \in Txs : ProcessActTx(t)

ProcessLossTx(t) ==
    \E e \in pending :
        /\ e.k = "loss" /\ e.tx = t
        /\ LiveAnch(AnchorOf[e.tx])
        /\ IF /\ e.tx \in DOMAIN cands
              /\ cands[e.tx].on
              /\ ~LocOnChain(cands[e.tx].h, cands[e.tx].b)
           THEN cands' = [cands EXCEPT ![e.tx].on = FALSE]
           ELSE cands' = cands
        /\ Dispose(e)
        /\ UNCHANGED <<chain, nextId, maxLen, fc, deliveredP,
                       deliveredC, outbox, performed>>

ProcessLoss == \E t \in Txs : ProcessLossTx(t)

(* handleForeclosureActConf: a certification whose location the
   chain has displaced is dropped; a verified one stages the
   foreclosure certified. The registry's row guard makes the write
   a no-op against an already-certified edge. *)
ProcessFcActTx(t) ==
    \E e \in pending :
        /\ e.k = "fcact" /\ e.tx = t
        /\ LiveAnch("C")
        /\ IF LocOnChain(e.h, e.b) /\ ~FcFrozen
           THEN fc' = [staged |-> TRUE, tx |-> e.tx, h |-> e.h,
                       b |-> e.b, on |-> TRUE, cert |-> TRUE]
           ELSE fc' = fc
        /\ Dispose(e)
        /\ UNCHANGED <<chain, nextId, maxLen, cands, deliveredP,
                       deliveredC, outbox, performed>>

ProcessFcAct == \E t \in Txs : ProcessFcActTx(t)

Drop ==
    /\ \E e \in pending : pending' = pending \ {e}
    /\ UNCHANGED <<chain, nextId, maxLen, cands, fc, deliveredP,
                   deliveredC, outbox, performed>>

Restart ==
    /\ pending # {}
    /\ pending' = {}
    /\ UNCHANGED <<chain, nextId, maxLen, cands, fc, deliveredP,
                   deliveredC, outbox, performed>>

----------------------------------------------------------------------
(* Restage: the latency path (parent rederive) and the healing
   path (child adoption), both computing the same pure function of
   the parent's current phase. A certified foreclosure is frozen.
   The parent witnessed or buried in the depended form clears the
   staging; in a different form, stages it on-chain; no witness at
   all downgrades staged evidence to off-chain. *)

Restage ==
    /\ ~FcFrozen
    /\ IF PhaseOfP.tag \in {"witnessed", "buried"}
       THEN IF PhaseOfP.tx = DependedForm
            THEN fc' = NoFc
            ELSE fc' = [staged |-> TRUE, tx |-> PhaseOfP.tx,
                        h |-> PhaseOfP.h, b |-> PhaseOfP.b,
                        on |-> TRUE, cert |-> FALSE]
       ELSE IF fc.staged /\ fc.on
            THEN fc' = [fc EXCEPT !.on = FALSE]
            ELSE fc' = fc
    /\ UNCHANGED <<chain, nextId, maxLen, cands, deliveredP,
                   deliveredC, outbox, performed, pending>>

----------------------------------------------------------------------
(* Delivery. Registry.Deliver's transaction: recheck the target,
   run the site handler (which enqueues its external effects), mark
   delivered, and — for a terminal target — settle dependent edges,
   all atomically. Burial in the depended form clears the edge;
   burial in another form, or abandonment, stages the settling
   witness as foreclosing evidence, frozen edges excepted. *)

SettledFc ==
    IF FcFrozen THEN fc
    ELSE IF PhaseOfP.tag = "buried" /\ PhaseOfP.tx = DependedForm
    THEN NoFc
    ELSE [staged |-> TRUE, tx |-> PhaseOfP.tx, h |-> PhaseOfP.h,
          b |-> PhaseOfP.b, on |-> TRUE, cert |-> FALSE]

DeliverP ==
    /\ deliveredP # PhaseOfP
    /\ deliveredP' = PhaseOfP
    /\ IF PhaseOfP.tag = "buried"
       THEN /\ outbox' = outbox \cup {"releaseP"}
            /\ fc' = SettledFc
       ELSE IF PhaseOfP.tag = "abandoned"
       THEN /\ outbox' = outbox \cup {"compensateP"}
            /\ fc' = SettledFc
       ELSE /\ outbox' = outbox
            /\ fc' = fc
    /\ UNCHANGED <<chain, nextId, maxLen, cands, deliveredC,
                   performed, pending>>

DeliverC ==
    /\ deliveredC # PhaseOfC
    /\ deliveredC' = PhaseOfC
    /\ outbox' = outbox \cup
        (IF PhaseOfC.tag = "buried" THEN {"releaseC"}
         ELSE IF PhaseOfC.tag = "abandoned" THEN {"compensateC"}
         ELSE {})
    /\ UNCHANGED <<chain, nextId, maxLen, cands, fc, deliveredP,
                   performed, pending>>

(* At-least-once outbox dispatch through idempotent handlers; set
   semantics is the idempotency abstraction. *)
DispatchE(e) ==
    /\ e \in outbox
    /\ performed' = performed \cup {e}
    /\ UNCHANGED <<chain, nextId, maxLen, cands, fc, deliveredP,
                   deliveredC, outbox, pending>>

Dispatch ==
    \E e \in {"releaseP", "compensateP", "releaseC", "compensateC"} :
        DispatchE(e)

----------------------------------------------------------------------

Init ==
    /\ chain = <<>>
    /\ nextId = 1
    /\ maxLen = 0
    /\ cands = [t \in {} |-> [h |-> 0, b |-> 0, on |-> FALSE,
                              cert |-> FALSE]]
    /\ fc = NoFc
    /\ deliveredP = Unwitnessed
    /\ deliveredC = Unwitnessed
    /\ outbox = {}
    /\ performed = {}
    /\ pending = {}

Next ==
    \/ Extend \/ Reorg
    \/ EmitConf \/ EmitAct \/ EmitLoss \/ EmitFcAct
    \/ ProcessConf \/ ProcessAct \/ ProcessLoss \/ ProcessFcAct
    \/ Drop \/ Restart
    \/ Restage
    \/ DeliverP \/ DeliverC \/ Dispatch

Spec == Init /\ [][Next]_vars

----------------------------------------------------------------------
(* Safety properties. *)

Effects == {"releaseP", "compensateP", "releaseC", "compensateC"}

TypeOK ==
    /\ chain \in Seq([id : 1..MaxBlocks, tx : Txs \cup {NoTx}])
    /\ nextId \in 1..(MaxBlocks + 1)
    /\ maxLen \in 0..MaxLen
    /\ DOMAIN cands \subseteq Txs
    /\ \A t \in DOMAIN cands :
        cands[t] \in [h : 1..MaxLen, b : 1..MaxBlocks,
                      on : BOOLEAN, cert : BOOLEAN]
    /\ \/ fc = NoFc
       \/ fc \in [staged : {TRUE}, tx : ForeclosingTxs,
                  h : 1..MaxLen, b : 1..MaxBlocks,
                  on : BOOLEAN, cert : BOOLEAN]
    /\ outbox \subseteq Effects
    /\ performed \subseteq Effects

(* Single-anchoring invariants, over both anchorings. *)
CertifiedOnChain ==
    \A t \in DOMAIN cands :
        cands[t].cert => LocOnChain(cands[t].h, cands[t].b)

NoFalseBurial ==
    \A a \in {"P", "C"} :
        PhaseAnch(a).tag = "buried" =>
            /\ LocOnChain(PhaseAnch(a).h, PhaseAnch(a).b)
            /\ TxAt(PhaseAnch(a).h) = PhaseAnch(a).tx
            /\ VerdictOf(PhaseAnch(a).tx) = "sat"

NoFalseAbandonDirect ==
    \A a \in {"P", "C"} :
        (PhaseAnch(a).tag = "abandoned"
         /\ PhaseAnch(a).cause = "foreign") =>
            /\ LocOnChain(PhaseAnch(a).h, PhaseAnch(a).b)
            /\ TxAt(PhaseAnch(a).h) = PhaseAnch(a).tx
            /\ VerdictOf(PhaseAnch(a).tx) = "foreign"

(* Cascade invariants. *)
CertifiedFcOnChain ==
    FcFrozen => /\ LocOnChain(fc.h, fc.b)
                /\ TxAt(fc.h) = fc.tx

(* A foreclosure abandonment names a foreclosing transaction
   genuinely on the dominant chain, and the depended-upon premise
   really is dead. *)
NoFalseForeclosure ==
    (PhaseOfC.tag = "abandoned" /\ PhaseOfC.cause = "foreclosed")
        => /\ LocOnChain(PhaseOfC.h, PhaseOfC.b)
           /\ TxAt(PhaseOfC.h) = PhaseOfC.tx
           /\ PhaseOfC.tx # DependedForm
           /\ DependedForm \notin OnChainTxs

(* The cascade never contradicts itself: a certified foreclosure
   and the parent act-final in the very form the child depends on
   cannot coexist — at the sensed tier or the delivered tier. *)
CascadeExclusive ==
    ~(FcFrozen /\ PhaseOfP.tag = "buried"
      /\ PhaseOfP.tx = DependedForm)

DeliveredCascadeExclusive ==
    ~(/\ deliveredC.tag = "abandoned"
      /\ deliveredC.cause = "foreclosed"
      /\ deliveredP.tag = "buried"
      /\ deliveredP.tx = DependedForm)

(* Outbox invariants: nothing reaches the world without a durable
   enqueue; release and compensation are mutually exclusive per
   anchoring; act-gated effects are released only for a delivered
   terminal phase whose evidence stands on the dominant chain. *)
PerformedEnqueued == performed \subseteq outbox

MaterializeOnce ==
    /\ ~({"releaseP", "compensateP"} \subseteq outbox)
    /\ ~({"releaseC", "compensateC"} \subseteq outbox)

GatedEffects ==
    /\ "releaseP" \in outbox =>
        /\ deliveredP.tag = "buried"
        /\ LocOnChain(deliveredP.h, deliveredP.b)
    /\ "releaseC" \in outbox =>
        /\ deliveredC.tag = "buried"
        /\ LocOnChain(deliveredC.h, deliveredC.b)
    /\ "compensateP" \in outbox => deliveredP.tag = "abandoned"
    /\ "compensateC" \in outbox => deliveredC.tag = "abandoned"

(* Action properties. *)
SensedTerminalAbsorbing ==
    [][\A a \in {"P", "C"} :
        IsTerminal(PhaseAnch(a)) => PhaseAnch(a)' = PhaseAnch(a)]_vars

DeliveredTerminalAbsorbing ==
    [][/\ IsTerminal(deliveredP) => deliveredP' = deliveredP
       /\ IsTerminal(deliveredC) => deliveredC' = deliveredC]_vars

ViewMonotone ==
    [][\A t \in DOMAIN cands :
        /\ t \in DOMAIN cands'
        /\ (cands[t].cert => cands'[t].cert)]_vars

(* A certified foreclosure is frozen outright: no restage,
   settlement, or event write touches it. *)
FcFrozenSticky == [][FcFrozen => fc' = fc]_vars

----------------------------------------------------------------------
(* Liveness. The notifier's liveness contract is
   modeled as truthful per-transaction refresh composites under
   weak fairness, exactly as in AnchoringWatcher.tla — see the
   discussion there; the async queue machinery remains adversarial
   and unfaired. Weak fairness on Restage is the adoption sweep
   re-running the pure staging function until it lands; weak
   fairness on delivery and dispatch is the retry discipline. WF
   over <A>_vars ignores vacuous firings, so each of these demands
   productive steps only. *)

RefreshTx(t) ==
    /\ LiveAnch(AnchorOf[t])
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
    /\ UNCHANGED <<chain, nextId, maxLen, fc, deliveredP,
                   deliveredC, outbox, performed, pending>>

CertifyTx(t) ==
    /\ LiveAnch(AnchorOf[t])
    /\ t \in OnChainTxs
    /\ Confs(t) >= Threshold
    /\ cands' =
        ((t :> [h |-> HeightOf(t), b |-> chain[HeightOf(t)].id,
                on |-> TRUE, cert |-> TRUE])
         @@ cands)
    /\ UNCHANGED <<chain, nextId, maxLen, fc, deliveredP,
                   deliveredC, outbox, performed, pending>>

CertifyFcTx(t) ==
    /\ LiveAnch("C")
    /\ ~FcFrozen
    /\ t \in ForeclosingTxs \cap OnChainTxs
    /\ Confs(t) >= Threshold
    /\ fc' = [staged |-> TRUE, tx |-> t, h |-> HeightOf(t),
              b |-> chain[HeightOf(t)].id, on |-> TRUE,
              cert |-> TRUE]
    /\ UNCHANGED <<chain, nextId, maxLen, cands, deliveredP,
                   deliveredC, outbox, performed, pending>>

LiveNext ==
    \/ Next
    \/ \E t \in Txs : RefreshTx(t) \/ CertifyTx(t)
    \/ \E t \in ForeclosingTxs : CertifyFcTx(t)

Fairness ==
    /\ \A t \in Txs :
        /\ WF_vars(RefreshTx(t))
        /\ WF_vars(CertifyTx(t))
    /\ \A t \in ForeclosingTxs : WF_vars(CertifyFcTx(t))
    /\ WF_vars(Restage)
    /\ WF_vars(DeliverP)
    /\ WF_vars(DeliverC)
    /\ \A e \in Effects : WF_vars(DispatchE(e))

LiveSpec == Init /\ [][LiveNext]_vars /\ Fairness

(* Both sites converge to their sensed phases. *)
CascadeConvergence ==
    <>[](deliveredP = PhaseOfP /\ deliveredC = PhaseOfC)

(* Every durably enqueued effect is eventually performed: the
   at-least-once half of the outbox contract (the at-most-once
   half being the sites' idempotency obligation). *)
EffectsDispatched ==
    \A e \in Effects : (e \in outbox) ~> (e \in performed)

======================================================================
