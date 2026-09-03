---------------------- MODULE AnchoringFleet ----------------------
(* Generalization of AnchoringCascade to a fleet: any number of
   anchorings, an arbitrary edge set (child, parent, depended
   form), per-outpoint transaction sources, and transactions that
   may touch several anchorings at once. Safety only. Used for the
   sweeper-integration instances (MC3.tla):

     - dual-child replacement cascade: parent realizable as s1 or
       s2, one child pinned to each form; the losing form's child
       forecloses while the winner's child stays viable, and one
       terminal settlement clears one edge while foreclosing the
       other;
     - duplicate registration: two anchorings over one trigger
       set, demonstrating cross-anchoring double materialization
       when the integration registers per attempt instead of per
       logical claim (a cautionary trace, not an invariant
       violation — exclusivity is per anchoring by design).

   Semantics per action mirror AnchoringCascade; see that module
   and README.md for the code correspondence. *)

EXTENDS Integers, Sequences, FiniteSets, TLC

CONSTANTS
    Anchorings,     \* anchoring identifiers
    Txs,            \* candidate spending transactions
    Outpoints,      \* all outpoints in play
    TriggersOf,     \* [Anchorings -> SUBSET Outpoints]
    SpendsOf,       \* [Txs -> SUBSET Outpoints]
    PredOK,         \* [Txs -> BOOLEAN]
    SourceOf,       \* [Outpoints -> Txs \cup {"genesis"}]: the tx
                    \* whose confirmation creates the outpoint
    Edges,          \* SUBSET [child, parent : Anchorings,
                    \*         form : Txs]
    Threshold, StabilityDepth,
    MaxLen, MaxBlocks, MaxPending,
    AlwaysConsume

NoTx == "none"

NoFc == [staged |-> FALSE, tx |-> NoTx, h |-> 1, b |-> 1,
         on |-> FALSE, cert |-> FALSE]

VARIABLES
    chain, nextId, maxLen,
    cands,      \* [Anchorings -> (partial tx -> [h, b, on, cert])]
    fc,         \* [Edges -> staged-foreclosure record]
    delivered,  \* [Anchorings -> phase]
    outbox,     \* durably enqueued effects [k, a]
    performed,  \* effects dispatched to the world
    pending     \* in-flight notification events

vars == <<chain, nextId, maxLen, cands, fc, delivered, outbox,
          performed, pending>>

----------------------------------------------------------------------
(* Chain helpers, as in the other modules. *)

Heights == 1..Len(chain)
TxAt(h) == chain[h].tx
OnChainTxs == {TxAt(h) : h \in Heights} \ {NoTx}
HeightOf(t) == CHOOSE h \in Heights : TxAt(h) = t
Confs(t) == Len(chain) - HeightOf(t) + 1
SpentOutpoints == UNION {SpendsOf[t] : t \in OnChainTxs}
LocOnChain(h, b) == h \in Heights /\ chain[h].id = b

Max(a, b) == IF a >= b THEN a ELSE b

(* A transaction touches every anchoring whose trigger set it
   intersects; it can satisfy an anchoring only by covering that
   anchoring's whole set (whatever else it spends alongside). *)
Touches(a, t) == SpendsOf[t] \cap TriggersOf[a] # {}
AnchsOf(t) == {a \in Anchorings : Touches(a, t)}
VerdictOf(a, t) ==
    IF TriggersOf[a] \subseteq SpendsOf[t] /\ PredOK[t]
    THEN "sat" ELSE "foreign"

FcCapable(e) == {t \in Txs : Touches(e.parent, t) /\ t # e.form}

----------------------------------------------------------------------
(* Phases and derivation, per anchoring. *)

Unwitnessed == [tag |-> "unwitnessed"]
Witnessed(t, h, b) ==
    [tag |-> "witnessed", tx |-> t, h |-> h, b |-> b]
Conflicted(S) == [tag |-> "conflicted", spends |-> S]
Buried(t, h, b) == [tag |-> "buried", tx |-> t, h |-> h, b |-> b]
AbandonedBy(t, h, b) ==
    [tag |-> "abandoned", cause |-> "foreign",
     tx |-> t, h |-> h, b |-> b]
(* Foreclosure abandonment retains the foreclosing edge's parent
   and depended form, as the Go Foreclosed cause records the
   parent: with several incoming edges this is what lets the
   delivered tier say WHICH premise died. *)
AbandonedFc(par, frm, t, h, b) ==
    [tag |-> "abandoned", cause |-> "foreclosed",
     parent |-> par, form |-> frm,
     tx |-> t, h |-> h, b |-> b]

IsTerminal(p) == p.tag \in {"buried", "abandoned"}

Frozen(e) == fc[e].staged /\ fc[e].cert

CertSat(a) == {t \in DOMAIN cands[a] :
    cands[a][t].cert /\ VerdictOf(a, t) = "sat"}
CertFor(a) == {t \in DOMAIN cands[a] :
    cands[a][t].cert /\ VerdictOf(a, t) = "foreign"}
LiveSat(a) == {t \in DOMAIN cands[a] :
    cands[a][t].on /\ VerdictOf(a, t) = "sat"}
LiveFor(a) == {t \in DOMAIN cands[a] :
    cands[a][t].on /\ VerdictOf(a, t) = "foreign"}
CertFcEdges(a) == {e \in Edges : e.child = a /\ Frozen(e)}

PhaseOfA(a) ==
    IF CertSat(a) # {} /\ CertFor(a) = {} THEN
        LET t == CHOOSE x \in CertSat(a) : TRUE
        IN Buried(t, cands[a][t].h, cands[a][t].b)
    ELSE IF CertFor(a) # {} /\ CertSat(a) = {} THEN
        LET t == CHOOSE x \in CertFor(a) : TRUE
        IN AbandonedBy(t, cands[a][t].h, cands[a][t].b)
    ELSE IF CertFcEdges(a) # {} THEN
        LET e == CHOOSE x \in CertFcEdges(a) : TRUE
        IN AbandonedFc(e.parent, e.form,
                       fc[e].tx, fc[e].h, fc[e].b)
    ELSE IF LiveSat(a) # {} /\ LiveFor(a) = {} THEN
        LET t == CHOOSE x \in LiveSat(a) : TRUE
        IN Witnessed(t, cands[a][t].h, cands[a][t].b)
    ELSE IF LiveFor(a) # {} THEN
        Conflicted(LiveFor(a))
    ELSE
        Unwitnessed

LiveA(a) == ~IsTerminal(PhaseOfA(a))

----------------------------------------------------------------------
(* Environment: chain evolution. A transaction is mineable only
   once every outpoint it spends exists on the dominant chain, so
   suffix truncation removes descendants with their sources. *)

MineableTxs ==
    {t \in Txs :
        /\ t \notin OnChainTxs
        /\ SpendsOf[t] \cap SpentOutpoints = {}
        /\ \A op \in SpendsOf[t] :
            \/ SourceOf[op] = "genesis"
            \/ SourceOf[op] \in OnChainTxs}

Extend ==
    /\ Len(chain) < MaxLen
    /\ nextId <= MaxBlocks
    /\ \E t \in MineableTxs \cup {NoTx} :
        chain' = Append(chain, [id |-> nextId, tx |-> t])
    /\ nextId' = nextId + 1
    /\ maxLen' = Max(maxLen, Len(chain) + 1)
    /\ UNCHANGED <<cands, fc, delivered, outbox, performed,
                   pending>>

Reorg ==
    \E d \in 1..Len(chain) :
        /\ Len(chain) - d >= maxLen - StabilityDepth
        /\ chain' = SubSeq(chain, 1, Len(chain) - d)
        /\ UNCHANGED <<nextId, maxLen, cands, fc, delivered,
                       outbox, performed, pending>>

----------------------------------------------------------------------
(* Notifier emissions, truthful at emission time. *)

CanEmit == Cardinality(pending) < MaxPending

EmitConf ==
    /\ CanEmit
    /\ \E t \in OnChainTxs :
        /\ \E a \in AnchsOf(t) : LiveA(a)
        /\ pending' = pending \cup
            {[k |-> "conf", tx |-> t, h |-> HeightOf(t),
              b |-> chain[HeightOf(t)].id]}
    /\ UNCHANGED <<chain, nextId, maxLen, cands, fc, delivered,
                   outbox, performed>>

EmitAct ==
    /\ CanEmit
    /\ \E t \in OnChainTxs :
        /\ \E a \in AnchsOf(t) : LiveA(a)
        /\ Confs(t) >= Threshold
        /\ pending' = pending \cup
            {[k |-> "act", tx |-> t, h |-> HeightOf(t),
              b |-> chain[HeightOf(t)].id]}
    /\ UNCHANGED <<chain, nextId, maxLen, cands, fc, delivered,
                   outbox, performed>>

EmitLoss ==
    /\ CanEmit
    /\ \E t \in Txs :
        /\ t \notin OnChainTxs
        /\ \E a \in AnchsOf(t) :
            LiveA(a) /\ t \in DOMAIN cands[a]
        /\ pending' = pending \cup {[k |-> "loss", tx |-> t]}
    /\ UNCHANGED <<chain, nextId, maxLen, cands, fc, delivered,
                   outbox, performed>>

(* Foreclosure certification per edge, at the child's threshold;
   over-approximated as in AnchoringCascade. *)
EmitFcAct ==
    /\ CanEmit
    /\ \E e \in Edges :
        /\ LiveA(e.child)
        /\ \E t \in FcCapable(e) \cap OnChainTxs :
            /\ Confs(t) >= Threshold
            /\ pending' = pending \cup
                {[k |-> "fcact", edge |-> e, tx |-> t,
                  h |-> HeightOf(t), b |-> chain[HeightOf(t)].id]}
    /\ UNCHANGED <<chain, nextId, maxLen, cands, fc, delivered,
                   outbox, performed>>

----------------------------------------------------------------------
(* Watcher: event processing. One notification fans out to each
   touching anchoring's registry independently, mirroring the
   per-anchoring subscriptions. *)

Dispose(e) ==
    IF AlwaysConsume
    THEN pending' = pending \ {e}
    ELSE pending' \in {pending, pending \ {e}}

ProcessConf ==
    \E ev \in pending, a \in Anchorings :
        /\ ev.k = "conf"
        /\ Touches(a, ev.tx)
        /\ LiveA(a)
        /\ IF LocOnChain(ev.h, ev.b)
           THEN cands' = [cands EXCEPT ![a] =
               ((ev.tx :> [h |-> ev.h, b |-> ev.b, on |-> TRUE,
                           cert |-> \/ (ev.tx \in DOMAIN cands[a]
                                        /\ cands[a][ev.tx].cert)
                                    \/ Threshold <= 1])
                @@ @)]
           ELSE cands' = cands
        /\ Dispose(ev)
        /\ UNCHANGED <<chain, nextId, maxLen, fc, delivered,
                       outbox, performed>>

ProcessAct ==
    \E ev \in pending, a \in Anchorings :
        /\ ev.k = "act"
        /\ Touches(a, ev.tx)
        /\ LiveA(a)
        /\ IF LocOnChain(ev.h, ev.b)
           THEN cands' = [cands EXCEPT ![a] =
               ((ev.tx :> [h |-> ev.h, b |-> ev.b, on |-> TRUE,
                           cert |-> TRUE])
                @@ @)]
           ELSE cands' = cands
        /\ Dispose(ev)
        /\ UNCHANGED <<chain, nextId, maxLen, fc, delivered,
                       outbox, performed>>

ProcessLoss ==
    \E ev \in pending, a \in Anchorings :
        /\ ev.k = "loss"
        /\ LiveA(a)
        /\ IF /\ ev.tx \in DOMAIN cands[a]
              /\ cands[a][ev.tx].on
              /\ ~LocOnChain(cands[a][ev.tx].h, cands[a][ev.tx].b)
           THEN cands' = [cands EXCEPT ![a][ev.tx].on = FALSE]
           ELSE cands' = cands
        /\ Dispose(ev)
        /\ UNCHANGED <<chain, nextId, maxLen, fc, delivered,
                       outbox, performed>>

ProcessFcAct ==
    \E ev \in pending :
        /\ ev.k = "fcact"
        /\ LiveA(ev.edge.child)
        /\ IF LocOnChain(ev.h, ev.b) /\ ~Frozen(ev.edge)
           THEN fc' = [fc EXCEPT ![ev.edge] =
               [staged |-> TRUE, tx |-> ev.tx, h |-> ev.h,
                b |-> ev.b, on |-> TRUE, cert |-> TRUE]]
           ELSE fc' = fc
        /\ Dispose(ev)
        /\ UNCHANGED <<chain, nextId, maxLen, cands, delivered,
                       outbox, performed>>

Drop ==
    /\ \E ev \in pending : pending' = pending \ {ev}
    /\ UNCHANGED <<chain, nextId, maxLen, cands, fc, delivered,
                   outbox, performed>>

Restart ==
    /\ pending # {}
    /\ pending' = {}
    /\ UNCHANGED <<chain, nextId, maxLen, cands, fc, delivered,
                   outbox, performed>>

----------------------------------------------------------------------
(* Restage per edge, as in AnchoringCascade: a pure function of
   the parent's current phase; certified edges frozen. *)

Restage ==
    \E e \in Edges :
        /\ ~Frozen(e)
        /\ LET pp == PhaseOfA(e.parent) IN
           IF pp.tag \in {"witnessed", "buried"}
           THEN IF pp.tx = e.form
                THEN fc' = [fc EXCEPT ![e] = NoFc]
                ELSE fc' = [fc EXCEPT ![e] =
                    [staged |-> TRUE, tx |-> pp.tx, h |-> pp.h,
                     b |-> pp.b, on |-> TRUE, cert |-> FALSE]]
           ELSE IF fc[e].staged /\ fc[e].on
           THEN fc' = [fc EXCEPT ![e].on = FALSE]
           ELSE fc' = fc
        /\ UNCHANGED <<chain, nextId, maxLen, cands, delivered,
                       outbox, performed, pending>>

----------------------------------------------------------------------
(* Delivery with terminal settlement over every dependent edge:
   abandonment forecloses each edge with the cause witness; burial
   clears edges pinned to the buried form and forecloses the rest;
   frozen edges untouched. Effects enqueue in the same step. *)

SettledFcMap(a, ph) ==
    [e \in Edges |->
        IF e.parent # a \/ Frozen(e)
        THEN fc[e]
        ELSE IF ph.tag = "buried" /\ ph.tx = e.form
        THEN NoFc
        ELSE [staged |-> TRUE, tx |-> ph.tx, h |-> ph.h,
              b |-> ph.b, on |-> TRUE, cert |-> FALSE]]

DeliverA(a) ==
    /\ delivered[a] # PhaseOfA(a)
    /\ delivered' = [delivered EXCEPT ![a] = PhaseOfA(a)]
    /\ LET ph == PhaseOfA(a) IN
       IF ph.tag = "buried"
       THEN /\ outbox' = outbox \cup {[k |-> "release", a |-> a]}
            /\ fc' = SettledFcMap(a, ph)
       ELSE IF ph.tag = "abandoned"
       THEN /\ outbox' = outbox \cup {[k |-> "compensate",
                                       a |-> a]}
            /\ fc' = SettledFcMap(a, ph)
       ELSE /\ outbox' = outbox
            /\ fc' = fc
    /\ UNCHANGED <<chain, nextId, maxLen, cands, performed,
                   pending>>

Deliver == \E a \in Anchorings : DeliverA(a)

Dispatch ==
    /\ \E ef \in outbox : performed' = performed \cup {ef}
    /\ UNCHANGED <<chain, nextId, maxLen, cands, fc, delivered,
                   outbox, pending>>

----------------------------------------------------------------------

Init ==
    /\ chain = <<>>
    /\ nextId = 1
    /\ maxLen = 0
    /\ cands = [a \in Anchorings |->
                   [t \in {} |-> [h |-> 0, b |-> 0, on |-> FALSE,
                                  cert |-> FALSE]]]
    /\ fc = [e \in Edges |-> NoFc]
    /\ delivered = [a \in Anchorings |-> Unwitnessed]
    /\ outbox = {}
    /\ performed = {}
    /\ pending = {}

Next ==
    \/ Extend \/ Reorg
    \/ EmitConf \/ EmitAct \/ EmitLoss \/ EmitFcAct
    \/ ProcessConf \/ ProcessAct \/ ProcessLoss \/ ProcessFcAct
    \/ Drop \/ Restart
    \/ Restage
    \/ Deliver \/ Dispatch

Spec == Init /\ [][Next]_vars

----------------------------------------------------------------------
(* Safety properties, generalized over the fleet. *)

Effects == [k : {"release", "compensate"}, a : Anchorings]

TypeOK ==
    /\ chain \in Seq([id : 1..MaxBlocks, tx : Txs \cup {NoTx}])
    /\ nextId \in 1..(MaxBlocks + 1)
    /\ maxLen \in 0..MaxLen
    /\ \A a \in Anchorings :
        /\ DOMAIN cands[a] \subseteq Txs
        /\ \A t \in DOMAIN cands[a] :
            cands[a][t] \in [h : 1..MaxLen, b : 1..MaxBlocks,
                             on : BOOLEAN, cert : BOOLEAN]
    /\ outbox \subseteq Effects
    /\ performed \subseteq Effects

CertifiedOnChain ==
    \A a \in Anchorings : \A t \in DOMAIN cands[a] :
        cands[a][t].cert =>
            LocOnChain(cands[a][t].h, cands[a][t].b)

NoFalseBurial ==
    \A a \in Anchorings :
        PhaseOfA(a).tag = "buried" =>
            /\ LocOnChain(PhaseOfA(a).h, PhaseOfA(a).b)
            /\ TxAt(PhaseOfA(a).h) = PhaseOfA(a).tx
            /\ VerdictOf(a, PhaseOfA(a).tx) = "sat"

NoFalseAbandonDirect ==
    \A a \in Anchorings :
        (PhaseOfA(a).tag = "abandoned"
         /\ PhaseOfA(a).cause = "foreign") =>
            /\ LocOnChain(PhaseOfA(a).h, PhaseOfA(a).b)
            /\ TxAt(PhaseOfA(a).h) = PhaseOfA(a).tx
            /\ VerdictOf(a, PhaseOfA(a).tx) = "foreign"

(* A certified foreclosure genuinely kills its premise: the
   foreclosing transaction stands on chain and the depended form
   does not. *)
CertifiedFcSound ==
    \A e \in Edges :
        Frozen(e) =>
            /\ LocOnChain(fc[e].h, fc[e].b)
            /\ TxAt(fc[e].h) = fc[e].tx
            /\ fc[e].tx # e.form
            /\ e.form \notin OnChainTxs

(* No edge is both foreclosed with finality and satisfied with
   finality: the winning form's child never carries a certified
   foreclosure. *)
NoCrossForeclosure ==
    \A e \in Edges :
        ~(/\ Frozen(e)
          /\ PhaseOfA(e.parent).tag = "buried"
          /\ PhaseOfA(e.parent).tx = e.form)

(* The delivered-tier statement, per edge: a child delivered as
   foreclosed through a specific edge never coexists with that
   edge's parent delivered buried in the depended form. *)
DeliveredCrossExclusive ==
    \A e \in Edges :
        ~(/\ delivered[e.child].tag = "abandoned"
          /\ delivered[e.child].cause = "foreclosed"
          /\ delivered[e.child].parent = e.parent
          /\ delivered[e.child].form = e.form
          /\ delivered[e.parent].tag = "buried"
          /\ delivered[e.parent].tx = e.form)

PerformedEnqueued == performed \subseteq outbox

MaterializeOnce ==
    \A a \in Anchorings :
        ~({[k |-> "release", a |-> a],
           [k |-> "compensate", a |-> a]} \subseteq outbox)

GatedEffects ==
    \A a \in Anchorings :
        /\ [k |-> "release", a |-> a] \in outbox =>
            /\ delivered[a].tag = "buried"
            /\ LocOnChain(delivered[a].h, delivered[a].b)
        /\ [k |-> "compensate", a |-> a] \in outbox =>
            delivered[a].tag = "abandoned"

SensedTerminalAbsorbing ==
    [][\A a \in Anchorings :
        IsTerminal(PhaseOfA(a)) => PhaseOfA(a)' = PhaseOfA(a)]_vars

DeliveredTerminalAbsorbing ==
    [][\A a \in Anchorings :
        IsTerminal(delivered[a]) =>
            delivered'[a] = delivered[a]]_vars

ViewMonotone ==
    [][\A a \in Anchorings : \A t \in DOMAIN cands[a] :
        /\ t \in DOMAIN cands'[a]
        /\ (cands[a][t].cert => cands'[a][t].cert)]_vars

FcFrozenSticky ==
    [][\A e \in Edges : Frozen(e) => fc'[e] = fc[e]]_vars

======================================================================
