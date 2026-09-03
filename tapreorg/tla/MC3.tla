----------------------------- MODULE MC3 -----------------------------
(* Fleet instances for the sweeper-integration questions.

   Dual-child (MC3_dualchild.cfg): parent P realizable as s1 or
   s2; child C1 pinned to s1 (spender c1 of an s1 output), child
   C2 pinned to s2 (spender c2 of an s2 output). Exercises the
   mixed terminal settlement — one edge cleared, the other
   foreclosed, in one delivery — and the viability claim: the
   winning form's child buries while the losing form's child
   forecloses.

   Duplicate registration (MC3_dupreg.cfg): anchorings A1 and A2
   over the SAME trigger set, as would result from registering per
   transaction attempt rather than per logical claim. All
   per-anchoring invariants still hold — and that is the point:
   the NeverDoubleRelease probe shows both anchorings release
   act-gated effects for one chain outcome. Exclusivity is per
   anchoring; registration granularity is the integration's
   obligation. *)

EXTENDS AnchoringFleet

----------------------------------------------------------------------
(* Dual-child instance. *)

DCAnchorings == {"P", "C1", "C2"}
DCTxs == {"s1", "s2", "c1", "c2"}
DCOutpoints == {"o1", "o2", "p1", "q1"}
DCTriggersOf ==
    ("P" :> {"o1", "o2"}) @@ ("C1" :> {"p1"}) @@ ("C2" :> {"q1"})
DCSpendsOf ==
    ("s1" :> {"o1", "o2"}) @@ ("s2" :> {"o1", "o2"}) @@
    ("c1" :> {"p1"}) @@ ("c2" :> {"q1"})
DCPredOK ==
    ("s1" :> TRUE) @@ ("s2" :> TRUE) @@ ("c1" :> TRUE) @@
    ("c2" :> TRUE)
DCSourceOf ==
    ("o1" :> "genesis") @@ ("o2" :> "genesis") @@
    ("p1" :> "s1") @@ ("q1" :> "s2")
DCEdges ==
    {[child |-> "C1", parent |-> "P", form |-> "s1"],
     [child |-> "C2", parent |-> "P", form |-> "s2"]}

DCEdge1 == [child |-> "C1", parent |-> "P", form |-> "s1"]
DCEdge2 == [child |-> "C2", parent |-> "P", form |-> "s2"]

(* Reachability probe, EXPECTED VIOLATED on the dual-child
   instance: the winning form's child buried while the losing
   form's child is abandoned by foreclosure — both outcomes final,
   simultaneously. This probe pins outcome coexistence only; its
   shortest witness reaches C1's foreclosure through the
   over-approximated certification event without ever delivering
   the parent, so it says nothing about the settlement path. *)
NeverMixedOutcome ==
    ~(/\ PhaseOfA("C2").tag = "buried"
      /\ PhaseOfA("C1").tag = "abandoned"
      /\ PhaseOfA("C1").cause = "foreclosed")

(* Action-level probe, EXPECTED VIOLATED: the mixed terminal
   settlement itself, with BOTH arms performing observable work in
   one parent-delivery transition. Pre-state: the losing C1 edge
   unstaged, and the winning C2 edge carrying stale uncertified
   staging on s1 (left by an earlier restage while the parent was
   witnessed in s1). Post-state: the losing edge staged on s2 and
   the stale staging cleared — so a broken staging arm and a
   broken clearing arm each make the witness unreachable.
   Requiring s1 to have been observed keeps the C1 edge's
   existence honest with respect to registry edge derivation. *)
NeverMixedSettlement ==
    [][~(
        /\ delivered["P"] # delivered'["P"]
        /\ delivered'["P"].tag = "buried"
        /\ delivered'["P"].tx = "s2"
        /\ "s1" \in DOMAIN cands["P"]
        /\ "s2" \in DOMAIN cands["P"]
        /\ ~fc[DCEdge1].staged
        /\ fc[DCEdge2].staged
        /\ fc[DCEdge2].tx = "s1"
        /\ fc'[DCEdge1].staged
        /\ fc'[DCEdge1].tx = "s2"
        /\ ~fc'[DCEdge2].staged
      )]_vars

----------------------------------------------------------------------
(* Duplicate-registration instance. *)

DRAnchorings == {"A1", "A2"}
DRTxs == {"s1"}
DROutpoints == {"o1", "o2"}
DRTriggersOf ==
    ("A1" :> {"o1", "o2"}) @@ ("A2" :> {"o1", "o2"})
DRSpendsOf == ("s1" :> {"o1", "o2"})
DRPredOK == ("s1" :> TRUE)
DRSourceOf == ("o1" :> "genesis") @@ ("o2" :> "genesis")
DREdges == {}

(* Cautionary probe, EXPECTED VIOLATED on the duplicate
   instance: one chain outcome releases act-gated effects twice,
   once per registered anchoring. *)
NeverDoubleRelease ==
    ~({[k |-> "release", a |-> "A1"],
       [k |-> "release", a |-> "A2"]} \subseteq outbox)

======================================================================
