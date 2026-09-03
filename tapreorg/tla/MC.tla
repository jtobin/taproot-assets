----------------------------- MODULE MC -----------------------------
(* Model instance: two satisfying forms of the anchoring event (s1
   and its RBF/sweep replacement s2, both spending the whole trigger
   set) and one foreign spender (f1, spending a strict subset —
   foreign by construction under the whole-set rule). *)

EXTENDS AnchoringWatcher

MCTxs == {"s1", "s2", "f1"}

(* Split-sweep instance (MC_split.cfg): the registered whole-set
   claim s1 against a rebatched realization — two partial
   spenders f1 and f2 that together consume the trigger set in
   separate transactions. Foreign by construction under the
   whole-set rule, so a sweep that "succeeded" in pieces
   forecloses the registered claim: the watcher is internally
   correct, and the registration granularity is the integration's
   obligation ("outpoints realizable separately belong to
   separate anchorings"). *)
MCTxsSplit == {"s1", "f1", "f2"}

MCTriggers == {"o1", "o2"}

MCSpendsOf ==
    ("s1" :> {"o1", "o2"}) @@
    ("s2" :> {"o1", "o2"}) @@
    ("f1" :> {"o1"}) @@
    ("f2" :> {"o2"})

MCPredOK ==
    ("s1" :> TRUE) @@ ("s2" :> TRUE) @@ ("f1" :> TRUE) @@
    ("f2" :> TRUE)

----------------------------------------------------------------------
(* Reachability probes: each is expected to be VIOLATED in its own
   TLC run, proving the corresponding scenario is reachable in the
   model (i.e. the model has teeth). A probe that passes means the
   model cannot exhibit the scenario at all — a faithfulness bug. *)

NeverBuried == PhaseOf.tag # "buried"

NeverAbandoned == PhaseOf.tag # "abandoned"

NeverConflicted == PhaseOf.tag # "conflicted"

(* A stale on-chain flag (recorded on-chain, actually reorged out,
   loss unprocessed) must be reachable: it is the tear the design
   defends against. *)
NeverStaleOnFlag ==
    \A t \in DOMAIN cands :
        cands[t].on => LocOnChain(cands[t].h, cands[t].b)

NeverDeliveredTerminal == ~IsTerminal(delivered)

(* The witnessed -> unwitnessed downgrade (witness reorged out with
   no successor) must be reachable. *)
NeverRegression ==
    [][~(PhaseOf.tag = "witnessed"
         /\ PhaseOf'.tag = "unwitnessed")]_vars

(* Split-sweep probes, on MCTxsSplit, both EXPECTED VIOLATED:
   two simultaneous partial foreign spends on one chain, and the
   split-realization abandonment of the whole-set claim (direct
   foreign burial — the dependency-edge foreclosure mechanism is
   not involved). *)
NeverTwoForeign == Cardinality(LiveFor) < 2

NeverSplitAbandonment ==
    ~(/\ PhaseOf.tag = "abandoned"
      /\ {"f1", "f2"} \subseteq DOMAIN cands)

======================================================================
