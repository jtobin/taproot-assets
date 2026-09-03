----------------------------- MODULE MC2 -----------------------------
(* Model instances for the cascade spec. The parent has satisfying
   forms s1 (the form the child depends on) and s2 (its RBF/sweep
   replacement), plus a foreign partial spender f1. The child has
   one satisfying spender c1 of an s1 output.

   Instances: MC2_repl.cfg exercises the replacement-foreclosure
   path (s1, s2, c1: restage staging from a differing parent
   witness); MC2_foreign.cfg the foreign-abandonment path (s1, f1,
   c1: settlement staging from the parent's terminal delivery);
   MC2_full.cfg the union. *)

EXTENDS AnchoringCascade

MCTxsFull == {"s1", "s2", "f1", "c1"}
MCTxsRepl == {"s1", "s2", "c1"}
MCTxsForeign == {"s1", "f1", "c1"}

MCParentTriggers == {"o1", "o2"}
MCChildTriggers == {"p1"}

MCSpendsOf ==
    ("s1" :> {"o1", "o2"}) @@ ("s2" :> {"o1", "o2"}) @@
    ("f1" :> {"o1"}) @@ ("c1" :> {"p1"})

MCPredOK ==
    ("s1" :> TRUE) @@ ("s2" :> TRUE) @@ ("f1" :> TRUE) @@
    ("c1" :> TRUE)

MCAnchorOf ==
    ("s1" :> "P") @@ ("s2" :> "P") @@ ("f1" :> "P") @@
    ("c1" :> "C")

MCDependedForm == "s1"

----------------------------------------------------------------------
(* Reachability probes, each expected to be VIOLATED in its own
   run against MC2_full.cfg; one that passes marks a scenario the
   model cannot exhibit — a faithfulness bug. *)

NeverFcStaged == ~fc.staged

NeverFcCertified == ~FcFrozen

(* The downgrade path: staged foreclosing evidence flipped
   off-chain after the parent lost its witness. *)
NeverFcOffChain == ~(fc.staged /\ ~fc.on)

NeverChildForeclosed ==
    ~(PhaseOfC.tag = "abandoned" /\ PhaseOfC.cause = "foreclosed")

NeverChildBuried == PhaseOfC.tag # "buried"

NeverReleaseCPerformed == "releaseC" \notin performed

NeverCompensatePPerformed == "compensateP" \notin performed

======================================================================
