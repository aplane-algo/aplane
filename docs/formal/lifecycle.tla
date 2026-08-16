---------------------------- MODULE lifecycle ----------------------------
(*
Fourth machine-checkable model in the APlane formalization roadmap (M4).

This module models the lifecycle lock-ordering claims from
FORMAL_LIFECYCLE_MODEL.md: the race between a signer holding the
read side of the lifecycle lock via BeginOperation, and an admin
acquiring the write side via Decommission.

It covers three invariants:

  - L4 : Final signing uses the runtime lease.
  - L5 : Decommission waits for held lease.
  - L6 : Decommission wins the race before lease.

L4 and L6 are checked directly via history variables (heldEver,
badAcquireAfterDecommission). L5 is a direct state predicate.

Unlike sign_boundary, policy_precedence, and composition (all
one-shot Init-only specs), this module has real transitions in
Next. Two signer processes and one admin process race over a
writer-priority RWMutex. The state space is small, but the
temporal-transition structure is the key novelty.

The module intentionally omits:

  - The full 9-step Decommission sequence (persist, lock runtime,
    stop watcher, fail pending approvals). Only the steps that
    interact with the lock are modeled.
  - L1, L2, L3, L9-L11. Sequential properties already covered by
    Go tests; not concurrency claims.
  - L8 (Pending Approvals Fail On Successful Decommission).
    Deferred to a future approval-coordinator model; the claim
    crosses the lifecycle/approval boundary and needs a state
    machine for pending approvals to model meaningfully.
  - Liveness (Decommission *eventually* completes). Requires
    fairness assumptions; deferred.
  - Composition with sign_boundary, policy_precedence, composition.
    Those are one-shot specs; composing temporal with one-shot
    requires re-architecting the composition.

If those concerns become security-critical for a particular
check, add a separate module rather than extending this one.

See FORMAL_TLA_LIFECYCLE_MODEL.md for the prose companion.
*)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    SignerProcs,   \* set of signer process model values, e.g. {s1, s2}
    admin,         \* admin process model value
    NONE           \* sentinel for "no writer holds the lock"

ASSUME admin \notin SignerProcs
ASSUME NONE \notin SignerProcs /\ NONE # admin

----------------------------------------------------------------------------
(* State sets *)

SignerState == {"Idle", "Rejected", "Holding", "Done"}
AdminState  == {"Idle", "Waiting", "WriteHeld", "Marked", "Finished"}

----------------------------------------------------------------------------
(* Variables *)

VARIABLES
    readers,                       \* SUBSET of signer process IDs holding the read side
    writer,                        \* admin or NONE
    decommissioned,                \* BOOLEAN
    procState,                     \* function: SignerProcs \cup {admin} -> SignerState \cup AdminState
    heldEver,                      \* function: SignerProcs -> BOOLEAN; L4 history flag
    badAcquireAfterDecommission    \* BOOLEAN; L6 regression-guard flag

vars == <<readers, writer, decommissioned, procState,
          heldEver, badAcquireAfterDecommission>>

----------------------------------------------------------------------------
(* Writer-pending semantic *)

\* Go's sync.RWMutex is writer-priority: once Lock() is called and
\* readers exist, subsequent RLock() calls block until the writer
\* has acquired and released. The model encodes this by treating
\* admin in any pre-Finished state past Idle as a queued/holding
\* writer that blocks new readers.
WriterPending == procState[admin] \in {"Waiting", "WriteHeld", "Marked"}

----------------------------------------------------------------------------
(* Initial state *)

Init ==
    /\ readers = {}
    /\ writer = NONE
    /\ decommissioned = FALSE
    /\ procState = [p \in SignerProcs \cup {admin} |-> "Idle"]
    /\ heldEver = [s \in SignerProcs |-> FALSE]
    /\ badAcquireAfterDecommission = FALSE

----------------------------------------------------------------------------
(* Signer actions *)

\* SignerAcquire models BeginOperation. The signer takes the read
\* side of the lifecycle lock, unless the lock is unavailable (writer
\* holds it, or writer is queued by writer-priority semantics). If
\* decommissioned is already TRUE, the signer is rejected; otherwise
\* it transitions to Holding.
SignerAcquire(s) ==
    /\ s \in SignerProcs
    /\ procState[s] = "Idle"
    /\ writer = NONE
    /\ ~WriterPending
    /\ \/ /\ decommissioned                              \* L6 path
          /\ procState' = [procState EXCEPT ![s] = "Rejected"]
          /\ UNCHANGED <<readers, writer, decommissioned,                         heldEver, badAcquireAfterDecommission>>
       \/ /\ ~decommissioned                             \* normal path: take read side
          /\ readers' = readers \cup {s}
          /\ procState' = [procState EXCEPT ![s] = "Holding"]
          /\ heldEver' = [heldEver EXCEPT ![s] = TRUE]
          \* The disjunct below is tautologically FALSE here because of the
          \* ~decommissioned guard above. It is the load-bearing regression
          \* guard for L6: if the guard is ever weakened or removed, this
          \* assignment flips the flag and L6_NoAcquireAfterDecommission
          \* fires.
          /\ badAcquireAfterDecommission' =
                 badAcquireAfterDecommission \/ decommissioned
          /\ UNCHANGED <<writer, decommissioned>>

\* SignerCompleteAndRelease models the signer completing its
\* in-flight signing work and releasing the read side.
SignerCompleteAndRelease(s) ==
    /\ s \in SignerProcs
    /\ procState[s] = "Holding"
    /\ readers' = readers \ {s}
    /\ procState' = [procState EXCEPT ![s] = "Done"]
    /\ UNCHANGED <<writer, decommissioned,                   heldEver, badAcquireAfterDecommission>>

----------------------------------------------------------------------------
(* Admin actions *)

\* AdminBeginDecommission models calling lifecycleMu.Lock(). The admin
\* enters the Waiting state, which blocks new readers (via the
\* WriterPending guard in SignerAcquire) but does not yet acquire the
\* write side.
AdminBeginDecommission ==
    /\ procState[admin] = "Idle"
    /\ procState' = [procState EXCEPT ![admin] = "Waiting"]
    /\ UNCHANGED <<readers, writer, decommissioned,                   heldEver, badAcquireAfterDecommission>>

\* AdminAcquireWrite waits for all readers to drain before taking the
\* write side. This is the L5 guard: the admin cannot proceed past
\* Waiting while any signer holds the read side.
AdminAcquireWrite ==
    /\ procState[admin] = "Waiting"
    /\ readers = {}
    /\ writer = NONE
    /\ writer' = admin
    /\ procState' = [procState EXCEPT ![admin] = "WriteHeld"]
    /\ UNCHANGED <<readers, decommissioned,                   heldEver, badAcquireAfterDecommission>>

\* AdminMarkDecommissioned sets the decommissioned flag while holding
\* the write side. New signers arriving after this point will observe
\* decommissioned = TRUE and transition to Rejected.
AdminMarkDecommissioned ==
    /\ procState[admin] = "WriteHeld"
    /\ decommissioned' = TRUE
    /\ procState' = [procState EXCEPT ![admin] = "Marked"]
    /\ UNCHANGED <<readers, writer,                   heldEver, badAcquireAfterDecommission>>

\* AdminReleaseWrite releases the write side. After this point, the
\* admin is Finished and the lifecycle sequence is complete. New
\* signers may still attempt SignerAcquire, but they will find
\* decommissioned = TRUE and be rejected.
AdminReleaseWrite ==
    /\ procState[admin] = "Marked"
    /\ writer' = NONE
    /\ procState' = [procState EXCEPT ![admin] = "Finished"]
    /\ UNCHANGED <<readers, decommissioned,                   heldEver, badAcquireAfterDecommission>>

----------------------------------------------------------------------------
(* Next and Spec *)

Next ==
    \/ \E s \in SignerProcs : SignerAcquire(s)
    \/ \E s \in SignerProcs : SignerCompleteAndRelease(s)
    \/ AdminBeginDecommission
    \/ AdminAcquireWrite
    \/ AdminMarkDecommissioned
    \/ AdminReleaseWrite

Spec == Init /\ [][Next]_vars

\* Symmetry over the signer processes. Two signers are interchangeable
\* for the purposes of the safety invariants, so TLC can prune the
\* state space by treating any swap as the same state. Referenced
\* from the cfg via `SYMMETRY SignerSymmetry`.
SignerSymmetry == Permutations(SignerProcs)

----------------------------------------------------------------------------
(* Invariants *)

\* TypeOK pins each variable to its declared domain and adds two
\* consistency invariants tying the redundant lock state (readers,
\* writer) to the per-process state machine (procState). Drift
\* between the two would otherwise slip past higher-level checks.
TypeOK ==
    /\ readers \subseteq SignerProcs
    /\ writer \in {NONE, admin}
    /\ decommissioned \in BOOLEAN
    /\ \A s \in SignerProcs : procState[s] \in SignerState
    /\ procState[admin] \in AdminState
    /\ heldEver \in [SignerProcs -> BOOLEAN]
    /\ badAcquireAfterDecommission \in BOOLEAN
    \* RWMutex exclusion.
    /\ readers # {} => writer = NONE
    /\ writer # NONE => readers = {}
    \* Lock state and process state stay consistent.
    /\ readers = {s \in SignerProcs : procState[s] = "Holding"}
    /\ (writer = admin) <=> (procState[admin] \in {"WriteHeld", "Marked"})

\* L4: Final signing uses the runtime lease. A signer can reach Done
\* only after having held the lease. Checked via the heldEver flag.
L4_LeaseGatesSigning ==
    \A s \in SignerProcs :
        procState[s] = "Done" => heldEver[s]

\* L5: Decommission waits for held lease. While any signer holds the
\* read side, the admin cannot have acquired the write side.
L5_DecommissionWaitsForHeldLease ==
    \A s \in SignerProcs :
        procState[s] = "Holding" =>
            procState[admin] \notin {"WriteHeld", "Marked", "Finished"}

\* L6: Decommission wins the race before lease. No signer transitions
\* Idle->Holding while decommissioned is TRUE. The flag stays FALSE
\* under the current spec; flips if a future edit weakens the guard.
L6_NoAcquireAfterDecommission ==
    ~badAcquireAfterDecommission

Safety ==
    /\ TypeOK
    /\ L4_LeaseGatesSigning
    /\ L5_DecommissionWaitsForHeldLease
    /\ L6_NoAcquireAfterDecommission

----------------------------------------------------------------------------
(* Liveness (checked by lifecycle_liveness.cfg under LiveSpec) *)

\* The safety model's signers are one-shot (Idle -> Holding -> Done), which
\* makes writer starvation unfalsifiable: finite one-shot readers always
\* drain. The daemon's reality is recurring signing operations, so the
\* liveness world adds SignerRestart (Done -> Idle) — a signer may begin a
\* new operation after finishing one. Under writer-priority semantics
\* (~WriterPending in SignerAcquire), a waiting admin still drains the
\* readers: restarted signers cannot re-acquire past a queued writer. The
\* documented mutation removes ~WriterPending from SignerAcquire, and TLC
\* then reports a lasso where reader churn starves the admin forever — the
\* starvation Go's writer-priority RWMutex exists to prevent.
SignerRestart(s) ==
    /\ s \in SignerProcs
    /\ procState[s] = "Done"
    /\ procState' = [procState EXCEPT ![s] = "Idle"]
    /\ UNCHANGED <<readers, writer, decommissioned,                   heldEver, badAcquireAfterDecommission>>

LiveNext ==
    \/ Next
    \/ \E s \in SignerProcs : SignerRestart(s)

\* Fairness assumptions, matching what the code guarantees:
\*  - per-signer SignerCompleteAndRelease: in-flight signing work completes
\*    and releases the read side (per-signer, not existential — with
\*    recurring signers, one signer's completions must not excuse
\*    another's hang);
\*  - the admin decommission procedure runs to completion once started
\*    (AcquireWrite / Mark / ReleaseWrite).
\* No fairness on SignerAcquire, SignerRestart, or AdminBeginDecommission:
\* starting an operation or a decommission is a choice, not a guarantee.
Fairness ==
    /\ \A s \in SignerProcs : WF_vars(SignerCompleteAndRelease(s))
    /\ WF_vars(AdminAcquireWrite)
    /\ WF_vars(AdminMarkDecommissioned)
    /\ WF_vars(AdminReleaseWrite)

LiveSpec == Init /\ [][LiveNext]_vars /\ Fairness

\* Progress: a queued decommission eventually completes (writer-priority
\* starvation freedom), and every held lease is eventually released.
Progress ==
    /\ (procState[admin] = "Waiting") ~> (procState[admin] = "Finished")
    /\ \A s \in SignerProcs :
           (procState[s] = "Holding") ~> (procState[s] = "Done")

============================================================================
