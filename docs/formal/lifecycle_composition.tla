--------------------- MODULE lifecycle_composition ---------------------
(*
Seventh machine-checkable model in the APlane formalization roadmap (M4).
Joins the temporal lifecycle lock model (lifecycle.tla) with the
signing-output layer to machine-check the end-to-end claim that a signer
produces signing output only while holding a lifecycle lease it acquired
before decommission -- "lifecycle unavailability implies no new signer
output."

lifecycle.tla proved the lock-ordering race (L4-L7) but stopped at the
lease; it did not model what the signer does with it. composition.tla and
approval_composition.tla proved the policy/approval -> output pipeline but
treated the runtime as always available. This module composes the two: it
keeps lifecycle.tla's temporal RWMutex race and adds a per-signer Sign step,
gated on holding the lease, that produces output only when the policy
decision is to sign.

The reconciliation the roadmap flagged (temporal vs one-shot): this is a
temporal-transition spec (real Next, like lifecycle.tla). The policy/approval
pipeline is *not* re-modeled here; its decision is consumed as the per-signer
boolean `policySigned`, whose derivation is machine-checked in composition.tla
and approval_composition.tla. This mirrors how approval_composition.tla
consumes the coordinator's terminal outcome: each layer's internals are
checked in its own module, and the composition checks only the new seam --
here, the lease gate on signing output.

New seam invariants:
  - LifecycleGatesOutput : a signer produces output only if it held a lease
    (acquired while not decommissioned) and the policy decision was to sign.
  - RejectedProducesNoOutput : a signer rejected at acquire (it arrived after
    the decommission mark) produces no output. With L6 this is the end-to-end
    "lifecycle unavailability implies no new signer output."

It also re-checks the carried lifecycle invariants L4-L7 under the extended
model. As with the other composed modules, copy drift for operators copied from
lifecycle.tla is checked by scripts/check-formal-copied-operators.py (`make
formal-copy-sync-check`, also run by `make formal-test`).

See FORMAL_TLA_LIFECYCLE_MODEL.md for the lock model and
FORMAL_TLA_COMPOSITION_MODEL.md for the policy -> output pipeline.
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

\* Signer states extend lifecycle.tla's with a Signed step: a holding signer
\* signs (while still holding the lease) before releasing.
SignerState == {"Idle", "Rejected", "Holding", "Signed", "Done"}
AdminState  == {"Idle", "Waiting", "WriteHeld", "Marked", "Finished"}
SignOut     == {"empty", "signed"}

----------------------------------------------------------------------------
(* Variables *)

VARIABLES
    readers,                       \* SUBSET of signer IDs holding the read side
    writer,                        \* admin or NONE
    decommissioned,                \* BOOLEAN
    registry_member,               \* BOOLEAN
    procState,                     \* SignerProcs \cup {admin} -> states
    heldEver,                      \* SignerProcs -> BOOLEAN: held a lease
    badAcquireAfterDecommission,   \* BOOLEAN: L6 regression guard
    policySigned,                  \* SignerProcs -> BOOLEAN: policy decision (input)
    signerOutput                   \* SignerProcs -> SignOut

vars == <<readers, writer, decommissioned, registry_member, procState,
          heldEver, badAcquireAfterDecommission, policySigned, signerOutput>>

WriterPending == procState[admin] \in {"Waiting", "WriteHeld", "Marked"}

----------------------------------------------------------------------------
(* Initial state *)

\* policySigned is a free per-signer input -- the policy/approval decision for
\* that signer's request, whose derivation is checked in composition.tla and
\* approval_composition.tla.
Init ==
    /\ readers = {}
    /\ writer = NONE
    /\ decommissioned = FALSE
    /\ registry_member = TRUE
    /\ procState = [p \in SignerProcs \cup {admin} |-> "Idle"]
    /\ heldEver = [s \in SignerProcs |-> FALSE]
    /\ badAcquireAfterDecommission = FALSE
    /\ policySigned \in [SignerProcs -> BOOLEAN]
    /\ signerOutput = [s \in SignerProcs |-> "empty"]

----------------------------------------------------------------------------
(* Signer actions *)

\* SignerAcquire models BeginOperation: take the read lease unless the writer
\* holds or is queued. A decommissioned runtime rejects the signer (no lease);
\* otherwise it transitions to Holding. (Identical lock semantics to
\* lifecycle.tla; carries the new policySigned/signerOutput unchanged.)
SignerAcquire(s) ==
    /\ s \in SignerProcs
    /\ procState[s] = "Idle"
    /\ writer = NONE
    /\ ~WriterPending
    /\ \/ /\ decommissioned
          /\ procState' = [procState EXCEPT ![s] = "Rejected"]
          /\ UNCHANGED <<readers, writer, decommissioned, registry_member,
                         heldEver, badAcquireAfterDecommission, policySigned,
                         signerOutput>>
       \/ /\ ~decommissioned
          /\ readers' = readers \cup {s}
          /\ procState' = [procState EXCEPT ![s] = "Holding"]
          /\ heldEver' = [heldEver EXCEPT ![s] = TRUE]
          /\ badAcquireAfterDecommission' =
                 badAcquireAfterDecommission \/ decommissioned
          /\ UNCHANGED <<writer, decommissioned, registry_member,
                         policySigned, signerOutput>>

\* SignerSign models final signing while the lease is held. Output is produced
\* from the policy decision: a signing decision yields "signed", a rejecting
\* one yields "empty". The lease is still held; SignerRelease releases it.
SignerSign(s) ==
    /\ s \in SignerProcs
    /\ procState[s] = "Holding"
    /\ procState' = [procState EXCEPT ![s] = "Signed"]
    /\ signerOutput' = [signerOutput EXCEPT ![s] =
                            IF policySigned[s] THEN "signed" ELSE "empty"]
    /\ UNCHANGED <<readers, writer, decommissioned, registry_member,
                   heldEver, badAcquireAfterDecommission, policySigned>>

\* SignerRelease releases the read lease after signing completes.
SignerRelease(s) ==
    /\ s \in SignerProcs
    /\ procState[s] = "Signed"
    /\ readers' = readers \ {s}
    /\ procState' = [procState EXCEPT ![s] = "Done"]
    /\ UNCHANGED <<writer, decommissioned, registry_member, heldEver,
                   badAcquireAfterDecommission, policySigned, signerOutput>>

----------------------------------------------------------------------------
(* Admin actions -- lock semantics identical to lifecycle.tla *)

AdminBeginDecommission ==
    /\ procState[admin] = "Idle"
    /\ procState' = [procState EXCEPT ![admin] = "Waiting"]
    /\ UNCHANGED <<readers, writer, decommissioned, registry_member, heldEver,
                   badAcquireAfterDecommission, policySigned, signerOutput>>

AdminAcquireWrite ==
    /\ procState[admin] = "Waiting"
    /\ readers = {}
    /\ writer = NONE
    /\ writer' = admin
    /\ procState' = [procState EXCEPT ![admin] = "WriteHeld"]
    /\ UNCHANGED <<readers, decommissioned, registry_member, heldEver,
                   badAcquireAfterDecommission, policySigned, signerOutput>>

AdminMarkDecommissioned ==
    /\ procState[admin] = "WriteHeld"
    /\ decommissioned' = TRUE
    /\ procState' = [procState EXCEPT ![admin] = "Marked"]
    /\ UNCHANGED <<readers, writer, registry_member, heldEver,
                   badAcquireAfterDecommission, policySigned, signerOutput>>

AdminReleaseWrite ==
    /\ procState[admin] = "Marked"
    /\ writer' = NONE
    /\ procState' = [procState EXCEPT ![admin] = "Finished"]
    /\ UNCHANGED <<readers, decommissioned, registry_member, heldEver,
                   badAcquireAfterDecommission, policySigned, signerOutput>>

AdminRegistryRemove ==
    /\ registry_member
    /\ registry_member' = FALSE
    /\ UNCHANGED <<readers, writer, decommissioned, procState, heldEver,
                   badAcquireAfterDecommission, policySigned, signerOutput>>

----------------------------------------------------------------------------
(* Next and Spec *)

Next ==
    \/ \E s \in SignerProcs : SignerAcquire(s)
    \/ \E s \in SignerProcs : SignerSign(s)
    \/ \E s \in SignerProcs : SignerRelease(s)
    \/ AdminBeginDecommission
    \/ AdminAcquireWrite
    \/ AdminMarkDecommissioned
    \/ AdminReleaseWrite
    \/ AdminRegistryRemove

Spec == Init /\ [][Next]_vars

SignerSymmetry == Permutations(SignerProcs)

----------------------------------------------------------------------------
(* Invariants *)

TypeOK ==
    /\ readers \subseteq SignerProcs
    /\ writer \in {NONE, admin}
    /\ decommissioned \in BOOLEAN
    /\ registry_member \in BOOLEAN
    /\ \A s \in SignerProcs : procState[s] \in SignerState
    /\ procState[admin] \in AdminState
    /\ heldEver \in [SignerProcs -> BOOLEAN]
    /\ badAcquireAfterDecommission \in BOOLEAN
    /\ policySigned \in [SignerProcs -> BOOLEAN]
    /\ signerOutput \in [SignerProcs -> SignOut]
    \* RWMutex exclusion.
    /\ readers # {} => writer = NONE
    /\ writer # NONE => readers = {}
    \* readers are exactly the signers currently holding the lease.
    /\ readers = {s \in SignerProcs : procState[s] \in {"Holding", "Signed"}}
    /\ (writer = admin) <=> (procState[admin] \in {"WriteHeld", "Marked"})

\* L4: a signer reaches a signing/terminal state only after holding a lease.
L4_LeaseGatesSigning ==
    \A s \in SignerProcs :
        procState[s] \in {"Signed", "Done"} => heldEver[s]

\* L5: while any signer holds the lease, the admin has not taken the write side.
L5_DecommissionWaitsForHeldLease ==
    \A s \in SignerProcs :
        procState[s] \in {"Holding", "Signed"} =>
            procState[admin] \notin {"WriteHeld", "Marked", "Finished"}

\* L6: no signer acquires the lease after the runtime is decommissioned.
L6_NoAcquireAfterDecommission ==
    ~badAcquireAfterDecommission

\* L7: a holding signer can always make progress (sign, then release),
\* regardless of registry membership or a decommission in progress.
L7_RegistryRemoveDoesNotPreventCompletion ==
    \A s \in SignerProcs :
        procState[s] = "Holding" => ENABLED SignerSign(s)

\* Seam: signing output exists only for a signer that held a lease and whose
\* policy decision was to sign. Composes the lifecycle lease gate with the
\* policy gate (the latter machine-checked in composition.tla).
LifecycleGatesOutput ==
    \A s \in SignerProcs :
        signerOutput[s] = "signed" => (heldEver[s] /\ policySigned[s])

\* Seam (headline): a signer rejected at acquire -- it arrived after the
\* decommission mark -- produces no output. With L6, this is the end-to-end
\* "lifecycle unavailability implies no new signer output."
RejectedProducesNoOutput ==
    \A s \in SignerProcs :
        procState[s] = "Rejected" => signerOutput[s] = "empty"

Safety ==
    /\ TypeOK
    /\ L4_LeaseGatesSigning
    /\ L5_DecommissionWaitsForHeldLease
    /\ L6_NoAcquireAfterDecommission
    /\ L7_RegistryRemoveDoesNotPreventCompletion
    /\ LifecycleGatesOutput
    /\ RejectedProducesNoOutput

----------------------------------------------------------------------------
(* Liveness (checked by lifecycle_composition_liveness.cfg under LiveSpec) *)

\* Fairness matches the code's guarantees: a signer that acquired the lease
\* signs and releases (per-signer -- one signer's progress must not excuse
\* another's hang), and the admin decommission procedure runs to completion
\* once started. No fairness on SignerAcquire or AdminBeginDecommission
\* (starting is a choice). The writer-starvation dimension is exercised in
\* lifecycle_liveness.cfg (via SignerRestart); this module's Progress is the
\* pipeline claim: no accepted request is left forever neither signed nor
\* rejected, and a queued decommission completes.
Fairness ==
    /\ \A s \in SignerProcs : WF_vars(SignerSign(s))
    /\ \A s \in SignerProcs : WF_vars(SignerRelease(s))
    /\ WF_vars(AdminAcquireWrite)
    /\ WF_vars(AdminMarkDecommissioned)
    /\ WF_vars(AdminReleaseWrite)

LiveSpec == Spec /\ Fairness

\* Progress: every held lease eventually completes (its output -- signed or
\* empty per the policy decision -- was recorded at the Sign step), and a
\* queued decommission eventually finishes.
Progress ==
    /\ (procState[admin] = "Waiting") ~> (procState[admin] = "Finished")
    /\ \A s \in SignerProcs :
           (procState[s] = "Holding") ~> (procState[s] = "Done")

============================================================================
