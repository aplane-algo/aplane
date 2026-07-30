------------------------ MODULE rotation_transition ------------------------
(*
Thirteenth machine-checkable model in the APlane formalization roadmap (M4).

This module models the key-term rotation transition proposed in
docs/PROPOSAL_KEYTERM_ROTATION.md: appending a term, rewrapping the mutable
live store under it, and closing the window — interleaved with crashes,
with resume at unlock, with an attacker who can write files directly, and
with the post-activation rollback divergence guard that rotation interacts
with.

It exists because three consecutive design-review rounds each found a defect
that no single-mechanism test would catch, and all three are cross-mechanism:

  - promotion of the current term at the wrong step, leaving the rewrap with
    no valid write authority;
  - clearing the rewrap window before recording the divergence baseline,
    which leaves rollback permanently refused;
  - an attacker injecting material under a retiring term during the window
    and having the rewrap launder it into the new term.

Each is expressible here, and each is a checked invariant below. The
generation_commit module covers the storage commit; this covers the
cryptographic transition layered over it.

It covers five effective invariants:

  - R1 : the store's own data is never stranded on an unreadable term.
  - R2 : only objects pinned by the cutover snapshot ever reach the new
         term (no laundering).
  - R3 : a rotation that closes its window leaves rollback available for a
         generation that was clean at cutover.
  - R4 : divergence is never erased — a generation diverged before the
         cutover never becomes clean.
  - R5 : resume never appends a second term. The state space includes T3 and
         a durable resident-term set, so the invariant is not implied by
         TypeOK. The negative-control config makes the violating second append
         reachable and requires TLC to fail R5.

Three negative controls are documented at their guards: removing the
`snapshot` membership test from Rewrap violates R2, allowing CloseWindow
before BaselineWritten violates R3, and
rotation_transition_negative.cfg runs ResumeAppendWithoutPendingGuard and
requires an R5 violation. All three reproduce the review findings
mechanically; the R5 control runs in the standard formal harness.

The implementation supplies the model's term-authority, pinned-input, and
completion boundaries: ordinary reads use the settled/pending authority set,
historical reads require exact root anchors, resume promotes only a
snapshot-pinned retiring-term buffer, and completion requires fresh final
path-set/output-authority equality plus, for a clean rollback-eligible
cutover, a clean baseline before atomically clearing the pending descriptor.
The identity mutation lock excludes
cooperating writers, but not the direct-filesystem attacker modelled here.
The implementation scans both before and after baseline publication so an
edit after an entry is pinned fails its exact digest or final comparison; one
before the entry is read is on the pre-cutover side of the stated claim.

The module intentionally omits:

  - The KEK, the passphrase, and the keyring's wrapping. Rotation's
    correctness here is about term authority and ordering, not about the
    unwrap, which is a single atomic file write (see the proposal's
    single-root section).
  - Historical anchors and OpenSealed byte-binding. Those defend sealed
    priors against a retired-term forger; this model covers the mutable
    live store during a transition. A separate module should cover them.
  - Root replay. The proposal scopes it out explicitly: an attacker who
    replaces keyring.enc has substituted the store, which no in-store
    mechanism detects, so there is nothing here to check.
  - Multiple generations and the storage flip, which generation_commit.tla
    already models.
  - Term GC, deferred out of the first implementation.

See docs/PROPOSAL_KEYTERM_ROTATION.md for the prose companion.
*)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    T1,      \* the term in use before the rotation
    T2,      \* the term appended by the rotation
    T3,      \* a forbidden second append, reachable in the R5 negative control
    Legit,   \* objects the store legitimately holds at cutover
    Evil,    \* an object an attacker writes directly, bypassing the daemon
    ABSENT   \* an object not present in the store

ASSUME T1 # T2
ASSUME T1 # T3
ASSUME T2 # T3
ASSUME Evil \notin Legit
ASSUME ABSENT \notin {T1, T2, T3}

Objects == Legit \cup {Evil}
Terms == {T1, T2, T3}

----------------------------------------------------------------------------
(* Variables *)

VARIABLES
    running,          \* process is up; FALSE between Crash and Resume
    currentTerm,      \* the term new and current-generation writes use
    residentTerms,    \* terms durably present in the sealed keyring root
    retiring,         \* terms still authorized for reads while the window is open
    pending,          \* the rewrap window is open
    snapshot,         \* objects the cutover pinned as rewrap inputs
    cleanAtCutover,   \* the divergence decision recorded at cutover
    objTerm,          \* object -> the term its ciphertext is under, or ABSENT
    baseline,         \* a post-rewrap divergence baseline has been recorded
    diverged          \* the generation has semantic divergence (a later key)

vars == <<running, currentTerm, residentTerms, retiring, pending, snapshot,
          cleanAtCutover, objTerm, baseline, diverged>>

TypeOK ==
    /\ running \in BOOLEAN
    /\ currentTerm \in Terms
    /\ residentTerms \subseteq Terms
    /\ currentTerm \in residentTerms
    /\ retiring \subseteq residentTerms
    /\ pending \in BOOLEAN
    /\ snapshot \subseteq Objects
    /\ cleanAtCutover \in BOOLEAN
    /\ objTerm \in [Objects -> Terms \cup {ABSENT}]
    /\ baseline \in BOOLEAN
    /\ diverged \in BOOLEAN

----------------------------------------------------------------------------
(* Authority: which terms may be used for what, per the proposal's table. *)

\* Writes always use the current term. Reads additionally accept retiring
\* terms, but only while the window is open — that is what makes the rewrap
\* interruptible, and it is also what the laundering attack exploits.
ReadAuthorized(t) == t = currentTerm \/ (pending /\ t \in retiring)

----------------------------------------------------------------------------
(* Initial state: a settled store, everything on T1, no rotation. *)

Init ==
    /\ running = TRUE
    /\ currentTerm = T1
    /\ residentTerms = {T1}
    /\ retiring = {}
    /\ pending = FALSE
    /\ snapshot = {}
    /\ cleanAtCutover = TRUE
    /\ objTerm = [o \in Objects |-> IF o \in Legit THEN T1 ELSE ABSENT]
    /\ baseline = FALSE
    /\ diverged = FALSE

----------------------------------------------------------------------------
(* Ordinary operation *)

\* An operator generates a key after an activation: real semantic
\* divergence, which the rollback guard exists to protect.
OperatorMutation ==
    /\ running
    /\ ~pending
    /\ ~diverged
    /\ diverged' = TRUE
    /\ UNCHANGED <<running, currentTerm, residentTerms, retiring, pending,
                   snapshot, cleanAtCutover, objTerm, baseline>>

----------------------------------------------------------------------------
(* The rotation transition *)

\* The shared root mutation. The positive transition and the R5 negative
\* control use the same append semantics; only the positive transition carries
\* the ~pending guard. This keeps the mutation control tied mechanically to
\* the operation whose guard it tests.
AppendTerm(from, to) ==
    /\ currentTerm = from
    /\ currentTerm' = to
    /\ residentTerms' = residentTerms \cup {to}
    /\ retiring' = {from}
    /\ pending' = TRUE
    /\ snapshot' = {o \in Objects : objTerm[o] # ABSENT}
    /\ cleanAtCutover' = ~diverged
    /\ baseline' = FALSE
    /\ UNCHANGED <<objTerm, diverged>>

\* Step 1: one atomic root write. The new term is promoted here, not at the
\* end: steps 3-4 must have a valid write authority, and writing the old
\* current term would make the rewrap a no-op. The cutover snapshot pins
\* exactly the objects the rewrap may consume, and records the
\* clean-or-diverged decision while it is still knowable.
StartRotation ==
    /\ running
    /\ ~pending
    /\ AppendTerm(T1, T2)
    /\ UNCHANGED running

\* Steps 3-4: rewrap one pinned object onto the current term.
\*
\* NEGATIVE CONTROL: dropping the `o \in snapshot` conjunct is exactly the
\* laundering attack. TLC then finds a trace where Evil is injected under
\* the retiring term and promoted to the new term, violating R2.
Rewrap(o) ==
    /\ running
    /\ pending
    /\ o \in snapshot
    /\ objTerm[o] \in retiring
    /\ objTerm' = [objTerm EXCEPT ![o] = currentTerm]
    /\ UNCHANGED <<running, currentTerm, residentTerms, retiring, pending,
                   snapshot, cleanAtCutover, baseline, diverged>>

\* Step 5a: record the post-rewrap divergence baseline. Only for a
\* generation that was clean at cutover — a diverged generation must never
\* be made clean again (R4).
WriteBaseline ==
    /\ running
    /\ pending
    /\ ~baseline
    /\ \A o \in snapshot : objTerm[o] = currentTerm
    /\ baseline' = cleanAtCutover
    /\ UNCHANGED <<running, currentTerm, residentTerms, retiring, pending,
                   snapshot, cleanAtCutover, objTerm, diverged>>

\* Step 5b: close the window.
\*
\* NEGATIVE CONTROL: dropping the `baseline \/ ~cleanAtCutover` conjunct
\* permits closing before the baseline is durable. TLC then finds a trace
\* where a clean generation ends rotated with no baseline, and R3 fails —
\* the store whose every later rollback is refused forever.
CloseWindow ==
    /\ running
    /\ pending
    /\ \A o \in snapshot : objTerm[o] = currentTerm
    /\ (baseline \/ ~cleanAtCutover)
    /\ pending' = FALSE
    /\ retiring' = {}
    /\ UNCHANGED <<running, currentTerm, residentTerms, snapshot,
                   cleanAtCutover, objTerm, baseline, diverged>>

----------------------------------------------------------------------------
(* The attacker *)

\* An attacker with the retired term key and filesystem write access,
\* bypassing the daemon's mutation block entirely. They write an object
\* under a term the open window authorizes for reads, hoping the rewrap
\* pass will decrypt it and re-seal it under the new term.
AttackerInject ==
    /\ pending
    /\ objTerm[Evil] = ABSENT
    /\ \E t \in retiring :
         /\ ReadAuthorized(t)
         /\ objTerm' = [objTerm EXCEPT ![Evil] = t]
    /\ UNCHANGED <<running, currentTerm, residentTerms, retiring, pending,
                   snapshot, cleanAtCutover, baseline, diverged>>

----------------------------------------------------------------------------
(* Crash and resume *)

\* Every variable here is durable: the root write is atomic and each rewrap
\* is a durable single-file write. A crash therefore loses only liveness,
\* which is the property that makes a partially rewrapped store legal.
Crash ==
    /\ running
    /\ running' = FALSE
    /\ UNCHANGED <<currentTerm, residentTerms, retiring, pending, snapshot,
                   cleanAtCutover, objTerm, baseline, diverged>>

\* Resume runs at unlock, before the identity is enabled. It continues the
\* existing transition and must never append another term (R5). The root
\* fields are unchanged here; StartRotation is a separate operator whose
\* ~pending guard refuses a second append while this transition is open.
Resume ==
    /\ ~running
    /\ running' = TRUE
    /\ UNCHANGED <<currentTerm, residentTerms, retiring, pending, snapshot,
                   cleanAtCutover, objTerm, baseline, diverged>>

\* NEGATIVE CONTROL for R5. This is the bug the phase-3 implementation guard
\* must exclude: unlock sees a pending transition but starts rotation again,
\* appending T3 and replacing the root's transition metadata.
ResumeAppendWithoutPendingGuard ==
    /\ ~running
    /\ pending
    /\ running' = TRUE
    /\ AppendTerm(T2, T3)

----------------------------------------------------------------------------

Next ==
    \/ OperatorMutation
    \/ StartRotation
    \/ \E o \in Objects : Rewrap(o)
    \/ WriteBaseline
    \/ CloseWindow
    \/ AttackerInject
    \/ Crash
    \/ Resume

Spec == Init /\ [][Next]_vars

\* The ordinary cfg checks Spec. rotation_transition_negative.cfg checks this
\* mutation separately and must find an R5 counterexample. Keeping the
\* negative control out of Next means the production model remains the guarded
\* transition while the formal harness proves that the guard is load-bearing.
NextWithoutPendingGuard ==
    Next \/ ResumeAppendWithoutPendingGuard

NegativeSpec == Init /\ [][NextWithoutPendingGuard]_vars

----------------------------------------------------------------------------
(* Invariants *)

\* R1: the store's own data is never stranded — every legitimate object is
\* on a term the store can still read.
\*
\* Quantified over Legit, not Objects. An attacker-injected object left
\* unreadable after the window closes is the success case, not a violation:
\* the rewrap refused to promote it, so it stays on a retired term and
\* becomes garbage. An earlier draft quantified over all objects and TLC
\* immediately produced that trace, which is the model correcting the
\* invariant rather than the design.
R1_LiveDataNeverStranded ==
    \A o \in Legit :
        objTerm[o] # ABSENT => ReadAuthorized(objTerm[o])

\* R2: no laundering. Only objects the cutover pinned ever reach the new
\* term; anything injected afterwards stays where it was written.
R2_OnlyPinnedObjectsReachNewTerm ==
    \A o \in Objects :
        (objTerm[o] = currentTerm /\ currentTerm = T2) => o \in snapshot

\* R3: a completed rotation leaves rollback available for a generation that
\* was clean at cutover. Without the baseline, the rotated ciphertext
\* matches neither the at-mint manifest nor any baseline, and the guard
\* refuses every later rollback — permanently.
R3_CompletedRotationLeavesRollbackAvailable ==
    (~pending /\ currentTerm = T2 /\ cleanAtCutover) => baseline

\* R4: divergence is never erased. A generation that had diverged before
\* the cutover never acquires a baseline that would declare it clean.
R4_DivergenceNeverErased ==
    (baseline /\ currentTerm = T2) => cleanAtCutover

\* R5: resume must never append a second term. T3 is in the state space and
\* residentTerms may contain it under TypeOK, so this is not a type invariant.
\* rotation_transition_negative.cfg makes the unguarded append reachable and
\* requires TLC to fail this predicate.
R5_NoSecondAppend ==
    T3 \notin residentTerms

Safety ==
    /\ TypeOK
    /\ R1_LiveDataNeverStranded
    /\ R2_OnlyPinnedObjectsReachNewTerm
    /\ R3_CompletedRotationLeavesRollbackAvailable
    /\ R4_DivergenceNeverErased
    /\ R5_NoSecondAppend

============================================================================
