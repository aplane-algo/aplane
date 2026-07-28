------------------------- MODULE generation_commit -------------------------
(*
Twelfth machine-checkable model in the APlane formalization roadmap (M4).

This module models the generation commit protocol from ARCH_GENERATIONS.md
and internal/genstore/commit.go: minting a complete new generation and
committing it with one durable CURRENT flip, interleaved with crashes at
every step, followed by restart reconciliation.

The other modules in this directory model concurrency — two processes
racing over shared state. This one models a different interleaving with
the same shape: a single serialized writer (the identity mutation lock
makes the commit sequence non-concurrent) against a crash that can land
between any two steps, and against a filesystem that may lose any write
whose fsync has not completed.

It covers five invariants:

  - G1 : CURRENT never names a generation that is not fully published.
  - G2 : the parent is sealed before the child becomes current, so a
         committed generation always has a valid rollback target.
  - G3 : reconciliation leaves no published-but-uncommitted generation.
  - G4 : a commit whose durability could not be confirmed blocks signing
         until reconciliation.
  - G5 : reconciliation re-confirms the CURRENT flip's durability, so a
         store that reconciles cleanly is durably committed.

G1 is the load-bearing one. It is why MintSyncGenerations must precede
MintFlip: without that ordering a crash can persist the pointer flip
while losing the generation's directory entry, leaving CURRENT naming
nothing. Deleting the publishedDurable conjunct from MintFlip makes TLC
produce exactly that counterexample, which is the regression this model
exists to catch.

The counterexample is worth reading, because it does not take the obvious
route. MintSealParent carries its own publishedDurable guard, so a first
mint attempt stays safe even with MintFlip weakened. The violation comes
from the retry path: seal the parent, crash in the seal-before-flip
window, reconcile discards the published but uncommitted child (it is
durable by then, and CURRENT never named it) while leaving the parent
sealed, and the retry then reaches a weakened MintFlip on a freshly
published — not yet synced — generation, because parentSealed is already
satisfied from the first attempt. The conjunct on MintFlip is what holds
G1 there, where the seal step no longer re-derives it.

Durability is modeled explicitly rather than assumed. Each write that the
implementation follows with an fsync has a companion "durable" flag, and
Crash nondeterministically loses any write whose flag is still FALSE.
That nondeterminism is what makes ErrCommitDurabilityUnknown expressible:
a flip that is visible but unconfirmed may survive a crash or not, and
the protocol must be correct either way.

The module intentionally omits:

  - Content validation. Whether a generation's keys and key-type records
    decrypt and parse is checked at the reload gate, not by the commit
    protocol, and is covered by Go tests. Here a published generation is
    structurally complete by construction.
  - RollbackTo. It is a pointer flip with the same durability structure
    as the forward commit; its distinctive risk is divergence after
    post-activation mutation, which is a content question (guarded by
    recovered_rollback_diverged) rather than a crash-consistency one.
  - Garbage collection of sealed priors, and the retention window. Prune
    is crash-idempotent through tombstone renames and does not interact
    with the commit sequence modeled here.
  - Reconcile's retention exceptions. The implementation keeps a
    non-current unsealed generation when recovery metadata references it
    or when it is the current manifest's ParentID, which is damage
    (RetainedUnsealedParent) rather than an uncommitted attempt. The
    model's Reconcile discards unconditionally, so G3 is the claim for an
    undamaged store with no referenced generations — the case the commit
    protocol itself produces. Retention of referenced and damaged
    generations is a reconciliation-policy question, checked by Go tests.
  - Read-back failure during the flip. WriteCurrent also reports
    durability-unknown when it cannot re-read CURRENT after a failed
    write, a state where the flip may not have landed at all. The model
    enters durabilityUnknown only with the flip visible; both reach the
    same runtime outcome (signing blocked until reconciliation), which is
    what G4 constrains.
  - Multi-generation chains. Two generations are enough to express every
    ordering constraint in the protocol; a longer chain adds states
    without adding reachable shapes.
  - Concurrent minting. The identity mutation lock serializes it, and
    that lock is modeled in lifecycle.tla.

If those concerns become security-critical for a particular check, add a
separate module rather than extending this one.

See ARCH_GENERATIONS.md for the prose companion.
*)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    P,   \* parent generation: the store's committed state before the mint
    C    \* child generation: the one being minted

ASSUME P # C

Generations == {P, C}

----------------------------------------------------------------------------
(* Variables *)

VARIABLES
    running,            \* process is up; FALSE between Crash and Reconcile
    mode,               \* "signing" or "recovery"
    staged,             \* generations/.staging-<C> exists
    published,          \* generations/<C> exists (the staging rename landed)
    publishedDurable,   \* fsync of generations/ confirmed that rename
    parentSealed,       \* P carries seal.json
    current,            \* the generation CURRENT names
    currentDurable,     \* fsync of the identity directory confirmed the flip
    durabilityUnknown,  \* a flip went visible with its fsync unconfirmed
    postReconcile       \* set by Reconcile, cleared when the next mint starts

vars == <<running, mode, staged, published, publishedDurable, parentSealed,
          current, currentDurable, durabilityUnknown, postReconcile>>

TypeOK ==
    /\ running \in BOOLEAN
    /\ mode \in {"signing", "recovery"}
    /\ staged \in BOOLEAN
    /\ published \in BOOLEAN
    /\ publishedDurable \in BOOLEAN
    /\ parentSealed \in BOOLEAN
    /\ current \in Generations
    /\ currentDurable \in BOOLEAN
    /\ durabilityUnknown \in BOOLEAN
    /\ postReconcile \in BOOLEAN

----------------------------------------------------------------------------
(* Initial state: a healthy store holding only the parent generation. *)

Init ==
    /\ running = TRUE
    /\ mode = "signing"
    /\ staged = FALSE
    /\ published = FALSE
    /\ publishedDurable = FALSE
    /\ parentSealed = FALSE
    /\ current = P
    /\ currentDurable = TRUE
    /\ durabilityUnknown = FALSE
    /\ postReconcile = FALSE

----------------------------------------------------------------------------
(* Mint steps, in the order commit.go performs them.                       *)
(* Each step is guarded on the previous one having completed, which is how *)
(* the protocol's ordering constraints enter the model.                    *)

\* Stage the new generation: create generations/.staging-<C>, copy the
\* parent's namespaces into it, apply the operation, validate, and write
\* the manifest. Modeled as one step: nothing outside the staging
\* directory is touched, so a crash anywhere inside it is indistinguishable.
MintStage ==
    /\ running
    /\ mode = "signing"
    /\ ~staged
    /\ ~published
    /\ current = P
    /\ staged' = TRUE
    /\ postReconcile' = FALSE
    /\ UNCHANGED <<running, mode, published, publishedDurable, parentSealed,
                   current, currentDurable, durabilityUnknown>>

\* Publish the generation by renaming staging into place. The rename is
\* atomic but its directory entry is not yet durable.
MintPublish ==
    /\ running
    /\ staged
    /\ staged' = FALSE
    /\ published' = TRUE
    /\ publishedDurable' = FALSE
    /\ UNCHANGED <<running, mode, parentSealed, current, currentDurable,
                   durabilityUnknown, postReconcile>>

\* fsync generations/. Mandatory before the flip: see G1.
MintSyncGenerations ==
    /\ running
    /\ published
    /\ ~publishedDurable
    /\ publishedDurable' = TRUE
    /\ UNCHANGED <<running, mode, staged, published, parentSealed, current,
                   currentDurable, durabilityUnknown, postReconcile>>

\* Seal the outgoing generation while it is still current: the last write
\* it ever receives, and what makes it a valid rollback target. WriteSeal
\* is durable on return, so there is no separate confirm step.
MintSealParent ==
    /\ running
    /\ published
    /\ publishedDurable
    /\ ~parentSealed
    /\ parentSealed' = TRUE
    /\ UNCHANGED <<running, mode, staged, published, publishedDurable,
                   current, currentDurable, durabilityUnknown, postReconcile>>

\* The commit itself: rename CURRENT over itself pointing at C. Visible
\* immediately; not yet proven to survive a power loss.
MintFlip ==
    /\ running
    /\ published
    /\ publishedDurable        \* removing this conjunct breaks G1
    /\ parentSealed
    /\ current = P
    /\ current' = C
    /\ currentDurable' = FALSE
    /\ UNCHANGED <<running, mode, staged, published, publishedDurable,
                   parentSealed, durabilityUnknown, postReconcile>>

\* fsync the identity directory: the flip is now durable and the commit
\* is complete.
MintConfirmFlip ==
    /\ running
    /\ mode = "signing"        \* after a reported durability failure the
                               \* commit path has already returned; only
                               \* reconciliation re-syncs
    /\ current = C
    /\ ~currentDurable
    /\ currentDurable' = TRUE
    /\ UNCHANGED <<running, mode, staged, published, publishedDurable,
                   parentSealed, current, durabilityUnknown, postReconcile>>

\* The identity-directory fsync failed. The pointer is visible, so the
\* commit IS in effect for every subsequent resolution, but it may not
\* survive a power loss: ErrCommitDurabilityUnknown. Signing stops now,
\* not at the next unlock.
MintFlipDurabilityUnknown ==
    /\ running
    /\ current = C
    /\ ~currentDurable
    /\ mode = "signing"
    /\ mode' = "recovery"
    /\ durabilityUnknown' = TRUE
    /\ UNCHANGED <<running, staged, published, publishedDurable, parentSealed,
                   current, currentDurable, postReconcile>>

----------------------------------------------------------------------------
(* Crash                                                                    *)

\* A crash may land between any two steps. Every write whose fsync has not
\* completed may or may not survive; the protocol must be correct under
\* either outcome, so both are explored.
\*
\* Staging residue may survive or not: either way reconciliation treats it
\* as garbage, so both outcomes are allowed without constraint.
Crash ==
    /\ running
    /\ running' = FALSE
    /\ staged' \in BOOLEAN
    /\ published' \in (IF published /\ ~publishedDurable
                       THEN BOOLEAN
                       ELSE {published})
    /\ publishedDurable' = publishedDurable
    /\ current' \in (IF current = C /\ ~currentDurable
                     THEN Generations
                     ELSE {current})
    /\ UNCHANGED <<mode, parentSealed, currentDurable, durabilityUnknown,
                   postReconcile>>

----------------------------------------------------------------------------
(* Restart reconciliation                                                   *)

\* genstore.Reconcile at unlock: discard staging residue, discard published
\* generations CURRENT does not name (uncommitted attempts are never
\* resumed), and re-confirm the flip's durability by syncing the identity
\* directory. A store that reconciles cleanly returns to signing.
\*
\* Crash-during-reconcile needs no separate action: TLA+ actions are atomic,
\* so an interrupted reconcile is a Crash that fires before Reconcile, and
\* the next Reconcile starts from the same store state. Reconcile applied to
\* an already-reconciled store is a no-op, which is idempotence.
Reconcile ==
    /\ ~running
    /\ running' = TRUE
    /\ mode' = "signing"
    /\ staged' = FALSE
    /\ published' = (published /\ current = C)
    /\ publishedDurable' = (published /\ current = C)
    /\ currentDurable' = TRUE
    /\ durabilityUnknown' = FALSE
    /\ postReconcile' = TRUE
    /\ UNCHANGED <<parentSealed, current>>

----------------------------------------------------------------------------

Next ==
    \/ MintStage
    \/ MintPublish
    \/ MintSyncGenerations
    \/ MintSealParent
    \/ MintFlip
    \/ MintConfirmFlip
    \/ MintFlipDurabilityUnknown
    \/ Crash
    \/ Reconcile

Spec == Init /\ [][Next]_vars

----------------------------------------------------------------------------
(* Invariants *)

\* G1: CURRENT never names a generation whose directory is absent. This is
\* the invariant that forces the generations/ fsync to precede the flip.
G1_CurrentNamesPublishedGeneration ==
    (current = C) => published

\* G2: the outgoing generation is sealed before the incoming one becomes
\* current, so a committed generation always has a valid rollback target.
\* One-directional by design: a sealed generation that is still current is
\* the tolerated seal-before-flip crash window, not a violation.
G2_ParentSealedBeforeChildCurrent ==
    (current = C) => parentSealed

\* G3: reconciliation leaves no published-but-uncommitted generation. A
\* published generation CURRENT does not name is an abandoned attempt and
\* is discarded, never resumed.
G3_NoUncommittedGenerationAfterReconcile ==
    (running /\ postReconcile) => ~(published /\ current = P)

\* G4: a commit whose durability could not be confirmed never signs. The
\* runtime is either down or in recovery until reconciliation heals it.
G4_DurabilityUnknownBlocksSigning ==
    durabilityUnknown => (~running \/ mode = "recovery")

\* G5: a store that has reconciled is durably committed — reconciliation
\* re-syncs the identity directory, so the pointer read at unlock is the
\* pointer that survives the next power loss.
G5_ReconcileRestoresDurableCurrent ==
    (running /\ postReconcile) => currentDurable

Safety ==
    /\ TypeOK
    /\ G1_CurrentNamesPublishedGeneration
    /\ G2_ParentSealedBeforeChildCurrent
    /\ G3_NoUncommittedGenerationAfterReconcile
    /\ G4_DurabilityUnknownBlocksSigning
    /\ G5_ReconcileRestoresDurableCurrent

============================================================================
