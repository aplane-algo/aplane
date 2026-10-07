-------------------------- MODULE recovery_binding --------------------------
EXTENDS TLC

(***************************************************************************
Recovery binding model: which generation the runtime acts on after a store
root commit whose follow-up reload fails.

store_root_commit.tla says how a new generation becomes the authenticated
root selection. This module picks up from there: the runtime holds a cached
binding to a generation (the keystore's active paths) and a key cache built
from the generation it last scanned successfully. A root-changing mutation
commits the root and then reloads, both under the store mutation lock. The
reload can fail (the selected generation does not validate, or the root no
longer authenticates), and the three guards checked here are what keep a
failed reload from leaving the runtime acting on the superseded, sealed
generation:

  BindBeforeValidate     the reload binds the authenticated selection before
                         any step that can fail, so a failed reload still
                         leaves the binding on the root's generation.
  MaintenanceReadsRoot   recovery maintenance (deleted-archive list and
                         prune) authenticates the root itself instead of
                         trusting the cached binding.
  RecoveryBeforeRelease  a failed post-commit reload enters recovery before
                         the mutation lock is released, so no request is
                         served from the stale key cache in between.

All three are TRUE in the code. The negative control sets the first two to
FALSE, the shape before commit b0e51275, and TLC reproduces that bug: the
reload fails, the binding stays on the old generation, and prune acts on
the sealed rollback target while the root selects the new generation
(RB1_MaintenanceFollowsRoot).

Code anchors:
  - CommitRoot/BeginReload/ReloadBind/ReloadSucceed/ReloadFail transcribe
    internal/signerapp/admin/policy.go ApplyPolicy and commitAndReload,
    internal/signerapp/backupadmin/direct_restore.go, and the reload order
    in internal/signerapp/templates/reload.go (BindStoreRootSelection first)
    with internal/keystore/file.go Scan and BindStoreRootSelection over
    internal/genstore/store_root.go AuthenticateStoreRootSelection and
    ValidateStoreRootSelection.
  - Maintain transcribes internal/signerapp/daemon/admin_services.go
    authenticatedSelection as used by ListDeletedArchive and
    PruneDeletedArchive.
  - Serve is a signing request or key write gated by the runtime state
    (internal/signerapp/runtime/runtime.go SetRecovery, IsRecovery; the
    IsUnlocked gate in internal/signerapp/rest/preconditions.go and
    internal/signerapp/signing/service.go).
  - RootDamaged/RootRepaired stand for a store-root.enc that stops or
    resumes authenticating (operator restore of a foreign or damaged file).

See FORMAL_TLA_RECOVERY_BINDING_MODEL.md for the prose companion.
***************************************************************************)

CONSTANTS BindBeforeValidate, MaintenanceReadsRoot, RecoveryBeforeRelease

Old == "old"
New == "new"
None == "none"
Gens == {Old, New}

VARIABLES
    root,             \* the generation store-root.enc selects
    rootAuth,         \* store-root.enc authenticates under the held keyring
    bound,            \* the keystore's cached binding (active paths), or None
    cacheGen,         \* the generation the key cache was last built from
    lockHeld,         \* the store mutation lock is held
    phase,            \* "idle" | "committed" | "bound" | "failed"
    recovery,         \* the runtime is in recovery: signing and key writes refused
    maintainedStale,  \* history flag: maintenance acted on a generation other than root
    servedStale       \* history flag: a request was served from a stale cache
                      \* after the mutation lock was released

vars == <<root, rootAuth, bound, cacheGen, lockHeld, phase, recovery,
          maintainedStale, servedStale>>

Init ==
    /\ root = Old
    /\ rootAuth = TRUE
    /\ bound = Old
    /\ cacheGen = Old
    /\ lockHeld = FALSE
    /\ phase = "idle"
    /\ recovery = FALSE
    /\ maintainedStale = FALSE
    /\ servedStale = FALSE

----------------------------------------------------------------------------
(* Mutations: commit then reload, under the store mutation lock *)

\* CommitRoot is a root-changing operation (policy apply, restore, changepass)
\* taking the lock and committing the new generation as the root selection.
\* The commit itself is store_root_commit.tla; here it is one step.
CommitRoot ==
    /\ ~lockHeld
    /\ phase = "idle"
    /\ rootAuth
    /\ root = Old
    /\ lockHeld' = TRUE
    /\ root' = New
    /\ phase' = "committed"
    /\ UNCHANGED <<rootAuth, bound, cacheGen, recovery, maintainedStale, servedStale>>

\* BeginReload is a reload with no commit: the recovery reconcile, or an
\* explicit reload. It runs under the same lock.
BeginReload ==
    /\ ~lockHeld
    /\ phase = "idle"
    /\ lockHeld' = TRUE
    /\ phase' = "committed"
    /\ UNCHANGED <<root, rootAuth, bound, cacheGen, recovery, maintainedStale, servedStale>>

\* ReloadBind is the reload's first step: authenticate a fresh exact root
\* read and bind what it selects, before validation or scanning can fail. A
\* root that no longer authenticates leaves no authority to bind. Without
\* BindBeforeValidate (the pre-fix code) the binding moves only on success.
ReloadBind ==
    /\ phase = "committed"
    /\ bound' = IF ~BindBeforeValidate THEN bound
                ELSE IF rootAuth THEN root ELSE None
    /\ phase' = "bound"
    /\ UNCHANGED <<root, rootAuth, cacheGen, lockHeld, recovery, maintainedStale, servedStale>>

\* ReloadSucceed: the selected generation validates and scans; the key cache
\* follows the root, recovery (if any) lifts, and the lock is released.
ReloadSucceed ==
    /\ phase = "bound"
    /\ rootAuth
    /\ bound' = root
    /\ cacheGen' = root
    /\ recovery' = FALSE
    /\ lockHeld' = FALSE
    /\ phase' = "idle"
    /\ UNCHANGED <<root, rootAuth, maintainedStale, servedStale>>

\* ReloadFail: validation or scanning fails, or the root did not
\* authenticate. The key cache keeps the generation it last scanned. With
\* RecoveryBeforeRelease the runtime enters recovery in the same step the
\* lock is released; without it the lock is released first and recovery is
\* entered by a later step (EnterRecoveryLate), leaving a window.
ReloadFail ==
    /\ phase = "bound"
    /\ lockHeld' = FALSE
    /\ IF RecoveryBeforeRelease
       THEN recovery' = TRUE /\ phase' = "idle"
       ELSE recovery' = recovery /\ phase' = "failed"
    /\ UNCHANGED <<root, rootAuth, bound, cacheGen, maintainedStale, servedStale>>

EnterRecoveryLate ==
    /\ phase = "failed"
    /\ recovery' = TRUE
    /\ phase' = "idle"
    /\ UNCHANGED <<root, rootAuth, bound, cacheGen, lockHeld, maintainedStale, servedStale>>

----------------------------------------------------------------------------
(* What runs against which generation *)

\* Serve is a signing request or a key write. Signing is gated by the
\* runtime state only (not the mutation lock), so during a mutation it may
\* still run from the key cache; that window is the accepted cost of a
\* non-atomic runtime swap and is not flagged. Once the lock is released, a
\* request served from a cache behind the root is the bug the flag records.
Serve ==
    /\ ~recovery
    /\ servedStale' = (servedStale \/ (~lockHeld /\ cacheGen # root))
    /\ UNCHANGED <<root, rootAuth, bound, cacheGen, lockHeld, phase, recovery, maintainedStale>>

\* Maintain is deleted-archive list or prune. With MaintenanceReadsRoot it
\* authenticates the root itself and errors (no action) when the root does
\* not authenticate; without it (the pre-fix code) it trusts the cached
\* binding. Prune takes the mutation lock, so neither runs mid-mutation.
Maintain ==
    /\ ~lockHeld
    /\ LET target == IF MaintenanceReadsRoot THEN root ELSE bound
       IN  /\ IF MaintenanceReadsRoot THEN rootAuth ELSE bound # None
           /\ maintainedStale' = (maintainedStale \/ target # root)
    /\ UNCHANGED <<root, rootAuth, bound, cacheGen, lockHeld, phase, recovery, servedStale>>

----------------------------------------------------------------------------
(* Root authentication *)

RootDamaged ==
    /\ ~lockHeld
    /\ rootAuth
    /\ rootAuth' = FALSE
    /\ UNCHANGED <<root, bound, cacheGen, lockHeld, phase, recovery, maintainedStale, servedStale>>

RootRepaired ==
    /\ ~lockHeld
    /\ ~rootAuth
    /\ rootAuth' = TRUE
    /\ UNCHANGED <<root, bound, cacheGen, lockHeld, phase, recovery, maintainedStale, servedStale>>

----------------------------------------------------------------------------
(* Next and Spec *)

Next ==
    \/ CommitRoot
    \/ BeginReload
    \/ ReloadBind
    \/ ReloadSucceed
    \/ ReloadFail
    \/ EnterRecoveryLate
    \/ Serve
    \/ Maintain
    \/ RootDamaged
    \/ RootRepaired

Spec == Init /\ [][Next]_vars

----------------------------------------------------------------------------
(* Invariants *)

TypeOK ==
    /\ root \in Gens
    /\ rootAuth \in BOOLEAN
    /\ bound \in Gens \cup {None}
    /\ cacheGen \in Gens
    /\ lockHeld \in BOOLEAN
    /\ phase \in {"idle", "committed", "bound", "failed"}
    /\ recovery \in BOOLEAN
    /\ maintainedStale \in BOOLEAN
    /\ servedStale \in BOOLEAN
    /\ lockHeld <=> phase \in {"committed", "bound"}

\* RB1: recovery maintenance acts only on the generation the root selects.
RB1_MaintenanceFollowsRoot == ~maintainedStale

\* RB2: once a mutation has released the lock, no request is served from a
\* key cache behind the root.
RB2_NoStaleServiceAfterMutation == ~servedStale

\* RB3: a key cache behind the root means the runtime is mid-mutation or in
\* recovery.
RB3_StaleCacheImpliesRecoveryOrMutation == cacheGen # root => (recovery \/ lockHeld)

\* RB4: outside a mutation, a binding is the root's generation.
RB4_BindingFollowsRoot == (~lockHeld /\ phase = "idle" /\ bound # None) => bound = root

Safety ==
    /\ TypeOK
    /\ RB1_MaintenanceFollowsRoot
    /\ RB2_NoStaleServiceAfterMutation
    /\ RB3_StaleCacheImpliesRecoveryOrMutation
    /\ RB4_BindingFollowsRoot

=============================================================================
