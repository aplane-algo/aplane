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
reload builds the generation the root selects before it installs any of it,
and then publishes it, publishes recovery's view of it, or keeps the view in
service. The build can fail (the selected generation does not validate, or
the root no longer authenticates), and the four guards checked here are what
keep a failed reload from leaving the runtime acting on the superseded,
sealed generation:

  RecoveryBindsSelection  recovery's view is bound to the selection the build
                          authenticated, or to nothing when the root did not
                          authenticate, so a failed reload still leaves the
                          binding on the root's generation.
  KeepNeedsBoundSelection a failed reload keeps the view in service only
                          while the root still selects the generation it is
                          bound to.
  MaintenanceReadsRoot    recovery maintenance (deleted-archive list and
                          prune) authenticates the root itself instead of
                          trusting the cached binding.
  RecoveryBeforeRelease   a failed post-commit reload enters recovery before
                          the mutation lock is released, so no request is
                          served from the stale key cache in between.

All four are TRUE in the code. The negative control sets the first and the
third to FALSE, the shape before commit b0e51275, and TLC reproduces that
bug: the reload fails, the binding stays on the old generation, and prune
acts on the sealed rollback target while the root selects the new generation
(RB1_MaintenanceFollowsRoot). A second negative control sets
KeepNeedsBoundSelection to FALSE: a failed reload after a commit keeps the
superseded generation's view, and the binding is behind the root outside a
mutation (RB4_BindingFollowsRoot).

Code anchors:
  - CommitRoot/BeginReload/Build/ReloadSucceed/ReloadFail/ReloadKeep
    transcribe internal/signerapp/admin/policy.go ApplyPolicy,
    internal/signerapp/backupadmin/direct_restore.go and
    direct_rollback.go, with internal/signerapp/productruntime/view.go
    FollowCommit and Reconcile over reloadView (the failure rule), and
    internal/signerapp/startup/product_build.go Build over
    internal/genstore/store_root.go AuthenticateStoreRootSelection and
    ValidateStoreRootSelection. BeginReload's reloads (the watcher's, an
    in-place write's) are productruntime.Runtime.Reload over the same
    reloadView: no commit moved the root, so ReloadKeep meets its guard
    unless the root stopped authenticating, which fails them.
  - Maintain transcribes internal/signerapp/daemon/admin_services.go
    authenticatedSelection as used by ListDeletedArchive (under
    withStoreInspection) and PruneDeletedArchive (under withStoreMutation).
  - Serve is a signing request or key write gated by the runtime state
    (internal/signerapp/runtime/runtime.go SetRecovery, IsRecovery; the
    IsUnlocked gate in internal/signerapp/rest/preconditions.go and
    internal/signerapp/signing/service.go).
  - RootDamaged/RootRepaired stand for a store-root.enc that stops or
    resumes authenticating (operator restore of a foreign or damaged file).

See FORMAL_TLA_RECOVERY_BINDING_MODEL.md for the prose companion.
***************************************************************************)

CONSTANTS RecoveryBindsSelection, KeepNeedsBoundSelection, MaintenanceReadsRoot, RecoveryBeforeRelease

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
    built,            \* the generation the reload's build found the root
                      \* selecting, or None when it did not authenticate
    phase,            \* "idle" | "committed" | "built" | "failed"
    recovery,         \* the runtime is in recovery: signing and key writes refused
    maintainedStale,  \* history flag: maintenance acted on a generation other than root
    servedStale       \* history flag: a request was served from a stale cache
                      \* after the mutation lock was released

vars == <<root, rootAuth, bound, cacheGen, lockHeld, built, phase, recovery,
          maintainedStale, servedStale>>

Init ==
    /\ root = Old
    /\ rootAuth = TRUE
    /\ bound = Old
    /\ cacheGen = Old
    /\ lockHeld = FALSE
    /\ built = Old
    /\ phase = "idle"
    /\ recovery = FALSE
    /\ maintainedStale = FALSE
    /\ servedStale = FALSE

----------------------------------------------------------------------------
(* Mutations: commit then reload, under the store mutation lock *)

\* CommitRoot is a root-changing operation (policy apply, restore, rollback)
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
    /\ UNCHANGED <<rootAuth, bound, cacheGen, built, recovery, maintainedStale, servedStale>>

\* BeginReload is a reload with no commit: the recovery reconcile, the
\* watcher's reload, or an in-place write's. It runs under the same lock.
BeginReload ==
    /\ ~lockHeld
    /\ phase = "idle"
    /\ lockHeld' = TRUE
    /\ phase' = "committed"
    /\ UNCHANGED <<root, rootAuth, bound, cacheGen, built, recovery, maintainedStale, servedStale>>

\* Build is the reload's build: it reads the root once and authenticates
\* what it selects, and installs nothing. The binding stays where it is
\* until a view is published.
Build ==
    /\ phase = "committed"
    /\ built' = IF rootAuth THEN root ELSE None
    /\ phase' = "built"
    /\ UNCHANGED <<root, rootAuth, bound, cacheGen, lockHeld, recovery, maintainedStale, servedStale>>

\* ReloadSucceed: the selected generation validates and scans, and the whole
\* view is published: the binding and the key cache follow the root,
\* recovery (if any) lifts, and the lock is released.
ReloadSucceed ==
    /\ phase = "built"
    /\ built # None
    /\ bound' = built
    /\ cacheGen' = built
    /\ recovery' = FALSE
    /\ lockHeld' = FALSE
    /\ phase' = "idle"
    /\ UNCHANGED <<root, rootAuth, built, maintainedStale, servedStale>>

\* ReloadFail: the build failed, or the store is in doubt, and recovery's
\* view is published: with RecoveryBindsSelection it is bound to the build's
\* selection, or to nothing; without it (the pre-fix code) the binding stays.
\* The view holds no keys; the key cache's generation is kept here, and
\* recovery refuses to serve from it. With RecoveryBeforeRelease the runtime
\* enters recovery in the same step the lock is released; without it the
\* lock is released first and recovery is entered by a later step
\* (EnterRecoveryLate), leaving a window.
ReloadFail ==
    /\ phase = "built"
    /\ bound' = IF RecoveryBindsSelection THEN built ELSE bound
    /\ lockHeld' = FALSE
    /\ IF RecoveryBeforeRelease
       THEN recovery' = TRUE /\ phase' = "idle"
       ELSE recovery' = recovery /\ phase' = "failed"
    /\ UNCHANGED <<root, rootAuth, cacheGen, built, maintainedStale, servedStale>>

\* ReloadKeep: a build that failed for a reason that is not a defect of the
\* selected generation, on a store not in doubt, keeps the view in service
\* (row 5 of the failure rule). With KeepNeedsBoundSelection it may do so
\* only while the root still selects the generation the view is bound to;
\* otherwise the reload fails (row 3).
ReloadKeep ==
    /\ phase = "built"
    /\ KeepNeedsBoundSelection => (built # None /\ built = bound)
    /\ lockHeld' = FALSE
    /\ phase' = "idle"
    /\ UNCHANGED <<root, rootAuth, bound, cacheGen, built, recovery, maintainedStale, servedStale>>

EnterRecoveryLate ==
    /\ phase = "failed"
    /\ recovery' = TRUE
    /\ phase' = "idle"
    /\ UNCHANGED <<root, rootAuth, bound, cacheGen, lockHeld, built, maintainedStale, servedStale>>

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
    /\ UNCHANGED <<root, rootAuth, bound, cacheGen, lockHeld, built, phase, recovery, maintainedStale>>

\* Maintain is deleted-archive list or prune. With MaintenanceReadsRoot it
\* authenticates the root itself and errors (no action) when the root does
\* not authenticate; without it (the pre-fix code) it trusts the cached
\* binding. Prune takes the mutation lock and list takes it with TryLock
\* (store_busy while it is held), so neither runs mid-mutation.
Maintain ==
    /\ ~lockHeld
    /\ LET target == IF MaintenanceReadsRoot THEN root ELSE bound
       IN  /\ IF MaintenanceReadsRoot THEN rootAuth ELSE bound # None
           /\ maintainedStale' = (maintainedStale \/ target # root)
    /\ UNCHANGED <<root, rootAuth, bound, cacheGen, lockHeld, built, phase, recovery, servedStale>>

----------------------------------------------------------------------------
(* Root authentication *)

RootDamaged ==
    /\ ~lockHeld
    /\ rootAuth
    /\ rootAuth' = FALSE
    /\ UNCHANGED <<root, bound, cacheGen, lockHeld, built, phase, recovery, maintainedStale, servedStale>>

RootRepaired ==
    /\ ~lockHeld
    /\ ~rootAuth
    /\ rootAuth' = TRUE
    /\ UNCHANGED <<root, bound, cacheGen, lockHeld, built, phase, recovery, maintainedStale, servedStale>>

----------------------------------------------------------------------------
(* Next and Spec *)

Next ==
    \/ CommitRoot
    \/ BeginReload
    \/ Build
    \/ ReloadSucceed
    \/ ReloadFail
    \/ ReloadKeep
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
    /\ built \in Gens \cup {None}
    /\ phase \in {"idle", "committed", "built", "failed"}
    /\ recovery \in BOOLEAN
    /\ maintainedStale \in BOOLEAN
    /\ servedStale \in BOOLEAN
    /\ lockHeld <=> phase \in {"committed", "built"}

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
