---------------------- MODULE session_ownership ----------------------
(*
Eighth machine-checkable model in the APlane formalization roadmap (M4),
and the machine-checked counterpart to the admin-session ownership design
shipped in "Preserve admin unlock ownership" (daemon/ipc.go
handleRegisteredClient, adminserver.SessionManager, adminserver
displacement flow).

It models the lifecycle of admin (apadmin/apconsole) sessions against one
identity: sessions authenticate (which unlocks the identity as a side
effect -- the current, deliberate code ordering), get promoted to the
single active owner slot, displace each other, and exit. The daemon's
disconnect defer decides whether an exiting session runs "owner cleanup"
(fail pending approvals + lock when lock_on_disconnect is set).

The safety question this module answers is the one from the fix: because
unlock happens during authentication, BEFORE the session becomes the
active owner, any failure between those two points (pending-slot
contention, displacement rejection, promotion failure, connection drop)
must not strand the identity unlocked with no session left whose exit
will re-lock it.

The code's mechanism, modeled here exactly:

  - Auth unlocks and marks the session authenticated
    (adminserver/session.go AuthenticateOutcome; ipc.go sets
    cleanupRuntime on AuthOutcomeAuthenticated -- auth_only observer
    sessions never set it and are outside this model).
  - PromoteToActive is an atomic swap under the SessionManager mutex:
    the replacement becomes active in the same step the old owner is
    removed (manager.go PromoteToActive). Only after that is the old
    session notified and closed (DisplaceSession) -- so there is no
    window where a confirmed displacement has removed the owner before
    the replacement holds the slot.
  - The disconnect defer runs owner cleanup iff the controlling session
    authenticated AND (it was the active client OR no active client
    remains): ipc.go "cleanupRuntime && (wasActiveClient ||
    !HasClient())". The second disjunct is the fix: a session
    that unlocked but never became owner still re-locks on its way out
    unless someone else took over.

Scope note (`auth_only`, introduced in admin protocol 4.4 and retained in
protocol 5): AuthSucceed models the controlling `auth` message, which unlocks
and enters the ownership lifecycle. The `auth_only` message verifies the
passphrase and binds a server-enforced public-read observer without authorizing
or invoking identity.unlock. It never enters the active-owner slot and cannot
replace an owner or run owner disconnect cleanup. It therefore changes none of
this model's ownership or lock-state variables; its lifecycle and dispatch
allowlist are pinned by Go tests rather than represented as an AuthSucceed
variant.

Invariants:
  - SO1 : at most one session is the active owner.
  - SO2 : while the identity is unlocked with lock_on_disconnect set,
          some authenticated session is still live -- the owner, or a
          session whose exit will run owner cleanup. Equivalently: the
          identity is never stranded unlocked with nobody responsible.

Mutations (documented; the shipped spec passes both restored):
  - Reverting the cleanup condition to the pre-fix "authenticated &&
    wasActiveClient" (drop the ~othersActive disjunct in Exit) lets
    auth-success-followed-by-promotion-failure strand the unlock: TLC
    violates SO2 in three steps (AuthSucceed, Exit, with
    lockOnDisconnect = TRUE).
  - Additionally clearing the owner at displacement-confirm time (the
    pre-fix OfferDisplacement, modeled by splitting PromoteReplace into
    a clear step and a later promote step) reproduces the original
    two-session bug. With the fixed cleanup condition but pre-fix
    clearing, SO2 holds but the displaced session's exit over-locks the
    identity out from under the incoming replacement -- which is why the
    fix changed both the condition and the ordering.

The module intentionally omits: multiple product runtimes (the implementation
has one process-wide runtime and owner slot), the operator unlock/lock IPC
commands and passphrase retry (outside this model -- here unlock
is only the auth side effect under scrutiny), pending-slot contention
detail (BindPreAuthPending losers simply Exit while Authed), and the
approval-prompt consequences of cleanup (approval_coordinator.tla's AP7).

lock_on_disconnect is chosen nondeterministically at Init and never
changes; SO2 is vacuous when it is FALSE (the operator opted out of
re-locking), and TLC explores both configurations.
*)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS Sessions   \* set of admin-session model values, e.g. {a1, a2, a3}

----------------------------------------------------------------------------
(* State sets *)

\* PreAuth: connected, not yet authenticated. Authed: authenticated (the
\* identity was unlocked during auth) but not yet the active owner.
\* Active: the single active owner. Displaced: atomically replaced by a
\* newer owner, not yet exited. Exited: the disconnect defer has run.
LiveStates == {"PreAuth", "Authed", "Active", "Displaced"}
SessState  == LiveStates \cup {"Exited"}

----------------------------------------------------------------------------
(* Variables *)

VARIABLES
    sessState,          \* function: Sessions -> SessState
    authenticated,      \* function: Sessions -> BOOLEAN (sticky auth flag)
    unlocked,           \* BOOLEAN: the identity's keystore is unlocked
    lockOnDisconnect    \* BOOLEAN: config, fixed at Init

vars == <<sessState, authenticated, unlocked, lockOnDisconnect>>

ActiveSet == {s \in Sessions : sessState[s] = "Active"}

----------------------------------------------------------------------------
(* Initial state *)

Init ==
    /\ sessState = [s \in Sessions |-> "PreAuth"]
    /\ authenticated = [s \in Sessions |-> FALSE]
    /\ unlocked = FALSE
    /\ lockOnDisconnect \in BOOLEAN

----------------------------------------------------------------------------
(* Actions *)

\* AuthSucceed models AuthenticateOutcome returning AuthOutcomeAuthenticated:
\* the store is unlocked as a side effect of verifying the passphrase, and
\* the daemon marks the session authenticated -- BEFORE any ownership is
\* established. This is the ordering the invariant must survive.
AuthSucceed(s) ==
    /\ sessState[s] = "PreAuth"
    /\ sessState' = [sessState EXCEPT ![s] = "Authed"]
    /\ authenticated' = [authenticated EXCEPT ![s] = TRUE]
    /\ unlocked' = TRUE
    /\ UNCHANGED lockOnDisconnect

\* Promote models PromoteToActive with no current owner: the authenticated
\* session takes the active slot.
Promote(s) ==
    /\ sessState[s] = "Authed"
    /\ ActiveSet = {}
    /\ sessState' = [sessState EXCEPT ![s] = "Active"]
    /\ UNCHANGED <<authenticated, unlocked, lockOnDisconnect>>

\* PromoteReplace models a confirmed displacement: PromoteToActive's atomic
\* swap makes the replacement the owner in the same step the old owner is
\* removed; the old session is then notified and closed (DisplaceSession)
\* and exits later via Exit. Displacement confirmation itself has no state
\* effect (it only authorizes this step), so it is not a separate action.
PromoteReplace(s) ==
    /\ sessState[s] = "Authed"
    /\ ActiveSet # {}
    /\ sessState' = [u \in Sessions |->
                        IF u = s THEN "Active"
                        ELSE IF sessState[u] = "Active" THEN "Displaced"
                        ELSE sessState[u]]
    /\ UNCHANGED <<authenticated, unlocked, lockOnDisconnect>>

\* Exit models every way a session leaves, uniformly through the disconnect
\* defer in ipc.go handleRegisteredClient: failed auth (default branch),
\* pending-slot or promotion failure (early return while Authed),
\* displacement close, and plain connection drop. ClearActive removes the
\* session from the owner slot if it still holds it; owner cleanup (fail
\* pending approvals + lock under lock_on_disconnect) runs iff the session
\* authenticated and either it was the owner or no owner remains. The
\* ~othersActive disjunct is the load-bearing half of the fix: without it,
\* an unlock whose session never became owner is stranded.
Exit(s) ==
    /\ sessState[s] \in LiveStates
    /\ LET wasActive    == sessState[s] = "Active"
           othersActive == \E t \in Sessions \ {s} : sessState[t] = "Active"
           ownerCleanup == authenticated[s] /\ (wasActive \/ ~othersActive)
       IN /\ sessState' = [sessState EXCEPT ![s] = "Exited"]
          /\ unlocked' = IF ownerCleanup /\ lockOnDisconnect THEN FALSE ELSE unlocked
    /\ UNCHANGED <<authenticated, lockOnDisconnect>>

----------------------------------------------------------------------------
(* Next and Spec *)

Next ==
    \/ \E s \in Sessions : AuthSucceed(s)
    \/ \E s \in Sessions : Promote(s)
    \/ \E s \in Sessions : PromoteReplace(s)
    \/ \E s \in Sessions : Exit(s)

Spec == Init /\ [][Next]_vars

\* Sessions are interchangeable for the safety invariants.
SessionSymmetry == Permutations(Sessions)

----------------------------------------------------------------------------
(* Invariants *)

\* TypeOK pins domains and records the structural facts the actions
\* maintain: only authenticated sessions reach Authed/Active/Displaced.
TypeOK ==
    /\ sessState \in [Sessions -> SessState]
    /\ authenticated \in [Sessions -> BOOLEAN]
    /\ unlocked \in BOOLEAN
    /\ lockOnDisconnect \in BOOLEAN
    /\ \A s \in Sessions :
           sessState[s] \in {"Authed", "Active", "Displaced"} => authenticated[s]

\* SO1: the SessionManager holds at most one active owner
\* (single map slot, swapped atomically).
SO1_SingleActiveOwner ==
    Cardinality(ActiveSet) <= 1

\* SO2: an unlocked product runtime with lock_on_disconnect set always has a live
\* authenticated session -- the owner, or a session whose exit will run
\* owner cleanup and re-lock. This is the "no stranded unlock" invariant
\* the fix exists to establish: it fails on the pre-fix cleanup condition.
SO2_UnlockedHasOwner ==
    (unlocked /\ lockOnDisconnect) =>
        \E s \in Sessions :
            authenticated[s] /\ sessState[s] \in {"Authed", "Active", "Displaced"}

Safety ==
    /\ TypeOK
    /\ SO1_SingleActiveOwner
    /\ SO2_UnlockedHasOwner

============================================================================
