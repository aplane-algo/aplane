-------------------------- MODULE enrollment_queue --------------------------
EXTENDS Naturals, FiniteSets, TLC

(***************************************************************************
Client enrollment model: the two daemon-written documents that decide which
SSH client keys may connect, the enrolled-key registry
(identities/default/.ssh/authorized_keys) and the pending-enrollment queue
(pending_enrollments.json), under the applied-vs-durable publication rule.

A client asks to be enrolled and is answered at once; the request waits on
disk until the operator approves (key moves into the registry), rejects, or
it lapses. Every change to either document is one durable publish
(fsutil.WriteFileDurable: stage, fsync, rename, directory fsync), which can
fail at three points:

  "ok"    renamed and synced; the new document is durable.
  "early" failed before the rename; the file still holds the old document.
  "late"  failed after the rename (the directory fsync); the file holds the
          new document but it may not survive a crash.

The runtime always serves what the file holds (the view follows the file,
never the other way round), remembers that the file is not known durable,
and re-publishes it before the next operation on that file. A change that
reached the file is "applied": it is audited and acted on even when the
publish failed late, and the caller is told so with ErrAppliedNotDurable.
A success answer to a client ("pending", "enrolled") is given only on the
strength of a synced file, so a crash never takes back what a client was
told. RequireDurableAck = FALSE is the deliberate negative control: a
"pending" answer given on a late-failed write is then taken back by a crash
and violates EQ2_PendingAckSurvivesCrash.

Code anchors:
  - RequestEnrolled/RequestQueued transcribe
    internal/signerapp/productruntime/runtime.go QueueEnrollment
    (ensureRegistryDurableLocked before the "already enrolled" answer,
    ensureQueueDurableLocked, enrollqueue.Queue.WithRequest with its
    one-entry-per-key refresh and MaxPending cap) and
    internal/signerapp/enrollment/service.go Request, which answers a
    not-yet-durable queue write with an error so the client retries.
  - Approve/Reject/Import/Revoke transcribe runtime.go ApproveEnrollment
    (registry before queue; a late registry write still clears the request;
    an enrolled key is audited whether or not the write was durable),
    RejectEnrollment (refuses a request whose key is already enrolled),
    ImportClientKey (clears the request only after a fully durable registry
    write), and RevokeAuthorizedKey, over publishRegistryLocked and
    publishQueueLocked.
  - ResyncRegistry/ResyncQueue are ensureRegistryDurableLocked and
    ensureQueueDurableLocked; Crash is the restart that reloads both files
    (LoadAuthorizedKeys, LoadEnrollmentQueue); Lapse is enrollqueue.TTL
    (lapsed entries are dropped by every reader).
  - The publish outcomes are internal/fsutil/durable.go WriteFileDurable as
    classified by publishRegistryFileLocked and publishQueueFileLocked.

See FORMAL_TLA_ENROLLMENT_QUEUE_MODEL.md for the prose companion.
***************************************************************************)

CONSTANTS
    Keys,              \* client key model values, e.g. {k1, k2, k3}
    MaxPending,        \* enrollqueue.MaxPending (16 in code; small here)
    RequireDurableAck  \* TRUE in code; FALSE is the negative control

ASSUME MaxPending \in Nat /\ MaxPending >= 1

VARIABLES
    reg,              \* enrolled keys: the live registry view, which equals the file
    regStable,        \* the registry content guaranteed to survive a crash
    regSynced,        \* the last registry publish completed its syncs (~clientsUnsynced)
    queue,            \* pending keys: the live queue view, which equals the file
    queueStable,      \* the queue content guaranteed to survive a crash
    queueSynced,      \* the last queue publish completed its syncs (~pendingUnsynced)
    pendingAcked,     \* keys whose client was told "pending" and whose request
                      \* no operator action or lapse has since removed
    enrolledAcked,    \* keys whose client was told "enrolled" and which no
                      \* revocation has since removed
    audited,          \* keys audited CLIENT_ENROLLED
    ackedUnsynced,    \* history flag: a success answer was read from an unsynced file
    rejectedEnrolled  \* history flag: a reject dropped the request of an enrolled key

vars == <<reg, regStable, regSynced, queue, queueStable, queueSynced,
          pendingAcked, enrolledAcked, audited, ackedUnsynced, rejectedEnrolled>>

Outcomes == {"ok", "early", "late"}

\* Applied reports whether the file, and so the view, holds the new document.
Applied(o) == o # "early"

----------------------------------------------------------------------------
(* One durable publish of each document *)

\* PublishRegistry installs next according to the outcome: the view follows
\* the file, the stable content moves only on a complete sync, and any
\* failure leaves the registry marked as needing a sync.
PublishRegistry(next, o) ==
    /\ reg' = IF Applied(o) THEN next ELSE reg
    /\ regStable' = IF o = "ok" THEN next ELSE regStable
    /\ regSynced' = (o = "ok")

PublishQueue(next, o) ==
    /\ queue' = IF Applied(o) THEN next ELSE queue
    /\ queueStable' = IF o = "ok" THEN next ELSE queueStable
    /\ queueSynced' = (o = "ok")

RegistryUnchanged == UNCHANGED <<reg, regStable, regSynced>>
QueueUnchanged == UNCHANGED <<queue, queueStable, queueSynced>>

\* ClearRequest removes k's request as the operator's answer to it; once the
\* removal is applied the client's "pending" is answered, durable or not.
ClearRequest(k) ==
    \E o \in Outcomes :
        /\ PublishQueue(queue \ {k}, o)
        /\ pendingAcked' = IF Applied(o) THEN pendingAcked \ {k} ELSE pendingAcked

----------------------------------------------------------------------------
(* Initial state: a daemon start over existing files. Keys already enrolled
   were audited when they were enrolled. *)

Init ==
    /\ reg \in SUBSET Keys
    /\ regStable = reg
    /\ regSynced = TRUE
    /\ queue \in SUBSET Keys
    /\ Cardinality(queue) <= MaxPending
    /\ queueStable = queue
    /\ queueSynced = TRUE
    /\ pendingAcked = {}
    /\ enrolledAcked = {}
    /\ audited = reg
    /\ ackedUnsynced = FALSE
    /\ rejectedEnrolled = FALSE

----------------------------------------------------------------------------
(* Client requests *)

\* RequestEnrolled answers "enrolled" to a key already in the registry. The
\* answer is read from the registry, so it waits for the registry to be
\* synced (ensureRegistryDurableLocked). The ackedUnsynced disjunct is the
\* EQ1 regression guard: it is FALSE because of the regSynced conjunct, and
\* dropping that conjunct flips it.
RequestEnrolled(k) ==
    /\ regSynced
    /\ k \in reg
    /\ enrolledAcked' = enrolledAcked \cup {k}
    /\ ackedUnsynced' = (ackedUnsynced \/ ~regSynced)
    /\ RegistryUnchanged /\ QueueUnchanged
    /\ UNCHANGED <<pendingAcked, audited, rejectedEnrolled>>

\* RequestQueued records a new request or refreshes a waiting one. A waiting
\* key does not count against the cap. The client is told "pending" only
\* when the write completed its syncs; a late failure records the request
\* (the operator can act on it) but answers an error so the client retries.
RequestQueued(k) ==
    /\ regSynced
    /\ k \notin reg
    /\ queueSynced
    /\ k \in queue \/ Cardinality(queue) < MaxPending
    /\ \E o \in Outcomes :
        LET acked == o = "ok" \/ (~RequireDurableAck /\ o = "late")
        IN  /\ PublishQueue(queue \cup {k}, o)
            /\ pendingAcked' = IF acked THEN pendingAcked \cup {k} ELSE pendingAcked
            /\ ackedUnsynced' = (ackedUnsynced \/ (acked /\ o # "ok"))
    /\ RegistryUnchanged
    /\ UNCHANGED <<enrolledAcked, audited, rejectedEnrolled>>

----------------------------------------------------------------------------
(* Operator answers *)

\* Approve enrolls the key of a waiting request and removes the request. The
\* registry is published first; a key that reached the live registry is
\* audited as enrolled whether or not that write was durable, and the
\* request is then cleared. Only an early registry failure leaves everything
\* untouched. A key already enrolled (an earlier approval whose queue write
\* failed) writes no registry and only clears the request.
Approve(k) ==
    /\ queueSynced /\ regSynced
    /\ k \in queue
    /\ IF k \in reg
       THEN /\ RegistryUnchanged
            /\ audited' = audited
            /\ ClearRequest(k)
       ELSE \E oR \in Outcomes :
            /\ PublishRegistry(reg \cup {k}, oR)
            /\ IF Applied(oR)
               THEN /\ audited' = audited \cup {k}
                    /\ ClearRequest(k)
               ELSE /\ audited' = audited
                    /\ QueueUnchanged
                    /\ pendingAcked' = pendingAcked
    /\ UNCHANGED <<enrolledAcked, ackedUnsynced, rejectedEnrolled>>

\* Reject drops a waiting request without enrolling its key. A request whose
\* key is already enrolled is refused (ErrAlreadyEnrolled): dropping it would
\* leave the key usable with no record that the operator ever answered. The
\* rejectedEnrolled disjunct is the EQ6 regression guard: FALSE because of
\* the k \notin reg conjunct, flipped if that check is dropped.
Reject(k) ==
    /\ queueSynced
    /\ k \in queue
    /\ k \notin reg
    /\ rejectedEnrolled' = (rejectedEnrolled \/ (k \in reg))
    /\ ClearRequest(k)
    /\ RegistryUnchanged
    /\ UNCHANGED <<enrolledAcked, audited, ackedUnsynced>>

\* Import enrolls a key the operator supplied directly. A waiting request for
\* the same key is cleared, but only after a fully durable registry write:
\* a late registry failure returns before touching the queue, so the key is
\* enrolled (and audited) while its request stays listed.
Import(k) ==
    /\ queueSynced /\ regSynced
    /\ IF k \in reg
       THEN /\ RegistryUnchanged
            /\ audited' = audited
            /\ IF k \in queue
               THEN ClearRequest(k)
               ELSE QueueUnchanged /\ pendingAcked' = pendingAcked
       ELSE \E oR \in Outcomes :
            /\ PublishRegistry(reg \cup {k}, oR)
            /\ audited' = IF Applied(oR) THEN audited \cup {k} ELSE audited
            /\ IF oR = "ok" /\ k \in queue
               THEN ClearRequest(k)
               ELSE QueueUnchanged /\ pendingAcked' = pendingAcked
    /\ UNCHANGED <<enrolledAcked, ackedUnsynced, rejectedEnrolled>>

\* Revoke removes an enrolled key. Once the removal is applied the key's
\* "enrolled" answer no longer stands (its connections are closed), durable
\* or not; a crash may then restore the key, which the revocation reported.
Revoke(k) ==
    /\ regSynced
    /\ k \in reg
    /\ \E o \in Outcomes :
        /\ PublishRegistry(reg \ {k}, o)
        /\ enrolledAcked' = IF Applied(o) THEN enrolledAcked \ {k} ELSE enrolledAcked
    /\ QueueUnchanged
    /\ UNCHANGED <<pendingAcked, audited, ackedUnsynced, rejectedEnrolled>>

----------------------------------------------------------------------------
(* Time, repair, and failure *)

\* Lapse drops a request that outlived enrollqueue.TTL. Every reader prunes
\* lapsed entries, so the live and stable contents lapse together, and the
\* client's "pending" is over: it requests again.
Lapse(k) ==
    /\ k \in queue \cup queueStable
    /\ queue' = queue \ {k}
    /\ queueStable' = queueStable \ {k}
    /\ pendingAcked' = pendingAcked \ {k}
    /\ RegistryUnchanged
    /\ UNCHANGED <<queueSynced, enrolledAcked, audited, ackedUnsynced, rejectedEnrolled>>

\* ResyncRegistry re-publishes the registry left by an earlier failed write
\* before any operation on it proceeds. A resync that fails again changes
\* nothing (a stutter), and the operation it preceded is answered with an
\* error.
ResyncRegistry ==
    /\ ~regSynced
    /\ PublishRegistry(reg, "ok")
    /\ QueueUnchanged
    /\ UNCHANGED <<pendingAcked, enrolledAcked, audited, ackedUnsynced, rejectedEnrolled>>

ResyncQueue ==
    /\ ~queueSynced
    /\ PublishQueue(queue, "ok")
    /\ RegistryUnchanged
    /\ UNCHANGED <<pendingAcked, enrolledAcked, audited, ackedUnsynced, rejectedEnrolled>>

\* Crash restarts the daemon. Each file comes back as either what it last
\* held or what was last durable, and the restart reads both files as the
\* state of record. Clients keep what they were told.
Crash ==
    /\ ~regSynced \/ ~queueSynced
    /\ reg' \in {reg, regStable}
    /\ regStable' = reg'
    /\ regSynced' = TRUE
    /\ queue' \in {queue, queueStable}
    /\ queueStable' = queue'
    /\ queueSynced' = TRUE
    /\ UNCHANGED <<pendingAcked, enrolledAcked, audited, ackedUnsynced, rejectedEnrolled>>

----------------------------------------------------------------------------
(* Next and Spec *)

Next ==
    \/ \E k \in Keys : RequestEnrolled(k)
    \/ \E k \in Keys : RequestQueued(k)
    \/ \E k \in Keys : Approve(k)
    \/ \E k \in Keys : Reject(k)
    \/ \E k \in Keys : Import(k)
    \/ \E k \in Keys : Revoke(k)
    \/ \E k \in Keys : Lapse(k)
    \/ ResyncRegistry
    \/ ResyncQueue
    \/ Crash

Spec == Init /\ [][Next]_vars

\* Keys are interchangeable for the safety invariants.
KeySymmetry == Permutations(Keys)

----------------------------------------------------------------------------
(* Invariants *)

\* TypeOK also pins the meaning of "synced": a synced file is its own stable
\* content.
TypeOK ==
    /\ reg \subseteq Keys
    /\ regStable \subseteq Keys
    /\ regSynced \in BOOLEAN
    /\ queue \subseteq Keys
    /\ queueStable \subseteq Keys
    /\ queueSynced \in BOOLEAN
    /\ pendingAcked \subseteq Keys
    /\ enrolledAcked \subseteq Keys
    /\ audited \subseteq Keys
    /\ ackedUnsynced \in BOOLEAN
    /\ rejectedEnrolled \in BOOLEAN
    /\ regSynced => regStable = reg
    /\ queueSynced => queueStable = queue

\* EQ1: no success answer is given on the strength of an unsynced file.
EQ1_NoAckFromUnsyncedFile == ~ackedUnsynced

\* EQ2: a request the client was told is pending is in the queue, across
\* crashes, until the operator answers it or it lapses.
EQ2_PendingAckSurvivesCrash == pendingAcked \subseteq queue

\* EQ3: a key the client was told is enrolled is in the registry, across
\* crashes, until it is revoked.
EQ3_EnrolledAckSurvivesCrash == enrolledAcked \subseteq reg

\* EQ4: every enrolled key was audited CLIENT_ENROLLED, including keys whose
\* registry write was applied but not durable.
EQ4_EnrolledKeysAudited == reg \subseteq audited

\* EQ5: the queue never exceeds its cap; refreshes do not grow it.
EQ5_QueueBounded == Cardinality(queue) <= MaxPending

\* EQ6: rejecting never drops the request of a key that is enrolled.
EQ6_RejectNeverStrandsEnrolledKey == ~rejectedEnrolled

Safety ==
    /\ TypeOK
    /\ EQ1_NoAckFromUnsyncedFile
    /\ EQ2_PendingAckSurvivesCrash
    /\ EQ3_EnrolledAckSurvivesCrash
    /\ EQ4_EnrolledKeysAudited
    /\ EQ5_QueueBounded
    /\ EQ6_RejectNeverStrandsEnrolledKey

=============================================================================
