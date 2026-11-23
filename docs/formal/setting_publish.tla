--------------------------- MODULE setting_publish ---------------------------
(*
When a change to a writable signer setting takes effect, relative to its save.

A boolean setting has a restrictive value (require_contained,
require_cosigner and lock_on_disconnect: true; user_auto_approve: false).
The signer reads the value in effect from memory; the file is what the next
start loads. The rule in
internal/signerapp/admin/service.go::updateAdminSettingLocked is that a
change toward the restrictive value is published before its save and stays
in effect if the save fails, reported unsaved, and that any other change is
published only once its save has put the new file in place.

Invariants:

  - SP1 : the value in effect is never more permissive than the file's.
  - SP2 : outside an update, a value in effect that differs from the file's
          is reported unsaved, and an unsaved value is the restrictive one.
  - SP3 : a restrictive request is in effect for as long as its save takes.
  - SP4 : the answer matches the state: a success leaves memory and file on
          the requested value; "applied, not saved" leaves the restrictive
          value in effect and unsaved; a plain or audit failure changed
          nothing in effect.
  - SP5 : a non-restrictive update never reaches save, placement, or ok
          without a durable intent audit record, and a restrictive update
          never blocks on auditing.

The model covers one setting. Settings are independent: each has its own
unsaved flag, an update runs under the store mutation lock, and the save
rewrites only its own key.

The model intentionally omits:

  - passphrase_timeout and theme, which are never restrictive and follow the
    permissive path (durable intent audit before save),
  - the headless refusals of lock_on_disconnect and passphrase_timeout,
  - a hand edit of the file while the signer runs (it takes effect at the
    next start; the signer makes no check for one),
  - the directory flush after the rename: its failure
    (fsutil.ErrPublishedNotDurable) leaves the new file in place and is a
    success, SavePlaced then Publish here,
  - the best-effort SETTING_CHANGED and SETTING_SAVE_ERROR outcome entries
    written after the save returns.

See FORMAL_TLA_SETTING_PUBLISH_MODEL.md for the prose companion.
*)
EXTENDS TLC

CONSTANTS
    RestrictiveFirst,          \* a restrictive change is published before its save
    PermissiveAfterSave,       \* any other change is published only after its save
    AuditPermissiveBeforeSave  \* a non-restrictive change durably records intent before its save

ASSUME RestrictiveFirst \in BOOLEAN
ASSUME PermissiveAfterSave \in BOOLEAN
ASSUME AuditPermissiveBeforeSave \in BOOLEAN

\* TRUE is the restrictive value throughout.
Result == {"none", "ok", "applied_not_saved", "failed", "audit_failed"}

VARIABLES
    mem,        \* the value in effect
    file,       \* the value the next start loads
    unsaved,    \* the signer reports the setting unsaved
    pc,         \* "idle", "auditing", "saving", or "placed": an update holds the
                \* store mutation lock
    req,        \* the value the update in progress asked for
    early,      \* the update in progress took the restrictive path
    audited,    \* the update in progress durably recorded its intent before saving
    result      \* the last update's answer

vars == <<mem, file, unsaved, pc, req, early, audited, result>>

Init ==
    /\ file \in BOOLEAN
    /\ mem = file
    /\ unsaved = FALSE
    /\ pc = "idle"
    /\ req = FALSE
    /\ early = FALSE
    /\ audited = FALSE
    /\ result = "none"

\* restricts(): the request is for the restrictive value, and that value is
\* not yet in effect or is in effect ahead of the file.
Restricts(v) == v /\ (~mem \/ unsaved)

Begin(v) ==
    /\ pc = "idle"
    /\ req' = v
    /\ early' = Restricts(v)
    /\ audited' = FALSE
    /\ result' = "none"
    /\ IF Restricts(v)
          THEN /\ pc' = "saving"
               /\ IF RestrictiveFirst
                     THEN mem' = TRUE /\ unsaved' = TRUE
                     ELSE UNCHANGED <<mem, unsaved>>
          ELSE /\ pc' = IF AuditPermissiveBeforeSave THEN "auditing" ELSE "saving"
               /\ IF ~PermissiveAfterSave
                     THEN mem' = v /\ UNCHANGED unsaved
                     ELSE UNCHANGED <<mem, unsaved>>
    /\ UNCHANGED file

\* The durable SETTING_CHANGE_INTENT write succeeds for a non-restrictive update.
AuditDurable ==
    /\ pc = "auditing"
    /\ audited' = TRUE
    /\ pc' = "saving"
    /\ UNCHANGED <<mem, file, unsaved, req, early, result>>

\* The audit log is unavailable or its durable write fails: the non-restrictive
\* update is refused without touching the file or memory.
AuditFail ==
    /\ pc = "auditing"
    /\ result' = "audit_failed"
    /\ pc' = "idle"
    /\ UNCHANGED <<mem, file, unsaved, req, early, audited>>

\* The save's rename puts the new file in place.
SavePlaced ==
    /\ pc = "saving"
    /\ file' = req
    /\ pc' = "placed"
    /\ UNCHANGED <<mem, unsaved, req, early, audited, result>>

\* Memory follows the file and is no longer ahead of it.
Publish ==
    /\ pc = "placed"
    /\ mem' = req
    /\ unsaved' = FALSE
    /\ result' = "ok"
    /\ pc' = "idle"
    /\ UNCHANGED <<file, req, early, audited>>

\* The old file is still in place. A restrictive value stays in effect and
\* unsaved; any other value was never published.
SaveFail ==
    /\ pc = "saving"
    /\ result' = IF early THEN "applied_not_saved" ELSE "failed"
    /\ pc' = "idle"
    /\ UNCHANGED <<mem, file, unsaved, req, early, audited>>

\* A restart, or a crash at any point of an update: the save replaces the
\* file in one rename, so the file holds the old value or the new one.
\* Restarting from "placed" is a crash after the rename.
Restart ==
    /\ mem' = file
    /\ unsaved' = FALSE
    /\ pc' = "idle"
    /\ audited' = FALSE
    /\ result' = "none"
    /\ UNCHANGED <<file, req, early>>

Next ==
    \/ \E v \in BOOLEAN : Begin(v)
    \/ AuditDurable
    \/ AuditFail
    \/ SavePlaced
    \/ Publish
    \/ SaveFail
    \/ Restart

Spec == Init /\ [][Next]_vars

----------------------------------------------------------------------------
TypeOK ==
    /\ mem \in BOOLEAN
    /\ file \in BOOLEAN
    /\ unsaved \in BOOLEAN
    /\ pc \in {"idle", "auditing", "saving", "placed"}
    /\ req \in BOOLEAN
    /\ early \in BOOLEAN
    /\ audited \in BOOLEAN
    /\ result \in Result

\* SP1: a signing request, which reads mem at any moment, never sees a
\* permissive value where the file holds the restrictive one.
SP1_NeverMorePermissiveThanFile == file => mem

\* SP2: memory ahead of the file is reported, and only a restrictive value
\* is ever ahead.
SP2_AheadOfFileIsReported ==
    /\ (pc = "idle" /\ mem # file) => unsaved
    /\ unsaved => mem

\* SP3: a restrictive request is in effect from the start of its update.
SP3_RestrictiveInEffectDuringSave == (pc # "idle" /\ req) => mem

\* SP4: the answer matches the state it reports.
SP4_AnswerMatchesState ==
    /\ result = "ok" => (mem = req /\ file = req /\ ~unsaved)
    /\ result = "applied_not_saved" => (mem /\ unsaved)
    /\ result = "failed" => (mem = file \/ unsaved)
    /\ result = "audit_failed" => (~early /\ (mem = file \/ unsaved))

\* SP5: a non-restrictive update never saves, places, or succeeds without a
\* durable intent audit record, and a restrictive update never enters auditing.
SP5_AuditDirectionRule ==
    /\ (~early /\ pc \in {"saving", "placed"}) => audited
    /\ (~early /\ result = "ok") => audited
    /\ (pc = "auditing") => ~early

Safety ==
    /\ TypeOK
    /\ SP1_NeverMorePermissiveThanFile
    /\ SP2_AheadOfFileIsReported
    /\ SP3_RestrictiveInEffectDuringSave
    /\ SP4_AnswerMatchesState
    /\ SP5_AuditDirectionRule

=============================================================================
