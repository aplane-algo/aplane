# Audit Logging

apsigner maintains an append-only audit log that records security-relevant events. The log provides a structured trail for compliance and incident investigation.

This page covers the signer's audit log. To see more or less diagnostic output from `apshell` or apconsole, use [`loglevel`](USER_COMMANDS.md#loglevel).

## Log Location

The audit log is written to `audit.log` in the apsigner data directory:

```
$APSIGNER_DATA/audit.log
```

- File permissions: `0600` (owner read/write only)
- Created automatically on server startup
- If the log cannot be opened, apsigner prints a warning and continues without audit logging

## Log Format

Each line is a JSON object with the following fields:

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | string | UTC timestamp (RFC 3339) |
| `event` | string | Event type (see below) |
| `principal` | string | Principal performing the action |
| `requester_principal` | string | Principal requesting the action |
| `approver_principal` | string | Principal approving or rejecting the action |
| `admin_session_id` | string | Admin protocol session ID |
| `transport` | string | Admin or signing transport, such as `ipc`, `ssh`, or `http` |
| `outcome` | string | Event outcome, such as `requested`, `approved`, `rejected`, `failed`, or `connected` |
| `txn_auth` | string | Signing key address (auth addr). Omitted on an entry for a position the signer does not sign: a passthrough or foreign position in a `SIGN_REJECTED`, for example |
| `txn_sender` | string | Transaction sender (if different from auth addr) |
| `txn_type` | string | Transaction type (`pay`, `axfer`, etc.) |
| `txn_details` | string | Human-readable transaction summary |
| `txid` | string | On `SIGN_APPROVED`, `ROTATING_RELEASE` and a withheld rotating signature's `SIGN_FAILED`: the ID of the transaction as signed, after the signer's planning. On a `SIGN_REJECTED` for a signer-invariant refusal: the ID of the entry's transaction as planned in the group the signer was asked to sign, which the signer did not sign (for a cosigned component or a rotating sign, the ID of the bytes the client presented) |
| `fee` | int | `SIGN_APPROVED`: the signed transaction's final fee in microAlgos; `0` is written. A `SIGN_REJECTED` for a signer-invariant refusal: that transaction's fee as planned |
| `group_id` | string | `SIGN_APPROVED` and a withheld rotating signature's `SIGN_FAILED`: the final group ID (base64), when the transaction was signed in a group. A `SIGN_REJECTED` for a signer-invariant refusal: the planned group's ID, when the transaction is in a group, so that refusal's entries join by it |
| `group_txids` | string[] | `SIGN_APPROVED`, and a `SIGN_REJECTED` for a signer-invariant refusal: every transaction ID of that group, in group order |
| `dummy_count` | int | `SIGN_APPROVED`, and a `SIGN_REJECTED` for a signer-invariant refusal: how many of `group_txids`, at the end, are dummies the request added that the signer signs itself (on a `SIGN_REJECTED`, would have signed); none for a cosigned component, whose dummies the client signs |
| `remote_addr` | string | Client IP address (for auth failures, sessions) |
| `reason` | string | Event-specific detail such as rejection reason, key type, deleted filename, or SSH fingerprint |
| `policy_rule_id` | string | Matching policy rule for a rejection, forced review, or explicit auto-approval |
| `witness_key_id` | string | Public witness authority affected by a cosigner-reference mutation |
| `key_count` | int | Number of keys (for reload/start events) |
| `archive_sha256` | string | SHA-256 digest of a backup/restore archive |
| `replace_existing` | bool | Whether a credential restore was authorized to replace existing entries |
| `operation_id` | string | Durable restore operation identifier, or the request ID of a policy or ASA set change, or the ID of a signing or planning request (the client's `request_id` when it sent one, else a random ID the signer minted; see [Signing](#signing)) |
| `result_code` | string | Result code of a failed or uncertain policy or ASA set change |
| `changed` | bool | On a succeeded policy or ASA set change only: whether it minted a generation (`false` is written, for a policy apply that changed nothing) |
| `generation_id` | string | Generation a change minted, also when its commit is uncertain |
| `policy_updates`, `policy_removals` | string[] | Selectors a policy apply submits or removes, at most 64 each |
| `policy_updates_omitted`, `policy_removals_omitted` | int | Selectors left out of those lists |
| `expected_policy_set_sha256`, `expected_snapshot_sha256` | string | The digests an apply request expects: the request's claim, not verified state |
| `base_policy_set_sha256`, `policy_set_sha256` | string | The verified policy set an apply changed, and the set it left |
| `asa_action` | string | `add` or `remove` |
| `network`, `genesis_hash`, `asset_id` | | The asset an ASA set change names; on an outcome, the chain it was resolved to |

Fields are omitted when empty.

### Example Entries

```json
{"timestamp":"2026-02-28T16:00:00Z","event":"SERVER_START","key_count":3}
{"timestamp":"2026-02-28T16:00:05Z","event":"SESSION_CONNECTED","principal":"system:product-admin","requester_principal":"system:product-admin","admin_session_id":"admin-1","transport":"ipc","outcome":"connected","remote_addr":"local"}
{"timestamp":"2026-02-28T16:01:10Z","event":"PLAN_REQUEST","principal":"client:SHA256:example","requester_principal":"client:SHA256:example","transport":"http","outcome":"requested","txn_auth":"ABC...XYZ","txn_sender":"ABC...XYZ","txn_details":"pay 1.5 ALGO to DEF...UVW","operation_id":"plan-1"}
{"timestamp":"2026-02-28T16:01:12Z","event":"SIGN_REQUEST","principal":"client:SHA256:example","requester_principal":"client:SHA256:example","transport":"http","outcome":"requested","txn_auth":"ABC...XYZ","txn_sender":"ABC...XYZ","txn_details":"pay 1.5 ALGO to DEF...UVW","operation_id":"sign-1"}
{"timestamp":"2026-02-28T16:01:12Z","event":"SIGN_APPROVED","principal":"client:SHA256:example","requester_principal":"client:SHA256:example","approver_principal":"system:product-admin","transport":"http","outcome":"approved","txn_auth":"ABC...XYZ","txn_sender":"ABC...XYZ","txn_details":"txn 1/1 signed","txid":"TXA...","operation_id":"sign-1","fee":3000,"group_id":"Gk1...=","group_txids":["TXA...","TXD..."],"dummy_count":1}
{"timestamp":"2026-02-28T16:05:00Z","event":"SERVER_STOP"}
```

## Event Types

### Server Lifecycle

| Event | Description |
|-------|-------------|
| `SERVER_START` | Server started; `key_count` shows loaded keys |
| `SERVER_STOP` | Server shut down gracefully |
| `SERVER_STOP_INCOMPLETE` | A service failed to drain, or a key use still held key material at the shutdown deadline; `outcome` is `failed` and `reason` names the service error or the key use |
| `KEY_RELOAD` | Keys reloaded from keystore; `key_count` shows new count |

### Key Management

| Event | Description |
|-------|-------------|
| `KEY_GENERATED` | A new key was generated through the authenticated admin surface |
| `KEY_DELETED` | A key was deleted through the authenticated admin surface |
| `KEY_IMPORTED` | A key was imported through the authenticated admin surface |
| `KEY_EXPORTED` | A recovery-material export attempt was recorded; `outcome` identifies the result |
| `KEY_REJECTED` | A key file was skipped during signer scan because it violated a load-time key-file invariant |
| `BACKUP_CREATED` | A key backup was created through the authenticated admin surface |
| `BACKUP_IMPORTED` | A deeply verified uploaded backup was published into managed storage |
| `BACKUP_EXPORT_STARTED` | An authenticated client began reading a managed backup archive; a non-zero initial offset is still audited |
| `BACKUP_FAILED` | A key backup failed through the authenticated admin surface |
| `BACKUP_RESTORE_PREVIEWED` | A managed backup restore preview succeeded through the authenticated admin surface |
| `BACKUP_RESTORE_PREVIEW_FAILED` | A managed backup restore preview failed through the authenticated admin surface |
| `CREDENTIAL_RESTORE_INTENT` | A direct restore was requested; written and fsynced before active-store mutation |
| `CREDENTIAL_RESTORE_SUCCEEDED` | Credential restore committed and reloaded successfully |
| `CREDENTIAL_RESTORE_FAILED` | Credential restore failed; a reload failure after commit enters recovery mode and requires explicit reconciliation or eligible rollback |
| `CREDENTIAL_RESTORE_COMMIT_UNCERTAIN` | A restore's replacement `store-root.enc` is visible but durability is unconfirmed; signing remains recovery-blocked pending reconciliation |
| `CREDENTIAL_RESTORE_ROLLBACK` | Explicit restore rollback succeeded or failed |
| `STORE_INITIALIZED` | Store initialization succeeded through authenticated local IPC |
| `STORE_INITIALIZE_FAILED` | Store initialization failed through authenticated local IPC |
| `PASSPHRASE_CHANGED` | Store passphrase rotation succeeded through authenticated local IPC |
| `PASSPHRASE_CHANGE_FAILED` | Store passphrase rotation failed through authenticated local IPC |
| `COSIGNER_REFERENCE_CHANGED` | A product cosigner-reference catalog record was imported, promoted, or removed |

Credential restore entries may include `archive_sha256`, `operation_id`,
`replace_existing`, and `key_count`, in addition to normal session/
principal/transport attribution.

### Generation and Deleted-Archive Maintenance

Maintenance records intent before destructive work and records its outcome:

| Event pair | Operation |
|------------|-----------|
| `GENERATION_QUARANTINE_INTENT` / `GENERATION_QUARANTINED` | Quarantine a non-authoritative generation |
| `GENERATION_QUARANTINE_PRUNE_INTENT` / `GENERATION_QUARANTINE_PRUNED` | Prune a quarantined generation |
| `GENERATION_ABANDONED_DISCARD_INTENT` / `GENERATION_ABANDONED_DISCARDED` | Discard an abandoned, unvalidatable generation |
| `DELETED_ARCHIVE_PRUNE_INTENT` / `DELETED_ARCHIVE_PRUNED` | Prune selected deleted-archive entries through the admin protocol |

See [store maintenance](USER_STORE_MGMT.md) for restrictions and the current
CLI limitation on deleted-archive pruning.

### Policy and ASA Set Changes

| Event | Description |
|-------|-------------|
| `POLICY_APPLY_INTENT` | An `apply_policy` request was received; written and fsynced before the change runs |
| `POLICY_APPLY_SUCCEEDED` | The apply succeeded; `changed` says whether it minted a generation |
| `POLICY_APPLY_FAILED` | The apply was refused or failed before committing |
| `POLICY_APPLY_COMMIT_UNCERTAIN` | The apply's generation may be committed but is unconfirmed, or the runtime did not reload it; signing is blocked pending recovery |
| `ASA_SET_UPDATE_INTENT` | An `add_asa` or `remove_asa` request was received; written and fsynced before the change runs |
| `ASA_SET_UPDATE_SUCCEEDED` | The ASA set change committed |
| `ASA_SET_UPDATE_FAILED` | The change was refused or failed before committing |
| `ASA_SET_UPDATE_COMMIT_UNCERTAIN` | As for a policy apply |

Each change writes one intent and then one outcome, both with the admin
session's attribution and the request ID as `operation_id`. Entries name
documents by selector and assets by chain and ID, never document contents.
Every string taken from the request or an error is cut to 128 bytes (1024
for `reason`), with its original length noted, so a malformed request
cannot write a large entry. An `operation_id` longer than 128 bytes, in any
entry, is written as its first 32 bytes followed by `…sha256:` and the
digest of the whole ID, the same in the intent and the outcome.
If the intent cannot be written, the change is refused before it runs: with
`audit_unavailable` when the daemon has no audit log (it could not be opened
at startup; repair it and restart the daemon), or `audit_write_failed` when
the write failed (repair the cause and retry). The daemon still starts and
signs without an audit log; only these changes, restores and generation
maintenance require one. Restores and generation maintenance keep their own
result codes (`restore_audit_failed`, `quarantine_audit_failed`,
`abandoned_discard_audit_failed`, `archive_audit_failed`), with the same
advice: restart when the daemon has no audit log, retry after a failed
write. A failure to write the outcome is reported on the
daemon's stderr and never undoes or repeats the change. An intent with no
outcome, after a crash, is not proof that the change failed: the store's
generation records say what committed. Offline `apadmin policy rescue` and
`apstore policy sign` run without the daemon and write no audit entries.

### Signing

| Event | Description |
|-------|-------------|
| `SIGN_REQUEST` | Transaction submitted for signing, as the client sent it, before the signer's planning |
| `PLAN_REQUEST` | Transaction submitted to `/plan`, which signs nothing; the same fields as `SIGN_REQUEST`. `/plan` writes no other signing entry |
| `SIGN_APPROVED` | Transaction signed by the signer, one entry per transaction signed with a key (not emitted for passthrough or foreign entries). It records the transaction as signed: planning may have raised its fee, set its group ID and added dummies, so `txid`, `fee`, `group_id` and `group_txids` are those of the transactions returned to the client, not of the request |
| `SIGN_REJECTED` | Transaction rejected. A refusal before the operator names its source in the reason: `signer_invariant:` (a refusal no policy can allow, such as a nonparticipating `keyreg`, on either node role, or a rekey to a held aplane key that is not a valid rekey target), `policy_engine_rejected:` (the signer's policy) or `cosigner_policy_rejected:` (a cosigner's policy). Other reasons record the operator's decision. A signer-invariant refusal on the signer names one position: it writes an entry for each position the signer signs and one for the named position, even a passthrough or foreign one, and every one of them identifies its transaction as planned with the `txid`, `fee`, `group_id`, `group_txids` and `dummy_count` a `SIGN_APPROVED` for it would have had. A policy refusal writes an entry per position the signer signs, with no `txid`. A request refused before the signer's gates, for example `bounded_cosigner_required`, writes none |
| `SIGN_FAILED` | Signing failed due to a technical error (key not found, assembly error, etc.). A rotating signature refused at the last check after it was recorded as signed is a `SIGN_FAILED` whose `reason` begins `signature withheld after it was recorded as signed`. It has the `txid` and `group_id` of that `SIGN_APPROVED`, so a search on either finds both: the signature never left the signer |
| `ROTATING_RELEASE` | A rotating-account signature was released; retained records rebuild release and leaf-use history after unlock |
| `ROTATING_RECOVERY` | A rotating-account recovery action or outcome was recorded |

Every entry a signing or planning request writes carries the request's ID
as `operation_id`. For a request that sent a `request_id`, that is the
client's ID, and the client chooses it: it can send the same ID twice or
one that looks like the signer's, and entries sharing it then belong to
more than one request, so keeping it unique is the client's job. For a
request sent without one, the signer mints a random ID, `req-` and 16 hex
digits (64 random bits, so two minted IDs do not repeat in practice).
`/sign/component` and
`/sign/assemble` return the ID as `request_id`, and while a request waits
for approval the signer's console shows the first 20 characters of its
ID, all of a minted one. So one request reads as a sequence: its
`SIGN_REQUEST` entries (what was asked), then either a `SIGN_APPROVED` per
transaction signed or the `SIGN_REJECTED` or `SIGN_FAILED` entries that
stopped it. A request with no outcome entry was not signed: it was
cancelled, found no apadmin connected to approve it, was stopped by a
lock, or was refused before the signer's gates ran (a planning error, or
`bounded_cosigner_required`, for example). To find what was signed in a group on chain, search for `group_id` or
any of `group_txids`. No signing entry records key material, signatures or
LogicSig argument values.

### Authentication

| Event | Description |
|-------|-------------|
| `AUTH_FAILED` | Authentication attempt failed; `remote_addr` identifies the client |
| `AUTH_FAILURES_SUPPRESSED` | Unauthenticated failures beyond the rate limit (a burst of 20, then one per 6 seconds) were counted instead of logged individually; `suppressed_count` is the number |
| `COSIGNER_REJECTIONS_SUPPRESSED` | Cosigner rejections (policy rejections and signer-invariant refusals) beyond the same rate limit were counted instead of logged individually; `suppressed_count` is the number. Cosigner signatures are always logged individually |
| `AUTHORIZATION_DENIED` | Authenticated admin principal lacked authorization for the requested action/resource |

### Sessions

| Event | Description |
|-------|-------------|
| `SESSION_CONNECTED` | IPC admin session established |
| `SESSION_DISCONNECTED` | Session ended |
| `IDENTITY_LOCKED` | Signing authority locked through an authenticated admin session |
| `CLIENT_ENROLLMENT_REQUESTED` | A client asked to be enrolled; the request waits for the operator (principal `client:<fingerprint>`, `client_label` carries the requested label) |
| `CLIENT_ENROLLED` | Client SSH key enrolled by the operator, by approving its request or importing the key (`client_label` carries its display label; `remote_addr` is empty for an import) |
| `CLIENT_ENROLLMENT_REJECTED` | The operator rejected a waiting enrollment request |
| `CLIENT_KEY_REVOKED` | Enrolled client SSH key revoked by the operator; its connections were closed |

## Log Rotation

The audit log rotates automatically when it reaches **10 MB**:

1. Any existing `audit.log.1` is moved to `audit.log.2`
2. The current `audit.log` is renamed to `audit.log.1`
3. A new `audit.log` is created

Up to two rotated backups are retained (`audit.log.1` and `audit.log.2`).

If rotation fails, logging continues to the current file.

### Entry size

Every entry is bounded, whatever a request sent, so one request cannot push
the retained history out of the log:

- `reason` and `txn_details` are at most 8 KiB, which holds a signing
  rejection's violations for a full group; a longer one keeps its start and
  notes its original length.
- Every other text field (addresses, transaction IDs, principals, digests,
  network names and so on) is at most 128 bytes. Real values are far
  shorter and are logged exactly; this only cuts what a malformed request
  sent, such as an oversized `auth_address` in a signing request that is
  then refused.
- `operation_id` over 128 bytes becomes its first 32 bytes, `…sha256:` and
  the digest of the whole ID.
- `generation_ids` and `archive_entries` list at most 64 members of at most
  128 bytes each. A longer list is a **sample**: `generation_ids_omitted` or
  `archive_entries_omitted` counts the members left out, and their names are
  not recorded anywhere in the log. The operation itself still receives and
  acts on the whole selection. `group_txids` has the same bound
  (`group_txids_omitted`), which a group of at most 16 transactions never
  reaches.
- The policy and ASA set fields have their own, tighter bounds in
  [Policy and ASA Set Changes](#policy-and-asa-set-changes).

This keeps any one request from flushing the log, but not many requests:
enough of them can still rotate older entries out of the 30 MB retained.
Copy the log elsewhere if you need longer retention.

## Durability

Each log entry is flushed to disk immediately (`fsync`) after writing, which
may have a minor performance cost under high signing throughput. Write and sync
failures are reported rather than silent; an entry whose flush failed is not
guaranteed to survive a crash.

## Inspecting the Log

Since each line is a JSON object, standard tools work well:

```bash
# View all events
cat $APSIGNER_DATA/audit.log | jq .

# Filter signing events
grep SIGN_ $APSIGNER_DATA/audit.log | jq .

# Show auth failures
grep AUTH_FAILED $APSIGNER_DATA/audit.log | jq .

# Count events by type
jq -r .event $APSIGNER_DATA/audit.log | sort | uniq -c | sort -rn
```
