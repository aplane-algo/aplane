# Audit Logging

apsigner maintains an append-only audit log that records security-relevant events. The log provides a structured trail for compliance and incident investigation.

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
| `txn_auth` | string | Signing key address (auth addr) |
| `txn_sender` | string | Transaction sender (if different from auth addr) |
| `txn_type` | string | Transaction type (`pay`, `axfer`, etc.) |
| `txn_details` | string | Human-readable transaction summary |
| `txid` | string | Transaction ID (after signing) |
| `remote_addr` | string | Client IP address (for auth failures, sessions) |
| `reason` | string | Event-specific detail such as rejection reason, key type, deleted filename, or SSH fingerprint |
| `policy_rule_id` | string | Matching policy rule for a rejection, forced review, or explicit auto-approval |
| `witness_key_id` | string | Public witness authority affected by a cosigner-reference mutation |
| `key_count` | int | Number of keys (for reload/start events) |
| `archive_sha256` | string | SHA-256 digest of a backup/restore archive |
| `replace_existing` | bool | Whether a credential restore was authorized to replace existing entries |
| `operation_id` | string | Durable restore operation identifier, or the request ID of a policy or ASA set change |
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
{"timestamp":"2026-02-28T16:01:12Z","event":"SIGN_REQUEST","requester_principal":"client:SHA256:example","transport":"http","outcome":"requested","txn_auth":"ABC...XYZ","txn_sender":"ABC...XYZ","txn_type":"pay","txn_details":"pay 1.5 ALGO to DEF...UVW"}
{"timestamp":"2026-02-28T16:01:12Z","event":"SIGN_APPROVED","requester_principal":"client:SHA256:example","approver_principal":"system:product-admin","transport":"http","outcome":"approved","txn_auth":"ABC...XYZ","txn_sender":"ABC...XYZ","txn_details":"txn 1/1 signed"}
{"timestamp":"2026-02-28T16:05:00Z","event":"SERVER_STOP"}
```

## Event Types

### Server Lifecycle

| Event | Description |
|-------|-------------|
| `SERVER_START` | Server started; `key_count` shows loaded keys |
| `SERVER_STOP` | Server shut down gracefully |
| `SERVER_STOP_INCOMPLETE` | A service failed to drain; `outcome` is `failed` and `reason` names the service error |
| `KEY_RELOAD` | Keys reloaded from keystore; `key_count` shows new count |

### Key Management

| Event | Description |
|-------|-------------|
| `KEY_GENERATED` | A new key was generated through the authenticated admin surface |
| `KEY_DELETED` | A key was deleted through the authenticated admin surface |
| `KEY_IMPORTED` | A key was imported through the authenticated admin surface |
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
If the intent cannot be written, the change is refused before it runs: with
`audit_unavailable` when the daemon has no audit log (it could not be opened
at startup; repair it and restart the daemon), or `audit_write_failed` when
the write failed (repair the cause and retry). The daemon still starts and
signs without an audit log; only these changes, restores and generation
maintenance require one. A failure to write the outcome is reported on the
daemon's stderr and never undoes or repeats the change. An intent with no
outcome, after a crash, is not proof that the change failed: the store's
generation records say what committed. Offline `apadmin policy rescue` and
`apstore policy sign` run without the daemon and write no audit entries.

### Signing

| Event | Description |
|-------|-------------|
| `SIGN_REQUEST` | Transaction submitted for signing |
| `SIGN_APPROVED` | Transaction signed successfully by the signer (not emitted for passthrough or foreign entries) |
| `SIGN_REJECTED` | Transaction rejected by policy or operator |
| `SIGN_FAILED` | Signing failed due to a technical error (key not found, assembly error, etc.) |

### Authentication

| Event | Description |
|-------|-------------|
| `AUTH_FAILED` | Authentication attempt failed; `remote_addr` identifies the client |
| `AUTH_FAILURES_SUPPRESSED` | Unauthenticated failures beyond the rate limit (a burst of 20, then one per 6 seconds) were counted instead of logged individually; `suppressed_count` is the number |
| `COSIGNER_REJECTIONS_SUPPRESSED` | Cosigner policy rejections beyond the same rate limit were counted instead of logged individually; `suppressed_count` is the number. Cosigner signatures are always logged individually |
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
