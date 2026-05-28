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
| `identity_id` | string | Owning signer identity; omitted for process-level events |
| `target_identity_id` | string | Signer identity targeted by the action |
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
| `key_count` | int | Number of keys (for reload/start events) |

Fields are omitted when empty.

### Example Entries

```json
{"timestamp":"2026-02-28T16:00:00Z","event":"SERVER_START","key_count":3}
{"timestamp":"2026-02-28T16:00:05Z","event":"SESSION_CONNECTED","identity_id":"default","target_identity_id":"default","principal":"system:product-admin","requester_principal":"system:product-admin","admin_session_id":"admin-1","transport":"ipc","outcome":"connected","remote_addr":"local"}
{"timestamp":"2026-02-28T16:01:12Z","event":"SIGN_REQUEST","identity_id":"default","target_identity_id":"default","requester_principal":"default","transport":"http","outcome":"requested","txn_auth":"ABC...XYZ","txn_sender":"ABC...XYZ","txn_type":"pay","txn_details":"pay 1.5 ALGO to DEF...UVW"}
{"timestamp":"2026-02-28T16:01:12Z","event":"SIGN_APPROVED","identity_id":"default","target_identity_id":"default","requester_principal":"default","approver_principal":"system:product-admin","transport":"http","outcome":"approved","txn_auth":"ABC...XYZ","txn_sender":"ABC...XYZ","txn_details":"txn 1/1 signed"}
{"timestamp":"2026-02-28T16:05:00Z","event":"SERVER_STOP"}
```

The examples show `"default"` as the identity. See [ARCH_OVERVIEW.md](ARCH_OVERVIEW.md) (Identity Model).

## Event Types

### Server Lifecycle

| Event | Description |
|-------|-------------|
| `SERVER_START` | Server started; `key_count` shows loaded keys |
| `SERVER_STOP` | Server shut down gracefully |
| `KEY_RELOAD` | Keys reloaded from keystore; `key_count` shows new count |

### Key Management

| Event | Description |
|-------|-------------|
| `KEY_GENERATED` | A new key was generated through the authenticated admin surface |
| `KEY_DELETED` | A key was deleted through the authenticated admin surface |
| `KEY_IMPORTED` | A key was imported through the authenticated admin surface |
| `KEY_REJECTED` | A key file was skipped during signer scan because it violated a load-time key-file invariant |
| `BACKUP_CREATED` | A key backup was created through the authenticated admin surface |
| `BACKUP_FAILED` | A key backup failed through the authenticated admin surface |
| `BACKUP_RESTORE_PREVIEWED` | A managed backup restore preview succeeded through the authenticated admin surface |
| `BACKUP_RESTORE_PREVIEW_FAILED` | A managed backup restore preview failed through the authenticated admin surface |
| `BACKUP_RESTORE_STARTED` | A managed backup restore operation started through the authenticated admin surface |
| `BACKUP_RESTORE_COMPLETED` | A managed backup restore operation completed through the authenticated admin surface |
| `BACKUP_RESTORE_PARTIAL` | A managed backup restore operation restored at least one key and failed at least one key |
| `BACKUP_RESTORE_FAILED` | A managed backup restore operation failed before restoring a key |
| `STORE_INITIALIZED` | Store initialization succeeded through authenticated local IPC |
| `STORE_INITIALIZE_FAILED` | Store initialization failed through authenticated local IPC |
| `PASSPHRASE_CHANGED` | Store passphrase rotation succeeded through authenticated local IPC |
| `PASSPHRASE_CHANGE_FAILED` | Store passphrase rotation failed through authenticated local IPC |

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
| `AUTHORIZATION_DENIED` | Authenticated admin principal lacked authorization for the requested action/resource |

### Sessions

| Event | Description |
|-------|-------------|
| `SESSION_CONNECTED` | IPC or SSH session established |
| `SESSION_DISCONNECTED` | Session ended |
| `IDENTITY_LOCKED` | Identity locked through an authenticated admin session |
| `TOKEN_PROVISIONED` | API token provisioned via SSH connection |

## Log Rotation

The audit log rotates automatically when it reaches **10 MB**:

1. Any existing `audit.log.1` is moved to `audit.log.2`
2. The current `audit.log` is renamed to `audit.log.1`
3. A new `audit.log` is created

Up to two rotated backups are retained (`audit.log.1` and `audit.log.2`).

If rotation fails, logging continues to the current file.

## Durability

Each log entry is flushed to disk immediately (`fsync`) after writing. This ensures entries survive unexpected crashes but may have a minor performance cost under high signing throughput.

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
