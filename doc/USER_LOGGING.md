# Audit Logging

apsignerd maintains an append-only audit log that records security-relevant events. The log provides a tamper-evident trail for compliance and incident investigation.

## Log Location

The audit log is written to `audit.log` in the apsignerd data directory:

```
$APSIGNER_DATA/audit.log
```

- File permissions: `0600` (owner read/write only)
- Created automatically on server startup
- If the log cannot be opened, apsignerd prints a warning and continues without audit logging

## Log Format

Each line is a JSON object with the following fields:

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | string | UTC timestamp (RFC 3339) |
| `event` | string | Event type (see below) |
| `principal` | string | Authenticated identity (e.g., `"default"`) |
| `txn_auth` | string | Signing key address (auth addr) |
| `txn_sender` | string | Transaction sender (if different from auth addr) |
| `txn_type` | string | Transaction type (`pay`, `axfer`, etc.) |
| `txn_details` | string | Human-readable transaction summary |
| `txid` | string | Transaction ID (after signing) |
| `remote_addr` | string | Client IP address (for auth failures, sessions) |
| `reason` | string | Rejection or failure reason |
| `key_count` | int | Number of keys (for reload/start events) |

Fields are omitted when empty.

### Example Entries

```json
{"timestamp":"2026-02-28T16:00:00Z","event":"SERVER_START","key_count":3}
{"timestamp":"2026-02-28T16:00:05Z","event":"SESSION_CONNECTED","principal":"default","remote_addr":"127.0.0.1:44820","reason":"admin"}
{"timestamp":"2026-02-28T16:01:12Z","event":"SIGN_REQUEST","principal":"default","txn_auth":"ABC...XYZ","txn_sender":"ABC...XYZ","txn_details":"pay 1.5 ALGO to DEF...UVW"}
{"timestamp":"2026-02-28T16:01:12Z","event":"SIGN_APPROVED","principal":"default","txn_auth":"ABC...XYZ","txn_sender":"ABC...XYZ","txn_details":"txn 1/1 signed"}
{"timestamp":"2026-02-28T16:05:00Z","event":"SERVER_STOP"}
```

## Event Types

### Server Lifecycle

| Event | Description |
|-------|-------------|
| `SERVER_START` | Server started; `key_count` shows loaded keys |
| `SERVER_STOP` | Server shut down gracefully |
| `KEY_RELOAD` | Keys reloaded from keystore; `key_count` shows new count |

### Signing

| Event | Description |
|-------|-------------|
| `SIGN_REQUEST` | Transaction submitted for signing |
| `SIGN_APPROVED` | Transaction signed successfully |
| `SIGN_REJECTED` | Transaction rejected by policy or operator |
| `SIGN_FAILED` | Signing failed due to a technical error (key not found, assembly error, etc.) |

### Authentication

| Event | Description |
|-------|-------------|
| `AUTH_FAILED` | Authentication attempt failed; `remote_addr` identifies the client |

### Sessions

| Event | Description |
|-------|-------------|
| `SESSION_CONNECTED` | IPC or SSH session established |
| `SESSION_DISCONNECTED` | Session ended |
| `TOKEN_PROVISIONED` | API token provisioned via SSH connection |

## Log Rotation

The audit log rotates automatically when it reaches **10 MB**:

1. The current `audit.log` is renamed to `audit.log.1`
2. A new `audit.log` is created
3. Only one backup (`.1`) is kept; previous backups are overwritten

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
