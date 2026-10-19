# Security Architecture

This document describes APlane's security architecture: authentication channels,
SSH transport security, the closed single-product authorization model
(principals, stable actions, resources, and enforcement points), passphrase and
key handling, audit, cache integrity, and defense-in-depth controls.

## Contents

- [Overview](#overview)
- [Authentication Channels](#authentication-channels)
- [Connection Models Compared](#connection-models-compared)
- [SSH Tunnel (Transport Layer)](#ssh-tunnel-transport-layer)
- [Authorization](#authorization)
- [Interface Architecture](#interface-architecture)
- [Security Properties](#security-properties)
- [Summary](#summary)
- [Source of Truth](#source-of-truth)

## Overview

APlane uses a multi-layer security model designed for distinct use cases.

**Authorization:** Runtime code uses the `auth.Authorizer` path. Product
credentials map to the reserved `system:product-admin` principal, and the
closed product authorizer requires exact membership in its explicit action
allowlist. See
[Authorization](#authorization) for the detailed model.

**Policy enforcement:** Operator approval and warning surfacing are active. A narrow signer safety policy layer is implemented for product-scoped policy stored as a node default (`default.json`) plus optional per-key documents (`policies/<selector>.json`) on both node roles, with guards such as a per-type allow/review/reject gate, rekey rejection, close-out rejection, clawback rejection, amount/fee ceilings, transfer review thresholds, forced review for warning-level findings (including application update, asset reconfigure/destroy, and asset freeze), and a narrow auto-approval rule for single 0-value ALGO/ASA self-transfer requests. A key with no document of its own follows the default; the shipped cosigner default is deny-all.

**Deployment scope:** the fixed product store and runtime are described in [ARCH_OVERVIEW.md](ARCH_OVERVIEW.md#fixed-product-store-and-runtime).

| Channel | Tool | User Type | Auth Method | Connection Model |
|---------|------|-----------|-------------|------------------|
| SSH Tunnel + HTTP | apshell | Agents or users | Enrolled SSH public key | Persistent (transport) |
| Admin protocol over IPC | apadmin / apapprover | Human operator | Passphrase | Persistent (session) |

## Authentication Channels

### 1. HTTP REST API (Connection-Authenticated)

Used by apshell and other HTTP clients for signing requests. The REST API is
reachable only through the node's SSH server: the client authenticates the
SSH connection with its enrolled key, and each `direct-tcpip` channel it opens
is handed off in-process to the HTTP server as an API connection that carries
the verified key fingerprint. A request carries no credential of its own.

```
┌─────────────────────────────────────────────────────────────────┐
│  SSH connection authenticated by enrolled key SHA256:...        │
│  └── direct-tcpip channel handed off as an API connection       │
│      (sshtunnel.APIConn, fingerprint attached to the context)   │
│  Request: POST /sign                                            │
│  Body: { "requests": [{ "auth_address": "...",                 │
│                        "txn_bytes_hex": "..." }] }              │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Step 1: Authentication (who is this?)                          │
│  Authenticator.Authenticate(ctx, request)                       │
│  └── reads the connection identity from the request context     │
│  └── looks the fingerprint up in the enrolled-key registry      │
│  └── Returns Identity client:<fingerprint> or 401 Unauthorized  │
│  └── node fail-closed: 503 before any enrolled-key lookup       │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Step 2: Authorization (are they allowed?)                      │
│  Authorizer.Authorize(identity, action, resource)               │
│  └── Product authorizer checks its explicit action allowlist    │
│  └── Returns nil (allowed) or 403 Forbidden                     │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Step 3: Handler processes request                              │
└─────────────────────────────────────────────────────────────────┘
```

**Characteristics:**
- **Connection-scoped identity**: Every request on a tunneled connection is
  attributed to the key that authenticated that connection; nothing in a
  request can supply or override it
- **No login step and no shared secret**: There is no API token, no
  `Authorization` header, and no credential file on either side. The client's
  SSH private key is its only credential
- **Loopback carries no identity**: The loopback TCP listener on
  `endpoint.signer_port` answers only `/health`; every other path on it gets
  `401` with `Authentication required: connect through an enrolled SSH key`
- **Unauthenticated responses close the connection**: `Connection: close` is
  set on auth failures, `/health`, and unknown routes, so an unauthenticated
  client cannot hold a connection slot with keep-alive requests

**Client Credential Details:**
- Ed25519, ECDSA (P-256/384/521), or hardware-backed `sk-` Ed25519/ECDSA key
  at the endpoint's `identity_file` (default `$APCLIENT_DATA/.ssh/id_ed25519`,
  mode 0600) or held by an SSH agent
- Enrolled once per node, either by an operator approving the client's
  `request-enrollment` request or by the operator importing the public key;
  the node records it in `identities/default/.ssh/authorized_keys`
- Identified everywhere by its SHA256 fingerprint; the principal is
  `client:<fingerprint>`

**Credential Lifecycle:**

| Aspect | Behavior |
|--------|----------|
| Scope | One enrollment per client key per node; the same key may be enrolled at a signer and at cosigners |
| Revocation | Operator revokes one key, or every key, from the `apadmin` Enrolled Clients screen (one key also with `apadmin clients revoke <fingerprint>`); the key's live SSH connections are closed and its next handshake is refused |
| Per-client differentiation | Each client is a distinct key, so audit and revocation are per client |
| Compromise impact | A stolen private key authenticates as that client until it is revoked; it grants no admin capability, because the admin protocol is reachable only over local IPC |

**Client Key Handling:**

Clients should:
- Keep the private key owner-only (mode `0600`) or in an SSH agent
- Never copy one key to several machines; enroll each machine's own key
- Report a suspected key compromise so the operator can revoke it

**Protected Endpoints:**
- `POST /sign` - Submit signing requests
- `POST /sign/bounded-admin` - Prepare an external contract-admin partial
- `POST /sign/component` - Produce guarded or bounded, kind-tagged components
- `POST /sign/assemble` - Assemble guarded or bounded-cosigner signed groups
- `POST /sign/cancel` - Cancel a live synchronous signing request by request ID
- `POST /sign/rotating/prepare` - Prepare a rotating-key signing stage
- `POST /sign/rotating/sign` - Sign with a prepared rotating-key stage
- `POST /plan` - Preview group building (dummies, fees, group ID) without signing
- `GET /status` - Return signer status, keyset revision, and approval timing metadata
- `GET /keys` - List available signing keys
- `GET /keytypes` - List available key types and creation parameters
- `POST /admin/generate` - Generate new keys
- `DELETE /admin/keys` - Delete keys
- `POST /admin/rotating/recover` - Start or cancel a rotating account's stage recovery

**Request Size Limits:**
- JSON POST endpoints (`/sign`, `/sign/bounded-admin`, `/sign/component`,
  `/sign/assemble`, `/sign/cancel`, `/sign/rotating/prepare`,
  `/sign/rotating/sign`, `/plan`, `/admin/generate`, and
  `/admin/rotating/recover`) enforce a 5 MB request body limit
- Oversized requests receive HTTP 413 (Payload Too Large)
- All authentication error responses use JSON format (not text/plain)

See [ARCH_SIGNING.md](ARCH_SIGNING.md#http-api-contract) for the authoritative route and wire
contracts.

Simulation is client-owned after ordinary signing. Apsigner exposes no
simulation route and does not contact algod for simulation. It applies the
same policy, approval, signing, and audit behavior as submission, releases an
executable group, and cannot know whether the client later simulates or submits
it.

> **Note on admin endpoints:** The `/admin/*` endpoints are authenticated like `/sign` and `/keys`: by the enrolled client key on the connection. An enrolled client may generate and delete keys; it never receives administrative actions (unlock, policy, settings, enrollment, revocation), which exist only on the admin protocol over local IPC.

**Unprotected Endpoints:**
- `GET /health` - Health check (no sensitive data)

### 2. Admin Protocol (Passphrase-Based Session)

Used by apadmin for interactive key management and signer control over the
local IPC Unix socket. SSH does not carry the admin protocol: it refuses
session channels, so a client holding an enrolled key still cannot reach the
passphrase prompt remotely.

```
┌──────────────┐                              ┌──────────────┐
│ apadmin  │                              │  apsigner      │
└──────┬───────┘                              └──────┬───────┘
       │                                             │
       │  1. Connect to aplane.sock                  │
       │────────────────────────────────────────────>│
       │                                             │
       │  2. MsgTypeAuthRequired                     │
       │<────────────────────────────────────────────│
       │                                             │
       │  3. AuthMessage { passphrase,               │
       │                   protocol_version }        │
       │────────────────────────────────────────────>│
       │                                             │
       │  4. Bind product runtime (default)          │
       │     Open product store-root.enc             │
       │     (Argon2id KEK + AES-256-GCM unwrap)     │
       │                                             │
       │  5. AuthResultMessage { success: true }     │
       │<────────────────────────────────────────────│
       │                                             │
       │     Session bound to product runtime        │
       │     (Session.bound = productruntime.Runtime)      │
       │                                             │
       │  ══════ SESSION AUTHENTICATED ══════════════│
       │                                             │
       │  6. Commands (no re-auth needed)            │
       │<───────────────────────────────────────────>│
       │     generate, import, delete, sign...       │
       │                                             │
```

**Characteristics:**
- **Persistent session**: Authenticate once, connection stays trusted
- **Interactive login**: Human enters passphrase
- **Dual-purpose passphrase**: Authentication + unwrapping the store's keyring
- **Single active admin**: Only one admin client connection is allowed at a time

**Passphrase Verification (Keyring):**
1. The store root (`store-root.enc`) carries the Argon2id parameters and salt in
   the clear, and the term keys sealed under a key-encryption key
2. Server derives the KEK from passphrase + salt using Argon2id (memory-hard)
3. Attempts the AEAD unwrap of the sealed term set
4. If the unwrap authenticates, the passphrase is valid — there is no separate
   check value to compare
5. The term keys are retained in memory for decrypting key files; the KEK is
   zeroed immediately (see [Keyring Encryption](#keyring-encryption))

**Session Lifecycle:**
```
Connect → Authenticate → [Commands...] → Disconnect
                                              │
                                              ▼
                                    lock_on_disconnect: true
                                    └── Signer locks, keys cleared
```

## Connection Models Compared

### Stateless (HTTP)

```
Request 1: POST /sign ──► Authenticate (connection key) ──► Handle ──► Response
Request 2: POST /sign ──► Authenticate (connection key) ──► Handle ──► Response
Request 3: GET /keys  ──► Authenticate (connection key) ──► Handle ──► Response
```

- No server-side session state beyond the SSH connection itself
- Every request is re-attributed to the key that authenticated its connection
- Scalable (no session storage)
- Suitable for automation/scripting

### Persistent (Admin Session)

```
Connect ──► Authenticate ──┬── Command 1 ──► Response
                          ├── Command 2 ──► Response
                          ├── Command 3 ──► Response
                          └── Disconnect
```

- Server tracks authenticated connection
- Passphrase entered once per session
- Human-friendly (interactive prompts)
- Suitable for key management operations

## SSH Tunnel (Transport Layer)

Every apshell connection to an apsigner, local or remote, is an SSH tunnel:

```
┌──────────┐                                          ┌────────────┐
│  apshell │◄═══════ SSH Tunnel (persistent) ════════►│  apsigner │
└──────────┘                                          └────────────┘
     │                                                       │
     │    HTTP requests ride direct-tcpip channels that       │
     │    carry the connection's enrolled-key identity        │
     │                                                       │
```

### SSH Authentication Model

SSH public-key authentication is the whole client authentication model. The
normal SSH username is the fixed non-secret value `aplane`; the server accepts
the connection only if the presented key is enrolled in the node's registry.

**Authentication flow:**

```
Client                                               Server
  │                                                       │
  │  1. SSH connect (username=aplane, pubkey=KEY)         │
  │──────────────────────────────────────────────────────>│
  │                                                       │
  │  2. Key type accepted? Fingerprint enrolled?         │
  │     Enrollment re-checked after the handshake        │
  │<──────────────────────────────────────────────────────│
  │                                                       │
  │  3. SSH session established; the server records the  │
  │     connection under the key's fingerprint           │
  │                                                       │
  │  4. direct-tcpip channels -> API connections carrying │
  │     that fingerprint -> HTTP handlers                 │
```

Keys are enrolled only by the operator: by approving a queued
`request-enrollment` request, or by importing a public key directly.

**Key points:**
- A key that is not enrolled fails the handshake with the standard SSH
  "unable to authenticate" error; the client surfaces this as
  `sshtunnel.ErrKeyNotEnrolled` and apshell tells the user to run
  `request-enrollment`
- Enrollment is re-checked against the installed registry after the handshake,
  so a key revoked while its handshake was in flight is refused
- The server never carries session channels for `aplane`: port forwarding
  (`direct-tcpip` channels to loopback destinations) is the only service, so
  the key grants API access and nothing else
- The accepted key algorithms are Ed25519, ECDSA (P-256/384/521), and
  hardware-backed `sk-` variants; the server's algorithm list refuses other
  keys before any signature is verified

### Client-Side Host Key Verification (TOFU)

The client verifies the server's identity using Trust On First Use (TOFU):

```
Client                                              Server
  │                                                      │
  │  1. SSH connect                                      │
  │─────────────────────────────────────────────────────>│
  │                                                      │
  │  2. Server sends host key                            │
  │<─────────────────────────────────────────────────────│
  │                                                      │
  │  3. Client checks endpoint known_hosts_path          │
  │     - Key found and matches → Continue               │
  │     - Key found but differs → REJECT (MITM warning)  │
  │     - Key not found → Prompt user to accept (TOFU)   │
  │                                                      │
```

**Configuration:**
- Client: the endpoint record's `known_hosts_path` in `$APCLIENT_DATA/endpoints.yaml` - where to store/verify server keys (default: `.ssh/known_hosts`, relative to `$APCLIENT_DATA`)
- Server: `endpoint.ssh.host_key_path` - persistent host key (default: `.ssh/ssh_host_key`, relative to `$APSIGNER_DATA`)

A wrongly trusted first endpoint learns nothing reusable: SSH public-key
authentication signs a session-bound challenge, so an impostor cannot replay
the client's signature against the real signer, and the client sends no
secret of any kind.

### SSH Security Properties

| Property | Implementation |
|----------|----------------|
| Client authentication | Enrolled SSH public key; the registry is `identities/default/.ssh/authorized_keys` |
| Key enrollment | Operator approval of a queued `request-enrollment` request, or operator import of the public key |
| Host key verification | TOFU model with persistent known_hosts |
| Credential confidentiality | The private key never leaves the client; no shared secret exists on either side |
| Replay resistance | Standard SSH public-key authentication over a session-bound exchange |
| Key revocation | Operator-initiated via apadmin; closes the key's active SSH connections and refuses its next handshake |
| Transport encryption | SSH protocol (Ed25519 host keys) |

### SSH Audit Logging

All SSH connections are logged for audit purposes:

```json
{"timestamp":"2026-01-18T10:30:00Z","event":"SESSION_CONNECTED","principal":"system:product-admin","requester_principal":"system:product-admin","outcome":"connected","remote_addr":"192.168.1.5:54321","reason":"ssh"}
{"timestamp":"2026-01-18T11:45:00Z","event":"SESSION_DISCONNECTED","principal":"system:product-admin","requester_principal":"system:product-admin","outcome":"disconnected","remote_addr":"192.168.1.5:54321","reason":"ssh"}
```

Logged information:
- Remote IP address and port
- Connect/disconnect events, including `request-enrollment` connections
- The key fingerprint appears only in the enrollment and revocation events,
  not in the session entries

**Note:** The SSH username is the fixed non-secret value `aplane`. The SSH auth-log
callback records only remote address, authentication method, and outcome; it
does not log the username, interactive responses, or authentication errors.

### SSH Configuration Reference

Server SSH settings live under `endpoint.ssh:`. If the block or individual
fields are omitted, apsigner fills in defaults and still starts the SSH server.

| Option | Default | Description |
|--------|---------|-------------|
| `endpoint.signer_port` | `11270` | Loopback REST API port behind the endpoint |
| `endpoint.ssh.listen_address` | `127.0.0.1` | SSH listener bind address |
| `endpoint.ssh.port` | `1127` | SSH listener port |
| `endpoint.ssh.host_key_path` | `.ssh/ssh_host_key` | Server host key (auto-generated if missing) |

The enrolled-client registry is not configurable: it is always
`identities/default/.ssh/authorized_keys` inside the product store, and the
daemon is its only writer.

**Example config.yaml with SSH:**
```yaml
endpoint:
  signer_port: 11270
  ssh:
    listen_address: 127.0.0.1
    port: 1127
```

**Important distinction:**
- SSH tunnel provides **transport security** and **client authentication**
- HTTP requests carry no credential; the HTTP server authenticates each request
  by the identity of the API connection it arrived on
- Authorization is still evaluated per request, against the client role's
  explicit action allowlist

### SSH Server Limits and Lifecycle

The SSH server allows at most 64 concurrent pending handshakes and closes
excess arrivals; one remote address may hold at most 8 of them. Authentication
has a 60-second socket deadline, cleared after successful authentication.
Accepted sockets are tracked before authentication so shutdown also closes
stalled handshakes. The limit applies to pending authentication, not
established sessions.

Client TCP dialing and SSH authentication share one setup timeout (60 seconds
by default). Setup cancellation closes the socket to interrupt blocked I/O.
Successful connections detach from that setup timeout; their established
connection lifecycle remains separately owned.
The setup timeout also covers interactive first-use host-key approval, giving
the operator time to compare the displayed fingerprint.

SSH server callbacks are startup-only. Key checking, key enrollment,
operator checks, enrollment approval and audit, session notifications, and the
API channel handoff must be configured before `Start`; setters fail fast after
the server has started.

### Client Enrollment via SSH

A client whose key is not yet enrolled asks the node to enroll it with the
`request-enrollment` command. The request is queued for the operator and
answered at once; the client learns the outcome by connecting. Together
with operator import of a public key (below), this is the whole bootstrap.

```
┌──────────┐                                          ┌────────────┐
│  apshell │                                          │  apsigner │
└────┬─────┘                                          └─────┬──────┘
     │                                                      │
     │  1. SSH connect (username=request-enrollment,        │
     │     any supported key)                               │
     │─────────────────────────────────────────────────────>│
     │                                                      │
     │  2. exec "enroll [<label>]"                           │
     │─────────────────────────────────────────────────────>│
     │                                                      │
     │  3. Request written to the pending queue             │
     │     (identities/default/.ssh/pending_enrollments.json)│
     │     reply "pending <fingerprint>", exit 0            │
     │<─────────────────────────────────────────────────────│
     │                                                      │
     │  4. Operator (apadmin) sees the request: at once if  │
     │     connected, otherwise at the next login or in     │
     │     the Enrolled Clients screen                      │
     │                                                      │
     │  5. Operator approves: key written to the registry,  │
     │     request removed from the queue; or rejects:      │
     │     request removed                                  │
     │                                                      │
     │  6. Client connects as "aplane" with the same key    │
     │     (refused until the approval)                     │
     │                                                      │
```

**Key points:**
- Enrollment requires operator approval (human in the loop), but the client
  does not wait for it: the request is persisted and the operator answers it
  whenever convenient, from the live popup, the Enrolled Clients screen, or
  `apadmin clients approve`
- The SSH public key identifies the requesting client; the label is display
  information the client asked for, never authority. The operator may
  replace it when approving
- The reply names the fingerprint of the key the server recorded; the client
  checks it against the key it authenticated with. `enrolled <fingerprint>`
  (exit 0) is answered instead when the key is already in the registry
- Key enrollment is product-scoped under `identities/default/.ssh/authorized_keys`;
  the queue sits beside it in `pending_enrollments.json`, and both are
  written only by the daemon
- Audit: `CLIENT_ENROLLMENT_REQUESTED` when a new request is queued,
  `CLIENT_ENROLLED` or `CLIENT_ENROLLMENT_REJECTED` with the admin session's
  attribution when the operator answers
- Refusals are reported as `ERROR: ...` lines with exit status 1:
  `enrollment queue is full; ask the operator to clear it and try again`, or
  `failed to record enrollment request` when the queue cannot be written
- Nothing is stored on the client: its key is its credential, and the node
  records the request and then the enrollment. A rejected or lapsed request
  is simply gone; the client's next `connect` is refused and it may request
  again

**Protocol steps:**

1. client connects as `request-enrollment` with any supported key
2. server rejects every other username before SSH auth succeeds
3. the exec request `enroll` or `enroll <label>` is accepted on that
   connection; the label is at most 64 bytes of printable single-line text,
   and any other command is refused: the exec request is answered false and
   `ERROR: unknown command` is written, with no exit status
4. a key the registry already holds is answered `enrolled <fingerprint>`
   with exit 0 and nothing is queued; like every success answer read from
   the registry, it is given only once the registry is durable (a registry
   left by an earlier failed write is re-published first, and the request
   fails with `ERROR: failed to record enrollment request` if that fails)
5. otherwise the server records the request (public key, label, remote
   address, time) in `identities/default/.ssh/pending_enrollments.json`,
   written atomically and durably like the registry, and under the same
   rule for a write that fails after its rename: a request the file then
   holds is a queued request for the operator (audited, announced) and the
   queue is re-published before its next write, but the client is answered
   `ERROR: enrollment request recorded but not yet durable; retry the
   request`, exit 1, so it retries and is answered `pending` only once the
   queue is durable (the retry refreshes the entry and is not audited or
   announced again); a new request is audited as
   `CLIENT_ENROLLMENT_REQUESTED` and announced to a connected admin session
   as `client_enrollment_request`; a repeat for a waiting key refreshes its
   entry. Refusals are `ERROR: enrollment queue is full; ask the operator to
   clear it and try again` and `ERROR: failed to record enrollment request`,
   exit 1
6. server replies `pending <fingerprint>` with exit 0; the client checks the
   fingerprint against the key it authenticated with and disconnects. Nothing
   is stored on the client
7. later, an admin session approves (`approve_enrollment`: the key and label
   are added to the registry under the publication rule, the entry is
   removed, `CLIENT_ENROLLED` is audited) or rejects (`reject_enrollment`:
   the entry is removed, `CLIENT_ENROLLMENT_REJECTED` is audited). The audit
   event follows the change that took effect, not the command's outcome: a
   key that entered the live registry is audited as enrolled even when the
   approval then reports a durability failure or could not clear the entry
   (a repeat approval clears it without a second `CLIENT_ENROLLED`; rejecting
   such a request is refused so the queue and the registry never disagree
   about the key), and a request dropped by a write that is not yet durable
   is audited as rejected. Labels written by the admin protocol follow the
   same rule as client-supplied ones: printable single-line text of at most
   64 bytes. Every
   waiting request is announced again when an admin session authenticates
8. the client learns the outcome by connecting: an enrolled key is accepted,
   anything else is refused at the handshake

**Pre-enrollment.** The operator can also enroll a key without a request
from the client: the Enrolled Clients screen's import form and
`apadmin clients import <public-key-file|-> [--label <text>]` take one
OpenSSH public-key line (its comment is the label unless one is given). The
operator must verify the key's fingerprint with the client's owner through a
channel they trust; the public key itself is not secret. A waiting request
for the same key is cleared by the import.

During enrollment, apshell displays the complete SHA256 fingerprint
of the key that signed SSH authentication, including agent-selected keys.
The admin enrollment request already carries that fingerprint; this adds no wire
field. It identifies the requesting client key, not an individual request,
the server host key, or a Witness Key ID.

The admin protocol message is `import_client_key` (one OpenSSH
public-key line; its comment is the label unless one is given). Imports reject
authorized_keys options, including reserved `aplane-` options, and trailing key
lines with `invalid_request`; unsupported restrictions are never silently
discarded. The key type check is the same as for `request-enrollment`, the
write follows the publication rule, a waiting request for the same key is cleared, and
`CLIENT_ENROLLED` is audited with an empty remote address.

The publication rule both files follow (a write that fails after its rename
is applied and audited but not acknowledged to the client until a sync
succeeds, and a crash can only take back what was never acknowledged) is
modeled in [`formal/enrollment_queue.tla`](formal/enrollment_queue.tla); see
[FORMAL_TLA_ENROLLMENT_QUEUE_MODEL.md](FORMAL_TLA_ENROLLMENT_QUEUE_MODEL.md).

**Queue file.** The queue is loaded once at startup, like the registry, and a
queue file the daemon cannot read completely refuses to serve. Waiting requests
survive a daemon restart.
The queue document has `schema_version: 1` and a `requests` array. Each request
stores `public_key` (an OpenSSH line), optional `label` and `remote_addr`, and
`requested_at` (a JSON timestamp). The parser and publication owner is
`internal/signerapp/enrollqueue`; the product runtime serializes queue and
registry mutations under the same lock.

**Limits.** `request-enrollment` accepts any supported client key, so the
flow is reachable without credentials, and the queue it writes to is bounded:
- One queue entry per key: a repeated request refreshes the entry's
  timestamp, remote address, and label (when given) rather than adding one,
  and does not count against the cap
- At most 16 keys may be waiting (`enrollqueue.MaxPending`); a further key is
  refused with `enrollment queue is full` until the operator approves or
  rejects an entry
- An entry lapses after 7 days (`enrollqueue.TTL`); the client requests again
- Each `request-enrollment` connection may make one enrollment request, and the
  connection closes when that request ends, whatever the outcome
- A `request-enrollment` connection that has not started enrollment within 30
  seconds is closed
- At most 8 `request-enrollment` connections are open at once
- The client key must be Ed25519, ECDSA (P-256/384/521), or a
  hardware-backed `sk-` Ed25519/ECDSA key. This applies to every SSH client,
  not only `request-enrollment`: the server's public-key algorithm list refuses
  other keys (RSA, DSA, certificates) before the key is parsed or any
  signature is verified. RSA is excluded because its verification cost grows
  with a modulus size the client chooses, and a key refused only in the
  public-key callback is still verified when the client sends a signed
  request without a preliminary query
- Independent of the username, one remote IP may hold at most 8 of the 64
  pending SSH handshake slots, so a single host cannot keep every slot busy
  for the 60-second handshake timeout
- The server sends each SSH client a keepalive every 15 seconds and closes a
  connection that does not reply within 30 seconds, so a client that keeps
  TCP open but stops answering does not hold its connection indefinitely
- Each `request-enrollment` connection may have at most 2 open session channels;
  further channels are rejected before they are accepted
- A client must accept the enrollment response within 10 seconds; a client
  that stops reading (for example by advertising a zero receive window) is
  disconnected
- Enrollment never holds up signing: a request is answered without waiting
  for the operator, so the approval coordinator's single delivery turn is
  used by signing requests only. An enrollment request pops up in apadmin
  when an operator is connected, but the signer does not wait on it
- Client-supplied text (for example an unknown exec command) is quoted and
  truncated before it is logged, so it cannot inject terminal escapes into an
  operator console

### Client Key Revocation

The operator revokes an enrolled client key from the apadmin TUI Enrolled
Clients screen (opened with `c` from the key list). The screen lists every
enrolled key with its fingerprint, label, key type, and whether it is connected
right now, and offers per-key revocation or, as the emergency lever,
revocation of every key.

```
┌──────────┐      ┌──────────┐                     ┌────────────┐
│ apadmin │      │  apshell │                     │  apsigner │
└────┬─────┘      └────┬─────┘                     └─────┬──────┘
     │                  │                                 │
     │  1. Operator revokes key SHA256:...                │
     │───────────────────────────────────────────────────>│
     │                  │                                 │
     │                  │  2. Server removes the key from │
     │                  │     authorized_keys (validated, │
     │                  │     atomically published)       │
     │                  │                                 │
     │                  │  3. Server sends key-revoked@   │
     │                  │     aplane and closes the key's │
     │                  │     SSH connections             │
     │                  │<────────────── [disconnected] ──│
     │                  │                                 │
     │                  │  4. Client must request-        │
     │                  │     enrollment again; the       │
     │                  │     operator approves it later  │
     │                  │                                 │
```

**What happens on revocation** (`revoke_enrolled_key`, `revoke_all_enrolled_keys`):
1. The registry is rewritten without the key, under the publication rule
   (validate the full candidate, write atomically, install under one lock)
2. Every SSH connection authenticated with that key receives the
   `key-revoked@aplane` global request and is closed; the result reports how
   many connections were closed
3. A handshake that completed against the previous registry is re-checked
   against the installed one and refused
4. The `CLIENT_KEY_REVOKED` audit entry records the fingerprint, label, and
   closed-connection count with the admin session's attribution; revoke-all
   writes one entry per key with no count

`sshtunnel.Server.CloseConnectionsForFingerprint(fingerprint, reason)` and
`CloseAllClientConnections(reason)` close connections by key.

**Client re-authorization:**
- The client must run `request-enrollment` again (same flow as initial enrollment), or the operator re-imports its public key
- The operator approves the new request from the apadmin TUI or `apadmin clients approve`, at any later time
- If a client runs `request-enrollment` while still connected to that node, the session is disconnected first
- Once re-enrolled, the client can `connect` normally with the same key

**Use cases:**
- Compromised or lost client machine
- Decommissioning a device
- Revoking every client at once after an incident, then selectively re-approving only trusted clients

### Uniform SSH Tunneling

All apshell connections to the signer use SSH tunneling, regardless of whether the signer is on localhost or a remote host. This provides uniform per-client identity via SSH public keys.

```
┌──────────┐                                          ┌────────────┐
│  apshell │◄═══════ SSH Tunnel (encrypted) ═════════►│  apsigner │
│          │ :random ───── direct-tcpip channels ────►│ API conns  │
└──────────┘                                          └────────────┘
     │
     └── HTTP through the tunnel; each request attributed to the connection's key
```

**Why uniform SSH:**
- Every client has a unique SSH key identity, even on localhost
- The signer distinguishes clients by key for authentication, audit, and revocation
- Consistent security model regardless of network topology

**Connection properties:**
- SSH provides transport encryption and client authentication
- Host key verification prevents MITM (TOFU via known_hosts)
- Random local port avoids conflicts
- Authorization is evaluated per HTTP request against the client role

**Configuration:**
- Client connection profiles live in `$APCLIENT_DATA/endpoints.yaml`
- An endpoint URL is `ssh://host[:port]`; a node is reachable only this way
- Endpoint records carry the SSH identity file and `known_hosts` path;
  relative paths resolve against the client data directory
- Server SSH listener settings live in signer `config.yaml` under
  `endpoint.ssh:`
- `request-enrollment [--endpoint <alias>] [--label <text>]` uses the same
  endpoint record to reach the node it enrolls with

**Bootstrap requirement:**
Non-interactive modes (scripts, JS runner) reject unknown SSH hosts — they require the signer's host key to already be in `known_hosts`. Users must first connect interactively with `apshell` (via `connect` or `request-enrollment`), which prompts for TOFU host key approval and saves it. After that, scripts and automation can connect without prompts.

The `request-enrollment` flow (or an operator import of the public key) is the only bootstrap path: one operator decision enrolls the client's key, and that key is the client's whole credential. This is a single trust decision that fully onboards the client; the client does not wait for it, and connects once it has been made.

## Authorization

This section defines APlane's product authorization model: the reserved admin
principal, explicit allowed actions, resources, and the enforcement points that
protect signer operations.

Product-store model: see [ARCH_OVERVIEW.md](ARCH_OVERVIEW.md) (Fixed Product Store and Runtime). The
product surface exposes one reserved administrator principal and no mutable
principal, group, grant, or runtime-selection management.

### Purpose

Authorization answers this question:

```text
May this principal perform this action on this resource?
```

It is separate from:

- **Authentication:** Which credential was presented, and did it verify?
- **Product-store ownership:** Which process owns keys, config, the enrolled
  client registry, runtime state, and approval state?
- **Signing policy:** Is a specific transaction safe enough to sign?
- **Encryption and key handling:** How passphrases, term keys, and key files
  are protected.

For wire and storage compatibility contracts, see
[ARCH_CONTRACTS.md](ARCH_CONTRACTS.md).

### Core Concepts

#### Credential

A credential is proof presented at an authentication boundary.

Credential types include:

- an enrolled client SSH key, presented at the SSH handshake; the HTTP API is
  reachable only through that tunnel, and each request is attributed to the
  key that authenticated its connection
- admin passphrase over local IPC

Credentials authenticate access. They are not themselves the authorization
subject.

#### Principal

A principal is the actor used for authorization decisions.

The admin passphrase authenticates the reserved system principal:

```text
system:product-admin
```

An enrolled client key authenticates a client principal named by the key's
SHA256 fingerprint, with role `client`:

```text
client:SHA256:<fingerprint>
```

`default` is not a principal. It names the product signing store directory in
durable paths.

#### Product Store and Target Attribution

The one product store owns signer state:

- encrypted key files
- keystore metadata
- product runtime config
- enrolled client registry (`.ssh/authorized_keys`)
- pending enrollment queue (`.ssh/pending_enrollments.json`)
- approval coordinator
- runtime lock/unlock state
- watcher and reload ownership

Its durable namespace is `identities/default/`. The directory name is not an
authorization principal or request value.

#### Action

An action is a stable operation name used for authorization checks and audit.

Examples:

```text
sign.request
keys.generate
policy.update
clients.revoke
```

#### Resource

`auth.Resource` describes the concrete thing being accessed:

```go
type Resource struct {
    Type string
    ID   string
}
```

Conventions:

- `Type` is the resource family, such as `key`, `keys`, `policy`,
  `transaction`, or `client`.
- `ID` is the concrete resource identifier when one exists, such as a key
  address, request ID, or template key type.

### Product Authorization

The product mode is:

```text
mode: product_single
admin principal: system:product-admin
client principals: client:<fingerprint>, role client
authorization source: closed action allowlists (product admin, client role)
identity/principal/group/grant management: no mutable management graph
client enrollment UI: pending/enrolled lists, approve, reject, import, revoke
```

The authorization path is:

```text
credential
  -> authenticated product session or tunneled API connection
  -> system:product-admin, or client:<fingerprint> with role client
  -> explicit ProductAllowedActions or ClientAllowedActions membership
     (resource type and ID are recorded for attribution only)
```

Important implications:

- Logging in with `apadmin` authenticates against the product store, and the admin
  session authorizes as `system:product-admin`.
- A tunneled HTTP request authorizes as the client principal of its
  connection. `ClientAllowedActions` (`internal/authz`) grants only what the
  authenticated HTTP routes expose: `identity.view`, `sign.request` (which
  also covers `/sign/rotating/prepare` and `/sign/rotating/sign`),
  `sign.component`, `sign.assemble`, `keys.view`, `keys.generate`,
  `keys.delete`, `keys.recover`, and `keytypes.view`. Clients never receive
  administrative actions. `keys.recover` is its own action rather than a
  use of `identity.view`: viewing status works while locked, but starting a
  recovery grant schedules seed-derived background computation, so it is
  gated like signing.
- A known action is not automatically allowed. It must also appear in the
  explicit allowlist for that principal kind.

### Authorization Flow

#### HTTP

HTTP requests are authenticated by their connection, then authorized:

```text
SSH handshake with enrolled key
  -> direct-tcpip channel handed off as an API connection (sshtunnel.APIConn)
  -> auth.ConnIdentity{KeyFingerprint} attached to the connection context
  -> productAuthenticator looks the fingerprint up in the enrolled registry
  -> client:<fingerprint> (role client)
  -> ProductAuthorizer (ClientAllowedActions)
  -> process-owned product runtime
  -> handler
```

A request carries no credential: nothing in it can supply or override the
connection identity. The loopback REST listener attaches no identity, so on it
only `/health` answers and every other route fails authentication with `401`.
Authentication and authorization never select a runtime or store.

#### Admin IPC

Local admin sessions use the product passphrase and bind to the product runtime:

```text
admin auth message
  -> passphrase verification
  -> system:product-admin principal
  -> default runtime binding
  -> ProductAuthorizer
  -> admin operation
```

Membership in the operating-system `aplane` group grants only the ability to
traverse `/run/apsigner` and connect to `aplane.sock`. It grants no access to
the private signer store. The admin passphrase, principal mapping, product
runtime binding, and explicit action authorization are still required after
socket connection.

Auth-time unlock is authorization-gated before the runtime is unlocked.
Explicit admin lock requests retain the stable `identity.lock` action name.
Admin disconnect cleanup applies the product runtime's `lock_on_disconnect`
setting. Local admin idle timeout is enforced by `apadmin` as a disconnect,
not by a signer-side activity grant.

#### No Remote Admin Transport

The admin protocol is carried only over the local IPC socket. SSH carries
API port forwarding and `request-enrollment` bootstrap. API-authenticated
connections refuse session channels; enrollment connections accept only the
enrollment exec flow, so no admin subsystem is reachable over SSH. Remote
administration means logging in to the signer host and running `apadmin`
there.

Recovery-material operations are narrower than normal admin
operations: `keys.import` is accepted only on local IPC admin sessions,
`keys.export` is denied on all admin transports, and `keys.generate` never
returns generated recovery material over the admin protocol.

### Action Vocabulary

Stable action names live in `internal/auth/authorizer.go`. A known-action guard
makes action typos such as `keys.veiw` fail before allowlist matching.

| Action | Meaning | Typical Resource | Unlock Required |
|--------|---------|------------------|-----------------|
| `identity.view` | View identity state | `identity` | No |
| `identity.unlock` | Unlock signer identity | `identity` | No |
| `identity.lock` | Lock signer identity | `identity` | No |
| `identity.backup` | Create, export/read back, and delete signer-managed encrypted backup archives for the product store | `identity`, `backup` | Yes for create/delete; export/read is available in unlocked or recovery state |
| `identity.restore` | List, import, preview, and directly restore managed credential archives, roll back the latest eligible restore, and reconcile product-store recovery state | `identity`, `backup`, `backup_upload` | Yes; recovery-mode inventory, repair, and resolution are allowed while signing remains blocked |
| `identity.passphrase` | Rotate the identity keystore passphrase | `identity` | Yes |
| `sign.request` | Request transaction signing, signing plan, or sign-request cancellation | `transaction` | Yes for signing/cancel |
| `sign.component` | Request user, cosigner, or bounded-base authorization components over a frozen group | `transaction` | Yes |
| `sign.assemble` | Assemble verified user and cosigner component signatures into signed guarded transactions | `transaction` | Yes |
| `sign.approve` | Approve or reject signing request | `sign_request` | No |
| `keys.view` | List keys or view key details | `keys`, `key` | Yes for key list/details |
| `keys.generate` | Generate a key | `key` | Yes |
| `keys.import` | Import a key | `key` | Yes |
| `keys.export` | Export a key mnemonic (disabled) | `key` | Yes |
| `keys.delete` | Delete a key | `key` | Yes |
| `keys.recover` | Start or cancel a rotating account's stage recovery: a bounded search that derives stage addresses into the signer's own cache and never signs | `key` | Yes to start; a cancel answers while locked |
| `cosigners.view` | List/show public cosigner references and export public witness metadata | `cosigner_references`, `cosigner_reference`, `cosigner_public` | No |
| `cosigners.manage` | Import or remove signer-owned public cosigner references | `cosigner_reference` | Yes |
| `generations.view` | Inspect current/retained generations, quarantine, and selected deleted-archive usage | `generations`, `deleted_archive` | No; runtime must be unlocked or authenticated recovery |
| `identity.generation.quarantine.prune` | Irreversibly delete explicitly selected non-authoritative quarantined generation publications after durable audit | `generation_quarantine` | Yes; recovery-admin state is allowed |
| `identity.generation.abandoned.discard` | Irreversibly delete explicitly selected in-place abandoned publications that reconciliation cannot safely quarantine | `generation_abandoned` | Yes; recovery-admin state is allowed |
| `identity.archive.prune` | Irreversibly delete explicitly selected canonical entries from the selected generation's deleted credential/template archive after durable intent audit | `deleted_archive` | Yes; recovery-admin state is allowed |
| `keytypes.view` | List available key types | `keytypes` | No |
| `keytypes.activate` | Activate a key type | `keytype` | Yes |
| `keytypes.deactivate` | Deactivate a key type | `keytype` | Yes |
| `templates.view` | List template library | `templates` | Yes |
| `templates.install` | Install a template | `template` | Yes |
| `templates.remove` | Remove an installed template | `template` | Yes |
| `policy.view` | View signer policy | `policy` | No |
| `policy.update` | Update signer policy | `policy` | No |
| `settings.view` | View admin settings | `settings` | No |
| `settings.update` | Update admin settings | `settings` | No |
| `clients.view` | List enrolled client keys and their live connections, and the enrollment requests waiting for approval | `clients`, `client_enrollment` | No |
| `clients.enroll` | Approve or reject a queued client enrollment request, or import a client public key directly | `client_enrollment`, `client` | No |
| `clients.revoke` | Revoke one enrolled client key, or every key, closing its connections | `client`, `clients` | No |
| `health.get` | Reserved action name; `/health` is unauthenticated and does not call the authorizer | `system` | No |

New sensitive operations must either use an existing action with the same
meaning or define a new stable action before implementation.

### Product Action Allowlist

`ProductAllowedActions` and `ClientAllowedActions` are closed, explicit sets
populated in code. The product authorizer grants an operation only when all of
these conditions hold:

- the principal is exactly `system:product-admin`, or is a `client:` principal
  whose role is `client`;
- the action is in the closed known-action vocabulary;
- the action is independently present in the allowlist for that principal
  kind.

Callsites supply a concrete resource type and, where applicable, ID for target
attribution and audit. The current product authorizer decides on principal,
role, and action membership; it does not match resource-specific grants.

Adding a known action does not add it to the product allowlist. This preserves
a deliberate review point for new sensitive operations. There is no runtime
principal, group, grant, wildcard-target, membership, or disabled-node graph in
the single-product authorizer.

### Enforcement Points

Authorization checks must run before private-key access, mutation, approval
response handling, client enrollment or revocation, or policy/settings changes.

Enforced callsites:

- `internal/signerapp/daemon/http_runtime.go` wraps HTTP `/sign`,
  `/sign/component`, `/sign/assemble`, `/sign/bounded-admin`,
  `/sign/rotating/prepare`, `/sign/rotating/sign`, `/sign/cancel`, `/plan`,
  `/status`, `/keys`, `/keytypes`, `/admin/generate`, and `/admin/keys` with
  `requireAuth`.
- `internal/signerapp/daemon/http_auth.go` calls `Authorizer.Authorize` after
  authentication and before the handler executes.
- `internal/signerapp/adminserver/session.go` gates auth-time unlock through
  `authorizeIdentity`.
- `internal/signerapp/adminserver/handlers.go` gates admin `unlock`, key
  list/details/generate/import/export/delete, key type list/activate/deactivate,
  template list/install/remove, policy view/update, settings view/update,
  signer-managed backup creation/list, credential restore preview/apply,
  restore rollback/reconciliation,
  passphrase rotation, signing approval response, queued-enrollment
  approve/reject, public client-key import, pending/enrolled-key listing,
  key revocation, cosigner-reference view/manage,
  generation inspection, quarantine prune, abandoned-generation discard, and
  deleted-archive prune through `s.authorize`. `lock_identity` is gated with
  `authorizeIdentity` for `identity.lock`.

`/health` is intentionally absent from the enforcement list. It is an
unauthenticated health endpoint in [ARCH_SIGNING.md](ARCH_SIGNING.md#http-api-contract);
`health.get` is reserved.

### Denial Semantics

Authorization is fail-closed:

- nil or unknown principal is forbidden
- unknown action is forbidden before allowlist matching
- known but unlisted action is forbidden

Wire behavior:

- HTTP authentication failure returns `401`
- When the node is in fail-closed state, authenticated HTTP routes return `503`
  before any enrolled-key lookup; the attempt is still audited as `AUTH_FAILED`
- HTTP authorization failure returns `403`
- IPC/admin authorization failure returns an `error` message with code
  `authorization_denied`
- HTTP authorization denials are written to the audit log as auth failures with
  an authorization reason
- IPC/admin authorization denials are written to the audit log as
  `AUTHORIZATION_DENIED`

### Audit Attribution

Audit records identify the actors and request context for sensitive operations.

The attribution fields are listed under [Audit Logger](#audit-logger).

Target invariant:

```text
Every sensitive operation should be attributable to its principal and relevant
operation-specific resource evidence.
```

Authorization denials must also be attributable. Admin denials record the
session, principal, action, resource, and denial reason. HTTP
denials record the authenticated principal and remote address at the HTTP auth
boundary.

### Security Invariants

- Runtime code must not use an allow-all authorizer.
- Product authorization must use an explicit action allowlist.
- Every private-key operation must have an authorization check.
- Every key, policy, settings, template, client-registry, identity, or
  lifecycle mutation must have an authorization check.
- Auth-time unlock must be authorization-gated.
- Approval responses must be authorization-gated.
- Authorization resources must not grow a runtime or store selector.
- Unknown actions must fail closed.
- Unknown actions must fail before allowlist matching so callsite typos do
  not create ad hoc permissions.
- Unknown principals must fail closed.
- `system:product-admin` is reserved.
- A client principal's role is assigned by the trusted authentication path,
  never read from a request.

## Interface Architecture

Authentication, authorization, and audit logging are abstracted behind
interfaces for extensibility. This section summarizes the interfaces; the
authorization architecture and invariants live in
[Authorization](#authorization).

### Authenticator Interface

```go
// internal/auth/authenticator.go
type Authenticator interface {
    Authenticate(ctx context.Context, r *http.Request) (*Identity, error)
    Method() string
}

type Identity struct {
    ID             string            // "client:<fingerprint>" or "system:product-admin"
    Type           string            // "client" or "system"
    Method         string            // "ssh-key" or "ipc-passphrase"
    Role           string            // assigned by the trusted auth path; selects permissions
    KeyFingerprint string            // SHA256 fingerprint of the enrolled client key
    Label          string            // enrolled key's display label; never authority
    Metadata       map[string]string // Additional claims
}
```

**Implementation:**
- `productAuthenticator` (`internal/signerapp/daemon/product_authenticator.go`)
  reads the `auth.ConnIdentity` the HTTP server attached to the connection
  context, looks the fingerprint up in the enrolled-key registry, and returns
  `client:<fingerprint>` with role `client`. A loopback connection carries no
  identity and fails with `ErrNoCredentials`; an unenrolled fingerprint fails
  with `ErrInvalidCredentials`

### Authorizer Interface

The authorization model separates the actor principal from the resource being
acted on. Admin sessions over IPC authenticate the reserved
`system:product-admin` principal; tunneled HTTP connections authenticate a
`client:<fingerprint>` principal whose role grants only the client action set.

```go
// internal/auth/authorizer.go
type Authorizer interface {
    Authorize(ctx context.Context, identity *Identity, action Action, resource Resource) error
}

type Action string  // "sign.request", "keys.view", "keys.generate"
type Resource struct {
    Type string     // "transaction", "keys", "system"
    ID   string     // Resource identifier (e.g., key address)
}
```

**Implementation:**
- `internal/authz.ProductAuthorizer` - exact principal/role and action-allowlist checks with no mutable principal/group/grant graph; resource fields are call-site attribution, not a resource-grant condition
- `authz.NewProductSingleAuthorizer()` - maps product credentials to the reserved `system:product-admin` principal and a copied explicit action allowlist

See [Action Vocabulary](#action-vocabulary), [Principal](#principal),
[Denial Semantics](#denial-semantics), and [Enforcement Points](#enforcement-points).

### Audit Logger

```go
// internal/signerapp/audit/audit.go
type AuditLogger struct {
    file    *os.File
    mu      sync.Mutex
    path    string
    written uint64

    authFailures       entryLimiter
    cosignerRejections entryLimiter
}

type AuditEntry struct {
    Timestamp          time.Time
    Event              AuditEventType
    Principal          string
    RequesterPrincipal string
    ApproverPrincipal  string
    AdminSessionID     string
    Transport          string
    Outcome            string
    TxnAuth            string
    TxnSender          string
    TxnType            string
    TxnDetails         string
    TxID               string
    RemoteAddr         string
    Reason             string
    PolicyRuleID       string
    WitnessKeyID       string
    KeyCount           int
    SuppressedCount    int
    ClientLabel        string
    ClosedConnections  int
    RotatingStage      *uint64
    RotatingLastValid  uint64
    // abridged: backup, restore, and generation fields such as
    // ArchiveSHA256, OperationID, GenerationIDs, GenerationID,
    // ManifestSHA256, and the Term* counters are omitted here
}
```

The current implementation is a concrete append-only JSONL logger in
`internal/signerapp/audit/audit.go`, not a generic cross-application
`internal/audit` sink package.
`NewAuditLogger(path)` opens the audit log (`audit.log`) with mode `0600`,
appends one JSON object per line with a UTC timestamp, and syncs each write.

Audit entries carry attribution fields:

- `principal`: principal field
- `requester_principal`: principal requesting the action; for tunneled
  HTTP signing requests this is the connection's `client:<fingerprint>`
- `approver_principal`: principal approving or rejecting the action
- `admin_session_id`: admin protocol session ID when available
- `transport`: `ipc`, `ssh`, `http`, or empty for process-level events
- `outcome`: requested, approved, rejected, failed, denied, connected, disconnected, or similar
- `txn_auth`, `txn_sender`, `txn_type`, `txn_details`, `txid`: transaction/key attribution for signing and key events
- `remote_addr`: remote address when available
- `reason`: rejection, failure, or denial detail when available
- `policy_rule_id`: policy rule that forced manual signing review, when present
- `key_count`: key count for startup and reload events
- `witness_key_id`: public witness authority affected by a cosigner-reference mutation
- `client_label`: display label of the key in enrollment and revocation events
- `closed_connections`: live connections closed by a key revocation
- `suppressed_count`: failures or rejections counted by a suppression summary entry
- `rotating_stage`, `rotating_last_valid`: stage revealed and last valid round
  for `ROTATING_RELEASE`

Requester and approver remain distinct principal fields in the log shape.

Rotation:

- size-based at 10 MB
- rotate to `audit.log.1`
- previous `audit.log.1` rotates to `audit.log.2`
- two rotated generations retained

Denial behavior:

- HTTP authentication failures and HTTP authorization denials are recorded as
  `AUTH_FAILED` with a reason such as `missing_credentials`,
  `invalid_credentials`, or `unauthorized: <action>`.
- Unauthenticated `AUTH_FAILED` entries are rate limited, because audit
  retention is a few rotated 10 MB files and any local process can reach the
  loopback REST API: a burst of 20 is logged individually, then one per 6
  seconds, and the rest are counted in an `AUTH_FAILURES_SUPPRESSED` entry
  (`suppressed_count`) written within a minute of the first suppressed
  failure, and on shutdown. A flood stays visible without rotating earlier
  entries out of the log. Authorization denials of an authenticated
  principal are not rate limited.
- Cosigner policy rejections (`SIGN_REJECTED` for a cosigner component) are
  rate limited the same way, with a separate budget and a
  `COSIGNER_REJECTIONS_SUPPRESSED` summary. The caller is authenticated, but
  a compromised signer side enrolled at the cosigner can provoke
  rejections at will; without the limit it could rotate the record of what
  the cosigner signed out of the log. Cosigner signatures (`SIGN_APPROVED`)
  are never rate limited.
- Admin protocol authorization denials are recorded as
  `AUTHORIZATION_DENIED` with the admin session context, action/resource details,
  principal attribution, transport, and denial reason.

Events:

- `SERVER_START`
- `SERVER_STOP`
- `SERVER_STOP_INCOMPLETE`
- `SIGN_REQUEST`
- `SIGN_APPROVED`
- `SIGN_REJECTED`
- `SIGN_FAILED`
- `ROTATING_RELEASE`
- `AUTH_FAILED`
- `AUTH_FAILURES_SUPPRESSED`
- `COSIGNER_REJECTIONS_SUPPRESSED`
- `AUTHORIZATION_DENIED`
- `KEY_RELOAD`
- `KEY_GENERATED`
- `KEY_DELETED`
- `KEY_IMPORTED`
- `KEY_REJECTED`
- `BACKUP_CREATED`
- `BACKUP_IMPORTED`
- `BACKUP_EXPORT_STARTED`
- `BACKUP_FAILED`
- `BACKUP_RESTORE_PREVIEWED`
- `BACKUP_RESTORE_PREVIEW_FAILED`
- `CREDENTIAL_RESTORE_INTENT`
- `CREDENTIAL_RESTORE_SUCCEEDED`
- `CREDENTIAL_RESTORE_FAILED`
- `CREDENTIAL_RESTORE_COMMIT_UNCERTAIN`
- `CREDENTIAL_RESTORE_ROLLBACK`
- `STORE_INITIALIZED`
- `STORE_INITIALIZE_FAILED`
- `PASSPHRASE_CHANGED`
- `PASSPHRASE_CHANGE_FAILED`
- `COSIGNER_REFERENCE_CHANGED`
- `GENERATION_QUARANTINE_INTENT`
- `GENERATION_QUARANTINED`
- `GENERATION_QUARANTINE_PRUNE_INTENT`
- `GENERATION_QUARANTINE_PRUNED`
- `GENERATION_ABANDONED_DISCARD_INTENT`
- `GENERATION_ABANDONED_DISCARDED`
- `DELETED_ARCHIVE_PRUNE_INTENT`
- `DELETED_ARCHIVE_PRUNED`
- `SESSION_CONNECTED`
- `SESSION_DISCONNECTED`
- `IDENTITY_LOCKED`
- `CLIENT_ENROLLMENT_REQUESTED`
- `CLIENT_ENROLLED`
- `CLIENT_ENROLLMENT_REJECTED`
- `CLIENT_KEY_REVOKED`

Signing-audit semantics:

- `SIGN_APPROVED` is emitted only for transactions the signer actually signs
- foreign and passthrough entries may appear in `SIGN_REQUEST`/planning context, but are not recorded as `SIGN_APPROVED`
- signing audit over HTTP records `transport:"http"` and the connection's `client:<fingerprint>` principal as requester
- cosigner-role component signing currently records approvals and policy
  rejections through `SIGN_APPROVED`/`SIGN_REJECTED`; `txn_auth` is the
  Witness Key ID, `txn_sender` is the decoded target sender, and
  `policy_rule_id` carries the rule ID of the first policy violation when present
- `ROTATING_RELEASE` is written durably before a rotating account's stage
  signature leaves the signer; it records the account, `txid`,
  `rotating_stage`, and `rotating_last_valid`, and the signer rebuilds its
  release memory from these entries at unlock (see
  [ARCH_SIGNING.md](ARCH_SIGNING.md#rotating-accounts-rotating1))
- approval audit enriches approved/rejected records with the admin session approver principal when an admin response supplies it
- approved/rejected signing records include `policy_rule_id` when a policy rule forced manual review before the operator decision
- admin authorization-denial audit records event `AUTHORIZATION_DENIED`, outcome `denied`, admin session ID, transport, principal attribution, action/resource details in `reason`, and remote address when available
- IPC admin session connected/disconnected audit records the admin session ID, transport, principal, and remote address; SSH connect/disconnect entries record the remote address, `reason:"ssh"`, and outcome, attributed to `system:product-admin`
- key-management audit events are emitted for both REST and authenticated IPC admin operations and name the requester: REST `KEY_GENERATED`/`KEY_DELETED` entries carry the enrolled client's `client:<fingerprint>` principal with `transport: http` and its remote address, and IPC entries (including `KEY_IMPORTED` and `PASSPHRASE_CHANGED`) carry the admin session's principal, session ID, and transport
- `KEY_REJECTED` is emitted when signer key scanning skips a key file that
  violates a load-time key-file invariant; for LogicSig salt failures,
  `reason` includes the key filename and rejection reason

Backup-audit semantics:

- `BACKUP_CREATED` is emitted when an authenticated admin backup operation
  writes a managed archive; `reason` contains the archive path
- `BACKUP_IMPORTED` is emitted after an uploaded archive passes deep
  verification and is published into the managed backup set
- `BACKUP_EXPORT_STARTED` is emitted on the first successful chunk read for a
  managed archive transfer, including when a client starts at a non-zero
  offset; reaching EOF closes the inferred transfer for subsequent auditing
- `BACKUP_FAILED` is emitted when backup creation, import commit, or export
  streaming fails; `reason` contains the failure reason
- `BACKUP_RESTORE_PREVIEWED` is emitted when an authenticated preview operation successfully decrypts and inspects a managed archive; `reason` contains the resolved archive path and `key_count` contains previewed keys
- `BACKUP_RESTORE_PREVIEW_FAILED` is emitted when an authenticated preview request fails; `reason` contains the failure reason
- `CREDENTIAL_RESTORE_INTENT` is durably audited before restore can make its
  first generation-store write. It records the operation ID and
  `replace_existing`; durable-write failure aborts with no store mutation.
- `CREDENTIAL_RESTORE_SUCCEEDED` and `CREDENTIAL_RESTORE_FAILED` carry the
  available archive SHA-256, operation ID, replacement option, and key count.
- `CREDENTIAL_RESTORE_COMMIT_UNCERTAIN` distinguishes a visible store-root
  replacement whose directory-sync durability could not be confirmed; signing stays
  recovery-blocked until reconciliation confirms the root and reloads the
  visible generation.
- `CREDENTIAL_RESTORE_ROLLBACK` records explicit rollback success or failure.
  Failed attempts use `outcome:"failed"` and `reason`.

Store-management audit semantics:

- `STORE_INITIALIZED` is emitted when authenticated local IPC store initialization succeeds
- `STORE_INITIALIZE_FAILED` is emitted when authenticated local IPC store initialization fails
- `PASSPHRASE_CHANGED` is emitted when authenticated local IPC passphrase rotation succeeds; re-encrypted key/template counts are recorded on the event
- `PASSPHRASE_CHANGE_FAILED` is emitted when authenticated local IPC passphrase rotation fails
- `COSIGNER_REFERENCE_CHANGED` is emitted when an admin session imports,
  promotes, or removes a cosigner-reference record; `outcome` is the action
  (or `failed`) and `witness_key_id` identifies the authority, with no
  public-key material in the entry
- generation maintenance is audited in intent/result pairs: each `*_INTENT`
  entry is written durably before the store changes, and a durable-write
  failure refuses the operation. `GENERATION_QUARANTINE_INTENT` and
  `GENERATION_QUARANTINED` come from reconciliation and carry the generation
  and manifest identifiers; the quarantine prune, abandoned-generation
  discard, and deleted-archive prune pairs come from admin sessions and carry
  the operation ID, the affected generation IDs or archive entries, and
  `byte_count` (see [Reconciliation and quarantine](ARCH_STORE.md#reconciliation-and-quarantine)
  and [Deleted archive capacity](ARCH_STORE.md#deleted-archive-capacity))
- `CLIENT_ENROLLMENT_REQUESTED` is emitted when a new `request-enrollment` request is queued (a repeat that refreshes an existing entry is not audited again); its principal and requester are `client:<fingerprint>`, and it carries the remote address and `client_label`
- `CLIENT_ENROLLED` is emitted when an admin session enrolls a key, by approving its queued request or by importing the public key; it carries the key fingerprint, the `client_label` recorded, the request's remote address (empty for an import), and the admin session attribution
- `CLIENT_ENROLLMENT_REJECTED` is emitted when an admin session rejects a queued request; it carries the fingerprint, `client_label`, and admin session attribution
- `CLIENT_KEY_REVOKED` is emitted when an admin session revokes one enrolled key or every key; it carries the fingerprint, `client_label`, closed-connection count (single-key revocation only; revoke-all entries carry no count), and admin session attribution

### Auth Pipeline in Server

All sensitive handlers run through both authentication and authorization:

```go
// internal/signerapp/daemon/run.go composes the Signer; internal/signerapp/daemon/http_runtime.go
// registers handlers. Product authentication is bound directly to the one runtime.
authorizer := authz.NewProductSingleAuthorizer()

server := &Signer{
    nodeFailState: &productruntime.NodeFailState{},
    authorizer:    authorizer,
}
server.httpAuth = newProductAuthenticator(server.nodeFailState, productRuntime)

// Handler registration with action and resource (internal/signerapp/daemon/http_runtime.go)
mux.HandleFunc("/sign", server.requireAuth(auth.ActionSignRequest, auth.Resource{Type: "transaction"}, server.handleSign))
mux.HandleFunc("/sign/bounded-admin", server.requireAuth(auth.ActionSignRequest, auth.Resource{Type: "transaction"}, server.handleBoundedAdmin))
mux.HandleFunc("/sign/component", server.requireAuth(auth.ActionSignComponent, auth.Resource{Type: "transaction"}, server.handleSignComponent))
mux.HandleFunc("/sign/assemble", server.requireAuth(auth.ActionSignAssemble, auth.Resource{Type: "transaction"}, server.handleSignAssemble))
mux.HandleFunc("/sign/rotating/prepare", server.requireAuth(auth.ActionSignRequest, auth.Resource{Type: "transaction"}, server.handleRotatingPrepare))
mux.HandleFunc("/sign/rotating/sign", server.requireAuth(auth.ActionSignRequest, auth.Resource{Type: "transaction"}, server.handleRotatingSign))
mux.HandleFunc("/sign/cancel", server.requireAuth(auth.ActionSignRequest, auth.Resource{Type: "transaction"}, server.handleSignCancel))
mux.HandleFunc("/plan", server.requireAuth(auth.ActionSignRequest, auth.Resource{Type: "transaction"}, server.handlePlan))
mux.HandleFunc("/status", server.requireAuth(auth.ActionIdentityView, auth.Resource{Type: "identity"}, server.handleStatus))
mux.HandleFunc("/keys", server.requireAuth(auth.ActionKeysView, auth.Resource{Type: "keys"}, server.handleKeys))
mux.HandleFunc("/keytypes", server.requireAuth(auth.ActionKeyTypesView, auth.Resource{Type: "keytypes"}, server.handleKeyTypes))
mux.HandleFunc("/admin/generate", server.requireAuth(auth.ActionKeysGenerate, auth.Resource{Type: "key"}, server.handleAdminGenerate))
mux.HandleFunc("/admin/keys", server.requireAuth(auth.ActionKeysDelete, auth.Resource{Type: "key"}, server.handleAdminDelete))
```

HTTP authentication resolves the connection's enrolled key against the
registry bound to the one product runtime. Node failure is checked first and
fails closed.

```go
// internal/signerapp/daemon/http_auth.go
func (fs *Signer) requireAuth(action auth.Action, resource auth.Resource, next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        ctx := r.Context()

        // Step 1: Authentication - who is this?
        identity, err := fs.httpAuth.Authenticate(ctx, r)
        if err != nil {
            // Return 401 Unauthorized
            return
        }

        // Step 2: Authorization - are they allowed?
        if err := fs.authorizer.Authorize(ctx, identity, action, resource); err != nil {
            // Return 403 Forbidden
            return
        }

        // Step 3: Inject identity into request context
        ctx = auth.ContextWithIdentity(ctx, identity)
        next(w, r.WithContext(ctx))
    }
}
```

Handlers may extract the authenticated principal identity with
`auth.IdentityFromContext(r.Context())` for attribution. They do not use it to
select storage: key lookups, policy, approvals, and mutation all use the
process-owned product runtime. Boundary adapters stamp the fixed `default`
value into compatibility-bearing audit and status fields.

This pipeline keeps handler code behind the `Authorizer` interface.

## Security Properties

### Client Key Authentication (HTTP over SSH)

| Property | Implementation |
|----------|----------------|
| Credential | Client SSH private key (Ed25519, ECDSA, or hardware-backed `sk-`); never transmitted |
| Identity | SHA256 key fingerprint, attached to the API connection by the SSH server |
| Registry | `identities/default/.ssh/authorized_keys`, daemon-written, strict parser, atomic publication |
| Transport security | Loopback REST listener answers only `/health`; every authenticated request arrives through an SSH tunnel |

### Passphrase Authentication (Admin Protocol)

| Property | Implementation |
|----------|----------------|
| Key derivation | Argon2id (memory-hard, GPU-resistant) |
| Encryption | AES-256-GCM (authenticated encryption) |
| Socket security | `/run/apsigner` mode 0750, Unix socket mode 0660, strict non-writable parent validation |
| Memory protection | `mlockall()` prevents swap when enabled successfully, keys zeroed after use (see below) |
| Single active admin session | Only one apadmin/apapprover admin connection at a time over IPC |

### Keyring Encryption

The store keeps its data keys in a keyring (the arrangement HashiCorp Vault's
barrier uses): the passphrase unwraps a stored key rather than becoming one.

```
┌──────────────────────────────────────────────────────────────────┐
│  Unlock Flow                                                     │
│                                                                  │
│  Passphrase ──── Argon2id (memory-hard) ────► KEK                │
│                       ▲                        │                 │
│                       │                        ▼                 │
│            store-root.enc (salt)         Unwrap term keys        │
│                                                │                 │
│                                                ▼                 │
│                                          Decrypt key files       │
└──────────────────────────────────────────────────────────────────┘
```

**Benefits:**
- Single Argon2id derivation at unlock time instead of per-file
- One KDF operation to open the keyring; full unlock also validates and scans
  the selected generation, so its cost grows with store contents
- Term keys held in signer memory during session and covered by process memory
  locking when that protection is enabled successfully
- The KEK never outlives the unwrap, so a memory disclosure yields term keys but
  not the ability to unwrap a future keyring

**Store Root (`store-root.enc`), schema `aplane.store-root.v1`:**

```json
{
  "schema": "aplane.store-root.v1",
  "format_version": 1,
  "keyring": {
    "schema": "aplane.keyring.v3",
    "envelope_version": 3,
    "kdf_time": 2,
    "kdf_memory": 65536,
    "kdf_threads": 4,
    "salt": "<base64 KEK salt>",
    "nonce": "<base64 nonce>",
    "sealed_keyring": "<base64 sealed term set>"
  },
  "current_generation_id": "gen-1700000000-0123abcd",
  "selection_term": 4,
  "selection_mac": "<64 lowercase hex: current-term HMAC-SHA256>"
}
```

The KDF parameters and salt are in the clear because they are inputs to the
unwrap, not secrets. The selection MAC binds the generation selector to the
exact wrapped keyring, making authority and content selection one commit.

**Keystore Marker (`.keystore`):**

```json
{
  "version": 6,
  "layout": "store-root/v1",
  "created": "2026-07-27T07:35:34Z"
}
```

The marker exists only so an older binary rejects the store before touching
anything. It carries no salt, no verifier, and no KDF parameters, so nothing in
it can disagree with the keyring.

**Key File Envelope Versions:**

| Version | Use | Description |
|---------|-----|-------------|
| 2 | Standalone backup/export | Self-contained passphrase-based encryption with an embedded salt; used by `apstore` `.apb` files, not by in-keystore `.key` or `.cos` files |
| 3 | In-keystore managed objects | Term envelope for account `.key`, cosigner witness `.cos`, and templates; records the term that sealed it and binds the term plus the object's class and canonical selector into the AEAD's authenticated data |

**Memory Protection:**

Memory protection consists of two measures that prevent private key material from being written to disk:
1. **Disable core dumps** (`setrlimit(RLIMIT_CORE, 0)`) - prevents memory dump on crash
2. **Lock memory** (`mlockall()`) - prevents memory pages from being swapped to disk

Core-dump disabling is usually available to the process. Memory locking may
require root, `CAP_IPC_LOCK`, or a raised `RLIMIT_MEMLOCK`.

| Config | Behavior |
|--------|----------|
| `require_memory_protection: false` (default) | Warn if protection cannot be enabled, continue startup |
| `require_memory_protection: true` | Fail startup if either protection measure fails |

Set `require_memory_protection: true` in production environments where key security is critical. The server will refuse to start without full memory protection.

**Note:** apshell keeps account signing authority on apsigner, but it does handle
its client SSH authentication key. External plugins may also hold their own
private signing material in their own plugin processes.

### Term Key Lifecycle and Concurrency

#### Lifecycle Overview

Term keys follow a strict lifecycle:

1. **Unwrap** — at unlock the passphrase is fed to Argon2id to produce a KEK, which `crypto.OpenStoreRootStore` uses to unwrap the term keys and authenticate generation selection.
2. **Held in signer memory** — the term keys are stored in `FileKeyStore.keyring` and are protected from swap when process memory locking is enabled successfully.
3. **Zeroed on lock or shutdown** — `ClearKeys()` overwrites every term key with zeros and drops the keyring.

`WithKeyring` is the only accessor. `Unlock` returns no key material, and
nothing hands out a term key's bytes: callers receive the keyring and ask it to
seal or open.

#### WithKeyring Callback

Every operation that needs to seal or open (signing, export, key scan, store)
calls:

```go
keyStore.WithKeyring(func(kr *crypto.Keyring) error {
    // kr is open for the duration of this callback
    plaintext, err := kr.Open(sealed, crypto.AccountKeyContext(address))
})
```

`WithKeyring` acquires `cacheLock.RLock()` for the lifetime of the callback, so
`ClearKeys()` cannot zero the keyring while a caller is using it. If the
keystore is locked (`keyring == nil`) it returns an error immediately.

The same RLock-through-operation pattern is used in `Get` and `Scan` (and by
every `WithKeyring` callback) — any code path that uses the keyring holds
`RLock` through the entire cryptographic operation. Because no copy of a term
key is ever handed out, there is nothing to outlive the lock.

#### RLock / WLock Concurrency

`FileKeyStore.cacheLock` is a single `sync.RWMutex` guarding both the key cache and the keyring:

| Operation | Lock | Can overlap with |
|-----------|------|------------------|
| Keyring-backed decrypt, export, scan, store | `RLock` | Other `RLock` holders |
| `ClearKeys()` | `WLock` | Nothing — blocks until all `RLock` holders finish |
| `Unlock()` (open the keyring) | `WLock` | Nothing |

Multiple keyring-backed operations proceed concurrently under `RLock`. When
the signer locks, `ClearKeys()` requests the exclusive `WLock` and blocks until
every in-flight keyring reader finishes. This prevents term-key use after
zeroing. Decrypted request-owned `KeyMaterial` can continue beyond key
retrieval and is separately zeroed by the signing executor.

#### Lock Path

Callers (the admin `lock_identity` handler and IPC disconnect cleanup) call
`productruntime.Runtime.Lock()` directly, which conceptually executes the following steps in order:

1. Set the lock runtime state to `Locked`; if it was already locked, return without side effects.
2. Run the identity lock callback (`performLockCleanup`). The key watcher stays running; while locked it marks the identity dirty instead of reloading keys.
3. Drain background key users: cancel their contexts and wait for them to finish, before `passphraseLock` is taken.
4. Acquire `passphraseLock.WLock`:
   - `keySession.Destroy()` — blocks until in-flight `GetKey` calls release the
     session; request-wide draining is owned by the request server lifecycle.
   - Reinitialize the key session with the same `keyStore`.
   - `keyStore.ClearKeys()` — zeros every term key under `cacheLock.WLock`.
5. Release `passphraseLock`.
6. Acquire `keysLock.WLock`, clear all identity key maps, release.
7. Notify the admin hub that the signer identity is locked.

The locks are never held simultaneously — each is acquired and released sequentially, avoiding deadlock.

Authenticated admin clients may request the same lock path explicitly with
`lock_identity`. The request is authorized with `identity.lock` for the bound
identity. `apadmin` handles local inactivity by disconnecting; the signer then
applies `lock_on_disconnect` in the normal disconnect cleanup path.

#### Shutdown Path

On `SIGINT` / `SIGTERM`, `internal/signerapp/startup.RunLifecycle` stops
started services in reverse start order. It closes audit logging and destroys
the one product runtime only after every service reports a clean stop:

All service stops share one 5 s shutdown deadline.

1. Close the API listener, cancel every in-flight request context, then
   `httpServer.Shutdown(ctx)` — drain in-flight HTTP requests. Every request
   context descends from one server base context, so a `/sign` parked on
   operator approval is rejected at once instead of holding shutdown until the
   deadline (and cannot be approved after the stop began).
2. Cancel and stop the SSH server.
3. `ipcServer.Stop()` — stop accepting new IPC connections and close active sessions.
4. Stop the rotating stage-table worker.
5. Write `SERVER_STOP` and close the audit log.
6. Call `Destroy()` on the product runtime:
   - `StopKeyWatcher()` — prevents new reloads.
   - drain background key users, then take the passphrase lock, as a lock does,
     so a lock cleanup racing shutdown cannot interleave.
   - `keySession.Destroy()` — drain in-flight key retrieval operations.
   - `keyStore.ClearKeys()` — zero every term key.

If any service stop fails, lifecycle writes a synced
`SERVER_STOP_INCOMPLETE` record with the service error. A deadline error means
a handler may still be executing, so lifecycle retains the audit logger and
runtime state until process exit; this avoids tearing dependencies down under
that handler and leaves the logger open for its final records. A non-deadline
error is reported only after handlers have drained, so the logger is closed and
runtime key state is destroyed normally. The SSH server applies the lifecycle
deadline to its accept loop and connection handlers and returns the deadline
error rather than treating an incomplete drain as success. The clean shutdown
destroy path stops watcher dispatch before draining key operations and zeroing
the keyring.

#### Passphrase Zeroing Discipline

Every code path that converts a passphrase string to `[]byte` zeros the byte slice after use:

```go
passphraseBytes := []byte(passphrase)
defer crypto.ZeroBytes(passphraseBytes)
```

This applies to:

- **IPC auth** — passphrase verified by unwrapping the keyring, then zeroed.
- **Unlock** — passphrase used to unwrap the keyring, zeroed immediately after `passphraseLock` is released.
- **Export request**: the passphrase field of a key-export request is zeroed on receipt; key export is always refused.
- **Startup auto-unlock** — `startPassphrase` from `TEST_PASSPHRASE` or `passphrase_command_argv` is zeroed immediately after the initial `ReloadWithPassphrase` call completes.

### Passphrase Command Helper Protocol

The signer supports an external command protocol for passphrase storage and retrieval, following the same pattern as Git credential helpers. This enables headless operation (auto-unlock at startup) and automated keystore management without human interaction.

**Configuration:**

```yaml
# identities/default/unlock.yaml, normally written by appass
passphrase_command_argv: ["/usr/local/bin/appass-file", "/var/lib/apsigner/identities/default/passphrase"]
passphrase_command_env:          # optional, process env is never inherited
```

Path resolution: the helper is configured in `identities/default/unlock.yaml`,
and its `passphrase_command_argv` elements are used as written; `argv[0]` must
be an absolute path. Relative-path resolution against the data directory
applies only to the legacy `passphrase_command_argv` in the process-global
`config.yaml`, which is consulted only when `unlock.yaml` has no command.

**Protocol contract:**

The verb is injected as `argv[1]` before the user's arguments. For example, `["/usr/local/bin/appass-file", "/var/lib/apsigner/identities/default/passphrase"]` with verb `read` executes `/usr/local/bin/appass-file read /var/lib/apsigner/identities/default/passphrase`.

| Verb | stdin | stdout | Required |
|------|-------|--------|----------|
| `read` | nothing | passphrase bytes | yes |
| `write` | passphrase bytes | passphrase bytes (read-back) | optional |

- **`read`**: Returns the stored passphrase on stdout. Exit 0 on success, non-zero on failure.
- **`write`**: Receives the new passphrase on stdin, stores it, then echoes the stored value back on stdout for round-trip verification. Exit non-zero if the write verb is unsupported — callers fall back to displaying the passphrase for manual storage.

**Output handling:**

- Exactly one trailing newline is stripped (not `TrimSpace` — leading/trailing spaces in passphrases are preserved)
- Output prefixed with `base64:` or `hex:` is decoded accordingly
- NUL bytes are rejected
- stdout is capped at 8 KB; stderr is discarded (a misbehaving helper could leak secrets to stderr)

**Callers:**

| Caller | Verb | Purpose |
|--------|------|---------|
| `apsigner` startup (headless) | `read` | Auto-unlock signer at boot |
| `apstore initialize` | `write` | Store the chosen passphrase when a helper is already configured |
| `apadmin changepass` | `write` | Require manual entry of the old passphrase, then store the new passphrase after atomic key re-encryption |

`appass` setup does not go through `WritePassphrase`: for `appass-file` it
writes the passphrase file directly, and for `appass-systemd-creds` it invokes
the helper's `write` verb itself and runs its own round-trip check before
writing `unlock.yaml`.

**Round-trip verification (`write`):**

`WritePassphrase` sends the passphrase on stdin, captures the read-back from stdout, and compares using `subtle.ConstantTimeCompare`. A mismatch aborts the operation. For `changepass`, the current passphrase is always entered manually even when a helper is configured for startup auto-unlock. Key re-encryption is authoritative once committed; a later helper-write failure is reported as a warning and requires the operator to repair auto-unlock using the new passphrase.

**Security properties:**

| Property | Implementation |
|----------|----------------|
| Environment isolation | Process environment is never inherited; only `passphrase_command_env` entries and `CREDENTIALS_DIRECTORY` (systemd credential path) are passed |
| Binary validation | Must be executable, must not be group/world-writable |
| Path restriction | `argv[0]` must be absolute; `unlock.yaml` argv is used as written (only the legacy `config.yaml` field is resolved against the data directory) |
| Timeout | 5-second deadline with process-group kill (child processes included) |
| Output limit | 8 KB max stdout to prevent memory exhaustion |
| Constant-time comparison | Write round-trip uses `crypto/subtle` |

**Bundled helpers:**

- **`appass-file`** (dev-only) — Plaintext file helper. Stores the passphrase unencrypted on disk. Implements both `read` and `write`. **Not for production** — the passphrase is readable by anyone with access to the file.

- **`appass-systemd-creds`** (production, Linux) — Encrypts the passphrase using `systemd-creds`, which binds the encrypted blob to the machine's TPM2 chip and/or host key. The credential file persists on disk across reboots but can only be decrypted on the same machine. Implements both `read` and `write` with round-trip verification. Requires **systemd 250+** (Ubuntu 24.04+, Debian 12+, RHEL/Rocky 9+). Not available on Ubuntu 22.04 or earlier.

  ```yaml
  # identities/default/unlock.yaml, normally written by appass
  passphrase_command_argv:
    - /usr/local/bin/appass-systemd-creds
    - /var/lib/apsigner/identities/default/passphrase.cred
  ```

  **How `read` works:**

  `appass-systemd-creds read` uses a two-tier strategy:

  1. **Preferred: `CREDENTIALS_DIRECTORY`** — When running under a systemd unit with `LoadCredentialEncrypted`, systemd (PID 1, running as root) decrypts the credential at service start and places the plaintext in a tmpfs at `$CREDENTIALS_DIRECTORY/aplane-passphrase`. `appass-systemd-creds` reads directly from this path. No root access required. The `CREDENTIALS_DIRECTORY` environment variable is automatically passed through to passphrase command helpers (the only exception to the env-isolation policy).

  2. **Fallback: `systemd-creds decrypt`** — When `CREDENTIALS_DIRECTORY` is not set (e.g., manual invocation outside a systemd unit), `appass-systemd-creds` calls `systemd-creds decrypt --name=aplane-passphrase <file> -` directly. This requires root or polkit authorization because `systemd-creds` must access the TPM2 device or host key.

  **How `write` works:**

  `appass-systemd-creds write` reads the passphrase from stdin, calls `systemd-creds encrypt --name=aplane-passphrase - <file>` to create the encrypted credential, verifies the round-trip by decrypting and comparing, then echoes the passphrase to stdout. Always requires root since `systemd-creds encrypt` accesses the TPM2/host key directly. This is a one-time operation for `appass` setup or passphrase change.

  **Credential naming:**

  The `--name=aplane-passphrase` flag binds the credential to that specific name. The encrypted blob cannot be decrypted under a different name, preventing it from being repurposed by other services. The same name must appear in both `systemd-creds encrypt` and the `LoadCredentialEncrypted` directive.

  **Key material selection:**

  `systemd-creds` automatically selects the best available key material:

  | Available | Encryption binding | Security level |
  |-----------|-------------------|----------------|
  | TPM2 + host key | Hardware chip + file on disk | Strongest — disk theft alone is insufficient |
  | TPM2 only | Hardware chip | Strong — requires physical machine |
  | Host key only | File at `/var/lib/systemd/credential.secret` | Weaker — disk clone is sufficient to decrypt |

  Check what your machine supports:
  ```bash
  systemd-creds has-tpm2
  ```

  If the machine lacks a TPM2 chip, the credential is bound only to the host key (a symmetric key file on disk, readable only by root). This protects against casual file reads but **not** against an attacker who can clone the entire disk. For stronger protection on non-TPM2 machines, a custom helper integrating a secrets manager (HashiCorp Vault, cloud KMS, etc.) is recommended.

  **Persistence across reboots:**

  The encrypted `.cred` file is a regular file on disk — it survives reboots. On each service start, systemd re-decrypts it using the same TPM2/host key. The decrypted plaintext in `$CREDENTIALS_DIRECTORY` is ephemeral (tmpfs) and disappears when the service stops or the machine powers off.

  **What it protects against:**

  | Threat | Protected? | Notes |
  |--------|-----------|-------|
  | Disk theft (machine off) | Yes (with TPM2) | Credential bound to hardware chip |
  | Disk cloning | Yes (with TPM2) | TPM2 state cannot be cloned |
  | Unauthorized file read | Yes | `.cred` file is encrypted; plaintext only in root-owned tmpfs |
  | Root on running machine | No | Root can read `$CREDENTIALS_DIRECTORY` or dump process memory |
  | Disk theft (no TPM2) | No | Host key is on the same disk |

See [USER_INSTALL.md](USER_INSTALL.md#systemd-install) for the operator setup steps (verifying TPM2, initializing the keystore, configuring `appass`, rotating the passphrase, and migrating to a new machine).

**Writing a custom helper:**

A helper is any executable that accepts a verb as its first argument. Minimal shell example:

```sh
#!/bin/sh
case "$1" in
  read)  security find-generic-password -s apsigner -w ;;
  write) security delete-generic-password -s apsigner 2>/dev/null
         read -r pass
         security add-generic-password -s apsigner -w "$pass"
         echo "$pass" ;;
  *)     exit 2 ;;
esac
```

Helpers that only support `read` should exit non-zero on `write`. The caller will fall back to displaying the passphrase for manual storage.

### Bounded Authorization Contract Admin Witnesses

Bounded1 requires the base spending signature on every accepted transaction.
When a profile authorizes `rekey` with `admin_key`, every pure rekey also
requires a Falcon-1024 contract-admin signature over a domain-separated digest
of the exact transaction ID and immutable bounded program binding. Composer-
owned checks reject rekey-plus-transfer, close, clawback, unsupported types,
and over-ceiling fees before either signing path.

The contract-admin private key is a Falcon-1024 witness in standalone custody,
never a signer or `apstore` key. Apsigner
runs normal policy and forced operator review, loads only the spending key, and
returns a typed partial through `/sign/bounded-admin`. `aprekey`
independently validates the finalized group, stored bounded metadata, supplied
program, and pure-rekey shape before producing the final LogicSig argument.
Ordinary `/sign` rejects admin-key operations rather than returning an
apparently complete transaction.

Keeping the `.wit` artifact off the signer makes the account
structurally unable to perform admin-key operations when external custody is
unavailable. A compromised unlocked signer can still make policy-permitted
spends and request a partial, but cannot complete the on-chain admin gate.

The same witness key form is used for signer-custodied cosigner authority, but
the custodian capabilities are disjoint: the networked signer produces only
`APLANE_COSIGNER_V1` component-domain signatures, while the offline ceremony
produces only `APLANE_BOUNDED_ADMIN_AUTH_V1` signatures. One keypair should
serve one role for life. Known local collisions are rejected during account
generation; out-of-band reuse remains an operator responsibility and
invalidates the intended role-containment argument.

Online `aprekey rekey` owns network and signer connectivity but delegates
private-key use to the helper's signing path. For a stronger custody boundary,
`prepare-rekey` writes a non-secret `.apbounded-admin-request` for transfer to an
offline ceremony machine; `sign` returns a request-bound
`.apbounded-admin-signature`; and `complete` rechecks the frozen request before
submission. See [ARCH_BOUNDED_DSA.md](ARCH_BOUNDED_DSA.md).

### Defense in Depth

| Attack Vector | Mitigation |
|---------------|------------|
| Credential guessing | No shared secret exists; SSH public-key authentication only |
| SSH key compromise | Per-key revocation closes the key's connections and refuses its next handshake; the key grants no admin capability |
| Timing attacks | SSH signature verification; no secret comparison on the HTTP path |
| Memory forensics | `mlockall()`, key zeroing, core dumps disabled |
| Swap file leakage | Memory locking prevents swap (`require_memory_protection: true` enforces this) |
| Socket hijacking | Permissions check, symlink rejection |
| Blind signing | TxnBytesHex required, transaction verification |
| Foreign LSig resource manipulation | `lsig_resources` is advisory; incorrect hints cause submission failure, not security bypass |
| LogicSig delegation | "Program" prefix blocked (prevents standing spend authorization) |
| MITM on SSH | TOFU host key verification via known_hosts |
| Cache tampering | HMAC-signed cache files (see below) |
| Policy tampering | Each policy document in the selected generation (`default.json` and every `policies/<selector>.json`) has a `.hmac` sidecar that authenticates its exact bytes with a key derived from the product store's current term key; missing or mismatched policy integrity on any document fails the whole policy load |
| Plugin filesystem access | External plugins require OS sandboxing and checksum verification |
| Manual production startup | `.prod` signer data marker blocks startup unless systemd-managed |

Production-managed signer data directories contain `.prod`. When this marker is
present, `apsigner` refuses manual startup unless `APLANE_SYSTEMD_MANAGED=1`
or parent PID is 1, so operators use the managed service path with the expected
passphrase helper and memory-protection settings.

### Cache Integrity Protection

apshell uses local cache files to store aliases, sets, signer addresses, and other user data. These caches are protected against tampering using HMAC-SHA256 signatures.

**Why cache integrity matters:**
- An attacker who modifies `alias_cache.json` could redirect payments to malicious addresses
- Modified `signer_cache.json` could cause transactions to be signed by wrong keys
- Cache tampering is a local attack vector that bypasses network security

**Implementation:**

```
┌──────────────────────────────────────────────────────────────────┐
│  Signed Cache Format                                             │
│                                                                  │
│  {                                                               │
│    "version": 1,                                                 │
│    "data": "<base64-encoded cache JSON>",                        │
│    "hmac": "<hex-encoded HMAC-SHA256 signature>"                 │
│  }                                                               │
└──────────────────────────────────────────────────────────────────┘

On save:  data → JSON serialize → base64 encode → HMAC sign → write
On load:  read → verify HMAC → base64 decode → JSON deserialize → data
```

**Key management:**
- A 256-bit random signing key is generated on first use
- Stored in `cache/.cache_key` with mode 0600
- Key is unique per installation (different key per machine/user)

**Protected caches:**
| Cache File | Contents |
|------------|----------|
| `cache/alias_cache.json` | User-defined address aliases |
| `cache/set_cache.json` | User-defined address sets |
| `cache/signer_cache.json` | Signer address → key mappings |
| `cache/<network>_asa_cache.json` | ASA metadata by network context token |
| `cache/<network>_auth_cache.json` | Rekeyed account auth addresses by network context token |

**Failure behavior:**
- If HMAC verification fails, a security warning is displayed
- The cache is not loaded (starts fresh)
- User is alerted to potential tampering

## Summary

| Aspect | HTTP (apshell) | IPC (apadmin) | SSH Tunnel |
|--------|-------------|-------------------|------------|
| Auth credential | Enrolled SSH key of the connection | Passphrase | Enrolled SSH key |
| Auth frequency | Every request | Once per connection | Once per tunnel |
| Authorization | Authorizer interface | Authorizer interface | Transport only; tunneled HTTP requests authorize separately |
| Connection model | Stateless | Persistent session | Persistent transport |
| Security boundary | Possession of the enrolled private key | Knowledge of passphrase | Possession of the enrolled private key |
| Target user | Scripts/automation | Human operator | Remote agents/users |
| Key management | Yes (admin endpoints) | Yes | No |
| Signing approval | Via policy or TUI | Direct approve/reject | Via policy or TUI |
| Audit logging | Per-request | Session and action attribution | Connect/disconnect plus tunneled request/admin audit |

The multi-channel design separates concerns:
- **HTTP**: Optimized for automation, scriptability, stateless operation
- **IPC**: Optimized for human interaction, key security, session management
- **SSH**: Secure transport and the single client authentication step (enrolled public key)

**Admin endpoint separation:** `/admin/generate` and `/admin/keys` use
separate stable actions (`keys.generate`, `keys.delete`) from signing
(`sign.request`). The closed product allowlist names each action explicitly, so
adding a known action does not accidentally expose it; an enrolled client key
holds the `client` role and never an administrative action.

## Source of Truth

Primary implementation files:

- `internal/auth/authorizer.go`
- `internal/authz/authorizer.go`
- `internal/signerapp/adminserver/session.go`
- `internal/signerapp/adminserver/handlers.go`
- `internal/signerapp/daemon/http_auth.go`
- `internal/signerapp/daemon/product_authenticator.go`
- `internal/signerapp/daemon/http_runtime.go`
- `internal/signerapp/daemon/admin_services.go`
- `internal/signerapp/daemon/audit_attribution.go`
- `internal/signerapp/audit/audit.go`

Compatibility-bearing references:

- `internal/protocol/error_codes.go`
- `internal/protocol/messages.go`
- `docs/ARCH_CONTRACTS.md`
