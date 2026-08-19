# Security Architecture

This document describes APlane's security architecture: authentication channels,
SSH transport security, passphrase and key handling, audit, cache integrity, and
defense-in-depth controls. The closed single-product authorization model is
defined in [ARCH_AUTHORIZATION.md](ARCH_AUTHORIZATION.md).

## Overview

APlane uses a multi-layer security model designed for distinct use cases.

**Authorization:** Runtime code uses the `auth.Authorizer` path. Product
credentials map to the reserved `system:product-admin` principal, and the
closed product authorizer requires exact membership in its explicit action
allowlist. See
[ARCH_AUTHORIZATION.md](ARCH_AUTHORIZATION.md) for the detailed model.

**Policy enforcement:** Operator approval and warning surfacing are active. A narrow signer safety policy layer is implemented for product-scoped signing policy in `policy.yaml` and sentry component policy in sentry-domain `policy.yaml`, with guards such as rekey rejection, close-out rejection, clawback rejection, amount/fee ceilings, transfer review thresholds, forced review for warning-level findings, and a narrow auto-approval rule for single 0-value ALGO/ASA self-transfer requests.

**Deployment scope:** identity model is described in [ARCH_OVERVIEW.md](ARCH_OVERVIEW.md) (Identity Model).

| Channel | Tool | User Type | Auth Method | Connection Model |
|---------|------|-----------|-------------|------------------|
| SSH Tunnel + HTTP | apshell | Agents or users | Public key + token (2FA) | Persistent (transport) |
| Admin protocol over IPC | apadmin / apapprover | Human operator | Passphrase | Persistent (session) |
| Admin protocol over SSH subsystem | apadmin (remote) | Human operator | SSH key + token + passphrase | Persistent (session) |

## Authentication Channels

### 1. HTTP REST API (Token-Based)

Used by apshell and other HTTP clients for signing requests.

```
┌─────────────────────────────────────────────────────────────────┐
│  Request: POST /sign                                            │
│  Header: Authorization: aplane 5f7a8c9b2d1e4f6a...              │
│  Body: { "requests": [{ "auth_address": "...",                 │
│                        "txn_bytes_hex": "..." }] }              │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Step 1: Authentication (who is this?)                          │
│  Authenticator.Authenticate(request)                            │
│  └── TokenAuthenticator validates Authorization: aplane header  │
│      └── Constant-time comparison (timing-attack safe)          │
│  └── Returns Identity or 401 Unauthorized                       │
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
- **Stateless**: Each request authenticated independently
- **No login step**: Product token read from `identities/default/aplane.token` at startup
- **Security boundary**: Filesystem permissions on token file (mode 0600)
- **Trust model**: If you can read the token file, you can make API calls

**Token Details:**
- 32 bytes (256 bits) of cryptographic randomness
- Hex-encoded (64 characters)
- Generated on first server startup if not present
- Stored in `identities/default/aplane.token` with mode 0600

**Token Lifecycle and Limitations:**

One product token serves the fixed `default` signer runtime, so all clients
share the same bearer credential.

| Aspect | Behavior |
|--------|----------|
| Scope | One product token serves HTTP API and SSH tunnel authentication for `default` |
| Revocation | Operator can revoke/regenerate the product token from `apadmin`; clients must re-run `request-token` or otherwise receive the new token |
| Per-client differentiation | None at the bearer-token layer; all clients share the same credential |
| Compromise impact | Bearer access to HTTP wherever the signer API is reachable; normal SSH tunnel access also requires an enrolled SSH key |

**Client Token Handling:**

Clients receiving the token should:
- Obtain the token via secure out-of-band channel (encrypted transfer, secrets manager, physical)
- Store as `aplane.token` in the `$APCLIENT_DATA` directory with mode `0600`
- Never embed the token inline in scripts checked into version control
- Treat token compromise as full compromise; notify operator to rotate

**Protected Endpoints:**
- `POST /sign` - Submit signing requests
- `POST /sign/bounded-admin` - Prepare an external contract-admin partial
- `POST /sign/component` - Produce guarded or bounded, kind-tagged components
- `POST /sign/assemble` - Assemble guarded or bounded-sentry signed groups
- `POST /sign/cancel` - Cancel a live synchronous signing request by request ID
- `POST /plan` - Preview group building (dummies, fees, group ID) without signing
- `GET /status` - Return signer status, keyset revision, and approval timing metadata
- `GET /keys` - List available signing keys
- `GET /keytypes` - List available key types and creation parameters
- `POST /admin/generate` - Generate new keys
- `DELETE /admin/keys` - Delete keys

**Request Size Limits:**
- JSON POST endpoints (`/sign`, `/sign/bounded-admin`, `/sign/component`,
  `/sign/assemble`, `/sign/cancel`, `/plan`, and `/admin/generate`) enforce a
  5 MB request body limit
- Oversized requests receive HTTP 413 (Payload Too Large)
- All authentication error responses use JSON format (not text/plain)

See [ARCH_HTTP_API.md](ARCH_HTTP_API.md) for the authoritative route and wire
contracts.

Simulation is client-owned after ordinary signing. Apsigner exposes no
simulation route and does not contact algod for simulation. It applies the
same policy, approval, signing, and audit behavior as submission, releases an
executable group, and cannot know whether the client later simulates or submits
it.

> **Note on admin endpoints:** The `/admin/*` endpoints use the same token as `/sign` and `/keys`. In the single-operator model the token holder is the operator.

**Unprotected Endpoints:**
- `GET /health` - Health check (no sensitive data)

### 2. Admin Protocol (Passphrase-Based Session)

Used by apadmin for interactive key management and signer control over either:
- local IPC Unix socket
- remote SSH `aplane-admin` subsystem

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
       │  3. AuthMessage { passphrase, version }     │
       │────────────────────────────────────────────>│
       │                                             │
       │  4. Bind product runtime (default)          │
       │     Open product keyring.enc                │
       │     (Argon2id KEK + AES-256-GCM unwrap)     │
       │                                             │
       │  5. AuthResultMessage { success: true }     │
       │<────────────────────────────────────────────│
       │                                             │
       │     Session bound to product runtime        │
       │     (Session.bound = identity.Runtime)      │
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
- **Single active admin**: Only one admin client connection is allowed at a time across IPC and SSH admin transport

**Passphrase Verification (Keyring):**
1. The keyring root (`keyring.enc`) carries the Argon2id parameters and salt in
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
Request 1: POST /sign + Token ──► Authenticate ──► Handle ──► Response
Request 2: POST /sign + Token ──► Authenticate ──► Handle ──► Response
Request 3: GET /keys + Token  ──► Authenticate ──► Handle ──► Response
```

- No server-side session state
- Token required on every request
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

When apshell connects to a remote apsigner, it uses an SSH tunnel with configurable authentication:

```
┌──────────┐                                          ┌────────────┐
│  apshell │◄═══════ SSH Tunnel (persistent) ════════►│  apsigner │
└──────────┘                                          └────────────┘
     │                                                       │
     │    HTTP requests through tunnel still require         │
     │    token authentication on each request               │
     │                                                       │
```

### SSH Authentication Model

SSH authentication requires **both** a valid API token and a valid public key (2FA).
The normal SSH username is the fixed non-secret value `default`. The bearer token never appears
in SSH metadata; the client proves possession through a programmatic,
host-key-bound keyboard-interactive exchange after public-key authentication.

**Authentication flow:**

```
Client                                               Server
  │                                                       │
  │  1. SSH connect (username=default, pubkey=KEY)        │
  │──────────────────────────────────────────────────────>│
  │                                                       │
  │  2. Verify enrolled key possession; partial success  │
  │<──────────────────────────────────────────────────────│
  │                                                       │
  │  3. Exchange fresh client/server nonces              │
  │  4. Server proves token possession first             │
  │<──────────────────────────────────────────────────────│
  │  5. Client verifies server proof, then proves token   │
  │──────────────────────────────────────────────────────>│
  │                                                       │
  │  6. Server verifies proof; SSH session established   │
  │<──────────────────────────────────────────────────────│
```

Keys are enrolled exclusively through the `request-token` operator-approved flow.

**Key points:**
- Token is always required for normal connections (no "key-only" mode); the `request-token` bootstrap flow is the sole exception
- The keyboard-interactive exchange is fully programmatic and never prompts a user
- Proofs are HMAC-SHA256 values over the identity, accepted SSH host key, and two fresh nonces; server and client roles are domain-separated
- The server proves token possession before the client emits its proof
- Clients reject an SSH server that accepts the public key without completing mutual token proof
- Proof comparison is constant-time

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
  │  3. Client checks ssh.known_hosts_path               │
  │     - Key found and matches → Continue               │
  │     - Key found but differs → REJECT (MITM warning)  │
  │     - Key not found → Prompt user to accept (TOFU)   │
  │                                                      │
```

**Configuration:**
- Client: `ssh.known_hosts_path` - where to store/verify server keys (default: `$APCLIENT_DATA/.ssh/known_hosts`)
- Server: `ssh.host_key_path` - persistent host key (default: `$APSIGNER_DATA/.ssh/ssh_host_key`)

With explicit TOFU enabled, a wrongly trusted first endpoint still cannot learn
the bearer token: it cannot produce the server proof, and the client sends no
client proof until that proof verifies. A proof observed on one connection is
not reusable against the real signer because the accepted host-key hash and
fresh nonces differ.

### SSH Security Properties

| Property | Implementation |
|----------|----------------|
| Two-factor auth | Enrolled SSH public key + mutual, host-key-bound API token proof |
| Key enrollment | Operator-approved `request-token` flow only |
| Host key verification | TOFU model with persistent known_hosts |
| Token confidentiality | Token never appears in SSH username, metadata, challenge, or response |
| Proof replay resistance | Fresh client/server nonces and accepted host-key hash bind each proof transcript |
| Token validation | HMAC-SHA256 with constant-time proof comparison |
| Token revocation | Operator-initiated via apadmin; invalidates new HTTP requests and closes active SSH connections |
| Transport encryption | SSH protocol (Ed25519 keys) |

The token-confidentiality row applies to normal SSH authentication. Initial
provisioning intentionally sends the approved token over the constrained,
encrypted provisioning channel, and authenticated HTTP requests subsequently
carry the bearer token inside the SSH tunnel. Fresh nonce/proof state is
connection-local, is never reused, and is discarded after each authentication
attempt; garbage-collected SDKs cannot guarantee memory zeroization.

### SSH Audit Logging

All SSH connections are logged for audit purposes:

```json
{"timestamp":"2026-01-18T10:30:00Z","event":"SESSION_CONNECTED","identity_id":"default","target_identity_id":"default","principal":"system:product-admin","requester_principal":"system:product-admin","remote_addr":"192.168.1.5:54321","reason":"default"}
{"timestamp":"2026-01-18T11:45:00Z","event":"SESSION_DISCONNECTED","identity_id":"default","target_identity_id":"default","principal":"system:product-admin","requester_principal":"system:product-admin","remote_addr":"192.168.1.5:54321","reason":"default"}
```

Logged information:
- Remote IP address and port
- Key fingerprint (on registration)
- Connect/disconnect events

**Note:** The SSH username is the fixed non-secret product identity ID. The SSH auth-log
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
| `endpoint.ssh.authorized_keys_path` | `.ssh/authorized_keys` | Validated/resolved server setting for underlying SSH wiring; product client authorization and enrollment use `identities/default/.ssh/authorized_keys` |

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
- Application-level auth (`Authorization: aplane <token>`) is still required per HTTP request
- SSH key possession plus token proof authenticates the tunnel identity; the same token authorizes each HTTP request

### Token Provisioning via SSH

New clients without a token can request one through the SSH tunnel using the `request-token` command. This provides a secure bootstrap mechanism.

```
┌──────────┐                                          ┌────────────┐
│  apshell │                                          │  apsigner │
└────┬─────┘                                          └─────┬──────┘
     │                                                      │
     │  1. SSH connect (username=request-token:default,     │
     │     pubkey only)                                     │
     │─────────────────────────────────────────────────────>│
     │                                                      │
     │  2. Server verifies pubkey, starts token request     │
     │                                                      │
     │  3. Operator (apadmin) sees approval prompt         │
     │     "Client <fingerprint> requesting token"          │
     │                                                      │
     │  4. Operator approves/rejects                        │
     │                                                      │
     │  5. If approved: SSH key enrolled + token sent       │
     │<─────────────────────────────────────────────────────│
     │                                                      │
     │  6. Client saves token to aplane.token               │
     │                                                      │
```

**Key points:**
- Token provisioning requires operator approval (human in the loop)
- SSH public key identifies the requesting client
- Operator approval gates both key enrollment and token issuance: after approval, the SSH key is enrolled first, then the token is loaded/generated, then delivered to the client
- Key enrollment is product-scoped under `identities/default/.ssh/authorized_keys`
- No token is created or audited before both approval and enrollment succeed
- If token delivery to the client fails, no success audit is recorded
- Token is transmitted over the encrypted SSH channel
- Once provisioned, client can connect normally

### Token Revocation

The operator can revoke the current API token from the apadmin TUI Admin panel
using the `t` key. This invalidates the existing token and forces all clients
to re-authenticate.

```
┌──────────┐      ┌──────────┐                     ┌────────────┐
│ apadmin │      │  apshell │                     │  apsigner │
└────┬─────┘      └────┬─────┘                     └─────┬──────┘
     │                  │                                 │
     │  1. Operator presses t (Revoke Token)              │
     │───────────────────────────────────────────────────>│
     │                  │                                 │
     │                  │  2. Server generates new token  │
     │                  │     Writes to aplane.token      │
     │                  │     Updates HTTP authenticator  │
     │                  │     Updates SSH server          │
     │                  │                                 │
     │                  │  3. All active SSH connections  │
     │                  │     forcibly closed             │
     │                  │<────────────── [disconnected] ──│
     │                  │                                 │
     │                  │  4. Client must request-token   │
     │                  │     to obtain new token         │
     │                  │     (requires operator approval)│
     │                  │                                 │
```

**What happens on revocation:**
1. A new random token is generated and written to `identities/default/aplane.token`
2. The product HTTP token authenticator is updated in-memory
3. The SSH server records the new generation and closes every connection authenticated with an older product token
4. Connected clients see an immediate disconnect ("SSH tunnel disconnected")

**Client re-authorization:**
- Clients must run `request-token` to obtain a new token (same flow as initial provisioning)
- The operator must approve the new token request via the apadmin TUI
- If a client runs `request-token` while still connected, the session is automatically disconnected first
- Once re-provisioned, the client can `connect` normally with the new token

**Use cases:**
- Compromised token (e.g., leaked credential)
- Rotating credentials as a security practice
- Revoking access from a specific device (after revocation, selectively re-approve only trusted clients)

### Uniform SSH Tunneling

All apshell connections to the signer use SSH tunneling, regardless of whether the signer is on localhost or a remote host. This provides uniform per-client identity via SSH public keys.

```
┌──────────┐                                          ┌────────────┐
│  apshell │◄═══════ SSH Tunnel (encrypted) ═════════►│  apsigner │
│          │ :random ─────────────────────────► :11270│            │
└──────────┘                                          └────────────┘
     │
     └── HTTP through tunnel + Authorization: aplane <token>
```

**Why uniform SSH:**
- Every client has a unique SSH key identity, even on localhost
- The signer can distinguish between clients (e.g., for audit logging)
- Token-only access cannot distinguish between clients ("token holder")
- Consistent security model regardless of network topology

**Connection properties:**
- SSH provides transport encryption
- Host key verification prevents MITM (TOFU via known_hosts)
- Random local port avoids conflicts
- Token auth still required per HTTP request (2FA: SSH key + token)

**Configuration:**
- Client connection profiles live in `$APCLIENT_DATA/endpoints.yaml`
- An endpoint URL can be `ssh://host[:port]` for tunneled signer access
- Endpoint records carry the SSH identity file, `known_hosts` path, and token
  file; relative paths resolve against the client data directory
- Server SSH listener settings live in signer `config.yaml` under
  `endpoint.ssh:`
- `request-token` also uses SSH for token provisioning and writes the selected
  endpoint's token file

**Bootstrap requirement:**
Non-interactive modes (scripts, JS runner) reject unknown SSH hosts — they require the signer's host key to already be in `known_hosts`. Users must first connect interactively with `apshell` (via `connect` or `request-token`), which prompts for TOFU host key approval and saves it. After that, scripts and automation can connect without prompts.

The `request-token` flow is the only bootstrap path: a single operator approval gates both SSH key enrollment and API token issuance. This is a single trust decision that fully onboards the client.

## Interface Architecture

Authentication, authorization, and audit logging are abstracted behind
interfaces for extensibility. This section summarizes the interfaces; the
authorization architecture and invariants live in
[ARCH_AUTHORIZATION.md](ARCH_AUTHORIZATION.md).

### Authenticator Interface

```go
// internal/auth/authenticator.go
type Authenticator interface {
    Authenticate(ctx context.Context, r *http.Request) (*Identity, error)
    Method() string
}

type Identity struct {
    ID       string            // Unique identifier
    Type     string            // "service", "system", or other principal type
    Method   string            // "aplane-token", "mtls", "oidc"
    Metadata map[string]string // Additional claims
}
```

**Implementation:**
- `TokenAuthenticator` - Validates `Authorization: aplane <token>` header

### Authorizer Interface

The authorization model separates the actor principal from the target signing
identity. In product mode, compatibility credentials map to
`system:product-admin`; `default` is the signing identity being acted on,
not the authorization principal.

```go
// internal/auth/authorizer.go
type Authorizer interface {
    Authorize(ctx context.Context, identity *Identity, action Action, resource Resource) error
}

type Action string  // "sign.request", "keys.view", "keys.generate"
type Resource struct {
    Type string     // "transaction", "keys", "system"
    ID   string     // Resource identifier (e.g., key address)
    IdentityID string // Target signing identity
}
```

**Implementation:**
- `internal/authz.ProductAuthorizer` - exact principal, action-allowlist, and product-resource checks with no mutable principal/group/grant graph
- `authz.NewProductSingleAuthorizer()` - maps product credentials to the reserved `system:product-admin` principal and a copied explicit action allowlist

See [ARCH_AUTHORIZATION.md](ARCH_AUTHORIZATION.md) for the action vocabulary,
product-principal model, denial semantics, and enforcement points.

### Audit Logger

```go
// internal/signerapp/audit/audit.go
type AuditLogger struct {
    file    *os.File
    mu      sync.Mutex
    path    string
    written uint64
}

type AuditEntry struct {
    Timestamp          time.Time
    Event              AuditEventType
    IdentityID         string
    TargetIdentityID   string
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
}
```

The current implementation is a concrete append-only JSONL logger in
`internal/signerapp/audit/audit.go`, not a generic cross-application
`internal/audit` sink package.
`NewAuditLogger(path)` opens the audit log with mode `0600`, appends one JSON
object per line, syncs each write, and rotates around the current 10 MB limit.

Audit entries carry attribution fields:

- `identity_id`: fixed `default` attribution for product-runtime work
- `target_identity_id`: signing identity targeted by the action
- `principal`: principal field
- `requester_principal`: principal requesting the action
- `approver_principal`: principal approving or rejecting the action
- `admin_session_id`: admin protocol session ID when available
- `transport`: `ipc`, `ssh`, `http`, or empty for process-level events
- `outcome`: requested, approved, rejected, failed, denied, connected, disconnected, or similar
- `txn_auth`, `txn_sender`, `txn_type`, `txn_details`, `txid`: transaction/key attribution for signing and key events
- `remote_addr`: remote address when available
- `reason`: rejection, failure, or denial detail when available
- `key_count`: key count for startup and reload events

Denial behavior:

- HTTP authentication failures and HTTP authorization denials are recorded as
  `AUTH_FAILED` with a reason such as `missing_credentials`,
  `invalid_credentials`, `unsupported_identity:<identity>`, or
  `unauthorized:<action>`.
- Admin protocol authorization denials are recorded as
  `AUTHORIZATION_DENIED` with the admin session context, action/resource details,
  target identity, principal attribution, transport, and denial reason.

### Auth Pipeline in Server

All sensitive handlers run through both authentication and authorization:

```go
// cmd/apsigner/main.go composes the Signer; internal/signerapp/daemon/http_runtime.go
// registers handlers. Product authentication is bound directly to the one runtime.
productAuth := daemon.NewProductAuthenticator(nodeFailState, productRuntime)
authorizer := authz.NewProductSingleAuthorizer()

server := &Signer{
    authenticator: productAuth,
    runtime:       productRuntime,
    authorizer:    authorizer,
}

// Handler registration with action and resource (internal/signerapp/daemon/http_runtime.go)
mux.HandleFunc("/sign", server.requireAuth(auth.ActionSignRequest, auth.Resource{Type: "transaction"}, server.handleSign))
mux.HandleFunc("/sign/bounded-admin", server.requireAuth(auth.ActionSignRequest, auth.Resource{Type: "transaction"}, server.handleBoundedAdmin))
mux.HandleFunc("/sign/component", server.requireAuth(auth.ActionSignComponent, auth.Resource{Type: "transaction"}, server.handleSignComponent))
mux.HandleFunc("/sign/assemble", server.requireAuth(auth.ActionSignAssemble, auth.Resource{Type: "transaction"}, server.handleSignAssemble))
mux.HandleFunc("/sign/cancel", server.requireAuth(auth.ActionSignRequest, auth.Resource{Type: "transaction"}, server.handleSignCancel))
mux.HandleFunc("/plan", server.requireAuth(auth.ActionSignRequest, auth.Resource{Type: "transaction"}, server.handlePlan))
mux.HandleFunc("/status", server.requireAuth(auth.ActionIdentityView, auth.Resource{Type: "identity"}, server.handleStatus))
mux.HandleFunc("/keys", server.requireAuth(auth.ActionKeysView, auth.Resource{Type: "keys"}, server.handleKeys))
mux.HandleFunc("/keytypes", server.requireAuth(auth.ActionKeyTypesView, auth.Resource{Type: "keytypes"}, server.handleKeyTypes))
mux.HandleFunc("/admin/generate", server.requireAuth(auth.ActionKeysGenerate, auth.Resource{Type: "key"}, server.handleAdminGenerate))
mux.HandleFunc("/admin/keys", server.requireAuth(auth.ActionKeysDelete, auth.Resource{Type: "key"}, server.handleAdminDelete))
```

HTTP token authentication validates against the token authority bound to the
one product identity runtime. Node failure is checked first and fails closed.

```go
// internal/signerapp/daemon/http_auth.go
func (fs *Signer) requireAuth(action auth.Action, resource auth.Resource, next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        ctx := r.Context()

        // Step 1: Authentication - who is this?
        identity, err := fs.authenticator.Authenticate(ctx, r)
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

Handlers extract the identity with `auth.IdentityFromContext(r.Context())` and use `identity.ID` to scope key lookups and audit log entries through the bound identity runtime. In product mode, externally reachable flows target the product identity; `auth.CurrentProductIdentityID()` is a process-boundary/defaulting helper rather than the primary handler-time identity resolution mechanism.

This pipeline keeps handler code behind the `Authorizer` interface.

## Security Properties

### Token Authentication (HTTP)

| Property | Implementation |
|----------|----------------|
| Timing-attack resistance | `crypto/subtle.ConstantTimeCompare()` |
| Token entropy | 256 bits (cryptographically random) |
| Token storage | File with mode 0600 (owner read/write only) |
| Transport security | Local REST listener binds to `127.0.0.1`; normal client access goes through SSH tunnels |

### Passphrase Authentication (Admin Protocol)

| Property | Implementation |
|----------|----------------|
| Key derivation | Argon2id (memory-hard, GPU-resistant) |
| Encryption | AES-256-GCM (authenticated encryption) |
| Socket security | `/run/apsigner` mode 0750, Unix socket mode 0660, strict non-writable parent validation |
| Memory protection | `mlockall()` prevents swap when enabled successfully, keys zeroed after use (see below) |
| Single active admin session | Only one apadmin/apapprover admin connection at a time across IPC and SSH |

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
│              keyring.enc (salt)          Unwrap term keys        │
│                                                │                 │
│                                                ▼                 │
│                                          Decrypt key files       │
└──────────────────────────────────────────────────────────────────┘
```

**Benefits:**
- Single Argon2id derivation at unlock time instead of per-file
- O(1) unlock regardless of number of keys
- Term keys held in signer memory during session and covered by process memory
  locking when that protection is enabled successfully
- The KEK never outlives the unwrap, so a memory disclosure yields term keys but
  not the ability to unwrap a future keyring

**Keyring Root (`keyring.enc`), schema `aplane.keyring.v2`:**

```json
{
  "schema": "aplane.keyring.v2",
  "envelope_version": 2,
  "kdf_time": 2,
  "kdf_memory": 65536,
  "kdf_threads": 4,
  "salt": "<base64-encoded 32-byte KEK salt>",
  "nonce": "<base64-encoded 12-byte nonce>",
  "sealed_keyring": "<base64-encoded AES-GCM sealed term set>"
}
```

The KDF parameters and salt are in the clear because they are inputs to the
unwrap, not secrets. Everything secret is inside `sealed_keyring`.

**Keystore Marker (`.keystore`):**

```json
{
  "version": 5,
  "layout": "keyring/v2",
  "created": "2026-07-27T07:35:34Z"
}
```

The marker exists only so an older binary rejects the store before touching
anything. It carries no salt, no verifier, and no KDF parameters, so nothing in
it can disagree with the keyring.

**Key File Envelope Versions:**

| Version | Use | Description |
|---------|-----|-------------|
| 2 | Standalone backup/export | Self-contained passphrase-based encryption with an embedded salt; used by `apstore` `.apb` files, not by in-keystore `.key` or `.sen` files |
| 3 | In-keystore managed objects | Term envelope for account `.key`, sentry witness `.sen`, and templates; records the term that sealed it and binds the term plus the object's class and canonical selector into the AEAD's authenticated data |

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

**Note:** apshell does not require memory protection because it never handles private keys directly—it only constructs transactions and sends them to apsigner for signing.

### Term Key Lifecycle and Concurrency

#### Lifecycle Overview

Term keys follow a strict lifecycle:

1. **Unwrap** — at unlock the passphrase is fed to Argon2id to produce a KEK, which `crypto.OpenKeyringStore` uses to unwrap the stored term keys.
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

The same RLock-through-operation pattern is used in `Get`, `Store`,
`GetPublicKeyInfo`, and `Scan` — any code path that uses the keyring holds
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

`Signer.lock()` (in `internal/signerapp/daemon/runtime.go`) delegates to `identity.Runtime.Lock()`, which conceptually executes the following steps in order:

1. Set the lock runtime state to `Locked`; if it was already locked, return without side effects.
2. Run the identity lock callback (`performLock`). The key watcher stays running; while locked it marks the identity dirty instead of reloading keys.
3. Acquire `passphraseLock.WLock`:
   - `keySession.Destroy()` — blocks until in-flight `GetKey` calls release the
     session; request-wide draining is owned by the request server lifecycle.
   - Reinitialize the key session with the same `keyStore`.
   - `keyStore.ClearKeys()` — zeros every term key under `cacheLock.WLock`.
4. Release `passphraseLock`.
5. Acquire `keysLock.WLock`, clear all identity key maps, release.
6. Notify the admin hub that the signer identity is locked.

The locks are never held simultaneously — each is acquired and released sequentially, avoiding deadlock.

Authenticated admin clients may request the same lock path explicitly with
`lock_identity`. The request is authorized with `identity.lock` for the bound
identity. `apadmin` handles local inactivity by disconnecting; the signer then
applies `lock_on_disconnect` in the normal disconnect cleanup path.

#### Shutdown Path

On `SIGINT` / `SIGTERM`, `internal/signerapp/startup.RunLifecycle` stops
started services in reverse start order. It closes audit logging and destroys
the one product runtime only after every service reports a clean stop:

1. `httpServer.Shutdown(ctx)` — drain in-flight HTTP requests (5 s timeout).
2. Cancel and stop the SSH server.
3. `ipcServer.Stop()` — stop accepting new IPC connections and close active sessions.
4. Write `SERVER_STOP` and close the audit log.
5. Call `Destroy()` on the product runtime:
   - `StopKeyWatcher()` — prevents new reloads.
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
- **Export verification** — passphrase re-verified before export, then zeroed.
- **Startup auto-unlock** — `startPassphrase` from `TEST_PASSPHRASE` or `passphrase_command_argv` is zeroed immediately after the initial `ReloadWithPassphrase` call completes.

### Passphrase Command Helper Protocol

The signer supports an external command protocol for passphrase storage and retrieval, following the same pattern as Git credential helpers. This enables headless operation (auto-unlock at startup) and automated keystore management without human interaction.

**Configuration:**

```yaml
passphrase_command_argv: ["./appass-file", "passphrase"]
passphrase_command_env:          # optional, process env is never inherited
```

Path resolution: all elements of `passphrase_command_argv` are resolved relative to the data directory. Absolute paths are left unchanged.

**Protocol contract:**

The verb is injected as `argv[1]` before the user's arguments. For example, `["./appass-file", "passphrase"]` with verb `read` executes `./appass-file read passphrase`.

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
| `appass` setup | `write` | Store the product identity's auto-unlock passphrase |
| `apstore initialize` | `write` | Store the chosen passphrase when a helper is already configured |
| `apadmin changepass` | `write` | Require manual entry of the old passphrase, then store the new passphrase after atomic key re-encryption |

**Round-trip verification (`write`):**

`WritePassphrase` sends the passphrase on stdin, captures the read-back from stdout, and compares using `subtle.ConstantTimeCompare`. A mismatch aborts the operation. For `changepass`, the current passphrase is always entered manually even when a helper is configured for startup auto-unlock. Key re-encryption is authoritative once committed; a later helper-write failure is reported as a warning and requires the operator to repair auto-unlock using the new passphrase.

**Security properties:**

| Property | Implementation |
|----------|----------------|
| Environment isolation | Process environment is never inherited; only `passphrase_command_env` entries and `CREDENTIALS_DIRECTORY` (systemd credential path) are passed |
| Binary validation | Must be executable, must not be group/world-writable |
| Path restriction | Relative paths resolved against data directory; must be absolute after resolution |
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

The same witness key form is used for signer-custodied sentry authority, but
the custodian capabilities are disjoint: the networked signer produces only
`APLANE_SENTRY_V1` component-domain signatures, while the offline ceremony
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
| Token brute force | 256-bit token (2^256 combinations) |
| SSH key compromise | Token always required (2FA: token + key) |
| Timing attacks | Constant-time comparison |
| Memory forensics | `mlockall()`, key zeroing, core dumps disabled |
| Swap file leakage | Memory locking prevents swap (`require_memory_protection: true` enforces this) |
| Socket hijacking | Permissions check, symlink rejection |
| Blind signing | TxnBytesHex required, transaction verification |
| Foreign LSig resource manipulation | `lsig_resources` is advisory; incorrect hints cause submission failure, not security bypass |
| LogicSig delegation | "Program" prefix blocked (prevents standing spend authorization) |
| MITM on SSH | TOFU host key verification via known_hosts |
| Cache tampering | HMAC-signed cache files (see below) |
| Policy tampering | `identities/default/policy.yaml.hmac` authenticates the product policy document with a key derived from the product store's current term key; missing or mismatched policy integrity fails closed |
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
| Auth credential | Token file | Passphrase | SSH key + token (2FA) |
| Auth frequency | Every request | Once per connection | Once per tunnel |
| Authorization | Authorizer interface | Authorizer interface | Transport only; tunneled HTTP/admin paths authorize separately |
| Connection model | Stateless | Persistent session | Persistent transport |
| Security boundary | File permissions | Knowledge of passphrase | SSH key + token file |
| Target user | Scripts/automation | Human operator | Remote agents/users |
| Key management | Yes (admin endpoints) | Yes | No |
| Signing approval | Via policy or TUI | Direct approve/reject | Via policy or TUI |
| Audit logging | Per-request | Session and action attribution | Connect/disconnect plus tunneled request/admin audit |

The multi-channel design separates concerns:
- **HTTP**: Optimized for automation, scriptability, stateless operation
- **IPC**: Optimized for human interaction, key security, session management
- **SSH**: Secure transport for remote access, public key + token authentication (2FA)

**Admin endpoint separation:** `/admin/generate` and `/admin/keys` use
separate stable actions (`keys.generate`, `keys.delete`) from signing
(`sign.request`). The closed product allowlist names each action explicitly, so
adding a known action does not accidentally expose it; the current product
token intentionally represents the one full product administrator.

Authorization behavior is documented in
[ARCH_AUTHORIZATION.md](ARCH_AUTHORIZATION.md).
