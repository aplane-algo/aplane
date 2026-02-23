# Security Architecture

This document describes the authentication and authorization architecture of aPlane.

## Overview

aPlane uses a multi-layer authentication model designed for distinct use cases.

**Current state:** Authentication implies full authorization—any valid credential (token or passphrase) grants full capabilities on its respective channel. See [Authorization Interface](#authorizer-interface) for the extensibility path to role-based access control.

| Channel | Tool | User Type | Auth Method | Connection Model |
|---------|------|-----------|-------------|------------------|
| HTTP REST API | apshell | Scripts/automation | Bearer token | Stateless (per-request) |
| IPC Unix Socket | apadmin | Human operator | Passphrase | Persistent (session) |
| SSH Tunnel | apshell (remote) | Agents or users | Public key (+ optional token) | Persistent (transport) |

## Authentication Channels

### 1. HTTP REST API (Token-Based)

Used by apshell and other HTTP clients for signing requests.

```
┌─────────────────────────────────────────────────────────────────┐
│  Request: POST /sign                                            │
│  Header: Authorization: aplane 5f7a8c9b2d1e4f6a...            │
│  Body: { "sender_address": "...", "message_hex": "..." }        │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Step 1: Authentication (who is this?)                          │
│  Authenticator.Authenticate(request)                            │
│  └── TokenAuthenticator validates Authorization: aplane header │
│      └── Constant-time comparison (timing-attack safe)          │
│  └── Returns Identity or 401 Unauthorized                       │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Step 2: Authorization (are they allowed?)                      │
│  Authorizer.Authorize(identity, action, resource)               │
│  └── AllowAllAuthorizer permits all authenticated requests      │
│  └── Future: RBACAuthorizer for role-based access               │
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
- **No login step**: Token read from `aplane.token` file at startup
- **Security boundary**: Filesystem permissions on token file (mode 0600)
- **Trust model**: If you can read the token file, you can make API calls

**Token Details:**
- 32 bytes (256 bits) of cryptographic randomness
- Hex-encoded (64 characters)
- Generated on first server startup if not present
- Stored in `<keystore>/users/default/aplane.token` with mode 0600

**Token Lifecycle and Limitations:**

The current model uses a single process-wide token for all authentication:

| Aspect | Current Behavior |
|--------|------------------|
| Scope | One token serves HTTP API and SSH tunnel authentication |
| Revocation | None; rotation requires regenerating file and re-provisioning all clients |
| Per-client differentiation | None; all clients share the same credential |
| Compromise impact | Full access to both HTTP and SSH channels |

This simplicity is intentional for experimental deployments. Future versions will support a token store with per-client entries, expiry, and revocation (see [Future Enhancements](#future-enhancements)).

**Client Token Handling:**

Clients receiving the token should:
- Obtain the token via secure out-of-band channel (encrypted transfer, secrets manager, physical)
- Store as `aplane.token` in the `$APCLIENT_DATA` directory with mode `0600`
- Never embed the token inline in scripts checked into version control
- Treat token compromise as full compromise; notify operator to rotate

**Protected Endpoints:**
- `POST /sign` - Submit signing requests
- `POST /plan` - Preview group building (dummies, fees, group ID) without signing
- `GET /keys` - List available signing keys
- `POST /admin/generate` - Generate new keys
- `DELETE /admin/keys` - Delete keys

> **Note on admin endpoints:** The `/admin/*` endpoints use the same token as `/sign` and `/keys`. In the current single-user model this is fine — the token holder is the operator. If tokens are later shared with automation or distributed to multiple clients, key management operations should be gated behind a separate admin token or role (see [Future Enhancements](#future-enhancements)).

**Unprotected Endpoints:**
- `GET /health` - Health check (no sensitive data)

### 2. IPC Unix Socket (Passphrase-Based)

Used by apadmin for interactive key management and signer control.

```
┌──────────────┐                              ┌──────────────┐
│ apadmin  │                              │  apsignerd   │
└──────┬───────┘                              └──────┬───────┘
       │                                             │
       │  1. Connect to aplane.sock              │
       │────────────────────────────────────────────>│
       │                                             │
       │  2. MsgTypeAuthRequired                     │
       │<────────────────────────────────────────────│
       │                                             │
       │  3. AuthMessage { passphrase: "..." }       │
       │────────────────────────────────────────────>│
       │                                             │
       │  4. Verify against .keystore metadata        │
       │     (Argon2id + AES-256-GCM check field)  │
       │                                             │
       │  5. AuthResultMessage { success: true }     │
       │<────────────────────────────────────────────│
       │                                             │
       │     Identity set on connection              │
       │     (IPCConn.identity = "default")          │
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
- **Dual-purpose passphrase**: Authentication + encryption key derivation
- **Single client**: Only one apadmin connection allowed at a time

**Passphrase Verification (Master Key):**
1. Keystore metadata file (`.keystore`) contains master salt and encrypted check value
2. Server derives master key from passphrase + salt using Argon2id (memory-hard)
3. Attempts to decrypt check field (encrypted "ALGOPLANE_OK")
4. If decryption succeeds and plaintext matches, passphrase is valid
5. Master key is retained in memory for decrypting key files (see [Master Key Encryption](#master-key-encryption))

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

### Persistent (IPC)

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

When apshell connects to a remote apsignerd, it uses an SSH tunnel with configurable authentication:

```
┌──────────┐                                          ┌────────────┐
│  apshell │◄═══════ SSH Tunnel (persistent) ════════►│  apsignerd │
└──────────┘                                          └────────────┘
     │                                                       │
     │    HTTP requests through tunnel still require         │
     │    token authentication on each request               │
     │                                                       │
```

### SSH Authentication Model

SSH authentication requires **both** a valid API token and a valid public key (2FA).
The API token is passed as the SSH username, enabling single-step authentication.

| `ssh.auto_register` | Behavior |
|---------------------|----------|
| `true` (default)    | New keys are auto-registered after token validation |
| `false`             | Unknown keys are rejected; only pre-registered keys allowed |

**Authentication flow:**

```
Client                                              Server
  │                                                      │
  │  1. SSH connect (username=API_TOKEN, pubkey=KEY)     │
  │──────────────────────────────────────────────────────>│
  │                                                      │
  │  2. Server validates token (constant-time compare)   │
  │     ✗ Invalid → Reject                               │
  │     ✓ Valid → Check key                              │
  │                                                      │
  │  3. Server checks authorized_keys                    │
  │     - Key found → Authenticate                       │
  │     - Key not found + auto_register → Register + Auth│
  │     - Key not found + !auto_register → Reject        │
  │                                                      │
  │  4. SSH session established                          │
  │<──────────────────────────────────────────────────────│
```

**Key points:**
- Token is always required (no "key-only" mode)
- Token passed as SSH username (no keyboard-interactive prompts)
- Token verification uses constant-time comparison (timing-attack safe)

### Client-Side Host Key Verification (TOFU)

The client verifies the server's identity using Trust On First Use (TOFU):

```
Client                                              Server
  │                                                      │
  │  1. SSH connect                                      │
  │──────────────────────────────────────────────────────>│
  │                                                      │
  │  2. Server sends host key                            │
  │<──────────────────────────────────────────────────────│
  │                                                      │
  │  3. Client checks ssh_known_hosts_path               │
  │     - Key found and matches → Continue               │
  │     - Key found but differs → REJECT (MITM warning)  │
  │     - Key not found → Prompt user to accept (TOFU)   │
  │                                                      │
```

**Configuration:**
- Client: `ssh_known_hosts_path` - where to store/verify server keys (default: `$APCLIENT_DATA/.ssh/known_hosts`)
- Server: `ssh_host_key_path` - persistent host key (default: `$APSIGNER_DATA/.ssh/ssh_host_key`)

### SSH Security Properties

| Property | Implementation |
|----------|----------------|
| Two-factor auth | API token (as username) + Ed25519 public key |
| Key registration control | `ssh_auto_register` config option |
| Host key verification | TOFU model with persistent known_hosts |
| Token validation | Constant-time comparison (timing-attack safe) |
| Transport encryption | SSH protocol (Ed25519 keys) |

### SSH Audit Logging

All SSH connections are logged for audit purposes:

```json
{"timestamp":"2026-01-18T10:30:00Z","event":"SESSION_CONNECTED","principal":"[token]","remote_addr":"192.168.1.5:54321","reason":"[token]"}
{"timestamp":"2026-01-18T11:45:00Z","event":"SESSION_DISCONNECTED","principal":"[token]","remote_addr":"192.168.1.5:54321","reason":"[token]"}
```

Logged information:
- Remote IP address and port
- Key fingerprint (on registration)
- Connect/disconnect events

**Note:** The SSH username contains the API token, so it appears as `[token]` in logs to avoid leaking secrets.

### SSH Configuration Reference

SSH is configured via a nested `ssh:` block. Omit the block entirely to disable SSH.

| Option | Default | Description |
|--------|---------|-------------|
| `ssh.port` | `2222` | SSH listener port |
| `ssh.host_key_path` | `.ssh/ssh_host_key` | Server host key (auto-generated if missing) |
| `ssh.authorized_keys_path` | `.ssh/authorized_keys` | Allowed client public keys |
| `ssh.auto_register` | `true` | Auto-register new client keys after token validation |

**Example config.yaml with auto-registration (default):**
```yaml
signer_port: 11270
ssh:
  port: 2222
  auto_register: true   # New keys auto-register after token validation
```

**Example config.yaml for manual key management:**
```yaml
signer_port: 11270
ssh:
  port: 2222
  auto_register: false  # Reject unknown keys; add to authorized_keys manually
```

**Example config.yaml for direct access (no SSH):**
```yaml
signer_port: 8080
# No ssh: block - REST API binds to all interfaces
```

**Important distinction:**
- SSH tunnel provides **transport security** and **client authentication**
- Application-level auth (Bearer token in HTTP header) still required per request
- SSH key verifies the tunnel client; HTTP token authorizes API operations

### Token Provisioning via SSH

New clients without a token can request one through the SSH tunnel using the `request-token` command. This provides a secure bootstrap mechanism.

```
┌──────────┐                                          ┌────────────┐
│  apshell │                                          │  apsignerd │
└────┬─────┘                                          └─────┬──────┘
     │                                                      │
     │  1. SSH connect (no token yet, pubkey only)          │
     │──────────────────────────────────────────────────────>│
     │                                                      │
     │  2. Server verifies pubkey, starts token request     │
     │                                                      │
     │  3. Operator (apadmin) sees approval prompt          │
     │     "Client <fingerprint> requesting token"          │
     │                                                      │
     │  4. Operator approves/rejects                        │
     │                                                      │
     │  5. If approved: token sent to client                │
     │<──────────────────────────────────────────────────────│
     │                                                      │
     │  6. Client saves token to aplane.token               │
     │                                                      │
```

**Key points:**
- Token provisioning requires operator approval (human in the loop)
- SSH public key identifies the requesting client
- Token is transmitted over the encrypted SSH channel
- Once provisioned, client can connect normally

### Localhost vs Remote Connections

apshell uses different connection strategies based on network topology:

| Scenario | Connection Method | Why |
|----------|-------------------|-----|
| Client and signer on same machine | Direct HTTP | No encryption needed, same trust boundary |
| Client and signer on different machines | SSH tunnel | Encryption and host verification required |

**Localhost connection (direct):**
```
┌──────────┐                    ┌────────────┐
│  apshell │ ─── HTTP :11270 ──>│  apsignerd │
└──────────┘                    └────────────┘
     │
     └── Authorization: aplane <token>
```

- No SSH tunnel overhead
- Token auth provides access control
- No encryption (traffic never leaves machine)
- No MITM risk (connecting to yourself)

**Remote connection (SSH tunnel):**
```
┌──────────┐                                          ┌────────────┐
│  apshell │◄═══════ SSH Tunnel (encrypted) ═════════►│  apsignerd │
│          │ :random ─────────────────────────► :11270│            │
└──────────┘                                          └────────────┘
     │
     └── HTTP through tunnel + Authorization: aplane <token>
```

- SSH provides transport encryption
- Host key verification prevents MITM
- Random local port avoids conflicts
- Token auth still required per HTTP request

**Configuration behavior:**

When `ssh.host` is `localhost` or `127.0.0.1`:
- `connect` command uses direct HTTP (no tunnel)
- `request-token` command still uses SSH (for bootstrap)

When `ssh.host` is a remote address:
- `connect` command establishes SSH tunnel
- All HTTP traffic flows through the tunnel

This design allows a single config file to support both token provisioning (needs SSH) and efficient localhost operation (direct HTTP).

### Security Comparison: Localhost vs Tunnel

| Property | Localhost Direct | SSH Tunnel |
|----------|------------------|------------|
| Encryption | None (not needed) | SSH transport |
| Authentication | Token only | SSH key + Token (2FA) |
| Host verification | N/A | TOFU via known_hosts |
| Attack surface | Smaller (less code) | Larger (SSH stack) |
| Performance | Direct | Tunnel overhead |
| MITM protection | N/A (same machine) | Host key verification |

**Why no security benefit for localhost:**
- Traffic never crosses a network boundary
- If attacker is on the machine, they can access both SSH keys and token
- Same trust boundary either way
- Tunnel adds complexity without security benefit

## Interface Architecture

Authentication, authorization, and audit logging are abstracted behind interfaces for extensibility.

### Authenticator Interface

```go
// internal/auth/authenticator.go
type Authenticator interface {
    Authenticate(ctx context.Context, r *http.Request) (*Identity, error)
    Method() string
}

type Identity struct {
    ID       string            // Unique identifier
    Type     string            // "user", "service", "admin"
    Method   string            // "aplane-token", "mtls", "oidc"
    Metadata map[string]string // Additional claims
}
```

**Current Implementation:**
- `TokenAuthenticator` - Validates `Authorization: aplane <token>` header

**Future Implementations (extensible):**
- `MTLSAuthenticator` - Client certificate authentication
- `OIDCAuthenticator` - OpenID Connect tokens
- `ChainedAuthenticator` - Try multiple methods in order

### Authorizer Interface

```go
// internal/auth/authorizer.go
type Authorizer interface {
    Authorize(ctx context.Context, identity *Identity, action Action, resource Resource) error
}

type Action string  // "sign", "list_keys", "manage_keys"
type Resource struct {
    Type string     // "transaction", "keys", "system"
    ID   string     // Resource identifier (e.g., key address)
}
```

**Current Implementation:**
- `AllowAllAuthorizer` - Permits all actions for authenticated identities

**Future Implementations (extensible):**
- `RBACAuthorizer` - Role-based access control
- `PolicyAuthorizer` - Attribute-based policies

### Audit Sink Interface

```go
// internal/audit/audit.go
type Sink interface {
    Log(ctx context.Context, event Event) error
    Close() error
}

type Event struct {
    Time     time.Time
    Type     EventType         // "SIGN_REQUEST", "AUTH_FAILED", etc.
    Identity string            // Authenticated principal
    Action   string            // Operation performed
    Resource string            // Target of the action
    Success  bool
    Details  map[string]string // Event-specific information
}
```

**Current Implementations:**
- `FileSink` - JSON Lines to local file
- `MultiSink` - Fan-out to multiple sinks
- `NopSink` - Discard (for testing)

**Future Implementations (extensible):**
- `KafkaSink` - Stream to Kafka
- `SyslogSink` - Write to syslog
- `CloudWatchSink` - AWS CloudWatch Logs

### Auth Pipeline in Server

All sensitive handlers run through both authentication and authorization:

```go
// cmd/apsignerd/main.go
authenticator := auth.NewTokenAuthenticator(apiToken)
authorizer := auth.NewAllowAllAuthorizer()

server := &Signer{
    authenticator: authenticator,
    authorizer:    authorizer,
}

// Handler registration with action and resource
mux.HandleFunc("/sign", server.requireAuth(auth.ActionSign, auth.Resource{Type: "transaction"}, server.handleSign))
mux.HandleFunc("/keys", server.requireAuth(auth.ActionListKeys, auth.Resource{Type: "keys"}, server.handleKeys))
```

```go
// cmd/apsignerd/server.go
func (fs *Signer) requireAuth(action Action, resource Resource, next http.HandlerFunc) http.HandlerFunc {
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

Handlers extract the identity with `auth.IdentityFromContext(r.Context())` and use `identity.ID` to scope key lookups and audit log entries. Today all authenticators return `DefaultIdentityID` (`"default"`); the plumbing is ready for per-client identity when a real identity source is wired in.

This pipeline ensures that adding RBAC later requires no changes to handlers - just swap `AllowAllAuthorizer` for `RBACAuthorizer`.

## Security Properties

### Token Authentication (HTTP)

| Property | Implementation |
|----------|----------------|
| Timing-attack resistance | `crypto/subtle.ConstantTimeCompare()` |
| Token entropy | 256 bits (cryptographically random) |
| Token storage | File with mode 0600 (owner read/write only) |
| Transport security | SSH tunnel (remote) or localhost only |

### Passphrase Authentication (IPC)

| Property | Implementation |
|----------|----------------|
| Key derivation | Argon2id (memory-hard, GPU-resistant) |
| Encryption | AES-256-GCM (authenticated encryption) |
| Socket security | Unix socket with mode 0600, symlink rejection |
| Memory protection | `mlockall()` prevents swap, keys zeroed after use (see below) |
| Single client | Only one apadmin connection at a time |

### Master Key Encryption

The keystore uses a master key architecture (similar to HashiCorp Vault) for efficient key management:

```
┌──────────────────────────────────────────────────────────────────┐
│  Unlock Flow                                                      │
│                                                                   │
│  Passphrase ──┬── Argon2id (memory-hard) ────► Master Key        │
│               │        ▲                            │             │
│               │        │                            ▼             │
│               │   .keystore (salt)           Decrypt key files   │
│               │                                                   │
│               └── Verify via .keystore check field               │
└──────────────────────────────────────────────────────────────────┘
```

**Benefits:**
- Single Argon2id derivation at unlock time instead of per-file
- O(1) unlock regardless of number of keys
- Master key held in locked memory during session

**Keystore Metadata (`.keystore`):**

```json
{
  "version": 1,
  "salt": "<base64-encoded 32-byte master salt>",
  "check": "<base64-encoded AES-GCM encrypted 'ALGOPLANE_OK'>",
  "created": "2026-01-21T07:35:34Z"
}
```

| Field | Purpose |
|-------|---------|
| `version` | Metadata format version |
| `salt` | Master salt for Argon2id key derivation |
| `check` | Encrypted verification value (passphrase validation) |
| `created` | Keystore creation timestamp |

**Key File Envelope Versions:**

| Version | Status | Description |
|---------|--------|-------------|
| 1 | Current | Master key; uses keystore-wide master key (Argon2id derived) |

**Memory Protection:**

Memory protection consists of two measures that prevent private key material from being written to disk:
1. **Disable core dumps** (`setrlimit(RLIMIT_CORE, 0)`) - prevents memory dump on crash
2. **Lock memory** (`mlockall()`) - prevents memory pages from being swapped to disk

Both require root/sudo privileges to enable reliably.

| Config | Behavior |
|--------|----------|
| `require_memory_protection: false` (default) | Warn if protection cannot be enabled, continue startup |
| `require_memory_protection: true` | Fail startup if either protection measure fails |

Set `require_memory_protection: true` in production environments where key security is critical. The server will refuse to start without full memory protection.

**Note:** apshell does not require memory protection because it never handles private keys directly—it only constructs transactions and sends them to apsignerd for signing.

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
| Foreign LSig budget manipulation | `lsig_size` is advisory; incorrect hints cause submission failure, not security bypass |
| LogicSig delegation | "Program" prefix blocked (prevents standing spend authorization) |
| MITM on SSH | TOFU host key verification via known_hosts |
| Cache tampering | HMAC-signed cache files (see below) |

### Cache Integrity Protection

apshell uses local cache files to store aliases, sets, signer addresses, and other user data. These caches are protected against tampering using HMAC-SHA256 signatures.

**Why cache integrity matters:**
- An attacker who modifies `alias_cache.json` could redirect payments to malicious addresses
- Modified `signer_cache.json` could cause transactions to be signed by wrong keys
- Cache tampering is a local attack vector that bypasses network security

**Implementation:**

```
┌──────────────────────────────────────────────────────────────────┐
│  Signed Cache Format                                              │
│                                                                   │
│  {                                                                │
│    "version": 1,                                                  │
│    "data": "<base64-encoded cache JSON>",                        │
│    "hmac": "<hex-encoded HMAC-SHA256 signature>"                 │
│  }                                                                │
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
| `cache/auth_cache.json` | Rekeyed account auth addresses |

**Failure behavior:**
- If HMAC verification fails, a security warning is displayed
- The cache is not loaded (starts fresh)
- User is alerted to potential tampering

## Summary

| Aspect | HTTP (apshell) | IPC (apadmin) | SSH Tunnel |
|--------|-------------|-------------------|------------|
| Auth credential | Token file | Passphrase | SSH key (+ optional token) |
| Auth frequency | Every request | Once per connection | Once per tunnel |
| Authorization | Authorizer interface | Implicit (admin) | N/A (transport only) |
| Connection model | Stateless | Persistent session | Persistent transport |
| Security boundary | File permissions | Knowledge of passphrase | SSH key + token file |
| Target user | Scripts/automation | Human operator | Remote agents/users |
| Key management | Yes (admin endpoints) | Yes | No |
| Signing approval | Via policy or TUI | Direct approve/reject | Via policy or TUI |
| Audit logging | Per-request | N/A | Connect/disconnect events |

The multi-channel design separates concerns:
- **HTTP**: Optimized for automation, scriptability, stateless operation
- **IPC**: Optimized for human interaction, key security, session management
- **SSH**: Secure transport for remote access, public key authentication (+ optional token)

## Future Enhancements

The architecture is designed to support hardening without structural changes:

### Token Management

| Current | Future |
|---------|--------|
| Single `aplane.token` file | Token store (file or database) |
| No per-client identity | Per-agent tokens with unique IDs |
| No expiration | Configurable token TTL |
| Manual rotation only | Programmatic revocation |

The `TokenAuthenticator` interface already returns an `Identity` struct—future token stores will populate this with client-specific metadata. Identity-scoped keyspaces are already plumbed end-to-end: identity flows via context to handlers, key cache lookups are scoped by `identity.ID`, and audit log entries carry a `principal` field. Today all paths use `DefaultIdentityID` (`"default"`); wiring in a real identity source activates per-tenant key isolation without handler changes.

**Planned implementations:** `FileTokenStore` → `SqliteTokenStore` → `PostgresTokenStore`

### Authorization

The `Authorizer` interface is already wired into all protected endpoints. Upgrading from `AllowAllAuthorizer` to `RBACAuthorizer` requires no handler changes:

```
Current:  Authenticate → AllowAllAuthorizer → Handler
Future:   Authenticate → RBACAuthorizer    → Handler
```

**Admin endpoint separation:** Today `/admin/generate` and `/admin/keys` share the same token and `AllowAllAuthorizer` as `/sign`. When multi-client token support is added, key management operations (`ActionManageKeys`) should require an elevated role or a separate admin token so that signing-only clients cannot generate or delete keys.

### Security Parameters

These parameters are currently fixed but designed for future configurability:

| Parameter | Current Value | Hardening Direction |
|-----------|---------------|---------------------|
| Key derivation | Argon2id (64MB memory, GPU-resistant) | Already strong |
| SSH approval policy | Configurable | Require manual approval for all |
| Token entropy | 256 bits (32 bytes) | Already strong |

A future "enterprise profile" could enforce stricter defaults without architectural changes.
