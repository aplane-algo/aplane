# Authorization Architecture

This document defines APlane's product authorization model: the reserved admin
principal, explicit allowed actions, resources, and the enforcement points that
protect signer operations.

Product-store model: see [ARCH_OVERVIEW.md](ARCH_OVERVIEW.md) (Fixed Product Store and Runtime). The
product surface exposes one reserved administrator principal and no mutable
principal, group, grant, or runtime-selection management.

## Purpose

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

For broader authentication, SSH, passphrase, encryption, and defense-in-depth
details, see [ARCH_SECURITY.md](ARCH_SECURITY.md). For wire and storage
compatibility contracts, see [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md).

## Core Concepts

### Credential

A credential is proof presented at an authentication boundary.

Credential types include:

- an enrolled client SSH key, presented at the SSH handshake; the HTTP API is
  reachable only through that tunnel, and each request is attributed to the
  key that authenticated its connection
- admin passphrase over local IPC

Credentials authenticate access. They are not themselves the authorization
subject.

### Principal

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

### Product Store and Target Attribution

The one product store owns signer state:

- encrypted key files
- keystore metadata
- product runtime config
- enrolled client registry (`.ssh/authorized_keys`)
- approval coordinator
- runtime lock/unlock state
- watcher and reload ownership

Its durable namespace is `identities/default/`. The directory name is not an
authorization principal or request value.

### Action

An action is a stable operation name used for authorization checks and audit.

Examples:

```text
sign.request
keys.generate
policy.update
clients.revoke
```

### Resource

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

## Product Authorization

The product mode is:

```text
mode: product_single
admin principal: system:product-admin
client principals: client:<fingerprint>, role client
authorization source: closed action allowlists (product admin, client role)
identity/principal/group/grant management UI: enrolled-client list and revocation only
```

The authorization path is:

```text
credential
  -> authenticated product session or tunneled API connection
  -> system:product-admin, or client:<fingerprint> with role client
  -> explicit ProductAllowedActions or ClientAllowedActions membership
  -> concrete resource type and optional resource ID
```

Important implications:

- Logging in with `apadmin` authenticates against the product store, and the admin
  session authorizes as `system:product-admin`.
- A tunneled HTTP request authorizes as the client principal of its
  connection. `ClientAllowedActions` (`internal/authz`) grants only what the
  authenticated HTTP routes expose: `identity.view`, `sign.request`,
  `sign.component`, `sign.assemble`, `keys.view`, `keys.generate`,
  `keys.delete`, and `keytypes.view`. Clients never receive administrative
  actions.
- A known action is not automatically allowed. It must also appear in the
  explicit allowlist for that principal kind.

## Authorization Flow

### HTTP

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

### Admin IPC

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

### No Remote Admin Transport

The admin protocol is carried only over the local IPC socket. SSH carries
port forwarding to the HTTP API and `request-enrollment` bootstrap; it refuses
session channels, so no admin subsystem is reachable over SSH. Remote
administration means logging in to the signer host and running `apadmin`
there.

Recovery-material operations are narrower than normal admin
operations: `keys.import` is accepted only on local IPC admin sessions,
`keys.export` is denied on all admin transports, and `keys.generate` never
returns generated recovery material over the admin protocol.

## Action Vocabulary

Stable action names live in `internal/auth/authorizer.go`. A known-action guard
makes action typos such as `keys.veiw` fail before allowlist matching.

| Action | Meaning | Typical Resource | Unlock Required |
|--------|---------|------------------|-----------------|
| `identity.view` | View identity state | `identity` | No |
| `identity.unlock` | Unlock signer identity | `identity` | No |
| `identity.lock` | Lock signer identity | `identity` | No |
| `identity.backup` | Create, export/read back, and delete signer-managed encrypted backup archives for the product store | `identity` | Yes for create/delete; export/read is available in unlocked or recovery state |
| `identity.restore` | List, import, preview, and directly restore managed credential archives, roll back the latest eligible restore, and reconcile product-store recovery state | `identity` | Yes; recovery-mode inventory, repair, and resolution are allowed while signing remains blocked |
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

## Product Action Allowlist

`ProductAllowedActions` and `ClientAllowedActions` are closed, explicit sets
populated in code. The product authorizer grants an operation only when all of
these conditions hold:

- the principal is exactly `system:product-admin`, or is a `client:` principal
  whose role is `client`;
- the action is in the closed known-action vocabulary;
- the action is independently present in the allowlist for that principal
  kind; and
- the callsite supplies a concrete resource type and, where applicable, ID.

Adding a known action does not add it to the product allowlist. This preserves
a deliberate review point for new sensitive operations. There is no runtime
principal, group, grant, wildcard-target, membership, or disabled-node graph in
the single-product authorizer.

## Principal Resolution

Principal resolution maps authenticated credentials to authorization principals:

```text
admin passphrase
  -> system:product-admin

enrolled client SSH key (connection identity)
  -> client:<SHA256 fingerprint>, role client
```

## Enforcement Points

Authorization checks must run before private-key access, mutation, approval
response handling, client enrollment or revocation, or policy/settings changes.

Enforced callsites:

- `internal/signerapp/daemon/http_runtime.go` wraps HTTP `/sign`,
  `/sign/component`, `/sign/assemble`, `/sign/bounded-admin`, `/plan`, `/status`,
  `/keys`, `/keytypes`, `/admin/generate`, and `/admin/keys` with
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
  passphrase rotation, signing approval response, client enrollment response,
  enrolled-key listing, and key revocation through `s.authorize`.

`/health` is intentionally absent from the enforcement list. It is an
unauthenticated health endpoint in [ARCH_HTTP_API.md](ARCH_HTTP_API.md);
`health.get` is reserved.

## Denial Semantics

Authorization is fail-closed:

- nil or unknown principal is forbidden
- unknown action is forbidden before allowlist matching
- known but unlisted action is forbidden

Wire behavior:

- HTTP authentication failure returns `401`
- HTTP authorization failure returns `403`
- IPC/admin authorization failure returns an `error` message with code
  `authorization_denied`
- HTTP authorization denials are written to the audit log as auth failures with
  an authorization reason
- IPC/admin authorization denials are written to the audit log as
  `AUTHORIZATION_DENIED`

## Audit Attribution

Audit records identify the actors and request context for sensitive operations.

Relevant audit fields:

- `principal`: principal field
- `requester_principal`: principal requesting the operation; for tunneled
  HTTP requests this is the connection's `client:<fingerprint>`
- `approver_principal`: principal approving or rejecting the operation
- `admin_session_id`: admin protocol session ID
- `transport`: `ipc`, `ssh`, `http`, or empty for process events
- `policy_rule_id`: policy rule that forced manual signing review, when present

Target invariant:

```text
Every sensitive operation should be attributable to its principal and relevant
operation-specific resource evidence.
```

Authorization denials must also be attributable. Admin denials record the
session, principal, action, resource, and denial reason. HTTP
denials record the authenticated principal and remote address at the HTTP auth
boundary.

## Security Invariants

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

## Implementation

- stable action vocabulary
- closed product action allowlist
- reserved product-admin principal and fingerprint-named client principals
- admin session principal separation from target signing identity
- HTTP and admin operation gates

## Source Of Truth

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
