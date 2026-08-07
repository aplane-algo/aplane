# Authorization Architecture

This document defines APlane's authorization model: principals, groups, grants,
actions, resources, and the enforcement points that protect signer operations.

Identity model: see [ARCH_OVERVIEW.md](ARCH_OVERVIEW.md) (Identity Model). The
product surface does not expose tenant management, principal management, group
management, grant management, or multiple independent operator domains.

## Purpose

Authorization answers this question:

```text
May this principal perform this action on this target signing identity/resource?
```

It is separate from:

- **Authentication:** Which credential was presented, and did it verify?
- **Signing identity ownership:** Which identity owns keys, config, token files,
  runtime state, and approval state?
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

- HTTP API token from `identities/<identity>/aplane.token`
- admin passphrase over local IPC
- SSH public key plus token for tunnel access
- SSH public key plus token plus passphrase for the `aplane-admin` subsystem

Credentials authenticate access. They are not themselves the authorization
subject.

### Principal

A principal is the actor used for authorization decisions.

Compatibility credentials map to the reserved system principal:

```text
system:product-admin
```

A signing identity such as `default` is not inherently a principal. It is the
key-owning identity being acted on.

### Group

A group is a collection of principals. Group membership alone grants nothing.
Authorization still requires a grant.

The reserved system group is:

```text
system:product-admins
```

### Grant

A grant binds a subject to actions on a target identity.

Grant subjects are encoded as:

```text
principal:<principal-id>
group:<group-id>
```

### Signing Identity

A signing identity owns signer state:

- encrypted key files
- keystore metadata
- identity-scoped config
- API token file
- SSH authorized keys
- approval coordinator
- runtime lock/unlock state
- watcher and reload ownership

The product identity is `default`.

### Target Identity

The target identity is the signing identity an operation acts on. It is carried
through authorization as `auth.Resource.IdentityID`.

### Action

An action is a stable operation name used for authorization checks and audit.

Examples:

```text
sign.request
keys.generate
policy.update
token.revoke
```

### Resource

`auth.Resource` describes the concrete thing being accessed:

```go
type Resource struct {
    Type       string
    ID         string
    IdentityID string
}
```

Conventions:

- `IdentityID` is the target signing identity.
- `Type` is the resource family, such as `key`, `keys`, `policy`,
  `transaction`, or `token`.
- `ID` is the concrete resource identifier when one exists, such as a key
  address, request ID, template key type, or identity ID.
- Empty `IdentityID` is allowed only at boundaries that immediately resolve it
  from the authenticated identity or bound admin session.

## Product Mode

The product mode is:

```text
mode: product_single
exposed signing identity: default
admin principal: system:product-admin
admin group: system:product-admins
grant source: bootstrap records
grant-management UI: none
principal-management UI: none
tenant-management UI: none
```

The authorization path is:

```text
credential
  -> authenticated identity/session
  -> system:product-admin
  -> group:system:product-admins
  -> bootstrap grants
  -> target signing identity/resource
```

Important implications:

- Logging in with `apadmin` authenticates against the selected or bound signing
  identity, but the admin session authorizes as `system:product-admin`.
- `default` is the product signing identity. It is not the
  authorization principal.
- The grant-backed authorizer is used in product mode. Product
  compatibility is represented by bootstrap grants, not an allow-all bypass.

## Authorization Flow

### HTTP

HTTP requests use token authentication followed by authorization:

```text
Authorization: aplane <token>
  -> RegistryAuthenticator
  -> auth.Identity
  -> principal resolver
  -> auth.Authorizer
  -> handler
```

HTTP authentication maps authenticated identity-token credentials to the
bootstrap product principal for authorization. Request routing scopes work
to the authenticated signing identity and rejects cross-identity resource targets
unless explicitly supported by the boundary.

### Admin IPC

Local admin sessions use the admin passphrase and bind to a target identity:

```text
admin auth message
  -> passphrase verification
  -> system:product-admin principal
  -> target identity binding
  -> auth.Authorizer
  -> admin operation
```

Auth-time unlock is authorization-gated before the runtime is unlocked.
Explicit admin lock requests use `identity.lock` for the bound identity.
Admin disconnect cleanup applies the bound identity's `lock_on_disconnect`
setting. Local admin idle timeout is enforced by `apadmin` as a disconnect,
not by a signer-side activity grant.

### SSH Admin Subsystem

Remote admin sessions add SSH transport authentication before the same admin
protocol:

```text
SSH key + token
  -> identity pre-binding
  -> admin passphrase
  -> system:product-admin principal
  -> auth.Authorizer
  -> admin operation
```

The SSH layer authenticates transport and identity binding. The admin protocol
authorizes the operation before sensitive work.

Recovery-material operations are narrower than normal admin
operations: `keys.import` is accepted only on local IPC admin sessions,
`keys.export` is denied on all admin transports, and `keys.generate` never
returns generated recovery material over the admin protocol.

## Action Vocabulary

Stable action names live in `internal/auth/authorizer.go`. A known-action guard
makes action typos such as `keys.veiw` fail before grant matching even if a
grant accidentally contains the same typo.

| Action | Meaning | Typical Resource | Unlock Required |
|--------|---------|------------------|-----------------|
| `identity.view` | View identity state | `identity` | No |
| `identity.unlock` | Unlock signer identity | `identity` | No |
| `identity.lock` | Lock signer identity | `identity` | No |
| `identity.backup` | Create a signer-managed encrypted backup archive for the bound identity | `identity` | Yes |
| `identity.restore` | Preview and directly restore managed credential archives, roll back the latest eligible restore, and reconcile recovery state for the bound identity | `identity` | Yes; recovery-mode repair and resolution are allowed while signing remains blocked |
| `identity.passphrase` | Rotate the identity keystore passphrase | `identity` | Yes |
| `identity.decommission` | Decommission identity | `identity` | No |
| `sign.request` | Request transaction signing, signing plan, or sign-request cancellation | `transaction` | Yes for signing/cancel |
| `sign.component` | Request user-role or sentry-role component signatures for the guarded signing flow | `transaction` | Yes |
| `sign.assemble` | Assemble verified user and sentry component signatures into signed guarded transactions | `transaction` | Yes |
| `sign.approve` | Approve or reject signing request | `sign_request` | No |
| `keys.view` | List keys or view key details | `keys`, `key` | Yes for key list/details |
| `keys.generate` | Generate a key | `key` | Yes |
| `keys.import` | Import a key | `key` | Yes |
| `keys.export` | Export a key mnemonic (disabled) | `key` | Yes |
| `keys.delete` | Delete a key | `key` | Yes |
| `sentries.sync` | Sync public sentry reference metadata into the signer generation catalog | `sentries` | No |
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
| `token.provision` | Approve token provisioning | `token_provisioning` | No |
| `token.revoke` | Revoke identity API token | `token` | No |
| `health.get` | Reserved action name; `/health` is unauthenticated and does not call the authorizer | `system` | No |

New sensitive operations must either use an existing action with the same
meaning or define a new stable action before implementation.

## Grant Model

The runtime authorizer is populated in memory at startup. There is no
YAML grant loader and no on-disk grant file. The following YAML is
illustrative of a durable format; it is not a storage contract:

```yaml
principals:
  - id: system:product-admin
    type: system
    disabled: false

groups:
  - id: system:product-admins
    members:
      - system:product-admin
    disabled: false

grants:
  - subject: group:system:product-admins
    identity_id: "*"
    actions:
      - identity.view
      - identity.unlock
      - identity.lock
      - identity.backup
      - identity.restore
      - identity.passphrase
      - identity.decommission
      - sign.request
      - sign.component
      - sign.assemble
      - sign.approve
      - keys.view
      - keys.generate
      - keys.import
      - keys.export
      - keys.delete
      - sentries.sync
      - keytypes.view
      - keytypes.activate
      - keytypes.deactivate
      - templates.view
      - templates.install
      - templates.remove
      - policy.view
      - policy.update
      - settings.view
      - settings.update
      - token.provision
      - token.revoke
```

The `identity_id: "*"` bootstrap grant exists to preserve compatibility
while the backend is identity-scoped. It is not a general MT grant-management
policy.

## Principal Resolution

Principal resolution maps authenticated credentials to authorization principals:

```text
admin passphrase / SSH admin auth / compatibility identity token
  -> system:product-admin
```

## Enforcement Points

Authorization checks must run before private-key access, mutation, approval
response handling, token rotation, or policy/settings changes.

Enforced callsites:

- `internal/signerapp/daemon/http_runtime.go` wraps HTTP `/sign`,
  `/sign/component`, `/sign/assemble`, `/sign/bounded-component`,
  `/sign/bounded-assemble`, `/sign/bounded-admin`, `/plan`, `/status`,
  `/keys`, `/keytypes`, `/admin/generate`, `/admin/sentries/sync`, and
  `/admin/keys` with
  `requireAuth`. `/admin/sentries/sync` uses `sentries.sync` because it
  mutates public sentry reference metadata, not private key material.
- `internal/signerapp/daemon/http_auth.go` calls `Authorizer.Authorize` after
  authentication and before the handler executes.
- `internal/signerapp/adminserver/session.go` gates auth-time unlock through
  `authorizeIdentity`.
- `internal/signerapp/adminserver/handlers.go` gates admin `unlock`, key
  list/details/generate/import/export/delete, key type list/activate/deactivate,
  template list/install/remove, policy view/update, settings view/update,
  signer-managed backup creation/list, credential restore preview/apply,
  restore rollback/reconciliation,
  passphrase rotation, signing approval response, token provisioning response,
  and token revoke through `s.authorize`.

`/health` is intentionally absent from the enforcement list. It is an
unauthenticated health endpoint in [ARCH_HTTP_API.md](ARCH_HTTP_API.md);
`health.get` is reserved.

## Denial Semantics

Authorization is fail-closed:

- nil or missing identity is unauthorized
- unknown principal is forbidden
- disabled principal is forbidden
- disabled group is ignored
- disabled grant is ignored
- missing grant is forbidden
- unknown action is forbidden before grant matching
- mismatched target identity is forbidden unless the boundary explicitly supports
  cross-identity authorization

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

Audit records distinguish the actor from the signing identity being acted on.

Relevant audit fields:

- `identity_id`: owning or target identity
- `target_identity_id`: signing identity targeted by the operation
- `principal`: principal field
- `requester_principal`: principal requesting the operation
- `approver_principal`: principal approving or rejecting the operation
- `admin_session_id`: admin protocol session ID
- `transport`: `ipc`, `ssh`, `http`, or empty for process events
- `policy_rule_id`: policy rule that forced manual signing review, when present

Target invariant:

```text
Every sensitive operation should be attributable to both a target identity and a
principal.
```

Authorization denials must also be attributable. Admin denials record the
session, principal, target identity, action, resource, and denial reason. HTTP
denials record the authenticated identity and remote address at the HTTP auth
boundary.

## Security Invariants

- Runtime code must not use an allow-all authorizer.
- Product compatibility must be represented by bootstrap grants.
- Every private-key operation must have an authorization check.
- Every key, policy, settings, template, token, identity, or lifecycle mutation
  must have an authorization check.
- Auth-time unlock must be authorization-gated.
- Approval responses must be authorization-gated.
- Cross-identity access must be explicit.
- Unknown actions must fail closed.
- Unknown actions must fail before grant matching so callsite or grant typos do
  not create ad hoc permissions.
- Unknown or disabled principals must fail closed.
- Disabled groups and grants must not authorize.
- Group membership alone must not authorize.
- `system:product-admin` and `system:product-admins` are reserved names.

## Implementation

- stable action vocabulary
- in-memory grant-backed authorizer
- bootstrap product principal/group/grant
- admin session principal separation from target signing identity
- HTTP and admin operation gates

## Source Of Truth

Primary implementation files:

- `internal/auth/authorizer.go`
- `internal/authz/authorizer.go`
- `internal/signerapp/adminserver/session.go`
- `internal/signerapp/adminserver/handlers.go`
- `internal/signerapp/daemon/http_auth.go`
- `internal/signerapp/daemon/http_runtime.go`
- `internal/signerapp/daemon/admin_services.go`
- `internal/signerapp/daemon/audit_attribution.go`
- `internal/signerapp/audit/audit.go`

Compatibility-bearing references:

- `internal/protocol/error_codes.go`
- `internal/protocol/messages.go`
- `docs/ARCH_CONTRACTS.md`
