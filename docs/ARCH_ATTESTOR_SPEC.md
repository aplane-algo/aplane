# Attestor Signing Engineering Specification

Status: draft implementation planning spec.

Source design note: `temp/DESIGN_ATTESTOR_SIGNING.md`.

This file converts the design note into an engineering specification for an
MVP implementation. The design note remains useful rationale, but this file is
the implementable contract: endpoint shapes, storage ownership, security
requirements, module boundaries, and acceptance tests.

This document is not yet the canonical compatibility contract for released
attestor behavior. Until implementation lands, the existing canonical docs keep
their current contracts. Before shipping this feature, the compatibility-bearing
sections below must be copied or promoted into the canonical HTTP, contracts,
authorization, policy, and network docs named in Section 3.

## 1. Assessment Of The Design Note

`temp/DESIGN_ATTESTOR_SIGNING.md` is not yet an engineering specification. It
is a strong protocol and product design note, but an implementation team would
still need to resolve:

- exact HTTP status and error-envelope behavior,
- exact persistent store ownership and integrity protection,
- exact signing-provider registry changes needed to make "not signable by
  `/sign`" structural,
- concrete source files and package boundaries,
- authorization action additions,
- canonicalization fixture ownership,
- rollout and acceptance criteria.

This specification supplies those missing pieces for the MVP.

## 2. Scope

The MVP adds two-party LogicSig signing for accounts whose authorization
predicate requires:

- a user component signature produced by the user signer, and
- an attestor component signature produced by a separate attestor signer.

The MVP supports only transactions where:

```text
txn.Sender == attested_account
```

An attested LogicSig used as `AuthAddr` for another sender is out of scope and
must be rejected by component signing and assembly.

## 3. Normative References

Implementation work must preserve the current contracts in:

- `docs/ARCH_SPEC.md`
- `docs/ARCH_CONTRACTS.md`
- `docs/ARCH_AUTHORIZATION.md`
- `docs/ARCH_POLICY.md`
- `docs/ARCH_NETWORKS.md`
- `docs/ARCH_HTTP_API.md`
- `docs/ARCH_COOPERATIVE_SIGNING.md`

This file already lives under `docs/`, but it remains a planning spec until the
MVP is implemented. Promotion means updating `docs/ARCH_HTTP_API.md`,
`docs/ARCH_CONTRACTS.md`, `docs/ARCH_AUTHORIZATION.md`,
`docs/ARCH_POLICY.md`, and `docs/ARCH_NETWORKS.md` so shipped behavior and
SDK fixtures have one canonical source.

## 4. MVP Decisions

The MVP endpoint names are:

```text
POST /attestor/register-account
POST /sign/component
POST /sign/assemble
```

Existing and related endpoint decisions:

- `/plan` remains the canonical group planning endpoint.
- `/sign` never signs attested-account key types or attestor component key
  types.
- `/simulate` rejects attested-account senders in MVP.
- `/sign/cancel` is extended by the MVP to cancel live `/sign`,
  `/sign/component`, and `/attestor/register-account` approval waits by
  `request_id`. This is a proposed compatibility change and must be promoted
  into the canonical HTTP contract before release.

The MVP is synchronous. There is no polling API and no durable request table.

Final assembly is implemented server-side on the user signer through
`/sign/assemble`. Client-side assembly is deferred until a concrete consumer
needs `/keys` to expose the non-secret metadata required for assembly.

## 5. Actors And Trust Boundaries

Actors:

- `orchestrator`: the client flow, normally `apshell` or an SDK.
- `user signer`: the apsigner deployment and authenticated identity holding the
  attested account key file and the user's component private key.
- `attestor signer`: the apsigner deployment and authenticated identity holding
  the attestor component key and account-binding registry.

The current product deployment model is one `apsigner` on the signer host, with
one signer data directory resolved by `-d` or `APSIGNER_DATA`. Product UI/docs
are single-operator and expose the product identity, normally `default`.
Although the runtime has identity scoping, the system does not claim strong
tenant isolation or product support for unrelated operators sharing one node.

MVP supports these role-placement modes:

1. **Independent attestor deployment.** The attestor role runs in a separate
   attestor `apsigner` deployment/node. This is the mode for independent
   third-party attestation.
2. **Co-located attestor identity.** One `apsigner` process has separate
   identities, for example `identities/default` for user signing and
   `identities/attestor` for attestor component keys and account bindings. This
   separates identity-scoped keys, policy, unlock state, token, and binding
   storage, but it shares the process, host, process-global config, daemon
   lifecycle, and operator control plane. This can be production-acceptable
   when the co-located attestor identity attests accounts whose user component
   keys live on a different apsigner deployment/operator domain.
3. **Same identity self-attestation.** The product identity holds both ordinary
   signing keys and attestor component keys. This is the weakest separation and
   is for local development only. Production UX and docs must not recommend or
   present self-attestation as a security control.

Independence is evaluated per attested account. For a given account, the user
component private key and the attestor component private key must be held by
different apsigner deployments/operator domains to claim independent
attestation.

A two-party reciprocal deployment needs only two apsigner processes on two
machines. For example:

```text
Machine A apsigner
  identities/default   # A user keys
  identities/attestor  # attestor keys for B accounts

Machine B apsigner
  identities/default   # B user keys
  identities/attestor  # attestor keys for A accounts
```

Accounts owned by A use A's user component key and B's attestor component key.
Accounts owned by B use B's user component key and A's attestor component key.
Neither process attests its own local user accounts in production.

Multi-attestor-operator co-hosting on one node remains out of scope until the
broader multi-tenant signer model is hardened and productized.

This does not make `attestor` a product user or tenant. It is an
operator-controlled service role scoped to an apsigner identity. Product UX and
docs remain single-operator; the attestor identity is not a customer-management
surface, and unrelated operators must not be co-hosted under this MVP model.

### 5.1 APlane Invariant Compatibility

The attestor role placement above is compatible with current APlane invariants
when implemented with these constraints:

- HTTP token authentication selects exactly one identity runtime; requests do
  not carry a free-form target identity override.
- Attestor private keys stay under `identities/<identity>/keys/` and never
  leave `apsigner`.
- Attestor account bindings, profile trust roots, policy, unlock state, token,
  and audit records are identity-scoped.
- `/sign` never reaches attestor component keys or attested-account key types;
  component signing uses `/sign/component`.
- `/plan` continues to own canonical group shaping and uses attested-account
  metadata only for planning and size/fee budgeting.
- Product UI/docs do not claim tenant isolation or recommend self-attestation
  as a production control.

Violations would be: treating the attestor identity as an unrelated hosted
tenant, allowing callers to select arbitrary identities in request bodies,
sharing one account's user and attestor private keys in the same deployment
while claiming independent attestation, or letting the normal `/sign` provider
path sign attestor/attested key types.

The attestor profile is public routing and key metadata. It must never contain
bearer tokens or other credentials.

## 6. Key Types And Registries

### 6.1 Key Types

MVP key types:

```text
aplane.attestor-ed25519.v1
aplane.attestor-falcon1024-ed25519.v1
```

Optional MVP key type if implementation cost is low:

```text
aplane.attestor-ed25519-ed25519.v1
```

`aplane.attestor-ed25519.v1` is an attestor component key. It can produce raw
component signatures only. It is not an Algorand spending account and must not
be accepted by `/sign`.

Generated attestor component keys have a stable component key handle:

```text
component_key_id = "attkey_" || lower_hex(SHA-256(
  "APLANE_COMPONENT_KEY_V1" ||
  uint16_be(len(key_type)) ||
  key_type ||
  public_key_bytes
))
```

`component_key_id` is public, deterministic, and not an Algorand address. The
`attkey_` prefix is intentionally outside Algorand address syntax. Component
signing requests use this handle in the `component_key` field. Attestor
profiles may also carry an operator-assigned `attestor_key_id`, but that value
is profile metadata and must not be treated as a universal local key lookup
unless it resolves unambiguously to a local `component_key_id`.

If existing key inventory or generation DTOs require an `address` field for
every key row, a component-key row may carry a storage locator in that field
for compatibility. That locator is not a spendable account address, must be
marked as non-spending in UI, and must not be accepted as `auth_address`,
transaction sender, or rekey target. `/keys` and generation responses for
component keys must expose `component_key_id` so clients do not depend on the
compatibility locator.

`aplane.attestor-falcon1024-ed25519.v1` is an attested account key. It is a
DSA-backed LogicSig key on disk with:

- `category: dsa_lsig`
- user private key hex in the existing `private_key` JSON field
- user public key hex in the existing `public_key` JSON field
- `base_key_type: aplane.falcon1024.v1`
- compiled LogicSig bytecode hex in the existing `lsig_bytecode` JSON field
- off-curve `salt_counter`
- `signing_args` containing durable argument order
- attestor metadata under `parameters` / `params`

### 6.2 Registry And Keygen Requirements

The implementation must have separate exact-key-type registries or exact
allow/deny gates for:

- transaction signing,
- component signing,
- attested-account metadata and assembly,
- non-secret key-type metadata used by planning and inventory,
- key generation.

The current `internal/signing` provider lookup is family-oriented and can fall
back from a composed key type to its `base_key_type`. That behavior is correct
for ordinary DSA-backed LogicSigs, but it is not sufficient for attested
accounts. The `/sign` path must reject attested-account key types before
loading private key material or calling `internal/signing.GetProvider`.

Required `/sign` block:

```text
if key_type is an attestor component key:
    reject 400 with "attestor component keys require /sign/component"

if key_type is an attested account key:
    reject 400 with "this key type requires the attestor signing flow: use POST /sign/component then POST /sign/assemble"
```

This is an unsupported request shape, not a policy refusal, so it is `400`.
Policy, authorization, or operator refusal remains `403`.

Unit tests must prove that every attestor component key type and every
attested-account key type is absent from transaction signing execution, even
when `base_key_type` names a registered signing provider.

`internal/keygen` must not use family fallback to generate attestor key types.
Component-key generation and attested-account generation require exact
key-type matches. If implementation keeps a family-oriented generator registry,
the generation entrypoint must reject attestor component key types and
attested-account key types unless the exact requested key type is explicitly
registered and enabled for the authenticated identity.

Generation tests must prove:

- `aplane.attestor-ed25519.v1` generation returns `component_key_id`,
- `aplane.attestor-falcon1024-ed25519.v1` generation uses the attested-account
  generator, not the Falcon base generator through fallback,
- optional `aplane.attestor-ed25519-ed25519.v1` generation, if implemented,
  also uses exact-key-type generation.

### 6.3 `/plan` Metadata

`/plan` must recognize attested-account key types for metadata only:

- LogicSig bytecode size,
- signature argument sizes,
- dummy-count and fee budgeting,
- key inventory display,
- provenance display.

`/plan` must not load component private key bytes and must not use the
transaction-signing registry.

## 7. Signature Message Contract

Every component signs:

```text
m = SHA512_256("APLANE_ATTESTOR_V1" || role_byte || txid)
```

Where:

- `"APLANE_ATTESTOR_V1"` is the 18-byte ASCII tag.
- `role_byte == 0x01` for user signatures.
- `role_byte == 0x02` for attestor signatures.
- `txid` is the canonical 32-byte Algorand transaction ID for the finalized
  transaction.

For every `group_bytes_hex[i]`, the implementation must:

1. Hex-decode the value.
2. Require the bytes to start with the Algorand `"TX"` prefix used by
   `internal/txnutil.EncodeWithPrefix`.
3. Decode the transaction from the bytes after the prefix.
4. Re-encode it with `internal/txnutil.EncodeWithPrefix`.
5. Reject if re-encoded bytes differ from the request bytes.
6. Compute the transaction ID with the same algorithm as Algorand consensus and
   TEAL `txn TxID`.

This prevents non-canonical msgpack encodings from producing ambiguous audit or
signature inputs.

The TEAL template must build the same `m` on-chain from `txn TxID`, the domain
tag, and the role byte. Exact TEAL stack order is implementation-owned and must
be pinned by known-answer tests.

Hash choices are intentional and must not be collapsed into one algorithm
during implementation:

- component-signing messages use SHA512/256 because they are tied to Algorand
  transaction ID semantics and TEAL verification,
- attestor profile fingerprints, binding fingerprints, and group audit hashes
  use SHA-256 because they are off-chain canonical-data fingerprints.

## 8. Attested LogicSig Template

The MVP template verifies:

```text
verify_user(user_public_key, m_user, arg user_signature)
AND
verify_attestor(attestor_public_key, m_attestor, arg attestor_signature)
```

Template requirements:

- public keys are embedded in bytecode using constant bytes,
- `arg 0` is the user component signature,
- `arg 1` is the attestor component signature,
- additional runtime args, if any, appear after those two slots in stored
  `signing_args` order,
- the LogicSig address must be off-curve through the existing salt-counter
  mechanism,
- the stored bytecode, not a live template, is the signing authority for an
  existing key file.

The Falcon/Ed25519 hybrid in `lsig/falcon1024_ed25519` is a TEAL shape
reference only. It signs `txn TxID` directly and derives both keys from one
mnemonic. Attestor signing must use the role-separated message contract above.

## 9. Profile Canonicalization

The profile canonicalization algorithm is APlane Profile Canonicalization
(`APC`):

```text
APC(json) =
  RFC_8785_JCS(
    apply_NFC_to_all_strings(
      reject_duplicate_keys(json)
    )
  )
```

Additional APC rules:

- duplicate raw object keys fail with `apc_duplicate_key`,
- two raw keys that collide after NFC normalization fail with
  `apc_key_collision`,
- NFC is applied to object keys and string values,
- the profile signature input is `APC(profile without "signature")`,
- the profile fingerprint input is `APC(profile with "signature")`.

`profile_fingerprint` is:

```text
SHA-256(APC(full_profile_including_signature))
```

The implementation must add test vectors under `test/contracts/signerapi/` for:

- baseline profile,
- reordered keys,
- extra whitespace,
- NFD string values that normalize to the baseline,
- duplicate raw keys,
- post-NFC key collision,
- same body signed by two org keys producing distinct fingerprints.

### 9.1 Signed Attestor Profile V1

An attestor profile is a public, signed routing and key metadata document. It
is not a credentials file and must never contain bearer tokens, endpoint
secrets, SSH keys, passphrases, or local credential references.

The MVP profile schema is:

```json
{
  "schema_version": 1,
  "profile_id": "example-attestor-mainnet-v1",
  "display_name": "Example Attestor",
  "issuer": {
    "org_id": "example-attestor",
    "org_name": "Example Attestor, Inc.",
    "org_key_id": "org_2026_main",
    "org_public_key_hex": "..."
  },
  "valid_from": "2026-05-20T00:00:00Z",
  "valid_until": "2027-05-20T00:00:00Z",
  "networks": [
    {
      "network_id": "mainnet",
      "genesis_hash": "..."
    }
  ],
  "attestor_keys": [
    {
      "attestor_key_id": "default-ed25519-2026",
      "component_key_type": "aplane.attestor-ed25519.v1",
      "public_key_hex": "...",
      "signature_scheme": "aplane.attestor-ed25519.v1",
      "status": "active"
    }
  ],
  "templates": [
    {
      "template_key_type": "aplane.attestor-falcon1024-ed25519.v1",
      "template_fingerprint": "...",
      "user_key_type": "aplane.falcon1024.v1",
      "attestor_component_key_type": "aplane.attestor-ed25519.v1"
    }
  ],
  "signature": {
    "scheme": "aplane.profile-ed25519.v1",
    "org_key_id": "org_2026_main",
    "signature_hex": "..."
  }
}
```

Profile IDs, org IDs, org key IDs, and attestor key IDs are compatibility
identifiers. They must be 1 through 128 ASCII characters, start with a
lowercase letter or digit, and contain only lowercase letters, digits, `_`,
`-`, or `.`. Public keys are hex-encoded raw public keys for their declared
scheme. Timestamps are RFC3339 UTC.

The only MVP profile signature scheme is `aplane.profile-ed25519.v1`.
`signature_hex` is an Ed25519 signature over
`APC(attestor_profile without "signature")`. `signature.org_key_id` must equal
`issuer.org_key_id`, and the trusted organization key with that ID must have
the same public key as `issuer.org_public_key_hex`.

Profile import must fail closed for:

- malformed JSON,
- unsupported `schema_version`,
- unsupported signature scheme,
- duplicate raw keys or post-NFC key collisions,
- invalid identifier syntax,
- invalid key encoding or signature length,
- invalid timestamp format or `valid_until <= valid_from`,
- signature verification failure,
- unknown, revoked, or mismatched trusted org key,
- expired profile,
- empty `networks`, `attestor_keys`, or `templates`,
- unsupported network token syntax,
- duplicate `attestor_key_id` entries,
- duplicate `network_id` entries with different genesis hashes,
- duplicate genesis hashes mapped to different `network_id` values.

Importing a profile with an existing `profile_id` is an update, not a blind
overwrite. The new profile must verify against a currently trusted org key. If
its fingerprint differs from the stored profile, it must have a strictly newer
`valid_from` timestamp unless the operator uses an explicit force/update flow
that is audited. This prevents accidental rollback to an older signed profile.

### 9.2 Trusted Organization Keys

Trusted organization keys are local trust roots. They are identity-scoped and
behavior-bearing. The MVP trust-root payload is:

```json
{
  "schema_version": 1,
  "org_keys": [
    {
      "org_key_id": "org_2026_main",
      "scheme": "ed25519",
      "public_key_hex": "...",
      "status": "active",
      "trusted_at": "2026-05-20T12:34:56Z",
      "trusted_by_principal": "system:product-admin",
      "label": "Example Attestor production root"
    }
  ]
}
```

`status` values are:

```text
active
revoked
```

Only active trusted org keys can verify new attestor profile imports or current
profile drift checks. Revoking an org key does not delete stored attestor
profiles or account bindings, but any later operation that must re-verify a
profile signed by that org key fails closed unless a newer trusted root and
profile are imported.

## 10. Persistent Storage

All signer-side attestor state is identity-scoped and lives under:

```text
identities/<identity>/attestor/
```

Required files:

```text
identities/<identity>/attestor/profiles/<profile_id>.json
identities/<identity>/attestor/trusted_org_keys.json
identities/<identity>/attestor/trusted_org_keys.json.hmac
identities/<identity>/attestor/account_bindings.json
identities/<identity>/attestor/account_bindings.json.hmac
```

The exact file names may be refined during implementation, but the following
storage invariants are mandatory:

- attestor profile files are public but behavior-bearing; their signatures are
  verified on import and again before use,
- trusted organization keys are behavior-bearing trust roots and must be
  integrity-protected by the identity master key,
- account bindings are behavior-bearing authorization state and must be
  integrity-protected by the identity master key,
- mutation paths hold the identity store mutation lock,
- backups include attestor profiles, trusted org keys, and account bindings,
- restore validates integrity before making restored attestor state active,
- account-binding writes are atomic with respect to signer reload.

The MVP integrity sidecars for `trusted_org_keys.json` and
`account_bindings.json` use the same shape as `policy.yaml.hmac` unless the
implementation introduces a shared signed-file helper first. The HMAC key is
derived from the identity master key with distinct HKDF info strings:

```text
aplane attestor trusted org keys integrity v1
aplane attestor account bindings integrity v1
```

Profile JSON files do not need a local HMAC sidecar because the attestor
profile signature is the behavior-bearing integrity check. Restore must verify
both local HMAC sidecars and all attestor profile signatures before restored
attestor state becomes active.

An account binding record stores:

```json
{
  "attested_account": "...",
  "user_public_key": "...",
  "attestor_public_key": "...",
  "attestor_key_id": "...",
  "template_key_type": "aplane.attestor-falcon1024-ed25519.v1",
  "template_fingerprint": "...",
  "salt_counter": 42,
  "profile_id": "...",
  "profile_fingerprint": "...",
  "org_key_id": "...",
  "network_id": "mainnet",
  "genesis_hash": "...",
  "status": "active",
  "registration_timestamp": "RFC3339 UTC",
  "registered_by_principal": "...",
  "approved_by_principal": "..."
}
```

`status` values:

```text
active
suspended
revoked
```

Only `active` bindings are signable.

## 11. HTTP Contract

All new HTTP endpoints:

- accept JSON request bodies and return `Content-Type: application/json`,
- enforce `POST`,
- enforce the existing request body limit,
- use token auth with `Authorization: aplane <token>`,
- route to exactly one authenticated signer identity,
- require the signer identity to be unlocked unless noted otherwise,
- use `signerapi.ErrorResponse` with top-level `error` for non-2xx responses,
- use existing `ServiceError` HTTP mapping where possible.

Request `Content-Type` is not enforced in the MVP unless the broader HTTP
contract changes. Malformed JSON still returns `400`, and oversized bodies
still return `413`.

New DTOs live in:

```text
pkg/signerapi/attestor.go
internal/signerapi/attestor.go
```

Committed fixture JSON lives under:

```text
test/contracts/signerapi/
```

### 11.1 Authorization Actions

Add stable authorization actions in `internal/auth/authorizer.go`:

```text
attestor.profile.import
attestor.profile.view
attestor.account.register
attestor.account.view
attestor.account.update
sign.component
sign.assemble
```

Product-mode bootstrap grants must include these actions for
`system:product-admins`.

HTTP endpoint mapping:

```text
POST /attestor/register-account -> attestor.account.register, resource account_binding
POST /sign/component            -> sign.component, resource transaction
POST /sign/assemble             -> sign.assemble, resource transaction
```

If implementation chooses to reuse `sign.request` for a first internal patch,
that is acceptable only as a temporary development step. The shipped contract
must use stable, specific actions.

### 11.2 Request IDs And Cancellation

New endpoint request IDs use the same syntax as `/sign`:

```text
letters, digits, "-", "_", ".", ":"
max length 128
```

For new endpoints only, `request_id` is optional and the response always
returns a non-empty canonical request ID:

- caller-supplied IDs are echoed,
- omitted IDs are generated by the server,
- audit uses the returned ID,
- cancellation uses the returned ID only for live cancelable endpoint kinds.

Live `/sign/component` and `/attestor/register-account` requests register with
the existing live request registry using a request kind:

```text
sign
component
attestor_register
```

The live request namespace is one namespace per authenticated identity, not one
namespace per kind. A caller-supplied `request_id` that is already live for any
cancelable kind under the same identity must be rejected with `400` before a
new approval prompt is queued. This keeps `/sign/cancel` unambiguous because
its DTO carries only `request_id`.

Server-generated IDs should include an internal kind prefix or equivalent
entropy to avoid accidental collisions, but clients must treat returned IDs as
opaque strings.

`POST /sign/cancel` keeps its current DTO and response shape. It can cancel any
live request kind for the authenticated identity. This expansion is part of
the attestor MVP and must be promoted into `docs/ARCH_HTTP_API.md` and
`docs/ARCH_CONTRACTS.md` before release.

`/sign/assemble` does not wait for operator approval and is not cancelable
beyond normal HTTP context cancellation. Its `request_id` is for response and
audit correlation only; it is not registered as live request state and
`/sign/cancel` must return `not_found` for it.

## 12. `/attestor/register-account`

Request:

```json
{
  "request_id": "reg-001",
  "attested_account": "LOGICSIG_ACCOUNT_ADDRESS",
  "template_key_type": "aplane.attestor-falcon1024-ed25519.v1",
  "template_fingerprint": "...",
  "salt_counter": 42,
  "lsig_bytecode_hex": "...",
  "user_public_key": "...",
  "attestor_public_key": "...",
  "attestor_key_id": "default-ed25519-2026",
  "attestor_profile_id": "example-attestor-mainnet-v1",
  "network_id": "mainnet",
  "genesis_hash": "..."
}
```

Success response:

```json
{
  "request_id": "reg-001",
  "status": "registered",
  "attested_account": "LOGICSIG_ACCOUNT_ADDRESS",
  "binding_fingerprint": "...",
  "profile_fingerprint": "...",
  "org_key_id": "example-attestor-org-2026",
  "registration_timestamp": "2026-05-20T12:34:56Z"
}
```

Policy/operator rejection response:

```json
{
  "request_id": "reg-001",
  "status": "rejected",
  "reason": "policy_refused",
  "reason_detail": "profile_id not in operator allow-list"
}
```

Semantic registration refusals return HTTP `200` with `status:"rejected"`
because the endpoint completed its decision. This includes policy refusal,
operator rejection, profile/request mismatch, bytecode/address mismatch,
network mismatch against the profile, missing held attestor key, unsupported
template, approval timeout, and cancellation. Malformed JSON, invalid request
syntax, auth failures, unknown local profile ID, corrupted local profile state,
and internal errors use non-2xx `ErrorResponse`.

The `200` rejection response is an endpoint-specific exception to the current
generic HTTP status mapping, where policy/operator rejection and approval
timeout normally map to non-2xx statuses. Implementers must not reuse the
generic `/sign` `ServiceError` mapping for these registration decision
outcomes.

`reason` enum:

```text
policy_refused
profile_mismatch
bytecode_address_mismatch
network_not_in_profile
key_id_not_held
template_not_registered
approval_timeout
cancelled
unknown
```

Validation:

1. Resolve `attestor_profile_id` to the currently stored local profile.
2. Re-verify the profile signature against the locally trusted org key.
3. Verify `attestor_key_id`, `attestor_public_key`, `template_key_type`,
   `network_id`, and `genesis_hash` all belong to that profile.
4. Verify the signer holds an active component key whose public key matches
   the profile entry for `attestor_key_id`, and record its local
   `component_key_id`.
5. Verify `template_key_type` is registered as an attested-account template.
6. Rebuild LogicSig bytecode from template, user public key, attestor public
   key, and salt counter.
7. Require rebuilt bytecode to equal `lsig_bytecode_hex`.
8. Require bytecode-derived address to equal `attested_account`.
9. Run account-registration policy and approval.
10. Persist an active binding atomically if approved.
11. Return `registered`; otherwise return `rejected`.

`binding_fingerprint` is:

```text
SHA-256(APC(binding_record_without_mutable_status_fields))
```

The exact binding-fingerprint input must be pinned by Phase 0 fixtures.

## 13. `/sign/component`

Request:

```json
{
  "request_id": "cli-123",
  "role": "attestor",
  "component_key": "attkey_...",
  "attested_account": "LOGICSIG_ACCOUNT_ADDRESS",
  "group_bytes_hex": ["5458..."],
  "target_indices": [0],
  "counterparty_signatures": [
    {
      "target_index": 0,
      "role": "user",
      "signature": "..."
    }
  ]
}
```

Response:

```json
{
  "request_id": "cli-123",
  "component_key": "attkey_...",
  "signatures": [
    {
      "target_index": 0,
      "signature": "...",
      "signature_scheme": "aplane.attestor-ed25519.v1"
    }
  ]
}
```

Validation:

- `role` is exactly `user` or `attestor`.
- `group_bytes_hex` has length 1 through 16.
- `target_indices` is non-empty, unique, sorted or canonicalized for internal
  processing, and every value is in range.
- `component_key` resolves to a key that supports component signing for the
  declared role. For attestor component keys this is the local
  `component_key_id` defined in Section 6.1.
- `attested_account` resolves against the receiving signer:
  - role `user`: local `dsa_lsig` attested-account key file,
  - role `attestor`: local active account-binding registry entry.
- user/attestor public keys come from the local binding source, never from the
  request.
- every target transaction has `txn.Sender == attested_account`.
- every target transaction has `GenesisHash == binding.genesis_hash`.
- every transaction byte string is canonical per Section 7.
- group consistency is valid per Section 15.
- `component_key` public key equals the role public key in the binding.
- profile drift is checked before policy:
  - attestor role: drift fails closed with `binding_stale`,
  - user role: drift emits warning and continues.
- counterparty signatures, when present, are unique by `target_index`, cover
  only requested targets, have the opposite role, and verify against the
  binding public key for the counterparty role.

Policy:

- component signing uses the current policy phase order:
  `Always Deny > Always Review > Always Approve > Operator Default`.
- policy sees the full decoded group, not just target transactions.
- attestor-role transfer routing evaluates target movements as movements by
  the attested account.
- the default attestor policy requires verified user counterparty signatures
  before approval. Operators may relax this only through explicit policy.

Non-2xx failures use `ErrorResponse`. Policy/operator rejection is `403`.
Malformed shape and validation failures are `400` unless the existing error
model classifies them otherwise.

## 14. `/sign/assemble`

Request:

```json
{
  "request_id": "asm-001",
  "group_bytes_hex": ["5458..."],
  "targets": [
    {
      "target_index": 0,
      "attested_account": "LOGICSIG_ACCOUNT_ADDRESS",
      "user_signature": "...",
      "user_source_request_id": "cli-122",
      "attestor_signature": "...",
      "attestor_source_request_id": "cli-123",
      "runtime_args": []
    }
  ],
  "passthrough": [
    {
      "target_index": 1,
      "signed_txn_hex": "..."
    }
  ]
}
```

Response:

```json
{
  "request_id": "asm-001",
  "signed_group": ["..."]
}
```

Validation:

- `group_bytes_hex` has length 1 through 16.
- every group position appears exactly once in `targets` or `passthrough`.
- no duplicate `target_index` appears.
- every transaction byte string is canonical per Section 7.
- group consistency is valid per Section 15.
- each target resolves to a local attested-account key file on the user signer.
- target sender equals `attested_account`.
- target `GenesisHash` matches the stored key metadata.
- `user_signature` verifies over role `user` message.
- `attestor_signature` verifies over role `attestor` message.
- runtime args exactly fill stored `signing_args` slots beyond
  `user_signature` and `attestor_signature`.
- each passthrough signed transaction decodes and has a TxID equal to the
  unsigned transaction at the same group index.

Passthrough items use:

- `target_index`: the group position covered by the signed transaction,
- `signed_txn_hex`: hex-encoded Algorand signed transaction msgpack bytes.

`signed_txn_hex` is not TX-prefixed unsigned transaction bytes. It follows the
existing `/sign` passthrough meaning: the caller supplies already-signed
transaction bytes, and assembly returns them unchanged at that group position
after verifying that their decoded TxID matches `group_bytes_hex[target_index]`.

`/sign/assemble` does not perform private signing and does not run policy.

`user_source_request_id` and `attestor_source_request_id` are caller-asserted
forensic fields. The handler records them as claims only. They are not
cryptographic provenance until a future signed component-receipt mechanism is
added.

Schema-valid requests emit `ATTESTED_ASSEMBLY` audit events whether assembly
succeeds or fails.

## 15. Group Consistency

For `len(group_bytes_hex) == 1`:

- the decoded transaction's `Group` field must be zero.

For `len(group_bytes_hex) > 1`:

- every decoded transaction must have a non-zero `Group`,
- all `Group` values must be equal,
- recomputing the group ID from the decoded transactions with `Group` cleared
  must produce the same digest.

The `group_hash` audit field is:

```text
SHA-256(
  "APLANE_GROUP_V1" ||
  uint16_be(count) ||
  uint32_be(len(tx[0])) || tx[0] ||
  ...
)
```

`tx[i]` is exactly the TX-prefixed transport bytes from `group_bytes_hex[i]`
after hex decode. Do not strip the TX prefix for `group_hash`.

## 16. Network Scoping

Network identity is derived from transaction `GenesisHash`, not `GenesisID`.

Attestor profiles declare allowed networks as `(network_id, genesis_hash)`
pairs. `network_id` follows `docs/ARCH_NETWORKS.md` token syntax.

Account generation pins exactly one `genesis_hash` into:

- the user key file params,
- the attestor binding registry.

At component signing and assembly:

- target transaction `GenesisHash` must match the bound `genesis_hash`,
- signer config must be able to resolve the hash to a network context token,
- if `network_id` is present in stored metadata, it must match the resolver
  token or fail closed.

## 17. Profile Drift

Bindings store:

```text
profile_id
profile_fingerprint
org_key_id
```

Before attestor-role component signing, the attestor signer loads the current
local profile for `profile_id`, verifies its signature, computes its
fingerprint, and compares both `profile_fingerprint` and `org_key_id` with the
binding. Mismatch fails closed with `binding_stale`.

Before user-role component signing and `/sign/assemble`, the user signer
performs the same comparison when a current local profile exists. Mismatch
emits a warning into approval and audit but does not fail closed.

## 18. Policy

Add an account-registration policy phase for `/attestor/register-account`.
It uses the existing policy phase ordering, but evaluates account-binding
facts rather than transaction movements.

Registration selectors:

```text
profile_id
profile_fingerprint
org_key_id
network_id
genesis_hash
template_key_type
attestor_key_id
requester_principal
```

MVP policy extends `policy.yaml` with an optional top-level `attestor` block:

```yaml
attestor:
  schema_version: 1
  registration:
    rules:
      - id: allow_example_mainnet
        verdict: always_approve
        profile_ids: ["example-attestor-mainnet-v1"]
        profile_fingerprints: ["..."]
        org_key_ids: ["org_2026_main"]
        network_ids: ["mainnet"]
        genesis_hashes: ["..."]
        template_key_types: ["aplane.attestor-falcon1024-ed25519.v1"]
        attestor_key_ids: ["default-ed25519-2026"]
        requester_principals: ["system:product-admin"]
  component_signing:
    require_verified_user_signature_for_attestor: true
```

Validation rules:

- `attestor.schema_version` is required when the block is present and must be
  `1`.
- Unknown fields under `attestor`, `registration`, `component_signing`, or a
  registration rule fail policy validation.
- Registration rule IDs use the same grammar as transfer route IDs:
  `^[a-z0-9][a-z0-9_-]*$`.
- `verdict` is one of `always_deny`, `always_review`, or `always_approve`.
- Selector lists are optional, but a rule with no selectors is rejected unless
  it explicitly sets `match_all: true`.
- Empty selector lists are rejected.
- `network_ids` use network context token syntax.
- `genesis_hashes` are base64 or hex encoded 32-byte genesis hashes.

Registration policy uses the existing phase order:

```text
Always Deny > Always Review > Always Approve > Operator Default
```

If the `attestor.registration` block is absent or no rule matches, registration
falls through to the identity's Operator Default (`user_auto_approve`). A
matching `always_deny` rule produces `status:"rejected"` with
`reason:"policy_refused"` on `/attestor/register-account`.

Registration policy rule IDs in audit use:

```text
attestor_registration:<rule_id>
```

Component-signing policy reuses existing transaction policy and transfer
routing. The transfer-routing subject for attestor-role requests is the target
transaction sender, which must equal the attested account.

For attestor-role component signing, the default policy requires verified user
counterparty signatures for every requested target before approval can be
requested. This default applies when `attestor.component_signing` is absent.
Operators may relax it only by explicitly setting:

```yaml
attestor:
  schema_version: 1
  component_signing:
    require_verified_user_signature_for_attestor: false
```

When the requirement rejects a request, the policy rule ID is:

```text
attestor_component:missing_verified_user_signature
```

If the requirement is explicitly relaxed, audit records should include:

```text
attestor_component:user_signature_requirement_relaxed
```

Caller-specific transaction policy is deferred. Caller identity remains
available for authentication, revocation, audit, and rate limiting.

## 19. Audit

Add audit events:

```text
ATTESTOR_ACCOUNT_REGISTER_REQUEST
ATTESTOR_ACCOUNT_REGISTER_APPROVED
ATTESTOR_ACCOUNT_REGISTER_REJECTED
ATTESTOR_ACCOUNT_REGISTER_FAILED
ATTESTOR_COMPONENT_REQUEST
ATTESTOR_COMPONENT_APPROVED
ATTESTOR_COMPONENT_REJECTED
ATTESTOR_COMPONENT_FAILED
USER_COMPONENT_REQUEST
USER_COMPONENT_APPROVED
USER_COMPONENT_REJECTED
USER_COMPONENT_FAILED
ATTESTED_ASSEMBLY
```

Component audit records include:

- identity ID,
- request ID,
- component role,
- component key ID,
- attested account,
- target indices,
- target TxIDs,
- group hash,
- observed genesis hash,
- expected genesis hash,
- user public-key fingerprint,
- attestor public-key fingerprint,
- profile ID,
- profile fingerprint,
- org key ID,
- counterparty verification outcome,
- requester principal,
- approver principal when manually approved,
- policy rule ID when applicable.

`ATTESTED_ASSEMBLY` records:

- identity ID,
- request ID,
- group hash,
- target indices,
- attested accounts,
- claimed user and attestor source request IDs,
- outcome,
- structured failure reason.

Structured assembly failure reasons:

```text
signature_verification_failed
binding_stale
network_mismatch
group_inconsistent
coverage_violation
arg_count_mismatch
passthrough_txid_mismatch
key_missing
unknown
```

Audit values for claimed source request IDs must be documented as unauthenticated
claims.

## 20. UX And Tooling

Attestor signer:

```text
apshell generate aplane.attestor-ed25519.v1
apshell attestor profile export <component-key-id> --org-key <org-key-id> --out attestor-profile.json
```

The MVP does not add an `apstore generate` surface. Attestor component keys are
generated through the existing signer/admin key-generation path exposed by
`apshell generate` and `POST /admin/generate`, guarded by `keys.generate`.
If a later implementation adds offline `apstore` generation, it must define the
command ownership, authorization behavior, audit behavior, and tests in the
same change.

The attestor profile signature is produced by an organization profile-signing
key, not by the attestor component key itself. If profile export/signing is
implemented through a live signer endpoint, that endpoint must receive its own
stable authorization action and audit event before release. Offline profile
authoring is acceptable for MVP if it produces the signed attestor profile v1
schema defined in Section 9.1.

User signer/client:

```text
apshell attestor profile import attestor-profile.json --org-key <org-public-key>
apshell generate aplane.attestor-falcon1024-ed25519.v1 attestor_profile=<profile-id>
apshell attestor register <attested-account>
```

Shell command workflow logic belongs in `internal/apshellapp`, not
`cmd/apshell`. Reusable network/signing orchestration belongs in
`internal/engine` or a focused internal package.

Client-side credential routing must be separate from profiles. A suggested
client config file is:

```text
attestors.yaml
```

containing profile ID, endpoint URL override if needed, and local credential
reference. Tokens are never stored in profile JSON.

## 21. Implementation Ownership

Expected new or changed packages:

```text
pkg/signerapi/attestor.go
internal/attestor/profile/
internal/attestor/apc/
internal/attestor/binding/
internal/attestor/message/
internal/attestor/verify/
internal/signerapp/attestor/
internal/signerapp/signing/component.go
internal/signerapp/signing/assemble.go
cmd/apsigner/http_handlers_attestor.go
internal/signerclient/attestor.go
internal/apshellapp/attestor.go
internal/engine/attestor_signing.go
lsig/attestor_ed25519/
lsig/attestor_falcon1024_ed25519/
```

Existing package changes:

- `internal/auth`: add stable actions and bootstrap grants.
- `cmd/apsigner/http_runtime.go`: register new routes.
- `internal/signerapp/rest`: expose service methods for new endpoints.
- `internal/signerapp/audit`: add event types and fields.
- `internal/signing`: add exact key-type transaction-signing guard or split
  transaction/component registries.
- `internal/keygen`: add exact-key-type generators for component and
  attested-account key types, and block family fallback for those types.
- `internal/keys`: preserve attestor metadata in `KeyPair.Params`.
- `internal/signerapp/signing/planner_runtime.go`: allow attested-account
  metadata in `/plan` while blocking `/sign`.
- `internal/signerapp/signing/simulation.go` or REST simulate path: reject
  attested-account senders.
- `docs` and `test/contracts/signerapi`: add compatibility docs and fixtures.

Layering rules:

- `internal/attestor/*` owns APC canonicalization, attestor profile parsing and
  verification, binding fingerprints, component message construction, group
  hash helpers, and pure verifier primitives. It must not depend on HTTP,
  identity runtime, approval, keystore sessions, or shell packages.
- `internal/signerapp/attestor` owns signer-side attestor profile import/view,
  trust-root mutation, account-binding registration, binding storage, and
  policy facts.
- `internal/signerapp/signing` owns decoded transaction-group component
  signing and final assembly because those flows share planning, policy,
  approval, audit, and lifecycle behavior with existing signing.
- `internal/engine` owns reusable client/orchestrator attestor-signing
  mechanics.
- `internal/apshellapp` owns shell command workflows and typed request/result
  APIs.
- `cmd/apshell` and `cmd/apsigner` remain transport/composition adapters.

## 22. Acceptance Tests

Phase 0 contract tests:

- APC vectors pass in Go and are consumable by TypeScript/Python SDK tests.
- signed attestor profile v1 vectors cover valid import, unsupported schema,
  unsupported signature scheme, unknown org key, revoked org key, duplicate
  raw keys, post-NFC key collision, invalid signature, and rollback update.
- trusted org-key and account-binding integrity vectors reject tampering.
- group hash vectors pass.
- component message vectors pass.
- component key handle vectors produce stable `attkey_...` IDs and prove they
  are not Algorand addresses.
- registration success and rejection fixtures are committed.
- `/sign/component` and `/sign/assemble` fixtures, including passthrough
  assembly items, are committed.
- attestor policy YAML fixtures cover registration rules and
  `require_verified_user_signature_for_attestor`.

Unit tests:

- `/sign` rejects every attestor component key type.
- `/sign` rejects every attested-account key type before provider lookup.
- key generation uses exact-key-type gates for attestor component and
  attested-account key types.
- `/plan` accepts attested-account metadata and budgets LogicSig bytes.
- component message computation matches vectors.
- TEAL generated by attested template verifies known signatures in algod.
- live request registration rejects duplicate caller-supplied `request_id`
  values across `/sign`, `/sign/component`, and `/attestor/register-account`
  for the same identity.
- group consistency rejects singleton with group, multi-member missing group,
  divergent group, and wrong computed group.
- counterparty signature validation rejects wrong role, duplicate target,
  non-target target, invalid signature, and wrong public key.
- profile drift fails closed on attestor role.
- user role drift warns and continues.
- binding registry rejects tamper or failed integrity verification.
- `/simulate` rejects attested-account senders with a stable error message.
- `/sign/assemble` rejects malformed passthrough items and signed transaction
  TxID mismatches.

Integration tests:

- two isolated test `apsigner` deployments, user and attestor, each with its
  own temporary signer data root; this is test harness composition, not a
  product same-node multi-store deployment,
- signed profile import,
- account generation and registration,
- registration manual approval, auto approval, rejection, timeout, and cancel,
- `/sign/cancel` cancels live component-signing and registration approval waits
  and returns `not_found` for assembly request IDs,
- unregistered attestor component request rejected,
- missing local user key rejected,
- profile-label spoofing rejected,
- successful singleton attested payment,
- successful attested group with mixed senders and passthrough,
- successful multi-target group,
- cross-network attempt rejected,
- attestor policy rejection,
- stolen-user-key scenario where attestor refuses,
- rekey attempt cannot bypass attestor refusal,
- assembly emits audit on success and schema-valid failure,
- claimed source request IDs are recorded as claims.

SDK tests:

- Go, TypeScript, and Python DTO contract fixtures pass.
- SDK request deadlines for component signing and registration are approval-wait
  aware like `/sign`.
- SDK cancellation calls `/sign/cancel` with the returned request ID when the
  request ID was server-generated.

## 23. MVP Completion Criteria

The MVP is complete when:

- attestor component keys cannot sign through `/sign`,
- attested account keys cannot sign through `/sign`,
- attestor component key generation exposes stable non-address
  `component_key_id` handles,
- `/plan` handles attested account metadata,
- signed attestor profiles, trusted org keys, and account bindings use the
  schemas and integrity checks defined above,
- account registration stores integrity-protected bindings,
- `/sign/component` returns raw role-separated component signatures,
- `/sign/assemble` verifies and assembles final signed transaction bytes,
- `/sign/cancel` cancellation semantics for component signing and registration
  are promoted into the canonical HTTP contract,
- `/simulate` rejects attested accounts with a clear MVP limitation error,
- audit records registration, component signing, and assembly,
- backup and restore preserve attestor keys and account bindings,
- contract fixtures and integration tests pass,
- SDK DTOs and docs are updated in the same release window.

## 24. Deferred Work

Deferred from MVP:

- client-side assembly,
- plan receipts,
- signed component receipts,
- on-chain co-sign records,
- attestor-side assembly,
- M-of-N attestor templates,
- escape hatches and recovery keys,
- stateful recovery notices,
- attested-account simulation.
