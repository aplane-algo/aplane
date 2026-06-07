# Attestor Signing Engineering Specification

Status: draft implementation planning spec.

Source design note: `temp/DESIGN_ATTESTOR_SIGNING.md`.

This file converts the original design note into an engineering specification
for an MVP implementation. The model in this document intentionally differs
from the earlier registration-oriented design: initial attestation is stateless
and policy-driven.

This document is not yet the canonical compatibility contract for released
attestor behavior. Until implementation lands, the existing canonical docs keep
their current contracts. Before shipping this feature, the compatibility-bearing
sections below must be copied or promoted into the canonical HTTP, contracts,
authorization, policy, and network docs named in Section 3.
Promotion TODO: when the MVP ships, promote the compatibility-bearing sections
into the docs named below and remove or rewrite this planning-status language.

## 1. Assessment Of The Design Note

`temp/DESIGN_ATTESTOR_SIGNING.md` is useful rationale, but it is not the MVP
contract. The design note's registration/account-binding model is deliberately
out of scope for the first implementation.

The MVP attestor is a transaction-policy co-signer:

```text
Given canonical Algorand transaction/group bytes:
  decode the actual transaction facts
  evaluate the local identity policy over those facts
  if policy allows signing, produce attestor component signatures
```

The attestor does not register accounts, does not store account bindings, and
does not authorize based on labels, profiles, or caller-supplied descriptions.
The only authority for attestation is the authenticated signer's unlocked
attestor component key plus the identity's trusted `attestation.yaml` snapshot.

This specification supplies the remaining implementable pieces:

- endpoint shapes,
- exact signing-provider registry changes needed to make "not signable by
  `/sign`" structural,
- source files and package boundaries,
- authorization action additions,
- canonicalization fixture ownership,
- rollout and acceptance criteria.

## 2. Scope

The MVP adds two-party LogicSig signing for accounts whose authorization
predicate requires:

- a user component signature produced by the user signer, and
- an attestor component signature produced by a separate attestor signer.

The attestor's job is minimal:

```text
Attest that the selected transaction(s) match this identity's policy.
```

The MVP supports only transactions where:

```text
txn.Sender == attested_account
```

An attested LogicSig used as `AuthAddr` for another sender is out of scope and
must be rejected by component signing and assembly.

Attestor-role component signing is transfer-only in MVP. Target transactions
must produce direct transfer movements expressible by `transfer_policy`; the
supported attestation movement surface is defined in
[docs/ARCH_POLICY.md#transfer-routing](ARCH_POLICY.md#transfer-routing).
Target `appl`, `keyreg`, `acfg`, and other transactions that produce no
supported transfer movement are rejected because routing cannot cover them.

The attestor does not verify the account's LogicSig template as part of
authorization. The user/client key type owns LogicSig construction, hard-codes
the required attestor public key, defines the argument layout, and performs
final assembly. If a client obtains a signature from the wrong attestor key, the
signature is harmless because the LogicSig program will not accept it.

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
POST /sign/component
POST /sign/assemble
```

There is no MVP registration endpoint.

Explicitly out of scope for MVP:

- `POST /attestor/register-account`,
- account-binding storage,
- attestor profile import,
- attestor profile trust roots,
- profile drift checks,
- account lifecycle states such as active/suspended/revoked.

Existing and related endpoint decisions:

- `/plan` remains the canonical group planning endpoint.
- `/sign` never signs attested-account key types or attestor component key
  types.
- signer-side `POST /simulate` rejects attested-account senders in MVP because
  attested accounts require a client orchestrator and a second signer endpoint.
  `apshell send --simulate` may still simulate an attested transaction by
  running the attested component-signing/assembly flow and submitting the
  assembled group to algod simulation.
- Attestor-role `/sign/component` authorizes only transfer target transactions
  covered by deterministic routing. Target transactions with no supported
  transfer movement (`appl`, `keyreg`, `acfg`, etc.) are rejected.
- `/sign/cancel` remains scoped to live `/sign` requests in the current MVP.
  Component and assembly request IDs are correlation fields, not live durable
  request handles.

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
  the attestor component key and policy that governs when it may sign.

The current product deployment model is one `apsigner` on the signer host, with
one signer data directory resolved by `-d` or `APSIGNER_DATA`. Product UI/docs
are single-operator and expose the product identity, normally `default`.
Although the runtime has identity scoping, the system does not claim strong
tenant isolation or product support for unrelated operators sharing one node.
The attestor MVP product model keeps that shape: one apsigner endpoint is
presented as one active authenticated identity, normally `default`. Endpoint
bodies do not carry an `identity` field, and MVP routes do not add identity path
segments such as `/sign/component/<identity>`.

Future multitenancy must introduce identity routing consistently across
`/sign`, `/sign/component`, `/sign/assemble`, `/keys`, policy, and admin
surfaces. Identity selection must be part of authenticated routing/session
context, not a free-form transaction request field.

MVP supports single-purpose apsigner nodes:

1. **Signer node.** The apsigner data root has `node.yaml` `role: signer` and
   may hold ordinary account-signing keys and attested account keys. It must
   not hold attestor component private keys.
2. **Attestor node.** The apsigner data root has `node.yaml` `role: attestor`
   and may hold attestor component private keys and attestor policy. It must
   not hold ordinary account-signing keys or attested account keys.

There is no `dual` node role and no supported same-process mixed-role hosting.
The previous same-process co-location model is removed deliberately. Nothing is
lost in capability: co-located development or same-host deployments can still
run one signer data directory/process and one attestor data directory/process.
What goes away is a single apsigner process that contains both role families,
and that removal is what provides the structural single-purpose guarantee.

Independence is evaluated per attested account. For a given account, the user
component private key and the attestor component private key must be held by
different apsigner deployments/operator domains to claim independent
attestation.

A two-party reciprocal deployment that wants independent attestation uses
separate signer and attestor nodes across operator domains. For example:

```text
Machine A signer node
  identities/default   # A user keys

Machine A attestor node
  identities/default   # attestor keys and policy for B accounts

Machine B signer node
  identities/default   # B user keys

Machine B attestor node
  identities/default   # attestor keys and policy for A accounts
```

Accounts owned by A use A's user component key and B's attestor component key.
Accounts owned by B use B's user component key and A's attestor component key.
Neither signer node attests its own local user accounts in production.

Multi-attestor-operator co-hosting on one node remains out of scope until the
broader multi-tenant signer model is hardened and productized.

This does not make `attestor` a product user or tenant. It is an
operator-controlled service role scoped to an apsigner node. Product UX and
docs remain single-operator; unrelated operators must not be co-hosted under
this MVP model.

### 5.1 Node Role

Each signer data root has a node role stored in root `node.yaml`:

```yaml
schema_version: 1
role: signer
created_at: "2026-06-07T00:00:00Z"
```

Allowed values are exactly:

- `signer`: the node may hold and use ordinary account/signing keys,
  including attested account keys such as `aplane.falcon1024-att-ed25519.v1`.
  It must not hold attestor component keys.
- `attestor`: the node may hold and use attestor component keys such as
  `aplane.attestor-ed25519.v1` and `aplane.attestor-falcon1024.v1`. It must
  not hold ordinary account/signing keys.

The default for a new initialization is `signer`. Unset role must never mean
"anything goes": initialized stores require `node.yaml`, and startup rejects a
missing, malformed, or unknown node role.

Role is bound to the node/data root, not to an individual identity. A node may
host multiple identities only when they all share the same role. Identity-level
`mode` is an unsupported pre-release shape and startup must reject it rather
than migrate it.

Node role gates key class at every key-ingestion boundary:

- key generation and mnemonic import reject key types disallowed by the
  node role;
- restore, hand-placed key files, and other out-of-band changes fail closed at
  key scan/load when the scanned inventory contains a key type disallowed by
  the node role;
- service endpoints reject role/use mismatches even if a forbidden key file is
  present on disk.

There is no role-change operation. An operator that needs both roles creates
two complete data roots. If a contradiction arrives through backup restore or
manual file placement, key load fails closed for the node and surfaces the
conflict until the operator removes the conflicting key files or uses a data
root initialized for the correct role. After a reload detects the contradiction,
the process marks the identity registry closed so HTTP and admin identity
resolution refuse all identities until operator cleanup and restart.

`node.yaml` is plaintext for early startup and diagnostics, but the role is
also integrity-bound per initialized identity by an HMAC sidecar over the exact
root `node.yaml` bytes. The HMAC is verified after the identity master key is
available and before unlock-dependent key scan, generation, import, restore, or
signing service dispatch. A failed role HMAC check fails closed.

Node role is a key-class and operational guardrail, not an independence proof.
A signer and attestor node on one host, or under one operator, are still one
operational trust and availability domain. Independent attestation remains a
deployment-domain property: for a given account, the user component private key
and embedded attestor component private key must be controlled by different
operator domains.

### 5.2 APlane Invariant Compatibility

The attestor role placement above is compatible with current APlane invariants
when implemented with these constraints:

- HTTP token authentication selects exactly one identity runtime; requests do
  not carry a free-form target identity override.
- `/sign/component` and `/sign/assemble` follow `/sign`: they operate on the
  authenticated signer identity selected before endpoint logic runs.
- Attestor private keys stay under `identities/<identity>/keys/` and never
  leave `apsigner`.
- Attestor policy, unlock state, token, and audit records are identity-scoped;
  `attestation.yaml` and policy document domains are defined in
  [ARCH_POLICY.md#role-domains](ARCH_POLICY.md#role-domains).
- Node role is loaded from root `node.yaml` and integrity-checked before key
  generation, mnemonic import, scan/load, and signing service dispatch; the
  role check is enforced against key type/category metadata, not string
  appearance.
- `/sign` never reaches attestor component keys or attested-account key types;
  component signing uses `/sign/component`.
- `/plan` continues to own canonical group shaping and uses attested-account
  metadata only for planning and size/fee budgeting.
- Product UI/docs do not claim tenant isolation or recommend self-attestation
  as a production control.

Violations would be: treating the attestor node identity as an unrelated
hosted tenant, allowing callers to select arbitrary identities in request bodies,
sharing one account's user and attestor private keys in the same deployment
while claiming independent attestation, letting the normal `/sign` provider
path sign attestor/attested key types, or authorizing attestation from
caller-supplied labels instead of decoded transaction facts.

## 6. Key Types And Registries

### 6.1 Key Types

MVP key types:

```text
aplane.attestor-ed25519.v1
aplane.attestor-falcon1024.v1
aplane.falcon1024-att-ed25519.v1
aplane.falcon1024-att-falcon1024.v1
```

The MVP deliberately has no all-Ed25519 attested account key type. Future
attested-account key types should follow the same client-side account-key
naming pattern `aplane.<user-key-family>-att-<attestor-key-family>.v1`.

`aplane.attestor-ed25519.v1` and `aplane.attestor-falcon1024.v1` are
attestor component keys. They can produce raw component signatures only. They
are not Algorand spending accounts and must not be accepted by `/sign`.

`aplane.falcon1024-att-ed25519.v1` embeds an Ed25519 attestor verifier.
`aplane.falcon1024-att-falcon1024.v1` embeds a Falcon-1024 attestor verifier.
The attested-account key type determines which attestor component key type and
signature scheme are accepted by assembly and by the LogicSig bytecode.

Generated attestor component keys are selected by a canonical component-key
selector:

```text
all attestor component keys:
  component_key = "a_" || lower_hex(sha256(public_key_bytes))
```

`a_` means "APlane component selector." The selector is public,
deterministic, not an Algorand address, and always a 66-character
`a_<64 lowercase hex>` string. The hash input is the canonical public-key bytes
for the component key type, independent of key family or public-key size. The
full component public key remains exposed in `public_key_hex`; for Ed25519
and Falcon attestors, that public key is the value embedded in the matching
`aplane.<user-key-family>-att-<attestor-key-family>.v1` LogicSig bytecode and
used for endpoint routing. Component signing requests use the selector in the
`component_key` field when selecting a specific local attestor component key.

If an attestor identity has exactly one active attestor component key, clients
may omit `component_key` for role `attestor` and the signer may select that key
unambiguously. If more than one active attestor component key exists,
`component_key` is required. Key selection never affects policy authorization;
policy is evaluated from decoded transaction facts.

If existing key inventory or generation DTOs require an `address` field for
every key row, a component-key row uses the canonical component-key selector in
that field. That locator is not a spendable account address, must be marked as
non-spending in UI, and must not be accepted as `auth_address`, transaction
sender, or rekey target.

For MVP wire DTOs, component-key inventory and generation responses use these
exact additive fields:

```json
{
  "address": "a_<sha256-public-key>",
  "public_key_hex": "...",
  "key_type": "aplane.attestor-ed25519.v1",
  "is_component_key": true,
  "is_spending_account": false
}
```

The client obtains the attestor component public key from the attestor signer's
`/keys` projection before generating an attested account. That public key, not
an endpoint URL or credential, is embedded in the generated LogicSig.
For Falcon-sized public keys or offline provisioning, the attestor operator may
instead export the same public key through:

```text
apstore attestor export-public <component_key> [output-json]
```

The exported JSON envelope has schema `aplane.attestor-public-key.v1`; its
`public_key_hex` field is the value to embed as `attestor_public_key`, and its
`component_key` field is the local `a_` selector. The envelope is public-only
and carries no private key material or endpoint trust claim.
The user signer may import that envelope into its local public attestor
reference library with:

```text
apstore attestor import-public <export-json> <name>
```

After import, generation may use `attestor=<name>` instead of
`attestor_public_key=<hex>`. The signer resolves the name locally, validates
that the imported component key type matches the attested account key type, and
persists only the resolved `attestor_public_key`.

When matching references exist, identity-scoped `/keytypes` metadata may expose
the attested-account creation parameter as `attestor` with `type:"select"` and
`options[]` set to the imported reference names. This lets admin clients choose
from the library instead of asking users to paste public-key hex.

For all component-key rows, `address` is the `a_` selector and
`public_key_hex` is the full component public key. Existing spending account
rows omit `is_component_key` or set it to `false`, and omit
`is_spending_account` or set it to `true`. SDKs and shell UI must treat absent
`is_component_key` as `false`. They must not infer that an `address` field is
an Algorand address when `is_component_key:true` or `is_spending_account:false`.
Every ingestion point that accepts account-like strings must rely on key
type/category metadata and the `is_component_key` / `is_spending_account`
projection, not string shape. Component selectors must be rejected wherever an
Algorand account address is required, including transaction sender,
`auth_address`, and rekey target inputs.

`POST /admin/generate` for a component key returns the same fields plus the
existing `parameters` field when parameters are present. Contract fixtures must
pin both `/keys` and `/admin/generate` component-key examples.

For attested account rows, `/keys` must expose the non-secret creation metadata
needed for client orchestration:

```json
{
  "address": "<attested_account_address>",
  "public_key_hex": "...",
  "key_type": "aplane.falcon1024-att-ed25519.v1",
  "parameters": {
    "attestor_public_key": "<attestor_public_key_hex>"
  }
}
```

This is a compatibility-bearing `/keys` wire projection. The value is the
attestor public key stored at generation time and embedded in the LogicSig; it
is not an endpoint credential and does not prove ownership by any remote
attestor endpoint.

`aplane.falcon1024-att-ed25519.v1` and
`aplane.falcon1024-att-falcon1024.v1` are attested account keys. Each is a
DSA-backed LogicSig key on disk with:

- `category: dsa_lsig`
- user private key hex in the existing `private_key` JSON field
- user public key hex in the existing `public_key` JSON field
- `base_key_type: aplane.falcon1024.v1`
- compiled LogicSig bytecode hex in the existing `lsig_bytecode` JSON field
- off-curve `salt_counter`
- `signing_args` containing durable argument order
- attestor public-key metadata under `parameters` / `params`

The attested account key stores the attestor public key selected by the user at
generation time. That public key is a LogicSig verifier input, not attestor-side
authorization state.

Both attested account key types are library-visible compiled providers, not
default-enabled key types. An identity must activate the relevant key type from
the KeyType Library before the generation surface offers it.

The `falcon1024-att-ed25519` and `falcon1024-att-falcon1024` families name
both component signature schemes: Falcon-1024 for the user role and either
Ed25519 or Falcon-1024 for the attestor role. The stored template metadata and
bytecode remain the signing authority, but the stable key type identifier must
expose the attestor verifier family because changing it requires different
LogicSig bytecode.

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

- `aplane.attestor-ed25519.v1` generation returns canonical `public_key_hex`
  and uses a stable `a_` component-key selector derived from that public key,
- `aplane.attestor-falcon1024.v1` generation returns canonical
  `public_key_hex` and uses a stable `a_` component-key selector derived from
  that public key,
- `aplane.falcon1024-att-ed25519.v1` and
  `aplane.falcon1024-att-falcon1024.v1` generation use exact attested-account
  generators, not the Falcon base generator through fallback.

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
- group audit hashes use SHA-256 because they are off-chain canonical-data
  fingerprints.

## 8. Attested LogicSig Template

The MVP template verifies:

```text
verify_user(user_public_key, m_user, arg user_signature)
AND
verify_attestor(attestor_public_key, m_attestor, arg attestor_signature)
```

Template requirements:

- public keys are embedded in bytecode using constant bytes,
- the attestor public key is chosen at user key generation time,
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

## 9. Stateless Attestation Model

There is no account registration or account-binding store in the MVP.

The attestor does not decide whether an account is "registered", "active", or
"trusted". It decides only whether the target transaction facts satisfy this
identity's policy. The transaction sender address is the policy subject.

Example deterministic attestation policy:

```yaml
transfer_policy:
  schema_version: 1
  enabled: true
  routes:
    - id: a_to_b_c
      networks: ["mainnet"]
      sources: ["A..."]
      assets: ["algo"]
      destinations: ["B...", "C..."]
```

For an attestor component request, the signer extracts the supported direct
transfer movements defined in
[ARCH_POLICY.md#transfer-routing](ARCH_POLICY.md#transfer-routing). Target
transactions that produce none of those movements are rejected.

Policy must use decoded canonical transactions as the source of truth:

- sender comes from transaction `Sender`,
- receiver comes from `Receiver` or `AssetReceiver`,
- close destinations come from close fields,
- assets and amounts come from transaction fields,
- network comes from transaction `GenesisHash`,
- group context comes from decoded group membership.

The request body may select target indices and a local component key. It must
not supply policy facts such as "source A", "destination B", profile labels, or
route labels as trusted inputs.

For MVP, the attestor does not require or verify user counterparty signatures
before signing. The user signature is enforced by the final LogicSig. A future
policy option may require a verified user component signature first, but that
is not part of the initial model.

## 10. Persistent Storage

The MVP adds no new attestor-side behavior-bearing storage beyond existing
identity-scoped keys, policy, token, unlock config, and audit log.

Specifically, MVP does not create:

```text
identities/<identity>/attestor/
identities/<identity>/attestor/profiles/
identities/<identity>/attestor/trusted_org_keys.json
identities/<identity>/attestor/account_bindings.json
```

Attestor component private keys are normal encrypted identity key files under:

```text
identities/<identity>/keys/
```

Attestor authorization policy is a separate identity-scoped signed policy file:

```text
identities/<identity>/attestation.yaml
identities/<identity>/attestation.yaml.hmac
```

The same policy HMAC, reload, backup, restore, and fail-closed behavior from
`docs/ARCH_CONTRACTS.md` applies to both `policy.yaml` and
`attestation.yaml`.

Backup and restore preserve attestor component keys through the normal key
backup path and preserve policy snapshots through the existing managed backup
policy snapshot. Restore does not install policy automatically; restored policy
YAML must be reviewed and re-signed for the destination store through the
existing policy recovery flow.

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

HTTP service role dispatch must honor node role:

- `signer` nodes may use `/sign`, `/plan`, `/simulate`, user-role
  `/sign/component`, and `/sign/assemble`. Attestor-role `/sign/component`
  must be rejected because the node is not allowed to hold attestor component
  private keys.
- `attestor` nodes may use attestor-role `/sign/component`. `/sign`,
  `/simulate`, user-role `/sign/component`, and `/sign/assemble` must be
  rejected because the node is not allowed to hold account/signing keys.

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
sign.component
sign.assemble
```

Product-mode bootstrap grants must include these actions for
`system:product-admins`.

HTTP endpoint mapping:

```text
POST /sign/component -> sign.component, resource transaction
POST /sign/assemble  -> sign.assemble, resource transaction
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

For attestor endpoints, `request_id` is optional and the response always
returns a non-empty canonical request ID:

- caller-supplied IDs are echoed,
- omitted IDs are generated by the server,
- audit and assembly may record the returned ID.

Component and assembly request IDs are correlation IDs only in the current MVP.
They are not stored in the approval coordinator, are not durable, and are not
polling handles.

Server-generated IDs should include an internal kind prefix or equivalent
entropy to avoid accidental collisions, but clients must treat returned IDs as
opaque strings.

`POST /sign/cancel` keeps its current DTO, response shape, and scope. It can
cancel live `/sign` requests for the authenticated identity. It returns
`not_found` for `/sign/component` and `/sign/assemble` request IDs because
those endpoints are synchronous correlation-only flows in MVP.

`/sign/assemble` does not wait for operator approval and is not cancelable
beyond normal HTTP context cancellation. Its `request_id` is for response and
audit correlation only.

### 11.3 Request Description Rendering

Neither user-role nor attestor-role `/sign/component` queues operator approval
in the current MVP.

Both roles must supply a structured request description, analogous to the
existing transaction `txdesc`, so audit records can explain the decision
without trusting caller labels.

Component-signing request descriptions must show:

- request kind and component role,
- selected component key selector for attestor role
  (`component_key`, the canonical component-key selector),
- attested account / transaction sender,
- target indices and target TxIDs,
- decoded transfer facts for each target,
- observed genesis hash / resolved network token,
- group hash,
- policy verdict phase or deterministic attestation outcome,
- policy rule ID when available,
- warnings such as rekey, close-out, clawback, asset close, or high fee.

These descriptions are presentation-only and must not introduce signing inputs.
The authoritative signing inputs remain the decoded group bytes and target
indices. Description rendering lives in `internal/signerapp/txdesc` or a
focused sibling package, not in transport adapters.

## 12. `/sign/component`

Request:

```json
{
  "request_id": "cli-123",
  "role": "attestor",
  "component_key": "a_<sha256-public-key>",
  "group_bytes_hex": ["5458..."],
  "target_indices": [0]
}
```

Response:

```json
{
  "request_id": "cli-123",
  "component_key": "a_<sha256-public-key>",
  "signatures": [
    {
      "target_index": 0,
      "signature": "...",
      "signature_scheme": "aplane.attestor-ed25519.v1"
    }
  ]
}
```

The request and response examples show the attestor role. Role-specific wire
values are:

- attestor role: `component_key` is the local attestor component-key selector
  (Section 6.1). It may be omitted only when the authenticated identity has
  exactly one active attestor component key. The response `signature_scheme` is
  the attestor component key type, for example `aplane.attestor-ed25519.v1` or
  `aplane.attestor-falcon1024.v1`.
- user role: `component_key` is the local attested-account LogicSig address,
  because the user's component private key lives in that `dsa_lsig`
  attested-account key file. The response `signature_scheme` is the user key
  type, for example `aplane.falcon1024.v1`.

Validation:

- `role` is exactly `user` or `attestor`.
- `group_bytes_hex` has length 1 through 16.
- `target_indices` is non-empty, unique, sorted or canonicalized for internal
  processing, and every value is in range.
- every transaction byte string is canonical per Section 7.
- group consistency is valid per Section 14.
- every target transaction has `txn.Sender` equal to the attested account being
  authorized. For role `user`, the attested account is the local
  attested-account LogicSig selected by `component_key`; for role `attestor`,
  the attested account is the target transaction sender being evaluated
  against policy.
- every target transaction has a non-empty `GenesisHash` that resolves to an
  allowed network context token for policy evaluation.
- role `attestor`: `component_key`, after optional unambiguous defaulting,
  resolves to a local active attestor component key.
- role `user`: `component_key` resolves to a local `dsa_lsig`
  attested-account key file, and every target transaction has
  `txn.Sender == component_key`.

Attestor-role policy:

- component signing uses the attestation policy domain described in
  `docs/ARCH_POLICY.md`: deterministic reject or sign, with no operator
  default and no human review.
- policy evaluates target transactions in the context of the decoded group.
- policy evaluates only decoded transaction facts and existing signer-owned
  context. It does not use caller-supplied labels.
- transfer routing is the positive authorization surface for attestation. All
  target transactions must be supported transfer shapes, every extracted target
  movement must be covered by a matching route, and no transaction guard or
  route outcome may deny the request.
- for the common case "A can send to B and C", the route's `sources` contains
  Algorand address `A` and `destinations` contains addresses `B` and `C`.
- passthrough and non-target group slots participate in group context, warning
  display, and request descriptions, but attestor policy verdicts are produced
  for target slots only.
- if the effective attestation policy does not positively authorize every
  target movement, the request is rejected.

User-role policy:

- user component signing uses the same transaction policy phase order as
  `/sign`.
- the effective policy is selected by the local attested-account key type.
- user-role component signing does not require or consult an attestor-side
  account binding.

Non-2xx failures use `ErrorResponse`. Policy/operator rejection is `403`.
Malformed shape and validation failures are `400` unless the existing error
model classifies them otherwise.

## 13. `/sign/assemble`

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
- group consistency is valid per Section 14.
- each target resolves to a local attested-account key file on the user signer.
- target sender equals `attested_account`.
- target `GenesisHash` matches the stored key metadata when stored metadata
  contains a pinned genesis hash.
- `user_signature` verifies over role `user` message.
- `attestor_signature` verifies over role `attestor` message using the
  attestor public key embedded in the local attested-account key's stored
  LogicSig bytecode/metadata.
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
forensic fields. In the current MVP they are response/request correlation
claims only and are not written as structured assembly audit fields. They are
not cryptographic provenance until a future signed component-receipt mechanism
is added.

Structured assembly audit is deferred. Until that lands, assembly failures are
reported to the caller through the HTTP response and do not emit a dedicated
`ATTESTED_ASSEMBLY` audit event.

## 14. Group Consistency

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

## 15. Network Scoping

Network identity is derived from transaction `GenesisHash`, not `GenesisID`.

Attestor component signing uses the same genesis-hash-to-network-token
resolution as normal signer policy:

- built-in mainnet/testnet/betanet genesis hashes resolve to their built-in
  tokens,
- configured signer genesis mappings resolve custom networks,
- unknown genesis hashes fail closed when a network-scoped policy rule must be
  evaluated.

At component signing and assembly:

- target transaction `GenesisHash` is decoded from the transaction bytes,
- policy uses the resolved network token,
- `GenesisID` may be displayed as diagnostic data but is never the policy key.

## 16. Policy

The MVP uses the shared policy language in two signed identity-scoped
documents: `policy.yaml` for normal transaction signing and `attestation.yaml`
for attestor component signing.

The policy question is:

```text
May this identity produce this kind of signature for these decoded transaction facts?
```

For `/sign`, the signature kind is transaction/account signing. For
`/sign/component` role `attestor`, the signature kind is attestor component
signing. The stored policy language is shared; the evaluation context differs.

Client signing keeps the existing policy phase order:

```text
Always Deny > Always Review > Always Approve > Operator Default
```

Attestation uses the same decoded transaction facts and routing engine, but its
verdict surface is deterministic. As shorthand:

```text
deny > allow/sign
```

This means Always Deny and deterministic guard failures reject before routing
allow-list success; a transfer route match authorizes only when no deny guard
matches and every target movement is covered.

There is no `Always Review` prompt and no `user_auto_approve` fallback for
attestor component signing.

`transfer_policy` is the only MVP positive-authorization surface for
attestation; other applicable policy fields are deterministic deny guards.
For attestation, routing acts as an allow-list: all target transfer movements
must match a route, no deny guard may match, and the effective attestation
policy must not contain review-producing routing behavior such as
`on_no_route: review` or `review_above`. Target transactions that produce no
supported transfer movement are rejected because there is no route coverage
that can authorize them. See Section 9 for an example policy shape.

Policy evaluation context:

- normal `/sign`: evaluates signer-controlled request slots as today.
- `/sign/component` role `user`: evaluates local user component target slots.
- `/sign/component` role `attestor`: evaluates selected target slots as
  attestation targets, even though the attestor does not own the transaction
  sender account.

Existing signer-specific rules must be interpreted carefully in the attestor
context:

- `reject_close_remainder`, `reject_asset_close`, and `reject_clawback` apply
  directly.
- `max_fee_microalgos`, `max_algo_payments`, and `max_asa_amounts` apply
  directly.
- `review_algo_payments`, `review_asa_amounts`, and
  `always_review_warnings` are client-signing-only and do not apply to
  attestor component signing.
- `reject_foreign_rekey` is client-signing-only. Attestation uses
  `attestation.reject_rekey` and the MVP default is to reject any non-zero
  `RekeyTo`.
- `auto_approve_self_noop_transfer` remains a transaction-signing convenience
  rule and must not be treated as attestor-specific authorization. If present
  in common policy, it harmlessly never fires for attestor requests because its
  predicate requires signer-owned address context.

No new `attestor.registration` policy block exists in MVP.

Caller-specific transaction policy is deferred. Caller identity remains
available for authentication, revocation, audit, and rate limiting.

## 17. Audit

Current MVP audit behavior:

- attestor-role component approvals are recorded through existing
  `SIGN_APPROVED` audit entries,
- attestor-role component policy rejections are recorded through existing
  `SIGN_REJECTED` audit entries,
- `txn_auth` carries the attestor component selector,
- `txn_sender` carries the decoded target transaction sender,
- `txn_details`/`reason` identify the attestation component-signing outcome,
- `policy_rule_id` is present when a deterministic attestation policy rule
  caused rejection.

This keeps attestor component decisions visible without adding a new audit
schema during the beta/invisible feature window.

Future structured audit work may add dedicated events:

```text
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

Future component audit records should include:

- identity ID,
- request ID,
- component role,
- component key selector for attestor role (`component_key`),
- attested account / transaction sender,
- target indices,
- target TxIDs,
- group hash,
- observed genesis hash,
- resolved network token,
- decoded transfer facts for target transactions,
- warnings,
- requester principal,
- approver principal when manually approved for user-role component signing,
- policy verdict phase,
- policy rule ID when applicable.

Future `ATTESTED_ASSEMBLY` records should include:

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
network_mismatch
group_inconsistent
coverage_violation
arg_count_mismatch
passthrough_txid_mismatch
key_missing
unknown
```

Audit values for claimed source request IDs must be documented as
unauthenticated claims.

## 18. UX And Tooling

Attestor signer:

```text
apshell generate aplane.attestor-ed25519.v1
apshell generate aplane.attestor-falcon1024.v1
apstore attestor export-public <component_key> [output-json]
apstore attestor import-public <export-json> <name>
```

The MVP does not add an `apstore generate` surface. Attestor component keys are
generated through the existing signer/admin key-generation path exposed by
`apshell generate` and `POST /admin/generate`, guarded by `keys.generate`.
`apstore attestor export-public` is an offline public-only export of the verifier
input for an already-created attestor component key. It reads only the
component key's public metadata sidecar, does not generate keys, and does not
bypass the disabled private-key export path.
If a later implementation adds offline `apstore` generation, it must define the
command ownership, authorization behavior, audit behavior, and tests in the
same change.

User signer/client:

```text
apstore keytype enable falcon1024-att-ed25519.v1
apstore keytype enable falcon1024-att-falcon1024.v1
apshell generate aplane.falcon1024-att-ed25519.v1 attestor_public_key=<hex>
apshell generate aplane.falcon1024-att-falcon1024.v1 attestor_public_key=<hex>
apshell generate aplane.falcon1024-att-ed25519.v1 attestor=<name>
apshell generate aplane.falcon1024-att-falcon1024.v1 attestor=<name>
apshell send <amount> algo from <attested-account> to <receiver>
```

`apshell send` detects attested-account key types and performs the user
component-signing call, attestor component-signing call, local user-signer
assembly call, and algod submit transparently.

1. The user generates an attested account key that hard-codes the attestor
   public key in the LogicSig program.
2. The orchestrator obtains a user component signature from the user signer.
3. The orchestrator sends canonical transaction/group bytes to the attestor
   signer.
4. The attestor signer evaluates `attestation.yaml` over decoded transaction
   facts and returns attestor component signatures when allowed.
5. The user signer assembles the final signed group.

Shell command workflow logic belongs in `internal/apshellapp`, not
`cmd/apshell`. Reusable network/signing orchestration belongs in
`internal/engine` or a focused internal package. Endpoint resolvers that need
signer HTTP clients must obtain them through the existing
`internal/engine/connect` ownership path rather than creating a parallel
connection or tunnel lifecycle.

Client-side credential routing is separate local client config. Signer
endpoint connection profiles live in `$APCLIENT_DATA/endpoints.yaml`; API
tokens remain in endpoint-scoped token files referenced by those profiles.
Endpoint-published attestor inventory uses the expected attestor public key hex
as the map key under that endpoint's `published_attestors`; runtime routing is
derived from this inventory. Tokens are never stored in attested LogicSig
metadata.

Example:

```yaml
# $APCLIENT_DATA/endpoints.yaml
schema_version: 1
default: primary
endpoints:
  primary:
    url: ssh://signer.example:1127
    signer_port: 11270
    token_file: aplane.token
  attestor-local:
    url: ssh://127.0.0.1:2223
    signer_port: 11270
    token_file: tokens/attestor-local.token
    published_attestors:
      "<embedded-attestor-public-key-hex>":
        component_key: a_88aa9cc9abffc13e3355b74c100177a9bbd1df04dacf18b6e15974e3dc69b078
        key_type: aplane.attestor-ed25519.v1
        last_seen_at: "2026-06-04T00:00:00Z"
```

Operator handoff uses a public endpoint envelope rather than manual YAML edits
in the common case:

```bash
# signer side
apstore -d "$APSIGNER_DATA" endpoint export \
  --host signer.example \
  --out signer.endpoint.json

# attestor side
apstore -d "$APSIGNER_DATA" endpoint export \
  --host attestor.example \
  --out attestor.endpoint.json

# client side
apshell -d "$APCLIENT_DATA"
> endpoints import-public --alias main --role signer signer.endpoint.json
> endpoints import-public --alias attestor-local --role attestor attestor.endpoint.json
> endpoints show attestor-local
> request-token --endpoint attestor-local
> connect main
> endpoints sync-attestors
```

The exported `aplane.endpoint.v1` envelope is public routing metadata only and
uses the same `schema: "aplane.<name>.vN"` JSON-envelope convention as attestor
public-key exports. It contains no client-local alias, attestor public-key
metadata, API token, private key, mnemonic, encrypted key payload, passphrase,
or `known_hosts` entry, and it cannot use `url: self`. Importing the envelope
with a client-chosen alias only configures the endpoint profile. It does not
discover attestor keys or prove endpoint ownership; the
trust anchor remains the attestor public key that was selected at user-key
generation and embedded in the LogicSig. Import replaces existing endpoint
data for the same alias. The same URL may be imported under two aliases only
when the roles differ, such as a dev node serving both the client signer and a
local attestor. Dry-run import must run the same validation and conflict checks
as a real import without writing files.

After endpoint tokens and SSH host trust are established, `apshell endpoints
sync-attestors [--dry-run] [--yes]` queries `/keys` on configured `attestor`
endpoints, extracts attestor component-key `public_key_hex` values, and
atomically rebuilds reachable endpoints' `published_attestors` inventory in
`endpoints.yaml`. Temporarily unavailable endpoints, including locked signer
identities, are skipped and preserve their existing `published_attestors`
entries. Authentication failures, endpoint configuration errors, malformed
responses, duplicate public keys advertised by multiple endpoint aliases, and
component-key validation failures are hard errors and leave files unchanged.

After discovery, `sync-attestors` prints the attestor component IDs it is about
to publish and requires confirmation, unless `--yes` is provided, before
copying that local `published_attestors` inventory into the connected user
signer identity as source-marked public attestor reference records. This sync is
for generation UX: it makes endpoint-discovered attestors selectable in
`/keytypes` consumers such as `apadmin`. It carries only public metadata and
does not move endpoint tokens, SSH trust, or any private key material. The
signer continues to resolve the selected reference to the embedded attestor
public key at generation time.

A logical attestor may have multiple equivalent endpoints for availability.
The client may call each endpoint's `/keys` projection to check whether it
advertises the expected `public_key_hex`, but this is an early-fail
misconfiguration check only and does not prove key ownership. Network failure
may fail over to another equivalent endpoint; policy rejection is final and
must not be retried as an outage. The actual trust anchor remains the attestor
public key embedded at `aplane.<user-key-family>-att-<attestor-key-family>.v1`
generation time.
If the client performs the optional pre-assembly attestor signature check, it
must use the shared `internal/attestor/verify` primitives so message
construction stays byte-identical to signer assembly and on-chain LogicSig
verification.

Endpoint resolution rules:

- If an endpoint's `published_attestors[attestor_public_key]` inventory exists,
  the client routes attestor-role signing to that endpoint for that public key.
  A `/keys` mismatch for a configured endpoint is a hard configuration error,
  not permission to fall back to local self-discovery.
- If no explicit mapping exists, development self-discovery may resolve to the
  currently connected signer when that signer advertises a matching
  attestor component key. The attested account key type determines the required
  attestor component key type: `aplane.falcon1024-att-ed25519.v1` matches
  `aplane.attestor-ed25519.v1`, and
  `aplane.falcon1024-att-falcon1024.v1` matches
  `aplane.attestor-falcon1024.v1`. This is local development ergonomics only;
  docs must not present self-attestation as production third-party attestation
  or as a security control.
- Remote production attestor endpoints must use an authenticated confidential
  transport. The preferred product path is the existing SSH tunnel and
  `known_hosts` trust model owned by `internal/engine/connect`; HTTPS with
  normal signer token authentication is also acceptable when deployed with
  ordinary TLS validation. Raw remote `http://` examples are loopback/dev only.

## 19. Implementation Ownership

Expected new or changed packages:

```text
pkg/signerapi/attestor.go
internal/attestor/message/
internal/attestor/verify/
internal/signerapp/signing/component.go
internal/signerapp/signing/assemble.go
cmd/apsigner/http_handlers_attestor.go
internal/signerclient/attestor.go
internal/apshellapp/attestor.go
internal/engine/attestor_signing.go
lsig/falcon1024_attested/
```

There is no `lsig/` package for attestor component key types such as
`aplane.attestor-ed25519.v1` or `aplane.attestor-falcon1024.v1`: they are raw
component-signing keys, not LogicSigs. Their generation lives under
`internal/keygen`; Ed25519 component signing uses the standard Ed25519 helper,
and Falcon component signing reuses the signer-side Falcon operations.
Falcon-user attested-account templates live in `lsig/falcon1024_attested`.
Future attested-account templates should follow the
`aplane.<user-key-family>-att-<attestor-key-family>.v1` naming pattern and live
in focused packages for their user-key family.

Existing package changes:

- `internal/auth`: add stable actions and bootstrap grants.
- `cmd/apsigner/http_runtime.go`: register new routes.
- `internal/signerapp/rest`: expose service methods for new endpoints.
- `internal/signerapp/rest` and the `/keys` inventory DTO in `pkg/signerapi`:
  expose `public_key_hex`, `is_component_key`, and `is_spending_account` for
  component-key rows in `/keys` and key-generation responses, and expose
  `parameters.attestor_public_key` for attested-account rows.
- `internal/signerapp/txdesc`: add component request descriptions for manual
  review and audit (Section 11.3).
- `internal/signerapp/audit`: add event types and fields.
- `internal/signing`: add exact key-type transaction-signing guard or split
  transaction/component registries.
- `internal/keygen`: add exact-key-type generators for component and
  attested-account key types, and block family fallback for those types.
- `internal/keys`: preserve attestor public-key metadata in `KeyPair.Params`.
- `internal/policy`: support evaluating an attestor component-signing context
  over selected target transactions using the existing policy model.
- `internal/signerapp/signing/planner_runtime.go`: allow attested-account
  metadata in `/plan` while blocking `/sign`.
- `internal/signerapp/signing/simulation.go` or REST simulate path: reject
  attested-account senders.
- `docs` and `test/contracts/signerapi`: add compatibility docs and fixtures.

Layering rules:

- `internal/attestor/*` owns component message construction, group hash
  helpers, and pure verifier primitives. It must not depend on HTTP, identity
  runtime, approval, keystore sessions, or shell packages.
- `internal/policy` owns reusable transaction-fact policy evaluation for both
  normal signing and attestor component-signing contexts.
- `internal/signerapp/signing` owns decoded transaction-group component
  signing and final assembly because those flows share planning, policy,
  approval, audit, and lifecycle behavior with existing signing.
- `internal/engine` owns reusable client/orchestrator attestor-signing
  mechanics.
- `internal/apshellapp` owns shell command workflows and typed request/result
  APIs.
- `cmd/apshell` and `cmd/apsigner` remain transport/composition adapters.

## 20. Acceptance Tests

Phase 0 contract tests:

- group hash vectors pass.
- component message vectors pass.
- component-key selector vectors prove all attestor component-key selectors are
  `a_<sha256(pubkey)>` regardless of key type, prove the hash and prefix are
  stable, and prove selectors are not accepted as Algorand spending addresses.
- `/keys` and `/admin/generate` component-key fixtures include `address`,
  `public_key_hex`, `key_type`, `is_component_key:true`, and
  `is_spending_account:false`.
- `/keys` attested-account fixtures include `parameters.attestor_public_key`.
- `/sign/component` and `/sign/assemble` fixtures, including passthrough
  assembly items, are committed.
- attestor policy YAML fixtures prove existing `transfer_policy` routes can
  express "A can send to B and C" without registration.
- policy YAML fixtures containing `client_signing:` round-trip through
  `appolicy` and `apstore policy check/sign/verify` without losing
  valid-but-not-guided-edited YAML structure.
- attestation YAML fixtures use direct attestor policy fields with no
  `attestation:` wrapper and pass `apstore policy check/sign/verify`.

Unit tests:

- node role config parses `node.yaml`, defaults new initialization to
  `signer`, and rejects missing, malformed, or unknown role values for
  initialized stores.
- node role HMAC verification rejects tampered `node.yaml` before publishing
  unlocked runtime state.
- identity config rejects pre-release `mode` fields.
- node role rejects disallowed key generation and mnemonic import before
  writing key files.
- key reload fails closed and publishes no active key snapshot when scanned key
  inventory contains a key type disallowed by the node role.
- role-conflicting inventory in any identity fails closed for the whole node.
- `/sign` rejects every attestor component key type.
- `/sign` rejects every attested-account key type before provider lookup.
- key generation uses exact-key-type gates for attestor component and
  attested-account key types.
- component-key compatibility locator values, when present, are rejected as
  transaction sender, `auth_address`, and rekey target.
- `/sign/component` policy evaluation uses decoded transaction sender,
  receiver, amount, asset, fee, close, clawback, rekey, network, and group
  facts, never request labels.
- attestor role accepts a policy-allowed `A -> B` payment and rejects an
  otherwise identical `A -> D` payment when `D` is not routed.
- attestor role rejects route misses under deterministic `attestation.yaml`
  transfer policy and fails closed when policy would require a review or
  operator-default outcome.
- attestor role rejects `appl`, `keyreg`, `acfg`, and any other target
  transaction that produces no supported transfer movement.
- attestor role rejects unknown genesis hashes when network-scoped policy must
  be evaluated.
- attestor role rejects non-zero `RekeyTo` in MVP.
- attestor role applies close, asset close, clawback, fee, and amount
  thresholds consistently with the shared policy model.
- user-role component signing evaluates the local attested-account key type
  policy and does not require an attestor-side binding.
- component-signing request descriptions render the fields required by Section
  11.3.
- `/plan` accepts attested-account metadata and budgets LogicSig bytes.
- component message computation matches vectors.
- TEAL generated by each shipped attested-account template verifies known
  signatures in algod.
- group consistency rejects singleton with group, multi-member missing group,
  divergent group, and wrong computed group.
- signer-side `POST /simulate` rejects attested-account senders with a stable
  error message.
- `/sign/assemble` rejects malformed passthrough items and signed transaction
  TxID mismatches.

Integration tests:

- two isolated test `apsigner` deployments, user and attestor, each with its
  own temporary signer data root; this is test harness composition, not a
  product same-node multi-store deployment,
- account generation with a hard-coded attestor public key,
- successful singleton attested payment allowed by attestor `attestation.yaml`,
- successful multi-target group where every original sender is an attested
  account,
- successful assembly with passthrough signed entries, including signer-added
  dummy entries when LogicSig budget requires them,
- cross-network attempt rejected,
- route-miss attestor policy rejection,
- attestor rejection of `appl`, `keyreg`, and `acfg` target transactions from
  an attested account because routing cannot authorize them,
- user-role component-signing validates local attested-account key ownership
  and returns role-separated user component signatures,
- attestor-role component-signing deterministic approval and rejection without
  operator prompts,
- `/sign/cancel` returns `not_found` for component and assembly request IDs,
- missing local user key rejected,
- stolen-user-key scenario where attestor refuses based on transaction policy,
- rekey attempt cannot bypass attestor refusal,
- assembly emits audit on success and schema-valid failure,
- claimed source request IDs are recorded as claims.

SDK tests:

- Go, TypeScript, and Python DTO contract fixtures pass.
- SDK component-signing and assembly deadlines use ordinary request timeouts.
- SDK cancellation continues to target `/sign` only; component and assembly
  request IDs are correlation fields.

## 21. MVP Completion Criteria

The MVP is complete when:

- each signer data root has an enforced root `node.yaml` role with new
  initialization defaulting to `signer`, invalid roles failing config load, and
  identity-level `mode` rejected as an unsupported pre-release shape,
- node role is integrity-bound per initialized identity and tampered
  `node.yaml` fails closed before unlock-dependent signing state is published,
- key generation, mnemonic import, signer reload/load, and signing service
  dispatch reject key classes disallowed by the node role,
- attestor component keys cannot sign through `/sign`,
- attested account keys cannot sign through `/sign`,
- attestor component key generation exposes canonical `a_` selectors derived
  as `a_<sha256(pubkey)>` and marks them as non-spending component keys,
- `apstore attestor export-public` emits a public-only
  `aplane.attestor-public-key.v1` envelope and rejects selector/public-key
  mismatches,
- `apstore attestor import-public/list` manages identity-scoped
  public-only attestor references, attested-account generation accepts
  `attestor=<name>` as a local alias for `attestor_public_key=<hex>`, and
  identity-scoped key-type metadata exposes matching references as select
  options for admin clients,
- `/plan` handles attested account metadata,
- no registration endpoint, account-binding store, profile store, or trust-root
  store is required for attestation,
- `/sign/component` returns raw role-separated component signatures after
  evaluating decoded transaction facts against `attestation.yaml`,
- `/sign/assemble` verifies and assembles final signed transaction bytes,
- signer-side `POST /simulate` rejects attested accounts with a clear MVP
  limitation error, while `apshell send --simulate` can use the full attested
  orchestration flow and algod simulation,
- audit records attestor component approvals/rejections through existing sign
  audit events; structured component and assembly audit events are deferred,
- backup and restore preserve attestor component keys through the normal key
  backup path,
- contract fixtures and integration tests pass,
- SDK DTOs and docs are updated in the same release window.

## 22. Deferred Work

Deferred from MVP:

- client-side assembly,
- plan receipts,
- signed component receipts,
- on-chain co-sign records,
- attestor-side assembly,
- M-of-N attestor templates,
- escape hatches and recovery keys,
- optional stricter template/LogicSig preflight by the attestor,
- optional policy requiring a verified user component signature before
  attestor signing,
- public attestor profiles for discovery/marketing metadata,
- stateful account registration or recovery notices,
- attested-account simulation,
- guided role-aware editing for nested `client_signing:` blocks in
  `policy.yaml`.
