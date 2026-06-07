# Formal Attested Signing Model

> Status: precise English model, not machine-checked.
> This document formalizes the current attested-account component-signing
> workflow: user component signing, attestor component signing, assembly, and
> client endpoint routing.
> Invariant status (implemented / intended / derived / etc.) is tracked in
> [FORMAL_TRACEABILITY.md](FORMAL_TRACEABILITY.md).

## Sources

Normative inputs:

- [ARCH_SPEC.md#attested-signing-and-attestor-nodes](ARCH_SPEC.md#attested-signing-and-attestor-nodes):
  attestor component key types, attested account key types, endpoint workflow,
  role-separated messages, assembly semantics, and endpoint routing trust
  model.
- [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md): `/keys`, `/sign/component`,
  `/sign/assemble`, endpoint registry, node role, split policy files,
  and on-disk selector contracts.
- [ARCH_POLICY.md](ARCH_POLICY.md): attestor-domain `policy.yaml`, attestor component
  transfer policy, deterministic reject-only route-miss behavior, and
  component-key overrides.
- [FORMAL_POLICY_MODEL.md](FORMAL_POLICY_MODEL.md): client-signing policy
  precedence. This model imports only the snapshot and overlay concepts; the
  attestor role has no manual-review or operator-default verdict.
- [FORMAL_SIGNING_AUTHORITY_MODEL.md](FORMAL_SIGNING_AUTHORITY_MODEL.md):
  stored key-file authority for existing keys.

This model does not replace
[ARCH_SPEC.md#attested-signing-and-attestor-nodes](ARCH_SPEC.md#attested-signing-and-attestor-nodes).
It extracts the state, transition, and invariant surface that should remain
stable as the implementation evolves.

## Scope

This model covers the current MVP:

- attested Falcon account keys whose LogicSig bytecode embeds one attestor
  public key,
- attestor component keys selected by txid-shaped component selectors,
- `/sign/component` for user-role and attestor-role component signatures,
- `/sign/assemble` verification and LogicSig argument packing,
- `apshell send` orchestration for attested account senders,
- client endpoint discovery and sync for attestor routing,
- node role gates for signer nodes and attestor nodes.

It does not model:

- cryptographic algorithm security,
- TEAL opcode semantics or LogicSig budget internals,
- account registration or account-binding databases,
- trust in endpoint metadata as a security control,
- SSH host-key or token issuance state machines,
- operator behavior or manual approval for attestor component requests.

## Abstract Objects

### Attested Account Key

`AttestedAccountKey` is a DSA-backed LogicSig key file for an account whose
program requires two component signatures. The model observes:

- account address derived from stored LogicSig bytecode,
- stored user public/private component key material,
- stored attestor public key parameter,
- stored attested account key type, which determines the attestor component
  key family,
- stored signing metadata, bytecode, and runtime argument contract.

The attestor trust decision is made at key generation time by embedding the
chosen attestor public key into this key's LogicSig program and stored
parameters. Later endpoint routing does not move that trust anchor.

### Attestor Component Key

`AttestorComponentKey` is a non-spending key with:

- key category `component`,
- key type `aplane.sen-ed25519.v1` or
  `aplane.sen-falcon1024.v1`,
- public/private component key material,
- selector derived as uppercase base32 SHA-512/256 of the domain-separated key
  type and canonical public key bytes.

The selector is a routing and policy handle. It is not an Algorand sender,
auth address, close target, rekey target, or account address.

### Component Message

For a canonical target transaction with `txid`, the component-signing message is:

```text
m = SHA512_256("APLANE_ATTESTOR_V1" || role_byte || txid)
```

`role_byte = 0x01` for the user role and `role_byte = 0x02` for the attestor
role. The same pure message/verification primitives must be used by signer
services and optional client-side verification.

### Attestor Policy Snapshot

`AttestorPolicySnapshot` is the verified effective attestor-domain `policy.yaml` snapshot
for one attestor identity. It contains transfer routing and sparse
`key_overrides` keyed by component selector.

Unlike client-signing policy, attestor policy has no manual-review verdict and
no operator default. If no positive transfer route authorizes every target
transaction, the request rejects.

### Endpoint Registry

`EndpointRegistry` is client-local routing state in `endpoints.yaml`.

An endpoint can be role `signer` or `attestor`. A client has one primary signer
endpoint and zero or more attestor endpoints. Attestor endpoint inventory may
publish public attestor keys and selectors. That inventory is routing metadata
only; it is not proof that the endpoint owns any private key.

## Transitions

### Detect Attested Send

`apshell send` consults the primary signer's key cache. If any sender is an
attested account key type, the client uses the attested orchestration path.
The current MVP rejects mixed ordinary and attested original senders in one
group.

### Build Canonical Group

The client plans the transaction group, adds required dummy transactions for
LogicSig budget, fixes fees and group ID, and encodes the canonical unsigned
group bytes. Component signatures are always over target transaction IDs from
this canonical group.

### User Component Sign

The client calls the primary signer:

```text
POST /sign/component role=user component_key=<attested_account>
```

The signer loads the local attested account key only if every requested target
sender equals `component_key`. It signs the user-role component message with
the user component private key stored in that attested account key.

### Attestor Component Sign

For each distinct embedded attestor public key, the client resolves an attestor
endpoint and calls:

```text
POST /sign/component role=attestor component_key=<component_selector>
```

The attestor signer evaluates the attestor-domain `policy.yaml` transfer policy for every
target transaction before loading the component private key. The request is
accepted only when the effective attestor policy authorizes all target
transactions.

### Assemble

The client returns to the primary signer:

```text
POST /sign/assemble
```

For each target, the primary signer loads its local attested account key and:

1. verifies `user_signature` against the user public key stored in that local
   key,
2. verifies `attestor_signature` against the attestor public key embedded in
   that local key,
3. packs both signatures according to the attested account key type,
4. builds LogicSig args from stored signing metadata,
5. verifies the resulting LogicSig address equals the attested account,
6. returns signed group bytes, preserving passthrough bytes only if their
   decoded transaction ID matches the canonical group entry.

The assembling signer trusts values it stored at generation time. It does not
trust endpoint metadata supplied during the transaction flow.

### Discover And Sync Attestors

`endpoints sync-attestors` queries reachable attestor endpoints with valid
tokens, refreshes their published inventory in `endpoints.yaml`, and then, with
operator confirmation, syncs the published public attestor references into the
primary signer's local generation library. Unavailable or locked endpoints keep
their previous inventory. Authentication, malformed metadata, and duplicate
public-key routing errors fail without writing partial updates.

## Invariants

### A1: Role-Separated Messages

User-role and attestor-role signatures are over different messages for the
same target transaction.

```text
ComponentMessage(user, txid) != ComponentMessage(attestor, txid)
```

### A2: Direct Signing Rejects Attested Key Classes

`/sign` must reject attestor component key types and attested account key types.
They can sign only through `/sign/component` plus `/sign/assemble`.

```text
KeyType in AttestorComponentTypes union AttestedAccountTypes =>
  Reject(/sign, key_type)
```

### A3: User Component Sender Binding

User-role component signing for an attested account signs only target
transactions whose sender equals the requested attested account.

```text
Exists target: target.sender != component_key =>
  Reject(UserComponentSign)
```

### A4: Attestor Policy Before Key Load

Attestor-role component signing evaluates the effective attestor-domain `policy.yaml`
policy before loading the component private key.

```text
not AttestorPolicyAllowsAllTargets(snapshot, request) =>
  RejectBeforePrivateKeyLoad(request)
```

### A5: Component Selector Validates Key Class

An attestor component selector may load only a component key whose stored key
type, category, selector, and public/private key pair agree.

```text
LoadAttestorComponent(selector) succeeds =>
  key.category = component and
  key.selector = selector and
  key.public_private_pair_valid
```

### A6: Assembly Verifies User Signature Locally

Assembly accepts a user component signature only if it verifies against the user
public key stored in the local attested account key.

```text
not Verify(user_public_from_local_key, ComponentMessage(user, txid), user_sig)
  => Reject(Assemble)
```

### A7: Assembly Verifies Attestor Signature Against Embedded Key

Assembly accepts an attestor component signature only if it verifies against
the attestor public key stored in the local attested account key.

```text
not Verify(attestor_public_from_local_key,
           ComponentMessage(attestor, txid),
           attestor_sig) => Reject(Assemble)
```

### A8: Passthrough Bytes Remain Bound To Group Entry

Assembly preserves passthrough signed bytes only when their decoded transaction
ID equals the canonical unsigned group entry at the same index.

```text
TxID(DecodeSignedTxn(passthrough[i]).txn) != CanonicalGroup[i].txid =>
  Reject(Assemble)
```

### A9: Endpoint Mapping Is Routing, Not Trust

Endpoint `/keys` metadata can fail early for ergonomics, but it is not an
ownership proof. If an explicit endpoint mapping fails to advertise the
embedded attestor public key, the client errors and does not silently fall back
to self-discovery.

```text
ExplicitEndpoint(pubkey) exists and
not EndpointAdvertises(pubkey) =>
  RejectRoutingWithoutFallback
```

Security still comes from A7 and from on-chain LogicSig verification.

### A10: Client Verification Uses Shared Primitive

Any client-side attestor signature precheck derives the message through the
shared attestor verification package, not by reconstructing bytes ad hoc.

```text
ClientVerifyAttestorSig(target) uses ComponentMessage(attestor, target.txid)
```

### A11: Component Response Shape Is Exact

A component-sign response must contain exactly one signature for each requested
target, no unexpected target indices, no duplicate target indices, and the
expected signature scheme when the requester knows it.

```text
ResponseTargets != RequestedTargets or DuplicateTarget or WrongScheme =>
  Reject(Response)
```

### A12: Endpoint Sync Is Atomic Around Hard Failures

Attestor discovery may preserve stale inventory for unavailable or locked
endpoints, but authentication failures, malformed metadata, and duplicate
attestor public keys reject without writing partial routing updates.

```text
HardDiscoveryFailure => EndpointRegistryAfter = EndpointRegistryBefore
```

### A13: Node Role Gates Key Classes

Node role controls which key classes may be generated, imported, loaded, or
activated for a signer data root:

```text
role = signer   => reject attestor component private keys
role = attestor => reject spending/user signing keys and attested account keys
```

There is no `dual` role and no supported role-change transition. Conflicting
active key inventory fails closed for the whole node.

## Assumptions

This model assumes:

- canonical group decoding and txid computation match algod and SDK rules,
- cryptographic verification primitives are correct,
- stored attested account key metadata accurately describes its bytecode and
  embedded attestor key,
- endpoint tokens and host-key trust are handled by the connection layer,
- the on-chain LogicSig program enforces the same embedded attestor public key
  requirement that assembly checks locally.

## Code and Test Anchors

Implementation areas that should remain aligned with this model:

- `internal/attestor/message`
- `internal/attestor/verify`
- `internal/attestor/keytypes`
- `internal/signerapp/signing/component.go`
- `internal/signerapp/signing/component_sign.go`
- `internal/signerapp/signing/component_assemble.go`
- `internal/signerapp/signing/attestor_gate.go`
- `internal/engine/attested_submit.go`
- `internal/engine/attestor_endpoint.go`
- `internal/config/client_endpoints.go`
- `internal/apshellapp/endpoints.go`
- `internal/policy`
- `internal/signerapp/identity`
- `internal/signerapp/keyadmin`

High-value test anchors:

- role-separated message generation,
- direct `/sign` rejection for every attestor component and attested account
  key type,
- sender binding before user component key load,
- deterministic attestor-domain `policy.yaml` policy rejection before attestor key load,
- component selector/type/category/public-private validation,
- assembly rejection for wrong user signatures,
- assembly rejection for wrong attestor signatures,
- passthrough transaction-ID mismatch rejection,
- explicit endpoint mismatch rejection without self fallback,
- shared client-side attestor signature verification,
- malformed component response rejection,
- endpoint sync preserve/abort behavior,
- node role generation/import/reload/service-dispatch gates.

## Open Questions

These should be answered before a machine-checkable model:

1. Decide whether the first TLA+ attested model should abstract cryptographic
   verification as booleans or model signature roles as uninterpreted tokens.
2. Decide whether endpoint discovery belongs in the first attested module or
   should be a separate routing-state model joined later.
3. Decide whether to model node role in the attested module or in a separate
   durable-inventory/role model.
