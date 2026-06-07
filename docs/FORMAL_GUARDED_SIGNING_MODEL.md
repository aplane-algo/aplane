# Formal Guarded Signing Model

> Status: precise English model, not machine-checked.
> This document formalizes the current guarded-account component-signing
> workflow: user component signing, sentry component signing, assembly, and
> client endpoint routing.
> Invariant status (implemented / intended / derived / etc.) is tracked in
> [FORMAL_TRACEABILITY.md](FORMAL_TRACEABILITY.md).

## Sources

Normative inputs:

- [ARCH_SPEC.md#guarded-signing-and-sentry-nodes](ARCH_SPEC.md#guarded-signing-and-sentry-nodes):
  sentry component key types, guarded account key types, endpoint workflow,
  role-separated messages, assembly semantics, and endpoint routing trust
  model.
- [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md): `/keys`, `/sign/component`,
  `/sign/assemble`, endpoint registry, node role, `policy.yaml`,
  and on-disk selector contracts.
- [ARCH_POLICY.md](ARCH_POLICY.md): sentry-domain `policy.yaml`, sentry component
  transfer policy, deterministic reject-only route-miss behavior, and
  component-key overrides.
- [FORMAL_POLICY_MODEL.md](FORMAL_POLICY_MODEL.md): client-signing policy
  precedence. This model imports only the snapshot and overlay concepts; the
  sentry role has no manual-review or operator-default verdict.
- [FORMAL_SIGNING_AUTHORITY_MODEL.md](FORMAL_SIGNING_AUTHORITY_MODEL.md):
  stored key-file authority for existing keys.

This model does not replace
[ARCH_SPEC.md#guarded-signing-and-sentry-nodes](ARCH_SPEC.md#guarded-signing-and-sentry-nodes).
It extracts the state, transition, and invariant surface that should remain
stable as the implementation evolves.

## Scope

This model covers the current MVP:

- guarded Falcon account keys whose LogicSig bytecode embeds one sentry
  public key,
- sentry component keys selected by txid-shaped component selectors,
- `/sign/component` for user-role and sentry-role component signatures,
- `/sign/assemble` verification and LogicSig argument packing,
- `apshell send` orchestration for guarded account senders,
- client endpoint discovery and sync for sentry routing,
- node role gates for signer nodes and sentry nodes.

It does not model:

- cryptographic algorithm security,
- TEAL opcode semantics or LogicSig budget internals,
- account registration or account-binding databases,
- trust in endpoint metadata as a security control,
- SSH host-key or token issuance state machines,
- operator behavior or manual approval for sentry component requests.

## Abstract Objects

### Guarded Account Key

`GuardedAccountKey` is a DSA-backed LogicSig key file for an account whose
program requires two component signatures. The model observes:

- account address derived from stored LogicSig bytecode,
- stored user public/private component key material,
- stored sentry public key parameter,
- stored guarded account key type, which determines the sentry component
  key family,
- stored signing metadata, bytecode, and runtime argument contract.

The sentry trust decision is made at key generation time by embedding the
chosen sentry public key into this key's LogicSig program and stored
parameters. Later endpoint routing does not move that trust anchor.

### Sentry Component Key

`SentryComponentKey` is a non-spending key with:

- key category `component`,
- key type `aplane.sentry-ed25519.v1` or
  `aplane.sentry-falcon1024.v1`,
- public/private component key material,
- selector derived as uppercase base32 SHA-512/256 of the domain-separated key
  type and canonical public key bytes.

The selector is a routing and policy handle. It is not an Algorand sender,
auth address, close target, rekey target, or account address.

### Component Message

For a canonical target transaction with `txid`, the component-signing message is:

```text
m = SHA512_256("APLANE_SENTRY_V1" || role_byte || txid)
```

`role_byte = 0x01` for the user role and `role_byte = 0x02` for the sentry
role. The same pure message/verification primitives must be used by signer
services and optional client-side verification.

### Sentry Policy Snapshot

`SentryPolicySnapshot` is the verified effective sentry-domain `policy.yaml` snapshot
for one sentry identity. It contains transfer routing and sparse
`key_overrides` keyed by component selector.

Unlike client-signing policy, sentry policy has no manual-review verdict and
no operator default. If no positive transfer route authorizes every target
transaction, the request rejects.

### Endpoint Registry

`EndpointRegistry` is client-local routing state in `endpoints.yaml`.

An endpoint can be role `signer` or `sentry`. A client has one primary signer
endpoint and zero or more sentry endpoints. Sentry endpoint inventory may
publish public sentry keys and selectors. That inventory is routing metadata
only; it is not proof that the endpoint owns any private key.

## Transitions

### Detect Guarded Send

`apshell send` consults the primary signer's key cache. If any sender is an
guarded account key type, the client uses the guarded orchestration path.
The current MVP rejects mixed ordinary and guarded original senders in one
group.

### Build Canonical Group

The client plans the transaction group, adds required dummy transactions for
LogicSig budget, fixes fees and group ID, and encodes the canonical unsigned
group bytes. Component signatures are always over target transaction IDs from
this canonical group.

### User Component Sign

The client calls the primary signer:

```text
POST /sign/component role=user component_key=<guarded_account>
```

The signer loads the local guarded account key only if every requested target
sender equals `component_key`. It signs the user-role component message with
the user component private key stored in that guarded account key.

### Sentry Component Sign

For each distinct embedded sentry public key, the client resolves a sentry
endpoint and calls:

```text
POST /sign/component role=sentry component_key=<component_selector>
```

The sentry signer evaluates the sentry-domain `policy.yaml` transfer policy for every
target transaction before loading the component private key. The request is
accepted only when the effective sentry policy authorizes all target
transactions.

### Assemble

The client returns to the primary signer:

```text
POST /sign/assemble
```

For each target, the primary signer loads its local guarded account key and:

1. verifies `user_signature` against the user public key stored in that local
   key,
2. verifies `sentry_signature` against the sentry public key embedded in
   that local key,
3. packs both signatures according to the guarded account key type,
4. builds LogicSig args from stored signing metadata,
5. verifies the resulting LogicSig address equals the guarded account,
6. returns signed group bytes, preserving passthrough bytes only if their
   decoded transaction ID matches the canonical group entry.

The assembling signer trusts values it stored at generation time. It does not
trust endpoint metadata supplied during the transaction flow.

### Discover And Sync Sentries

`endpoints sync-sentries` queries reachable sentry endpoints with valid
tokens, refreshes their published inventory in `endpoints.yaml`, and then, with
operator confirmation, syncs the published public sentry references into the
primary signer's local generation library. Unavailable or locked endpoints keep
their previous inventory. Authentication, malformed metadata, and duplicate
public-key routing errors fail without writing partial updates.

## Invariants

### A1: Role-Separated Messages

User-role and sentry-role signatures are over different messages for the
same target transaction.

```text
ComponentMessage(user, txid) != ComponentMessage(sentry, txid)
```

### A2: Direct Signing Rejects Guarded Key Classes

`/sign` must reject sentry component key types and guarded account key types.
They can sign only through `/sign/component` plus `/sign/assemble`.

```text
KeyType in SentryComponentTypes union GuardedAccountTypes =>
  Reject(/sign, key_type)
```

### A3: User Component Sender Binding

User-role component signing for a guarded account signs only target
transactions whose sender equals the requested guarded account.

```text
Exists target: target.sender != component_key =>
  Reject(UserComponentSign)
```

### A4: Sentry Policy Before Key Load

Sentry-role component signing evaluates the effective sentry-domain `policy.yaml`
policy before loading the component private key.

```text
not SentryPolicyAllowsAllTargets(snapshot, request) =>
  RejectBeforePrivateKeyLoad(request)
```

### A5: Component Selector Validates Key Class

A sentry component selector may load only a component key whose stored key
type, category, selector, and public/private key pair agree.

```text
LoadSentryComponent(selector) succeeds =>
  key.category = component and
  key.selector = selector and
  key.public_private_pair_valid
```

### A6: Assembly Verifies User Signature Locally

Assembly accepts a user component signature only if it verifies against the user
public key stored in the local guarded account key.

```text
not Verify(user_public_from_local_key, ComponentMessage(user, txid), user_sig)
  => Reject(Assemble)
```

### A7: Assembly Verifies Sentry Signature Against Embedded Key

Assembly accepts a sentry component signature only if it verifies against
the sentry public key stored in the local guarded account key.

```text
not Verify(sentry_public_from_local_key,
           ComponentMessage(sentry, txid),
           sentry_sig) => Reject(Assemble)
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
embedded sentry public key, the client errors and does not silently fall back
to self-discovery.

```text
ExplicitEndpoint(pubkey) exists and
not EndpointAdvertises(pubkey) =>
  RejectRoutingWithoutFallback
```

Security still comes from A7 and from on-chain LogicSig verification.

### A10: Client Verification Uses Shared Primitive

Any client-side sentry signature precheck derives the message through the
shared sentry verification package, not by reconstructing bytes ad hoc.

```text
ClientVerifySentrySig(target) uses ComponentMessage(sentry, target.txid)
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

Sentry discovery may preserve stale inventory for unavailable or locked
endpoints, but authentication failures, malformed metadata, and duplicate
sentry public keys reject without writing partial routing updates.

```text
HardDiscoveryFailure => EndpointRegistryAfter = EndpointRegistryBefore
```

### A13: Node Role Gates Key Classes

Node role controls which key classes may be generated, imported, loaded, or
activated for a signer data root:

```text
role = signer   => reject sentry component private keys
role = sentry => reject spending/user signing keys and guarded account keys
```

There is no `dual` role and no supported role-change transition. Conflicting
active key inventory fails closed for the whole node.

## Assumptions

This model assumes:

- canonical group decoding and txid computation match algod and SDK rules,
- cryptographic verification primitives are correct,
- stored guarded account key metadata accurately describes its bytecode and
  embedded sentry key,
- endpoint tokens and host-key trust are handled by the connection layer,
- the on-chain LogicSig program enforces the same embedded sentry public key
  requirement that assembly checks locally.

## Code and Test Anchors

Implementation areas that should remain aligned with this model:

- `internal/sentry/message`
- `internal/sentry/verify`
- `internal/sentry/keytypes`
- `internal/signerapp/signing/component.go`
- `internal/signerapp/signing/component_sign.go`
- `internal/signerapp/signing/component_assemble.go`
- `internal/signerapp/signing/attestor_gate.go`
- `internal/engine/guarded_submit.go`
- `internal/engine/attestor_endpoint.go`
- `internal/config/client_endpoints.go`
- `internal/apshellapp/endpoints.go`
- `internal/policy`
- `internal/signerapp/identity`
- `internal/signerapp/keyadmin`

High-value test anchors:

- role-separated message generation,
- direct `/sign` rejection for every sentry component and guarded account
  key type,
- sender binding before user component key load,
- deterministic sentry-domain `policy.yaml` policy rejection before sentry key load,
- component selector/type/category/public-private validation,
- assembly rejection for wrong user signatures,
- assembly rejection for wrong sentry signatures,
- passthrough transaction-ID mismatch rejection,
- explicit endpoint mismatch rejection without self fallback,
- shared client-side sentry signature verification,
- malformed component response rejection,
- endpoint sync preserve/abort behavior,
- node role generation/import/reload/service-dispatch gates.

## Open Questions

These should be answered before a machine-checkable model:

1. Decide whether the first TLA+ guarded model should abstract cryptographic
   verification as booleans or model signature roles as uninterpreted tokens.
2. Decide whether endpoint discovery belongs in the first guarded module or
   should be a separate routing-state model joined later.
3. Decide whether to model node role in the guarded module or in a separate
   durable-inventory/role model.
