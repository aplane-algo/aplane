# Formal Guarded Signing Model

> Status: precise English model, not machine-checked.
> This document formalizes the current guarded-account component-signing
> workflow: user component signing, sentry component signing, assembly, and
> client endpoint routing.
> Invariant status (implemented / intended / derived / etc.) is tracked in
> [FORMAL_TRACEABILITY.md](FORMAL_TRACEABILITY.md).

## Sources

Normative inputs:

- [ARCH_SENTRY.md](ARCH_SENTRY.md):
  sentry key types, guarded account key types, endpoint workflow,
  role-separated messages, assembly semantics, and endpoint routing trust
  model.
- [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md): `/keys`, `/sign/component`,
  `/sign/assemble`, endpoint registry, node role, `policy.yaml`,
  and on-disk selector contracts.
- [ARCH_POLICY.md](ARCH_POLICY.md): sentry-domain `policy.yaml`, sentry
  transfer policy, deterministic reject-only route-miss behavior, and
  Sentry Key ID overrides.
- [FORMAL_POLICY_MODEL.md](FORMAL_POLICY_MODEL.md): client-signing policy
  precedence. This model imports only the snapshot and overlay concepts; the
  sentry role has no manual-review or operator-default verdict.
- [FORMAL_SIGNING_AUTHORITY_MODEL.md](FORMAL_SIGNING_AUTHORITY_MODEL.md):
  stored key-file authority for existing keys.

This model does not replace [ARCH_SENTRY.md](ARCH_SENTRY.md).
It extracts the state, transition, and invariant surface that should remain
stable as the implementation evolves.

## Scope

This model covers the current MVP:

- guarded Falcon account keys whose LogicSig bytecode embeds one sentry
  public key,
- sentry keys selected by txid-shaped Sentry Key IDs,
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
- stored user-role public/private key material,
- stored sentry public key parameter,
- stored guarded account key type, which determines the sentry key family,
- stored signing metadata, bytecode, and runtime argument contract.

The current guarded account key types are
`aplane.falcon1024-sentry-falcon1024.v1` and `aplane.corridor.v1` (a Falcon
account whose program additionally restricts spends to a recipient corridor and
permits a sentry-authorized 0-ALGO self-pay rekey). Both share the
two-component-signature assembly modeled here; corridor's recipient-corridor and
rekey restrictions are LogicSig program semantics and sentry transfer/rekey
policy, out of scope per the TEAL/budget exclusion in Scope and the sentry
policy snapshot.

Signer inventory projects each guarded key with `signing_flow: sentry1` and
its `sentry_component_key_type`; clients route on that projection rather than
on the key-type string.

The sentry trust decision is made at key generation time by embedding the
chosen sentry public key into this key's LogicSig program and stored
parameters. Later endpoint routing does not move that trust anchor.

### Sentry Key

`SentryComponentKey` is a non-spending key with:

- key category `component`,
- key type `aplane.sentry-falcon1024.v1`,
- public/private sentry key material,
- Sentry Key ID derived as uppercase base32 SHA-512/256 of the
  domain-separated key type and canonical public key bytes.

The selector is a routing and policy handle. It is not an Algorand sender,
auth address, close target, rekey target, or account address.

### Component Message

For a canonical target transaction with `txid`, the component-signing message is:

```text
m = SHA512_256("APLANE_SENTRY_V1" || role_byte || txid)
```

`role_byte = 0x01` for the user role and `role_byte = 0x02` for the sentry
role. The same pure message/verification primitives must be used by all
signer services; clients do not verify component signatures (A10).

### Sentry Policy Snapshot

`SentryPolicySnapshot` is the verified effective sentry-domain `policy.yaml` snapshot
for one sentry identity. It contains transfer routing and sparse
`key_overrides` keyed by Sentry Key ID.

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

`apshell send` resolves each original sender through the auth-address cache and
consults the primary signer's key cache for the effective signer. Detection is
flow-driven: signer inventory labels each guarded key with
`signing_flow: sentry1` plus its `sentry_component_key_type`, and any
effective signer with a non-empty signing flow routes through guarded
orchestration, which then rejects flow labels other than `sentry1` before any
signing request (A15). The client does not classify key-type strings itself.
Mixed ordinary positions, direct guarded senders, and senders rekeyed to
guarded authorizers are supported: guarded positions become component-signing
targets, and ordinary signer-managed positions are signed later over the same
canonical group.

### Build Canonical Group

The client classifies original positions into guarded targets and non-guarded
originals, plans the transaction group, adds required dummy transactions for
LogicSig budget across every LogicSig position, fixes fees and group ID, and
encodes the canonical unsigned group bytes. Non-guarded positions are budgeted
by effective signer/AuthAddr, not by transaction sender alone. Component
signatures are always over target transaction IDs from this canonical group.

### User Component Sign

The client calls the primary signer:

```text
POST /sign/component role=user component_key=<guarded_account>
```

The signer loads `component_key` as a local guarded account key. The decoded
target sender may differ from `component_key`; authorizer binding is verified
during assembly. The signer signs the user-role component message with the user
component private key stored in that guarded account key.

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

### Sign Non-Guarded Originals

If the canonical group contains non-guarded original positions, the client
calls the primary signer `/sign` over the full canonical group. Non-guarded
originals are sign-mode entries, guarded target positions are `foreign` entries
with accurate `lsig_size` hints, and client-signed dummies are `foreign`
context entries. The signer returns signed bytes only for the non-guarded
positions and `""` for the foreign slots.

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
6. signs the canonical transaction with that LogicSig and verifies the decoded
   signed transaction is still the same txid and carries `AuthAddr` equal to the
   guarded account when the decoded sender differs,
7. returns signed group bytes, preserving passthrough bytes for signed
   non-guarded originals and client-signed dummies only if their decoded
   transaction ID matches the canonical group entry.

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

`/sign` must reject sentry key types and guarded account key types.
They can sign only through `/sign/component` plus `/sign/assemble`.

```text
KeyType in SentryComponentTypes union GuardedAccountTypes =>
  Reject(/sign, key_type)
```

### A3: User Component Key Binding

User-role component signing loads the requested `component_key` as a local
guarded account key before signing any user-role component message.

```text
not LoadGuardedAccount(component_key) =>
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

A Sentry Key ID may load only a sentry key whose stored key
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

### A10: Component Signatures Are Opaque To The Client

The client performs no cryptographic verification of component signatures.
It validates response shape (A11) and forwards signatures to assembly.
Rejection authority is signer assembly (A6, A7) and the on-chain LogicSig.
The client therefore must not link the signature verification primitives;
`cmd/apshell` is pinned to not compile `internal/sentry/verify` or the
Falcon implementation libraries.

```text
ClientHandles(signature) = collect + forward
not exists ClientVerify(signature)
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

### A14: Assembly Binds Guarded Account As Sender Or AuthAddr

Assembly returns a guarded target only when the decoded signed transaction still
matches the canonical target transaction ID, and when a non-guarded sender is
authorized by the guarded account through `AuthAddr`.

```text
TxID(AssembledSignedTxn.txn) != CanonicalGroup[target].txid =>
  Reject(Assemble)

CanonicalGroup[target].sender != guarded_account and
AssembledSignedTxn.AuthAddr != guarded_account =>
  Reject(Assemble)
```

### A15: Clients Route On Versioned Signing-Flow Metadata

The current guarded choreography is named `sentry1`: canonical TX-prefixed
transport, role-tagged component messages, one user plus one sentry component
signature per target, Sentry Key ID selectors, and assembly with
arg 0 = user / arg 1 = sentry. The label is frozen — any choreography change
mints a new label, and unrelated future mechanisms get their own label family.
Clients detect guarded sends from the `signing_flow` inventory field, treat
key-type and component-key-type strings as opaque, and fail fast on flow
labels they do not implement, before any component signing request is sent.

```text
SignerInventory(key).signing_flow == "" => PlainSignPath(key)
SignerInventory(key).signing_flow == "sentry1" => Sentry1Orchestration(key)
SignerInventory(key).signing_flow not in ClientFlows => Reject(Send)
```

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
- `internal/sentry/canonical`
- `internal/sentry/verify`
- `internal/sentry/keytypes`
- `internal/signerapp/signing/component.go`
- `internal/signerapp/signing/component_sign.go`
- `internal/signerapp/signing/component_assemble.go`
- `internal/signerapp/signing/sentry_gate.go`
- `internal/engine/guarded/submit.go`
- `internal/engine/guarded/discovery.go`
- `internal/config/client_endpoints.go`
- `internal/apshellapp/endpoints.go`
- `internal/policy`
- `internal/signerapp/identity`
- `internal/signerapp/keyadmin`

High-value test anchors:

- role-separated message generation,
- direct `/sign` rejection for every sentry and guarded account
  key type,
- sender binding before user-role key load,
- deterministic sentry-domain `policy.yaml` policy rejection before sentry key load,
- Sentry Key ID/type/category/public-private validation,
- assembly rejection for wrong user signatures,
- assembly rejection for wrong sentry signatures,
- passthrough transaction-ID mismatch rejection,
- explicit endpoint mismatch rejection without self fallback,
- client binaries excluding signature verification primitives,
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
