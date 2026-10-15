# Key Types

> Key types and LogicSig providers: the dimensions that describe one signing
> authority, the canonical key type identifier, the authorization ontology, the
> three resolution axes, and the LogicSig provider registry, templates, and
> derivation.

This document explains how APlane composes key types, account-authorization
forms, LogicSig policy contracts, auxiliary authorities, signing flows, and
provider implementations. It also explains how the codebase answers questions
about a key type, and **why** there are three separate resolution mechanisms
rather than one. Read this before changing their boundaries (see
[Why not collapse them](#why-not-collapse-them)).

The [LogicSig providers](#logicsig-providers) section is the detailed registry
reference for one of the three axes (Resolve).

## Contents

- [Protocol dimensions and terminology](#protocol-dimensions-and-terminology)
- [Key type identifier contract](#key-type-identifier-contract)
- [Authorization object ontology](#authorization-object-ontology)
- [Key types summary](#key-types-summary)
- [The three axes](#the-three-axes)
- [LogicSig providers](#logicsig-providers)
- [See also](#see-also)

## Protocol dimensions and terminology

APlane uses several independently versioned dimensions to describe one signing
authority. They answer different questions and must not be inferred from one
another merely because two dimensions currently use the same string.

| Dimension | Question it answers | Examples | Source of truth |
|---|---|---|---|
| **Key type** | What durable kind of account or witness key is this? | `ed25519`, `aplane.falcon1024.v1`, `aplane.corridor.v1` | Stored `key_type`; provider/template definition |
| **Account authorization type** | What protocol-level mechanism authorizes the account? | native signature, DSA LogicSig, generic LogicSig | Key category and stored key material |
| **Authorization contract** | Which reusable, versioned on-chain envelope and metadata vocabulary constrain this LogicSig? | `bounded1` | Template `bounded.contract` and durable `bounded_authorization.contract` |
| **Policy/profile** | What concrete behavior narrows the account contract? | fixed allowlist, Merkle recipient proof, timelock, Corridor composition | Full key-type provider/template plus behavior parameters |
| **Base key type** | Which private signing primitive produces the account's DSA signature arguments? | `aplane.falcon1024.v1`, `aplane.ed25519.v1` | Stored `base_key_type` and composed provider definition |
| **Auxiliary authority enrollment** | Which additional authority participates, for which role or operation, and under whose custody? | cosigner witness, external contract-admin witness | Embedded public key, durable metadata, and custody-specific message contract |
| **Signing flow** | Which versioned client/server protocol obtains a usable signature for this key? | empty ordinary flow, `bounded1`, `cosigner1`, `bounded-cosigner1` | Signer-advertised `signing_flow` |
| **Endpoint choreography** | Which ordered calls implement the selected flow for this transaction path? | `/sign`; `/sign/component` then `/sign/assemble`; `/sign/bounded-admin` then `aprekey` | Flow contract, transaction classification, and HTTP DTOs |
| **Provider and routing family** | Which registered implementation performs keygen, derivation, signing, or assembly? | composed provider routed through `aplane.falcon1024`; dedicated guarded provider | Provider registry and `RoutingFamily()` |
| **Principal authorization** | May the authenticated caller invoke this operation on the target identity/resource? | `sign.request`, `sign.component`, `sign.assemble` | Reserved product principal, closed action allowlist, and HTTP/admin enforcement point |
| **Signer policy domain** | Which off-chain rules gate release of a signature that the key and on-chain program could produce? | client-signing policy, cosigner policy | Node role, the node's policy documents, and the selected policy key |
| **Network context** | Which configured network and network-scoped policy apply to the transaction? | `mainnet`, `voi_mainnet`, `localnet` | Transaction `GenesisHash` resolved to a network context token |

The terms are related, but none is a synonym for another:

- A **key type** is the stable, user-visible and durable identity of a key
  definition. It fixes the provider/template behavior that created the key.
- An **authorization contract** is a reusable versioned contract used by one or
  more key types. `bounded1` is currently the only bounded-authorization
  contract. Many key types may instantiate it with different profiles and
  behavior parameters.
- A **profile** is the concrete policy compiled for a key type or key instance.
  A bounded profile cannot widen the bounded envelope; a dedicated compiled
  policy owns its complete program outside that reusable bounded contract.
- An **auxiliary authority** is not automatically an account key or a policy.
  Its enrollment names a role, message domain, custody boundary, and the paths
  on which its signature is required.
- A **signing flow** is a wire-routing capability, not an on-chain program.
  Clients select it from inventory and must fail closed on unknown values.
- An **endpoint choreography** is the transaction-path-specific sequence inside
  a flow. One key-level flow can have more than one path: a bounded spend uses
  ordinary `/sign`, while an admin-key rekey uses `/sign/bounded-admin` and
  external completion.
- A **provider** is an implementation mechanism. Changing registry ownership or
  routing does not by itself change a key type, authorization contract, or
  signing flow, although behavior-visible changes may require versioning those
  contracts.

The word **contract** has three related but distinct uses in APlane:

- An **authorization contract**, such as `bounded1`, is an on-chain LogicSig
  behavior and its canonical durable metadata vocabulary.
- A **wire or storage contract** is a compatibility-bearing DTO, file shape, or
  behavioral guarantee, indexed in `ARCH_CONTRACTS.md`.
- A **message or transcript contract** is an exact cryptographic encoding and
  domain, such as `APLANE_COSIGNER_V1` or `APLANE_BOUNDED_ADMIN_AUTH_V1`.

Likewise, account authorization is distinct from principal authorization and
signer policy. The account key and LogicSig determine what can authorize the
Algorand account; the fixed product principal and closed action allowlist
determine whether the caller may invoke an APlane endpoint; signer or cosigner
policy determines whether that permitted call may release a signature for the
particular transaction.

`bounded1` is always the bounded authorization-contract identifier and is also
the signing-flow label for bounded profiles that need no online cosigner. A
cosigner-enabled bounded profile keeps `contract: bounded1` but advertises the
distinct `bounded-cosigner1` choreography. The contract identifier selects
canonical on-chain and durable metadata semantics; the flow label tells the
client how to route a request. Likewise, `cosigner1` is a signing-flow label and
an embedded bounded cosigner contract value, while `APLANE_COSIGNER_V1` is the
cryptographic component-message domain used by that flow. Neither is a key
type.

### How the dimensions compose

For a generated account key, the relationship is:

```text
full key_type
  -> account authorization type
  -> provider/template and optional base_key_type
  -> optional reusable authorization contract and concrete profile
  -> optional auxiliary authority enrollments
  -> rendered bytecode + durable instance signing metadata
  -> inventory signing_flow and size/routing metadata
  -> client endpoint choreography for the classified transaction path
  -> authentication + principal authorization + signer policy gates
  -> signature release and final on-chain program enforcement
```

The full `key_type` remains the durable account identity throughout this chain.
The stored bytecode and versioned signing metadata, not the currently installed
template, are authoritative for signing an existing LogicSig key. Inventory is
a projection of that authority for clients; it does not replace the key file or
the on-chain program.

Runtime selection follows these rules:

1. The effective signer or `AuthAddr` selects the account key instance.
2. Its full `key_type` and durable metadata select account behavior and the
   implementation needed by the signer.
3. Signer inventory projects a `signing_flow`; the client routes on that field,
   not on key-type naming conventions, `base_key_type`, or provider family.
4. Transaction classification may choose a path-specific choreography inside
   the flow, such as bounded spend versus external-admin rekey.
5. HTTP principal authorization decides whether the caller may invoke the
   endpoint. Signer or cosigner policy independently decides whether the specific
   transaction may receive a signature.
6. Assembly verifies signatures, argument placement, canonical transaction
   bytes, and the effective authorizer. The LogicSig program remains the final
   on-chain authority.

An auxiliary-authority overlay may be combined with a policy form only when an
explicit account contract, durable metadata shape, and signing flow define the
combination. The combination must not be inferred from a key-type substring or
from the presence of a witness key alone.

### Worked compositions

| Key type | Account authorization | Contract/profile | Base primitive | Auxiliary authority | Advertised flow and choreography |
|---|---|---|---|---|---|
| `ed25519` | Native | none | Ed25519, self-owned | none | empty flow; `/sign` |
| `falcon1024` | Native PQ | none | protocol Falcon-1024 scheme `f1`, self-owned | none | empty flow; `/sign`; consensus v42+; top-level `PQsig` |
| `aplane.falcon1024.v1` | DSA LogicSig | plain DSA | Falcon-1024, self-owned | none | empty flow; `/sign` |
| `aplane.falcon1024-allowlist.v1` | DSA LogicSig | bounded `bounded1`; fixed recipient allowlist | `aplane.falcon1024.v1` | none | `bounded1`; spend/rekey through `/sign` as permitted by the profile |
| `aplane.falcon1024-allowlist-alock.v1` | DSA LogicSig | bounded `bounded1`; fixed recipient/asset/amount allowlist | `aplane.falcon1024.v1` | external Falcon contract admin for rekey | `bounded1`; spend through `/sign`, admin rekey through `/sign/bounded-admin` plus `aprekey` |
| `aplane.falcon1024-cosigner1024.v1` | DSA LogicSig | dedicated guarded verifier | `aplane.falcon1024.v1` | signer-custodied Falcon cosigner witness | `cosigner1`; user `/sign/component`, cosigner `/sign/component`, then `/sign/assemble` |
| `aplane.corridor.v1` | DSA LogicSig | bounded `bounded1`; framework Merkle recipient allowlist | `aplane.falcon1024.v1` | signer-custodied Falcon cosigner on spend; distinct external Falcon admin on rekey | `bounded-cosigner1`; `/plan`, kind-tagged `/sign/component`, then `/sign/assemble` |
| `aplane.htlc.v1` | Generic LogicSig | generic TEAL HTLC policy | none | none | empty flow; ordinary LogicSig assembly through `/sign` |

The examples describe the currently implemented architecture. A future change
that composes dimensions differently must update the relevant contract and flow
rather than silently teaching clients to infer a new combination.

### Independent version boundaries

Version the dimension whose compatibility contract changes:

| Change | Version boundary |
|---|---|
| Concrete program behavior or key-definition semantics | New `key_type` version |
| Bounded envelope, canonical profile, argument-source vocabulary, or admin transcript | New bounded authorization contract, such as `bounded2`, and affected key types |
| Client/server component ordering, required endpoints, or assembly DTO semantics | New `signing_flow` label |
| Cryptographic message shape | New message-domain version and every program/flow that verifies it |
| Template syntax without changing an existing key's durable behavior | Template schema version |
| Durable key signing metadata shape | `signing_metadata_version` |
| HTTP or SDK payload shape | Versioned endpoint/DTO contract according to `ARCH_SIGNING.md` |

These versions may advance independently. A key type version must still pin the
complete behavior it relies on, and compatibility-bearing changes commonly
require advancing more than one dimension together.

## Key type identifier contract

Every protocol, config, key file, template, and key type state field named
`key_type` carries the canonical identifier, not a presentation label.

Canonical forms:

- native Ed25519 is the single-segment built-in `ed25519`
- native Falcon-1024 is the single-segment built-in `falcon1024`. It is a
  protocol-native post-quantum account and is distinct from every
  `aplane.falcon1024.*` LogicSig key type
- APlane-defined LogicSig, template, and compiled-provider key types use
  `publisher.family.vN`, where `vN` is a literal `v` followed by a positive
  decimal version, for example `aplane.falcon1024.v1`,
  `aplane.htlc.v1`, `aplane.falcon1024-allowlist.v1`, and
  `aplane.falcon1024-allowlist-alock.v1`
- witness keys use the same canonical key-type identifier contract,
  currently `aplane.witness-falcon1024.v1`; signer-custodied instances serve
  as cosigner component-signing keys selected by 52-character txid-shaped
  Witness Key IDs, not spending accounts. The
  compatibility wire/storage field name for that selector remains
  `component_key`.
- external bounded contract-admin authorities use the same witness key type
  and Witness Key ID, but private material remains in a structurally distinct
  standalone `.wit` container owned by `aprekey`. It is never a signer-managed
  `.key`/`.cos` credential or spending account.
- `aplane.falcon1024-allowlist-alock.v1` is reserved for the schema-v2
  framework-owned bounded1 allowlist. Its spending key and contract admin key
  are both Falcon-1024. Bounded1 has no Ed25519 contract-admin variant and no
  admin-key algorithm selector.
- the dedicated guarded account key type
  `aplane.falcon1024-cosigner1024.v1` names both its account DSA and cosigner DSA.
  `aplane.corridor.v1` is instead an optional schema-v2 composed template: its
  durable `bounded_authorization` metadata declares `bounded1`, a `cosigner1`
  spend gate, and the framework Merkle allowlist policy. Clients must not infer
  those dimensions from the key-type string.

YAML templates declare `publisher`, `family`, and integer `version`; the
computed key type is `publisher.family.v<version>`. Clients and tools must send
and persist the full canonical identifier in `key_type` fields. Human-facing
CLI/TUI input and display use the same canonical identifier; publisher
namespaces are not inferred or elided.

Terminology:

- `family` is the middle segment of `publisher.family.vN`. It groups versions
  of one key type or template policy, for example
  `aplane.falcon1024-allowlist.v1` and `aplane.falcon1024-allowlist.v2`.
- `base_key_type` is the field composed DSA templates use to point at their
  private signing primitive. For example,
  `base_key_type: aplane.falcon1024.v1` means the template's DSA signature is
  produced and packed with Falcon-1024, while the account/template identity is
  still named by its own `key_type` and `family` segment (e.g.
  `family: falcon1024-allowlist`).
- `base_key_type` is not a universal owner or routing key. Account semantics,
  creation parameters, TEAL bytecode, metadata, and guarded assembly remain
  owned by the full `key_type` unless a specific contract says otherwise.
  Guarded account key types are the important example: their signing primitive
  is Falcon-1024, but their account semantics and cosigner assembly are guarded
  account semantics.
- `RoutingFamily()` on Go provider types is the registry routing key (see
  [Resolve](#resolve--key-type--implementation)), and `Family` / `FamilyName`
  registration fields are registry/display metadata. The family-keyed registry
  fallback is an implementation detail, not a replacement for canonical
  `key_type` identity.

## Authorization object ontology

The resolution mechanisms below are separate from the security ontology. The
ontology first identifies what authorizes an account, then any LogicSig policy
form, and finally any additional authority. These dimensions must not be
collapsed into one flat key-type hierarchy.

### Account authorization types

| Type | Account authority | Signer representation |
|---|---|---|
| **Native** | A protocol-native account signature: Algorand Ed25519 (`ed25519`) or native Falcon-1024 (`falcon1024`, consensus v42+). | Encrypted signer `.key` with native private material. |
| **DSA LogicSig** | A LogicSig verifies one or more digital signatures and may enforce additional transaction policy. | Encrypted signer `.key` with DSA private material, compiled bytecode, and signing metadata. |
| **Generic LogicSig** | TEAL predicates alone authorize the account; there is no DSA private key. | Encrypted signer `.key` containing final bytecode, parameters, derivation metadata, and signing metadata but no private signing material. |

An account authorization type identifies the account-level mechanism. It does
not by itself say whether the account is guarded or which transaction effects a
LogicSig admits.

### DSA LogicSig policy forms

The schema-v2 composed-DSA contract uses **bounded DSA** for DSA-backed LogicSigs
whose admitted transaction effects, maximum fee, argument layout, and optional
contract-admin operations are represented by canonical signer metadata and
enforced in both planning and TEAL. Its machine names are `bounded` and
`bounded1`.

DSA LogicSig policy categories are:

- **Plain DSA**: only the DSA verification program, with no composed policy.
- **Bounded DSA**: schema-v2 composed policy with a closed framework-enforced
  effect and argument contract.
- **Custom DSA policy**: schema-v1 composed policy authored directly as TEAL.
- **Dedicated compiled policy**: provider-owned LogicSig policy outside the
  composed-template schema, such as the legacy
  `aplane.falcon1024-cosigner1024.v1` guarded verifier.

Schema-v1 custom policy remains a fully supported expert mode. "Expert" is a
documentation description, not a feature gate, warning requirement, or reduced
execution mode. Generic LogicSig templates are a separate category. Guarded
signing is an orthogonal authority axis and may be combined with a DSA account
model without becoming a policy category itself.

### Auxiliary authority types

Auxiliary authority keys do not independently authorize an Algorand account.
They participate in a specific account or operation contract:

| Type | Custody and use | Signer key type? |
|---|---|---|
| **Witness key, cosigner enrollment** | Stored as a cosigner-managed `.cos` credential and used through `/sign/component`; its signature is assembled into a guarded-account LogicSig. | Yes. `aplane.witness-falcon1024.v1`, durable category `witness`; never accepted as a spending account by ordinary `/sign`. |
| **Witness key, contract-admin enrollment** | Stored in a standalone encrypted `.wit` artifact and used only for a declared bounded admin operation through `aprekey`. | The key form has the same witness key type, but this custody container is never an `apstore` or signer key. |

The current authority overlays are therefore **unguarded**, **cosigner guarded**,
and **contract-admin-authorized operation**. Contract-admin authority is
operation-specific: the spending key still authenticates every bounded path,
and the external admin key currently authorizes only a pure rekey.

Witness **form**, **custody**, and **enrollment** are separate dimensions. The
key record carries no role field: the program that embeds the public key names
the role, and the custodian controls which message domain can be signed. A
networked signer may produce only `APLANE_COSIGNER_V1` component-domain
signatures; the offline ceremony may produce only
`APLANE_BOUNDED_ADMIN_AUTH_V1` signatures. One witness keypair should serve one
role for its entire life. The software rejects collisions visible in local
stores and cosigner references, but cannot detect out-of-band key copying.

Examples of the composed ontology:

| Key type | Account authorization | Policy form | Additional authority |
|---|---|---|---|
| `ed25519` | Native | n/a | none |
| `aplane.falcon1024.v1` | DSA LogicSig | Plain DSA | none |
| `aplane.falcon1024-allowlist.v1` | DSA LogicSig | Bounded DSA (`bounded1`) | none |
| `aplane.falcon1024-allowlist-alock.v1` | DSA LogicSig | Bounded DSA (`bounded1`) | external Falcon witness enrolled as contract admin for rekey |
| `aplane.falcon1024-cosigner1024.v1` | DSA LogicSig | dedicated compiled guarded verifier | signer-custodied Falcon witness enrolled as cosigner |
| `aplane.corridor.v1` | DSA LogicSig | Bounded DSA (`bounded1`) with framework Merkle policy | signer-custodied Falcon cosigner on spend plus external Falcon contract admin on rekey |
| `aplane.htlc.v1` | Generic LogicSig | generic TEAL policy | none |
| `aplane.rotating-hybrid.v1` | DSA LogicSig (`rotating_lsig`) | dedicated compiled stage program (Falcon-1024 and Ed25519, both required), a new program per spend | none; the signer reads the chain for the live stage (`rotating1` flow) |
| `aplane.rotating-wots-hybrid.v1` | DSA LogicSig (`rotating_lsig`) | dedicated compiled stage program (hash-based WOTS-w16 and Ed25519, both required), a new program per spend | none; same `rotating1` flow |

## Key types summary

| Key Type | Key-type family | Category | Description |
|----------|--------|----------|-------------|
| `ed25519` | n/a | `ed25519` | Native Algorand Ed25519 account; not a LogicSig |
| `falcon1024` | n/a | `native_pq` | Native protocol Falcon-1024 account (scheme `f1`, consensus v42+); not a LogicSig |
| `aplane.falcon1024.v1` | `aplane.falcon1024` | `dsa_lsig` | Default-enabled pure Falcon signature |
| `aplane.falcon1024-cosigner1024.v1` | `aplane.falcon1024-cosigner1024` | `dsa_lsig` | Library-visible guarded account: Falcon-1024 user + Falcon-1024 cosigner component signatures |
| `aplane.falcon1024-allowlist-alock.v1` | `falcon1024-allowlist-alock` | `dsa_lsig` | Optional bounded1 composed template: Falcon spending, fixed recipient/asset/amount allowlist, external Falcon contract-admin rekey |
| `aplane.corridor.v1` | `corridor` | `dsa_lsig` | Optional bounded1 composed template: Falcon spending, framework Merkle recipient policy, cosigner-gated spend, and external-admin pure rekey |
| `aplane.ed25519.v1` | `aplane.ed25519` | `dsa_lsig` | Library-visible Ed25519 LogicSig DSA provider; distinct from native `ed25519` |
| `aplane.htlc.v1` | `htlc` | `generic_lsig` | Optional template library: hash-locked payment |
| `aplane.falcon1024-allowlist.v1` | `falcon1024-allowlist` | `dsa_lsig` | Bundled bounded1 composed template: installed/enabled in new signer-role stores; Falcon + fixed receiver allowlist |
| `aplane.falcon1024-allowlist.v2` | `falcon1024-allowlist` | `dsa_lsig` | Optional bounded1 composed template: Falcon + signer-derived Merkle receiver proof |
| `aplane.falcon1024-timelock.v1` | `falcon1024-timelock` | `dsa_lsig` | Optional bounded1 composed template: Falcon + validity-round gate on spend and rekey |
| `aplane.rotating-hybrid.v1` | `aplane.rotating-hybrid` | `rotating_lsig` | Library-visible rotating account: Falcon-1024 + Ed25519 stage program, `rotating1` flow; signer-side only (no client provider) |
| `aplane.rotating-wots-hybrid.v1` | `aplane.rotating-wots-hybrid` | `rotating_lsig` | Library-visible rotating account: WOTS-w16 + Ed25519 stage program, `rotating1` flow; signer-side only (no client provider) |

## The three axes

A "key type" (e.g. `aplane.falcon1024.v1`, `aplane.corridor.v1`,
`aplane.falcon1024-cosigner1024.v1`) is asked three different *kinds* of
question, and each kind uses a different mechanism because each is callable from
a different place.

| Axis | Question it answers | Mechanism | Owner package(s) |
|---|---|---|---|
| **Resolve** | key type → its implementation | family-keyed registries + a `RoutingFamily` resolver | `internal/lsigprovider`, `internal/logicsigdsa` |
| **Classify** | key type → category facts (is it a guarded account? which witness form? what key size?) | string switches in neutral leaf packages | `internal/cosigner/keytypes`, `internal/witness`, `internal/rotatingkey` |
| **Behave** | do the operation (pack signatures, build assembly args, derive, sign) | provider-capability interfaces, queried from the resolved provider | `internal/signerapp/signing`, `internal/lsigprovider`, `internal/logicsigdsa` |

**The governing rule:** *do not unify mechanisms across axes that have different
call-site availability.* Resolve needs the registry; Classify must work with no
registry at all; Behave needs a concrete provider instance in hand. Those are
different runtime conditions, so they need different mechanisms — collapsing them
forces a call site to depend on something it does not have.

### Resolve — key type → implementation

**Mechanism:** registries keyed by *routing family*, plus the `RoutingFamily`
resolver and the shared `ResolveByKeyType` two-step lookup.

- `internal/lsigprovider/registry.go` — `RoutingFamily(keyType)` looks up the
  registered provider and returns `provider.RoutingFamily()`; for an unregistered
  key type it returns the normalized input.
- `internal/logicsigdsa/registry.go` — `ResolveByKeyType[T]` is the shared
  pattern used by the family-keyed registries: try an **exact key-type** match
  first (native + per-key-type registrations), then fall back to the key type's
  **routing family**.
- `internal/logicsigdsa/dsa.go` — the `LogicSigDSA` contract and package doc.

**Routing key = `RoutingFamily()`, not `BaseKeyType`.** A provider's
`RoutingFamily()` is its declared routing family — the registry key. For a
self-handling DSA that is its own family; for a composed template that delegates
to a base it is the *base's* family (e.g. `aplane.falcon1024-allowlist.v1` →
`aplane.falcon1024`). That base is a **registration fact**, not something
derivable from the key-type string, and it is deliberately not the same as the
key type's own display label.

> The routing method is named `RoutingFamily()` precisely so it is not confused
> with the other uses of the word "family": the key-type display segment and the
> YAML `family:` / wire `family` fields all carry a *different* value (the key
> type's own label, not its routing key). The method is the only one that is the
> registry routing key, and its name states that role.

Ed25519 is the canonical example because the native key type and the LogicSig
DSA family share the same cryptographic primitive but intentionally use different
registry names:

| String | What it is | Meaning |
|---|---|---|
| `ed25519` | Native key type and native routing family | Standard Algorand Ed25519 account signing. It does not use a LogicSig, is default-enabled, and the key type and family are the same string. |
| `aplane.ed25519` | Qualified LogicSig DSA routing family | APlane's Ed25519-inside-LogicSig registry family. It is not a creatable key type; it is the family-keyed registry bucket for LogicSig metadata, keygen, signing, and mnemonic ops. The `aplane.` qualifier prevents collision with native `ed25519`. |
| `aplane.ed25519.v1` | Versioned concrete LogicSig DSA key type | Version 1 of the APlane Ed25519 LogicSig DSA provider. Users can enable/create/import this key type; it signs with Ed25519, but verification happens inside TEAL via `ed25519verify_bare`. |

For composed templates, the key type's own label and its routing key can differ
again: `aplane.falcon1024-allowlist.v1` names the allowlist template, while its
`RoutingFamily()` is `aplane.falcon1024` because private-key operations delegate
to the Falcon LogicSig base.

### Classify — key type → category facts

**Mechanism:** pure string switches in neutral leaf packages. Witness form and
identity live in `internal/witness`; guarded-account role mapping lives in
`internal/cosigner/keytypes`. Examples:

- `IsGuardedAccountKeyType(keyType)`
- `CosignerComponentKeyTypeForGuardedAccount(keyType)`
- `witness.IsKeyType(keyType)`
- `witness.PublicKeySize(keyType)` / `witness.PrivateKeySize(keyType)`

**Invariant:** these classifiers import no registry, provider, or
algorithm-family package. This is load-bearing, not incidental.
Classification is consumed from about 20 call-site files across both the signer and the
client, many of which run with **no provider registered**, e.g.
`internal/cosigner/cosignerrefs/cosignerrefs.go`, `internal/keystore/file.go`,
and `internal/cache/signer.go`. Because the answer comes from the string alone,
it is identical in every binary and needs no registration step.

(`internal/witness` takes the frozen Falcon-1024 key/signature sizes from the
leaf `internal/falconparams` (checked against upstream) for the same reason,
with a consistency test against `lsig/falcon1024/family`.)

### Behave — do the operation

**Mechanism:** capability interfaces, type-asserted on the provider instance that
Resolve already produced. The operation runs only where a concrete provider is in
hand (signer-side, at derive/sign/assemble time), so a provider-method dispatch
is the right shape here.

- Core: `LSigProvider` / `SigningProvider` / `MnemonicProvider`
  (`internal/lsigprovider/provider.go`), `LogicSigDSA`
  (`internal/logicsigdsa/dsa.go`).
- Dedicated guarded-account assembly hook
  (`internal/signerapp/signing/component_assemble.go`):
  - `ComponentPacker.PackComponentSignatures(user, cosigner)` — pack the verified
    component signatures into the opaque blob.

The assembler resolves the provider, then asks it to behave — no `switch` on key
type:

```go
provider := lsigprovider.Get(keyMaterial.Type)        // Resolve
packer, ok := provider.(ComponentPacker)              // Behave: capability query
if !ok { /* fail closed */ }
packed, _ := packer.PackComponentSignatures(u, s)     // Behave: call
```

Bounded-cosigner assembly does not use a key-type-specific capability hook. It
reads the durable bounded argument-source contract and dispatches derived
arguments by the closed `kind` vocabulary; Corridor's Merkle proof is therefore
a `bounded1` behavior, not a Corridor provider method.

### Why not collapse them

The axes cannot be unified because doing so would force call sites to depend on
information they do not have.

**1. Do not route by `BaseKeyType` instead of `RoutingFamily()`.** Resolve cannot
key off the `BaseKeyType` edge because that breaks on
guarded/cosigner accounts: a guarded provider's `BaseKeyType` is
`aplane.falcon1024.v1`, but that is its *component-signing primitive*, not its
routing authority — the guarded account owns its own keygen, mnemonic-handler
registration, and metadata under its own family (this is internal handler
routing only; dedicated guarded accounts still report
`SupportsMnemonicImport() == false`, i.e. no user mnemonic import). Routing
metadata by `BaseKeyType` would return Falcon's metadata (wrong signature size) for
guarded keys. `BaseKeyType` cannot express the delegate-vs-self distinction;
`RoutingFamily()` can. **Route by `RoutingFamily()`.**

**2. Do not classify by provider capability instead of string switches.** A
provider declaration such as "I am a guarded account, my cosigner component is
X" cannot serve every
classification call site that has no provider: the client config, the keystore,
the cache. Those run in binaries that may not register guarded providers at all.
Classification must answer from the string, in any binary. **Classify by string
in the neutral leaf.**

The constraint is the same in both cases: collapsing an axis onto a mechanism
whose precondition (a populated registry / a provider instance) isn't met where
that axis is actually called. The three APIs answer different availability
constraints.

### Not a fourth axis: the LogicSig metadata fallback

`internal/algorithm/metadata.go`'s `GetMetadata` resolves via `ResolveByKeyType`
(the Resolve axis). When that fails it has a best-effort `hasFamilyPrefix`
fallback that substring-matches the key type against registered families. This is
primarily a client compatibility aid for an unregistered LogicSig template (for
example, a keystore template not loaded in this process). Because the returned
metadata also carries authorization and mnemonic semantics, the fallback is
restricted to registered `logic_sig` families. Native Ed25519 and native PQ
families resolve only by exact registered identity and are never inferred from a
third-party key-type substring. Keygen and signer execution still use registered
providers or the stored base key type. This remains a fallback on the Resolve
axis, not a separate resolution mechanism.

## LogicSig providers

### Package map

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          UNIFIED REGISTRY                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│  internal/lsigprovider/     Single registry for ALL LogicSig providers      │
│    ├── provider.go          Interface definitions (LSigProvider, etc.)      │
│    ├── types.go             ParameterDef, RuntimeArgDef, constants          │
│    └── registry.go          Register(), RegisterIfAbsent(), Get(), GetAll() │
└─────────────────────────────────────────────────────────────────────────────┘
         ▲                                              ▲
         │ registers                                    │ registers
         │                                              │
┌────────┴───────────────────┐    ┌─────────────────────┴─────────────────────┐
│   GENERIC TEMPLATES        │    │   DSA PROVIDERS                           │
├────────────────────────────┤    ├───────────────────────────────────────────┤
│ lsig/generictemplate/      │    │ lsig/falcon1024/                          │
│ library/templates/          │    │   ├── v1/standard.go   Pure Falcon DSA    │
│                            │    │   ├── v1/composer.go   Falcon wrapper     │
│ TEAL-only authorization,   │    │   └── register.go      Composed base reg  │
│ no cryptographic keys      │    │                                           │
│                            │    │ lsig/falcon1024_guarded/ Guarded cosigner   │
│                            │    │ lsig/ed25519lsig/        Ed25519 LSig     │
│ Sources:                   │    │ lsig/composeddsa/                         │
│   Optional library YAML    │    │   └── template.go      YAML compositions  │
│   Product key type state   │    │ Shared TEAL substitution:                 │
│                            │    │   tealtemplate scalar helpers               │
│                            │    │                                           │
│ Category: generic_lsig     │    │ Sources:                                  │
└────────────────────────────┘    │   Hardcoded Go (v1)                       │
                                  │   Optional library YAML                   │
                                  │   Product key type state                  │
                                  │                                           │
                                  │ Category: dsa_lsig                        │
                                  └───────────────────────────────────────────┘
```

Compiled DSA providers are registered from code and product visibility is
recorded in `internal/keytypecatalog`. Optional YAML templates are install
sources under `library/templates/`; generic and composed DSA templates are
imported with `apadmin template import`. Installed templates are stored encrypted
under product-store key type state via `internal/templatestore/` and loaded by the
signer template reload coordinator.

**Scoping invariant:** compiled providers are shared product capabilities, while
runtime-added `.template` files belong to the one durable `default` activation set. In practice:

- default-enabled built-in key types are available wherever their providers are registered
- library-visible built-in key types require an enabled product-store state record before generation surfaces expose them
- runtime-added `.template` files live in the selected generation's `keytypes/` with adjacent state records and affect the product runtime when enabled; disabled installed templates remain stored but are skipped during reload

**Schema invariant:** source-tree `.yaml` templates and runtime `.template`
files use the same logical template schema. The difference is representation,
not semantics:

- repo `.yaml` files are plaintext developer/source form under `library/templates/`
- runtime `.template` files are the encrypted on-disk form used under signer data directories, paired with plaintext key type state records

Already-generated keys keep their own stored TEAL/bytecode and do not depend on
later template-source changes.

The `bounded1` extension and its schema-v2 contract are frozen in
[ARCH_BOUNDED_DSA.md](ARCH_BOUNDED_DSA.md). The runtime accepts schema v1 for custom
composed DSA templates and schema v2 for bounded templates; each version rejects
the other's shape.

**Restore invariant:** credential backups do not carry template YAML. Restored
keys retain their durable signing metadata, while any required provider or
installed product template must already be available on the destination under the
normal registry and template precedence rules.
The key file remains the signing authority: generic v1 signing-metadata keys can
sign from stored bytecode/runtime args, and DSA v1 signing-metadata keys require
the stored `base_key_type` signer-side provider rather than the composed
template provider for their `key_type`.

Filtered views into the registry are provided by `internal/genericlsig`
(Template interface) and `internal/logicsigdsa` (LogicSigDSA interface).
Compiler-owned TEAL v13 auto-salting produces final bytecode;
`internal/lsigsalt` verifies the off-curve postcondition and retains legacy
derivation helpers. `internal/lsigresource` owns consensus resource profiles
and the pure group-size solver. Shared resource-dummy construction lives in
`internal/signing/`; final group and fee planning lives in
`internal/signerapp/signing/`.
Client registration enters through `lsig/all.go` (`lsig.RegisterClient`). Signer
registration enters through `lsig/signerreg.RegisterSigner`.

### Package summary

The Package Map above shows the registration topology — which packages plug
into the unified registry and how DSA versus generic-template providers are
organized. The table below names every package involved in the LogicSig
provider stack (including filtered views, template storage, salting, and
signing helpers that the diagram omits) and gives a one-line role for each.

| Package | Role |
|---------|------|
| `internal/lsigprovider` | **Unified registry** for all providers |
| `internal/genericlsig` | Template interface, type-filtered lookups |
| `internal/logicsigdsa` | DSA interface, type-filtered lookups |
| `internal/lsigsalt` | Off-curve verification and legacy derivation compatibility |
| `internal/lsigresource` | Structured program/argument/opcode profiles and consensus group solver |
| `internal/tealtemplate` | Strict `$variable` constant-block template renderer |
| `internal/tealtemplate/legacy.go` | Generated-mode restricted list expansion and scalar substitution utilities |
| `internal/keytypecatalog` | Compiled key type visibility catalog |
| `internal/keytypestate` | Product-store state record format and persistence primitives for library-visible compiled providers and installed templates |
| `internal/templatelibrary` | Library parsing and sole feature-level template/key-type mutation coordinator |
| `internal/templatestore` | Encrypted template file format and persistence primitives |
| `internal/signing` | Resource-dummy construction/signing and common transaction helpers |
| `lsig/composeddsa` | Generic runtime-compiled LogicSig composer used by DSA-backed composed templates, and parser/provider builder for composed DSA YAML templates |
| `lsig/falcon1024` | Falcon-1024 DSA base provider; `v1/composer.go` is the Falcon-specific wrapper over `lsig/composeddsa` |
| `lsig/ed25519lsig` | Library-visible Ed25519 LogicSig DSA provider |
| `lsig/falcon1024_guarded` | Falcon/Falcon guarded-account DSA provider (`aplane.falcon1024-cosigner1024.v1`) |
| `internal/boundedadmin/{message,program,protocol,authorization,helpersign}` | External Falcon contract-admin transcript, program validation, request/response protocol, and completion |
| `internal/witness` | Role-neutral witness-key vocabulary and identity (key IDs, sizes, public references) |
| `internal/witness/artifact` | Standalone witness-key custody artifact format |
| `internal/falconparams` | Client-safe Falcon-1024 size constants shared by LogicSig, witness, and signer metadata |
| `internal/boundedmeta` | Durable, non-secret bounded-authorization metadata stored with a LogicSig key |
| `internal/merkleallowlist` | Merkle recipient allowlist construction and proofs used by bounded templates |
| `internal/rotatingkey` | Classify-axis leaf for rotating account key types and their frozen sizes |
| `lsig/rotatinghybrid` | Rotating Falcon-1024 + Ed25519 key type: stage program, signer-side operations, and signer registration |
| `lsig/rotatingwots` | Rotating WOTS-w16 + Ed25519 key type: stage program, signer-side operations, and signer registration |
| `library/templates/aplane.corridor.v1.yaml` | Optional schema-v2 bounded-cosigner Corridor profile; compiled by `lsig/composeddsa` after product-store install |
| `lsig/dsafamily` | Client-safe registration descriptor shared by DSA families (signer-side descriptor in `lsig/dsafamily/signerreg`) |
| `lsig/signerreg` | Registers all built-in LogicSig signer-side providers with their catalog availability |
| `internal/signerapp/templates` | Read-only keystore template reload coordinator and state/fingerprint policy |
| `lsig/generictemplate` | Parser/provider builder for generic YAML templates |
| `library/templates/` | Optional importable template library |
| `lsig/all.go` | Registration entry point |

### Two categories of LogicSigs

| Category | Example Key Types | Has Keys | Signing |
|----------|-------------------|----------|---------|
| `generic_lsig` | `aplane.htlc.v1` after template import | No | TEAL-only authorization |
| `dsa_lsig` | `aplane.falcon1024.v1`, `aplane.ed25519.v1`, bounded `aplane.falcon1024-allowlist-alock.v1`, guarded `aplane.falcon1024-cosigner1024.v1`, `aplane.corridor.v1`; bundled Falcon templates after install | Yes | Cryptographic signature |
| `rotating_lsig` | `aplane.rotating-hybrid.v1`, `aplane.rotating-wots-hybrid.v1` | Yes | Per-stage hybrid signatures through the `rotating1` flow; signer-side codec, not an `lsigprovider` provider |

### Interface hierarchy

```
LSigProvider (base interface - ALL providers implement this)
├── Identity
│   ├── KeyType() string        "aplane.falcon1024.v1", "aplane.htlc.v1"
│   ├── RoutingFamily() string  "aplane.falcon1024" (registry routing key; see Resolve above)
│   └── Version() int           1, 2, etc.
├── Category
│   └── Category() string       "generic_lsig" or "dsa_lsig"
├── Display
│   ├── DisplayName() string    "Falcon-1024", "HTLC"
│   ├── Description() string    Short description for UI
│   └── DisplayColor() string   ANSI color code
├── Parameters
│   ├── CreationParams() []ParameterDef
│   └── ValidateCreationParams(params) error
├── Runtime
│   └── RuntimeArgs() []RuntimeArgDef
└── Args Assembly
    └── BuildArgs(signature, runtimeArgs) ([][]byte, error)
          │
          ▼
SigningProvider (extends LSigProvider)
├── CryptoSignatureSize() int
└── DeriveLsig(ctx, publicKey, params) (bytecode, address, error)
          │
          ▼
MnemonicProvider (extends SigningProvider)
├── MnemonicScheme() string         "bip39", "algorand"
├── MnemonicWordCount() int         24, 25
└── SupportsMnemonicImport() bool
```

Private-key key generation, signing, and mnemonic conversion are deliberately
outside this client-visible registry. Signer-side startup wires those operations
through the `internal/signing`, `internal/keygen`, and `internal/mnemonic`
registries.

### Unified registry

The `lsigprovider` package is the **single source of truth** for all LogicSig providers:

```go
// Registration - called from provider packages
func Register(p LSigProvider) {
    registerMu.Lock()
    defer registerMu.Unlock()

    // Validates key type, family, version, and category; returns the normalized key type
    keyType := validateProviderContract(p)
    if !providers.Set(keyType, p) {
        panic("duplicate LSig provider registration for key type: " + keyType)
    }

    // Apply stored algod client for late-registered providers
    applyStoredClientIfNeeded(p)
}

// Lookup - returns nil if not found
func Get(keyType string) LSigProvider {
    p, _ := providers.Get(normalize(keyType))
    return p
}

// Lookup with error
func GetOrError(keyType string) (LSigProvider, error) {
    if p, ok := providers.Get(normalize(keyType)); ok {
        return p, nil
    }
    return nil, fmt.Errorf("no LSig provider found for: %s", keyType)
}
```

The `genericlsig` and `logicsigdsa` packages delegate to `lsigprovider` and provide type-filtered views:

```go
// genericlsig.Get returns only Template implementations
func Get(keyType string) Template {
    p := lsigprovider.Get(keyType)
    if t, ok := p.(Template); ok {
        return t
    }
    return nil
}

// logicsigdsa.Get returns only LogicSigDSA implementations
func Get(keyType string) LogicSigDSA {
    p := lsigprovider.Get(keyType)
    if dsa, ok := p.(LogicSigDSA); ok {
        return dsa
    }
    return nil
}
```

### Registration flow

```
lsig.RegisterClient()
    │
    ├── keytypecatalog.Register(aplane.falcon1024.v1, default_enabled)
    │   └── falcon.RegisterClient()
    │       ├── v1.RegisterLogicSigDSA() → Falcon1024V1
    │       └── ... (metadata, address derivation)
    ├── keytypecatalog.Register(aplane.falcon1024-cosigner1024.v1, library)
    │   └── falcon1024guarded.RegisterClient()
    ├── keytypecatalog.Register(aplane.ed25519.v1, library)
    │   └── ed25519lsig.RegisterClient()
    ├── keytypecatalog.Register(aplane.rotating-hybrid.v1, library)
    │   └── (no client provider)
    └── keytypecatalog.Register(aplane.rotating-wots-hybrid.v1, library)
        └── (no client provider)

lsig/signerreg.RegisterSigner()
    ├── lsig.RegisterClient()
    ├── family signerreg RegisterSigner() calls add signing, keygen, and mnemonic handlers
    └── rotating signerreg Register() calls add the rotating key file codec,
        stage cryptography, and generator (outside lsigprovider)
```

Runtime templates (from keystore) are loaded after unlock:
```go
signertemplates.NewManager(paths).RegisterKeystoreTemplates(keyring)
```

### Algod client configuration

Providers that need runtime TEAL compilation implement `AlgodConfigurable`:

```go
type AlgodConfigurable interface {
    SetAlgodClient(client *algod.Client)
}

// Called during startup
lsigprovider.ConfigureAlgodClient(client)

// Stored for late-registered providers (e.g., keystore templates)
```

### BuildArgs: explicit arg ordering

The `BuildArgs` method encapsulates LogicSig arg ordering:

| Provider Type | Args Format |
|---------------|-------------|
| Generic (no runtime args) | `[]` |
| Generic (with runtime args) | `[preimage, ...]` |
| DSA (single-signature-arg form, e.g. `aplane.falcon1024.v1`) | `[signature]` |
| DSA (multi-signature-arg form, when declared by a custom provider) | `[r, s]` |
| DSA with runtime args | `[signature args..., runtime args...]` |

**Invariant**: Arg order is determined by `RuntimeArgs()` schema order at key
generation time, not map iteration. v1 signing-metadata key files persist that
runtime arg schema and use the stored copy at signing time. LogicSig key files
whose derivation metadata does not match their bytecode, or whose stored
bytecode derives an on-curve LogicSig address, are rejected during key scan.
LogicSig key files without
`signing_metadata_version` are rejected when signing or restore would otherwise
depend on missing durable signing metadata; the live provider schema is not used
as a fallback.

```go
// Generic template - no signature
func (t *YAMLTemplate) BuildArgs(sig []byte, args map[string][]byte) ([][]byte, error) {
    // sig is ignored for generic templates
    var result [][]byte
    for _, argDef := range t.RuntimeArgs() {  // Schema order is canonical
        if val, ok := args[argDef.Name]; ok {
            result = append(result, val)
        } else if argDef.Required {
            return nil, fmt.Errorf("missing required arg: %s", argDef.Name)
        }
    }
    return result, nil
}

// DSA - provider-specific signature args first, then runtime args
func (c *ComposedDSA) BuildArgs(sig []byte, args map[string][]byte) ([][]byte, error) {
    if sig == nil {
        return nil, fmt.Errorf("signature is required for DSA LogicSig")
    }
    sigArgs := providerSpecificSignatureArgs(sig) // e.g. [sig] or [r, s]
    result := append([][]byte{}, sigArgs...)
    for _, argDef := range c.RuntimeArgs() {  // Schema order is canonical
        if val, ok := args[argDef.Name]; ok {
            result = append(result, val)
        } else if argDef.Required {
            return nil, fmt.Errorf("missing required arg: %s", argDef.Name)
        }
    }
    return result, nil
}
```

**Note**: Runtime arg validation is shared through `lsigprovider.ValidateAndOrderArgs()`.
The engine validates signer-cache runtime arg metadata before submitting, and
providers also validate while assembling args. This keeps ordering deterministic
and rejects unknown or missing required args.

### Composed DSA

The generic `lsig/composeddsa` engine combines a DSA base with an optional TEAL
suffix. Strict template suffixes use declared `template_variables` and `$name`
constant references; generated-mode suffixes keep the restricted list-expansion
path. Falcon exposes that engine through Falcon-specific names:

```go
ExampleFalconHashlock = NewComposedFalcon(ComposedFalconConfig{
    KeyType:     "example.falcon-hashlock.v1",
    FamilyName:  "aplane.falcon1024",
    Version:     1,
    DisplayName: "Falcon-1024 Hashlock",
    Base:        family.FalconBase, // nil also defaults to family.FalconBase
    Params: []lsigprovider.ParameterDef{{
        Name: "hash", Type: "bytes", Required: true, MaxLength: 64,
        InputModes: []lsigprovider.InputMode{
            {Name: "preimage", Label: "Preimage", Transform: "sha256"},
            {Name: "hash", Label: "SHA-256 Hash"},
        },
    }},
    RuntimeArgs: []lsigprovider.RuntimeArgDef{{
        Name: "preimage", Type: "bytes", Required: true,
    }},
    TemplateMode: generictemplate.TemplateModeStrict,
    TemplateVars: []tealtemplate.TemplateVariable{{
        Name: "hash", Source: tealtemplate.SourceParameter,
        Parameter: "hash", Type: "bytes", Constant: tealtemplate.ConstantByte,
    }},
    TEALSuffix: `arg 1
sha256
$hash
==
assert`,
})
```

Generated TEAL structure:
```
#pragma version 13
bytecblock 0x<hash>                // strict template constants

// DSA signature verification (Falcon-1024 native opcode)
txn TxID
arg 0
pushbytes 0x<pubkey>
falcon_verify
assert

// TEAL suffix (with $variables rewritten to constant references)
arg 1; sha256; bytec_0; ==; assert

int 1
return
```

The TEAL above is the semantic renderer output before algod assembly. For
derivation version 3, algod may reuse generated constants or append a
semantically inert constant block while finding an off-curve address; APlane
does not author or patch a salt marker.

The example above is renderer output, not user-authored YAML source. Template
authors write symbolic `$hash` references; validation rejects raw
`bytecblock`/`intcblock` declarations and numeric constant references in
user-authored TEAL so the renderer can own generated constants and any
derivation-version salt anchor layout.

Current bundled address derivation delegates auto-salting to the TEAL v13
compiler. APlane accepts the compiler's final bytecode as authoritative,
checks its reported address and off-curve postcondition, derives resources from
that artifact, and persists it with
`lsig_derivation: algod_v13_auto_salt`. It does not reproduce or patch the
compiler's salt choice. Legacy derivation versions retain their marker,
trailing-block, and counter validation only for compatible stored records;
salt style is not exposed through public wire DTOs.

#### Bounded1 composer extension

Schema-v2 composed templates add a composer-owned transaction envelope ahead
of the author suffix. Authentication remains first; fee/type/effect dispatch
is second; author Layer 3 is reachable only from the pure-spend branch. The
composer owns all `__aplane_bounded1_` labels and the `bounded_` parameter
namespace.

Bounded-capable bases expose a static signature-argument layout. Bounded1 keeps
`LSigProvider.BuildArgs` unchanged, then assembles declared signer-derived and
caller runtime Layer-3 arguments into frozen slots selected by the plan. Durable
key metadata, rather than the installed YAML template, records path routing,
base argument count/sizes, all argument declarations and slots, profile, Falcon
contract-admin metadata, and reviewed per-path opcode ceilings.

Bounded emission uses the template/provider's declared derivation contract; it
does not invent a second bounded salt. Current bundled providers compile TEAL
v13 and persist algod's final auto-salted bytecode. See
[ARCH_BOUNDED_DSA.md](ARCH_BOUNDED_DSA.md).

#### Salting rationale

LogicSig addresses are derived from the compiled program hash. A random program
hash can decode as a valid Ed25519 public key, which would make the LogicSig
address also look like an ordinary signature account address. APlane therefore
treats "off-curve" as a key-file invariant for generated LogicSigs: generation
must produce bytecode whose address cannot correspond to an Ed25519 public key,
and scan/restore paths reject stored LogicSig bytecode that violates that
invariant.

For current bundled providers and `derivation_version: 3` templates, APlane
asks the pinned algod compiler for TEAL v13 bytecode and treats those returned
bytes as authoritative. The compiler may leave an already off-curve program
unchanged, reuse a generated constant block, or append a semantically inert
constant block while searching. APlane does not reproduce that search. It
checks that the compiler-reported address matches the final bytes, verifies the
address is off-curve, derives program length and resource metadata from the
final artifact, and persists it.

Source-to-address golden vectors are pinned to APlane's compiler toolchain,
not promised across arbitrary assembler implementations. Runtime signing is
reproducible from the persisted final bytecode.

Legacy derivation versions remain parseable where required by the on-disk
schema, but all bundled pre-release templates use `derivation_version: 3`.
Previously generated development LogicSig keys must be regenerated; APlane
does not silently reinterpret old bytecode.

**Note**: Falcon-1024 verification uses the native `falcon_verify` opcode (TEAL v12+), which takes:
1. Message (32 bytes) - the transaction ID
2. Signature (variable, at most 1,423 bytes) - deterministic compressed Falcon-1024 signature
3. Public key (1793 bytes) - Falcon-1024 public key

### Template systems

Generic templates use their own schema-v1 contract. Custom composed DSA
templates use composed schema v1 with an explicit `template_mode`; every
APlane-bundled composed template uses bounded schema v2. Bounded composed
templates use the separately validated contract described in
[ARCH_BOUNDED_DSA.md](ARCH_BOUNDED_DSA.md); composed schema v1 must reject
`bounded` rather than discard it.

The shared parser first inspects the raw mapping, rejects duplicate/merge keys,
aliases, multiple documents, and invalid schema selectors, then decodes the
selected version with recursive known-field checking. Composed schema v2
requires `bounded`; generic validation rejects schema v2 and all bounded fields.
Installed and library templates use this same parser before encrypted storage
or provider registration.

- `strict` mode declares `template_variables` and uses `$name` references that
  render through generated TEAL constant blocks.
- `generated` mode uses the restricted `@variable` scalar substitution plus
  `{{range @list}} ... {{.}} ... {{end}}` list-expansion grammar; arbitrary
  Go-template syntax is rejected and `template_variables` must not be declared.
  It is available to generic (schema v1) and composed (schema v1 or v2)
  templates, e.g. `aplane.htlc.v1` and the Falcon allowlist templates; it is not
  limited to bounded templates.
- `legacy` (schema v1 only) renders through the same `@variable` substitution
  and list-expansion path as `generated`, but without generated mode's up-front
  list-syntax validation; it is the effective mode for already-stored schema-v1
  templates with no `template_mode`. Template import requires an explicit mode,
  and schema v2 requires `strict` or `generated`.

#### Generic templates (`lsig/generictemplate`)

YAML-based TEAL templates with strict constant substitution:

```yaml
schema_version: 1
derivation_version: 3
template_type: generic
template_mode: strict
publisher: aplane
family: custom-escrow
version: 1
display_name: "Custom Escrow"
parameters:
  - name: recipient
    type: address
    required: true
template_variables:
  - name: recipient
    source: parameter
    parameter: recipient
    type: address
    constant: byte
teal: |
  txn Receiver
  $recipient
  ==
```

#### Composed DSA templates (`lsig/composeddsa`)

YAML-based DSA compositions with parameterized TEAL suffixes:

```yaml
schema_version: 1
derivation_version: 3
template_type: composed
base_key_type: aplane.falcon1024.v1
template_mode: strict
publisher: example
family: falcon-hashlock
version: 1
display_name: "Falcon-1024 Hashlock"
description: "Falcon signature with SHA256 hash verification"
parameters:
  - name: hash
    type: bytes
    required: true
    max_length: 64
    label: "SHA256 Hash"
template_variables:
  - name: hash
    source: parameter
    parameter: hash
    type: bytes
    constant: byte
runtime_args:
  - name: preimage
    type: bytes
    label: "Secret Preimage"
teal: |
  txn RekeyTo
  global ZeroAddress
  ==
  assert
  arg 1
  sha256
  $hash
  ==
  assert
```

For composed templates, `base_key_type` selects the signing provider while
the YAML `family` field names the template's own version line. The two are
independent: `base_key_type: aplane.falcon1024.v1` plus
`family: falcon1024-allowlist` yields a `key_type` of
`<publisher>.falcon1024-allowlist.vN` that signs with Falcon-1024, while
`base_key_type: aplane.ed25519.v1` plus `family: ed25519-allowlist`
yields a template key type that signs with Ed25519 inside a LogicSig.

Both composed templates and generic templates are stored by the signer through
`templatelibrary`, which coordinates the primitive `templatestore` and
`keytypestate` writes. The template store's storage
type vocabulary is limited to `generic` and `composed`; compiled providers use
product-store key type state with `SourceCompiled` and are exposed to admin/library
clients as `compiled_provider` without writing an encrypted `.template` file. At runtime
`internal/signerapp/templates` walks the product-store state once, decrypts enabled
installed templates, and dispatches each template to the generic or composed
parser/provider builder.

### Transaction-aware bounded arguments

Most DSA providers produce a fixed argument list from one key. Bounded1 starts
with that base layout, then statically orders signer-derived Layer-3 arguments,
caller runtime Layer-3 arguments, an optional cosigner signature slot
(bounded-cosigner1 profiles), and an optional final contract-admin slot.
Each slot records its source, maximum size, and spend/spending-rekey/admin-rekey
requirement. Interior slots forbidden on a selected path are explicit empty byte
strings; unused trailing slots may be omitted. Callers cannot populate derived
or admin slots.

The planner selects the path and freezes its slots. The executor verifies plan
integrity, generates only declared derived arguments, and places caller runtime
arguments only in their declared slots. An admin-key rekey is routed through
`/sign/bounded-admin`: apsigner returns the base-signature partial with the final
admin slot reserved, and `aprekey` independently validates the finalized
transaction and fills only that slot. Durable bounded metadata owns the layout
and per-path maximum signed size. See
[ARCH_BOUNDED_DSA.md](ARCH_BOUNDED_DSA.md).

## See also

- `docs/ARCH_SIGNING.md` — HTTP DTOs, error codes, and SDK contracts.
- `docs/ARCH_CONTRACTS.md` — compatibility-bearing contracts and pointers to
  their owning documents.
- `docs/ARCH_BOUNDED_DSA.md` — the `bounded1` authorization contract and its
  profile, metadata, and path semantics.
- `docs/ARCH_SECURITY.md` — product-principal and closed-action
  authorization for API and admin operations.
- `docs/ARCH_POLICY.md` — signer and cosigner policy domains that gate signature
  release.
- `docs/ARCH_NETWORKS.md` — network context and genesis-hash resolution.
- `docs/ARCH_GUARDED.md` — the guarded/cosigner account choreography.
- `docs/DEV_KEYTYPES.md` — how to add a key type (where these axes become
  concrete decisions).
- [ARCH_CRYPTO.md](ARCH_CRYPTO.md) - Full cryptographic subsystem documentation
