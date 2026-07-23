# Key Types, Authorization Contracts, and Resolution Axes

This document explains how APlane composes key types, account-authorization
forms, LogicSig policy contracts, auxiliary authorities, signing flows, and
provider implementations. It also explains how the codebase answers questions
about a key type, and **why** there are three separate resolution mechanisms
rather than one. Read this before changing their boundaries (see
[Why not collapse them](#why-not-collapse-them)).

`docs/ARCH_LSIG_PROVIDER.md` is the detailed registry reference; it covers one of
the three axes below (Resolve). This document is the cross-cutting view.

## The three axes

A "key type" (e.g. `aplane.falcon1024.v1`, `aplane.corridor.v1`,
`aplane.falcon1024-sentry1024.v1`) is asked three different *kinds* of
question, and each kind uses a different mechanism because each is callable from
a different place.

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
| **Auxiliary authority enrollment** | Which additional authority participates, for which role or operation, and under whose custody? | sentry witness, external contract-admin witness | Embedded public key, durable metadata, and custody-specific message contract |
| **Signing flow** | Which versioned client/server protocol obtains a usable signature for this key? | empty ordinary flow, `bounded1`, `sentry1`, `bounded-sentry1` | Signer-advertised `signing_flow` |
| **Endpoint choreography** | Which ordered calls implement the selected flow for this transaction path? | `/sign`; `/sign/component` then `/sign/assemble`; `/sign/bounded-admin` then `aprekey` | Flow contract, transaction classification, and HTTP DTOs |
| **Provider and routing family** | Which registered implementation performs keygen, derivation, signing, or assembly? | composed provider routed through `aplane.falcon1024`; dedicated guarded provider | Provider registry and `RoutingFamily()` |
| **Principal authorization** | May the authenticated caller invoke this operation on the target identity/resource? | `sign.request`, `sign.component`, `sign.assemble` | Principal/group/grant model and HTTP/admin enforcement point |
| **Signer policy domain** | Which off-chain rules gate release of a signature that the key and on-chain program could produce? | client-signing policy, sentry policy | Node role, `policy.yaml`, and the selected policy key |
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
  behavioral guarantee documented in `ARCH_CONTRACTS.md`.
- A **message or transcript contract** is an exact cryptographic encoding and
  domain, such as `APLANE_SENTRY_V1` or `APLANE_BOUNDED_ADMIN_AUTH_V1`.

Likewise, account authorization is distinct from principal authorization and
signer policy. The account key and LogicSig determine what can authorize the
Algorand account; the grant model determines who may call an APlane endpoint;
signer or sentry policy determines whether that permitted call may release a
signature for the particular transaction.

`bounded1` is always the bounded authorization-contract identifier and is also
the signing-flow label for bounded profiles that need no online sentry. A
sentry-enabled bounded profile keeps `contract: bounded1` but advertises the
distinct `bounded-sentry1` choreography. The contract identifier selects
canonical on-chain and durable metadata semantics; the flow label tells the
client how to route a request. Likewise, `sentry1` is a signing-flow label and
an embedded bounded sentry contract value, while `APLANE_SENTRY_V1` is the
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
   endpoint. Signer or sentry policy independently decides whether the specific
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
| `aplane.falcon1024.v1` | DSA LogicSig | plain DSA | Falcon-1024, self-owned | none | empty flow; `/sign` |
| `aplane.falcon1024-allowlist.v1` | DSA LogicSig | bounded `bounded1`; fixed recipient allowlist | `aplane.falcon1024.v1` | none | `bounded1`; spend/rekey through `/sign` as permitted by the profile |
| `aplane.falcon1024-allowlist-alock.v1` | DSA LogicSig | bounded `bounded1`; fixed recipient/asset/amount allowlist | `aplane.falcon1024.v1` | external Falcon contract admin for rekey | `bounded1`; spend through `/sign`, admin rekey through `/sign/bounded-admin` plus `aprekey` |
| `aplane.falcon1024-sentry1024.v1` | DSA LogicSig | dedicated guarded verifier | `aplane.falcon1024.v1` | signer-custodied Falcon sentry witness | `sentry1`; user `/sign/component`, sentry `/sign/component`, then `/sign/assemble` |
| `aplane.corridor.v1` | DSA LogicSig | bounded `bounded1`; framework Merkle recipient allowlist | `aplane.falcon1024.v1` | signer-custodied Falcon sentry on spend; distinct external Falcon admin on rekey | `bounded-sentry1`; `/sign/bounded-component`, sentry `/sign/component`, then `/sign/bounded-assemble` |
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
| HTTP or SDK payload shape | Versioned endpoint/DTO contract according to `ARCH_CONTRACTS.md` |

These versions may advance independently. A key type version must still pin the
complete behavior it relies on, and compatibility-bearing changes commonly
require advancing more than one dimension together.

## Authorization object ontology

The resolution mechanisms below are separate from the security ontology. The
ontology first identifies what authorizes an account, then any LogicSig policy
form, and finally any additional authority. These dimensions must not be
collapsed into one flat key-type hierarchy.

### Account authorization types

| Type | Account authority | Signer representation |
|---|---|---|
| **Native** | A protocol-native account signature, currently Algorand Ed25519. | Encrypted signer `.key` with native private material. |
| **DSA LogicSig** | A LogicSig verifies one or more digital signatures and may enforce additional transaction policy. | Encrypted signer `.key` with DSA private material, compiled bytecode, and signing metadata. |
| **Generic LogicSig** | TEAL predicates alone authorize the account; there is no DSA private key. | Encrypted signer `.key` containing bytecode, parameters, salt, and signing metadata but no private signing material. |

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
  `aplane.falcon1024-sentry1024.v1` guarded verifier.

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
| **Witness key, sentry enrollment** | Stored as a sentry-managed `.sen` credential and used through `/sign/component`; its signature is assembled into a guarded-account LogicSig. | Yes. `aplane.witness-falcon1024.v1`, durable category `witness`; never accepted as a spending account by ordinary `/sign`. |
| **Witness key, contract-admin enrollment** | Stored in a standalone encrypted `.wit` artifact and used only for a declared bounded admin operation through `aprekey`. | The key form has the same witness key type, but this custody container is never an `apstore` or signer key. |

The current authority overlays are therefore **unguarded**, **sentry guarded**,
and **contract-admin-authorized operation**. Contract-admin authority is
operation-specific: the spending key still authenticates every bounded path,
and the external admin key currently authorizes only a pure rekey.

Witness **form**, **custody**, and **enrollment** are separate dimensions. The
key record carries no role field: the program that embeds the public key names
the role, and the custodian controls which message domain can be signed. A
networked signer may produce only `APLANE_SENTRY_V1` component-domain
signatures; the offline ceremony may produce only
`APLANE_BOUNDED_ADMIN_AUTH_V1` signatures. One witness keypair should serve one
role for its entire life. The software rejects collisions visible in local
stores and sentry references, but cannot detect out-of-band key copying.

Examples of the composed ontology:

| Key type | Account authorization | Policy form | Additional authority |
|---|---|---|---|
| `ed25519` | Native | n/a | none |
| `aplane.falcon1024.v1` | DSA LogicSig | Plain DSA | none |
| `aplane.falcon1024-allowlist.v1` | DSA LogicSig | Bounded DSA (`bounded1`) | none |
| `aplane.falcon1024-allowlist-alock.v1` | DSA LogicSig | Bounded DSA (`bounded1`) | external Falcon witness enrolled as contract admin for rekey |
| `aplane.falcon1024-sentry1024.v1` | DSA LogicSig | dedicated compiled guarded verifier | signer-custodied Falcon witness enrolled as sentry |
| `aplane.corridor.v1` | DSA LogicSig | Bounded DSA (`bounded1`) with framework Merkle policy | signer-custodied Falcon sentry on spend plus external Falcon contract admin on rekey |
| `aplane.htlc.v1` | Generic LogicSig | generic TEAL policy | none |

## Resolution, classification, and behavior

| Axis | Question it answers | Mechanism | Owner package(s) |
|---|---|---|---|
| **Resolve** | key type → its implementation | family-keyed registries + a `RoutingFamily` resolver | `internal/lsigprovider`, `internal/logicsigdsa` |
| **Classify** | key type → category facts (is it a guarded account? which witness form? what key size?) | string switches in neutral leaf packages | `internal/sentry/keytypes`, `internal/witness` |
| **Behave** | do the operation (pack signatures, build assembly args, derive, sign) | provider-capability interfaces, queried from the resolved provider | `internal/signerapp/signing`, `internal/lsigprovider`, `internal/logicsigdsa` |

**The governing rule:** *do not unify mechanisms across axes that have different
call-site availability.* Resolve needs the registry; Classify must work with no
registry at all; Behave needs a concrete provider instance in hand. Those are
different runtime conditions, so they need different mechanisms — collapsing them
forces a call site to depend on something it does not have.

---

## Resolve — key type → implementation

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

---

## Classify — key type → category facts

**Mechanism:** pure string switches in neutral leaf packages. Witness form and
identity live in `internal/witness`; guarded-account role mapping lives in
`internal/sentry/keytypes`. Examples:

- `IsGuardedAccountKeyType(keyType)`
- `SentryComponentKeyTypeForGuardedAccount(keyType)`
- `witness.IsKeyType(keyType)`
- `witness.PublicKeySize(keyType)` / `witness.PrivateKeySize(keyType)`

**Invariant:** these classifiers import no registry, provider, or
algorithm-family package. This is load-bearing, not incidental.
Classification is consumed from ~18 call sites across both the signer and the
client, many of which run with **no provider registered** — e.g.
`internal/config/client_endpoints.go` (client-side), `internal/keystore/file.go`,
and `internal/cache/signer.go`. Because the answer comes from the string alone,
it is identical in every binary and needs no registration step.

(`internal/witness` declares the frozen Falcon-1024 key/signature sizes as
literals for the same reason, with a consistency test against
`lsig/falcon1024/family`.)

---

## Behave — do the operation

**Mechanism:** capability interfaces, type-asserted on the provider instance that
Resolve already produced. The operation runs only where a concrete provider is in
hand (signer-side, at derive/sign/assemble time), so a provider-method dispatch
is the right shape here.

- Core: `LSigProvider` / `SigningProvider` / `MnemonicProvider`
  (`internal/lsigprovider/provider.go`), `LogicSigDSA`
  (`internal/logicsigdsa/dsa.go`).
- Dedicated guarded-account assembly hook
  (`internal/signerapp/signing/component_assemble.go`):
  - `ComponentPacker.PackComponentSignatures(user, sentry)` — pack the verified
    component signatures into the opaque blob.

The assembler resolves the provider, then asks it to behave — no `switch` on key
type:

```go
provider := lsigprovider.Get(keyMaterial.Type)        // Resolve
packer, ok := provider.(ComponentPacker)              // Behave: capability query
if !ok { /* fail closed */ }
packed, _ := packer.PackComponentSignatures(u, s)     // Behave: call
```

Bounded-sentry assembly does not use a key-type-specific capability hook. It
reads the durable bounded argument-source contract and dispatches derived
arguments by the closed `kind` vocabulary; Corridor's Merkle proof is therefore
a `bounded1` behavior, not a Corridor provider method.

---

## Why not collapse them

The axes cannot be unified because doing so would force call sites to depend on
information they do not have.

**1. Do not route by `BaseKeyType` instead of `RoutingFamily()`.** Resolve cannot
key off the `BaseKeyType` edge because that breaks on
guarded/sentry accounts: a guarded provider's `BaseKeyType` is
`aplane.falcon1024.v1`, but that is its *component-signing primitive*, not its
routing authority — the guarded account owns its own keygen, mnemonic-handler
registration, and metadata under its own family (this is internal handler
routing only; dedicated guarded accounts still report
`SupportsMnemonicImport() == false`, i.e. no user mnemonic import). Routing
metadata by `BaseKeyType` would return Falcon's metadata (wrong signature size) for
guarded keys. `BaseKeyType` cannot express the delegate-vs-self distinction;
`RoutingFamily()` can. **Route by `RoutingFamily()`.**

**2. Do not classify by provider capability instead of string switches.** A
provider declaration such as "I am a guarded account, my sentry component is
X" cannot serve every
classification call site that has no provider: the client config, the keystore,
the cache. Those run in binaries that may not register guarded providers at all.
Classification must answer from the string, in any binary. **Classify by string
in the neutral leaf.**

The constraint is the same in both cases: collapsing an axis onto a mechanism
whose precondition (a populated registry / a provider instance) isn't met where
that axis is actually called. The three APIs answer different availability
constraints.

---

## Not a fourth axis: the metadata display fallback

`internal/algorithm/metadata.go`'s `GetMetadata` resolves via `ResolveByKeyType`
(the Resolve axis). When that fails it has a best-effort `hasFamilyPrefix`
fallback that substring-matches the key type against registered families. This is
**display-only** — it exists so an unregistered template (e.g. a keystore template
not loaded in this process, queried client-side for a display color) still gets a
plausible color. Keygen and signing never reach it: they always have a registered
provider or a stored base key type in the key file. The fallback avoids threading
the stored base key type through the `addressdisplay.ColorFormatter` callback
for cosmetic display. It is a fallback on the Resolve axis, not a separate
resolution mechanism.

---

## See also

- `docs/ARCH_CONTRACTS.md` — compatibility-bearing identifiers, DTOs, storage,
  and message contracts.
- `docs/ARCH_BOUNDED_DSA.md` — the `bounded1` authorization contract and its
  profile, metadata, and path semantics.
- `docs/ARCH_AUTHORIZATION.md` — principal/group/grant authorization for API
  and admin operations.
- `docs/ARCH_POLICY.md` — signer and sentry policy domains that gate signature
  release.
- `docs/ARCH_NETWORKS.md` — network context and genesis-hash resolution.
- `docs/ARCH_LSIG_PROVIDER.md` — the Resolve-axis registry, in detail.
- `docs/ARCH_SENTRY.md` — the guarded/sentry account choreography.
- `docs/DEV_KEYTYPES.md` — how to add a key type (where these axes become
  concrete decisions).
