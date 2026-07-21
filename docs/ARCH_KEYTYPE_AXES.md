# Key-Type Resolution: The Three Axes

This document explains how the codebase answers questions about a key type, and
**why** there are three separate mechanisms rather than one. Read this before
changing their boundaries (see [Why not collapse them](#why-not-collapse-them)).

`docs/ARCH_LSIG_PROVIDER.md` is the detailed registry reference; it covers one of
the three axes below (Resolve). This document is the cross-cutting view.

## The three axes

A "key type" (e.g. `aplane.falcon1024.v1`, `aplane.corridor.v1`,
`aplane.falcon1024-sentry1024.v1`) is asked three different *kinds* of
question, and each kind uses a different mechanism because each is callable from
a different place.

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
  composed-template schema, such as `aplane.corridor.v1`.

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
| `aplane.corridor.v1` | DSA LogicSig | dedicated compiled corridor policy | signer-custodied Falcon witness enrolled as sentry |
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
- Guarded-account assembly hooks
  (`internal/signerapp/signing/component_assemble.go`):
  - `ComponentPacker.PackComponentSignatures(user, sentry)` — pack the verified
    component signatures into the opaque blob.
  - `AssemblyExtraArgsProvider.AssemblyExtraArgs(txn, params)` — append extra
    LogicSig args computed from the target transaction (corridor's recipient
    Merkle proof). Providers that don't implement it append nothing.

The assembler resolves the provider, then asks it to behave — no `switch` on key
type:

```go
provider := lsigprovider.Get(keyMaterial.Type)        // Resolve
packer, ok := provider.(ComponentPacker)              // Behave: capability query
if !ok { /* fail closed */ }
packed, _ := packer.PackComponentSignatures(u, s)     // Behave: call
// ... AssemblyExtraArgsProvider queried the same way
```

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
routing only; guarded/corridor accounts still report
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

- `docs/ARCH_LSIG_PROVIDER.md` — the Resolve-axis registry, in detail.
- `docs/ARCH_SENTRY.md` — the guarded/sentry account choreography.
- `docs/DEV_KEYTYPES.md` — how to add a key type (where these axes become
  concrete decisions).
