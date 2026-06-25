# Key-Type Resolution: The Three Axes

This document explains how the codebase answers questions about a key type, and
**why** there are three separate mechanisms rather than one. Read this before
trying to unify them — that unification has been attempted twice and is wrong
both times (see [Why not collapse them](#why-not-collapse-them)).

`docs/ARCH_LSIG_PROVIDER.md` is the detailed registry reference; it covers one of
the three axes below (Resolve). This document is the cross-cutting view.

## The three axes

A "key type" (e.g. `aplane.falcon1024.v1`, `aplane.corridor.v1`,
`aplane.falcon1024-sentry-ed25519.v1`) is asked three different *kinds* of
question, and each kind uses a different mechanism because each is callable from
a different place.

| Axis | Question it answers | Mechanism | Owner package(s) |
|---|---|---|---|
| **Resolve** | key type → its implementation | family-keyed registries + a `RoutingFamily` resolver | `internal/lsigprovider`, `internal/logicsigdsa` |
| **Classify** | key type → category facts (is it a guarded account? which sentry component? what key size?) | string switches in a neutral leaf package | `internal/sentry/keytypes` |
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
to a base it is the *base's* family (e.g. `aplane.falcon1024-whitelist.v1` →
`aplane.falcon1024`). That base is a **registration fact**, not something
derivable from the key-type string, and it is deliberately not the same as the
key type's own display label.

> The routing method is named `RoutingFamily()` precisely so it is not confused
> with the other uses of the word "family": the key-type display segment and the
> YAML `family:` / wire `family` fields all carry a *different* value (the key
> type's own label, not its routing key). The method is the only one that is the
> registry routing key — and its name now says so.

---

## Classify — key type → category facts

**Mechanism:** pure string switches in `internal/sentry/keytypes`, a neutral leaf
package. Examples:

- `IsGuardedAccountKeyType(keyType)`
- `IsSentryComponentKeyType(keyType)`
- `SentryComponentKeyTypeForGuardedAccount(keyType)`
- `ComponentPublicKeySize(keyType)` / `ComponentPrivateKeySize(keyType)`

**Invariant:** `keytypes` imports no registry, provider, or algorithm-family
package — only the standard library. This is load-bearing, not incidental.
Classification is consumed from ~18 call sites across both the signer and the
client, many of which run with **no provider registered** — e.g.
`internal/config/client_endpoints.go` (client-side), `internal/keystore/file.go`,
and `internal/cache/signer.go`. Because the answer comes from the string alone,
it is identical in every binary and needs no registration step.

(`keytypes` declares the Falcon-1024 key/signature sizes as literals for the same
reason — to stay free of algorithm-family imports — with a consistency test that
cross-checks them against `lsig/falcon1024/family`.)

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

Two tempting unifications, both wrong, for the same reason — a call site would be
forced to depend on something it doesn't have.

**1. Route by `BaseKeyType` instead of `RoutingFamily()` (tried, abandoned).** The
idea was to make Resolve key off the `BaseKeyType` edge. It breaks on
guarded/sentry accounts: a guarded provider's `BaseKeyType` is
`aplane.falcon1024.v1`, but that is its *component-signing primitive*, not its
routing authority — the guarded account owns its own keygen, mnemonic-handler
registration, and metadata under its own family (this is internal handler
routing only; guarded/corridor accounts still report
`SupportsMnemonicImport() == false`, i.e. no user mnemonic import). Routing
metadata by `BaseKeyType` returned Falcon's metadata (wrong signature size) for
guarded keys. `BaseKeyType` cannot express the delegate-vs-self distinction;
`RoutingFamily()` can. **Route by `RoutingFamily()`.**

**2. Classify by provider capability instead of string switches (correctly never
shipped).** After the assembly hooks made Behave capability-driven, the natural
next step looked like moving Classify the same way — let the provider declare "I
am a guarded account, my sentry component is X." It would break every
classification call site that has no provider: the client config, the keystore,
the cache. Those run in binaries that may not register guarded providers at all.
Classification must answer from the string, in any binary. **Classify by string
in the neutral leaf.**

The shape of both mistakes is identical: collapsing an axis onto a mechanism
whose precondition (a populated registry / a provider instance) isn't met where
that axis is actually called. The current split is not three accidents — it is
three answers to three different availability constraints.

---

## Not a fourth axis: the metadata display fallback

`internal/algorithm/metadata.go`'s `GetMetadata` resolves via `ResolveByKeyType`
(the Resolve axis). When that fails it has a best-effort `hasFamilyPrefix`
fallback that substring-matches the key type against registered families. This is
**display-only** — it exists so an unregistered template (e.g. a keystore template
not loaded in this process, queried client-side for a display color) still gets a
plausible color. Keygen and signing never reach it: they always have a registered
provider or a stored base key type in the key file. It is kept (rather than
removed) because removing it cleanly would require threading the stored base key
type through the `addressdisplay.ColorFormatter` callback — a cross-layer change
not worth it for a cosmetic fallback. It is a fallback on the Resolve axis, not a
separate resolution mechanism.

---

## See also

- `docs/ARCH_LSIG_PROVIDER.md` — the Resolve-axis registry, in detail.
- `docs/ARCH_SENTRY.md` — the guarded/sentry account choreography.
- `docs/DEV_KEYTYPES.md` — how to add a key type (where these axes become
  concrete decisions).
