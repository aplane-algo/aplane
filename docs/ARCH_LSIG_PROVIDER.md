# LSig Provider Architecture

This document describes the LogicSig provider architecture.

## Package Map

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
│                            │    │ lsig/falcon1024_guarded/ Guarded sentry   │
│                            │    │ lsig/ed25519lsig/        Ed25519 LSig     │
│ Sources:                   │    │ lsig/composeddsa/                         │
│   Optional library YAML    │    │   └── template.go      YAML compositions  │
│   Identity key type state  │    │ Shared TEAL substitution:                 │
│                            │    │   tealtemplate scalar helpers               │
│                            │    │                                           │
│ Category: generic_lsig     │    │ Sources:                                  │
└────────────────────────────┘    │   Hardcoded Go (v1)                       │
                                  │   Optional library YAML                   │
                                  │   Identity key type state                 │
                                  │                                           │
                                  │ Category: dsa_lsig                        │
                                  └───────────────────────────────────────────┘
```

Compiled DSA providers are registered from code and product visibility is
recorded in `internal/keytypecatalog`. Optional YAML templates are install
sources under `library/templates/`; generic and composed DSA templates are
imported with `apadmin template import`. Installed templates are stored encrypted
under identity key type state via `internal/templatestore/` and loaded by the
signer template reload coordinator.

**Scoping invariant:** compiled providers are shared product capabilities, while
runtime-added `.template` files belong to the one durable `default` activation set. In practice:

- default-enabled built-in key types are available wherever their providers are registered
- library-visible built-in key types require an enabled identity state record before generation surfaces expose them
- runtime-added `.template` files live under `identities/default/keytypes/` with adjacent state records and affect the product runtime when enabled; disabled installed templates remain stored but are skipped during reload

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
The single registration entry point is `lsig/all.go`.

## Package Summary

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
| `internal/keytypestate` | Identity-scoped state record format and persistence primitives for library-visible compiled providers and installed templates |
| `internal/templatelibrary` | Library parsing and sole feature-level template/key-type mutation coordinator |
| `internal/templatestore` | Encrypted template file format and persistence primitives |
| `internal/signing` | Resource-dummy construction/signing and common transaction helpers |
| `lsig/composeddsa` | Generic runtime-compiled LogicSig composer used by DSA-backed composed templates, and parser/provider builder for composed DSA YAML templates |
| `lsig/falcon1024` | Falcon-1024 DSA base provider; `v1/composer.go` is the Falcon-specific wrapper over `lsig/composeddsa` |
| `lsig/ed25519lsig` | Library-visible Ed25519 LogicSig DSA provider |
| `lsig/falcon1024_guarded` | Falcon/Falcon guarded-account DSA provider (`aplane.falcon1024-sentry1024.v1`) |
| `internal/boundedadmin` | External Falcon contract-admin identity, transcript, artifact, and ceremony validation |
| `library/templates/aplane.corridor.v1.yaml` | Optional schema-v2 bounded-sentry Corridor profile; compiled by `lsig/composeddsa` after identity-local install |
| `lsig/sentryaccount` | Shared client-safe helpers for guarded sentry-account providers |
| `lsig/dsafamily` | Client-safe registration descriptor shared by DSA families (signer-side descriptor in `lsig/dsafamily/signerreg`) |
| `lsig/signerreg` | Registers all built-in LogicSig signer-side providers with their catalog availability |
| `internal/signerapp/templates` | Read-only keystore template reload coordinator and state/fingerprint policy |
| `lsig/generictemplate` | Parser/provider builder for generic YAML templates |
| `library/templates/` | Optional importable template library |
| `lsig/all.go` | Registration entry point |

## Two Categories of LogicSigs

| Category | Example Key Types | Has Keys | Signing |
|----------|-------------------|----------|---------|
| `generic_lsig` | `aplane.htlc.v1` after template import | No | TEAL-only authorization |
| `dsa_lsig` | `aplane.falcon1024.v1`, `aplane.ed25519.v1`, bounded `aplane.falcon1024-allowlist-alock.v1`, guarded `aplane.falcon1024-sentry1024.v1`, `aplane.corridor.v1`; bundled Falcon templates after install | Yes | Cryptographic signature |

## Interface Hierarchy

```
LSigProvider (base interface - ALL providers implement this)
├── Identity
│   ├── KeyType() string        "aplane.falcon1024.v1", "aplane.htlc.v1"
│   ├── RoutingFamily() string  "aplane.falcon1024" (registry routing key; see ARCH_KEYTYPE_AXES.md)
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
└── DeriveLsig(publicKey, params) (bytecode, address, error)
          │
          ▼
MnemonicProvider (extends SigningProvider)
├── MnemonicScheme() string         "bip39", "algorand"
└── MnemonicWordCount() int         24, 25
```

Private-key key generation, signing, and mnemonic conversion are deliberately
outside this client-visible registry. Signer-side startup wires those operations
through the `internal/signing`, `internal/keygen`, and `internal/mnemonic`
registries.

## Unified Registry

The `lsigprovider` package is the **single source of truth** for all LogicSig providers:

```go
// Registration - called from provider packages
func Register(p LSigProvider) {
    keyType := normalize(p.KeyType())
    providers.Set(keyType, p)

    // Apply stored algod client for late-registered providers
    if storedClient != nil {
        if configurable, ok := p.(AlgodConfigurable); ok {
            configurable.SetAlgodClient(storedClient)
        }
    }
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

## BuildArgs: Explicit Arg Ordering

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

## Composed DSA

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
    Base:        FalconBase,
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

### Bounded1 Composer Extension

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

### Salting Rationale

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

## Template Systems

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
- `generated` mode is reserved for bounded source generation such as
  `{{range @recipients}} ... {{.}} ... {{end}}`; arbitrary Go-template syntax
  is rejected.

### Generic Templates (`lsig/generictemplate`)

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

### Composed DSA Templates (`lsig/composeddsa`)

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

Both composed templates and generic templates are stored by the signer through
`templatelibrary`, which coordinates the primitive `templatestore` and
`keytypestate` writes. The template store's storage
type vocabulary is limited to `generic` and `composed`; compiled providers use
identity key type state with `SourceCompiled` and are exposed to admin/library
clients as `compiled_provider` without writing an encrypted `.template` file. At runtime
`internal/signerapp/templates` walks the identity state once, decrypts enabled
installed templates, and dispatches each template to the generic or composed
parser/provider builder.

## Transaction-Aware Bounded Arguments

Most DSA providers produce a fixed argument list from one key. Bounded1 starts
with that base layout, then statically orders signer-derived Layer-3 arguments,
caller runtime Layer-3 arguments, and an optional final contract-admin slot.
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

## Registration Flow

```
lsig.RegisterClient()
    │
    ├── keytypecatalog.Register(aplane.falcon1024.v1, default_enabled)
    │   └── falcon.RegisterClient()
    │       ├── v1.RegisterLogicSigDSA() → Falcon1024V1
    │       └── ... (metadata, address derivation)
    ├── keytypecatalog.Register(aplane.falcon1024-sentry1024.v1, library)
    │   └── falcon1024guarded.RegisterClient()
    └── keytypecatalog.Register(aplane.ed25519.v1, library)
        └── ed25519lsig.RegisterClient()

lsig/signerreg.RegisterSigner()
    ├── lsig.RegisterClient()
    └── family signerreg RegisterSigner() calls add signing, keygen, and mnemonic handlers
```

Runtime templates (from keystore) are loaded after unlock:
```go
signertemplates.NewManager(paths).RegisterKeystoreTemplates(identityID, keyring)
```

## Algod Client Configuration

Providers that need runtime TEAL compilation implement `AlgodConfigurable`:

```go
type AlgodConfigurable interface {
    SetAlgodClient(client *algod.Client)
}

// Called during startup
lsigprovider.ConfigureAlgodClient(client)

// Stored for late-registered providers (e.g., keystore templates)
```

For composed templates, `base_key_type` selects the signing provider while
the YAML `family` field names the template's own version line. The two are
independent: `base_key_type: aplane.falcon1024.v1` plus
`family: falcon1024-allowlist` yields a `key_type` of
`<publisher>.falcon1024-allowlist.vN` that signs with Falcon-1024, while
`base_key_type: aplane.ed25519.v1` plus `family: ed25519-allowlist`
yields a template key type that signs with Ed25519 inside a LogicSig.

## Key Types Summary

| Key Type | Key-type family | Category | Description |
|----------|--------|----------|-------------|
| `aplane.falcon1024.v1` | `aplane.falcon1024` | `dsa_lsig` | Default-enabled pure Falcon signature |
| `aplane.falcon1024-sentry1024.v1` | `aplane.falcon1024-sentry1024` | `dsa_lsig` | Library-visible guarded account: Falcon-1024 user + Falcon-1024 sentry component signatures |
| `aplane.falcon1024-allowlist-alock.v1` | `aplane.falcon1024-allowlist-alock` | `dsa_lsig` | Library-visible bounded1 fixed allowlist with Falcon spending and external Falcon contract-admin authorization |
| `aplane.corridor.v1` | `corridor` | `dsa_lsig` | Optional bounded1 composed template: Falcon spending, framework Merkle recipient policy, sentry-gated spend, and external-admin pure rekey |
| `aplane.ed25519.v1` | `aplane.ed25519` | `dsa_lsig` | Library-visible Ed25519 LogicSig DSA provider; distinct from native `ed25519` |
| `aplane.htlc.v1` | `htlc` | `generic_lsig` | Optional template library: hash-locked payment |
| `aplane.falcon1024-allowlist.v1` | `falcon1024-allowlist` | `dsa_lsig` | Bundled bounded1 composed template: installed/enabled in the product identity for new signer stores; Falcon + fixed receiver allowlist |
| `aplane.falcon1024-allowlist.v2` | `falcon1024-allowlist` | `dsa_lsig` | Optional bounded1 composed template: Falcon + signer-derived Merkle receiver proof |
| `aplane.falcon1024-timelock.v1` | `falcon1024-timelock` | `dsa_lsig` | Optional bounded1 composed template: Falcon + validity-round gate on spend and rekey |

## Related Documentation

- [ARCH_KEYTYPE_AXES.md](ARCH_KEYTYPE_AXES.md) - The three key-type resolution axes (Resolve / Classify / Behave); this document is the Resolve-axis detail
- [ARCH_CRYPTO.md](ARCH_CRYPTO.md) - Full cryptographic subsystem documentation
- [DEV_KEYTYPES.md](DEV_KEYTYPES.md) - Unified guide for adding key types and LogicSig templates
