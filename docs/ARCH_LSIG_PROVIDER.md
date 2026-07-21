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
│                            │    │ lsig/falcon1024_ed25519/ Dual DSA         │
│                            │    │ lsig/ecdsak1/             secp256k1 DSA   │
│                            │    │ lsig/corridor/           Corridor sentry  │
│                            │    │ lsig/falcon1024_guarded/ Guarded sentry   │
│                            │    │ lsig/ed25519lsig/        Ed25519 LSig     │
│ Sources:                   │    │ lsig/composeddsa/                         │
│   Optional library YAML    │    │   └── template.go      YAML compositions  │
│   Identity key type state  │    │ Shared TEAL substitution:                 │
│                            │    │   tealtemplate (legacy)                     │
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
imported with `apstore template import`. Installed templates are stored encrypted
under identity key type state via `internal/templatestore/` and loaded by the
signer template reload coordinator.

**Scoping invariant:** compiled providers are shared product capabilities, while
runtime-added `.template` files are identity-scoped signer state. In practice:

- default-enabled built-in key types are available wherever their providers are registered
- library-visible built-in key types require an enabled identity state record before generation surfaces expose them
- runtime-added `.template` files live under `identities/<identity>/keytypes/` with adjacent state records and affect only that identity runtime when enabled; disabled installed templates remain stored but are skipped during reload

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

**Restore precedence invariant:** when a backup carries bundled template YAML,
restore resolves template installation/provenance against local destination-state
precedence rather than the source system's original provenance:

- if the signer-data library has a YAML definition for that `key_type`, that
  definition is authoritative
- otherwise, if an identity-scoped keystore `.template` exists for the
  `key_type`, that definition is used
- otherwise, the bundled template may be installed when no authoritative local
  source exists

This means restore does not care whether the backup source originally obtained a
key type from an identity-local template or signer-data library template. The
destination system uses whatever local definition is available under the
precedence rules above.
The key file remains the signing authority: generic v1 signing-metadata keys can
sign from stored bytecode/runtime args, and DSA v1 signing-metadata keys require
the stored `base_key_type` signer-side provider rather than the composed
template provider for their `key_type`.

At `apstore backup import` time, bundled generic/composed template YAML is also
recompiled with the key's stored creation parameters and must reproduce the
key's stored LogicSig bytecode before the archive is admitted.

Filtered views into the registry are provided by `internal/genericlsig` (Template
interface) and `internal/logicsigdsa` (LogicSigDSA interface). Shared off-curve
LogicSig salting lives in `internal/lsigsalt`. Shared LogicSig dummy transaction
construction and the `TxLsigBudget` constant live in `internal/lsig/`;
dummy-fee calculation and signer planning live in `internal/signing/` and
`internal/signerapp/signing/`. The single registration entry point is
`lsig/all.go`.

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
| `internal/lsigsalt` | Shared off-curve LogicSig salting |
| `internal/tealtemplate` | Strict `$variable` constant-block template renderer |
|  `internal/tealtemplate` (legacy.go) | Generated-mode restricted list expansion and legacy scalar substitution utilities |
| `internal/keytypecatalog` | Compiled key type visibility catalog |
| `internal/keytypestate` | Identity-scoped state records for library-visible compiled providers and installed templates |
| `internal/templatelibrary` | Optional library list/install workflow |
| `internal/templatestore` | Encrypted template file storage |
| `internal/lsig` | Dummy transaction construction and LogicSig budget constant |
| `internal/signing` | Dummy fee distribution and transaction signing helpers |
| `lsig/composeddsa` | Generic runtime-compiled LogicSig composer used by Falcon, Ed25519, and ecdsak1 composed templates, and parser/provider builder for composed DSA YAML templates |
| `lsig/falcon1024` | Falcon-1024 DSA base provider; `v1/composer.go` is the Falcon-specific wrapper over `lsig/composeddsa` |
| `lsig/falcon1024_ed25519` | Dual Falcon-1024 / Ed25519 DSA provider |
| `lsig/ed25519lsig` | Library-visible Ed25519 LogicSig DSA provider, also used by composed templates such as `aplane.ed25519-allowlist.v1` |
| `lsig/ecdsak1` | secp256k1 LogicSig DSA provider |
| `lsig/falcon1024_guarded` | Falcon-1024 guarded-account DSA providers (`aplane.falcon1024-sentry-ed25519.v1`, `aplane.falcon1024-sentry-falcon1024.v1`) |
| `internal/boundedadmin` | External Falcon contract-admin identity, transcript, artifact, and ceremony validation |
| `lsig/corridor` | Always-sentry corridor DSA provider (`aplane.corridor.v1`): Falcon-1024 user + sentry signatures with recipient-corridor and rekey policy |
| `lsig/sentryaccount` | Shared client-safe helpers for guarded sentry-account providers |
| `lsig/dsafamily` | Client-safe registration descriptor shared by DSA families (signer-side descriptor in `lsig/dsafamily/signerreg`) |
| `lsig/signerreg` | Registers all built-in LogicSig signer-side providers with their catalog availability |
| `internal/signerapp/templates` | Keystore template reload coordinator and state/fingerprint policy |
| `lsig/generictemplate` | Parser/provider builder for generic YAML templates |
| `library/templates/` | Optional importable template library |
| `lsig/all.go` | Registration entry point |

## Two Categories of LogicSigs

| Category | Example Key Types | Has Keys | Signing |
|----------|-------------------|----------|---------|
| `generic_lsig` | `aplane.timed-allowlist.v1`, `aplane.allowlist.v1` after template import | No | TEAL-only authorization |
| `dsa_lsig` | `aplane.falcon1024.v1`, `aplane.ed25519.v1`, `aplane.falcon1024_ed25519.v1`, `aplane.ecdsak1.v1`, bounded `aplane.falcon1024-allowlist-alock.v1`, guarded `aplane.falcon1024-sentry-ed25519.v1`, `aplane.falcon1024-sentry-falcon1024.v1`, `aplane.corridor.v1`; `aplane.falcon1024-allowlist.v1` after new-store default install, `aplane.ed25519-allowlist.v1` after template import | Yes | Cryptographic signature |

## Interface Hierarchy

```
LSigProvider (base interface - ALL providers implement this)
├── Identity
│   ├── KeyType() string        "aplane.falcon1024.v1", "aplane.timed-allowlist.v1"
│   ├── RoutingFamily() string  "aplane.falcon1024" (registry routing key; see ARCH_KEYTYPE_AXES.md)
│   └── Version() int           1, 2, etc.
├── Category
│   └── Category() string       "generic_lsig" or "dsa_lsig"
├── Display
│   ├── DisplayName() string    "Falcon-1024", "Timed Allowlist"
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
| DSA (multi-signature-arg form, e.g. `aplane.ecdsak1.v1`) | `[r, s]` |
| DSA with runtime args | `[signature args..., runtime args...]` |

**Invariant**: Arg order is determined by `RuntimeArgs()` schema order at key
generation time, not map iteration. v1 signing-metadata key files persist that
runtime arg schema and use the stored copy at signing time. LogicSig key files
without `salt_counter`, or whose stored bytecode derives an on-curve LogicSig
address, are rejected during key scan. LogicSig key files without
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
    KeyType:     "aplane.falcon1024-hashlock.v1",
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
#pragma version 12
bytecblock 0x<hash>                // strict template constants
byte 0x41504c414e455f4c5349475f53414c545f56315f005f454e44
                                    // generated off-curve salt marker
pop

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

The example above is renderer output, not user-authored YAML source. Template
authors write symbolic `$hash` references; validation rejects raw
`bytecblock`/`intcblock` declarations and numeric constant references in
user-authored TEAL so the renderer can own generated constants and any
derivation-version salt anchor layout.

In the implementation, salted address derivation patches the compiled bytecode,
not the TEAL source. The salt anchor style is part of each versioned provider's
derivation contract. Template-backed programs with omitted
`derivation_version` are unsalted: APlane compiles the template as written,
performs no byte patching, and accepts generation only when the unmodified
bytecode already derives an off-curve LogicSig address. Template-backed
programs with `derivation_version: 1` use a stack-neutral generated marker
preamble (`byte 0x41504c414e455f4c5349475f53414c545f56315f005f454e44; pop`),
while template-backed programs with `derivation_version: 2` append a trailing
dead-code `bytecblock 0x00`. Provider-owned bare DSA versions may explicitly
choose a reference layout such as a fixed `bytecblock 0x00` preamble.
`aplane.falcon1024.v1` uses the Algorand Foundation
reference-compatible fixed `bytecblock` preamble, `aplane.ecdsak1.v1` uses a
fixed `bytecblock` preamble, generic or composed-template programs with
`derivation_version: 1` use the generated marker, and generic or
composed-template programs with `derivation_version: 2` use a trailing
dead-code `bytecblock`. `internal/lsigsalt` couples each salted style to the
locator used by `FindOffCurve`, which tries counter values `0..255` and returns
the first bytecode whose LogicSig address is off-curve. The bytecblock locator
verifies the preamble immediately after the TEAL version varint and never scans
later bytes. The marker locator matches
exactly one APlane-owned marker with 24 fixed bytes around the mutable counter;
that exact-marker match gives a collision margin of at least `2^-192`, so
shortening the marker is a derivation-contract change. The marker locator must
not match generic `pushbytes 0x00` occurrences. The trailing bytecblock locator
requires the salt block to be the final encoded instruction and patches its
single byte entry. The selected counter is persisted in the key file as
`salt_counter`; salt style is not exposed through public wire DTOs.

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
contract-admin metadata, and post-signing size.

Bounded emission preserves the base/template's existing resolved salt style; it
does not invent a bounded salt. The fixed bare-DSA bytecblock layout remains
incompatible with suffix composition, while `StylePushbytes`, trailing
bytecblock, and unsalted layouts retain their existing derivation contracts.
See [ARCH_BOUNDED_DSA.md](ARCH_BOUNDED_DSA.md).

### Salting Rationale

LogicSig addresses are derived from the compiled program hash. A random program
hash can decode as a valid Ed25519 public key, which would make the LogicSig
address also look like an ordinary signature account address. APlane therefore
treats "off-curve" as a key-file invariant for generated LogicSigs: generation
must produce bytecode whose address cannot correspond to an Ed25519 public key,
and scan/restore paths reject stored LogicSig bytecode that violates that
invariant.

The salt byte is only an address-derivation knob. It must change the compiled
program bytes, and therefore the LogicSig address, without changing the
authorization policy. APlane patches compiled bytecode rather than source so
the stored bytecode is the signing authority and the recorded `salt_counter`
reproduces the exact address chosen at generation time.

Provider-owned DSA programs may use a fixed `bytecblock 0x00` preamble because
APlane controls the entire generated program shape. In that setting the
`bytecblock` salt slot is part of the versioned provider derivation contract,
the locator can demand the slot immediately after the TEAL version varint, and
there is no user-authored suffix that depends on byte constant layout.

Template-backed programs use the generated `byte ...; pop` marker instead. A
`bytecblock` salt would still be present in bytecode and could still vary the
address, but it would also install byte-constant evaluator state until another
`bytecblock` replaces it. Template rendering already generates `bytecblock` and
`intcblock` declarations for symbolic `$name` references, and user-authored
template TEAL is intentionally relocatable: it cannot contain raw
`bytecblock`/`intcblock` declarations or numeric `bytec`/`intc` references.
Using a stack-neutral marker keeps the salt out of that constant-block system.
After the marker executes it has no stack or constant-pool effect, so salting
does not depend on where generated template constants are placed or which
constants the template uses.

Templates that omit `derivation_version` do not use a generated salt anchor at
all. That mode is deterministic and has no semantic footprint, but generation
can fail if the unmodified program hash is on-curve. Bundled and production
template-derived key types should therefore declare `derivation_version: 2`
unless they intentionally want the unsalted contract, which is selected by
omitting `derivation_version`.

This is a conservative compatibility choice. A raw/expert template mode could
relax the constant-block restrictions in the future, but that would be a new
derivation contract. The existing strict/generated template modes keep APlane
responsible for constant-block layout and keep salting independent of template
semantics.

**Note**: Falcon-1024 verification uses the native `falcon_verify` opcode (TEAL v12+), which takes:
1. Message (32 bytes) - the transaction ID
2. Signature (variable, typically ~1230–1280 bytes) - Falcon-1024 compressed signature
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
derivation_version: 2
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
derivation_version: 2
template_type: composed
base_key_type: aplane.falcon1024.v1
template_mode: strict
publisher: aplane
family: falcon1024-hashlock
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

Both composed templates and generic templates are stored by `apstore` via
`templatestore` under identity key type state. The template store's storage
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
admin slot reserved, and `apbounded-admin` independently validates the finalized
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
    ├── keytypecatalog.Register(aplane.falcon1024-sentry-ed25519.v1, library)
    │   └── falcon1024guarded.RegisterClient()
    ├── keytypecatalog.Register(aplane.falcon1024-sentry-falcon1024.v1, library)
    │   └── falcon1024guarded.RegisterClient()
    ├── keytypecatalog.Register(aplane.corridor.v1, library)
    │   └── corridor.RegisterClient()
    ├── keytypecatalog.Register(aplane.falcon1024_ed25519.v1, library)
    │   └── falcon1024_ed25519.RegisterClient()
    ├── keytypecatalog.Register(aplane.ecdsak1.v1, library)
    │   └── ecdsak1.RegisterClient()
    └── keytypecatalog.Register(aplane.ed25519.v1, library)
        └── ed25519lsig.RegisterClient()

lsig/signerreg.RegisterSigner()
    ├── lsig.RegisterClient()
    └── family signerreg RegisterSigner() calls add signing, keygen, and mnemonic handlers
```

Runtime templates (from keystore) are loaded after unlock:
```go
signertemplates.NewManager(paths).RegisterKeystoreTemplates(identityID, masterKey)
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
| `aplane.falcon1024_ed25519.v1` | `aplane.falcon1024_ed25519` | `dsa_lsig` | Library-visible dual Falcon + Ed25519 DSA |
| `aplane.ecdsak1.v1` | `aplane.ecdsak1` | `dsa_lsig` | Library-visible secp256k1 DSA |
| `aplane.falcon1024-sentry-ed25519.v1` | `aplane.falcon1024-sentry-ed25519` | `dsa_lsig` | Library-visible guarded account: Falcon-1024 user + Ed25519 sentry component signatures |
| `aplane.falcon1024-sentry-falcon1024.v1` | `aplane.falcon1024-sentry-falcon1024` | `dsa_lsig` | Library-visible guarded account: Falcon-1024 user + Falcon-1024 sentry component signatures |
| `aplane.falcon1024-allowlist-alock.v1` | `aplane.falcon1024-allowlist-alock` | `dsa_lsig` | Library-visible bounded1 fixed allowlist with Falcon spending and external Falcon contract-admin authorization |
| `aplane.corridor.v1` | `aplane.corridor` | `dsa_lsig` | Library-visible guarded account: Falcon-1024 user + sentry signatures with recipient corridor and sentry-authorized rekey |
| `aplane.ed25519.v1` | `aplane.ed25519` | `dsa_lsig` | Library-visible Ed25519 LogicSig DSA provider; distinct from native `ed25519` |
| `aplane.timed-allowlist.v1` | `timed-allowlist` | `generic_lsig` | Optional template library: timed recipient allowlist |
| `aplane.allowlist.v1` | `allowlist` | `generic_lsig` | Optional template library: restrict outgoing transfers to fixed recipient addresses |
| `aplane.htlc.v1` | `htlc` | `generic_lsig` | Optional template library: hash-locked payment |
| `aplane.ed25519-allowlist.v1` | `ed25519-allowlist` | `dsa_lsig` | Optional bounded1 composed template: Ed25519 + fixed receiver allowlist |
| `aplane.falcon1024-allowlist.v1` | `falcon1024-allowlist` | `dsa_lsig` | Bundled bounded1 composed template: installed/enabled for new signer identities; Falcon + fixed receiver allowlist |
| `aplane.falcon1024-allowlist.v2` | `falcon1024-allowlist` | `dsa_lsig` | Optional bounded1 composed template: Falcon + signer-derived Merkle receiver proof |
| `aplane.falcon1024-hashlock.v1` | `falcon1024-hashlock` | `dsa_lsig` | Optional bounded1 composed template: Falcon + runtime preimage gate on spend and rekey |
| `aplane.falcon1024-timelock.v1` | `falcon1024-timelock` | `dsa_lsig` | Optional bounded1 composed template: Falcon + validity-round gate on spend and rekey |

## Related Documentation

- [ARCH_KEYTYPE_AXES.md](ARCH_KEYTYPE_AXES.md) - The three key-type resolution axes (Resolve / Classify / Behave); this document is the Resolve-axis detail
- [ARCH_CRYPTO.md](ARCH_CRYPTO.md) - Full cryptographic subsystem documentation
- [DEV_KEYTYPES.md](DEV_KEYTYPES.md) - Unified guide for adding key types and LogicSig templates
