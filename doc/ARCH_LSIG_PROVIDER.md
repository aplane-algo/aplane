# LSig Provider Architecture

This document describes the LogicSig provider architecture after the unified registry refactoring.

## Package Map

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          UNIFIED REGISTRY                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│  internal/lsigprovider/     Single registry for ALL LogicSig providers      │
│    ├── provider.go          Interface definitions (LSigProvider, etc.)      │
│    ├── types.go             ParameterDef, RuntimeArgDef, constants          │
│    └── registry.go          Register(), Get(), GetSigning(), GetMnemonic()  │
└─────────────────────────────────────────────────────────────────────────────┘
         ▲                                              ▲
         │ registers                                    │ registers
         │                                              │
┌────────┴───────────────────┐    ┌─────────────────────┴─────────────────────┐
│   GENERIC TEMPLATES        │    │   DSA PROVIDERS                           │
├────────────────────────────┤    ├───────────────────────────────────────────┤
│ lsig/timelock/             │    │ lsig/falcon1024/                          │
│ lsig/hashlock/             │    │   ├── v1.go            Pure Falcon DSA    │
│ lsig/multitemplate/        │    │   ├── composer.go      ComposedDSA engine │
│                            │    │   ├── hashlock_v1.go   Go-defined comp.   │
│ TEAL-only authorization,   │    │   └── timelock_v1.go   Legacy precompiled │
│ no cryptographic keys      │    │                                           │
│                            │    │ lsig/falcon1024template/                  │
│ Sources:                   │    │   └── YAML-defined compositions           │
│   Hardcoded Go templates   │    │                                           │
│   Embedded YAML            │    │ Shared TEAL substitution:                 │
│   Keystore templates       │    │   internal/tealsubst/                     │
│                            │    │                                           │
│ Category: generic_lsig     │    │ Sources:                                  │
└────────────────────────────┘    │   Hardcoded Go (v1, hashlock, timelock)   │
                                  │   Embedded YAML                           │
                                  │   Keystore templates                      │
                                  │                                           │
                                  │ Category: dsa_lsig                        │
                                  └───────────────────────────────────────────┘
```

Both categories support three provider sources: hardcoded Go types, embedded YAML
templates (compile-time via `//go:embed`), and keystore templates (runtime via
`apstore add-template`). YAML templates are stored encrypted via
`internal/templatestore/` and loaded by their respective packages
(`multitemplate` and `falcon1024template`).

Filtered views into the registry are provided by `internal/genericlsig` (Template
interface) and `internal/logicsigdsa` (LogicSigDSA interface). Shared LogicSig
utilities (dummy transactions, budget calculation) live in `internal/lsig/`.
The single registration entry point is `lsig/all.go`.

## Package Summary

| Package | Role |
|---------|------|
| `internal/lsigprovider` | **Unified registry** for all providers |
| `internal/genericlsig` | Template interface, type-filtered lookups |
| `internal/logicsigdsa` | DSA interface, type-filtered lookups |
| `internal/tealsubst` | Shared TEAL `@variable` substitution utilities |
| `internal/templatestore` | Encrypted template file storage |
| `internal/lsig` | Shared utilities (dummy txns, budget calculation) |
| `lsig/falcon1024` | Falcon-1024 DSA: base provider, ComposedDSA engine, Go-defined compositions |
| `lsig/falcon1024template` | YAML loader for Falcon compositions (embedded + keystore) |
| `lsig/timelock` | Generic timelock template |
| `lsig/hashlock` | Generic hashlock template |
| `lsig/multitemplate` | YAML loader for generic templates (embedded + keystore) |
| `lsig/all.go` | Registration entry point |

## Two Categories of LogicSigs

| Category | Example Key Types | Has Keys | Signing |
|----------|-------------------|----------|---------|
| `generic_lsig` | `timelock-v1`, `hashlock-v1` | No | TEAL-only authorization |
| `dsa_lsig` | `falcon1024-v1`, `falcon1024-hashlock-v1` | Yes | Cryptographic signature |

## Interface Hierarchy

```
LSigProvider (base interface - ALL providers implement this)
├── Identity
│   ├── KeyType() string        "falcon1024-v1", "timelock-v1"
│   ├── Family() string         "falcon1024", "timelock"
│   └── Version() int           1, 2, etc.
├── Category
│   └── Category() string       "generic_lsig" or "dsa_lsig"
├── Display
│   ├── DisplayName() string    "Falcon-1024", "Timelock"
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
├── GenerateKeypair(seed) (pubKey, privKey, error)
├── Sign(privateKey, message) (signature, error)
└── DeriveLsig(publicKey, params) (bytecode, address, error)
          │
          ▼
MnemonicProvider (extends SigningProvider)
├── MnemonicScheme() string         "bip39", "algorand"
├── MnemonicWordCount() int         24, 25
├── SeedFromMnemonic(words, passphrase) ([]byte, error)
└── EntropyToMnemonic(entropy) ([]string, error)
```

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

The `genericlsig` and `logicsigdsa` packages now delegate to `lsigprovider` and provide type-filtered views:

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
| DSA (no TEAL suffix) | `[signature]` |
| DSA (with TEAL suffix) | `[signature, preimage, ...]` |

**Invariant**: Arg order is determined by `RuntimeArgs()` schema order, not map iteration. The schema is the canonical source of ordering.

```go
// Generic template - no signature
func (t *HashlockTemplate) BuildArgs(sig []byte, args map[string][]byte) ([][]byte, error) {
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

// DSA - signature first, then runtime args
func (c *ComposedDSA) BuildArgs(sig []byte, args map[string][]byte) ([][]byte, error) {
    if sig == nil {
        return nil, fmt.Errorf("signature is required for DSA LogicSig")
    }
    result := [][]byte{sig}
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

**Note**: Unknown arg rejection is handled by `ValidateLsigArgs()` on the client side before calling `BuildArgs()`. This separation allows the server to focus on assembly while the client provides user-friendly validation errors.

## ComposedDSA

The `ComposedDSA` combines a Falcon DSA base with an optional TEAL suffix using `@variable` substitution:

```go
FalconHashlockV1 = NewComposedDSA(ComposedDSAConfig{
    KeyType:     "falcon1024-hashlock-v1",
    FamilyName:  "falcon1024",
    Version:     1,
    DisplayName: "Falcon-1024 Hashlock",
    Base:        FalconBase,
    Params: []lsigprovider.ParameterDef{{
        Name: "hash", Type: "bytes", Required: true, MaxLength: 64,
    }},
    RuntimeArgs: []lsigprovider.RuntimeArgDef{{
        Name: "preimage", Type: "bytes", Required: true,
    }},
    TEALSuffix: `txn RekeyTo
global ZeroAddress
==
assert
txn CloseRemainderTo
global ZeroAddress
==
assert
arg 1
sha256
byte @hash
==
assert`,
})
```

Generated TEAL structure:
```
#pragma version 12
bytecblock 0x00                    // counter byte (0-255)

// TEAL suffix (with @variables substituted)
txn RekeyTo; global ZeroAddress; ==; assert
txn CloseRemainderTo; global ZeroAddress; ==; assert
arg 1; sha256; byte 0x<hash>; ==; assert

// DSA signature verification (Falcon-1024 native opcode)
txn TxID
arg 0
byte 0x<pubkey>
falcon_verify
```

**Note**: Falcon-1024 verification uses the native `falcon_verify` opcode (TEAL v12+), which takes:
1. Message (32 bytes) - the transaction ID
2. Signature (variable, typically ~1230–1280 bytes) - Falcon-1024 compressed signature
3. Public key (1793 bytes) - Falcon-1024 public key

## Template Systems

Both generic and Falcon templates use the same `@variable` substitution system
provided by `internal/tealsubst/`.

### Generic Templates (multitemplate)

YAML-based TEAL templates with parameter substitution:

```yaml
schema_version: 1
family: custom-escrow
version: 1
display_name: "Custom Escrow"
parameters:
  - name: recipient
    type: address
    required: true
teal: |
  txn Receiver
  addr @recipient
  ==
```

### Falcon Templates (falcon1024template)

YAML-based DSA compositions with parameterized TEAL suffix:

```yaml
schema_version: 1
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
  byte @hash
  ==
  assert
```

Both Falcon templates and generic templates are stored by `apstore` via `templatestore`,
and loaded at runtime by their respective packages (`falcon1024template` and `multitemplate`).

## Registration Flow

```
lsig.RegisterAll()
    │
    ├── falcon.RegisterAll()
    │   ├── RegisterLogicSigDSA()      → Falcon1024V1
    │   ├── RegisterFalconTimelockV1() → FalconTimelockV1
    │   ├── RegisterFalconHashlockV1() → FalconHashlockV1 (ComposedDSA)
    │   └── ... (metadata, signing, keygen, mnemonic)
    │
    ├── falcon1024template.RegisterTemplates()
    │   └── Load embedded YAML → Create ComposedDSA → Register
    │
    ├── timelock.RegisterTemplate()    → TimelockTemplate
    ├── hashlock.RegisterTemplate()    → HashlockTemplate
    └── multitemplate.RegisterTemplates() → Load embedded YAML templates
```

Runtime templates (from keystore) are loaded after unlock:
```go
multitemplate.RegisterKeystoreTemplates(identityID, masterKey)
falcon1024template.RegisterKeystoreTemplates(identityID, masterKey)
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

## Key Types Summary

| Key Type | Family | Category | Description |
|----------|--------|----------|-------------|
| `timelock-v1` | `timelock` | `generic_lsig` | Funds locked until round |
| `hashlock-v1` | `hashlock` | `generic_lsig` | Funds released with preimage |
| `falcon1024-v1` | `falcon1024` | `dsa_lsig` | Pure Falcon signature |
| `falcon1024-timelock-v1` | `falcon1024` | `dsa_lsig` | Falcon + timelock (legacy) |
| `falcon1024-hashlock-v1` | `falcon1024` | `dsa_lsig` | Falcon + hashlock (ComposedDSA) |

## Related Documentation

- [ARCH_CRYPTO.md](ARCH_CRYPTO.md) - Full cryptographic subsystem documentation
- [DEV_New_DSA_LSig.md](DEV_New_DSA_LSig.md) - Guide for adding new DSA providers
- [DEV_New_GenericLSig.md](DEV_New_GenericLSig.md) - Guide for adding generic templates
- [DEV_MULTITEMPLATE_LSIG.md](DEV_MULTITEMPLATE_LSIG.md) - YAML template development
