# Cryptographic Subsystem

> **Note**: This document covers the DSA provider system that enables aPlane's modular signature scheme support. For a high-level system overview, see [`ARCH_OVERVIEW.md`](ARCH_OVERVIEW.md).

## Overview

The cryptographic subsystem supports three fundamentally different types of authorization:

1. **Ed25519 (Native)** - Built into the Algorand protocol. Signatures go directly in `SignedTxn.Sig`.
2. **LogicSig-based DSAs** - Post-quantum schemes (Falcon-1024, etc.) implemented via TEAL programs. Cryptographic signatures go in `LogicSig.Args[0]`.
3. **Generic LogicSigs** - TEAL programs that authorize transactions without cryptographic signatures (e.g., timelock, hashlock). Authorization is purely through TEAL evaluation.

This architectural difference is reflected in the code organization:

```
internal/signing/              <- Signing providers and key file operations
    ├── provider.go            # Provider interface
    ├── registry.go            # Provider registry
    └── ed25519/               # Native Ed25519 provider

internal/genericlsig/          <- Generic LogicSig template registry
    ├── template.go            # Template interface + ParameterDef
    └── registry.go            # Self-registering template registry

lsig/                          <- All LogicSig providers (SINGLE IMPORT POINT)
    ├── all.go                 # Import all providers here
    ├── falcon1024/            # Falcon-1024 post-quantum DSA
    │   ├── v1.go              # LogicSigDSA registration
    │   ├── keys/              # Key processing, derivation
    │   ├── signing/           # Signing provider
    │   ├── derivation/        # TEAL template generation
    │   └── ...
    └── timelock/              # Timelock generic LogicSig template
        └── template.go        # Template implementation + registration

internal/lsig/                 <- Shared LogicSig utilities
    └── wrapper.go             # Dummy transaction wrapping
```

Ed25519 is native to Algorand and uses `internal/signing/ed25519/`. The `lsig/` directory contains schemes that work around protocol limitations using LogicSig.

### Three Types of LogicSig Providers

| Type | Example | Signature | File Format |
|------|---------|-----------|-------------|
| **Native** | Ed25519 | Goes in `SignedTxn.Sig` | `.key` (encrypted private key) |
| **DSA-based LogicSig** | Falcon-1024 | Cryptographic signature in `LogicSig.Args[0]` | `.key` (encrypted private key) |
| **Generic LogicSig** | Timelock | No signature (TEAL-only authorization) | `.key` (encrypted bytecode + parameters) |

### LSig Provider Architecture

The `lsigprovider` package is a **unified registry** for all LogicSig providers. Both generic templates and DSA providers register directly with this single registry:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           UNIFIED REGISTRY                                       │
│                         internal/lsigprovider                                    │
│  ┌───────────────────────────────────────────────────────────────────────────┐  │
│  │  Register(provider)  → adds provider to single registry                   │  │
│  │  Get(keyType)        → returns LSigProvider or nil                        │  │
│  │  GetSigning(keyType) → returns SigningProvider (via type assertion)       │  │
│  │  GetMnemonic(keyType)→ returns MnemonicProvider (via type assertion)      │  │
│  │  GetAll()            → returns all registered providers                   │  │
│  └───────────────────────────────────────────────────────────────────────────┘  │
│         ▲                         ▲                         ▲                    │
│         │ registers               │ registers               │ registers          │
└─────────┼─────────────────────────┼─────────────────────────┼────────────────────┘
          │                         │                         │
┌─────────┴─────────┐   ┌──────────┴──────────┐   ┌──────────┴───────────────────┐
│ GENERIC TEMPLATES │   │  DSA PROVIDERS      │   │  COMPOSED TEMPLATES          │
├───────────────────┤   ├─────────────────────┤   ├──────────────────────────────┤
│ lsig/timelock/    │   │ lsig/falcon1024/    │   │ lsig/falcon1024template/     │
│ lsig/hashlock/    │   │  ├─ v1.go           │   │  └─ provider.go              │
│ lsig/multitemplate│   │  ├─ timelock_v1.go  │   │                              │
│                   │   │  ├─ composer.go     │   │ Loads YAML, creates          │
│ Category:         │   │  └─ hashlock_v1.go  │   │ ComposedDSA instances        │
│ generic_lsig      │   │                     │   │                              │
│                   │   │ Category: dsa_lsig  │   │ Uses parameterized TEAL      │
└───────────────────┘   └─────────────────────┘   └──────────────────────────────┘
                                  │
                                  │ uses
                                  ▼
                        ┌─────────────────────┐
                        │ TEAL SUFFIX SYSTEM  │
                        │ internal/tealsubst/ │
                        │  └─ suffixes/       │
                        │     RegisterAll()   │
                        └─────────────────────┘
```

The `genericlsig` and `logicsigdsa` packages now provide **type-filtered views** into the unified registry rather than maintaining separate registries.

**Interface Hierarchy:**

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│   LSigProvider (base - ALL providers implement this)                            │
│   ├─ KeyType(), Family(), Version()                                             │
│   ├─ Category()  →  "generic_lsig" or "dsa_lsig"                                │
│   ├─ DisplayName(), Description(), DisplayColor()                               │
│   ├─ CreationParams()         ← parameters for LSig creation                    │
│   ├─ ValidateCreationParams()                                                   │
│   ├─ RuntimeArgs()            ← args needed at signing time                     │
│   └─ BuildArgs(sig, args)     ← assembles LogicSig.Args in correct order        │
│         │                                                                       │
│         ▼                                                                       │
│   SigningProvider (extends LSigProvider)                                        │
│   ├─ CryptoSignatureSize()                                                      │
│   ├─ GenerateKeypair(seed)                                                      │
│   ├─ Sign(privateKey, message)                                                  │
│   └─ DeriveLsig(publicKey, params)                                              │
│         │                                                                       │
│         ▼                                                                       │
│   MnemonicProvider (extends SigningProvider)                                    │
│   ├─ MnemonicScheme()         ← "bip39" or "algorand"                           │
│   ├─ MnemonicWordCount()      ← 24 for Falcon, 25 for Ed25519                   │
│   ├─ SeedFromMnemonic()                                                         │
│   └─ EntropyToMnemonic()                                                        │
└─────────────────────────────────────────────────────────────────────────────────┘
```

**BuildArgs**: Encapsulates the arg ordering convention:
- Generic LSigs: `BuildArgs(nil, args)` → `[runtime args...]`
- DSA LSigs: `BuildArgs(sig, args)` → `[signature, runtime args...]`

**Key Types and Families:**

| Key Type | Family | Category | Description |
|----------|--------|----------|-------------|
| `timelock-v1` | `timelock` | `generic_lsig` | Funds locked until specific round |
| `hashlock-v1` | `hashlock` | `generic_lsig` | Funds released with preimage |
| `falcon1024-v1` | `falcon1024` | `dsa_lsig` | Pure post-quantum Falcon signature |
| `falcon1024-timelock-v1` | `falcon1024` | `dsa_lsig` | Falcon + timelock (legacy hybrid) |
| `falcon1024-hashlock-v1` | `falcon1024` | `dsa_lsig` | Falcon + hashlock (ComposedDSA) |

**Key insight:** All `falcon1024-*` types share the same **family** (`falcon1024`) because they use the same cryptographic primitive. They differ in their TEAL suffix composition:
- `falcon1024-v1`: Pure signature verification
- `falcon1024-timelock-v1`: Legacy hybrid with round-based lock
- `falcon1024-hashlock-v1`: ComposedDSA with hashlock TEAL suffix (requires preimage runtime arg)

---

## Explicit Registration Architecture

LogicSig providers use an **explicit registration architecture** with `sync.Once` for thread-safe idempotency. This makes dependencies and initialization order visible in code.

### Adding a New Provider: 2 Changes

To add a new LogicSig provider (e.g., Falcon-512):

1. **Create your provider package** in `lsig/<provider>/` with a `RegisterAll()` function
2. **Add a registration call** to `lsig/all.go`

```go
// lsig/all.go - Add registration call
func RegisterAll() {
    registerAllOnce.Do(func() {
        falcon.RegisterAll()
        falcon512.RegisterAll()  // NEW - add this call
        // ...
    })
}
```

### How It Works

Each provider package exports explicit `Register*()` functions with `sync.Once`:

```go
// lsig/falcon1024/v1.go
var registerLogicSigDSAOnce sync.Once

func RegisterLogicSigDSA() {
    registerLogicSigDSAOnce.Do(func() {
        logicsigdsa.Register(&Falcon1024V1{})
    })
}
```

Aggregator functions call subordinates in correct order:

```go
// lsig/falcon1024/register.go
func RegisterAll() {
    registerAllOnce.Do(func() {
        RegisterLogicSigDSA()           // MUST be first - others depend on it
        RegisterMetadata()
        falconsigning.RegisterProvider()
        keygen.RegisterGenerator()
        mnemonic.RegisterHandler()
        falconkeys.RegisterProcessors()
    })
}
```

Entry points call top-level aggregators:

```go
// cmd/apsignerd/providers.go
func RegisterProviders() {
    lsig.RegisterAll()    // All Falcon + LogicSig templates
    ed25519.RegisterAll() // All Ed25519 components
}
```

All downstream systems query registries dynamically:
- **TUI key type selection**: Queries `keymgmt.GetValidKeyTypes()` for versioned types
- **Family lookups**: Uses exact-match keyType → family mappings

---

## LogicSigDSA Interface

For LogicSig-based schemes, a second interface handles the cryptographic primitives and LogicSig derivation.

**File**: `internal/logicsigdsa/dsa.go`

```
+-----------------------------------------------------------------+
|                      LogicSigDSA Registry                       |
|                  internal/logicsigdsa                           |
+-----------------------------------------------------------------+
|  falcon1024-v1   |  falcon1024-v2  |  falcon-512-v1 |  ...    |
|  (lsig/falcon1024)|    (future)      |    (future)    |         |
+-----------------------------------------------------------------+
                              ^
                    Version is part of identity
                    (different versions = different DSAs)
```

### Key Design Principles

| Principle | Description |
|-----------|-------------|
| **Versioned Identity** | Key types include version: `falcon1024-v1` |
| **Self-Registration** | Providers register family mappings in `init()` |
| **Single Interface** | One interface for all LogicSig-based DSAs |
| **Security Boundary** | Private keys never leave Signer |
| **Runtime Compilation** | TEAL is compiled via algod at derivation time |

### Interface Definition

**File**: `internal/logicsigdsa/dsa.go`

```go
type LogicSigDSA interface {
    // Identity
    KeyType() string  // e.g., "falcon1024-v1"
    Family() string   // e.g., "falcon1024" (algorithm family without version)
    Version() int     // e.g., 1 (derivation version number)

    // Metadata (for UI and fee estimation)
    CryptoSignatureSize() int // Max signature bytes (1280 for Falcon-1024)
    MnemonicScheme() string  // "bip39" or "algorand"
    MnemonicWordCount() int  // 24 for BIP-39
    DisplayColor() string    // ANSI color code ("33" = yellow)

    // Cryptographic operations
    GenerateKeypair(seed []byte) (publicKey, privateKey []byte, err error)
    DeriveLsig(publicKey []byte) (lsigBytecode []byte, address string, err error)
    Sign(privateKey []byte, message []byte) (signature []byte, err error)
}
```

### Why Version in Identity?

The same mnemonic with different derivation versions produces **different addresses**:

```
Mnemonic: "word1 word2 ... word24"
    |
    +-> falcon1024-v1 -> Address: ABCD...
    |
    +-> falcon1024-v2 -> Address: WXYZ... (different!)
```

Different LogicSig templates = different addresses = fundamentally different key types.

---

## Registry API

**File**: `internal/logicsigdsa/registry.go`

### Core Functions

```go
// Registration (called from init())
// Automatically registers keyType → family mapping from dsa.KeyType() and dsa.Family()
// All inputs are normalized to lowercase
Register(dsa LogicSigDSA)

// Manual family mapping (rarely needed - Register() handles this automatically)
RegisterFamily(keyType, family string)

// Lookup (all inputs normalized to lowercase)
Get(keyType string) LogicSigDSA           // Direct lookup
GetAll() []LogicSigDSA                    // All registered (sorted)
GetKeyTypes() []string                    // All key types (sorted)
IsRegistered(keyType string) bool         // Check if registered

// Family lookup (exact match, not prefix matching)
GetFamily(keyType string) string          // "falcon1024-v1" -> "falcon1024"
```

### Type Checking

```go
// Check if key type uses LogicSig (only versioned types like "falcon1024-v1")
IsLogicSigType(keyType string) bool
```

### Helper Functions

```go
// Metadata access (requires versioned key type)
GetCryptoSignatureSize(keyType string) int
GetDisplayColor(keyType string) string
GetMnemonicScheme(keyType string) string
GetMnemonicWordCount(keyType string) int
```

---

## Transaction Signing

Transaction signing uses a **server-side architecture** where the server (apsignerd) handles all complexity: key type detection, message derivation, dummy transaction creation, fee pooling, and group ID computation.

### Group Signing Flow (Primary)

The recommended approach is to send transactions to the `/sign` endpoint. The client is completely key-type agnostic:

```
+--------------------------------------------------------------+
|                     apshell (Client)                          |
|                                                              |
|  1. Build transaction(s) with SuggestedParams                |
|  2. Send GroupSignRequest to /sign                           |
|     - { auth_address, txn_bytes_hex } for each txn           |
|  3. Receive pre-assembled signed transactions                |
|  4. Submit all signed bytes to algod                         |
+--------------------------------------------------------------+
                          |
                          |  POST /sign
                          |  GroupSignRequest
                          v
+--------------------------------------------------------------+
|                   apsignerd (Server)                          |
|                                                              |
|  1. Decode transactions                                      |
|  2. Look up key types for each auth_address                  |
|  3. Analyze group for LogicSig budget requirements           |
|  4. Add dummy transactions if needed                         |
|  5. Pool fees onto first transaction (dummies have fee=0)    |
|  6. Compute group ID across all transactions                 |
|  7. Request approval (TUI or policy)                         |
|  8. For each transaction, sign by key type:                  |
|     - Ed25519: sign full txn bytes → SignedTxn.Sig           |
|     - LogicSig DSA: sign txn ID hash → LogicSig.Args[0]      |
|     - Generic LogicSig: attach bytecode + ordered args       |
|  9. Return msgpack-encoded SignedTxn for each               |
+--------------------------------------------------------------+
```

**Key benefit**: The client never needs to know the key type, signature size, or whether dummies are needed. See [`ARCH_TXNFLOW.md`](ARCH_TXNFLOW.md) for full protocol details.

---

## Falcon Implementation

### File Structure

```
lsig/falcon1024/
├── core.go              # falconCore - shared cryptographic operations
├── v1.go                # Falcon1024V1 - registers with logicsigdsa + family mappings
├── register.go          # Convenience import (imports all sub-packages)
├── metadata.go          # Algorithm metadata registration
├── family/
│   └── family.go        # Constants (key sizes, signature size, display color)
├── derivation/
│   ├── versions.go      # Version constants
│   └── v1/derive.go     # FROZEN v1 LogicSig derivation
├── keys/
│   ├── derive.go        # Address derivation utilities
│   ├── generation.go    # Key pair generation
│   ├── init.go          # Package initialization
│   └── processor.go     # Key processing and address derivation
├── keygen/
│   └── generator.go     # Key generation (uses logicsigdsa)
├── mnemonic/
│   └── handler.go       # BIP-39 mnemonic handling
└── signing/
    └── provider.go      # Signing provider (uses logicsigdsa)
```

### Core Implementation

**`lsig/falcon1024/core.go`** - Shared operations:

```go
type falconCore struct{}

// Metadata methods use constants from family package
func (c *falconCore) CryptoSignatureSize() int { return family.MaxSignatureSize }
func (c *falconCore) MnemonicScheme() string   { return family.MnemonicScheme }
func (c *falconCore) MnemonicWordCount() int   { return family.MnemonicWordCount }
func (c *falconCore) DisplayColor() string     { return family.DisplayColor }

func (c *falconCore) GenerateKeypair(seed []byte) ([]byte, []byte, error) {
    kp, err := falcongo.GenerateKeyPair(seed)
    if err != nil {
        return nil, nil, err
    }
    return kp.PublicKey[:], kp.PrivateKey[:], nil
}

func (c *falconCore) Sign(privateKey, message []byte) ([]byte, error) {
    var priv falcongo.PrivateKey
    copy(priv[:], privateKey)
    kp := falcongo.KeyPair{PrivateKey: priv}
    return kp.Sign(message)
}
```

**`lsig/falcon1024/family/family.go`** - Shared constants:

```go
const Name = "falcon1024"

const (
    PublicKeySize  = 1793
    PrivateKeySize = 2305
)

const MaxSignatureSize = 1280 // Falcon-1024 max signature size

const (
    MnemonicScheme    = "bip39"
    MnemonicWordCount = 24
)

const DisplayColor = "33" // ANSI yellow
```

**`lsig/falcon1024/v1.go`** - Version-specific with explicit registration:

```go
type Falcon1024V1 struct {
    falconCore  // Embed shared operations
}

func (f *Falcon1024V1) KeyType() string { return "falcon1024-v1" }
func (f *Falcon1024V1) Family() string  { return family.Name }
func (f *Falcon1024V1) Version() int    { return 1 }

func (f *Falcon1024V1) DeriveLsig(publicKey []byte) ([]byte, string, error) {
    var pub falcongo.PublicKey
    copy(pub[:], publicKey)

    lsigAcct, err := v1.DerivePQLogicSig(pub)
    if err != nil {
        return nil, "", err
    }

    addr, _ := lsigAcct.Address()
    return lsigAcct.Lsig.Logic, addr.String(), nil
}

var registerLogicSigDSAOnce sync.Once

// RegisterLogicSigDSA registers the DSA with the logicsigdsa registry.
// IMPORTANT: This must be called before other registrations that depend on it.
func RegisterLogicSigDSA() {
    registerLogicSigDSAOnce.Do(func() {
        logicsigdsa.Register(&Falcon1024V1{})
    })
}
```

### Runtime TEAL Compilation

Falcon-1024 uses the **ComposedDSA** architecture with runtime TEAL compilation via algod:

```go
// DeriveLsig uses runtime TEAL compilation for safety
func (f *Falcon1024V1) DeriveLsig(publicKey []byte, params map[string]string) ([]byte, string, error) {
    if f.algodClient == nil {
        return nil, "", fmt.Errorf("algod client not set")
    }

    // Use ComposedDSA with no TEAL suffix (pure Falcon-1024)
    comp := newFalconV1Composed()
    comp.SetAlgodClient(f.algodClient)
    return comp.DeriveLsig(publicKey, nil)
}
```

**Note**: The `lsig/falcon1024/derivation/v1/derive.go` file contains legacy precompiled derivation code preserved for backward-compatibility testing only. Production code uses runtime compilation.

---

## Dummy Transaction Wrapping (Server-Side)

**File**: `internal/lsig/wrapper.go`

Post-quantum signatures are large (Falcon: ~1280 bytes). Algorand limits LogicSig + args to 1000 bytes per transaction. The server automatically adds "dummy" transactions to provide additional budget.

These functions are used **server-side** by apsignerd when processing `/sign` and `/plan` requests:

```go
// CreateDummyTransactions creates zero-fee dummy self-payment transactions
func CreateDummyTransactions(count int, sp types.SuggestedParams) ([]types.Transaction, error)

// CalculateDummiesNeeded determines dummy count
// Formula: ceil((sigSize * lsigCount) / TxLsigBudget) - lsigCount
func CalculateDummiesNeeded(lsigCount int, sigSize int) int

// SignDummyTransactions signs dummies with embedded LogicSig
func SignDummyTransactions(dummyTxns []types.Transaction) ([][]byte, error)
```

**Foreign transaction LSig budget:** For multi-party signing, foreign transactions (those without `auth_address`) can include an `lsig_size` hint. The server uses this hint in the dummy calculation alongside locally-known LSig sizes. Foreign entries with `lsig_size > 0` are included in the LSig fee distribution pool.

### Example

For 1 Falcon transaction (1280-byte signature):
- Budget needed: 1280 bytes
- Budget per txn: 1000 bytes
- Transactions needed: ceil(1280/1000) = 2
- Dummies needed: 2 - 1 = 1

The client receives the signed dummy transactions as part of the `/sign` response and submits them along with the main transaction(s).

---

## Mixed Atomic Groups

Mixed atomic groups containing both Ed25519 and Falcon transactions **are fully supported**. This enables DeFi protocol integrations where:
- User signs with post-quantum LogicSig (Falcon-1024)
- Escrows/contracts sign with Ed25519 or LogicSig
- All execute atomically in a single group

### Server-Side Handling (Primary Path)

When transactions are sent to the `/sign` endpoint, the server automatically handles mixed groups:

1. **Analyzes** the group to identify LogicSig vs Ed25519 transactions
2. **Calculates** total LogicSig budget needed
3. **Adds dummies** if the group budget is insufficient
4. **Pools fees** across LogicSig transactions
5. **Signs** each transaction with the appropriate method
6. **Returns** all signed transactions (including any dummies)

The key insight is that **only LogicSig transactions consume the LogicSig budget**. Ed25519 transactions in the same group effectively "donate" their budget capacity to LogicSig transactions.

### Example: Mixed Group

Group with 3 transactions:
- Txn 1: Ed25519 (user payment)
- Txn 2: Falcon-1024 (user swap authorization)
- Txn 3: Ed25519 (escrow release)

Calculation:
- Group budget: 3 x 1000 = 3000 bytes
- LogicSig budget: 1 x 1280 = 1280 bytes (only the Falcon txn)
- 1280 < 3000 → **No dummies needed**

### Client-Side Usage

**File**: `internal/signing/multi.go`

The `SignAndSubmitViaGroup()` function provides the primary client interface:

```
SignAndSubmitViaGroup()
    |
    +-- Build SignRequest for each transaction
    |
    +-- Call RequestGroupSign() -> /sign endpoint
    |   (server handles dummies, fees, group ID)
    |
    +-- Decode signed transactions
    |
    +-- Submit to network
```

### Edge Cases

| Scenario | Result |
|----------|--------|
| All Ed25519 | Works (no LogicSig budget needed) |
| All Falcon | Works (dummies added as needed) |
| Mixed Ed25519 + Falcon | Works (budget shared) |
| Pre-grouped with sufficient capacity | Works (group ID preserved) |
| Pre-grouped with insufficient capacity | **Error** (can't add dummies without breaking group ID) |
| Group > 16 transactions after dummies | **Error** (Algorand limit) |

---

## Key Material Handling

**File**: `lsig/falcon1024/signing/provider.go`

Signer uses the signing provider to load and sign with keys:

```go
type FalconKeyMaterial struct {
    PrivateKey []byte  // Raw private key bytes
}

type FalconProvider struct{}

func (p *FalconProvider) LoadKeysFromData(data []byte) (*signing.KeyMaterial, error) {
    // Parse JSON, decode hex private key
    // Uses the exact versioned key type from the stored key file
    return &signing.KeyMaterial{
        Type:  keyPair.KeyType,  // e.g., "falcon1024-v1" from key file
        Value: &FalconKeyMaterial{PrivateKey: privBytes},
    }, nil
}

func (p *FalconProvider) SignMessage(key *signing.KeyMaterial, message []byte) ([]byte, error) {
    km := key.Value.(*FalconKeyMaterial)
    // Use the key's actual stored type to look up the correct DSA
    dsa := logicsigdsa.Get(key.Type)
    return dsa.Sign(km.PrivateKey, message)
}

func (p *FalconProvider) ZeroKey(key *signing.KeyMaterial) {
    if km, ok := key.Value.(*FalconKeyMaterial); ok {
        util.ZeroBytes(km.PrivateKey)
        km.PrivateKey = nil
    }
    key.Type = ""
    key.Value = nil
}
```

---

# User Guide: Building a New LogicSig Provider

This guide walks through creating a complete LogicSig provider for a new post-quantum algorithm.

## Quick Start

Adding a new provider requires:
1. **Creating your provider package** in `lsig/<provider>/` with `Register*()` functions
2. **Adding a registration call** to `lsig/all.go`

That's it! The explicit registration architecture handles everything else.

## Step 1: Create the Provider Package Structure

Create the following directory structure (using Falcon-512 as an example):

```
lsig/falcon512/
├── family/
│   └── family.go        # Constants (key sizes, signature size, color)
├── derivation/
│   ├── versions.go      # Version constants
│   └── v1/
│       └── derive.go    # FROZEN v1 LogicSig derivation
├── keys/
│   ├── derive.go        # Address derivation
│   ├── generation.go    # Key pair generation
│   ├── register.go      # Registration function
│   └── processor.go     # Key processing
├── keygen/
│   └── generator.go     # Key generation (general registry)
├── mnemonic/
│   └── handler.go       # Mnemonic handling (general registry)
├── signing/
│   └── provider.go      # Signing provider (general registry)
├── core.go              # Shared LogicSigDSA implementation
├── v1.go                # Version 1 DSA with self-registration
├── metadata.go          # Algorithm metadata registration
└── register.go          # Convenience import for all sub-packages
```

## Step 2: Define Family Constants

**`lsig/falcon512/family/family.go`**:

```go
package family

// Name is the algorithm family identifier (used in registries)
const Name = "falcon-512"

// Key sizes
const (
    PublicKeySize  = 897   // Falcon-512 public key size
    PrivateKeySize = 1281  // Falcon-512 private key size
)

// MaxSignatureSize is the maximum signature size for Falcon-512
const MaxSignatureSize = 690

// Mnemonic configuration
const (
    MnemonicScheme    = "bip39"
    MnemonicWordCount = 24
)

// DisplayColor is the ANSI color code for TUI display
const DisplayColor = "35" // Magenta
```

## Step 3: Implement the Core DSA

**`lsig/falcon512/core.go`**:

```go
package falcon512

import (
    "github.com/aplane-algo/aplane/lsig/falcon512/family"
    "your-falcon512-library/falcon512go"
)

// falcon512Core provides shared implementation for all Falcon-512 versions
type falcon512Core struct{}

// Metadata methods (same for all versions)
func (c *falcon512Core) CryptoSignatureSize() int { return family.MaxSignatureSize }
func (c *falcon512Core) MnemonicScheme() string   { return family.MnemonicScheme }
func (c *falcon512Core) MnemonicWordCount() int   { return family.MnemonicWordCount }
func (c *falcon512Core) DisplayColor() string     { return family.DisplayColor }

// GenerateKeypair generates a Falcon-512 key pair from a seed
func (c *falcon512Core) GenerateKeypair(seed []byte) ([]byte, []byte, error) {
    kp, err := falcon512go.GenerateKeyPair(seed)
    if err != nil {
        return nil, nil, err
    }
    return kp.PublicKey[:], kp.PrivateKey[:], nil
}

// Sign signs a message with a Falcon-512 private key
func (c *falcon512Core) Sign(privateKey, message []byte) ([]byte, error) {
    var priv falcon512go.PrivateKey
    copy(priv[:], privateKey)
    kp := falcon512go.KeyPair{PrivateKey: priv}
    return kp.Sign(message)
}
```

## Step 4: Implement Version 1 DSA with Explicit Registration

**`lsig/falcon512/v1.go`**:

```go
package falcon512

import (
    "fmt"
    "sync"

    "github.com/aplane-algo/aplane/lsig/falcon512/derivation/v1"
    "github.com/aplane-algo/aplane/lsig/falcon512/family"
    "github.com/aplane-algo/aplane/internal/logicsigdsa"

    "your-falcon512-library/falcon512go"
)

// Falcon512V1 implements LogicSigDSA for Falcon-512 with v1 derivation
type Falcon512V1 struct {
    falcon512Core  // Embed shared operations
}

// KeyType returns the full versioned identifier
func (f *Falcon512V1) KeyType() string { return "falcon-512-v1" }

// Family returns the algorithm family
func (f *Falcon512V1) Family() string { return family.Name }

// Version returns the derivation version number
func (f *Falcon512V1) Version() int { return 1 }

// DeriveLsig derives LogicSig bytecode and address from public key
func (f *Falcon512V1) DeriveLsig(publicKey []byte) ([]byte, string, error) {
    if len(publicKey) != family.PublicKeySize {
        return nil, "", fmt.Errorf("invalid public key size: expected %d, got %d",
            family.PublicKeySize, len(publicKey))
    }

    var pub falcon512go.PublicKey
    copy(pub[:], publicKey)

    lsigAcct, err := v1.DerivePQLogicSig(pub)
    if err != nil {
        return nil, "", fmt.Errorf("failed to derive LogicSig: %w", err)
    }

    addr, err := lsigAcct.Address()
    if err != nil {
        return nil, "", fmt.Errorf("failed to derive address: %w", err)
    }

    return lsigAcct.Lsig.Logic, addr.String(), nil
}

var registerLogicSigDSAOnce sync.Once

// RegisterLogicSigDSA registers the DSA with the logicsigdsa registry.
// IMPORTANT: This must be called before other registrations that depend on it.
func RegisterLogicSigDSA() {
    registerLogicSigDSAOnce.Do(func() {
        logicsigdsa.Register(&Falcon512V1{})
    })
}
```

## Step 5: Implement Runtime TEAL Derivation

DSA providers use **ComposedDSA** for runtime TEAL compilation via algod:

**`lsig/falcon512/v1.go`** (DeriveLsig method):

```go
// DeriveLsig derives the LogicSig bytecode and address from a public key.
// Uses runtime TEAL compilation via the ComposedDSA system.
func (f *Falcon512V1) DeriveLsig(publicKey []byte, params map[string]string) ([]byte, string, error) {
    if f.algodClient == nil {
        return nil, "", fmt.Errorf("algod client not set: configure teal_compiler_algod_url")
    }

    // Use ComposedDSA with empty TEAL suffix for pure DSA
    comp := NewComposedDSA(ComposedDSAConfig{
        KeyType:     "falcon-512-v1",
        FamilyName:  family.Name,
        Version:     1,
        DisplayName: "Falcon-512",
        Description: "Post-quantum signature using Falcon-512",
        Base:        Falcon512Base,
        TEALSuffix:  nil,        // No TEAL suffix = pure DSA
        Params:      nil,
        RuntimeArgs: nil,
    })
    comp.SetAlgodClient(f.algodClient)
    return comp.DeriveLsig(publicKey, nil)
}
```

**Important**: Implement `SetAlgodClient()` (via `AlgodConfigurable` interface) to receive the algod client at server startup.

## Step 6: Register with General Registries

Each sub-package exports explicit `Register*()` functions:

**`lsig/falcon512/metadata.go`**:

```go
package falcon512

import (
    "sync"

    "github.com/aplane-algo/aplane/internal/algorithm"
    "github.com/aplane-algo/aplane/lsig/falcon512/family"
)

type Falcon512Metadata struct{}

func (m *Falcon512Metadata) Family() string               { return family.Name }
func (m *Falcon512Metadata) CryptoSignatureSize() int     { return family.MaxSignatureSize }
func (m *Falcon512Metadata) MnemonicWordCount() int       { return family.MnemonicWordCount }
func (m *Falcon512Metadata) MnemonicScheme() string       { return family.MnemonicScheme }
func (m *Falcon512Metadata) RequiresLogicSig() bool       { return true }
func (m *Falcon512Metadata) CurrentLsigVersion() int      { return 1 }
func (m *Falcon512Metadata) SupportedLsigVersions() []int { return []int{1} }
func (m *Falcon512Metadata) DefaultDerivation() string    { return "bip39-standard" }
func (m *Falcon512Metadata) DisplayColor() string         { return family.DisplayColor }

var registerMetadataOnce sync.Once

func RegisterMetadata() {
    registerMetadataOnce.Do(func() {
        algorithm.RegisterMetadata(&Falcon512Metadata{})
    })
}
```

**`lsig/falcon512/keygen/generator.go`** - Exports `RegisterGenerator()` for `internal/keygen`
**`lsig/falcon512/mnemonic/handler.go`** - Exports `RegisterHandler()` for `internal/mnemonic`
**`lsig/falcon512/signing/provider.go`** - Exports `RegisterProvider()` for `internal/signing`

Each uses the same pattern: implement the interface and export a `Register*()` function with `sync.Once`.

## Step 7: Create Aggregator Function

**`lsig/falcon512/register.go`**:

```go
// Package falcon512 provides Falcon-512 post-quantum signature support.
//
// Call RegisterAll() to register all Falcon-512 components:
//
//     falcon512.RegisterAll()
package falcon512

import (
    "sync"

    "github.com/aplane-algo/aplane/lsig/falcon512/keygen"
    falcon512keys "github.com/aplane-algo/aplane/lsig/falcon512/keys"
    "github.com/aplane-algo/aplane/lsig/falcon512/mnemonic"
    falcon512signing "github.com/aplane-algo/aplane/lsig/falcon512/signing"
)

var registerAllOnce sync.Once

// RegisterAll registers all Falcon-512 components with their respective registries.
// This is idempotent and safe to call multiple times.
//
// Registration order is significant:
// 1. LogicSigDSA - MUST be first, others depend on logicsigdsa.Get()
// 2. Metadata - algorithm metadata for display
// 3. Signing provider - for transaction signing
// 4. Key generator - for key creation
// 5. Mnemonic handler - for mnemonic handling
// 6. Key processors - for key file processing
func RegisterAll() {
    registerAllOnce.Do(func() {
        RegisterLogicSigDSA()           // MUST be first
        RegisterMetadata()
        falcon512signing.RegisterProvider()
        keygen.RegisterGenerator()
        mnemonic.RegisterHandler()
        falcon512keys.RegisterProcessors()
    })
}
```

## Step 8: Add Registration Call to lsig/all.go

**`lsig/all.go`**:

```go
package lsig

import (
    "sync"

    falcon "github.com/aplane-algo/aplane/lsig/falcon1024"
    falcon512 "github.com/aplane-algo/aplane/lsig/falcon512"  // NEW - add this import
    // ... other imports
)

var registerAllOnce sync.Once

func RegisterAll() {
    registerAllOnce.Do(func() {
        // DSA-based LogicSig providers
        falcon.RegisterAll()
        falcon512.RegisterAll()  // NEW - add this call

        // Generic LogicSig templates
        // ...
    })
}
```

**This is the only file outside your provider package that needs modification.**

## Step 9: Verify Registration

```bash
# Build and verify
go build ./...

# Check apsignerd recognizes the new provider
./apsignerd --print-manifest | jq '.logicsig_dsas'

# Should show:
# [
#   { "key_type": "falcon1024-v1", ... },
#   { "key_type": "falcon-512-v1", ... }
# ]

# Test key generation
./apadmin --batch generate falcon-512

# Run tests
go test ./lsig/falcon512/...
```

## Checklist Summary

| Step | File/Action | Purpose |
|------|-------------|---------|
| 1 | Create `lsig/falcon512/` | Package structure |
| 2 | `family/family.go` | Constants |
| 3 | `core.go` | Shared crypto operations |
| 4 | `v1.go` | DSA + `RegisterLogicSigDSA()` with `sync.Once` |
| 5 | `derivation/v1/derive.go` | Frozen TEAL template |
| 6 | `metadata.go`, `keygen/`, `mnemonic/`, `signing/` | `Register*()` functions with `sync.Once` |
| 7 | `register.go` | `RegisterAll()` aggregator |
| 8 | **`lsig/all.go`** | **Add registration call (ONLY external change)** |
| 9 | Test | Verify registration |

---

## Adding a New Derivation Version

When the LogicSig template must change (e.g., TEAL version upgrade):

### 1. Freeze Current Version

The existing `v1/derive.go` is **never modified**.

### 2. Create New Version

```go
// lsig/falcon1024/derivation/v2/derive.go
// FROZEN after release
func DerivePQLogicSig(pub falcongo.PublicKey) (crypto.LogicSigAccount, error) {
    // New TEAL template
}
```

### 3. Create New DSA

```go
// lsig/falcon1024/v2.go
type Falcon1024V2 struct {
    falconCore  // Same crypto, different derivation
}

func (f *Falcon1024V2) KeyType() string { return "falcon1024-v2" }
func (f *Falcon1024V2) Family() string  { return family.Name }
func (f *Falcon1024V2) Version() int    { return 2 }

func (f *Falcon1024V2) DeriveLsig(publicKey []byte) ([]byte, string, error) {
    return v2.DerivePQLogicSig(pub)  // Use v2
}

var registerLogicSigDSAV2Once sync.Once

// RegisterLogicSigDSAV2 registers the v2 DSA with the logicsigdsa registry.
func RegisterLogicSigDSAV2() {
    registerLogicSigDSAV2Once.Do(func() {
        logicsigdsa.Register(&Falcon1024V2{})
    })
}
```

### 4. Update RegisterAll()

Add the new version to the aggregator:

```go
// lsig/falcon1024/register.go
func RegisterAll() {
    registerAllOnce.Do(func() {
        RegisterLogicSigDSA()    // v1
        RegisterLogicSigDSAV2()  // v2 - add this
        // ... rest of registrations
    })
}
```

### 5. UI Selection Update

Users explicitly select the key type version when generating keys. Both versions appear in the TUI selection list:
- `falcon1024-v1`
- `falcon1024-v2`

Existing v1 keys continue to work - each key file stores its exact type.

---

# User Guide: Building a Generic LogicSig Template

Generic LogicSig templates are different from DSA-based providers. They authorize transactions through TEAL program evaluation only, without requiring cryptographic signatures. Examples include timelock (funds released after a specific round) and hashlock (funds released when revealing a preimage).

## Quick Start

Adding a new generic LogicSig template requires:
1. **Creating your template package** in `lsig/<template>/` with a `RegisterTemplate()` function
2. **Adding a registration call** to `lsig/all.go`

That's it! The explicit registration architecture handles everything else.

## Key Differences from DSA Providers

| Aspect | DSA Provider (Falcon) | Generic Template (Timelock) |
|--------|----------------------|----------------------------|
| **Registers with** | `logicsigdsa`, `keygen`, `mnemonic`, `signing`, etc. | `genericlsig` only |
| **Has private key** | Yes | No |
| **Has mnemonic** | Yes | No |
| **User parameters** | None (derived from seed) | Yes (recipient, unlock_round, etc.) |
| **File format** | `.key` (encrypted private key) | `.key` (encrypted bytecode + parameters) |
| **Signing mode** | `/sign` endpoint | `/sign` endpoint |
| **TEAL source** | Verifies cryptographic signature | Evaluates conditions (time, recipient, etc.) |

## Step 1: Create the Template Package

Create a single file implementing the `genericlsig.Template` interface:

**`lsig/timelock/template.go`**:

```go
package timelock

import (
    "context"
    "encoding/base64"
    "fmt"
    "strconv"
    "sync"

    "github.com/aplane-algo/aplane/internal/genericlsig"

    "github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
)

// Family and version constants
const (
    family     = "timelock"
    versionV1  = "timelock-v1"
    versionPfx = "timelock-v"
)

// TimelockTemplate implements genericlsig.Template
type TimelockTemplate struct{}

// Compile-time check
var _ genericlsig.Template = (*TimelockTemplate)(nil)

// Identity methods
func (t *TimelockTemplate) KeyType() string { return versionV1 }
func (t *TimelockTemplate) Family() string  { return family }
func (t *TimelockTemplate) Version() int    { return 1 }

// Display methods
func (t *TimelockTemplate) DisplayName() string  { return "Timelock" }
func (t *TimelockTemplate) Description() string  { return "Restrict funds to recipient after specified round" }
func (t *TimelockTemplate) DisplayColor() string { return "35" } // Magenta

// Parameters defines the user-provided inputs
func (t *TimelockTemplate) Parameters() []lsigprovider.ParameterDef {
    return []lsigprovider.ParameterDef{
        {
            Name:        "recipient",
            Label:       "Recipient Address",
            Description: "Algorand address that can receive funds after unlock",
            Type:        "address",
            Required:    true,
            MaxLength:   58,
        },
        {
            Name:        "unlock_round",
            Label:       "Unlock Round",
            Description: "Round number after which funds can be withdrawn",
            Type:        "uint64",
            Required:    true,
            MaxLength:   20,
        },
    }
}

// ValidateParameters validates user inputs
func (t *TimelockTemplate) ValidateParameters(params map[string]string) error {
    recipient, ok := params["recipient"]
    if !ok || recipient == "" {
        return fmt.Errorf("missing required parameter: recipient")
    }
    if len(recipient) != 58 {
        return fmt.Errorf("invalid recipient address length: expected 58, got %d", len(recipient))
    }

    unlockRoundStr, ok := params["unlock_round"]
    if !ok || unlockRoundStr == "" {
        return fmt.Errorf("missing required parameter: unlock_round")
    }
    if _, err := strconv.ParseUint(unlockRoundStr, 10, 64); err != nil {
        return fmt.Errorf("invalid unlock_round: %w", err)
    }

    return nil
}

// GenerateTEAL generates the TEAL source code
func (t *TimelockTemplate) GenerateTEAL(params map[string]string) (string, error) {
    if err := t.ValidateParameters(params); err != nil {
        return "", err
    }

    unlockRound, _ := strconv.ParseUint(params["unlock_round"], 10, 64)
    recipient := params["recipient"]

    return fmt.Sprintf(timelockTEAL,
        unlockRound, recipient,
        unlockRound, recipient), nil
}

// Compile compiles TEAL and returns bytecode and address
func (t *TimelockTemplate) Compile(params map[string]string, algodClient *algod.Client) ([]byte, string, error) {
    tealSource, err := t.GenerateTEAL(params)
    if err != nil {
        return nil, "", err
    }

    result, err := algodClient.TealCompile([]byte(tealSource)).Do(context.Background())
    if err != nil {
        return nil, "", fmt.Errorf("TEAL compilation failed: %w", err)
    }

    bytecode, err := base64.StdEncoding.DecodeString(result.Result)
    if err != nil {
        return nil, "", fmt.Errorf("failed to decode bytecode: %w", err)
    }

    return bytecode, result.Hash, nil
}

// TEAL template
const timelockTEAL = `#pragma version 10
// Timelock: funds locked until round %d, then only to %s

txn FirstValid
int %d
>=

txn Receiver
addr %s
==
&&

txn CloseRemainderTo
global ZeroAddress
==
&&

txn RekeyTo
global ZeroAddress
==
&&

return
`

var registerTemplateOnce sync.Once

// RegisterTemplate registers the template with the genericlsig registry.
// This is idempotent and safe to call multiple times.
func RegisterTemplate() {
    registerTemplateOnce.Do(func() {
        genericlsig.Register(&TimelockTemplate{})
    })
}
```

## Step 2: Add Registration Call to lsig/all.go

**`lsig/all.go`**:

```go
package lsig

import (
    "sync"

    falcon "github.com/aplane-algo/aplane/lsig/falcon1024"
    "github.com/aplane-algo/aplane/lsig/hashlock"
    "github.com/aplane-algo/aplane/lsig/timelock"
    "github.com/aplane-algo/aplane/lsig/yourtemplate"  // NEW - add this import
)

var registerAllOnce sync.Once

func RegisterAll() {
    registerAllOnce.Do(func() {
        // DSA-based LogicSig providers
        falcon.RegisterAll()

        // Generic LogicSig templates
        timelock.RegisterTemplate()
        hashlock.RegisterTemplate()
        yourtemplate.RegisterTemplate()  // NEW - add this call
    })
}
```

**This is the only file outside your template package that needs modification.**

## Step 3: Verify Registration

```bash
# Build
go build ./...

# Test key generation in TUI
./apadmin
# Select "hashlock (generic lsig)" in Generate New Key

# Run tests
go test ./lsig/hashlock/...
```

## Generic LogicSig Registry API

**File**: `internal/genericlsig/registry.go`

```go
// Registration (called from init())
Register(t Template)

// Lookup
Get(keyType string) (Template, error)
GetAll() []Template
Count() int

// Type checking
IsGenericLSigType(keyType string) bool
```

## Template Interface

**File**: `internal/genericlsig/template.go`

```go
type Template interface {
    // Identity
    KeyType() string      // Versioned identifier (e.g., "timelock-v1")
    Family() string       // Family name (e.g., "timelock")
    Version() int         // Version number (e.g., 1)

    // Display
    DisplayName() string  // Human-readable name (e.g., "Timelock")
    Description() string  // Short description for UI
    DisplayColor() string // ANSI color code

    // Parameters
    Parameters() []ParameterDef
    ValidateParameters(params map[string]string) error

    // TEAL Generation
    GenerateTEAL(params map[string]string) (string, error)
    Compile(params map[string]string, algodClient *algod.Client) (bytecode []byte, address string, err error)
}

type ParameterDef struct {
    Name        string // Internal name (e.g., "recipient")
    Label       string // Human-readable label (e.g., "Recipient Address")
    Description string // Description for UI tooltips
    Type        string // "address", "uint64", "string"
    Required    bool
    MaxLength   int
}
```

## File Storage

Generic LogicSigs are stored as encrypted `.key` files (all key types use a unified extension):

```go
// internal/keys/lsig_file.go
type LSigFile struct {
    Address     string            `json:"address"`
    KeyType     string            `json:"key_type"`     // e.g., "timelock-v1"
    Template    string            `json:"template"`     // e.g., "timelock"
    Parameters  map[string]string `json:"parameters"`   // User-provided params
    BytecodeHex string            `json:"bytecode_hex"` // Compiled TEAL
}
```

All key files (DSA keys and LogicSig keys) are encrypted using AES-256-GCM to prevent tampering.

## Signing Flow

Generic LogicSigs use the `/sign` endpoint; the signer returns `LsigBytecode` and ordered args without a `Signature`:

```
1. apshell sends transaction with generic lsig sender
2. Signer receives request for the LogicSig address
3. TUI shows approval popup (no signature computation)
4. On approval, return success
5. apshell attaches bytecode and ordered args (if any)
6. Submit to network - TEAL program evaluates conditions
```

## Example Templates

| Template | Parameters | Use Case |
|----------|------------|----------|
| **timelock** | recipient, unlock_round | Time-locked escrow |
| **hashlock** | hash, recipient | Hash-locked payment |
| **multisig-lsig** | threshold, addresses | Multi-party approval |
| **recurring** | recipient, interval, amount | Recurring payments |

## Checklist Summary

| Step | File/Action | Purpose |
|------|-------------|---------|
| 1 | Create `lsig/<template>/template.go` | Implement Template interface with `RegisterTemplate()` using `sync.Once` |
| 2 | **`lsig/all.go`** | **Add registration call (ONLY external change)** |
| 3 | Test | Verify registration |

---

## Registry Architecture

The system uses **two layers of registries** by design:

```
+---------------------------------------------------------+
|     General-Purpose Registries (all key types)          |
|     keygen, mnemonic, signing, algorithm                |
|     Key: "falcon1024", "ed25519" (family names)        |
+---------------------------------------------------------+
                          |
          +---------------+---------------+
          v                               v
+---------------------+         +---------------------+
|   logicsigdsa       |         |   (no special       |
|   Post-quantum only |         |    registry)        |
|   Key: falcon1024-v1|        |   ed25519 is native |
+---------------------+         +---------------------+
```

### Why Two Layers?

| Registry | Registered As | Lookup Normalizes | Purpose |
|----------|---------------|-------------------|---------|
| `logicsigdsa` | `falcon1024-v1` | No | LogicSig derivation (version-specific) |
| `keygen` | `falcon1024` | Yes | Key generation |
| `mnemonic` | `falcon1024` | Yes | Import/export |
| `signing` | `falcon1024` | Yes | Key file operations |
| `algorithm` | `falcon1024` | Yes | UI metadata |

**Key insight**: Ed25519 uses the general registries but NOT logicsigdsa - it's native to Algorand and doesn't need LogicSig wrapping.

### Family-Level Normalization

Family-level registries use `logicsigdsa.GetFamily()` to normalize versioned types:

```go
// Dynamically registered by providers
GetFamily("falcon1024-v1")  -> "falcon1024"
GetFamily("falcon1024-v2")  -> "falcon1024"
GetFamily("falcon-512-v1")   -> "falcon-512"
GetFamily("ed25519")         -> "ed25519" (not versioned)
```

### Method Naming Convention

| Interface | Method | Returns | Example |
|-----------|--------|---------|---------|
| `LogicSigDSA` | `KeyType()` | Versioned type | `"falcon1024-v1"` |
| `Provider` | `Family()` | Algorithm family | `"falcon1024"` |
| `Generator` | `Family()` | Algorithm family | `"falcon1024"` |
| `Handler` | `Family()` | Algorithm family | `"falcon1024"` |
| `SignatureMetadata` | `Family()` | Algorithm family | `"falcon1024"` |

---

## Complete File Structure

```
internal/
├── signing/
│   ├── provider.go        # KEY FILE OPERATIONS
│   ├── registry.go        # Provider registry
│   └── ed25519/           # Ed25519 provider
│
├── logicsigdsa/           # LOGICSIG DSA SYSTEM (post-quantum)
│   ├── dsa.go             # LogicSigDSA interface
│   ├── dsa_test.go        # Interface tests
│   └── registry.go        # Registration, lookup, family mappings
│
├── lsig/                  # TRANSACTION WRAPPING (large signatures)
│   ├── wrapper.go         # CreateDummyTransactions, CalculateDummiesNeeded, SignDummyTransactions
│   ├── wrapper_test.go    # Wrapper tests
│   └── dummy.teal.tok     # Embedded dummy LogicSig bytecode
│
├── keygen/                # KEY GENERATION
│   └── generator.go       # Generator interface
│
├── mnemonic/              # MNEMONIC HANDLING
│   └── handler.go         # Handler interface
│
└── algorithm/             # METADATA
    └── metadata.go        # SignatureMetadata interface

lsig/                      # LOGICSIG-BASED SCHEMES
├── all.go                 # SINGLE REGISTRATION POINT (add new providers here)
└── falcon1024/            # Falcon-1024 post-quantum scheme
    ├── core.go            # falconCore (shared crypto ops)
    ├── v1.go              # Falcon1024V1 (LogicSigDSA + RegisterLogicSigDSA())
    ├── register.go        # RegisterAll() aggregator
    ├── metadata.go        # Algorithm metadata + RegisterMetadata()
    ├── family/
    │   └── family.go      # Constants (key sizes, signature size, color)
    ├── derivation/
    │   ├── versions.go    # Version constants
    │   └── v1/derive.go   # FROZEN v1 LogicSig derivation
    ├── keys/
    │   ├── derive.go      # Address derivation
    │   ├── generation.go  # Key pair generation
    │   ├── register.go    # RegisterProcessors()
    │   └── processor.go   # Key processing
    ├── keygen/generator.go  # RegisterGenerator()
    ├── mnemonic/handler.go  # RegisterHandler()
    └── signing/provider.go  # RegisterProvider()
```

### Why Ed25519 is in `internal/` and Falcon is in `lsig/`

**Ed25519** is native to Algorand:
- No TEAL program needed
- Signature goes in `SignedTxn.Sig` field
- Simple implementation
- Belongs with core signing infrastructure in `internal/signing/ed25519/`

**Falcon-1024** is implemented via LogicSig:
- Requires TEAL program to verify signature on-chain
- Signature goes in `LogicSig.Args[0]`
- Complex infrastructure (key derivation, TEAL templates, dummy transactions)
- Belongs in `lsig/` with other LogicSig-based schemes

---

## Manifest Auditing

```bash
./apsignerd --print-manifest
```

```json
{
  "logicsig_dsas": [
    {
      "key_type": "falcon1024-v1",
      "signature_size": 1280,
      "mnemonic_scheme": "bip39",
      "mnemonic_word_count": 24,
      "display_color": "33"
    }
  ],
  "signing_providers": [
    {"family": "ed25519"},
    {"family": "falcon1024"}
  ],
  "algorithm_metadata": [...]
}
```

---

## Security Considerations

### Key Zeroing

All implementations must zero private key material after use:

```go
func (p *FalconProvider) ZeroKey(key *signing.KeyMaterial) {
    if km, ok := key.Value.(*FalconKeyMaterial); ok {
        util.ZeroBytes(km.PrivateKey)
        km.PrivateKey = nil
    }
    key.Type = ""
    key.Value = nil
}
```

### Type Validation

Always validate key types before operations:

```go
if !logicsigdsa.IsLogicSigType(keyType) {
    return fmt.Errorf("unsupported key type: %s", keyType)
}
```

### Signature Size Constants

| Algorithm | Max Signature Size |
|-----------|-------------------|
| Falcon-1024 | 1280 bytes (variable, NIST standard) |
| Falcon-512 | ~690 bytes (variable, future) |
| Ed25519 | 64 bytes (no LogicSig needed) |

---

## Related Documentation

- [ARCH_OVERVIEW.md](ARCH_OVERVIEW.md) - High-level system architecture
- [ARCH_ENGINE.md](ARCH_ENGINE.md) - Engine layer architecture
- [ARCH_UI.md](ARCH_UI.md) - UI layer architecture
- [CONFIG.md](CONFIG.md) - Configuration reference

---

## Appendix A: Key Operation Flows

### A.1 Generate New Key Flow

**Entry Point:** `FalconGenerator.GenerateRandom(passphrase, keyType)`

All generation functions require an explicit key type parameter. The UI layer
provides the list of valid types for user selection.

```
1. GenerateRandom(passphrase, "falcon1024-v1")  // keyType always explicit
   |
   +-> logicsigdsa.Get("falcon1024-v1")  ->  returns Falcon1024V1 DSA
   |         |
   |         +-> registry.dsas["falcon1024-v1"]  ->  *Falcon1024V1
   |
   +-> crypto/rand.Read(entropy)  ->  32 bytes of random entropy
   |
   +-> falconmnemonic.EntropyToMnemonic(entropy)  ->  24 BIP-39 words
   |
   +-> falconmnemonic.SeedFromMnemonic(words, "")  ->  64-byte seed
   |
   +-> dsa.GenerateKeypair(seed)  ->  (publicKey, privateKey)
   |         |
   |         +-> Falcon1024V1.GenerateKeypair() via falcongo
   |
   +-> dsa.DeriveLsig(publicKey)  ->  (lsigBytecode, address)
   |         |
   |         +-> Falcon1024V1.DeriveLsig() uses v1 derivation template
   |
   +-> Build KeyPair struct:
   |       Type:            "falcon1024-v1"  <- explicit, stored in key file
   |       PublicKeyHex:    hex(publicKey)
   |       PrivateKeyHex:   hex(privateKey)
   |       EntropyHex:      hex(entropy)      <- for mnemonic re-export
   |       LsigBytecodeHex: hex(lsigBytecode)
   |       Derivation:      "bip39-standard"
   |
   +-> saveFalconKeys(keyPair, address, passphrase)
       |
       +-> Writes encrypted JSON to keys/{address}.key

2. Returns GenerationResult:
       Address:      "XXXX...XXXX"
       KeyType:      "falcon1024-v1"
       PublicKeyHex: "..."
       Mnemonic:     "word1 word2 ... word24"  <- shown to user once
       KeyFiles:     {paths...}
```

### A.2 Import from Mnemonic Flow

**Entry Point:** `FalconGenerator.GenerateFromMnemonic(mnemonic, passphrase, keyType)`

```
1. GenerateFromMnemonic(mnemonic, passphrase, "falcon1024-v1")
   |
   +-> logicsigdsa.Get("falcon1024-v1")  ->  returns Falcon1024V1 DSA
   |
   +-> falconmnemonic.SeedFromMnemonic(words, "")  ->  64-byte seed
   |
   +-> falconmnemonic.MnemonicToEntropy(words)  ->  32-byte entropy (for re-export)
   |
   +-> dsa.GenerateKeypair(seed)  ->  (publicKey, privateKey)
   |
   +-> dsa.DeriveLsig(publicKey)  ->  (lsigBytecode, address)
   |       |
   |       +-> Falcon1024V1.DeriveLsig() uses v1 derivation template
   |
   +-> Build KeyPair struct:
   |       Type:            "falcon1024-v1"  <- explicit, stored in key file
   |       PublicKeyHex:    hex(publicKey)
   |       PrivateKeyHex:   hex(privateKey)
   |       EntropyHex:      hex(entropy)
   |       LsigBytecodeHex: hex(lsigBytecode)
   |       Derivation:      "bip39-standard"
   |
   +-> saveFalconKeys(keyPair, address, passphrase)
       |
       +-> Writes encrypted JSON to keys/{address}.key
```

**Key difference from generate:**
- Generate: Creates random entropy -> derives mnemonic -> derives seed
- Import: User provides mnemonic -> derives seed

Both converge at the seed -> keypair -> LogicSig derivation step.

### A.3 DSA Registry Connection

The key type string connects all operations through the registry pattern:

```
1. At startup (explicit registration):
   -------------------------------------------------------------
   cmd/apsignerd/main.go:
       RegisterProviders()  // Called before any key operations

   cmd/apsignerd/providers.go:
       func RegisterProviders() {
           lsig.RegisterAll()     // All Falcon + LogicSig templates
           ed25519.RegisterAll()  // All Ed25519 components
       }

   lsig/all.go:
       func RegisterAll() {
           registerAllOnce.Do(func() {
               falcon.RegisterAll()  // Registers all Falcon components
               // ...
           })
       }

   lsig/falcon1024/register.go:
       func RegisterAll() {
           registerAllOnce.Do(func() {
               RegisterLogicSigDSA()  // MUST be first
               // ...
           })
       }

   lsig/falcon1024/v1.go:
       func RegisterLogicSigDSA() {
           registerLogicSigDSAOnce.Do(func() {
               logicsigdsa.Register(&Falcon1024V1{})
           })
       }

   This registers:
   - DSA: registry.dsas["falcon1024-v1"] = &Falcon1024V1{}
   - Family: registry.keyToFamily["falcon1024-v1"] = "falcon1024"


2. At operation time:
   -------------------------------------------------------------
   GenerateFromMnemonic(mnemonic, passphrase, "falcon1024-v1")
   |
   +-> dsa := logicsigdsa.Get("falcon1024-v1")
   |         |
   |         +-> return registry.dsas["falcon1024-v1"]  ->  *Falcon1024V1
   |
   +-> dsa.DeriveLsig(publicKey)
             |
             +-> Falcon1024V1.DeriveLsig() is called
                       |
                       +-> uses v1.DerivePQLogicSig() (v1 template)
```

**Summary:** The key type string `"falcon1024-v1"` is the link. It's used as the registry key during `Register()` and as the lookup key during `Get()`. The explicit registration via `RegisterAll()` makes the initialization order visible and deterministic.

### A.4 Explicit Key Type Selection

All generation functions require an explicit key type:

```go
// Generator interface
type Generator interface {
    Family() string
    GenerateFromSeed(seed []byte, passphrase []byte, keyType string) (*GenerationResult, error)
    GenerateFromMnemonic(mnemonic string, passphrase []byte, keyType string) (*GenerationResult, error)
    GenerateRandom(passphrase []byte, keyType string) (*GenerationResult, error)
}
```

The UI layer provides the list of valid types via `logicsigdsa.GetKeyTypes()`:
- `"falcon1024-v1"`
- `"ed25519"`
- etc.

The user explicitly selects from this list. No implicit defaults.
