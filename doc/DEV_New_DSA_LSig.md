# Adding a New DSA-Based LogicSig Provider

This guide provides step-by-step instructions for implementing a new DSA-based LogicSig provider (like Falcon-1024). DSA LogicSigs use cryptographic signatures verified by TEAL programs.

## Overview

**DSA-based LogicSigs** combine:
1. A cryptographic signature algorithm (e.g., Falcon, Dilithium)
2. A TEAL program that verifies signatures using algorithm-specific opcodes
3. Key generation, mnemonic handling, and signing infrastructure

**Key distinction from Generic LogicSigs:**
- DSA LogicSigs: Cryptographic signature verification in TEAL (`falcon_verify` opcode)
- Generic LogicSigs: Pure TEAL condition checks (no cryptographic keys)

## Architecture: ComposedDSA

All DSA LogicSigs use the **ComposedDSA** architecture, which:
- Combines a **DSA base struct** (cryptographic operations) with an optional **TEAL suffix** (inline TEAL conditions with `@variable` substitution)
- Uses **runtime TEAL compilation** via algod (no unsafe bytecode patching)
- Supports both pure DSAs (no TEAL suffix) and hybrid DSAs (with TEAL suffix containing conditions like rekey prevention, hashlock, etc.)

```
┌──────────────────────────────────────────────────────────────────────┐
│                          ComposedDSA                                 │
│                                                                      │
│  ┌──────────────────┐    ┌────────────────────────────────────────┐  │
│  │  *falconDSABase   │    │         TEAL Suffix                    │  │
│  │                   │    │  Inline TEAL with @variable refs       │  │
│  │ - Sign()          │    │  e.g., rekey check, hashlock check     │  │
│  │ - GenerateKeypair │    │  Substituted via internal/tealsubst    │  │
│  │ - TEAL verify     │    └────────────────────────────────────────┘  │
│  └──────────────────┘                                                │
│                                                                      │
│  GenerateTEAL() → preamble + substituted suffix + verify → algod     │
└──────────────────────────────────────────────────────────────────────┘
```

## File Structure

```
lsig/
├── all.go                        # Import registration (add one line)
└── <algorithm>/
    ├── register.go               # Main import, RegisterAll()
    ├── family/
    │   └── family.go             # Constants (sizes, colors, etc.)
    ├── base.go                   # DSA base struct implementation
    ├── composer.go               # ComposedDSA factory (if custom needed)
    ├── v1.go                     # Version 1 implementation
    ├── keygen/
    │   └── generator.go          # Key generation
    ├── mnemonic/
    │   └── handler.go            # Mnemonic handling
    ├── signing/
    │   └── provider.go           # Signing provider
    └── keys/
        └── register.go           # Key processor registration
```

## Step-by-Step Implementation

### Step 1: Create Family Constants

Create `lsig/<algorithm>/family/family.go`:

```go
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

// Package family provides <algorithm> family constants.
// Separate package to avoid import cycles.
package family

// Family identity
const Name = "<algorithm>"  // e.g., "falcon1024", "dilithium-3"

// Key sizes (from the cryptographic library)
const (
    PublicKeySize  = <size>  // bytes
    PrivateKeySize = <size>  // bytes
)

// Signature properties
const MaxSignatureSize = <size>  // Maximum signature size in bytes

// Mnemonic properties
const (
    MnemonicScheme    = "bip39"  // or "algorand"
    MnemonicWordCount = 24       // 24 for BIP-39 with 256-bit entropy
)

// Display properties
const DisplayColor = "33"  // ANSI color code
```

### Step 2: Implement the DSA Base Struct

The DSA base struct provides the cryptographic foundation. Create `lsig/<algorithm>/base.go`:

```go
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package <algorithm>

import (
    "bytes"
    "fmt"

    "github.com/aplane-algo/aplane/internal/crypto"
    "github.com/aplane-algo/aplane/lsig/<algorithm>/family"
    // Import your cryptographic library
)

// Placeholder patterns for TEAL patching
var (
    PublicKeyPlaceholder = bytes.Repeat([]byte{0x00}, family.PublicKeySize)
    CounterPattern       = []byte{0x26, 0x01, 0x01}  // bytecblock pattern
)

// <Algorithm>Base is the DSA base for <algorithm> composed LogicSigs.
var <Algorithm>Base = &<algorithm>DSABase{}

type <algorithm>DSABase struct{}

func (b *<algorithm>DSABase) Name() string {
    return family.Name
}

func (b *<algorithm>DSABase) PublicKeySize() int {
    return family.PublicKeySize
}

func (b *<algorithm>DSABase) PrivateKeySize() int {
    return family.PrivateKeySize
}

func (b *<algorithm>DSABase) CryptoSignatureSize() int {
    return family.MaxSignatureSize
}

func (b *<algorithm>DSABase) MnemonicScheme() string {
    return family.MnemonicScheme
}

func (b *<algorithm>DSABase) MnemonicWordCount() int {
    return family.MnemonicWordCount
}

func (b *<algorithm>DSABase) DisplayColor() string {
    return family.DisplayColor
}

func (b *<algorithm>DSABase) GenerateKeypair(seed []byte) (publicKey, privateKey []byte, err error) {
    // Use your cryptographic library to generate keypair from seed
    // ...
    return pub, priv, nil
}

func (b *<algorithm>DSABase) Sign(privateKey []byte, message []byte) (signature []byte, err error) {
    if len(privateKey) != family.PrivateKeySize {
        return nil, fmt.Errorf("invalid private key size: expected %d, got %d",
            family.PrivateKeySize, len(privateKey))
    }

    // Copy private key and zero after use
    var priv YourPrivateKeyType
    copy(priv[:], privateKey)
    defer crypto.ZeroBytes(priv[:])

    // Sign using your cryptographic library
    // ...
    return sig, nil
}

func (b *<algorithm>DSABase) SeedFromMnemonic(words []string, passphrase string) ([]byte, error) {
    // Convert mnemonic words to seed bytes
    // ...
    return seed, nil
}

func (b *<algorithm>DSABase) EntropyToMnemonic(entropy []byte) ([]string, error) {
    // Convert entropy to mnemonic words
    // ...
    return words, nil
}
```

Note: The DSA base is a concrete struct (`*<algorithm>DSABase`), not an interface implementation. The `ComposedDSAConfig.Base` field takes a `*falconDSABase` (for Falcon) or equivalent struct pointer directly.

### Step 3: Implement the Main DSA Provider (v1.go)

Create `lsig/<algorithm>/v1.go`. This uses ComposedDSA with no TEAL suffix for a pure DSA:

```go
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package <algorithm>

import (
    "fmt"
    "sync"

    "github.com/aplane-algo/aplane/internal/logicsigdsa"
    "github.com/aplane-algo/aplane/internal/lsigprovider"
    "github.com/aplane-algo/aplane/lsig/<algorithm>/family"

    "github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
)

// <Algorithm>V1 implements LogicSigDSA for <algorithm> with version 1 derivation.
//
// This uses the ComposedDSA architecture with no TEAL suffix for a pure DSA.
// An algod client must be configured before calling DeriveLsig.
type <Algorithm>V1 struct {
    <algorithm>Core  // Embed shared operations (optional helper)
    algodClient *algod.Client
}

// SetAlgodClient sets the algod client for runtime TEAL compilation.
// This must be called before DeriveLsig (typically done at server startup).
func (a *<Algorithm>V1) SetAlgodClient(client *algod.Client) {
    a.algodClient = client
}

func (a *<Algorithm>V1) KeyType() string {
    return "<algorithm>-v1"
}

func (a *<Algorithm>V1) Family() string {
    return family.Name
}

func (a *<Algorithm>V1) Version() int {
    return 1
}

func (a *<Algorithm>V1) Category() string {
    return lsigprovider.CategoryDSALsig
}

func (a *<Algorithm>V1) DisplayName() string {
    return "<Algorithm Display Name>"
}

func (a *<Algorithm>V1) Description() string {
    return "<Description of the algorithm>"
}

// DeriveLsig derives the LogicSig bytecode and address from a public key.
// Uses runtime TEAL compilation through the ComposedDSA system.
func (a *<Algorithm>V1) DeriveLsig(publicKey []byte, params map[string]string) ([]byte, string, error) {
    _ = params // Pure DSA ignores params

    if len(publicKey) != family.PublicKeySize {
        return nil, "", fmt.Errorf("invalid public key size: expected %d, got %d",
            family.PublicKeySize, len(publicKey))
    }

    if a.algodClient == nil {
        return nil, "", fmt.Errorf("algod client not set: configure teal_compiler_algod_url")
    }

    // Use ComposedDSA with no TEAL suffix (pure DSA)
    comp := NewComposedDSA(ComposedDSAConfig{
        KeyType:     "<algorithm>-v1",
        FamilyName:  family.Name,
        Version:     1,
        DisplayName: "<Algorithm>",
        Description: "<Description>",
        Base:        <Algorithm>Base,
        // No TEALSuffix, no Params, no RuntimeArgs = pure DSA
    })
    comp.SetAlgodClient(a.algodClient)
    return comp.DeriveLsig(publicKey, nil)
}

// CreationParams returns parameter definitions for LSig creation.
// Pure DSA has no creation parameters.
func (a *<Algorithm>V1) CreationParams() []lsigprovider.ParameterDef {
    return nil
}

func (a *<Algorithm>V1) ValidateCreationParams(params map[string]string) error {
    return nil
}

// RuntimeArgs returns argument definitions needed at signing time.
// Signatures are generated automatically, so no runtime args.
func (a *<Algorithm>V1) RuntimeArgs() []lsigprovider.RuntimeArgDef {
    return nil
}

// BuildArgs assembles the LogicSig Args array.
// For pure DSAs: [signature]
func (a *<Algorithm>V1) BuildArgs(signature []byte, runtimeArgs map[string][]byte) ([][]byte, error) {
    if signature == nil {
        return nil, fmt.Errorf("signature is required for DSA LogicSig")
    }
    return [][]byte{signature}, nil
}

// Compile-time interface checks
var (
    _ logicsigdsa.LogicSigDSA            = (*<Algorithm>V1)(nil)
    _ lsigprovider.LSigProvider          = (*<Algorithm>V1)(nil)
    _ lsigprovider.SigningProvider       = (*<Algorithm>V1)(nil)
    _ lsigprovider.MnemonicProvider      = (*<Algorithm>V1)(nil)
    _ lsigprovider.AlgodConfigurable     = (*<Algorithm>V1)(nil)
)

var registerLogicSigDSAOnce sync.Once

func RegisterLogicSigDSA() {
    registerLogicSigDSAOnce.Do(func() {
        logicsigdsa.Register(&<Algorithm>V1{})
    })
}
```

### Step 4: Implement Key Generation, Mnemonic, and Signing

These follow the same patterns as before (see `lsig/falcon1024/keygen/`, `mnemonic/`, `signing/` for examples). Key points:

- All handle key material securely with `crypto.ZeroBytes()`
- Use `sync.Once` for idempotent registration
- Register with respective registries (`keygen.Register`, `mnemonic.Register`, `signing.Register`)

### Step 5: Create Main Registration File

Create `lsig/<algorithm>/register.go`:

```go
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package <algorithm>

import (
    "sync"

    "github.com/aplane-algo/aplane/lsig/<algorithm>/keygen"
    <algorithm>keys "github.com/aplane-algo/aplane/lsig/<algorithm>/keys"
    "github.com/aplane-algo/aplane/lsig/<algorithm>/mnemonic"
    <algorithm>signing "github.com/aplane-algo/aplane/lsig/<algorithm>/signing"
)

var registerAllOnce sync.Once

// RegisterAll registers all <algorithm> components with their respective registries.
// Registration order is significant - LogicSigDSA must be first.
func RegisterAll() {
    registerAllOnce.Do(func() {
        // 1. LogicSigDSA MUST be registered first
        RegisterLogicSigDSA()

        // 2. Signing provider
        <algorithm>signing.RegisterProvider()

        // 3. Key generator
        keygen.RegisterGenerator()

        // 4. Mnemonic handler
        mnemonic.RegisterHandler()

        // 5. Key processors
        <algorithm>keys.RegisterProcessors()
    })
}
```

### Step 6: Add to lsig/all.go

```go
import (
    <algorithm> "github.com/aplane-algo/aplane/lsig/<algorithm>"
)

func RegisterAll() {
    registerAllOnce.Do(func() {
        // DSA-based LogicSig providers
        falcon.RegisterAll()
        <algorithm>.RegisterAll()
        // ...
    })
}
```

## Hybrid DSA LogicSigs

Hybrid DSAs combine cryptographic signatures with additional TEAL conditions (rekey prevention, hashlock, etc.). Instead of writing custom code, use **ComposedDSA with a TEAL suffix containing `@variable` substitution**.

### Using TEAL Suffix with @variable Substitution

The TEAL suffix is inline TEAL source code appended between the preamble (pragma + counter) and the DSA verification block. Variables in the suffix use the `@variable_name` syntax and are substituted at derivation time using `internal/tealsubst`.

```go
// Create a hashlock-enabled variant
func RegisterHashlockV1() {
    comp := NewComposedDSA(ComposedDSAConfig{
        KeyType:     "<algorithm>-hashlock-v1",
        FamilyName:  family.Name,
        Version:     1,
        DisplayName: "<Algorithm> Hashlock",
        Description: "Signature with SHA256 hash verification (requires preimage to spend)",
        Base:        <Algorithm>Base,
        Params: []lsigprovider.ParameterDef{{
            Name:     "hash",
            Label:    "SHA256 Hash",
            Type:     "bytes",
            Required: true,
        }},
        RuntimeArgs: []lsigprovider.RuntimeArgDef{{
            Name:        "preimage",
            Label:       "Secret Preimage",
            Description: "The secret value whose SHA256 hash matches the stored hash",
            Type:        "bytes",
            Required:    true,
        }},
        TEALSuffix: `// Prevent rekeying
txn RekeyTo
global ZeroAddress
==
assert
// Prevent closing account
txn CloseRemainderTo
global ZeroAddress
==
assert
// Hash verification: sha256(arg 1) == stored hash
arg 1
sha256
byte @hash
==
assert`,
    })
    logicsigdsa.Register(comp)
}
```

The generated TEAL program has this structure:

```teal
#pragma version 12

// Counter byte (varied 0-255 to avoid ed25519 curve addresses)
bytecblock 0x00

// --- TEAL suffix (substituted) ---
// Prevent rekeying
txn RekeyTo
global ZeroAddress
==
assert
// Prevent closing account
txn CloseRemainderTo
global ZeroAddress
==
assert
// Hash verification: sha256(arg 1) == stored hash
arg 1
sha256
byte 0x<hash_value>
==
assert

// === DSA Signature Verification ===
txn TxID
arg 0
byte 0x<pubkey>
<algorithm>_verify
```

### Writing TEAL Suffix with @variable Substitution

The TEAL suffix is raw TEAL source where `@variable_name` references are replaced with parameter values at derivation time. The substitution is handled by `internal/tealsubst` and formats values based on parameter type:

| Parameter Type | Substitution Format | Example |
|---|---|---|
| `bytes` | Prefixed with `0x` | `@hash` becomes `0xe3b0c4...` |
| `address` | Inserted as-is (base32) | `@recipient` stays as Algorand address |
| `uint64` | Inserted as-is (decimal) | `@unlock_round` stays as `12345` |

To add a new TEAL suffix:

1. **Write the inline TEAL** using `@variable_name` for any parameterized values
2. **Define `Params`** for each `@variable` (creation-time parameters provided when the LogicSig is derived)
3. **Define `RuntimeArgs`** for values needed at signing time (passed as `arg 1`, `arg 2`, etc.)
4. **Set `TEALSuffix`** in the `ComposedDSAConfig`

The `internal/tealsubst` package provides the substitution engine:
- `tealsubst.SubstituteVariables()` replaces `@variable` references with formatted values
- `tealsubst.ExtractVariables()` extracts all `@variable` names from TEAL source
- `tealsubst.ValidateVariablesAgainstParams()` validates that all variables have corresponding parameter definitions

### Common TEAL Suffix Patterns

Here are common inline TEAL patterns used in suffixes:

**Rekey prevention:**
```teal
txn RekeyTo
global ZeroAddress
==
assert
```

**Close-to prevention:**
```teal
txn CloseRemainderTo
global ZeroAddress
==
assert
```

**Timelock (unlocks after round N):**
```teal
txn FirstValid
int @unlock_round
>=
assert
```

**Hash preimage verification:**
```teal
arg 1
sha256
byte @hash
==
assert
```

These patterns are written directly in the `TEALSuffix` string -- there is no separate fragment or constraint abstraction layer.

## Key Interfaces

### AlgodConfigurable (Required for DSAs)

All DSA providers must implement this for runtime TEAL compilation:

```go
type AlgodConfigurable interface {
    SetAlgodClient(client *algod.Client)
}
```

The server calls `lsigprovider.ConfigureAlgodClient()` at startup to inject the client.

### LSigProvider Interfaces

```go
// Base interface (required)
type LSigProvider interface {
    KeyType() string
    Family() string
    Version() int
    Category() string
    DisplayName() string
    Description() string
    DisplayColor() string
    CreationParams() []ParameterDef
    ValidateCreationParams(map[string]string) error
    RuntimeArgs() []RuntimeArgDef
    BuildArgs(signature []byte, runtimeArgs map[string][]byte) ([][]byte, error)
}

// For DSAs with signing (required for DSA LSigs)
type SigningProvider interface {
    LSigProvider
    CryptoSignatureSize() int
    GenerateKeypair(seed []byte) (publicKey, privateKey []byte, err error)
    Sign(privateKey, message []byte) (signature []byte, err error)
    DeriveLsig(publicKey []byte, params map[string]string) ([]byte, string, error)
}

// For mnemonic support (recommended)
type MnemonicProvider interface {
    SigningProvider
    MnemonicScheme() string
    MnemonicWordCount() int
    SeedFromMnemonic(words []string, passphrase string) ([]byte, error)
    EntropyToMnemonic(entropy []byte) ([]string, error)
}
```

## Security Requirements

1. **Zero all sensitive data after use:**
   ```go
   defer crypto.ZeroBytes(privateKey)
   defer crypto.ZeroBytes(seed)
   ```

2. **Use crypto/rand for entropy:**
   ```go
   import "crypto/rand"
   rand.Read(entropy)  // Never use math/rand
   ```

3. **Validate key sizes:**
   ```go
   if len(publicKey) != family.PublicKeySize {
       return nil, fmt.Errorf("invalid public key size")
   }
   ```

4. **Require algod client for derivation:**
   ```go
   if a.algodClient == nil {
       return nil, "", fmt.Errorf("algod client not set")
   }
   ```

## Testing

1. **Build verification:**
   ```bash
   go build ./lsig/...
   go build ./...
   ```

2. **Unit tests:**
   ```bash
   go test ./lsig/<algorithm>/...
   ```

3. **Key generation test:**
   - Generate key in apadmin TUI
   - Export mnemonic
   - Re-import mnemonic
   - Verify same address is derived

4. **Signing test:**
   - Fund the generated address
   - Send a transaction from it
   - Verify transaction succeeds

## Checklist

- [ ] `family/family.go` - Constants defined
- [ ] `base.go` - DSA base struct implementation
- [ ] `v1.go` - Main provider with `SetAlgodClient()`, `BuildArgs()`, compile-time checks
- [ ] `keygen/generator.go` - Key generation with `sync.Once`
- [ ] `mnemonic/handler.go` - Mnemonic handling with `sync.Once`
- [ ] `signing/provider.go` - Signing provider with `sync.Once`
- [ ] `keys/register.go` - Key processors with `sync.Once`
- [ ] `register.go` - Main `RegisterAll()` function
- [ ] `lsig/all.go` - Registration call added
- [ ] All sensitive data zeroed after use
- [ ] `AlgodConfigurable` interface implemented
- [ ] Build succeeds: `go build ./...`
- [ ] Tests pass: `go test ./lsig/<algorithm>/...`

## See Also

- `doc/DEV_New_GenericLSig.md` - For TEAL-only LogicSigs without cryptographic keys
- `internal/tealsubst/` - TEAL `@variable` substitution engine
- `lsig/falcon1024/` - Reference implementation
