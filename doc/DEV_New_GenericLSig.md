# Adding a New Generic LogicSig Template

This guide provides step-by-step instructions for implementing new generic LogicSig templates. Generic LogicSigs authorize transactions through TEAL program evaluation only (no cryptographic signatures).

## Overview

**Generic LogicSigs** are parameterized TEAL programs that control spending conditions. Examples:
- **Timelock**: Funds released to recipient after a specific round
- **Hashlock**: Funds released when secret preimage is revealed (for atomic swaps)

**Key distinction from DSA-based LogicSigs** (like Falcon-1024):
- Generic LogicSigs: Pure TEAL condition checks, no cryptographic keys
- DSA LogicSigs: Cryptographic signature verification in TEAL

## File Structure

All generic LogicSig code lives in a single file:

```
lsig/
├── all.go                    # Import registration (add one line here)
├── <your-template>/
│   └── template.go           # Your entire implementation
├── timelock/
│   └── template.go           # Simple example (no runtime args)
└── hashlock/
    └── template.go           # Complex example (with runtime args)
```

## Step-by-Step Implementation

### Step 1: Create the Package Directory and File

Create `lsig/<name>/template.go`:

```go
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

// Package <name> provides a generic LogicSig template for <purpose>.
// <Detailed description of what this LogicSig does and its use cases.>
package <name>

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/genericlsig"
)
```

### Step 2: Define Constants

```go
const (
	family     = "<name>"        // e.g., "timelock", "hashlock"
	versionV1  = "<name>-v1"     // Versioned identifier
	versionPfx = "<name>-v"      // Version prefix for family lookup
)
```

### Step 3: Define the Template Struct with Compile-Time Check

```go
// Compile-time check that <Name>Template implements Template
var _ genericlsig.Template = (*<Name>Template)(nil)

// <Name>Template implements a <description> LogicSig
type <Name>Template struct{}
```

### Step 4: Implement Identity Methods

```go
// Identity methods
func (t *<Name>Template) KeyType() string { return versionV1 }
func (t *<Name>Template) Family() string  { return family }
func (t *<Name>Template) Version() int    { return 1 }
```

### Step 5: Implement Display Methods

```go
// Display methods
func (t *<Name>Template) DisplayName() string  { return "<Human Name>" }
func (t *<Name>Template) Description() string  { return "<Short description for UI>" }
func (t *<Name>Template) DisplayColor() string { return "<ANSI color code>" }
```

Available ANSI color codes:
- `"31"` - Red
- `"32"` - Green
- `"33"` - Yellow
- `"34"` - Blue
- `"35"` - Magenta (used by timelock)
- `"36"` - Cyan (used by hashlock)
- `"37"` - White

### Step 6: Implement Parameters()

Parameters are set at LogicSig **creation time** and baked into the TEAL program.

```go
func (t *<Name>Template) Parameters() []lsigprovider.ParameterDef {
	return []lsigprovider.ParameterDef{
		{
			Name:        "internal_name",      // Used in code
			Label:       "Human Label",        // Shown in TUI
			Description: "Help text for user", // Tooltip
			Type:        "address",            // See types below
			Required:    true,
			MaxLength:   58,                   // For validation
		},
		// ... more parameters
	}
}
```

**Parameter Types:**
| Type | Description | MaxLength | Validation |
|------|-------------|-----------|------------|
| `"address"` | 58-char Algorand address | 58 | Base32, checksum |
| `"uint64"` | Unsigned 64-bit integer | 20 | Numeric |
| `"string"` | Arbitrary string | varies | Printable chars |
| `"bytes"` | Hex-encoded bytes | varies | Hex chars only |

### Step 7: Implement RuntimeArgs() (Optional)

RuntimeArgs are provided at **transaction signing time**, not baked into TEAL. Return `nil` if not needed.

```go
// If your LogicSig needs no runtime arguments:
func (t *<Name>Template) RuntimeArgs() []lsigprovider.RuntimeArgDef {
	return nil
}

// If your LogicSig needs runtime arguments (like hashlock's preimage):
func (t *<Name>Template) RuntimeArgs() []lsigprovider.RuntimeArgDef {
	return []lsigprovider.RuntimeArgDef{
		{
			Name:        "preimage",           // Used in arg:preimage=<value>
			Label:       "Secret Preimage",    // Human label
			Description: "The 32-byte secret", // Help text
			Type:        "bytes",              // "bytes", "string", or "uint64"
			Required:    false,                // false if optional (e.g., refund path)
			ByteLength:  32,                   // Expected length (0 = variable)
		},
	}
}
```

### Step 7b: Implement BuildArgs()

BuildArgs assembles the LogicSig Args array. For generic templates, the signature parameter is ignored (generic LSigs don't use cryptographic signatures).

```go
func (t *<Name>Template) BuildArgs(signature []byte, runtimeArgs map[string][]byte) ([][]byte, error) {
	// Generic templates ignore signature (they don't use crypto signatures)
	var args [][]byte
	for _, argDef := range t.RuntimeArgs() {
		if val, ok := runtimeArgs[argDef.Name]; ok {
			args = append(args, val)
		} else if argDef.Required {
			return nil, fmt.Errorf("missing required arg: %s", argDef.Name)
		}
	}
	return args, nil
}
```

If your template has no RuntimeArgs, simply return nil:

```go
func (t *<Name>Template) BuildArgs(signature []byte, runtimeArgs map[string][]byte) ([][]byte, error) {
	return nil, nil
}
```

### Step 8: Implement ValidateCreationParams()

```go
func (t *<Name>Template) ValidateCreationParams(params map[string]string) error {
	// Validate each required parameter

	// For address parameters:
	addr, ok := params["recipient"]
	if !ok || addr == "" {
		return fmt.Errorf("recipient is required")
	}
	if _, err := types.DecodeAddress(addr); err != nil {
		return fmt.Errorf("invalid recipient address: %w", err)
	}

	// For uint64 parameters:
	roundStr, ok := params["unlock_round"]
	if !ok || roundStr == "" {
		return fmt.Errorf("unlock_round is required")
	}
	round, err := strconv.ParseUint(roundStr, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid unlock_round: %w", err)
	}
	if round == 0 {
		return fmt.Errorf("unlock_round must be greater than 0")
	}

	// For bytes parameters (hex):
	hashHex, ok := params["hash"]
	if !ok || hashHex == "" {
		return fmt.Errorf("hash is required")
	}
	hashBytes, err := hex.DecodeString(hashHex)
	if err != nil {
		return fmt.Errorf("invalid hash hex: %w", err)
	}
	if len(hashBytes) != 32 {
		return fmt.Errorf("hash must be 32 bytes, got %d", len(hashBytes))
	}

	return nil
}
```

### Step 9: Implement GenerateTEAL()

```go
func (t *<Name>Template) GenerateTEAL(params map[string]string) (string, error) {
	if err := t.ValidateCreationParams(params); err != nil {
		return "", err
	}

	// Extract parameters
	recipient := params["recipient"]
	unlockRound, _ := strconv.ParseUint(params["unlock_round"], 10, 64)

	// Generate TEAL (use string concatenation or fmt.Sprintf)
	teal := `#pragma version 10
// <Description of what this program does>

// SECURITY: Always prevent RekeyTo attacks
txn RekeyTo
global ZeroAddress
==
assert

// Your logic here...
txn Receiver
addr ` + recipient + `
==
assert

int 1
return
`
	return teal, nil
}
```

### Step 10: Implement Compile()

This is standard boilerplate:

```go
func (t *<Name>Template) Compile(params map[string]string, algodClient *algod.Client) ([]byte, string, error) {
	teal, err := t.GenerateTEAL(params)
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate TEAL: %w", err)
	}

	result, err := algodClient.TealCompile([]byte(teal)).Do(context.Background())
	if err != nil {
		return nil, "", fmt.Errorf("TEAL compilation failed: %w", err)
	}

	bytecode, err := base64.StdEncoding.DecodeString(result.Result)
	if err != nil {
		return nil, "", fmt.Errorf("failed to decode bytecode: %w", err)
	}

	// result.Hash is the program address (SHA512/256 of bytecode)
	return bytecode, result.Hash, nil
}
```

### Step 11: Implement RegisterTemplate() with sync.Once

```go
var registerTemplateOnce sync.Once

// RegisterTemplate registers the template with the genericlsig registry.
// This is idempotent and safe to call multiple times.
func RegisterTemplate() {
	registerTemplateOnce.Do(func() {
		genericlsig.Register(&<Name>Template{})
	})
}
```

Don't forget to add `"sync"` to your imports.

### Step 12: Add Registration Call to lsig/all.go

Add a registration call to the `RegisterAll()` function in `lsig/all.go`:

```go
func RegisterAll() {
	registerAllOnce.Do(func() {
		// DSA-based LogicSig providers (require cryptographic signing)
		falcon.RegisterAll()

		// Generic LogicSig templates (TEAL-only authorization)
		timelock.RegisterTemplate()
		hashlock.RegisterTemplate()
		<name>.RegisterTemplate()  // <Your description>
		multitemplate.RegisterTemplates()
	})
}
```

And add the import:
```go
import (
	"sync"

	falcon "github.com/aplane-algo/aplane/lsig/falcon1024"
	"github.com/aplane-algo/aplane/lsig/hashlock"
	"github.com/aplane-algo/aplane/lsig/multitemplate"
	"github.com/aplane-algo/aplane/lsig/timelock"
	"github.com/aplane-algo/aplane/lsig/<name>"  // <Your description>
)
```

## TEAL Security Patterns

**ALWAYS include these security checks:**

### 1. Prevent RekeyTo Attacks
```teal
txn RekeyTo
global ZeroAddress
==
assert
```

### 2. Prevent CloseRemainderTo Drain (if applicable)
```teal
// Option A: Disallow completely
txn CloseRemainderTo
global ZeroAddress
==
assert

// Option B: Allow only to specific address
txn CloseRemainderTo
addr <ALLOWED_ADDRESS>
==
txn CloseRemainderTo
global ZeroAddress
==
||
assert
```

### 3. Restrict Transaction Type (if applicable)
```teal
txn TypeEnum
int pay  // or: int axfer, int appl, etc.
==
assert
```

### 4. Time-Based Checks (use FirstValid, not global Round)
```teal
// Use txn FirstValid instead of global Round
// global Round is restricted in LogicSig mode on some networks
txn FirstValid
int <ROUND_NUMBER>
>=
assert
```

## Complete Examples

### Simple Example: Timelock (no runtime args)

See `lsig/timelock/template.go`:
- 2 parameters: `recipient` (address), `unlock_round` (uint64)
- No runtime args
- Single spending path: after unlock round, only to recipient

### Complex Example: Hashlock (with runtime args)

See `lsig/hashlock/template.go`:
- 4 parameters: `hash`, `recipient`, `refund_address`, `timeout_round`
- 1 runtime arg: `preimage` (provided via `arg:preimage=<value>`)
- Two spending paths: claim (with preimage) or refund (after timeout)

## Testing Your Implementation

1. **Build and verify compilation:**
   ```bash
   go build ./lsig/...
   go build ./...
   ```

2. **Generate a key in apadmin TUI:**
   - Press `g` to generate
   - Select your new template
   - Fill in parameters
   - Verify address is generated

3. **Test transactions in apshell:**
   ```bash
   # Fund the LogicSig address
   send 1 algo from <funded-account> to <logicsig-address>

   # Spend from LogicSig (with runtime args if needed)
   send 0.5 algo from <logicsig-address> to <recipient> arg:preimage=mysecret
   ```

## Checklist

- [ ] Package created at `lsig/<name>/template.go`
- [ ] Constants defined: `family`, `versionV1`, `versionPfx`
- [ ] Compile-time interface check: `var _ genericlsig.Template = (*<Name>Template)(nil)`
- [ ] All interface methods implemented:
  - [ ] `KeyType()`, `Family()`, `Version()`, `Category()`
  - [ ] `DisplayName()`, `Description()`, `DisplayColor()`
  - [ ] `CreationParams()`
  - [ ] `ValidateCreationParams()`
  - [ ] `RuntimeArgs()` (return nil if not needed)
  - [ ] `BuildArgs()` (assembles LogicSig.Args)
  - [ ] `GenerateTEAL()`
  - [ ] `Compile()`
- [ ] `RegisterTemplate()` implemented with `sync.Once`
- [ ] Registration call added to `lsig/all.go` `RegisterAll()` function
- [ ] TEAL includes RekeyTo protection
- [ ] TEAL includes CloseRemainderTo protection (if applicable)
- [ ] Build succeeds: `go build ./...`
