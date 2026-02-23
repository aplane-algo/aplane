# AI Developer Guide: Creating Multitemplate LogicSigs

This guide instructs LLMs on how to create new YAML-based LogicSig templates for aPlane.

## Overview

Multitemplate LogicSigs are declarative YAML files that define:
1. Template metadata (family, version, display info)
2. Parameters that users provide (addresses, numbers, hashes)
3. TEAL source code with variable substitution

Templates are embedded at compile time. No Go code is required.

## File Location

Create new templates at:
```
lsig/multitemplate/templates/<family>-v<version>.yaml
```

Example: `lsig/multitemplate/templates/escrow-v1.yaml`

## YAML Schema

```yaml
schema_version: 1              # Always use 1 (required for forward compatibility)
family: escrow                 # Lowercase, no spaces, used in key type
version: 1                     # Integer version number
display_name: "Escrow"         # Human-readable name for UI
description: "Brief description of what this template does"
display_color: "36"            # ANSI color code (optional)

parameters:
  - name: parameter_name       # Lowercase with underscores, used in TEAL as @parameter_name
    label: "Parameter Label"   # Human-readable label
    description: "Help text"   # Tooltip description
    type: address              # One of: address, uint64, bytes
    required: true             # true or false

    # Optional fields:
    example: "AAAA..."         # Example value for UI
    placeholder: "Enter..."    # Placeholder text
    min: 1                     # Minimum value (uint64 only)
    max: 1000000               # Maximum value (uint64 only)
    default: "100"             # Default value (optional params only)

runtime_args:                  # Optional: arguments needed at signing time
  - name: preimage             # Used in --lsig-arg preimage=<value>
    label: "Preimage"          # Human-readable label
    description: "Help text"   # Description for CLI help
    type: bytes                # One of: bytes, string, uint64
    byte_length: 32            # Expected length (0 = variable, optional)

teal: |
  #pragma version 10
  // TEAL code with @variable substitution
  txn Receiver
  addr @parameter_name
  ==
  return
```

## Parameters vs Runtime Args

**Parameters** are provided when creating the LogicSig key and get embedded in the TEAL bytecode via `@variable` substitution. They become part of the program.

**Runtime Args** are provided when spending from the LogicSig address. They're passed as LogicSig arguments (`arg 0`, `arg 1`, etc.) and accessed in TEAL via the `arg` opcode.

| | Parameters | Runtime Args |
|---|---|---|
| When provided | Key creation | Transaction signing |
| Embedded in | TEAL bytecode | LogicSig args |
| TEAL access | `@variable` substitution | `arg 0`, `arg 1`, etc. |
| Example | Recipient address, timeout | Hashlock preimage |

## Parameter Types

### `address`
- 58-character Algorand address
- Validated with SDK checksum verification
- Substituted as-is in TEAL (use with `addr` opcode)

```yaml
- name: recipient
  label: "Recipient Address"
  type: address
  required: true
  example: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"
```

TEAL usage:
```
addr @recipient
```

### `uint64`
- Unsigned 64-bit integer (0 to 18446744073709551615)
- Decimal digits only (no hex, no negative)
- Supports `min` and `max` constraints
- Substituted as-is in TEAL (use with `int` opcode)

```yaml
- name: timeout_round
  label: "Timeout Round"
  type: uint64
  required: true
  min: 1
  example: "50000000"
```

TEAL usage:
```
int @timeout_round
```

### `bytes`
- Hex-encoded byte string
- Accepts with or without `0x` prefix (normalized internally)
- Substituted with `0x` prefix in TEAL (use with `byte` opcode)

```yaml
- name: hash
  label: "SHA256 Hash"
  type: bytes
  required: true
  max_length: 64    # 32 bytes = 64 hex chars
  example: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
```

TEAL usage:
```
byte @hash
```

## Variable Substitution

Variables in TEAL are prefixed with `@`:

| Type | Input | TEAL Output |
|------|-------|-------------|
| address | `ABC...XYZ` | `ABC...XYZ` |
| uint64 | `12345` | `12345` |
| bytes | `deadbeef` | `0xdeadbeef` |
| bytes | `0xdeadbeef` | `0xdeadbeef` |

## TEAL Best Practices

### Always Include Security Checks

Every template MUST prevent these attacks:

```teal
// Prevent RekeyTo takeover (REQUIRED)
txn RekeyTo
global ZeroAddress
==
assert  // or && with other conditions

// Prevent unauthorized CloseRemainderTo (REQUIRED for payment templates)
txn CloseRemainderTo
global ZeroAddress
==
// OR allow closing to a specific address:
txn CloseRemainderTo
addr @recipient
==
||
assert
```

### Use TEAL Version 10

```teal
#pragma version 10
```

### Use `txn FirstValid` Instead of `global Round`

For time-based checks, use `txn FirstValid` because `global Round` is restricted in LogicSig mode:

```teal
// CORRECT: Check transaction can only be valid after unlock_round
txn FirstValid
int @unlock_round
>=

// WRONG: global Round may not work in LogicSig mode
// global Round
// int @unlock_round
// >=
```

### Include Comments

Document the logic for maintainability:

```teal
#pragma version 10
// Escrow: funds held until conditions met

// Check 1: Description of first check
txn SomeField
int @some_param
==

// Check 2: Description of second check
// ...
```

## Complete Example: Escrow Template

```yaml
schema_version: 1
family: escrow
version: 1
display_name: "Escrow"
description: "Hold funds until recipient provides approval code"
display_color: "33"

parameters:
  - name: recipient
    label: "Recipient Address"
    description: "Address that can claim funds with the approval code"
    type: address
    required: true
    example: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"
    placeholder: "Enter recipient address"

  - name: approval_hash
    label: "Approval Hash"
    description: "SHA256 hash of the approval code (32 bytes, hex)"
    type: bytes
    required: true
    max_length: 64
    example: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

  - name: timeout_round
    label: "Timeout Round"
    description: "Round after which sender can reclaim funds"
    type: uint64
    required: true
    min: 1
    example: "50000000"

  - name: sender
    label: "Sender Address"
    description: "Original sender who can reclaim after timeout"
    type: address
    required: true

teal: |
  #pragma version 10
  // Escrow: funds released to recipient with approval code, or back to sender after timeout

  // Security: Prevent RekeyTo
  txn RekeyTo
  global ZeroAddress
  ==
  assert

  // Check if timeout passed
  txn FirstValid
  int @timeout_round
  >=
  bnz refund_path

  // === CLAIM PATH (before timeout) ===
  // Verify approval code hash
  arg 0
  sha256
  byte @approval_hash
  ==
  assert

  // Verify receiver is recipient
  txn Receiver
  addr @recipient
  ==
  assert

  // CloseRemainderTo must be recipient or zero
  txn CloseRemainderTo
  addr @recipient
  ==
  txn CloseRemainderTo
  global ZeroAddress
  ==
  ||
  assert

  int 1
  return

  // === REFUND PATH (after timeout) ===
  refund_path:
      txn Receiver
      addr @sender
      ==
      assert

      txn CloseRemainderTo
      addr @sender
      ==
      txn CloseRemainderTo
      global ZeroAddress
      ==
      ||
      assert

      int 1
      return
```

## Validation Rules

The system validates templates at load time:

1. **Required fields**: `family`, `version`, `display_name`, `teal`
2. **Schema version**: Must be ≤ current supported version (1)
3. **Parameter names**: Must be unique, non-empty
4. **Parameter types**: Must be `address`, `uint64`, or `bytes`
5. **Min/max**: Only valid for `uint64` type; min ≤ max
6. **Default values**: Must pass type validation and constraints
7. **TEAL variables**: All `@variable` references must have matching parameter definitions

## Testing Your Template

After creating a template:

1. Rebuild: `go build ./...`
2. Run tests: `go test ./lsig/multitemplate/...`
3. Check in TUI: Run `apadmin` and verify template appears in key type selection
4. Test parameter validation by entering invalid values

## Common Mistakes

### Wrong: Using undefined variable
```yaml
parameters:
  - name: recipient
    type: address
teal: |
  addr @recepient   # TYPO: will fail validation
```

### Wrong: Min/max on non-uint64
```yaml
parameters:
  - name: addr
    type: address
    min: 1          # ERROR: min/max only for uint64
```

### Wrong: Missing security checks
```teal
// BAD: No RekeyTo check allows account takeover
txn Receiver
addr @recipient
==
return
```

### Wrong: Using global Round
```teal
// BAD: May fail in LogicSig mode
global Round
int @timeout
>=
```

## Template Checklist

Before submitting a new template, verify:

- [ ] `schema_version: 1` is set
- [ ] Family name is lowercase with no spaces
- [ ] All parameters have `name`, `label`, `type`, `required`
- [ ] TEAL includes `#pragma version 10`
- [ ] TEAL includes RekeyTo security check
- [ ] TEAL includes CloseRemainderTo security check (if handling payments)
- [ ] All `@variables` in TEAL have matching parameter definitions
- [ ] If TEAL uses `arg 0`, `arg 1`, etc., define corresponding `runtime_args`
- [ ] Examples are provided for complex parameters
- [ ] `go build ./...` succeeds
- [ ] `go test ./lsig/multitemplate/...` passes

## Related: Falcon-1024 DSA Templates

This guide covers **generic LogicSig templates** (TEAL-only, no cryptographic keys). For **DSA-based templates** that combine Falcon-1024 signatures with parameterized TEAL conditions (timelock, hashlock), see:

- **`lsig/falcon1024template/`** - YAML-based Falcon DSA composition templates
- **`doc/DEV_New_DSA_LSig.md`** - Guide for implementing DSA LogicSigs with ComposedDSA

### Key Differences

| Aspect | Multitemplate (this guide) | Falcon1024template |
|--------|---------------------------|-------------------|
| **Key type** | Generic LogicSig | DSA LogicSig |
| **Cryptographic keys** | None | Falcon-1024 keypair |
| **YAML sources** | `lsig/multitemplate/templates/` (embedded) or keystore | `lsig/falcon1024template/templates/` (embedded) or keystore |
| **Example** | `hashlock-v1`, `timelock-v1` | `falcon1024-hashlock-v1` |
| **TEAL** | Full standalone TEAL program | TEAL suffix (preamble + verify auto-generated) |
| **Signing** | N/A (TEAL conditions only) | Falcon-1024 signature |

Both systems use the same `@variable` substitution engine (`internal/tealsubst`). Falcon templates use the **ComposedDSA** architecture, which wraps a user-authored TEAL suffix with an auto-generated preamble and Falcon verification footer.
