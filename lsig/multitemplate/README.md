# Multitemplate LogicSig Provider

A declarative YAML-based system for defining generic LogicSig templates. Templates are embedded at compile time and automatically registered with the genericlsig registry.

## Quick Start

1. Create a YAML file in `lsig/multitemplate/templates/`
2. Rebuild the binary
3. Your template appears in the TUI key type selection

## YAML Schema (v1)

```yaml
schema_version: 1          # Schema version (required for forward compatibility)
family: timelock           # Template family name
version: 2                 # Version number within family
display_name: "Timelock"   # Human-readable name for UI
description: "..."         # Short description
display_color: "35"        # ANSI color code (optional, default: 35/magenta)

parameters:
  - name: recipient        # Internal name (used in TEAL as @recipient)
    label: "Recipient"     # UI label
    description: "..."     # UI tooltip
    type: address          # address | uint64 | bytes
    required: true

    # UI hints (optional)
    example: "AAAA..."     # Example value shown in UI
    placeholder: "Enter.." # Placeholder text for input field

    # Constraints (optional, uint64 only)
    min: 1                 # Minimum allowed value
    max: 1000000           # Maximum allowed value

    # Default (optional)
    default: "100"         # Default value for optional params

runtime_args:              # Arguments provided at signing time (optional)
  - name: preimage         # Internal name used in --lsig-arg
    label: "Preimage"      # UI label
    description: "..."     # Help text
    type: bytes            # bytes | string | uint64
    byte_length: 32        # Expected byte length (0 = variable)

teal: |
  #pragma version 10
  // Use @variable_name for parameter substitution
  txn Receiver
  addr @recipient
  ==
  return
```

## Parameter Types

| Type | Description | Validation |
|------|-------------|------------|
| `address` | Algorand address | 58 chars, SDK checksum validation |
| `uint64` | Unsigned integer | Digits only, fits in uint64, optional min/max |
| `bytes` | Hex-encoded bytes | Valid hex, optional 0x prefix accepted |

## Variable Substitution

Variables in TEAL source are marked with `@` prefix:
- `@recipient` → replaced with address value as-is
- `@amount` → replaced with uint64 value as-is
- `@hash` → replaced with `0x` + hex value

## Parameters vs Runtime Args

| | Parameters | Runtime Args |
|---|---|---|
| **When provided** | Key creation time | Transaction signing time |
| **Embedded in** | TEAL bytecode (@substitution) | LogicSig args (arg 0, arg 1, ...) |
| **Example use** | Recipient address, timeout round | Preimage for hashlock |

## Guarantees

- **Static TEAL only**: No runtime transforms or dynamic code generation
- **Deterministic**: Same parameters always produce identical bytecode
- **Validated at load time**: Invalid templates fail at startup, not runtime

## Adding a New Template

```yaml
# lsig/multitemplate/templates/mytemplate-v1.yaml
schema_version: 1
family: mytemplate
version: 1
display_name: "My Template"
description: "Description for UI"

parameters:
  - name: target
    label: "Target Address"
    type: address
    required: true
    example: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"

teal: |
  #pragma version 10
  txn Receiver
  addr @target
  ==
  return
```

Then rebuild: `make all`
