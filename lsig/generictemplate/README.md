# Generic Template LogicSig Provider

A declarative YAML-based system for defining generic LogicSig templates. In the
default build, templates are imported into an identity keystore with `apstore`
and registered after unlock/reload.

## Quick Start

1. Create a YAML file in `library/templates/` or another path.
2. Run `apstore template import <yaml-file>`.
3. Unlock or reload `apsigner`; the template appears in the TUI key type selection.

## YAML Schema (v2)

```yaml
schema_version: 1
derivation_version: 3     # TEAL v13 compiler-owned auto-salting
template_type: generic
template_mode: strict      # strict | generated
family: timelock           # Template family name
version: 2                 # Version number within family
display_name: "Timelock"   # Human-readable name for UI
description: "..."         # Short description
display_color: "35"        # ANSI color code (optional, default: 35/magenta)

parameters:
  - name: recipient        # Creation-time parameter
    label: "Recipient"     # UI label
    description: "..."     # UI tooltip
    type: address          # address | uint64 | bytes
    required: true

    # UI hints (optional)
    example: "AAAA..."     # Example value shown in UI
    placeholder: "Enter.." # Placeholder text for input field
    input_modes:           # Alternate UI entry modes (optional)
      - name: preimage
        label: "Preimage"
        transform: sha256  # Hash entered bytes before storing this parameter
        input_type: string # Treat input as raw text instead of hex bytes
      - name: hash
        label: "SHA256 Hash"

    # Constraints (optional, uint64 only)
    min: 1                 # Minimum allowed value
    max: 1000000           # Maximum allowed value

    # Default (optional)
    default: "100"         # Default value for optional params

template_variables:
  - name: recipient
    source: parameter
    parameter: recipient
    type: address
    constant: byte

runtime_args:              # Arguments provided at signing time (optional)
  - name: preimage         # Internal name used in --lsig-arg
    label: "Preimage"      # UI label
    description: "..."     # Help text
    type: bytes            # bytes | string | uint64
    byte_length: 32        # Expected byte length (0 = variable)

teal: |
  #pragma version 10
  txn Receiver
  $recipient
  ==
  return
```

## Parameter Types

| Type | Description | Validation |
|------|-------------|------------|
| `address` | Algorand address | 58 chars, SDK checksum validation |
| `address[]` | Comma-separated Algorand addresses | Each address is validated; duplicates rejected |
| `uint64` | Unsigned integer | Digits only, fits in uint64, optional min/max |
| `bytes` | Hex-encoded bytes | Valid hex, optional 0x prefix accepted |

`address[]` params are unordered by definition. Item order is canonicalized, so
`ADDR1,ADDR2` and `ADDR2,ADDR1` derive the same LogicSig program and address.

## Strict Template Variables

Strict templates reference declared creation-time constants with `$name`:

- `uint64` variables render through generated `intcblock` entries
- `bytes` variables render through generated `bytecblock` entries
- `address` variables render as decoded 32-byte public keys in `bytecblock`

Runtime args are separate signing-time inputs and are not template variables.

Templates that need bounded list expansion must use `template_mode: generated`.
Generated mode supports only the restricted `{{range @name}} ... {{.}} ... {{end}}`
construct plus scalar `@name` substitution.

## Parameters vs Runtime Args

| | Parameters | Runtime Args |
|---|---|---|
| **When provided** | Key creation time | Transaction signing time |
| **Embedded in** | TEAL bytecode (`$name` constants) | LogicSig args (arg 0, arg 1, ...) |
| **Example use** | Recipient address, timeout round | Preimage for hashlock |

## Guarantees

- **Static TEAL only**: No runtime transforms or dynamic code generation
- **Deterministic**: Same parameters always produce identical bytecode
- **Validated at load time**: Invalid templates fail at import or are skipped during reload
- **Versioned derivation**: Omitted `derivation_version` means no generated
  salting; generation succeeds only when the unmodified bytecode is already
  off-curve. `derivation_version: 1` preserves the legacy pushbytes/pop salt
  marker; `derivation_version: 2` uses a trailing dead-code `bytecblock` and
  requires the template TEAL to end with `return` or `err`;
  `derivation_version: 3` requires TEAL v13 and delegates auto-salting to the
  configured algod compiler

## Adding a New Template

```yaml
# library/templates/mytemplate-v1.yaml
schema_version: 1
derivation_version: 3
template_type: generic
template_mode: strict
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

template_variables:
  - name: target
    source: parameter
    parameter: target
    type: address
    constant: byte

teal: |
  #pragma version 10
  txn Receiver
  $target
  ==
  return
```

Then install: `apstore template import library/templates/mytemplate-v1.yaml`
