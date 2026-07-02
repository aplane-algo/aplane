# APlane Shell Plugin Architecture

## Overview

APlane Shell supports **external plugins** — standalone executables that run as separate processes and communicate via JSON-RPC over stdin/stdout. Plugins can be written in any language (Go, TypeScript, Python, etc.) and are discovered at runtime.

| Feature | Detail |
|---|---|
| **Language** | Any (Go, Node.js, Python, etc.) |
| **Loading** | At runtime from the filesystem |
| **Communication** | JSON-RPC over stdin/stdout |
| **Security** | Mandatory OS sandboxing, process isolation, no direct key access |
| **Use Case** | DeFi integrations, custom workflows, third-party extensions |

---

## Plugins

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Plugin Ecosystem                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐     │
│  │ Echo     │  │ Custom   │  │ Custom   │  │  Custom  │     │
│  │ Plugin   │  │ Plugin A │  │ Plugin B │  │  Plugin  │     │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘     │
│       │              │              │              │        │
│       └──────────────┴──────────────┴──────────────┘        │
│                           │ JSON-RPC                        │
└───────────────────────────┼─────────────────────────────────┘
                            ▼
        ┌─────────────────────────────────────┐
        │            apshell                  │
        │  • Plugin discovery & lifecycle     │
        │  • JSON-RPC communication           │
        │  • Transaction intent processing    │
        │  • Parameter resolution             │
        │  • Transaction signing & submission │
        └──────────────┬──────────────────────┘
                       │
                       ▼
        ┌─────────────────────────────────────┐
        │           apsigner                 │
        │  • Key management                   │
        │  • Transaction signing              │
        └─────────────────────────────────────┘
```

### Plugin Lifecycle

1. **Discovery**: APlane Shell scans plugin directories at startup
2. **Validation**: Manifests are validated, checksums are verified, executables checked
3. **Lazy Loading**: Plugin process spawned when first command is invoked
4. **Initialization**: Plugin receives `initialize` call with network config
5. **Execution**: Plugin processes `execute` calls for commands
6. **Idle**: Plugin remains running between commands
7. **Cleanup**: Plugin receives `shutdown` call when APlane Shell exits

### Plugin Discovery

Plugins are discovered from the client plugin catalog:

1. `$APCLIENT_DATA/plugins.yaml` lists enabled plugin directory names.
2. `$APCLIENT_DATA/plugins.available/<name>/` stores the corresponding plugin payload.

Each plugin must reside in its own subdirectory containing:
- `manifest.json` - Plugin manifest
- `checksums.sha256` - Integrity file listing plugin files
- Executable file (as specified in manifest)
- Any supporting files (libraries, scripts, etc.)

Symlinked plugin directories are ignored. If multiple enabled catalog
directories declare the same manifest `name`, the first enabled entry wins.

### The Manifest (`manifest.json`)

This file is the entry point for any external plugin.

**Example:**
```json
{
  "name": "my-plugin",
  "version": "1.0.0",
  "description": "My awesome plugin.",
  "author": "Author Name",
  "homepage": "https://github.com/author/plugin",

  "executable": "./my-plugin-executable",
  "args": [],

  "commands": [
    {
      "name": "my-command",
      "description": "Does something awesome.",
      "usage": "my-command <action> <amount> <asset>",
      "examples": ["my-command deposit 100 algo"],
      "category": "defi",
      "arg_specs": [
        {"type": "keyword", "values": ["deposit", "withdraw"]},
        {"type": "number"},
        {"type": "asset"}
      ]
    }
  ],

  "functions": [
    {
      "name": "myPluginDeposit",
      "description": "Deposit assets into the plugin",
      "params": [
        {"name": "amount", "type": "number", "description": "Amount to deposit"},
        {"name": "asset", "type": "asset", "description": "Asset name or ID"},
        {"name": "addr", "type": "address", "description": "Account address or alias"}
      ],
      "returns": "{txid: string, confirmed: boolean}",
      "command": ["deposit", "$amount", "$asset", "for", "$addr"]
    }
  ],

  "networks": ["testnet", "mainnet", "betanet"],
  "timeout": 30,
  "manifest_format": "1.0"
}
```

**Manifest Fields:**

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `name` | Yes | - | Unique plugin identifier |
| `version` | Yes | - | Semantic version (e.g., "1.0.0") |
| `description` | Yes | - | Brief description of the plugin |
| `author` | No | - | Plugin author |
| `homepage` | No | - | Plugin homepage URL |
| `executable` | Yes | - | Path to executable (relative to plugin dir, or system command) |
| `args` | No | `[]` | Command-line arguments to pass to the executable |
| `commands` | Yes | - | Array of commands the plugin provides (for CLI and tab completion) |
| `functions` | No | `[]` | Array of typed metadata for docs and automation surfaces (see [Typed Plugin Functions](#typed-plugin-functions)) |
| `networks` | No | all | Networks the plugin supports (empty = all networks) |
| `timeout` | No | 30 | Execution timeout in seconds |
| `manifest_format` | No | "1.0" | Plugin manifest schema format |

`manifest_format` describes the manifest file schema. It is separate from the
JSON-RPC envelope version, which is always the `jsonrpc: "2.0"` field in
runtime request and response frames.

**Note:** The `executable` field can reference:
- A local file: `"./plugin-binary"` or `"./dist/plugin.js"`
- A system command: `"node"` with `"args": ["dist/plugin.js"]`

The manifest does not define a per-plugin network permission. APlane
starts external plugins with network access enabled so they can reach the
configured algod, KMD, or indexer services they need.

**Command Fields:**

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Command name (what user types) |
| `description` | Yes | Brief description shown in help |
| `usage` | No | Usage string showing arguments |
| `examples` | No | Array of example invocations |
| `returns` | No | Human-readable description of the command result shape |
| `category` | No | Category for help grouping |
| `arg_specs` | No | Array of argument completion specs |

**ArgSpec Fields (for `arg_specs` array):**

| Field | Required | Description |
|-------|----------|-------------|
| `type` | Conditional | One of: `address`, `asset`, `set`, `keyword`, `number`, `file`, `custom`. Required if no `branches`. |
| `values` | No | For `keyword`: array of valid values. For `custom`: completer identifier |
| `branches` | No | Array of conditional branches for context-dependent completion |

**ArgSpec Types:**

| Type | Description | Completion Source |
|------|-------------|-------------------|
| `address` | Algorand address | Signer addresses + alias addresses |
| `asset` | ASA unit name | "algo" + registered ASAs |
| `set` | Address set | Set names with @ prefix |
| `keyword` | Fixed keyword | Values from `values` field |
| `number` | Numeric value | No completion |
| `file` | File path | Filesystem |
| `custom` | Reserved for plugin-provided completion | No completions available |

**Conditional Branching:**

For commands with subcommands that have different argument patterns, use `branches`:

```json
{
  "arg_specs": [
    {"type": "keyword", "values": ["deposit", "withdraw", "balance"]},
    {
      "branches": [
        {
          "when": {"arg": 0, "matches": "^deposit$"},
          "specs": [
            {"type": "number"},
            {"type": "keyword", "values": ["into"]},
            {"type": "custom", "values": ["validator_id"]}
          ]
        },
        {
          "when": {"arg": 0, "matches": "^withdraw$"},
          "specs": [
            {"type": "number"},
            {"type": "keyword", "values": ["from"]},
            {"type": "custom", "values": ["pool_id"]}
          ]
        },
        {
          "when": {"arg": 0, "matches": "^balance$"},
          "specs": [
            {"type": "address"}
          ]
        }
      ]
    }
  ]
}
```

**Branch Fields:**

| Field | Description |
|-------|-------------|
| `when.arg` | Argument index to check (0-based) |
| `when.matches` | Regex pattern to match against the argument value |
| `specs` | ArgSpecs to use when condition matches |

### Typed Plugin Functions

Plugin behavior is defined by commands; function metadata is supplementary.
Plugins can expose **typed function metadata** that documents an intended
JavaScript/automation call shape. Function-only plugins are rejected.

Typed metadata describes a function-style call shape:

- Named, typed parameters
- Returns data directly (not wrapped)
- Throws exceptions on error (instead of returning `success: false`)
- Provides a function-style interface for documentation and automation
  surfaces

Executable runtime code uses plugin commands:
```javascript
let r = plugin("my-plugin", "status", "alice")
if (r.success) {
    print(r.data.summary)
}
```

#### Function Schema

Add a `functions` array to your manifest alongside `commands`:

```json
{
  "name": "my-plugin",
  "version": "1.0.0",
  "commands": [...],
  "functions": [
    {
      "name": "myPluginDoSomething",
      "description": "Does something useful",
      "params": [
        {"name": "amount", "type": "number", "description": "Amount in ALGO"},
        {"name": "addr", "type": "address", "description": "Account address or alias"}
      ],
      "returns": "{txid: string, confirmed: boolean}",
      "command": ["do-something", "$amount", "for", "$addr"]
    }
  ]
}
```

#### Function Fields

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | JavaScript function name (camelCase, e.g., `retiDeposit`) |
| `description` | Yes | What the function does |
| `params` | Yes | Array of parameter definitions |
| `returns` | Yes | Return type description for documentation and automation metadata |
| `command` | Yes | Command template with `$param` placeholders |

#### Parameter Types

| Type | JS Type | Description |
|------|---------|-------------|
| `string` | `string` | Generic string |
| `number` | `number` | Numeric value |
| `address` | `string` | Algorand address or alias (resolved automatically) |
| `asset` | `string \| number` | Asset name (e.g., "usdc") or numeric ID (resolved for current network) |

#### Command Template

The `command` array defines how function parameters map to plugin command arguments. Use `$paramName` for substitution:

```json
{
  "name": "tinymanSwap",
  "params": [
    {"name": "amount", "type": "number"},
    {"name": "fromAsset", "type": "asset"},
    {"name": "toAsset", "type": "asset"},
    {"name": "addr", "type": "address"}
  ],
  "command": ["$amount", "$fromAsset", "to", "$toAsset", "for", "$addr"]
}
```

When called as `tinymanSwap(100, "usdc", "algo", "alice")`, this generates the command:
```
["100", "usdc", "to", "algo", "for", "alice"]
```

#### Complete Example: Generic Workflow Plugin

```json
{
  "name": "workflow-plugin",
  "version": "1.0.0",
  "description": "Example workflow plugin for account status and queued actions",
  "executable": "node",
  "args": ["dist/workflow-plugin.js"],

  "commands": [
    {
      "name": "workflow",
      "description": "Inspect workflow state and submit actions",
      "usage": "workflow list | status <addr> | submit <amount> algo for <addr> | cancel <action-id> for <addr>",
      "category": "ops"
    }
  ],

  "functions": [
    {
      "name": "workflowList",
      "description": "List all queued workflow actions",
      "params": [],
      "returns": "{actions: [{id: number, state: string, owner: string}]}",
      "command": ["list"]
    },
    {
      "name": "workflowStatus",
      "description": "Get workflow status for an account",
      "params": [
        {"name": "addr", "type": "address", "description": "Account address or alias"}
      ],
      "returns": "{summary: string, pending: number, account: string}",
      "command": ["status", "$addr"]
    },
    {
      "name": "workflowSubmit",
      "description": "Submit a new workflow action",
      "params": [
        {"name": "amount", "type": "number", "description": "Amount of ALGO to submit"},
        {"name": "addr", "type": "address", "description": "Account address or alias"}
      ],
      "returns": "{txids: string[], actionId: number}",
      "command": ["submit", "$amount", "algo", "for", "$addr"]
    },
    {
      "name": "workflowCancel",
      "description": "Cancel a queued workflow action",
      "params": [
        {"name": "actionId", "type": "number", "description": "Action ID to cancel"},
        {"name": "addr", "type": "address", "description": "Account address or alias"}
      ],
      "returns": "{txids: string[], actionId: number, cancelled: boolean}",
      "command": ["cancel", "$actionId", "for", "$addr"]
    }
  ],

  "networks": ["testnet", "mainnet"],
  "timeout": 120
}
```

#### How It Works

1. **Discovery**: At startup, `apshell` discovers plugins and parses their manifests
2. **Metadata loading**: Function metadata is loaded for documentation and automation surfaces
3. **Execution**: JavaScript calls the command runtime explicitly with `plugin(name, ...args)`
4. **RPC call**: The plugin's `execute` RPC method receives the selected command and argv-style args
5. **Result**: JavaScript receives `{success, message, data, presentation}` and decides how to handle it

The `command` array in a `functions` entry documents how a function-shaped call should map to
command arguments. It is not an independently registered JavaScript function.

#### Metadata Projection

Plugin command metadata is projected in command-first form:

```
PLUGIN COMMANDS:
Plugins are executed through plugin(name, ...args). Typed manifest metadata may exist for documentation and automation; executable behavior is command-first.

- workflow(...args: string[]): PluginResult
  Inspect workflow state and submit actions
  Usage: workflow list | status <addr> | submit <amount> algo for <addr> | cancel <action-id> for <addr>
```

This keeps generated or scripted usage aligned with the plugin's
command-based runtime surface.

#### Adding Typed Functions

If your plugin only has `commands`, you can add `functions` alongside them:

1. Keep `commands` for tab completion and the command interface
2. Add `functions` array with typed function definitions
3. Function names should be descriptive (e.g., `workflowStatus` not just `status`)
4. Keep one plugin `execute` handler for the command interface

Plugins with typed metadata may present the typed shape in documentation or
automation surfaces; commands are the executable runtime contract and are
available for direct command-line use.

### JSON-RPC Protocol

Plugins communicate with APlane Shell using JSON-RPC 2.0 over stdin/stdout.

#### initialize

Called once after the plugin starts.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "initialize",
  "params": {
    "network": "testnet",
    "algodUrl": "https://testnet-api.4160.nodely.dev",
    "algodToken": "",
    "indexerUrl": "https://testnet-idx.4160.nodely.dev",
    "version": "1.0"
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "success": true,
    "message": "Plugin initialized",
    "version": "1.0.0"
  }
}
```

#### execute

Called to run a specific command.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "execute",
  "params": {
    "command": "command-name",
    "args": ["arg1", "arg2"],
    "context": {
      "accounts": ["ADDR1...", "ADDR2..."],
      "assets": [{"assetId": 10458941, "name": "USDC", "unitName": "USDC", "decimals": 6}],
      "addressMap": {"alice": "ADDR1...", "bob": "ADDR2..."},
      "network": "testnet",
      "continuation": {}
    }
  }
}
```

**Response (informational):**
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "success": true,
    "message": "Validator list loaded",
    "data": {"validators": [{"id": 1, "stakers": 20}]},
    "presentation": {
      "title": "Reti Validators",
      "summary": "Showing 1 validator",
      "sections": [
        {
          "kind": "table",
          "columns": ["ID", "Stakers"],
          "rows": [{"cells": ["1", "20"]}]
        }
      ]
    }
  }
}
```

**Response (with transactions):**
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "success": true,
    "message": "Swap quote: 1.5 USDC for 10 ALGO",
    "transactions": [
      {
        "type": "raw",
        "encoded": "gqNzaWfEQE..."
      }
    ],
    "requiresApproval": true,
    "data": {
      "pool_address": "POOL...",
      "amount_in": "10000000",
      "amount_out_expected": "1500000"
    },
    "presentation": {
      "title": "Swap Quote",
      "summary": "Review before approval",
      "sections": [
        {
          "kind": "key_value",
          "items": [
            {"label": "Input", "value": "10.000000 ALGO"},
            {"label": "Expected Out", "value": "1.500000 USDC"}
          ]
        }
      ]
    }
  }
}
```

**Presentation Notes:**

- `data` is the canonical machine-readable result payload.
- `presentation` is optional human-oriented display metadata for apshell text mode.
- `message` should be a concise summary or fallback, not a second full copy of `data`.
- If `presentation` is absent, apshell falls back to `message` and transaction status output.

#### getInfo

Returns metadata about the plugin.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "getInfo",
  "params": {}
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "result": {
    "name": "plugin-name",
    "version": "1.0.0",
    "description": "Plugin description",
    "author": "Author",
    "commands": ["command1", "command2"],
    "networks": ["testnet", "mainnet"],
    "status": "ready"
  }
}
```

#### shutdown

Notifies the plugin to exit gracefully.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "method": "shutdown",
  "params": {}
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "result": {
    "success": true,
    "message": "Plugin shutdown"
  }
}
```

#### signTransactions

A host→plugin callback used in the `presign-plan` group flow (see
[Plugin Transaction Flows](#plugin-transaction-flows-group-modes)). After APlane
canonicalizes the group, it calls this method to have the plugin sign the slots it
declared in `pluginSigners`, over the canonical bytes. The plugin's signing material is
never exported to APlane: the plugin locates each key from the opaque `signerRef` it
supplied and signs by reference. A plugin that never returns `groupMode: "presign-plan"`
does not handle this method.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 5,
  "method": "signTransactions",
  "params": {
    "requests": [
      {
        "index": 0,
        "address": "PLUGIN_OWNED_ADDR...",
        "signerRef": "opaque-plugin-key-id",
        "encoded": "base64-canonical-unsigned-txn-msgpack"
      }
    ]
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 5,
  "result": {
    "signed": [
      {
        "index": 0,
        "encoded": "base64-signed-txn-msgpack"
      }
    ]
  }
}
```

**Request fields** (`requests[]`):

| Field | Type | Description |
|-------|------|-------------|
| `index` | int | Position of the slot in the canonical group |
| `address` | string | Sender of the slot |
| `signerRef` | string | Opaque identifier echoed from the slot's `pluginSigners` entry; the plugin uses it to locate its key |
| `encoded` | string | Base64 canonical unsigned transaction msgpack — the exact bytes the plugin signs |

**Response fields** (`signed[]`):

| Field | Type | Description |
|-------|------|-------------|
| `index` | int | Matches the request `index` |
| `encoded` | string | Base64 signed transaction msgpack for that slot |

The plugin returns one `signed` entry per request and signs the bytes exactly as
received. APlane submits the group as the union of these plugin-signed slots and its own
apsigner-signed slots; altering a slot's fields would break the shared group ID.

The core JSON-RPC surface every plugin handles (host→plugin) is:

- `initialize`
- `execute`
- `getInfo`
- `shutdown`

Plugins that use the `presign-plan` group flow also handle one additional host→plugin
method:

- `signTransactions`

There is intentionally no plugin→host signing callback. In particular,
`signTransaction` is not a supported method: a plugin may not ask apshell to
sign arbitrary bytes on its behalf. Plugins that own signing material use
`groupMode:"presign-plan"` and implement the host→plugin `signTransactions`
method above; plugins that need fully self-signed groups use
`groupMode:"pregrouped-signed"` with the mandatory decoded review path. Any
future plugin→host signing mechanism must be designed around mandatory decoded
review and fail-closed non-interactive behavior before it is added to the wire
protocol.

### Execution Context

APlane Shell provides execution context to plugins via the `context` field. The
runtime populates account, asset, alias, network, and continuation fields. The
protocol struct also reserves round/genesis/suggested-params fields; plugins
should not depend on those values unless the runtime explicitly populates them.

| Field | Type | Description |
|-------|------|-------------|
| `accounts` | `[]string` | List of all available account addresses (addresses that can sign) |
| `assets` | `[]object` | Structured known ASA metadata: `assetId`, `name`, `unitName`, `decimals` |
| `addressMap` | `map[string]string` | Alias → address mapping |
| `network` | `string` | Current network context token |
| `round` | `uint64` | Reserved; omitted unless explicitly populated by the runtime |
| `genesisId` | `string` | Reserved; omitted unless explicitly populated by the runtime |
| `genesisHash` | `string` | Reserved; omitted unless explicitly populated by the runtime |
| `suggestedParams` | `object` | Reserved; omitted unless explicitly populated by the runtime |
| `continuation` | `map[string]any` | Continuation context for multi-step workflows |

**Parameter Resolution (Priority Order):**

1. **ASA Names → Asset IDs**: Plugin receives structured `assets` metadata
   - Example: `assets: [{assetId: 10458941, name: "USDC", unitName: "USDC", decimals: 6}]`

2. **Aliases → Addresses**: Plugin receives `addressMap` with alias → address mappings
   - Example: `{"alice": "ALICE_ADDRESS...", "bob": "BOB_ADDRESS..."}`

### Transaction Intents

Plugins propose transactions by returning transaction intents in the execute response.
A `raw` (unsigned) intent is the default: APlane plans, signs, and submits it. A
`signed` intent carries an already-signed transaction and is valid only inside a plugin
group flow (`groupMode: "pregrouped-signed"`); see
[Plugin Transaction Flows](#plugin-transaction-flows-group-modes) below.

**TransactionIntent Fields:**

```go
type TransactionIntent struct {
    Type    string `json:"type"`    // "raw" (unsigned) or "signed" (pregrouped-signed)
    Encoded string `json:"encoded"` // Base64-encoded transaction msgpack
}
```

**Transaction Intent Types:**

| Type | Description | Required Fields |
|------|-------------|-----------------|
| `raw` | Fully formed unsigned transaction msgpack, base64-encoded | `encoded` |
| `signed` | Already-signed transaction msgpack, base64-encoded (only under `groupMode: "pregrouped-signed"`) | `encoded` |

### Multi-Step Workflows (Continuations)

For complex protocols that require multiple transaction submissions with confirmations between steps, plugins can use the continuation mechanism.

**Example Response with Continuation:**
```json
{
  "success": true,
  "message": "STEP 1: Create deposit escrow",
  "transactions": [
    {"type": "raw", "encoded": "..."}
  ],
  "requiresApproval": true,
  "continuation": {
    "command": "my-plugin",
    "args": ["_internal_step2", "arg1"],
    "context": {
      "escrowAddress": "ESCROW_ADDR...",
      "step2Data": "..."
    },
    "message": "Step 1 completed. Proceeding to Step 2..."
  }
}
```

**Continuation Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `command` | string | The plugin command to execute next |
| `args` | []string | Arguments for the next step |
| `context` | map | State to pass to the next step via `params.context.continuation` |
| `message` | string | Optional message to display before executing the next step |

**Execution Flow:**
1. Plugin returns Step 1 transactions + continuation
2. APlane Shell submits Step 1, waits for confirmation
3. APlane Shell automatically calls the continuation command
4. Continuation context is available in `params.context.continuation`
5. Plugin returns Step 2 transactions + continuation (or final result)
6. Process repeats until no continuation is returned

Continuation argument normalization follows the same manifest-driven rules as the initial command.
If a continuation command is not declared in the plugin manifest, APlane Shell has no `arg_specs`
metadata for it and will pass continuation args through unchanged.

### Unsupported `localSigners`

Top-level `localSigners` is intentionally unsupported. APlane does not accept
plugin-supplied secret keys, even for ephemeral accounts. If a plugin returns
`localSigners`, apshell rejects the result and tells the plugin author to use
one of the audited group modes below.

Plugins that need to sign accounts or LogicSigs outside apsigner custody must
either:

- return a complete, already-signed group with `groupMode:"pregrouped-signed"`,
  or
- use `groupMode:"presign-plan"` plus `pluginSigners`, so APlane can
  canonicalize the group and ask the plugin to sign only its declared slots over
  canonical bytes.

### Plugin Transaction Flows (Group Modes)

The default transaction intent flow covers plugins that propose transactions for
APlane-managed keys. Some protocols, however, need to take part in **building
and signing atomic groups that involve cryptography or signing
material APlane does not hold** — a LogicSig the plugin compiled, a key in an HSM, a
threshold quorum, or a counterparty's signature. The `ExecuteResult.groupMode` field
selects the flow:

| `groupMode` | Who signs each slot | APlane's role |
|---|---|---|
| _(empty)_ | apsigner | sign and submit APlane-managed raw transaction intents |
| `pregrouped-signed` | the plugin (every slot) | validate self-consistency and **submit verbatim**; apsigner signs nothing |
| `presign-plan` | plugin-owned slots **and** APlane-managed slots | canonicalize the group, call the plugin back to sign its slots, sign the managed slots, submit |

A plugin runs as an external process that holds its own keys; it can already build, sign,
and — unless it is network-sandboxed (`--unshare-net`) — submit its own groups. These
flows therefore add two things, and it is worth being precise about which is which.

**1. A governed submission path (`pregrouped-signed`) — not a new capability.** The plugin
returns a complete, already-signed atomic group (every intent `type: "signed"`). APlane
checks the group is internally consistent and submits it without modification — apsigner is
never involved. The plugin could have signed and broadcast these exact bytes itself; what
APlane adds is governance, not signing power: a **mandatory client-side review** is the
human-acceptance gate, it **fails closed** when run non-interactively (it will not
broadcast a group the operator never saw), and for a network-sandboxed plugin APlane is
also the only path to algod.

**2. Co-signing with managed accounts (`presign-plan`) — the one genuinely new capability.**
Only apsigner can produce a signature for an apsigner-held account, so atomically combining
the plugin's own signatures with apsigner's — under apsigner's policy and approval — is the
single thing a plugin cannot do on its own. The plugin returns an *unsigned*
draft (every intent `type: "raw"`) plus a `pluginSigners` list declaring the slots it
will sign itself — each with an address, an opaque `signerRef`, and the byte size
(`lsigSize`) of the LogicSig it will attach. APlane canonicalizes the group: it pools
fees, recomputes the group ID, and adds LogicSig opcode-budget transactions **sized from
the declared `lsigSize` values**, while a guard asserts every original slot's
transaction fields are preserved (only the group ID and fee may change). APlane then
calls the plugin's `signTransactions` method to sign its owned slots over the *canonical*
bytes, and apsigner signs the APlane-managed slots under its normal policy and approval.
**The plugin's signing keys are never exported** — it signs by reference, via the
callback.

The plugin declares its owned slots via a top-level `pluginSigners` array in the execute
result, alongside the unsigned `raw` intents:

```json
{
  "success": true,
  "message": "Shielded deposit",
  "groupMode": "presign-plan",
  "transactions": [
    {"type": "raw", "encoded": "..."},
    {"type": "raw", "encoded": "..."}
  ],
  "requiresApproval": true,
  "pluginSigners": [
    {
      "address": "PLUGIN_OWNED_ADDR...",
      "kind": "plugin-callback",
      "signerRef": "opaque-plugin-key-id",
      "lsigSize": 2048
    }
  ]
}
```

**`pluginSigners` fields:**

| Field | Type | Description |
|-------|------|-------------|
| `address` | string | Sender of the slot the plugin signs |
| `kind` | string | Signer kind; `plugin-callback` |
| `signerRef` | string | Opaque plugin-owned identifier echoed back in the `signTransactions` request so the plugin can locate its key |
| `lsigSize` | int | Byte size of the LogicSig (program + args) the plugin attaches to this slot. APlane counts it toward the group's pooled LogicSig budget. Omit or `0` when the slot carries no LogicSig |

The `groupMode` field is the top-level selector for the flow; `presign-plan` requires a
`pluginSigners` entry for every plugin-owned slot, and `pregrouped-signed` uses no
`pluginSigners`.

Supporting machinery: a **per-plugin state directory** (`APSHELL_PLUGIN_STATE_DIR`) for
persisting keys, cursors, or watermarks across invocations, and a role-aware review
renderer that shows, per slot, which party signs it and which fees APlane-managed
accounts pay.

**Trust boundary.** In `presign-plan`, apsigner still owns its slots — it applies its
full policy and approval to the managed transactions, exactly as for a direct `/sign`.
A plugin can *add* signers to a group; it cannot bypass apsigner's authority over
apsigner's keys.

#### What these flows enable

A plugin could always compose groups with keys held anywhere — its own LogicSig, an HSM
key, an MPC quorum, a counterparty's signature — and submit them itself. What these flows
add is narrower and more precise: the ability to **atomically include apsigner's
managed-key signatures in such a group, under apsigner's policy and approval**, plus a
**uniform operator conduit** — honest review, approval, audit, and (when the plugin is
network-sandboxed) the only egress — over plugin-built groups, including ones APlane never
signs. That is a general extension point, not a one-off; it is the substrate for whole
classes of plugin:

| Plugin class | Examples | Mode used |
|---|---|---|
| **External / non-exportable custody** | HSM/KMS bridge, MPC or threshold-signature coordinator, hardware-wallet bridge | `presign-plan` (plugin signs its slot via the callback) |
| **Smart-signature / composed-LogicSig auth** | multisig, whitelist, hashlock/HTLC escrows, atomic swaps, fee sponsors (paymaster: managed account pays, plugin LogicSig authorizes) | `presign-plan` (budget sized from `lsigSize`) |
| **Counterparty / relayer flows** | RFQ or order-book fills (maker pre-signs, taker submits), gasless meta-transactions, signed-voucher redemption | `pregrouped-signed` (submit the counterparty-signed group verbatim) |
| **Privacy / shielded pools** | mixers, confidential transfers, private voting | `presign-plan` (fund a shielded deposit) + `pregrouped-signed` (self-authorizing spend) |

The common thread is a plugin that **brings its own cryptography or signing material and
composes it into transaction groups**, with apsigner retaining authority over its own
slots. Notably, the `presign-plan` budget mechanism keys on each slot's *LogicSig size*,
not on any key-type label — so it serves the entire composed-LogicSig family uniformly,
including schemes that already exist as APlane key types (Falcon multisig, whitelist,
guarded, composed DSAs), with no per-scheme code. If a plain key type later gains a
native on-chain signature (so it no longer needs a LogicSig), it simply drops out of the
budget-sizing path automatically; the flow does not change.

For the signer-side substrate beneath these flows — the `/plan` and `/sign` pipeline, the
LogicSig pool-capacity formula, and the passthrough/foreign signing modes — see
[TXN_MIXED_GROUPS.md](TXN_MIXED_GROUPS.md).

### Error Codes

**Standard JSON-RPC Error Codes:**

| Code | Constant | Description |
|------|----------|-------------|
| -32700 | ParseError | Invalid JSON |
| -32600 | InvalidRequest | Invalid request object |
| -32601 | MethodNotFound | Method not found |
| -32602 | InvalidParams | Invalid parameters |
| -32603 | InternalError | Internal error |

**Custom APlane Shell Error Codes:**

| Code | Constant | Description |
|------|----------|-------------|
| -32000 | PluginError | Generic plugin error |
| -32001 | NetworkError | Network request failed |
| -32002 | AuthenticationError | Authentication failed |
| -32003 | InsufficientFunds | Not enough balance |
| -32004 | InvalidAddress | Invalid Algorand address |
| -32005 | TransactionFailed | Transaction submission failed |

### Transaction Processing Flow

The default (`groupMode` empty) flow:

1. Plugin returns transaction intents in execute response
2. APlane Shell processes intents:
   - Decodes `raw` unsigned transactions from base64 → msgpack
   - Validates transaction structure
3. User approval (if `requiresApproval: true`)
4. APlane Shell signs transactions via Signer
5. APlane Shell submits transactions to network
6. Transaction IDs displayed to user

When the result sets `groupMode`, APlane Shell dispatches to the corresponding plugin
group flow instead — see [Plugin Transaction Flows](#plugin-transaction-flows-group-modes).

### Creating an External Plugin

1. **Choose a Language:** Any language that can read from stdin, write to stdout, and handle JSON.

2. **Implement the JSON-RPC Server:** Listen for JSON-RPC requests on stdin and send responses to stdout.

3. **Implement Required Methods:** `initialize`, `execute`, `getInfo`, `shutdown` (and `signTransactions` if the plugin uses the `presign-plan` group flow)

4. **Create a Manifest:** Write a `manifest.json` file.

5. **Install the Plugin:** Copy your plugin directory under `$APCLIENT_DATA/plugins.available/` and list its directory name in `$APCLIENT_DATA/plugins.yaml`.

**Example: Simple Echo Plugin (Go)**

```go
package main

import (
    "bufio"
    "encoding/json"
    "os"
)

type Request struct {
    JSONRPC string                 `json:"jsonrpc"`
    ID      interface{}            `json:"id"`
    Method  string                 `json:"method"`
    Params  map[string]interface{} `json:"params"`
}

type Response struct {
    JSONRPC string      `json:"jsonrpc"`
    ID      interface{} `json:"id"`
    Result  interface{} `json:"result"`
}

func main() {
    scanner := bufio.NewScanner(os.Stdin)
    encoder := json.NewEncoder(os.Stdout)

    for scanner.Scan() {
        var req Request
        if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
            continue
        }

        var result interface{}
        switch req.Method {
        case "initialize":
            result = map[string]interface{}{
                "success": true,
                "message": "Echo plugin initialized",
                "version": "1.0.0",
            }
        case "execute":
            args := req.Params["args"].([]interface{})
            message := ""
            for _, arg := range args {
                message += arg.(string) + " "
            }
            result = map[string]interface{}{
                "success": true,
                "message": "Echo command completed",
                "data": map[string]interface{}{
                    "echoed": strings.TrimSpace(message),
                },
                "presentation": map[string]interface{}{
                    "title": "Echo",
                    "summary": "Echoed user input",
                    "sections": []map[string]interface{}{
                        {
                            "kind": "text",
                            "text": "Echo: " + strings.TrimSpace(message),
                        },
                    },
                },
            }
        case "getInfo":
            result = map[string]interface{}{
                "name":        "echo-plugin",
                "version":     "1.0.0",
                "description": "Simple echo plugin",
                "commands":    []string{"echo"},
                "status":      "ready",
            }
        case "shutdown":
            result = map[string]interface{}{
                "success": true,
                "message": "Shutdown",
            }
            encoder.Encode(Response{JSONRPC: "2.0", ID: req.ID, Result: result})
            os.Exit(0)
        }

        encoder.Encode(Response{JSONRPC: "2.0", ID: req.ID, Result: result})
    }
}
```

### Environment Variables

Plugins receive these environment variables when started:

| Variable | Description |
|----------|-------------|
| `APSHELL_NETWORK` | Current network context token |
| `APSHELL_ALGOD_URL` | Algod node URL from `config.yaml` (empty if not configured) |
| `APSHELL_ALGOD_TOKEN` | Algod API token from `config.yaml` (empty for public nodes) |
| `APSHELL_INDEXER_URL` | Indexer URL |
| `APSHELL_PLUGIN` | Set to "1" to indicate plugin context |

Algod settings are read from the `networks.<network>.algod` section of `config.yaml`. If algod is not configured for the current network, plugins receive empty strings and must handle this gracefully.

### Development Guidelines

**Manifest Best Practices:**
1. Use semantic versioning
2. Declare minimum required networks
3. Set appropriate timeouts (network operations need more time)
4. Provide detailed command descriptions and examples

**Protocol Implementation:**
1. Implement all four required methods
2. Always respond with matching request ID
3. Use `jsonrpc: "2.0"` in all responses
4. Flush stdout after each response
5. Log errors to stderr (not stdout)

**Parameter Resolution:**
1. Prefer `assets` for ASA metadata and resolve symbols case-insensitively against `unitName` or `name`
2. Check `addressMap` for alias → address resolution
3. Validate addresses before use
4. Return clear error messages for unknown aliases/assets

**Transaction Generation:**
1. Use `type: "raw"` with base64-encoded msgpack transactions
2. Set `requiresApproval: true` for transactions requiring user confirmation
3. Include metadata in `data` field for user information
4. Ensure transactions use the correct network genesis hash from context

### Plugin Directory Layout

```
plugins.available/my-plugin/
├── manifest.json          # Plugin manifest
├── checksums.sha256       # Mandatory integrity file
├── my-plugin              # Executable (compiled binary)
├── package.json           # If Node.js plugin
├── node_modules/          # Dependencies (if needed)
└── README.md              # Plugin documentation
```

### Example Plugins

Example plugins are available in `examples/external_plugins/`:

| Plugin | Language | Description | Typed Metadata |
|--------|----------|-------------|----------------|
| **echo-plugin** | Go | Development-only protocol illustration; not bundled or installed | `echoMessage()` |
| **reti** | TypeScript / Node.js, built with Node SEA | Réti staking-protocol example; source-only, not bundled into production release archives | `retiList()`, `retiDeposit()`, `retiWithdraw()`, `retiBalance()`, `retiClaim()` |

These in-repo example plugins include typed metadata for documentation and
automation surfaces; executable runtime behavior is command-first.

For a dev environment, install every example plugin in one step:
```bash
make example-plugins
```
This builds every example, copies each one with a complete payload into
`$APCLIENT_DATA/plugins.available/`, and writes `plugins.yaml` enabling them.
The target is destructive on those two paths and is intended for dev client
data directories only. To build the examples without modifying `$APCLIENT_DATA`,
use `make build-example-plugins` instead and copy/enable manually.

Use `echo-plugin` only as a source-level illustration of the plugin protocol.
It is not bundled into release archives and install helpers do not copy it into
the plugin catalog.

### Bundled Plugins

Production bundled plugins live under the repository top-level `plugins/`
directory.

Use `algokit-localnet` when you want the supported LocalNet operations plugin
that talks to a running AlgoKit LocalNet through localhost algod/KMD APIs. It
does not shell out to `algokit`, `ak`, or `goal`. Release/install payloads stage
it under `plugins.available/algokit-localnet`; it becomes active when
`algokit-localnet` is listed in `$APCLIENT_DATA/plugins.yaml`. It reads LocalNet
endpoint and wallet overrides from `APLANE_LOCALNET_ALGOD_URL`,
`APLANE_LOCALNET_KMD_URL`, `APLANE_LOCALNET_TOKEN`,
`APLANE_LOCALNET_WALLET`, and `APLANE_LOCALNET_WALLET_PASSWORD`; `aplocalnet`
can activate the plugin and persist a KMD URL override into `apenv.sh`.
Use `reti` when you want a concrete example that:

- tracks network changes at execute time
- talks to the current Réti contracts through the TypeScript/Algokit client stack
- builds a standalone executable so Node.js and npm are build-time dependencies
- owns the Réti command surface without importing APlane `internal/` packages
- includes typed function metadata for documentation and automation surfaces

Reti's source lives under `examples/external_plugins/reti/`. The release
workflow does not build or stage it into production archives; build it only
through the explicit example-plugin workflow when you want to evaluate it
locally.

Release archives stage runtime plugin payloads at
`dist/bundled-plugins/<os>-<arch>/<plugin>` (currently `algokit-localnet`,
covering Linux and macOS amd64/arm64) and installers copy them into
`$APCLIENT_DATA/plugins.available/`.
Catalog entries are not loaded by `apshell` unless their directory names are
listed in `$APCLIENT_DATA/plugins.yaml`; installer runs refresh staged catalog
entries and preserve existing activation choices.

### Security Model

**OS-Level Sandboxing:**

External plugins run in OS-level sandboxes that restrict filesystem access. This prevents malicious or compromised plugins from accessing sensitive data.

| Platform | Technology | Status |
|----------|------------|--------|
| Linux | [bubblewrap](https://github.com/containers/bubblewrap) | Required (`apt install bubblewrap`) |
| macOS | sandbox-exec (Seatbelt) | Built-in |
| Windows | Not supported | Use WSL2 (runs Linux sandbox) |

**Sandboxing is mandatory.** If the sandbox is unavailable (e.g., bubblewrap not installed on Linux), plugins will not run.

**What plugins CAN access:**
- `/usr`, `/lib`, `/lib64`, `/bin`, `/sbin` (read-only) - system binaries and libraries
- `/etc/ssl`, `/etc/ca-certificates` (read-only) - TLS certificates
- `/etc/resolv.conf`, `/etc/hosts`, `/etc/nsswitch.conf` (read-only) - DNS resolution
- Plugin directory (read-only) - the plugin's own files
- `/tmp` and platform temporary directories (read-write) - temporary files
- Network - enabled for all external plugins for algod, KMD, or indexer API calls

**What plugins CANNOT access:**
- `~/.ssh` - SSH keys
- `~/.aws` - AWS credentials
- `~/.gnupg` - GPG keys
- `~/.config` - application configs
- User home directory (except plugin dir if located there)
- Any path not explicitly mounted

**Sensitive environment variables filtered:**
- `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`
- `GITHUB_TOKEN`, `GH_TOKEN`, `NPM_TOKEN`
- `SSH_AUTH_SOCK`, `SSH_AGENT_PID`, `GPG_AGENT_INFO`

**Linux Sandbox Details (bubblewrap):**

Plugins run in isolated namespaces:
- User namespace (`--unshare-user`)
- PID namespace (`--unshare-pid`)
- IPC namespace (`--unshare-ipc`)
- UTS namespace (`--unshare-uts`)
- Cgroup namespace (`--unshare-cgroup`)
- Network is shared (plugins need algod, KMD, or indexer access)

The sandbox dies with the parent process (`--die-with-parent`), preventing orphaned sandboxed processes.

**macOS Sandbox Details (Seatbelt):**

Uses dynamically generated Seatbelt profiles with `sandbox-exec`. The profile:
- Denies all access by default (`(deny default)`)
- Explicitly allows required paths and operations
- Blocks sensitive home directory paths
- Allows filesystem metadata reads needed by Node.js/TLS/DNS startup while
  keeping file contents behind the explicit read allowlist

**Verifying Sandbox Status:**

When a plugin starts, you'll see:
```
[plugin-name] Running in sandbox (bubblewrap (Linux))
```
or
```
[plugin-name] Running in sandbox (sandbox-exec (macOS))
```

**Process Isolation:**
- Plugins run as separate subprocesses
- Cannot access APlane Shell memory or keys
- Communication only via stdin/stdout

**No Direct Key Access:**
- Plugins cannot sign transactions
- Only propose transaction intents
- APlane Shell/Signer performs all signing
- Plugins that need to bring their own signing material must use
  `pregrouped-signed` or `presign-plan`; apshell never accepts plugin-supplied
  secret keys.

**User Approval:**
- Transactions with `requiresApproval: true` require user confirmation
- User sees decoded transaction details before approval

**Resource Limits:**
- Timeout enforcement (default 30s)
- Process cleanup on timeout or error

**Integrity Verification:**
- All plugins must include `checksums.sha256` with SHA256 hashes
- Executable must be listed in checksums
- Entries use sha256sum-style `<64-hex-sha256><spaces><relative-file>` lines
- Paths listed in `checksums.sha256` must stay inside the plugin directory
- If `executable` names a system command, the first manifest arg is treated as
  the plugin-owned executable/script for checksum verification
- Checksums verified at discovery time

---

## Plugin Development Guidelines

This section outlines best practices for developing robust external plugins.

### Handle Network Changes

**Important:** Users can switch network context tokens at any time during a session. Plugins must handle this correctly.

The network is provided in two places:
1. **Initialization** (`initialize` method): `params.network` - the network when the plugin started
2. **Execution** (`execute` method): `context.network` - the current network for this command

**Problem:** If a plugin only uses the initialization network, it will use the wrong network after the user switches. For example, resolving mainnet USDC (31566704) on testnet will fail with a 404 error.

**Solution:** Always check `context.network` in your execute handler and update if changed:

```javascript
// JavaScript example
async function handleExecute(params) {
    const context = params.context || {};

    // Check if network changed since initialization
    if (context.network && context.network !== pluginState.network) {
        logInfo(`Network changed: ${pluginState.network} -> ${context.network}`);
        pluginState.network = context.network;
        // Reinitialize network-specific resources if needed (API clients, app IDs, etc.)
    }

    // ... rest of execute logic
}
```

```go
// Go example
func handleExecute(params ExecuteParams) (*ExecuteResult, error) {
    if params.Context.Network != "" && params.Context.Network != pluginState.Network {
        log.Printf("Network changed: %s -> %s", pluginState.Network, params.Context.Network)
        pluginState.Network = params.Context.Network
        // Reinitialize network-specific resources
    }

    // ... rest of execute logic
}
```

### Asset Resolution

The `context.assets` array provides structured ASA metadata. Note:
- **ALGO is NOT in `assets`** - it's the native currency, not an ASA
- Plugins should handle "ALGO" or "algo" natively (typically asset ID 0)
- Asset IDs are network-specific (e.g., USDC is 31566704 on mainnet, 10458941 on testnet)

```javascript
// Handle ALGO specially
function resolveAssetId(assetIdentifier, assets) {
    if (assetIdentifier.toLowerCase() === 'algo') {
        return 0; // ALGO is always asset ID 0
    }

    const normalized = assetIdentifier.toLowerCase();
    const match = (assets || []).find(asset =>
        asset.unitName?.toLowerCase() === normalized ||
        asset.name?.toLowerCase() === normalized
    );
    if (match) {
        return match.assetId;
    }

    // Try parsing as numeric asset ID
    const parsed = parseInt(assetIdentifier);
    if (!isNaN(parsed)) {
        return parsed;
    }

    throw new Error(`Unknown asset: ${assetIdentifier}`);
}
```

### Address Resolution

The `context.addressMap` provides alias → address mappings. Always resolve aliases before using addresses:

```javascript
function resolveAddress(input, addressMap) {
    // Check if it's already an address (58-char base32)
    if (/^[A-Z2-7]{58}$/.test(input)) {
        return input;
    }

    // Try alias lookup
    if (addressMap && addressMap[input]) {
        return addressMap[input];
    }

    throw new Error(`Unknown account: ${input}`);
}
```

### Error Handling

- Return clear error messages that help users understand what went wrong
- Include the operation that failed and any relevant IDs (asset IDs, addresses)
- For network errors, indicate if it might be a network mismatch issue

### Testing Across Networks

Always test your plugin on multiple networks:
1. Start on testnet, run commands
2. Switch to mainnet (`network mainnet`), run the same commands
3. Switch back to testnet, verify it still works

---

## See Also

- [Plugin Transaction Flows](#plugin-transaction-flows-group-modes) - The `pregrouped-signed` / `presign-plan` group modes and the plugin classes they enable
- [TXN_MIXED_GROUPS.md](TXN_MIXED_GROUPS.md) - LogicSig pool capacity and mixed-group signing on the signer side
- [plugins/README.md](../plugins/README.md) - Bundled production plugins
- [examples/external_plugins/README.md](../examples/external_plugins/README.md) - Plugin examples
- [Makefile](../Makefile) - All available build targets
