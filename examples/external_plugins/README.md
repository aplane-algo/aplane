# External Plugins for aPlane Shell

This directory contains example external plugins that demonstrate the subprocess-based plugin architecture.

## External vs Core Plugins

aPlane Shell supports two types of plugins:

### Core Plugins (in `coreplugins/`)
- Compiled into the binary
- Written in Go
- Full access to internal APIs
- Loaded at compile time via build tags

### External Plugins (this directory)
- Run as separate processes
- Can be written in any language
- Communicate via JSON-RPC over stdin/stdout
- Sandboxed with limited permissions
- Discovered at runtime

## Prerequisites

| Plugin | Language | Requirements |
|--------|----------|-------------|
| echo-plugin | Go | Go 1.21+ |
| reti | TypeScript | Node.js 20+, npm |
| tinymanswap | TypeScript | Node.js 20+, npm |

## Building the Example Plugins

### echo-plugin (Go)

```bash
cd echo-plugin
go build -o echo-plugin echo-plugin.go
```

### reti (TypeScript)

```bash
cd reti
npm install
npm run build
```

### tinymanswap (TypeScript)

```bash
cd tinymanswap
npm install
npm run build
```

## Plugin Structure

Each external plugin must have:

1. **manifest.json** - Describes the plugin capabilities
2. **Executable** - The plugin program (can be any language)

## Example Plugins

### echo-plugin

A simple demonstration plugin that shows the basics. Provides two commands:
- `echo <message>` - Simply echoes back the message
- `echo-tx <message>` - Creates a zero-amount self-payment with the message as a note

### reti

Interacts with the [Reti](https://reti.vote) staking protocol. Commands: `reti list`, `reti pools`, `reti deposit`, `reti withdraw`, `reti balance`.

### tinymanswap

Performs token swaps via the [Tinyman](https://tinyman.org) AMM. Command: `tinymanswap <amount> <from> to <to> for <account>`.

## Plugin Discovery

Plugins are discovered from these locations (in order):
1. `$APSHELL_HOME/plugins/` - User plugins (if APSHELL_HOME is set)
2. `./plugins/` - Current directory plugins
3. `/usr/local/lib/apshell/plugins/` - System-wide plugins

## Creating a New Plugin

### 1. Create the manifest.json

```json
{
  "name": "my-plugin",
  "version": "1.0.0",
  "description": "Description of your plugin",
  "executable": "./my-plugin",
  "commands": [
    {
      "name": "mycommand",
      "description": "What this command does",
      "usage": "mycommand <args>"
    }
  ],
  "networks": ["testnet", "mainnet"],
  "timeout": 30,
  "protocol_version": "1.0"
}
```

### 2. Implement the JSON-RPC Protocol

Your plugin must handle these methods:

- **initialize** - Called when plugin starts
- **execute** - Called to run a command
- **getInfo** - Returns plugin information
- **shutdown** - Clean shutdown request

### 3. Communication Protocol

Plugins communicate via:
- **Input**: JSON-RPC requests on stdin (line-delimited)
- **Output**: JSON-RPC responses on stdout (line-delimited)
- **Logging**: Use stderr for debug output

## Transaction Intents

External plugins cannot directly sign or submit transactions. Instead, they return "transaction intents" that describe what transactions should be created:

```json
{
  "type": "payment",
  "from": "SENDER_ADDRESS",
  "to": "RECEIVER_ADDRESS",
  "amount": 1000000,
  "note": "Payment note",
  "description": "Human-readable description"
}
```

aPlane Shell validates these intents and handles the actual transaction creation and signing.

## Security Model

External plugins run with restricted permissions:
- No direct access to private keys
- No direct network access (unless explicitly allowed)
- Resource limits (memory, CPU time)
- Process isolation

## Testing a Plugin

1. Build your plugin executable
2. Place it in one of the discovery directories
3. Test discovery: `apshell plugin list`
4. Test execution: `apshell plugin run <plugin-name> <command>`

## Language Support

External plugins can be written in any language. Examples:

- **Go**: See echo-plugin/
- **Python**: Use json module for JSON-RPC
- **Node.js**: Use readline for stdin, process.stdout for output
- **Shell**: Use jq for JSON processing

## Protocol Documentation

See `/internal/plugin/jsonrpc/methods.go` for the complete protocol definition including all request/response types.

## Converting from Core Plugin

To convert a core plugin (like tinymanswap) to external:

1. Extract the business logic
2. Replace direct API calls with JSON-RPC callbacks
3. Return transaction intents instead of creating transactions
4. Add manifest.json
5. Build as standalone executable

## Debugging Tips

- Use stderr for debug output: `fmt.Fprintf(os.Stderr, "Debug: %v\n", data)`
- Test manually: `echo '{"jsonrpc":"2.0","method":"getInfo","id":1}' | ./my-plugin`
- Check manifest validity: `cat manifest.json | jq .`
- Monitor plugin discovery: `APSHELL_DEBUG=1 apshell plugin list`

## Guidelines and Best Practices

Lessons learned from implementing complex external plugins (based on the tinymanswap conversions):

### 1. Group ID Management and Transaction Signing

**The Problem**: When dealing with atomic transaction groups that require mixed signing (some transactions signed by ephemeral keys, some by user keys), group IDs must be computed BEFORE any signing occurs.

**Why This Matters**:
- aPlane Shell may need to add dummy transactions to accommodate large Falcon signatures (3180 bytes each)
- The group ID is part of what gets signed, so it must be correct before signing
- Pre-signing transactions with the wrong group ID will cause "inconsistent group values" errors

**The Solution**:
- **External plugins should return UNSIGNED transactions**, even if they involve ephemeral keys
- Pass ephemeral key material (like escrow secret keys) in the `data` field of the response
- Let aPlane Shell handle all signing after proper group ID computation

**Example** (Reti staking plugin):

```javascript
// ❌ WRONG: Pre-signing transactions in the plugin
const signedTxn = algosdk.signTransaction(txn, someKey.sk);
return {
  type: 'raw',
  encoded: Buffer.from(signedTxn.blob).toString('base64'),
  signed: true
};

// ✅ CORRECT: Return unsigned transactions
return {
  success: true,
  transactions: unsignedTransactions.map(txnB64 => ({
    type: 'raw',
    encoded: txnB64
  })),
  data: {
    validatorId: workflow.validatorId,
    poolAppId: workflow.poolAppId
  }
};
```

Then aPlane Shell handles signing:
1. Receives unsigned transactions
2. Analyzes transactions to determine dummy needs (for Falcon signatures)
3. Creates dummy transactions if needed
4. Computes group ID for ALL transactions (original + dummies)
5. Sends transactions to Signer for signing

### 2. Security Boundaries

**Principle**: External plugins should NEVER handle user wallet keys, but MAY handle ephemeral keys created for specific transactions.

- **User keys**: Must only be accessed by Signer (hardware-secured)
- **Ephemeral keys**: Created temporarily for specific protocols (like DeFi escrows), safe for plugin to handle
- **Logic signatures**: Can be pre-signed by plugins if they represent non-custodial logic

### 3. Transaction Intent vs. Raw Transactions

External plugins can return transactions in two ways:

**Option A: Transaction Intents** (Simpler, recommended for basic cases)
```json
{
  "type": "payment",
  "from": "ADDRESS",
  "to": "ADDRESS",
  "amount": 1000000
}
```

**Option B: Raw Transactions** (Required for complex protocols)
```json
{
  "type": "raw",
  "encoded": "<base64-encoded-msgpack-transaction>"
}
```

Use raw transactions when:
- The protocol generates complex application call transactions
- You're wrapping existing SDK transaction builders (like Tinyman)
- Transaction parameters can't be expressed as simple intents

### 4. Data Field Usage

The `data` field in responses is for passing metadata that aPlane Shell needs for special handling:

```javascript
return {
  success: true,
  transactions: [...],
  data: {
    // Local signers: plugin-controlled accounts to sign locally
    // Use this when the plugin generates ephemeral keys (e.g., escrows)
    localSigners: [
      {
        address: "ESCROW_ADDRESS...",
        secretKey: "base64-encoded-64-byte-ed25519-key"
      }
    ],

    // Custom metadata for display:
    amount: 1.5,
    poolAddress: "...",
    // etc.
  }
};
```

**Local Signers**: When your plugin creates ephemeral accounts (like deposit escrows), include their keys in `localSigners`. aPlane Shell will:
- Sign transactions from these addresses locally
- Send all other transactions to apsignerd for user key signing
- Handle group orchestration (dummies, fees, group ID)

### 5. Reference Implementation Pattern

When converting a core plugin to external, the core plugin implementation serves as the reference:

1. **Core plugin** shows how aPlane Shell should handle the transactions internally
2. **External plugin** should return data that allows aPlane Shell to replicate that behavior
3. Compare the core plugin's transaction processing logic with what you're implementing externally

See the `reti/` and `tinymanswap/` directories for complete examples of external plugins that interact with DeFi protocols.