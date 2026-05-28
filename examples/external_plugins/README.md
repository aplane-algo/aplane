# External Plugins for APlane Shell

This directory contains example external plugins that demonstrate the subprocess-based plugin architecture.

## Plugin Architecture

APlane Shell plugins are standalone executables that run as separate processes,
communicating via JSON-RPC over stdin/stdout. They can be written in any language
and are discovered at runtime.

## Prerequisites

| Plugin | Language | Requirements |
|--------|----------|-------------|
| echo-plugin | Go | Go 1.21+; source-level illustration only |
| reti | TypeScript / Node.js | Node.js 20+, npm at build time |

## Building the Example Plugins

### echo-plugin (Go)

```bash
cd echo-plugin
go build -o echo-plugin echo-plugin.go
```

`echo-plugin` is purely a development illustration of the plugin protocol. It
is not bundled into production release archives; production `install.sh` does
not copy it into `plugins.available`. The dev installer
(`scripts/install-example-plugins.sh`) does install it alongside the other
examples for protocol exploration.

### reti (TypeScript / Node.js)

```bash
cd reti
npm ci
npm run build
```

This produces a standalone `reti` executable through Node SEA. The built plugin
does not require Node.js or npm at runtime. The example uses exact direct
dependency versions, a committed lockfile with integrity hashes, and a local
`.npmrc` that enforces exact saves, strict Node engine checks, and no dependency
lifecycle scripts during install. Use `npm ci` so installs follow the lockfile.

To build every example, including the development-only `echo-plugin`, without
modifying any client data directory, use:

```bash
make build-example-plugins
```

For the full dev install — build every example and copy them into
`$APCLIENT_DATA/plugins.available/`, enabled in `plugins.yaml` — use
`make example-plugins` (covered in [Installing in a Dev
Environment](#installing-in-a-dev-environment) below).

`reti` is source-only example code. Production release archives do not build or
ship its runtime payload.

## Installing in a Dev Environment

For local development, `make example-plugins` is the one-shot installer for
every example in this directory. From the repo root:

```bash
make example-plugins
```

The target:

1. Runs `make install-example-plugins` (non-interactive npm install) and
   `make build-example-plugins` to produce each plugin's runtime payload.
2. **Wipes and recreates** `$APCLIENT_DATA/plugins.available/`.
3. Copies every example with a complete payload
   (`manifest.json` + `checksums.sha256` + matching executable) into the
   catalog. Examples with an incomplete payload are skipped with a note.
4. **Overwrites** `$APCLIENT_DATA/plugins.yaml` with an `enabled_plugins:`
   list naming every example it installed — so all installed examples are
   enabled, including `echo-plugin`.

`make example-plugins` is implemented by `scripts/install-example-plugins.sh`
and the script can also be invoked directly when that is more convenient.

`$APCLIENT_DATA` defaults to `$HOME/aplane/apclient`; set it explicitly to
target a different client data directory:

```bash
APCLIENT_DATA=/tmp/aplane-dev/apclient make example-plugins
```

Because the workflow is destructive on `plugins.available/` and `plugins.yaml`,
run it only against a dev client data directory. Production installs use
`install.sh` instead, which preserves existing activation choices and does not
touch examples that are not part of the release payload.

To build the example plugins without modifying `$APCLIENT_DATA` at all, use
`make build-example-plugins`.

## Plugin Structure

Each external plugin must have:

1. **manifest.json** - Describes the plugin capabilities
2. **Executable** - The plugin program (can be any language)

## Example Plugins

### echo-plugin

A source-only demonstration plugin that shows the basics. It is not bundled
into production release archives, but the dev installer
(`scripts/install-example-plugins.sh`) does copy it into the example
`plugins.available/` catalog. Provides one command:
- `echo <message>` - Simply echoes back the message

### reti

Réti staking-contract integration example. Source lives here and is not bundled
into production release archives. Implemented with the current
TypeScript/Algokit Réti client stack, it can be built as a standalone
executable and provides:

- `reti list`
- `reti validator <validator_id>`
- `reti pools <validator_id>`
- `reti deposit <amount> algo into <validator_id> for <account>`
- `reti withdraw <amount|all> algo from app <pool_app_id> for <account>`
- `reti withdraw <amount|all> algo from validator <validator_id> pool <pool_id> for <account>`
- `reti balance <account>`
- `reti claim <account>`

## Plugin Discovery

Plugins are discovered from `$APCLIENT_DATA/plugins.available/`, but only when
their directory names are listed in `$APCLIENT_DATA/plugins.yaml`:

```yaml
enabled_plugins:
  - reti
```

Production bundled plugins live under the repository top-level `plugins/`
directory. `algokit-localnet` is maintained there rather than as an example.

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
  "manifest_format": "1.0"
}
```

`manifest_format` names the manifest schema.

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

For `execute`, keep two result layers distinct:

- `data`: canonical machine-readable payload
- `presentation`: optional human-oriented rendering metadata for apshell text mode

Use `message` as a short summary or fallback, not as a second full copy of `data`.

## Transaction Intents

External plugins cannot directly sign or submit transactions. Instead, they
return raw unsigned transaction intents:

```json
{
  "type": "raw",
  "encoded": "base64-encoded-unsigned-transaction-msgpack"
}
```

APlane Shell validates these intents and handles signing and submission.

## Security Model

External plugins run as separate processes and do not have access to
signer-managed private keys. Treat them as untrusted code unless you have
reviewed the plugin yourself.

## Testing a Plugin

1. Build your plugin executable
2. Place it in one of the discovery directories
3. Check discovery: `plugins`
4. Inspect one plugin: `plugins reti-plugin`
5. Run the plugin through its exposed command, for example `reti validator 1`

## Language Support

External plugins can be written in any language. Examples:

- **Go**: See echo-plugin/
- **Python**: Use json module for JSON-RPC
- **Node.js**: See reti/; use readline for stdin, process.stdout for output
- **Shell**: Use jq for JSON processing

## Scope

This repo includes:

- `echo-plugin` as the minimal protocol reference
- `reti` as a source-only Réti protocol example

More complex or unofficial integrations can still live in separate
repositories.

## Protocol Documentation

See `/internal/plugin/jsonrpc/methods.go` for the complete protocol definition including all request/response types.

## Debugging Tips

- Use stderr for debug output: `fmt.Fprintf(os.Stderr, "Debug: %v\n", data)`
- Test manually: `echo '{"jsonrpc":"2.0","method":"getInfo","id":1}' | ./my-plugin`
- Check manifest validity: `cat manifest.json | jq .`
- Inspect discovered plugin metadata with `plugins`

## Guidelines and Best Practices

### 1. Group ID Management and Transaction Signing

**The Problem**: When dealing with atomic transaction groups that require mixed signing (some transactions signed by ephemeral keys, some by user keys), group IDs must be computed BEFORE any signing occurs.

**Why This Matters**:
- APlane Shell may need to add dummy transactions to accommodate large Falcon signatures (3180 bytes each)
- The group ID is part of what gets signed, so it must be correct before signing
- Pre-signing transactions with the wrong group ID will cause "inconsistent group values" errors

**The Solution**:
- **External plugins should return UNSIGNED transactions**, even if they involve ephemeral keys
- Pass ephemeral key material (like escrow secret keys) in the `data` field of the response
- Let APlane Shell handle all signing after proper group ID computation

**Example** (Réti-style transaction-building plugin):

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
  transactions: unsignedTransactions.map((txnB64) => ({
    type: 'raw',
    encoded: txnB64,
    description: 'Reti addStake transaction'
  })),
  data: {
    validatorId: 12,
    poolId: 2,
    poolAppId: 734900001
  }
};
```

Then APlane Shell handles signing:
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
- You're wrapping existing SDK transaction builders
- Transaction parameters can't be expressed as simple intents
- You are building protocol flows like the in-repo Réti plugin

### 4. Data Field Usage

The `data` field in responses is for passing metadata that APlane Shell needs for special handling:

```javascript
return {
  success: true,
  transactions: [...],
  // Local signers: plugin-controlled accounts to sign locally
  // Use this when the plugin generates ephemeral keys (e.g., escrows)
  localSigners: [
    {
      address: "ESCROW_ADDRESS...",
      secretKey: "base64-encoded-64-byte-ed25519-key"
    }
  ],

  data: {
    // Custom metadata for display:
    amount: 1.5,
    poolAddress: "...",
    // etc.
  }
};
```

**Local Signers**: When your plugin creates ephemeral accounts (like deposit escrows), include their keys in top-level `localSigners`. APlane Shell will:
- Sign transactions from these addresses locally
- Send all other transactions to apsigner for user key signing
- Handle group orchestration (dummies, fees, group ID)

Use `echo-plugin` as the minimal in-repo reference implementation and `reti`
as a protocol example for a real DeFi integration whose runtime payload is
built and shipped in release archives.
