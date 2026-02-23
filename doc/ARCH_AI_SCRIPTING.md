# AI & Scripting Architecture

This document describes the JavaScript scripting system and AI-assisted code generation in aPlane Shell.

## Overview

aPlane provides two complementary approaches to automation:

1. **JavaScript Scripting** - Write scripts directly using a sandboxed JavaScript runtime
2. **AI Code Generation** - Describe operations in natural language and have AI generate JavaScript

Both use the same underlying JavaScript API and Goja runtime.

```
┌─────────────────────────────────────────────────────────────────────┐
│                         User Input                                   │
├──────────────────────────────┬──────────────────────────────────────┤
│   Direct JavaScript          │   Natural Language                    │
│   js send("alice", "bob",    │   ai send 5 algo from alice to bob   │
│      algo(5))                │                                       │
└──────────────┬───────────────┴───────────────┬──────────────────────┘
               │                               │
               │                               ▼
               │                    ┌─────────────────────┐
               │                    │   AI Provider       │
               │                    │   (Claude/GPT)      │
               │                    │   + System Prompt   │
               │                    └──────────┬──────────┘
               │                               │
               │                               ▼
               │                    ┌─────────────────────┐
               │                    │   Generated JS      │
               │                    │   + Confirmation    │
               │                    └──────────┬──────────┘
               │                               │
               ▼                               ▼
        ┌─────────────────────────────────────────────────┐
        │              Goja JavaScript Runtime             │
        │                                                  │
        │   Core API: send(), balance(), optIn(), etc.     │
        │   Plugin Functions: retiBalance(), tinymanSwap() │
        └─────────────────────────────────────────────────┘
```

---

# Part 1: JavaScript Scripting

## Running JavaScript

### From Command Line

```bash
# Run a .js file
apshell -js script.js

# Run from stdin
echo 'print(network())' | apshell -js -

# Evaluate an expression
apshell -e 'print(algo(1.5))'
```

### From the REPL

```
# Run a .js file from filesystem
testnet> js examples/balances.js

# Brace-delimited (inline)
testnet> js { print('hello'); print('world') }

# Simple inline (single statement)
testnet> js print('hello')

# Multi-line mode (blank line to execute)
testnet> js
Enter JavaScript (blank line to execute):
... for (let i = 0; i < 3; i++) {
...     print('Count:', i)
... }
...
Count: 0
Count: 1
Count: 2
```

Note: In inline mode, use single quotes for strings (the REPL parser consumes double quotes).

---

## JavaScript API Reference

### Output

```javascript
print(...args: any)
```
Print arguments to console, space-separated.

```javascript
log(...args: any)
```
Debug output (only shown when verbose mode is enabled).

---

### Helpers

```javascript
algo(n: number): number
```
Convert ALGO to microAlgos: `algo(1.5)` → `1500000`

```javascript
microalgos(n: number): number
```
Identity function for clarity (validates non-negative).

---

### Account & Balance

```javascript
balance(addressOrAlias: string): object
```
Get balance info for an account.
- Returns:
  ```javascript
  {
    algo: number,          // Balance in microAlgos
    assets: {              // Map of asset ID to holding info
      [id]: { amount: number, unitName: string, decimals: number, frozen: boolean }
    },
    address: string,       // Resolved address
    alias: string,         // Alias if defined
    minBalance: number,    // Minimum balance requirement
    authAddr: string       // Auth address if rekeyed
  }
  ```

```javascript
accounts(): array
```
List all known accounts (from aliases and signers).
- Returns: `[{ address: string, alias: string, isSignable: boolean, keyType: string }, ...]`
- Note: When user prompts refer to an account's "type", this means the `keyType` property (e.g., "ed25519", "falcon1024-v1", "timelock-v1").

```javascript
resolve(addressOrAlias: string): object
```
Resolve an alias or address to both forms.
- Returns: `{ address: string, alias: string }`

---

### Aliases

```javascript
alias(name: string): string | null
```
Get address for an alias. Returns `null` if not found.

```javascript
aliases(): object
```
Get all defined aliases.
- Returns: `{ name: address, ... }`

```javascript
addAlias(name: string, address: string): object
```
Add or update an alias.
- Returns: `{ name: string, address: string, created: boolean }`

```javascript
removeAlias(name: string): string
```
Remove an alias. Returns the address that was removed.

---

### Sets

```javascript
set(name: string): array | null
```
Get addresses in a set. Returns `null` if not found.
- Returns: `[address, ...]`

```javascript
sets(): array
```
Get all set names.
- Returns: `[name, ...]`

```javascript
createSet(name: string, addresses: array): object
```
Create or replace a set with the given addresses.
- Returns: `{ name: string, count: number, updated: boolean }`

```javascript
addToSet(name: string, addresses: array): object
```
Add addresses to an existing set (creates if doesn't exist).
- Returns: `{ name: string, count: number, added: number, oldCount: number }`

```javascript
removeFromSet(name: string, addresses: array): object
```
Remove addresses from a set.
- Returns: `{ name: string, count: number, removed: number }`

```javascript
deleteSet(name: string): object
```
Delete a set entirely.
- Returns: `{ name: string, deleted: number }`

---

### Signers & Holders

```javascript
signers(): object
signers(addresses: array): array
```
Without arguments: returns map of all signer addresses to key types.
With array argument: filters to only addresses that are signers.
- Returns (no args): `{ address: keyType, ... }`
- Returns (with array): `[address, ...]` (filtered)

```javascript
holders(): array
holders(assetRef: string | number): array
holders(addresses: array, assetRef: string | number): array
```
Get addresses with non-zero balance of an asset.
- `assetRef` - Asset ID, unit name (e.g., "usdc"), or "algo" (default)
- With array first arg: filters input addresses to only those holding the asset
- Returns: `[address, ...]`

---

### Signing Info

```javascript
keys(): array
```
List signing keys from Signer.
- Returns: `[{ address: string, keyType: string }, ...]`

```javascript
signableAddresses(): array
```
Get all addresses we can sign for.
- Returns: `[address, ...]`

```javascript
canSignFor(address: string): object
```
Check if we can sign for an address.
- Returns: `{ canSign: boolean, isLsig: boolean }`

---

### Network & Configuration

```javascript
network(): string
```
Current network: `"testnet"`, `"mainnet"`, or `"betanet"`

```javascript
connected(): boolean
```
Returns `true` if connected to Signer.

```javascript
status(): object
```
Get connection status.
- Returns:
  ```javascript
  {
    network: string,
    connected: boolean,
    target: string,        // Connection target (e.g., "localhost:9800")
    signingMode: string,   // "local", "remote", or "disconnected"
    writeMode: boolean
  }
  ```

```javascript
writeMode(): boolean
```
Get current write mode setting.

```javascript
setWriteMode(enabled: boolean)
```
Enable or disable transaction JSON writing.

```javascript
setVerbose(enabled: boolean)
```
Enable or disable verbose output.

---

### Transactions

All transaction functions return `{ txid: string, confirmed: boolean }` unless noted otherwise.

```javascript
validate(address: string): object
```
Validate signing capability by sending 0 ALGO to self.
- Returns: `{ txid: string, confirmed: boolean, address: string }`

```javascript
send(from: string, to: string, amount: number, options?: object)
```
Send ALGO from one account to another.
- `from` - Sender address or alias
- `to` - Receiver address or alias
- `amount` - Amount in microAlgos (use `algo()` helper)
- `options` - Optional: `{ note: string, fee: number, wait: boolean }`

```javascript
sendAsset(from: string, to: string, assetId: number, amount: number, options?: object)
```
Send an ASA from one account to another.
- `from` - Sender address or alias
- `to` - Receiver address or alias
- `assetId` - Asset ID
- `amount` - Amount in base units (not decimal-adjusted)
- `options` - Optional: `{ note: string, fee: number, wait: boolean }`

```javascript
optIn(account: string, assetId: number, options?: object)
```
Opt an account into an ASA.
- `account` - Account address or alias
- `assetId` - Asset ID to opt into
- `options` - Optional: `{ fee: number, wait: boolean }`

```javascript
optOut(account: string, assetId: number, closeTo?: string, options?: object)
```
Opt an account out of an ASA.
- `account` - Account address or alias
- `assetId` - Asset ID to opt out of
- `closeTo` - Optional: address to send remaining asset balance
- `options` - Optional: `{ fee: number, wait: boolean }`

```javascript
sweep(from: string, to: string, options?: object)
```
Close an account, sending all ALGO to destination.
- `from` - Account to close (address or alias)
- `to` - Destination for remaining balance (address or alias)
- `options` - Optional: `{ fee: number, wait: boolean }`

```javascript
keyreg(account: string, mode: string, options?: object)
```
Mark an account online or offline for consensus participation.
- `account` - Account address or alias
- `mode` - `"online"` or `"offline"`
- `options` - For online mode, must include participation keys:
  ```javascript
  {
    votekey: string,      // Base64-encoded vote key
    selkey: string,       // Base64-encoded selection key
    sproofkey: string,    // Base64-encoded state proof key
    votefirst: number,    // First valid round
    votelast: number,     // Last valid round
    keydilution: number,  // Key dilution
    eligible: boolean     // Incentive eligibility (optional)
  }
  ```

```javascript
waitForTx(txid: string, rounds?: number): boolean
```
Wait for a transaction to be confirmed.
- `txid` - Transaction ID to wait for
- `rounds` - Maximum rounds to wait (default: 5)
- Returns: `true` on success, throws on timeout

---

### Rekey Operations

```javascript
rekey(from: string, to: string, options?: object)
```
Rekey an account to a new auth address.
- `from` - Account to rekey (address or alias)
- `to` - New auth address (address or alias)
- `options` - Optional: `{ fee: number, wait: boolean }`

```javascript
unrekey(account: string, options?: object)
```
Rekey an account back to itself (remove rekeying).
- `account` - Account to unrekey (address or alias)
- `options` - Optional: `{ fee: number, wait: boolean }`

```javascript
isRekeyed(address: string): object
```
Check if an account is rekeyed.
- Returns: `{ rekeyed: boolean, authAddr: string }`

---

### Participation & Consensus

```javascript
participation(address: string): object
```
Get participation status for an account.
- Returns:
  ```javascript
  {
    address: string,
    status: string,             // "online" or "offline"
    isOnline: boolean,
    voteKey: string,
    selectionKey: string,
    stateProofKey: string,
    voteFirstValid: number,
    voteLastValid: number,
    voteKeyDilution: number,
    incentiveEligible: boolean
  }
  ```

```javascript
incentiveEligible(address: string): boolean
```
Check if an account is eligible for consensus incentives.

---

### Atomic Transactions

```javascript
atomicSend(payments: array, options?: object)
```
Send multiple ALGO payments atomically.
- `payments` - Array of payment objects:
  ```javascript
  [
    { from: string, to: string, amount: number, note?: string },
    ...
  ]
  ```
- `options` - Optional: `{ fee: number, wait: boolean }`
- Returns: `{ txids: [string, ...], confirmed: boolean }`

```javascript
atomicSendAsset(transfers: array, options?: object)
```
Send multiple ASA transfers atomically. All transfers must use the same asset.
- `transfers` - Array of transfer objects:
  ```javascript
  [
    { from: string, to: string, assetId: number, amount: number, note?: string },
    ...
  ]
  ```
- `options` - Optional: `{ fee: number, wait: boolean }`
- Returns: `{ txids: [string, ...], confirmed: boolean }`

---

### ASA Management

```javascript
assetInfo(assetId: number): object
```
Get full metadata for an ASA.
- Returns:
  ```javascript
  {
    assetId: number,
    unitName: string,
    name: string,
    decimals: number,
    total: number,
    creator: string,
    manager: string,
    reserve: string,
    freeze: string,
    clawback: string,
    defaultFrozen: boolean,
    url: string
  }
  ```

### ASA Cache

```javascript
cachedAssets(): array
```
List cached ASAs.
- Returns: `[{ assetId: number, unitName: string, name: string, decimals: number }, ...]`

```javascript
cacheAsset(assetId: number): object
```
Fetch and cache asset info.
- Returns: `{ assetId: number, unitName: string, name: string, decimals: number }`

```javascript
uncacheAsset(assetId: number): boolean
```
Remove an asset from cache.

```javascript
clearAssetCache(): number
```
Clear all cached assets. Returns count of removed items.

---

## Scripting Examples

### Validate an account multiple times
```javascript
let account = 'alice'

for (let i = 1; i <= 3; i++) {
    print('Validation', i, 'of 3')
    let result = send(account, account, 0)
    print('  txid:', result.txid)
}
```

### Check balances across a set
```javascript
let validators = set('validators')
if (!validators) {
    print('No validators set defined')
} else {
    let total = 0
    for (let addr of validators) {
        let bal = balance(addr)
        print(addr.substring(0, 8) + '...:', bal.algo / 1e6, 'ALGO')
        total += bal.algo
    }
    print('Total:', total / 1e6, 'ALGO')
}
```

### Distribute ALGO to low-balance accounts
```javascript
let treasury = 'treasury'
let minBalance = algo(100)
let topUp = algo(10)

for (let validator of set('validators') || []) {
    let bal = balance(validator)
    if (bal.algo < minBalance) {
        print('Topping up', validator.substring(0, 8) + '...')
        send(treasury, validator, topUp)
    }
}
```

### Conditional opt-in
```javascript
let account = 'alice'
let assetId = 31566704  // USDC on mainnet

let bal = balance(account)
let alreadyOptedIn = bal.assets[assetId] !== undefined

if (!alreadyOptedIn) {
    print('Opting in to asset', assetId)
    optIn(account, assetId)
} else {
    print('Already opted in')
}
```

### Atomic payment to multiple recipients
```javascript
let sender = 'treasury'

atomicSend([
    { from: sender, to: 'alice', amount: algo(10) },
    { from: sender, to: 'bob', amount: algo(20) },
    { from: sender, to: 'charlie', amount: algo(15) }
])
```

### Check participation status
```javascript
let validators = set('validators') || []

for (let addr of validators) {
    let p = participation(addr)
    let status = p.isOnline ? 'ONLINE' : 'offline'
    let eligible = p.incentiveEligible ? ' (incentive eligible)' : ''
    print(addr.substring(0, 8) + '...:', status + eligible)
}
```

### Rekey account to signer
```javascript
let account = 'alice'
let signerKey = 'signer-main'

// Check if already rekeyed
let rekeyStatus = isRekeyed(account)
if (rekeyStatus.rekeyed) {
    print('Already rekeyed to:', rekeyStatus.authAddr)
} else {
    print('Rekeying', account, 'to', signerKey)
    rekey(account, signerKey)
    print('Done!')
}
```

---

## Runtime Behavior

### State Persistence

In REPL mode, the JavaScript runtime persists across `js` command invocations. Variables defined in one command are available in subsequent commands:

```
testnet> js let count = 0
testnet> js count++
0
testnet> js count++
1
```

This does **not** persist across separate apshell sessions - the runtime is in-memory only.

CLI mode (`-js` or `-e`) creates a fresh runtime each invocation.

### Error Handling

All API functions throw JavaScript exceptions on error. Use try/catch to handle them:

```javascript
try {
    send('alice', 'bob', algo(10))
} catch (e) {
    print('Transaction failed:', e)
}
```

### Write Mode

When write mode is enabled (`write on` in REPL or `setWriteMode(true)` in JS), transaction functions will save transaction JSON to `txnjson/<txid>.json`.

### Security Model

JavaScript scripts run in a sandboxed environment:

- **No file system access** - Cannot read/write files
- **No network access** - Cannot make HTTP requests (only Algorand API via the provided functions)
- **No process spawning** - Cannot execute system commands
- **No key access** - Private keys remain in Signer; scripts only build transactions

Scripts interact with the blockchain exclusively through the provided API functions.

---

# Part 2: AI Code Generation

## Overview

The `ai` command enables natural language to JavaScript code generation, allowing users to describe operations in plain English and have the system generate executable JavaScript code.

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   User Prompt   │────►│   AI Provider   │────►│  Generated JS   │
│                 │     │                 │     │                 │
│ "send 5 algo    │     │ Anthropic/OpenAI│     │ send("alice",   │
│  from alice     │     │ + SystemPrompt  │     │   "bob",        │
│  to bob"        │     │                 │     │   algo(5))      │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                                                        │
                                                        ▼
                                                ┌─────────────────┐
                                                │  JS Runtime     │
                                                │  (Goja)         │
                                                └─────────────────┘
```

## Package Structure

```
internal/ai/
├── provider.go      # Provider interface and auto-detection
├── anthropic.go     # Anthropic/Claude implementation
├── openai.go        # OpenAI/GPT implementation
└── prompt.go        # System prompt with API documentation
```

## Provider Interface

```go
type Provider interface {
    // GenerateCode generates JavaScript code from a natural language prompt.
    GenerateCode(prompt string) (string, error)

    // Name returns the provider name for display.
    Name() string

    // SetPlugins configures legacy plugin documentation for the system prompt.
    SetPlugins(plugins []PluginInfo)

    // SetFunctions configures typed function documentation for the system prompt.
    SetFunctions(functions []FunctionInfo)
}
```

## Supported Providers

| Provider | Environment Variable | Default Model |
|----------|---------------------|---------------|
| Anthropic | `ANTHROPIC_API_KEY` | `claude-sonnet-4-5-20250929` |
| OpenAI | `OPENAI_API_KEY` | `gpt-5.2` |

Provider is auto-detected based on which API key is set. If both are set, Anthropic takes precedence.

## Model Configuration

The AI model can be overridden in `config.yaml`:

```json
{
  "ai_model": "claude-haiku-4-5-20250929"
}
```

Leave empty or omit to use the provider's default model. This allows switching between models without changing environment variables—useful for balancing cost, speed, and capability.

## User Flow

```
┌──────────────────────────────────────────────────────────────┐
│ 1. User enters: ai send 5 algo from alice to bob             │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│ 2. Provider sends prompt + SystemPrompt to API               │
│    - SystemPrompt contains full JavaScript API documentation │
│    - Includes type annotations and examples                  │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│ 3. API returns generated JavaScript code                     │
│    - Code is extracted from markdown blocks if present       │
│    - Stored in LastScript immediately                        │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│ 4. Code displayed to user with confirmation prompt           │
│                                                              │
│    --- Generated Code ---                                    │
│    send("alice", "bob", algo(5))                             │
│    ----------------------                                    │
│                                                              │
│    Execute? [y/N]:                                           │
└──────────────────────────────────────────────────────────────┘
                              │
              ┌───────────────┴───────────────┐
              │                               │
              ▼                               ▼
┌─────────────────────────┐     ┌─────────────────────────────┐
│ User confirms (y)       │     │ User declines (n)           │
│ → Code executed via     │     │ → Code preserved in         │
│   Goja JS runtime       │     │   LastScript for jssave     │
└─────────────────────────┘     └─────────────────────────────┘
```

## System Prompt

The system prompt (`internal/ai/prompt.go`) is dynamically generated at runtime to include both the core API documentation and any available plugin functions.

### Prompt Structure

```
┌─────────────────────────────────────────────────────────────────┐
│                      System Prompt                               │
├─────────────────────────────────────────────────────────────────┤
│ 1. BASE PROMPT (static)                                         │
│    - Role definition: "Code generator for aPlane"            │
│    - Output format: Raw JavaScript only                         │
│    - Core API reference with TypeScript annotations             │
│    - Built-in examples                                          │
├─────────────────────────────────────────────────────────────────┤
│ 2. PLUGIN FUNCTIONS (dynamic, if plugins available)             │
│    - Typed function signatures from plugin manifests            │
│    - Parameter types (number, address, asset, string)           │
│    - Return type documentation                                  │
│    - Plugin-specific examples                                   │
├─────────────────────────────────────────────────────────────────┤
│ 3. LEGACY PLUGIN COMMANDS (dynamic, backward compat)            │
│    - Only shown for plugins without typed functions             │
│    - String-based argument documentation                        │
│    - Usage patterns and examples                                │
└─────────────────────────────────────────────────────────────────┘
```

### Plugin Discovery Flow

```
┌─────────────────┐
│   ai command    │
│   executed      │
└────────┬────────┘
         │
         ▼
┌─────────────────────────────────────────────────────┐
│ 1. Discover plugins from filesystem                  │
│    $APSHELL_HOME/plugins/*/manifest.json             │
└────────┬────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────┐
│ 2. Parse manifests, extract:                         │
│    - commands[] → PluginInfo (legacy interface)      │
│    - functions[] → FunctionInfo (typed interface)    │
└────────┬────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────┐
│ 3. Call provider.SetPlugins() and SetFunctions()     │
└────────┬────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────┐
│ 4. GenerateCode() uses dynamic prompt                │
│    BuildSystemPromptWithFunctions(plugins, functions)│
└─────────────────────────────────────────────────────┘
```

### FunctionInfo Structure

```go
// Typed function definition (from plugin manifest)
type FunctionInfo struct {
    Name        string          // JS function name (e.g., "retiBalance")
    Description string          // What the function does
    Params      []FunctionParam // Typed parameters
    Returns     string          // Return type description
}

type FunctionParam struct {
    Name        string // Parameter name
    Type        string // "string", "number", "address", "asset"
    Description string // Human-readable description
}
```

### Generated Prompt Example

With plugins installed, the system prompt includes:

```
PLUGIN FUNCTIONS:
External plugin functions for DeFi and other operations. These are first-class JS functions.
- Return data directly (not wrapped in {success, message, data})
- Throw on error (use try/catch if needed)
- Asset parameters accept names like 'usdc' or numeric IDs (resolved for current network)
- Address parameters accept aliases like 'alice' or full Algorand addresses

- retiList(): {validators: [{id: number, name: string, commission: number, totalStaked: number}]}
  List all available Reti staking validators
- retiBalance(addr: string /* address or alias */): {stakes: [{poolAppId: number, validatorId: number, balance: number}], totalStaked: number}
  Get Reti staking balance for an account
- retiDeposit(amount: number, validatorId: number, addr: string /* address or alias */): {txids: string[], validatorId: number, poolAppId: number}
  Deposit ALGO into a Reti validator
- tinymanSwap(amount: number, fromAsset: string | number, toAsset: string | number, addr: string): {...}
  Swap tokens using Tinyman AMM

PLUGIN FUNCTION EXAMPLES:
User: check my reti staking balance
Code:
let b = retiBalance("alice")
print("Total staked: " + b.totalStaked + " ALGO")
for (let stake of b.stakes) {
    print("  Pool " + stake.poolAppId + ": " + stake.balance + " ALGO")
}

User: list all reti validators
Code:
let v = retiList()
for (let val of v.validators) {
    print(val.id + ": " + val.name + " (commission: " + val.commission + "%, staked: " + val.totalStaked + ")")
}
```

### Core API Categories

The base prompt (static) includes documentation for:

| Category | Functions |
|----------|-----------|
| Helpers | `algo()`, `microalgos()`, `print()`, `log()` |
| Accounts | `balance()`, `accounts()`, `resolve()` |
| Aliases | `alias()`, `aliases()`, `addAlias()`, `removeAlias()` |
| Sets | `set()`, `sets()`, `createSet()`, `addToSet()`, `removeFromSet()`, `deleteSet()` |
| Signers | `signers()`, `keys()`, `signableAddresses()`, `canSignFor()` |
| Holders | `holders()` |
| Status | `network()`, `connected()`, `status()`, `writeMode()`, `setWriteMode()`, `setVerbose()` |
| Transactions | `send()`, `sendAsset()`, `optIn()`, `optOut()`, `sweep()`, `validate()`, `keyreg()`, `waitForTx()` |
| Rekey | `rekey()`, `unrekey()`, `isRekeyed()` |
| Participation | `participation()`, `incentiveEligible()` |
| Atomic | `atomicSend()`, `atomicSendAsset()` |
| ASA Management | `assetInfo()` |
| ASA Cache | `cachedAssets()`, `cacheAsset()`, `uncacheAsset()`, `clearAssetCache()` |
| Asset Lookup | `getAsaId()` |

### Prompt Size

**Base prompt (no plugins):**
- ~2,500 tokens
- ~$0.003-0.01 per request

**With typical plugins (tinyman, reti):**
- ~3,500 tokens
- ~$0.005-0.015 per request

## Code Extraction

API responses may include markdown formatting. The `extractCode()` function strips it:

```go
func extractCode(text string) string {
    markers := []string{"```javascript", "```js", "```"}
    for _, marker := range markers {
        if idx := strings.Index(text, marker); idx != -1 {
            // Extract content between markers
        }
    }
    return text
}
```

## Integration with jssave

The AI command integrates with the `jssave` command for script persistence:

```go
// In cmdAI, immediately after generation:
r.LastScript = code
r.LastScriptSource = "ai"
```

This enables:
```
ai check all validator balances
> Execute? [n]
> Cancelled (use 'jssave <path>' to save the generated code)

jssave scripts/check-validators.js
> Saved to scripts/check-validators.js (156 bytes)
```

## Security Considerations

### Confirmation Required

All generated code requires explicit user confirmation before execution. This prevents:
- Unexpected transactions
- Unintended state changes
- Malformed operations

### No Automatic Execution

The AI never executes code automatically. The flow is always:
1. Generate
2. Display
3. Confirm
4. Execute (only if confirmed)

### API Key Security

- API keys read from environment variables only
- Never logged or displayed
- Never included in generated code

## Error Handling

| Error | Cause | Resolution |
|-------|-------|------------|
| "no API key found" | Neither `ANTHROPIC_API_KEY` nor `OPENAI_API_KEY` set | Set appropriate environment variable |
| "API request failed" | Network error or timeout | Check connectivity, retry |
| "API error: ..." | Provider-side error (rate limit, invalid key) | Check API key, wait for rate limit |
| "empty response" | API returned no content | Retry with different prompt |

## Adding a New Provider

1. Create `internal/ai/<provider>.go`
2. Implement the `Provider` interface
3. Add to `NewProvider()` switch in `provider.go`
4. Add environment variable detection in `detectProvider()`

Example skeleton:

```go
type NewProvider struct {
    apiKey     string
    model      string
    httpClient *http.Client
}

func (p *NewProvider) Name() string {
    return "NewProvider"
}

func (p *NewProvider) GenerateCode(prompt string) (string, error) {
    // 1. Build request with SystemPrompt + user prompt
    // 2. Send to API
    // 3. Parse response
    // 4. Extract code from markdown if present
    return extractCode(response), nil
}

var _ Provider = (*NewProvider)(nil)
```

## Typed Functions and JS Runtime Integration

When the AI generates code that uses typed plugin functions (e.g., `retiBalance("alice")`), those functions are already registered in the JS runtime at startup.

### Registration Flow

```
┌─────────────────────────────────────────────────────┐
│ apshell startup                                      │
└────────┬────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────┐
│ Plugin discovery: scan plugin directories            │
│ Parse manifest.json for each plugin                  │
└────────┬────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────┐
│ For each function in manifest.functions:             │
│   jsapi.registerTypedPluginFunction(fn)              │
│   → Creates JS wrapper in Goja runtime               │
└────────┬────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────┐
│ Runtime ready with:                                  │
│ - Core API functions (send, balance, etc.)           │
│ - Typed plugin functions (retiBalance, etc.)         │
└─────────────────────────────────────────────────────┘
```

### Wrapper Function Behavior

Auto-generated JS wrappers handle:

1. **Parameter validation**: Check argument count matches function definition
2. **Template substitution**: Replace `$param` placeholders with actual values
3. **Plugin execution**: Call plugin's `execute` RPC method
4. **Error handling**: Throw JS exceptions on failure (not `{success: false}`)
5. **Data unwrapping**: Return `result.data` directly (not wrapped)

```go
// Simplified wrapper logic (internal/jsapi/api.go)
func (a *API) registerTypedPluginFunction(pf PluginFunction) {
    fn := func(call goja.FunctionCall) goja.Value {
        // Validate parameters
        if len(call.Arguments) < len(pf.Params) {
            panic("requires N arguments")
        }

        // Substitute $param in command template
        args := substituteParams(pf.Command, pf.Params, call.Arguments)

        // Execute plugin
        success, message, data, err := executor.ExecutePlugin(pf.PluginName, args)

        // Throw on error (unlike legacy which returns success: false)
        if !success {
            panic(fmt.Sprintf("%s() failed: %s", pf.Name, message))
        }

        // Return data directly
        return runtime.ToValue(data)
    }

    runtime.Set(pf.Name, fn)
}
```

## Typed Functions vs Legacy Commands

| Aspect | Typed Functions | Legacy Commands |
|--------|-----------------|-----------------|
| Call syntax | `retiBalance("alice")` | `reti("balance", "alice")` |
| Return value | Data directly | `{success, message, data}` |
| Error handling | Throws exception | Returns `success: false` |
| AI prompt | TypeScript signature | Usage string |
| Generated code | Clean, idiomatic | Requires success check |

**AI-generated code comparison:**

```javascript
// With typed functions (cleaner)
let b = retiBalance("alice")
print("Total staked: " + b.totalStaked)

// With legacy commands (verbose)
let r = reti("balance", "alice")
if (r.success) {
    print("Total staked: " + r.data.totalStaked)
} else {
    print("Error: " + r.message)
}
```

---

## Line-Based Scripts

Traditional `.apshell` scripts execute REPL commands line by line:

```bash
apshell -script commands.apshell
```

Example `commands.apshell`:
```
# Comments start with #
alias treasury ADDR123...
send 10 algo from alice to bob
optin 31566704 for alice
```

Line-based scripts have no variables, loops, or conditionals. For complex automation, use JavaScript scripts instead.

---

## Related Documentation

- [ARCH_ENGINE.md](ARCH_ENGINE.md) - Engine layer (JS runtime integration)
- [ARCH_UI.md](ARCH_UI.md) - Command handling
- [ARCH_PLUGINS.md](ARCH_PLUGINS.md) - Plugin system and typed function manifest format
