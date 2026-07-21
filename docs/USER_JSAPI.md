# JavaScript API Reference

`apshell` exposes JavaScript automation through the `js` command (with a
`-help` flag that prints this reference). MCP clients fetch the same reference
by calling the `js_reference` tool. This document is the user-facing API
reference for scripts.

For architecture and implementation boundaries, see
[ARCH_REPL.md](ARCH_REPL.md), [ARCH_MCP.md](ARCH_MCP.md), and
[ARCH_CONTRACTS.md](ARCH_CONTRACTS.md).

## Running JavaScript

Inside `apshell`:

```text
js scripts/batch-send.js
js { print(network()) }
js
  print(status().network)

js -help
```

From the command line:

```bash
apshell -js script.js
apshell -js -
apshell -e 'print(network())'
```

`js` runs files, inline snippets, or multi-line input. `js -help` prints this
API reference. MCP clients invoke the `js` tool with a `code` argument to run
JavaScript (receiving a `{value, output}` JSON object) and use `js_reference`
to fetch this reference. Use `jssave` to persist snippets and `jslist` to
enumerate them.

## Conventions

Amounts are integer microAlgos unless otherwise stated. Use:

```javascript
algo(1.25)        // 1250000
microalgos(1000)  // 1000
```

Most transaction functions accept a final options object:

```javascript
{
  wait: true,          // default true
  fee: 1000,           // optional flat fee in microAlgos
  note: "memo text"    // optional transaction note
}
```

When `fee` is supplied, it is used as a flat fee. If omitted, normal fee
calculation is used.

Address arguments can be full Algorand addresses or aliases known to `apshell`.
Set names use arrays in JavaScript API calls; the `@setname` shell syntax is for
the REPL command language, not JS function arguments.

Byte arguments used by application calls and LogicSig runtime args accept
strings with the `hex:`, `b64:`, `text:`, and `0x` prefixes, or a byte array
such as `[104, 105]`. See [USER_COMMANDS.md](USER_COMMANDS.md) (Byte Encodings)
for supported prefixes.

Errors throw JavaScript exceptions. Use `try` / `catch` for recoverable flows:

```javascript
try {
  send("alice", "bob", algo(1))
} catch (e) {
  print("send failed: " + e)
}
```

Scripts do not have direct filesystem, network, process, or private-key access.
They operate through the exported shell functions, and signing still routes
through normal signer approval and policy boundaries.

## Output And Runtime State

| Function | Returns |
|---|---|
| `print(...values)` | Prints concatenated values; returns `undefined` |
| `log(...values)` | Prints only when verbose mode is enabled; returns `undefined` |
| `network()` | Current network name |
| `status()` | `{ network, connected, target, signingMode, writeMode, simulate }` |
| `connected()` | Boolean signer connection state |
| `setWriteMode(enabled)` | Sets transaction JSON write mode (debugging tool) |
| `writeMode()` | Boolean write mode state |
| `setVerbose(enabled)` | Sets verbose output mode |
| `setSimulate(enabled)` | Sets simulation mode |
| `simulate()` | Boolean simulation mode state |
| `waitForTx(txid, rounds = 5)` | Waits for confirmation; returns `true` |

Example:

```javascript
setVerbose(true)
log("network: ", network())
print(JSON.stringify(status()))
```

## Accounts, Aliases, And Sets

| Function | Returns |
|---|---|
| `balance(addressOrAlias)` | `{ address, alias, algo, minBalance, authAddr, assets }` |
| `accounts()` | `[{ address, alias, isSignable, keyType }]` |
| `resolve(addressOrAlias)` | `{ address, alias }` |
| `alias(name)` | Address string, or `null` |
| `aliases()` | Object mapping alias name to address |
| `addAlias(name, address)` | `{ name, address, created }` |
| `removeAlias(name)` | Removed address string |
| `set(name)` | Address array, or `null` |
| `sets()` | Set name array |
| `createSet(name, addresses)` | `{ name, count, updated }` |
| `addToSet(name, addresses)` | `{ name, count, added, oldCount }` |
| `removeFromSet(name, addresses)` | `{ name, count, removed }` |
| `deleteSet(name)` | `{ name, deleted }`, where `deleted` is the number of removed members |

`balance().assets` is an object keyed by asset ID:

```javascript
{
  "10458941": {
    amount: 123,
    unitName: "USDC",
    decimals: 6,
    frozen: false
  }
}
```

Examples:

```javascript
addAlias("treasury", "<ALGORAND_ADDRESS>")
createSet("payroll", ["alice", "bob", "charlie"])

for (const account of accounts()) {
  print(account.alias || account.address, " ", account.keyType || "")
}
```

Alias and set names may contain only ASCII letters, numbers, `-`, and `_`, and
are stored in lowercase. Reserved alias/set command words cannot be used as
persisted alias or set names.

## Signer And Key Management

| Function | Returns |
|---|---|
| `signers()` | Object mapping signer address to key type |
| `signers(addresses)` | Filtered array containing only addresses that are signer keys |
| `keys()` | `[{ address, keyType }]` from the connected signer |
| `signableAddresses()` | Address array |
| `canSignFor(addressOrAlias)` | `{ canSign, isLsig }` |
| `keyTypes()` | Available key type metadata from the signer |
| `generateKey(keyType, params = {})` | `{ address, keyType }` |
| `deleteKey(addressOrAlias)` | `{ address, deleted: true }` |

`keyTypes()` returns objects like:

```javascript
{
  keyType: "aplane.falcon1024.v1",
  family: "aplane.falcon1024",
  displayName: "Falcon-1024",
  description: "...",
  requiresLogicSig: true,
  mnemonicWordCount: 24,
  mnemonicImport: true,
  mnemonicScheme: "bip39",
  creationParams: [
    { name, label, description, type, required, example, placeholder, default }
  ],
  runtimeArgs: [
    { name, label, description, type, required, byteLength }
  ]
}
```

Examples:

```javascript
for (const kt of keyTypes()) {
  print(kt.keyType, " ", kt.displayName)
}

let generated = generateKey("aplane.htlc.v1", {
  hash: "SHA256_HEX",
  recipient: "ADDR1",
  refund_address: "ADDR2",
  timeout_round: "50000000"
})
print(generated.address)
```

## Asset Queries And Cache

| Function | Returns |
|---|---|
| `assetInfo(assetId)` | Full ASA metadata |
| `cachedAssets()` | `[{ assetId, unitName, name, decimals }]` |
| `cacheAsset(assetId)` | `{ assetId, unitName, name, decimals }` |
| `uncacheAsset(assetId)` | `true` |
| `clearAssetCache()` | Number of removed cache entries |
| `getAsaId(name, network = currentNetwork)` | Asset ID, or `null` |
| `holders(asset = "algo")` | Addresses with non-zero ALGO or ASA balance |
| `holders(addresses, asset = "algo")` | Filtered subset of `addresses` |

`getAsaId()` uses the same ASA resolver as shell commands. On the current
network it checks cached asset unit/name metadata first, then built-in metadata
and explicit convenience aliases. With an explicit non-current network argument,
only built-ins and aliases are available. Unknown or ambiguous references return
`null`.

`assetInfo(assetId)` returns:

```javascript
{
  assetId, unitName, name, decimals, total,
  creator, manager, reserve, freeze, clawback,
  defaultFrozen, url
}
```

Examples:

```javascript
let usdc = getAsaId("usdc")
if (usdc !== null) {
  cacheAsset(usdc)
  print(assetInfo(usdc).unitName)
}

let signersWithAlgo = holders(signableAddresses(), "algo")
```

## Transaction Functions

Most transaction functions return:

```javascript
{ txid, confirmed }
```

Group functions return:

```javascript
{ txids, confirmed }
```

### ALGO

| Function | Description |
|---|---|
| `send(from, to, amount, options = {})` | Send ALGO |
| `validate(addressOrAlias)` | Send 0 ALGO to self to validate signing |
| `sweep(from, to, options = {})` | Close account and send remaining ALGO to `to` |
| `close(from, to, options = {})` | Close account; supports LogicSig runtime args |

Examples:

```javascript
send("alice", "bob", algo(2), { note: "rent" })
sweep("old-account", "treasury", { wait: true })

close("hashlock-lsig", "treasury", {
  lsigArgs: {
    preimage: "text:secret"
  }
})
```

### ASA

| Function | Description |
|---|---|
| `sendAsset(from, to, assetId, amount, options = {})` | Send ASA units |
| `optIn(account, assetId, options = {})` | Opt into an ASA |
| `optOut(account, assetId, closeToOrOptions?, options?)` | Opt out of an ASA |

`optOut` accepts these forms:

```javascript
optOut(account, assetId)
optOut(account, assetId, closeTo)
optOut(account, assetId, options)
optOut(account, assetId, closeTo, options)
optOut(account, assetId, null, options)
```

Examples:

```javascript
let usdc = getAsaId("usdc")
optIn("alice", usdc)
sendAsset("alice", "bob", usdc, 10_000_000)
optOut("alice", usdc, "treasury")
```

### Atomic Groups

| Function | Description |
|---|---|
| `atomicSend(payments, options = {})` | Send multiple ALGO payments atomically |
| `atomicSendAsset(transfers, options = {})` | Send multiple ASA transfers atomically |

Payment object:

```javascript
{ from, to, amount, note }
```

ASA transfer object:

```javascript
{ from, to, assetId, amount, note }
```

Examples:

```javascript
atomicSend([
  { from: "treasury", to: "alice", amount: algo(1) },
  { from: "treasury", to: "bob", amount: algo(1) }
])

atomicSendAsset([
  { from: "treasury", to: "alice", assetId: getAsaId("usdc"), amount: 1000000 },
  { from: "treasury", to: "bob", assetId: getAsaId("usdc"), amount: 1000000 }
])
```

### Rekey

| Function | Returns |
|---|---|
| `rekey(from, to, options = {})` | `{ txid, confirmed }` |
| `unrekey(account, options = {})` | `{ txid, confirmed }` |
| `isRekeyed(addressOrAlias)` | `{ rekeyed, authAddr }` |

Examples:

```javascript
rekey("hot", "cold")
print(isRekeyed("hot").authAddr)
unrekey("hot")
```

### Key Registration And Participation

| Function | Returns |
|---|---|
| `keyreg(account, "offline")` | `{ txid, confirmed }` |
| `keyreg(account, "online", options)` | `{ txid, confirmed }` |
| `participation(addressOrAlias)` | Participation key/status object |
| `incentiveEligible(addressOrAlias)` | Boolean |

Online `keyreg` options:

```javascript
{
  votekey,
  selkey,
  sproofkey,
  votefirst,
  votelast,
  keydilution,
  eligible
}
```

`participation()` returns:

```javascript
{
  address,
  status,
  isOnline,
  voteKey,
  selectionKey,
  stateProofKey,
  voteFirstValid,
  voteLastValid,
  voteKeyDilution,
  incentiveEligible
}
```

### External Transaction Files And Group Planning

| Function | Returns |
|---|---|
| `sign(filepath, { wait = true } = {})` | `{ txids, confirmed }` |
| `plan(signRequests)` | `{ transactions, mutations? }` |

`sign()` reads an external transaction file, signs, submits, and optionally waits.

`plan()` sends transaction sign requests to the signer group planner without
signing or triggering approval. Request fields:

```javascript
{
  authAddress,
  txnSender,
  txnBytesHex,
  signedTxnHex,
  lsigSize,
  lsigArgs: { name: "hex-string" }
}
```

## Application Interaction

### Reads

| Function | Description |
|---|---|
| `appInfo(appId)` | Application metadata |
| `appGlobal(appId)` | Global state |
| `appLocal(appId, account)` | Local state for an account |
| `appBox(appId, boxName)` | Single box value |
| `appBoxes(appId)` | Box list |

`boxName` accepts the byte formats described in [Conventions](#conventions).

### Deploy

```javascript
appDeploy(from, approvalPath, clearPath, options = {})
```

Options:

```javascript
{
  approvalCompiled: false,
  clearCompiled: false,
  globalUint,
  globalBytes,
  localUint,
  localBytes,
  extraPages,
  wait,
  fee,
  note
}
```

Returns:

```javascript
{
  tx_id,
  confirmed,
  app_id,       // present when wait=true and creation is confirmed
  app_address   // present when wait=true and creation is confirmed
}
```

Note: `appDeploy` uses snake_case field names (`tx_id`, `app_id`, `app_address`),
unlike the camelCase `txid` returned by other transaction functions.

### Raw App Calls

```javascript
appCallRaw(appId, from, appArgs, options = {})
```

`appArgs` is an array of byte values. Options:

```javascript
{
  pay,              // optional companion payment to the app address
  accounts: [],
  apps: [],
  assets: [],
  boxes: [],
  onCompletion: "noop",
  wait,
  fee,
  note
}
```

`onCompletion` supports `noop`, `optin`, `closeout`, `clear`, `update`, and
`delete`.

Box references can be strings for boxes in the current app, or objects:

```javascript
[
  "text:box-name",
  { appId: 123, name: "hex:626f78" }
]
```

Returns `{ txid, txids, confirmed }` for a single app call, or
`{ txids, confirmed, grouped: true }` when a companion payment is used.

Example:

```javascript
appCallRaw(123, "alice", ["text:deposit"], {
  pay: algo(1),
  boxes: ["text:balance:alice"]
})
```

### ABI App Calls

```javascript
appCall(appId, method, abiPath, from, args, options = {})
```

`args` is an array converted to ABI argument strings. Options are the same as
`appCallRaw`.

Returns `{ txid, txids, confirmed, method }` for a single call, or
`{ txids, confirmed, grouped: true, method }` when a companion payment is used.

Example:

```javascript
appCall(123, "deposit(uint64)void", "artifacts/app.arc32.json", "alice", [100], {
  pay: algo(1),
  boxes: ["text:deposit"]
})
```

## Plugins

```javascript
plugin(name, ...args)
```

Returns:

```javascript
{
  success,
  message,
  data,          // optional plugin data
  presentation   // optional presentation payload
}
```

Example:

```javascript
let r = plugin("workflow", "status", "alice")
if (!r.success) {
  throw new Error(r.message)
}
print(JSON.stringify(r.data))
```

## Complete Example

```javascript
setVerbose(true)

let usdc = getAsaId("usdc")
if (usdc === null) {
  throw new Error("USDC is not known on " + network())
}

cacheAsset(usdc)

let recipients = set("payroll")
if (recipients === null || recipients.length === 0) {
  throw new Error("payroll set is empty")
}

let transfers = recipients.map(addr => ({
  from: "treasury",
  to: addr,
  assetId: usdc,
  amount: 1000000,
  note: "payroll"
}))

let result = atomicSendAsset(transfers, { wait: true })
print("submitted: ", result.txids.join(", "))
```
