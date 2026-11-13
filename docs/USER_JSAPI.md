# JavaScript API Reference

`apshell` exposes JavaScript automation through the `js` command (with a
`-help` flag that prints this reference). MCP clients fetch the same reference
by calling the `js_reference` tool. This document is the user-facing API
reference for scripts.

For architecture and implementation boundaries, see
[ARCH_SHELL.md](ARCH_SHELL.md#repl-surface) (REPL and MCP surfaces).

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
  fee: 1000,           // optional client base fee in microAlgos
  note: "memo text"    // optional transaction note
}
```

When `fee` is supplied, the client uses it as a flat base fee. If omitted,
normal client fee calculation is used. The signer adds its authorization
charge on top; this option is not a cap on the final fee. Caller-supplied
excess for purposes such as inner transactions is preserved. See
[FEE_HANDLING.md](FEE_HANDLING.md#fee-ownership).

Amounts, fees and IDs must be a number, a `BigInt`, or a string of plain
decimal digits. Nothing is coerced: `null`, `undefined`, `''`, a boolean, and
strings such as `'0x10'` or `'1e6'` are errors, and so is a whole number past
`Number.MAX_SAFE_INTEGER`, which JavaScript has already rounded; pass a
`BigInt` or a decimal string for those.

Where a name is expected (an address, alias, asset or method), `undefined`
and `null` are errors, not the words "undefined" and "null". A list of
addresses must hold only strings. An option of the wrong type, such as
`{ wait: "false" }`, is an error, not an option left out, and so is an option
the function does not read, such as `{ nowait: true }`. `algo()` takes a
number only. `setSimulate()`, `setWriteMode()` and `setVerbose()` take `true`
or `false` only.

Address arguments can be full Algorand addresses or aliases known to `apshell`.
Set names use arrays in JavaScript API calls; the `@setname` shell syntax is for
the REPL command language, not JS function arguments.

Byte arguments used by application calls, box names and LogicSig runtime args
accept a byte array such as `[104, 105]`, or a string with a prefix: `hex:`,
`b64:`, `text:` or `str:`, `int:` (a decimal number, sent as 8 big-endian
bytes), `addr:` (an address, sent as its 32-byte public key), or `0x`. A
string with no prefix is sent as text, unless it contains a colon: then it is
refused, so `"int:5"` or a mistyped prefix is never sent as text by accident.
Write literal text with a colon as `"text:user:alice"`. See
[USER_COMMANDS.md](USER_COMMANDS.md) (Byte Encodings).

Errors throw JavaScript exceptions. Use `try` / `catch` for recoverable flows:

```javascript
try {
  send("alice", "bob", algo(1))
} catch (e) {
  print("send failed: " + e)
}
```

A function that submits transactions throws a failure of its signing and
submission step as an `Error` object, not a string. These functions are
`send()`, `sendAsset()`, `validate()`, `close()`, `optIn()`, `optOut()`,
`keyreg()`, `rekey()`, `unrekey()`, `sign()`, `atomicSend()`,
`atomicSendAsset()`, `appDeploy()`, `appCallRaw()` and `appCall()`. For
`sweep()` and `plugin()`, any failure of the run is thrown this way. The
text is the same as before: an uncaught error, `"failed: " + e`, `String(e)`
and `e.message` all give it. Two things differ from a thrown string:
`typeof e` is `"object"`, and `print(e)` prints the object's properties
(`map[... value:<text>]`), because `print()` does not convert an `Error` to
its text. Use `print(String(e))`. These functions still throw their other
failures, such as a bad argument or a failed preparation, as strings.

When the failure came at or after algod's submit call, the error says which
transactions it concerns and how far they got:

- `e.txids`: the IDs of the transactions whose submission failed, in group
  order. Look them up before retrying: some may be on the network.
- `e.submission`: how far their submission got: `"submitted"` (algod
  accepted them; the wait for their confirmation then failed), `"unknown"`
  (algod gave no answer, or answered with an HTTP status other than 400),
  `"rejected"` (algod answered with HTTP 400; read the reason in the
  message, since a transaction already in the ledger is answered this way
  too) or `"not_sent"` (nothing was sent).

A `sweep()` in which several transactions failed this way has every one of
their IDs in `e.txids` and no `e.submission`; its message gives each
account's reason. A failure before the submit call has neither property.

```javascript
try {
  send("alice", "bob", algo(1))
} catch (e) {
  if (e.txids) {
    print("submission " + e.submission + ": check " + e.txids.join(", ") + " before retrying")
  }
}
```

The MCP `js` tool reports the outcome of every such failure of the run, the
caught ones too, in its result's `submissions` (see
[ARCH_SHELL.md](ARCH_SHELL.md#submission-outcomes)). Nothing retries.

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

Simulation mode requests ordinary executable signatures and normal signer
approval, then routes the exact signed group from the client to algod
simulation instead of submission. Use `plan(requests)` when inspection without
signing or approval is required.

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
persisted alias or set names, and `addAlias()` refuses a name that is itself an
Algorand address. An address argument always means that address; no alias can
redirect it.

## Signer And Key Management

| Function | Returns |
|---|---|
| `signers()` | Object mapping signer address to key type |
| `signers(addresses)` | Filtered array containing only addresses that are signer keys |
| `keys()` | `[{ address, keyType }]` from the connected signer |
| `signableAddresses()` | Address array |
| `canSignFor(addressOrAlias)` | `{ canSign, isLsig, authorizationKind }` where the kind is `ed25519`, `native_pq`, or `logic_sig` |
| `keyTypes()` | Available key type metadata from the signer |
| `generateKey(keyType, params = {})` | `{ address, keyType, warnings }`. `warnings` is an array of the signer's notes about the account, empty when there are none. The account is created either way, so check it. |
| `deleteKey(addressOrAlias)` | `{ address, deleted: true }` |

`keyTypes()` returns objects like:

```javascript
{
  keyType: "falcon1024",
  family: "falcon1024",
  displayName: "falcon1024",
  description: "...",
  authorizationKind: "native_pq",
  requiresLogicSig: false,
  mnemonicWordCount: 25,
  mnemonicImport: true,
  mnemonicScheme: "algorand",
  creationParams: [
    { name, label, description, type, required, example, placeholder, default }
  ],
  runtimeArgs: [
    { name, label, description, type, required, byteLength }
  ]
}
```

Examples (the operator must install `aplane.htlc.v1` before generating from
it; substitute real addresses and a SHA-256 hash):

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
| `sweep(from, to, options = {})` | Send each account's balance, less `leaving`, to `to`. The accounts stay open. `from` is one account or an array |
| `close(from, to, options = {})` | Close account; supports LogicSig runtime args |

Examples:

```javascript
send("alice", "bob", algo(2), { note: "rent" })
sweep("hot-wallet", "treasury", { leaving: algo(1) })        // keep 1 ALGO
sweep("hot-wallet", "treasury")                              // keep only the minimum balance
sweep(["a", "b"], "treasury", { asset: 31566704 })           // an ASA, all of it

close("htlc-lsig", "treasury", {
  lsigArgs: {
    preimage: "text:secret"
  }
})
```

`lsigArgs: { name: value }`, on `close()` and `sweep()`, is the shell's
`arg:<name>=<value>` with no account: each name goes to every transaction the
call builds. The JS API has no form that names an account, as
`arg:<account>:<name>=<value>` does in the shell; a `sweep()` over accounts
that take different arguments is written as one `sweep()` per account, or
run as the shell's `sweep` command. A name a key does not take is refused,
and a native account (ed25519, native Falcon) takes none, so `lsigArgs` on a
`sweep()` that includes one fails that account's transaction. A name is
passed on as given, in `close()` and `sweep()` alike: the shell's rule that a
name may not contain `:` keeps its two `arg:` forms apart and does not apply
to an object key, and a name the signing key does not declare is refused. See
[USER_COMMANDS.md](USER_COMMANDS.md#logicsig-arguments).

`sweep()` is the shell's `sweep` command. It does not close the account; that
is `close()`. Its options are `asset` (an asset ID; absent or 0 is ALGO),
`leaving` (what to keep in each account, in microAlgos or the asset's base
units), `fee`, `wait` and `lsigArgs` (as for `close()`). It takes
no `note`. An option that is present must have a value: `{leaving: undefined}`
is an error, not "leave nothing".

It returns `{asset, to, simulated, succeeded, failed, items}`, where each item
is `{from, amount, txid, confirmed, skipped, error}`. `amount` is what was to
be sent from that account, whether or not it was: count only items with no
`error` and no `skipped`. `simulated` is true when simulate mode was on, in
which case nothing was sent. An account with nothing
above `leaving`, or one not opted into the asset, is skipped: `skipped` gives
the reason and nothing is sent. When some transactions fail, read `failed` and
each item's `error`. When every transaction fails, `sweep()` throws, with each
account's reason.

A failed item can still have a `txid`: the transaction was sent and waiting
for its confirmation failed, because it timed out or the network dropped it.
The thrown message names such a transaction ("sent as ..."). Check whether it
confirmed before retrying.

Without `leaving`, an ALGO sweep leaves each account its own minimum balance,
which is the most an open account can send, and an ASA sweep leaves nothing.
`leaving: 0` on an ALGO sweep is taken as written: it tries to send the whole
balance less fees, and the network refuses that. Use `close()` to empty an
account.

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

`votekey`, `selkey`, `sproofkey`, `votefirst`, `votelast` and `keydilution`
are all required to go online. They belong to the participation key, so there
are no defaults: a registration with the wrong window or dilution goes through
but can't vote.

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

`sign()` reads an external transaction file, verifies the live algod is
running supported consensus v42 or v43, signs, submits, and optionally waits.
Each transaction must be for the active algod's network: a genesis hash, or a
set genesis ID, that differs from the algod's is refused before signing, as
`transaction at index N is for another network`.

`plan()` sends transaction sign requests to the signer group planner without
signing or triggering approval. As with `sign()`, each request's transaction,
and a passthrough entry's inner transaction, must be for the active algod's
network, and bytes that are not a canonical transaction are refused before
anything is sent. The planned fees include the signer's
authorization charge, added on top of the fees you set (see
[FEE_HANDLING.md](FEE_HANDLING.md#fee-ownership)). To sign a single
transaction, submit its original draft rather than the transaction `plan()`
returned: a single transaction has no group ID, so planning the planned
transaction again adds the charge again. `txnBytesHex` is the hex of the
letters `TX` followed by the transaction's canonical msgpack encoding, and
`signedTxnHex` the hex of a signed transaction's canonical encoding; the
signer refuses bytes without the `TX` prefix or in any other encoding. Request
fields:

```javascript
{
  authAddress,
  txnSender,
  txnBytesHex,
  signedTxnHex,
  lsigArgs: { name: "hex-string" }
}
```

An unsigned foreign slot may declare exactly one authorization hint:

```javascript
{ txnBytesHex, pqScheme: "f1" }

// or
{
  txnBytesHex,
  lsigResources: {
    programBytes,
    argumentBytes,
    maxOpcodeCost
  }
}
```

`pqScheme` declares native-PQ authorization for an unsigned foreign slot and
currently accepts `"f1"` (Falcon-1024). It is mutually exclusive with
`lsigResources`, which declares LogicSig authorization. A passthrough request
whose `signedTxnHex` carries a LogicSig must also include `lsigResources`; the
signer checks the program and argument byte counts against the signed envelope
and uses the declared reviewed opcode ceiling. `plan()` validates that the live
client algod is running supported consensus v42 or v43 before contacting apsigner.

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

`apps` is sent exactly as listed: in that order, with any repeats, and with
the called app if you list it. A program reads the list by position, so it is
never tidied. A box reference to another app adds that app at the end only
when the list doesn't already have it. Each entry uses one of the call's
reference slots, so a call near the network's limit can be rejected by the
node. A zero app ID is refused.

A box given as a name, or as `{ name }` with no `appId`, belongs to the called
app and always points at position 0. `{ appId, name }` points at that app's
position in `apps`.

Use `noop`, `optin`, `closeout`, `clear`, or `delete` for `onCompletion`.
The parser also recognizes `update`, but these JavaScript options do not
accept replacement approval/clear programs, so an update fails validation.
For updates, use the shell's [`app call`](USER_COMMANDS.md#app) with
`oncomp=update`, `approval=<path>`, and `clear=<path>` (through the MCP
`execute` tool or an interactive terminal).

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

`args` is an array with one entry per method argument, converted by the
argument's ABI type. Options are the same as `appCallRaw`.

| JavaScript value | Accepted for |
|------------------|--------------|
| number, `BigInt`, or a decimal string | `uintN`, `byte`, `ufixedNxM` |
| `true` / `false` | `bool` |
| `Uint8Array`, an array of byte numbers, or a byte-encoded string (`hex:`, `b64:`, `text:`) | `byte[]`, `byte[N]` |
| string | `string`, `address`; nothing else is accepted for `string` |
| array | arrays and tuples; each element is converted by its own type, so a `byte[]` inside a tuple takes the same forms as one at the top level |

A string given for a `string` argument is sent exactly as written, including
one that starts with `json:`; a string holding a lone surrogate or the
replacement character U+FFFD is refused. A decimal string is accepted for a
number inside an array or tuple as well as at the top level. A whole number past `Number.MAX_SAFE_INTEGER`
is refused, because JavaScript has already rounded it: pass a `BigInt` or a
decimal string. `null` and `undefined` are refused. A numeric string must be plain decimal:
`"0100"`, `"0x10"` and `"1_000"` are refused, not read as octal, hex or a
grouped number.

An array or tuple passed as one JSON string, such as `'[7,"text:abcd"]'`,
follows the shell's [`--arg`](USER_COMMANDS.md#app) rule: a byte array inside
it needs an encoding prefix, and a bare string there is refused. The array
form `[7, "abcd"]` is unchanged and reads the bare string as text.

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

`plugin()` runs the plugin as the `apshell` command does. An argument that is
an `arg:` word, such as `"arg:preimage=text:x"` or
`"arg:alice:preimage=text:x"`, is a LogicSig argument for the first step's
transactions, as on the command line (see
[ARCH_PLUGINS.md](ARCH_PLUGINS.md#logicsig-arguments-arg)); it is not passed
to the plugin. Each step's transactions are reviewed and submitted, and a step that returns a
`continuation` is followed, so the call returns only after the last step:
`success`, `message`, `data` and `presentation` are the last step's. When any
step submitted transactions, `data.txids` lists every transaction ID it
submitted, in order (in simulate mode, the IDs of the simulated transactions;
apshell's record, so a plugin's own `txids` field is replaced), and a run of
more than one such step adds `data.steps`, one `{ message, txids }` per step.
The IDs include any budget dummy transactions the signer added. In such a run
a plugin's own `steps` field is replaced as `txids` is, and when a run
submitted transactions, plugin data that is not an object is not returned.
`data` has
`localSigners` removed in every outcome; data the plugin returned as an object
stays an object, empty if `localSigners` was all it held.

Before the run has produced any transaction IDs, a cancelled review or the
plugin's own failure returns `{ success: false, message }`. Once it has, from
the steps it submitted or from a failing step whose submission returned IDs
with its error, a step that errors, is cancelled or reports failure throws,
because the workflow may be half done. The error lists those IDs in one list:
"this run produced transaction(s) …: look them up before running it again".
The list does not say which of them confirmed: the step output printed for
each completed step does, and what became of a failing step's transactions
(confirmed, rejected, or no answer) is not reported, so look each one up
before running the plugin again. In simulate mode nothing
is sent: the error says "this run simulated transaction(s) …, which were not
sent", and a failed simulation's own IDs are not listed.

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
