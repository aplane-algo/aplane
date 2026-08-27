# apshell MCP Manual

A condensed operating manual for driving **apshell** through its MCP interface
(`apshell --mcp`). It is written for an LLM or SDK client that issues tool calls,
not for a human at a terminal.

The two existing reference tools are surface listings:

- `mcp_reference` — the shell command grammar (live `help` output).
- `js_reference` — the JavaScript API (signatures and return types).

This manual is the missing layer between them: the **operating model** — how the
system is wired, what actually signs your transactions, what can block a call,
and how to go from nothing to a confirmed transaction. It distills the
human-facing `ARCH_*`/`USER_*` docs; each section ends with pointers to the full
source. It is intended to be served on demand via an `mcp_manual` tool, the same
way `js_reference` serves `USER_JSAPI.md`.

> Precedence: where this manual and a live tool result disagree, trust the live
> result. `keytypes`, `status`, and `mcp_reference` reflect connected-signer
> state; this document defines the system design.

---

## 1. Mental model: three processes, one trust boundary

```
+----------+  JSON-RPC / stdio  +------------------+  SSH tunnel   +-----------+
|   LLM    | <----------------> |  apshell --mcp   | <-----------> |  apsigner |
|  client  |   (MCP tools)      |  (client/REPL)   |   or loopback |  (signer) |
+----------+                    +--------+---------+   REST        +-----------+
                                         |
                                         v
                                  algod / indexer
                                  (the network)
```

Three distinct processes:

1. **You (the MCP client)** issue tool calls over stdio.
2. **apshell** is the *client*: it parses commands, resolves aliases, builds
   transactions, talks to the network (algod/indexer), and routes signing
   requests to the signer. **It holds no private keys.**
3. **apsigner** is the *signer*: a network-isolated daemon that owns the keys,
   applies policy, and signs. Reached over an SSH tunnel (remote) or loopback
   REST (local).

**The one rule that explains everything else:** *signer-managed private keys
never leave the signing device.* The client builds and submits; the signer
signs. This is why scripts have no key access, why signing is a request/approve
round-trip rather than a local call, and why a key generation request returns
only an address.

`status` reports the live picture of this wiring:

```json
{"network":"localnet","signer_connected":true,
 "connection_target":"127.0.0.1 (ssh:49467, signer:60040)","ssh_tunnel":true,
 "write_mode":false,"signer_key_count":0, ...}
```

Runtime model: APlane exposes one **single-product signing runtime** with no
runtime selector. Client SSH enrollments distinguish *which device/agent* is
acting for that product runtime.

> Full detail: [ARCH_OVERVIEW.md](ARCH_OVERVIEW.md), [ARCH_MCP.md](ARCH_MCP.md),
> [ARCH_AUTHORIZATION.md](ARCH_AUTHORIZATION.md).

---

## 2. The tool surface

The MCP server exposes these tools:

| Tool | Use it for |
|------|-----------|
| `execute` | Run one shell command. Best for one-off actions and reads. |
| `js` | Run JavaScript in the Goja runtime. Best for loops, computed args, structured results. Returns `{value, output}`. |
| `mcp_reference` | Fetch the full shell command grammar (live `help`). |
| `js_reference` | Fetch the JavaScript API reference. |
| `mcp_manual` | Fetch this manual. |
| `doc` | List the bundled deep-reference docs, or fetch one by name (e.g. `doc WP_CORRIDORS`). |
| `jssave` | Persist a JS snippet to `scripts/` (or an absolute path). |
| `jslist` | List saved scripts as `[{name, size, mtime}]`. |

**Reading the deep docs.** Throughout this manual, a *Full detail* pointer names
a bundled reference doc (e.g. `ARCH_TXNFLOW`). Fetch any of them with the `doc`
tool — `doc` with no argument lists everything available with one-line summaries,
and `doc name=ARCH_TXNFLOW` returns the full Markdown. Those docs are the
authoritative source; this manual is the map.

### `execute` vs `js` — how to choose

- **`execute`** — a single command in shell grammar
  (`send 5 usdc from treasury to alice`). Every supported command returns an
  intentional structured JSON result through the same handler used by the
  interactive shell. Interactive/process commands are rejected before they
  run; use the dedicated tool or workflow named in the error.
- **`js`** — when you need control flow, arithmetic on amounts, or a typed
  result object. The last expression is JSON-serialized into `value`; `print()`
  output is captured into `output`.

### Commands blocked from `execute`

These return an error telling you the right path:

| Blocked | Use instead |
|---------|-------------|
| `js`, `jssave`, `jslist` | the dedicated MCP tools |
| `request-token` | interactive approval — run real `apshell` in a terminal |
| `quit`, `exit` | MCP disconnect |
| `keyreg` with no args | provide args directly (`keyreg alice online`) — paste mode is interactive |

> Full detail: [ARCH_MCP.md](ARCH_MCP.md), [ARCH_REPL.md](ARCH_REPL.md).

---

## 3. Conventions: addresses, assets, amounts, bytes

**Addresses** can be a raw 58-char address or any of:

| Reference | Meaning |
|-----------|---------|
| `alice` | a user alias (stored lowercase) |
| `@setname` | a user-defined set |
| `@all` | all known accounts (aliases + signer keys) |
| `@signers` | all accounts the connected signer can sign for |
| `@holders(<asset>)` | dynamic set of holders of an asset |
| `[ a b c ]` | an inline group of addresses (shell only) |

In the **JS API**, pass addresses/aliases as strings and sets as arrays — the
`@name` syntax is shell-only. Alias/set names allow ASCII letters, digits, `-`,
`_` only.

**Assets**: `algo` (asset ID 0), a cached unit name (`usdc`), or a numeric ID
(`31566704`). Name→ID resolution is **per network** — `usdc` is `31566704` on
mainnet but `10458941` on testnet. Cache names with `asa add` / `cacheAsset()`.

**Amounts**: human/display units in the shell (`send 1.5 algo`, `100 usdc`);
**microAlgos / raw units in JS** — use the helpers `algo(1.25)` → `1250000` and
`microalgos(1000)`. `fee=` is always raw microAlgos.

**Byte encodings** (for LogicSig `arg:` values, raw app args, and box names):

| Form | Bytes |
|------|-------|
| `hex:abcdef` | hex |
| `b64:q83v` | base64 |
| `text:hello` | UTF-8 |
| `0xabcdef` | hex |
| bare value | UTF-8 |
| `[104, 105]` | byte array (JS) |

Box names also accept `<app-id>:<name>`.

> Full detail: [USER_COMMANDS.md](USER_COMMANDS.md) (Byte Encodings),
> [USER_JSAPI.md](USER_JSAPI.md), [ARCH_NETWORKS.md](ARCH_NETWORKS.md).

---

## 4. The key model

### Four authorization categories

| Category | What signs | Signature lands in |
|----------|-----------|--------------------|
| **Native Ed25519** (`ed25519`) | the key signs the full transaction | `SignedTxn.Sig` (64 bytes) |
| **Native Falcon-1024** (`falcon1024`) | the key signs the full transaction | top-level `SignedTxn.PQsig` (scheme `f1`) |
| **DSA-backed LogicSig** (`dsa_lsig`) | a crypto key signs, wrapped in a LogicSig | `LogicSig.Args[0]` (Falcon variable, at most 1,423 bytes) |
| **Generic LogicSig** (`generic_lsig`) | TEAL logic only — **no key, no signature** | args filled from the key file's stored schema |

The two native account key types are not LogicSig-backed. Witness keys are
auxiliary non-account keys; signer-custodied instances serve the sentry
component role, while standalone `.wit` instances may serve contract admin.

### Key types (identifiers are `publisher.family.vN`)

| keyType | Category | Typical availability |
|---------|----------|----------------------|
| `ed25519` | native | default-enabled |
| `falcon1024` | native_pq | **default-enabled** (protocol-native post-quantum) |
| `aplane.falcon1024.v1` | dsa_lsig | **default-enabled** (post-quantum default) |
| `aplane.ed25519.v1` | Ed25519 dsa_lsig | library-visible |
| `aplane.falcon1024-allowlist.v1` | dsa_lsig (composed) | bundled, installed+enabled on new stores |
| `aplane.falcon1024-allowlist.v2` | bounded dsa_lsig (Merkle allowlist) | optional template |
| `aplane.falcon1024-allowlist-alock.v1` | bounded dsa_lsig (admin-protected rekey) | optional template |
| `aplane.corridor.v1` | bounded-sentry dsa_lsig (Merkle spend corridor, admin-protected rekey) | optional template |
| `aplane.falcon1024-timelock.v1` | dsa_lsig (composed) | optional template |
| `aplane.htlc.v1` | generic_lsig | optional template |
| `aplane.falcon1024-sentry1024.v1` | guarded dsa_lsig | library-visible |
| `aplane.witness-falcon1024.v1` | witness key | sentry node `.sen` custody or external `.wit` custody |

**Always call `keytypes` to see what the connected signer actually exposes** —
availability is product-scoped. Visibility states: `default_enabled` (every
store), `library` (compiled in but needs an enabled state record in the product
store), `disabled`. A library-visible or template key type must be activated
by an operator before it appears; an agent cannot install templates (that needs
the master passphrase over local IPC) — generate the YAML and hand it to the
user.

### Why a key is independent of the network

A LogicSig's address is the hash of its compiled program. The program is
deterministic, so the same key produces the same address on every Algorand
network. **Generating a key does not bind it to mainnet/testnet/localnet** —
network only matters when you fund, opt in, or transact. Signing authority lives
in the key *file* (compiled bytecode, derivation metadata, and signing metadata
captured at creation), not in the template. Salt metadata is derivation-specific:
compiler-auto-salted records omit `salt_counter`, while compatible manual-salt
records retain it. Disabling or changing a key type therefore never breaks an
existing key's ability to sign.

### Creation params vs runtime args

- **Creation params** are baked into the address at generation time (e.g. a
  allowlist's `recipients`, a timelock's unlock round, a hashlock's hash). Pass
  them to `generate`/`generateKey`. Address-list and uint-list params are
  canonicalized (sorted) before the address is derived.
- **Runtime args** are supplied per transaction at signing time (e.g. an HTLC
  preimage). Shell syntax: `arg:preimage=0x...`. JS: the `lsigArgs` option.

### Restricted variants (the safety is in the program)

- `aplane.falcon1024-allowlist.v1` — bounded pay/asset-transfer receivers must
  be self or allowlisted; close, clawback, and non-transfer types are rejected.
- `aplane.falcon1024-allowlist.v2` — the bounded allowlist using a
  signer-generated Merkle proof for non-self spend destinations.
- `aplane.falcon1024-allowlist-alock.v1` — the bounded fixed allowlist whose
  pure rekey additionally requires an external Falcon admin signature.
- `aplane.falcon1024-timelock.v1` — bounded Falcon transfer and pure-rekey
  paths gated by `FirstValid >= unlock_round`.
- `aplane.htlc.v1` — claim with preimage before timeout, refund after.

### Corridors

A **Corridor v1** account uses the optional `aplane.corridor.v1` bounded-sentry
LogicSig profile. Its non-self payment and asset-transfer destinations must
prove membership in the generation-time Merkle recipient set, and every spend
also needs the enrolled sentry's Falcon authorization. A distinct offline
contract-admin witness co-authorizes pure rekey operations.

Recipient-constrained accounts can compose into **graphs** — a directed edge
A→B exists wherever B is in A's recipient set — so operators can build chains,
hubs, or closed meshes. `aplane.falcon1024-allowlist.v1` is a simpler fixed-list
template, not the Corridor v1 key type.

You create one by **applying a corridor LogicSig to a regular account**: rekey an
ordinary account so the Corridor program becomes its effective signer (then run
`rekey refresh`). The address is unchanged. Corridor-authorized spends are then
limited to its accepted transfer forms and recipient set; close, clawback, and
hybrid rekey-and-spend forms are rejected.

> Full detail: [WP_CORRIDORS.md](WP_CORRIDORS.md).

### Lifecycle

| Operation | Shell | JS |
|-----------|-------|-----|
| Generate | `generate <keyType> [param=value ...]` | `generateKey(keyType, params)` |
| Delete | `delete <address>` | `deleteKey(addr)` |
| Rekey | `rekey <acct> to <signer>` | `rekey(from, to)` |
| Unrekey | `unrekey <acct>` | `unrekey(acct)` |

Mnemonic import exists only for families whose provider supports it (generic
LogicSig templates have no key to import).

> ⚠️ **Rekey gotcha:** after a `rekey`, run `rekey refresh` (or
> `rekey refresh <addr>`) — otherwise the signer keeps using the *old*
> authorizer. See [USER_COMMANDS.md](USER_COMMANDS.md#rekeying-commands).

> Full detail: [USER_KEYTYPES.md](USER_KEYTYPES.md),
> [KEYTYPE_CAPABILITIES.md](KEYTYPE_CAPABILITIES.md),
> [ARCH_CRYPTO.md](ARCH_CRYPTO.md),
> [ARCH_KEY_LIFECYCLE.md](ARCH_KEY_LIFECYCLE.md),
> [ARCH_LSIG_PROVIDER.md](ARCH_LSIG_PROVIDER.md).

---

## 5. Transaction & signing flow

The client builds the group and submits it; the signer canonicalizes the group
(group ID, fees, dummy budget) and then signs each entry according to its key
type. You stay key-type agnostic — you send unsigned transaction bytes and the
signer decides what to sign:

| Key type | Message signed |
|----------|----------------|
| Ed25519 | the full transaction (`"TX"` + msgpack) |
| Native Falcon | the full transaction (`"TX"` + msgpack), emitted as top-level `PQsig` |
| LogicSig DSA | the 32-byte transaction ID (`SHA512/256("TX"+msgpack)`) |
| Generic LogicSig | nothing — TEAL logic authorizes, args come from the stored schema |

### Signer endpoints

| Endpoint | Returns |
|----------|---------|
| `POST /sign` | `signed[]` — hex signed-txn blobs, 1:1 with positions |
| `POST /plan` | `transactions[]` — TX-prefixed **unsigned** canonical txns (no signing, no approval) |
| `POST /sign/component` | guarded or bounded component signatures over a frozen group |
| `POST /sign/assemble` | final guarded or bounded signed group after component verification |
| `POST /sign/bounded-admin` | partial for an external contract-admin ceremony |
| `POST /sign/cancel` | cancel a pending approval prompt by request ID |

`plan()` in JS previews the planned group (dummies, fees, group ID) without
triggering approval — use it to inspect before committing.

### Per-entry modes (multi-party)

Each entry in a sign/plan request is exactly one of:

- **Sign** — `auth_address` + `txn_bytes_hex`; the signer signs it.
- **Passthrough** — `signed_txn_hex`; preserved byte-for-byte (already signed).
- **Foreign** — `txn_bytes_hex` *without* `auth_address`; included for group
  building, resource/fee math, and approval context, but never signed here. A
  foreign LogicSig may declare `lsig_resources` with `program_bytes`,
  `argument_bytes`, and `max_opcode_cost`. On `/plan` you get canonical
  unsigned bytes back; on `/sign` you get `""`.

An **all-foreign request is rejected** (nothing to do). To finalize a group with
another party's slots, `/plan` first, then resubmit their finalized slots as
passthrough.

### Groups, dummies, and fees

- LogicSig program bytes, arguments, and opcode cost are separate resources.
  On v42, dummies buy argument/opcode capacity; excess program bytes add a
  group fee surcharge instead. This release supports only the v42 contract.
- The signer computes one aggregate consensus fee over the final group,
  credits existing pooled fees, and assigns any deficit only to mutable
  signer-controlled slots. Foreign and passthrough slots are never rewritten.
- **Pre-grouped transactions are immutable.** If a pre-grouped batch needs more
  dummies than its budget allows, the request is **rejected** — submit the
  transactions *ungrouped* and let the signer build the group.
- Mixed groups (Ed25519 + DSA LogicSig + generic LogicSig + foreign +
  passthrough) are supported in one atomic group, subject to the rules above.

### Client-side pre-flight (before the signer is involved)

`send`/`sendAsset` check on-chain state first and fail early:

- ASA: sender opted in, sender balance sufficient, receiver opted in.
- ALGO: sender balance ≥ amount + fee; blocks sends < 0.1 ALGO to an apparently
  new account; warns (does not block) if the post-send balance would drop below
  the 0.1 ALGO minimum.

These are static, per-sender checks; they do not model cross-funding within a
group. Plugin-built groups can bypass them.

> Full detail: [ARCH_TXNFLOW.md](ARCH_TXNFLOW.md),
> [TXN_MIXED_GROUPS.md](TXN_MIXED_GROUPS.md),
> [TXN_FEE_SPLITTING.md](TXN_FEE_SPLITTING.md),
> [USER_TRANSFER_ROUTING.md](USER_TRANSFER_ROUTING.md),
> [TXN_BALANCE_VERIFICATION.md](TXN_BALANCE_VERIFICATION.md).

---

## 6. Policy, approval, and what can block a call

A sign request is not guaranteed to succeed. The signer evaluates policy and may
sign automatically, require a human, or refuse outright. **Policy is selected by
the `auth_address` that will sign** (matters for rekeyed accounts), and a
request captures its policy snapshot when it starts — a mid-flight policy reload
does not re-evaluate it.

### Verdict precedence (most restrictive wins)

```
Always Deny  >  Always Review  >  Always Approve  >  Operator Default
```

| Verdict | Client-visible effect |
|---------|------------------------|
| **Always Deny** | Rejected before approval. An operator prompt cannot rescue it. |
| **Always Review** | Forces a human approval prompt even if auto-approve is on; the call **waits** for the operator's decision (approve → signed; reject → rejected). Cancel with `/sign/cancel`. |
| **Always Approve** | Signed without a prompt. |
| **Operator Default** | Falls to `user_auto_approve`: `true` signs, `false` requires review. |

The product policy document is in the selected generation at
`identities/default/generations/<selected-generation>/policy.yaml`
(with an HMAC sidecar; a missing/mismatched sidecar **fails closed**). Runtime
settings (`user_auto_approve`, `lock_on_disconnect`, `passphrase_timeout`) live
in `identities/default/config.yaml`.

### Things that surprise clients

- **Locked signer** → keys are unusable; signing fails closed. The client cannot
  force an unlock.
- **Always Review** → the call may block for a long time and can still be
  rejected by the human. Don't assume a fast return.
- **Transfer routing** (`transfer_policy` in `policy.yaml`) is an allowlist gate
  over payment/transfer/close/clawback destinations. A route match means "may
  continue," **not** "approved" — fee/rekey/close/clawback checks and Operator
  Default still apply. Routing does **not** choose the sender or move funds for
  you.
- **Auto-approve self no-op** (`auto_approve_self_noop_transfer`) is the only
  Always Approve field and is deliberately narrow (a single 0-value self
  transfer, no group/rekey/close/clawback/note, fee ≤ 1000).
- Wire-level auth outcomes: `401` (authentication), `403` (authorization,
  fail-closed).

### Sentry / guarded signing (when present)

Guarded account key types embed a sentry's public key in their LogicSig, so a
transaction needs **two** authorizations: the user signer proves control, and a
separate **sentry** signer authorizes the facts under sentry policy. The client
orchestrates this automatically when any effective signer is a guarded account —
it never holds keys:

- Guarded/sentry keys are **never** signed via plain `/sign` (it rejects them).
  They go through `/sign/component` (roles `user` and `sentry`) and
  `/sign/assemble`.
- Sentry endpoints live in `endpoints.yaml` with `role: sentry`. For each
  operation, the client queries authenticated `/keys` and routes to the one
  endpoint advertising the required embedded public key.
- Sentry policy has only two outcomes — **reject or sign** (no human, no
  Operator Default). A locked, unreachable, stale, or wrong sentry endpoint
  fails **closed** before submission.

> Full detail: [ARCH_POLICY.md](ARCH_POLICY.md), [USER_POLICY.md](USER_POLICY.md),
> [ARCH_SENTRY.md](ARCH_SENTRY.md).

---

## 7. Rehearse before you commit

Four levers let you inspect a transaction before it is real:

| Lever | Shell | JS | Effect |
|-------|-------|-----|--------|
| Simulate | `simulate on` / `simulate <cmd>` | `setSimulate(true)` | Ordinary executable signing and approval, then client-side algod simulation without submission |
| Plan | — | `plan(requests)` | Build the canonical group (dummies/fees/group ID) without signing or approval |
| Write | `write on` | `setWriteMode(true)` | Dump transaction JSON to `txnjson/` for inspection |
| Verbose | `verbose on` | `setVerbose(true)` | Emit `log()` output and extra diagnostics |
| Wait | `nowait` to skip | `{ wait: false }` | Whether to wait for confirmation (default: wait) |

A good pattern for anything irreversible is to inspect with `plan()` first,
then simulate and read the diagnostics. Simulation releases reusable signed
bytes even though apshell does not submit them.

> Full detail: [USER_JSAPI.md](USER_JSAPI.md), [USER_LOGGING.md](USER_LOGGING.md).

---

## 8. Connection, endpoints, and networks

- **`connect [alias]`** opens the SSH tunnel to the signer (default endpoint, or
  a named one). **`disconnect`** closes it.
- **`request-token`** obtains an API token from the signer — **interactive and
  not available via MCP**; run real `apshell` in a terminal once to enroll. MCP
  refuses to start without an existing enrollment (token + trusted host).
- **`endpoints`** manages signer/sentry routing profiles (`list`, `show`,
  `create`, `import`, `discover-sentries`, `default`, `delete`). Routing lives in
  `endpoints.yaml`, not `config.yaml`. There is exactly one `role: signer`
  endpoint; the rest are `role: sentry`.

**Networks** are local context tokens — `mainnet`, `testnet`, `betanet`,
`localnet`, and custom tokens. Built-ins map to fixed genesis hashes; custom
tokens set `networks.<token>.genesis_hash` in signer config. Switch with
`network <token>`. The active network determines algod endpoint, cache
namespace, and asset-name resolution.

> Full detail: [ARCH_MCP.md](ARCH_MCP.md) (Configuration),
> [ARCH_NETWORKS.md](ARCH_NETWORKS.md), [USER_CONFIG.md](USER_CONFIG.md).

---

## 9. Plugins

Plugins extend the command surface. They are discovered from
`plugins.available/<name>/` and enabled by listing the directory name in
`plugins.yaml`; each carries a `manifest.json` and a mandatory
`checksums.sha256`, runs as a sandboxed JSON-RPC subprocess, and may include an
`mcp.md` whose contents are appended to the `execute` tool description at
startup.

Invoke from JS with `plugin(name, ...args)`, which returns:

```javascript
{ success, message, data, presentation }
```

(Always check `success`.) Ephemeral plugin signing keys (`localSigners`) are
unsupported; if a plugin returns `localSigners`, APlane rejects the plugin
result before submission.

**`algokit-localnet`** is the bundled LocalNet plugin (active when listed in
`plugins.yaml`). It talks directly to LocalNet's algod/KMD APIs and provides the
`localnet` command — notably `localnet fund <address>`, which funds from a
pre-funded KMD wallet (not from signer keys). This is how you fund a freshly
generated key on LocalNet.

> Full detail: [ARCH_PLUGINS.md](ARCH_PLUGINS.md), and the plugin's own
> `mcp.md` / `README.md`.

---

## 10. Common workflows

### From zero to a sent transaction (LocalNet)

```text
status                         # confirm signer_connected + network=localnet
keytypes                       # see what you can generate
generate aplane.falcon1024.v1  # create a post-quantum key (returns an address)
keys                           # read the new address
localnet fund <address>        # fund it from the LocalNet KMD wallet
balance <address> algo         # confirm funds
send 1 algo from <address> to <other>   # may require operator approval
```

(On TestNet, skip `localnet fund` and use the faucet at
`https://lora.algokit.io/testnet/fund`.)

### Send ALGO / ASA

```text
send 5 algo from treasury to alice note="rent"
optin usdc for alice
send 100 usdc from alice to bob
```

```javascript
send("treasury", "alice", algo(5), { note: "rent" })
let usdc = getAsaId("usdc")
optIn("alice", usdc)
sendAsset("alice", "bob", usdc, 100_000000)
```

### Atomic group (JS)

```javascript
atomicSendAsset([
  { from: "treasury", to: "alice", assetId: getAsaId("usdc"), amount: 1_000000 },
  { from: "treasury", to: "bob",   assetId: getAsaId("usdc"), amount: 1_000000 },
], { wait: true })
```

### App call (JS)

```javascript
appCall(123, "deposit(uint64)void", "artifacts/app.arc32.json", "alice", [100], {
  pay: algo(1),
  boxes: ["text:deposit"],
})
```

### Rekey (with the required refresh)

```text
rekey hot to cold
rekey refresh hot          # REQUIRED — else the signer uses the old authorizer
rekey list
```

> Full detail: [USER_QUICKSTART_LOCALNET.md](USER_QUICKSTART_LOCALNET.md),
> [USER_QUICKSTART.md](USER_QUICKSTART.md),
> [ARCH_APP_INTERACTION.md](ARCH_APP_INTERACTION.md).

---

## 11. Client data directory

Everything is scoped to the client data dir (`$APCLIENT_DATA`, or `-d <path>`);
each MCP server instance uses its own:

| Path | Holds |
|------|-------|
| `config.yaml` | network, `networks_allowed`, theme, poll interval, per-network algod |
| `endpoints.yaml` | signer + sentry routing profiles (the default endpoint) |
| `plugins.yaml` | names of enabled plugins |
| `plugins.available/<name>/` | plugin payloads |
| `aplane.token` (and `tokens/<alias>.token`) | API tokens (from `request-token`) |
| `scripts/` | saved JS (`jssave` / `jslist` / `js <file.js>`) |
| `txnjson/` | transaction JSON written in `write` mode |
| `.ssh/` | tunnel identity (`id_ed25519`) and `known_hosts` |
| `.mcp.json` | MCP server config for clients that read Claude-style JSON (written by the installer) |
| `.codex/config.toml` | Project-scoped Codex MCP server config (written by the installer) |
| cache | token-scoped ASA/alias/auth caches |

> Full detail: [USER_CONFIG.md](USER_CONFIG.md),
> [USER_CONFIG_REFERENCE.md](USER_CONFIG_REFERENCE.md).

---

## 12. Quick gotcha checklist

- **Keys live on the signer.** You only ever see addresses.
- **A key is network-agnostic.** Generating it commits to no network.
- **`keytypes` is the source of truth** for what you can generate, not this list.
- **Signing can block or be denied** by policy; `Always Review` waits on a human.
- **A locked signer fails closed.** You cannot unlock it from the client.
- **Pre-grouped + insufficient LogicSig resources or fees → rejected.** Submit
  ungrouped.
- **All-foreign sign/plan requests are rejected.**
- **After `rekey`, run `rekey refresh`.**
- **`request-token`, `js`, `jssave`, `jslist`, `quit`, `exit`, and `keyreg`
  (no args) are not available via the `execute` tool** — use the dedicated
  tools or a terminal.
- **Amounts: human units in the shell, microAlgos in JS** (`algo()` /
  `microalgos()`).
- **Asset names resolve per network.** Inspect with `plan()` and remember that
  `simulate` requests executable signatures before anything irreversible.

---

## Related documentation

- [ARCH_MCP.md](ARCH_MCP.md) — MCP server, tool surface, routing
- [ARCH_REPL.md](ARCH_REPL.md) — command parsing, dispatch, and shared results
- [USER_JSAPI.md](USER_JSAPI.md) — JavaScript API (served by `js_reference`)
- [USER_COMMANDS.md](USER_COMMANDS.md) — shell command grammar and byte encodings
- [ARCH_OVERVIEW.md](ARCH_OVERVIEW.md) — system architecture and identity model
- [ARCH_TXNFLOW.md](ARCH_TXNFLOW.md) — transaction/group/signing flow
- [ARCH_POLICY.md](ARCH_POLICY.md) / [USER_POLICY.md](USER_POLICY.md) — policy and approval
- [ARCH_SENTRY.md](ARCH_SENTRY.md) — guarded signing
- [USER_KEYTYPES.md](USER_KEYTYPES.md) / [KEYTYPE_CAPABILITIES.md](KEYTYPE_CAPABILITIES.md) — key types
- [WP_CORRIDORS.md](WP_CORRIDORS.md) — corridors (constrained-transfer graphs)
- [ARCH_PLUGINS.md](ARCH_PLUGINS.md) — plugins
- [USER_QUICKSTART_LOCALNET.md](USER_QUICKSTART_LOCALNET.md) / [USER_QUICKSTART.md](USER_QUICKSTART.md) — getting started
