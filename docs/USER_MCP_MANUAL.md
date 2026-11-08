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
source. It is served on demand via the `mcp_manual` tool, the same
way `js_reference` serves `USER_JSAPI.md`.

> Precedence: where this manual and a live tool result disagree, trust the live
> result. `keytypes`, `status`, and `mcp_reference` reflect connected-signer
> state; this document defines the system design.

---

## 1. Mental model: three processes, one trust boundary

```
+----------+  JSON-RPC / stdio  +------------------+  SSH tunnel   +-----------+
|   LLM    | <----------------> |  apshell --mcp   | <-----------> |  apsigner |
|  client  |   (MCP tools)      |  (client/REPL)   |               |  (signer) |
+----------+                    +--------+---------+               +-----------+
                                         |
                                         v
                                  algod
                                  (the network)
```

Three distinct processes:

1. **You (the MCP client)** issue tool calls over stdio.
2. **apshell** is the *client*: it parses commands, resolves aliases, builds
   transactions, talks to the network through algod, and routes signing
   requests to the signer. **Account signing keys stay on apsigner; the client
   holds only its own SSH key.**
3. **apsigner** is the *signer*: a separate daemon that owns the keys,
   applies policy, and signs. It also contacts its configured algod for work
   such as TEAL compilation and fresh rotating-account state checks. Client
   API calls arrive over an enrolled SSH tunnel; direct loopback REST serves
   only `/health`.

**The one rule that explains everything else:** *ordinary signing returns
authorization, not private keys.* The client builds and submits; the signer
signs. This is why scripts have no key access, why signing is a request/approve
round-trip rather than a local call, and why a key generation request returns
only an address.

`status` reports the live picture of this wiring:

```json
{"network":"localnet","signer_connected":true,
 "connection_target":"127.0.0.1 (ssh:49467)","ssh_tunnel":true,
 "write_mode":false,"signer_key_count":0, ...}
```

Runtime model: APlane exposes one **single-product signing runtime** with no
runtime selector. Client SSH enrollments distinguish *which device/agent* is
acting for that product runtime.

> Full detail: [ARCH_OVERVIEW.md](ARCH_OVERVIEW.md), [ARCH_SHELL.md](ARCH_SHELL.md#mcp-surface),
> [ARCH_SECURITY.md](ARCH_SECURITY.md#authorization).

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
| `doc` | List the bundled deep-reference docs, or fetch one by name (e.g. `doc ARCH_GUARDED`). |
| `jssave` | Persist a JS snippet to `scripts/` (or an absolute path). |
| `jslist` | List saved scripts as `[{name, size, mtime}]`. |

**Reading the deep docs.** Throughout this manual, a *Full detail* pointer names
a bundled reference doc (e.g. `ARCH_SIGNING`). Fetch any of them with the `doc`
tool — `doc` with no argument lists everything available with one-line summaries,
and `doc name=ARCH_SIGNING` returns the full Markdown. Those docs are the
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
| `enroll` | interactive host trust — run real `apshell` in a terminal |
| `help` | `mcp_reference` |
| `config` | `status` for safe runtime information; edit configuration outside MCP |
| `script` | individual `execute` calls or the `js` tool |
| `cosigner` (all subcommands), `endpoints add` | interactive apshell for the guided trust workflow |
| `clear` | no machine-readable equivalent is needed |
| `quit`, `exit`, `q` | MCP disconnect |
| `keyreg` with no args | provide args directly (`keyreg alice online`) — paste mode is interactive |

> Full detail: [ARCH_SHELL.md](ARCH_SHELL.md#mcp-surface) (MCP and REPL surfaces).

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

### Authorization categories

| Category | What signs | Signature lands in |
|----------|-----------|--------------------|
| **Native Ed25519** (`ed25519`) | the key signs the full transaction | `SignedTxn.Sig` (64 bytes) |
| **Native Falcon-1024** (`falcon1024`) | the key signs the full transaction | top-level `SignedTxn.PQsig` (scheme `f1`) |
| **DSA-backed LogicSig** (`dsa_lsig`) | a crypto key signs, wrapped in a LogicSig | `LogicSig.Args[0]` (Falcon variable, at most 1,423 bytes) |
| **Generic LogicSig** (`generic_lsig`) | TEAL logic only — **no key, no signature** | args filled from the key file's stored schema |
| **Rotating LogicSig** | Falcon-1024, Ed25519, and XMSS, SLH-DSA, or WOTS+C authorize each stage | stage LogicSig arguments; each spend rekeys to the next stage |

The two native account key types are not LogicSig-backed. Witness keys are
auxiliary non-account keys that a cosigner holds for the cosigner component
role.

### Key types (identifiers are `publisher.family.vN`)

| keyType | Category | Typical availability |
|---------|----------|----------------------|
| `ed25519` | native | default-enabled |
| `falcon1024` | native_pq | **default-enabled** (protocol-native post-quantum) |
| `aplane.falcon1024.v1` | dsa_lsig | internal-only; composition and existing accounts |
| `aplane.ed25519.v1` | Ed25519 dsa_lsig | internal-only; composition and existing accounts |
| `aplane.falcon1024-b.v1` | bounded dsa_lsig (allowlist, timelock, Corridor presets) | default-enabled on signer nodes |
| `aplane.htlc.v1` | generic_lsig | optional template |
| `aplane.falcon1024-cosigner1024.v1` | guarded dsa_lsig | library-visible |
| `aplane.rotating-triple-xmss.v1` | rotating LogicSig | library-visible |
| `aplane.rotating-triple-slhdsa.v1` | rotating LogicSig | library-visible |
| `aplane.rotating-triple-wotsc.v1` | rotating LogicSig | library-visible |
| `aplane.witness-falcon1024.v1` | witness key | default-enabled on cosigner nodes (`.cos`) |

**Always call `keytypes` to see what the connected signer actually exposes** —
availability is product-scoped. Visibility states: `default_enabled` (for the applicable node role), `library` (compiled in but needs an enabled state record in the product
store), `internal_only` (composition and existing credentials only), `disabled`. A library-visible or template key type must be activated
by an operator before it appears; an agent cannot install templates (that needs
the master passphrase over local IPC) — generate the YAML and hand it to the
user.

### Network binding and stored credentials

Native account addresses are independent of the network. A LogicSig address
is the hash of its program, so it is the same wherever that exact program is
used. However, **rotating accounts bind their stages to a genesis hash**:
generating from the same seed for different networks produces different
accounts. Templates can also bake network restrictions into their programs.
Balances, opt-ins, and on-chain authorizers are always network-specific.

Existing LogicSig credentials retain their compiled bytecode and derivation
and signing metadata; rotating credentials instead retain the seed and bound
genesis hash used to derive stage programs. Disabling a key type stops new
creation without disabling existing valid credentials. Signing still requires
a supported provider. Compiler-auto-salted records omit `salt_counter`, while
compatible manual-salt records retain it.

### Creation params vs runtime args

- **Creation params** are baked into the address at generation time (e.g. a
  allowlist's `recipients`, a timelock's unlock round, an HTLC's hash). Pass
  them to `generate`/`generateKey`. Address-list and uint-list params are
  canonicalized (sorted) before the address is derived.
- **Runtime args** are supplied per transaction at signing time (e.g. an HTLC
  preimage). Shell syntax: `arg:preimage=0x...`. JS: the `lsigArgs` option.

### Restricted variants (the safety is in the program)

- `aplane.falcon1024-b.v1` — the general bounded account. Its presets are an
  allowlist (pay and asset-transfer receivers must be self or listed, with a
  signer-generated Merkle proof for a long list), a locked allowlist that
  refuses rekeys, Corridor, and a timelock (`FirstValid >= unlock_round` before
  any spend; it refuses rekeys). Close, clawback, and non-transfer types are
  rejected. A rekey, when allowed, needs the spending key alone.
- `aplane.htlc.v1` — ALGO only and all-or-nothing: `close` to the recipient with the
  preimage before timeout, or to the refund address after.

### Corridors

A **Corridor v1** account is the Corridor preset of `aplane.falcon1024-b.v1`, a
bounded-cosigner LogicSig profile. Its non-self payment and asset-transfer
destinations must prove membership in the generation-time Merkle recipient set,
and every spend also needs the enrolled cosigner's Falcon authorization. It
refuses rekeys, so if the cosigner is lost, its funds cannot be recovered.

Recipient-constrained accounts can compose into **graphs** — a directed edge
A→B exists wherever B is in A's recipient set — so operators can build chains,
hubs, or closed meshes. The Allowlist and Locked Allowlist presets are simpler
recipient lists with no cosigner.

You create one by **applying a corridor LogicSig to a regular account**: rekey an
ordinary account so the Corridor program becomes its effective signer (then run
`rekey refresh`). The address is unchanged. Corridor-authorized spends are then
limited to its accepted transfer forms and recipient set; close, clawback, and
hybrid rekey-and-spend forms are rejected.

> Full detail: [ARCH_GUARDED.md](ARCH_GUARDED.md#corridor-v1) (the Corridor v1
> contract) and [USER_KEYTYPES.md](USER_KEYTYPES.md) (generating and using it).

### Lifecycle

| Operation | Shell | JS |
|-----------|-------|-----|
| Generate | `generate <keyType> [param=value ...]` | `generateKey(keyType, params)` |
| Delete | `delete <address>` | `deleteKey(addr)` |
| Rekey | `rekey <acct> to <signer>` | `rekey(from, to)` |
| Unrekey | `unrekey <acct>` | `unrekey(acct)` |

Mnemonic import is a local apadmin IPC operation, outside the shell/MCP surface.
The [approved native-only policy](ARCH_KEYTYPES.md#mnemonic-backup-and-recovery)
limits mnemonic import, export, and recovery to native accounts. Plain LogicSig
providers are internal-only and cannot be enabled or generated directly. Use
encrypted backups for all LogicSig accounts.

> **Rekey refresh:** a confirmed rekey through the ordinary single-transaction
> workflow refreshes the affected client
> auth-cache entry automatically. Run `rekey refresh <addr>` after other
> submission workflows, external changes, an unconfirmed submission, or a
> reported refresh failure. See [USER_COMMANDS.md](USER_COMMANDS.md#rekeying-commands).

> Full detail: [USER_KEYTYPES.md](USER_KEYTYPES.md),
> [KEYTYPE_CAPABILITIES.md](KEYTYPE_CAPABILITIES.md),
> [ARCH_CRYPTO.md](ARCH_CRYPTO.md),
> [ARCH_STORE.md](ARCH_STORE.md#keys-and-key-types),
> [ARCH_KEYTYPES.md](ARCH_KEYTYPES.md#logicsig-providers).

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
  group fee surcharge instead. This release supports exactly v42 and v43,
  with identical resource rules.
- The signer computes one aggregate consensus fee over the final group,
  checks that the client's fees cover the client's own transactions, and adds
  its authorization charge (dummy base fees, priced LogicSig program bytes,
  native-PQ contributions) on top, only to mutable signer-controlled slots. A
  client surplus, such as an app call's extra fee for inner transactions, is
  never spent on the charge. Foreign and passthrough slots are never rewritten.
- **Pre-grouped transactions are immutable.** If a pre-grouped batch needs more
  dummies than its budget allows, the request is **rejected** — submit the
  transactions *ungrouped* and let the signer build the group.
- Mixed native and LogicSig groups are supported; foreign and passthrough
  entries cannot coexist in the same request.

### Client-side pre-flight (before the signer is involved)

`send`/`sendAsset` check on-chain state first and fail early:

- ASA: sender opted in, sender balance sufficient, receiver opted in.
- ALGO: sender balance ≥ amount + fee; blocks sends < 0.1 ALGO to an apparently
  new account; warns (does not block) if the post-send balance would drop below
  the 0.1 ALGO minimum.

These are static, per-sender checks; they do not model cross-funding within a
group. Plugin-built groups can bypass them.

> Full detail: [ARCH_SIGNING.md](ARCH_SIGNING.md),
> [TXN_MIXED_GROUPS.md](TXN_MIXED_GROUPS.md),
> [FEE_HANDLING.md](FEE_HANDLING.md),
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
| **Always Review** | With User Auto-Approve on, signs without a prompt. Otherwise the call **waits** for the operator's decision (approve → signed; reject → rejected). Cancel with `/sign/cancel`. |
| **Always Approve** | Signed without a prompt. |
| **Operator Default** | Falls to `user_auto_approve`: `true` signs, `false` requires review. |

Policy is a set of v1 JSON documents in the selected generation: the node
default `identities/default/generations/<selected-generation>/default.json`,
which governs every key without a policy of its own, and `policies/<key>.json`
for a key that has one (a signing address on a signer node, a Witness Key ID
on a cosigner node; the file replaces the default for that key wholesale).
Each has an HMAC sidecar; a missing/mismatched sidecar **fails closed**.
Runtime settings (`user_auto_approve`, `lock_on_disconnect`,
`passphrase_timeout`) live in `identities/default/config.yaml`.

### Things that surprise clients

- **Locked signer** → keys are unusable; signing fails closed. The client cannot
  force an unlock.
- **Always Review** → the call may block for a long time and can still be
  rejected by the human. Don't assume a fast return.
- **Transfer routing** (`transfer_policy` in the policy document) is an allowlist gate
  over payment/transfer/close/clawback destinations. A route match means "may
  continue," **not** "approved" — fee/rekey/close/clawback checks and Operator
  Default still apply. Routing does **not** choose the sender or move funds for
  you.
- **Auto-approve self no-op** (`auto_approve_self_noop_transfer`) is the only
  Always Approve field and is off in the shipped policy. It requires one
  zero-value self-transfer with no rekey, close, clawback, note, or lease. Only
  permitted signer resource dummies may accompany it, with a normalized fee
  of at most 1,000 microAlgos. Priced program bytes and native PQ charges
  disqualify it. It does not apply to a one-ALGO self-send.
- Wire-level auth outcomes: `401` (authentication), `403` (authorization,
  fail-closed).

### Cosigner / guarded signing (when present)

Guarded account key types embed a cosigner's public key in their LogicSig, so a
transaction needs **two** authorizations: the user signer proves control, and a
separate **cosigner** signer authorizes the facts under cosigner policy. The client
orchestrates this automatically when any effective signer is a guarded account —
it never receives account signing keys:

- Guarded/cosigner keys are **never** signed via plain `/sign` (it rejects them).
  They go through `/sign/component` (roles `user` and `cosigner`) and
  `/sign/assemble`.
- Cosigner endpoints live in `endpoints.yaml` with `role: cosigner`. For each
  operation, the client queries authenticated `/keys` and routes to the one
  endpoint advertising the required embedded public key.
- Cosigner policy has only two outcomes — **reject or sign** (no human, no
  Operator Default). A cosigner key is governed by its own policy file or, if
  it has none, by the node default, which as shipped rejects every request. A
  locked, unreachable, stale, or wrong cosigner endpoint fails **closed**
  before submission.

> Full detail: [ARCH_POLICY.md](ARCH_POLICY.md), [USER_POLICY.md](USER_POLICY.md),
> [ARCH_GUARDED.md](ARCH_GUARDED.md).

---

## 7. Rehearse before you commit

These controls help inspect planning, signature release, and submission:

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
- **`enroll`** asks the signer to enroll this client's SSH key —
  **interactive and not available via MCP**; run real `apshell` in a terminal
  once to submit the request, then have the operator approve it. MCP refuses
  to start without a trusted host, and the signer refuses the tunnel until the
  key is enrolled.
- **`endpoints`** manages signer/cosigner routing profiles (`list`, `show`,
  `create`, `import`, `discover-cosigners`, `default`, `delete`, plus interactive
  `add`). Routing lives in
  `endpoints.yaml`, not `config.yaml`. There is exactly one `role: signer`
  endpoint; the rest are `role: cosigner`.

**Networks** are local context tokens — `mainnet`, `testnet`, `betanet`,
`localnet`, and custom tokens. Built-ins map to fixed genesis hashes; custom
tokens set `networks.<token>.genesis_hash` in signer config. Switch with
`network <token>`. The active network determines algod endpoint, cache
namespace, and asset-name resolution.

> Full detail: [ARCH_SHELL.md](ARCH_SHELL.md#mcp-surface) (Configuration),
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
generate falcon1024            # create a native post-quantum key (returns an address)
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

### Rekey and explicit refresh

```text
rekey hot to cold
rekey refresh hot          # explicit refresh after external/unconfirmed changes
rekey list
```

> Full detail: [USER_QUICKSTART_LOCALNET.md](USER_QUICKSTART_LOCALNET.md),
> [USER_QUICKSTART.md](USER_QUICKSTART.md),
> [ARCH_SHELL.md](ARCH_SHELL.md#app-interaction).

---

## 11. Client data directory

Everything is scoped to the client data dir (`$APCLIENT_DATA`, or `-d <path>`);
each MCP server instance uses its own:

| Path | Holds |
|------|-------|
| `config.yaml` | network, `networks_allowed`, theme, poll interval, per-network algod |
| `endpoints.yaml` | signer + cosigner routing profiles (the default endpoint) |
| `plugins.yaml` | names of enabled plugins |
| `plugins.available/<name>/` | plugin payloads |
| `scripts/` | saved JS (`jssave` / `jslist` / `js <file.js>`) |
| `txnjson/` | transaction JSON written in `write` mode |
| `.ssh/` | tunnel identity (`id_ed25519`, the client's only credential) and `known_hosts` |
| `.mcp.json` | MCP server config for clients that read Claude-style JSON (written by the installer) |
| `.codex/config.toml` | Project-scoped Codex MCP server config (written by the installer) |
| cache | token-scoped ASA/alias/auth caches |

> Full detail: [USER_CONFIG.md](USER_CONFIG.md),
> [USER_CONFIG_REFERENCE.md](USER_CONFIG_REFERENCE.md).

---

## 12. Quick gotcha checklist

- **Keys live on the signer.** You only ever see addresses.
- **Check network binding.** Rotating accounts bind to one network; templates
  may also embed network restrictions.
- **`keytypes` is the source of truth** for what you can generate, not this list.
- **Signing can block or be denied** by policy; `Always Review` waits on a human.
- **A locked signer fails closed.** You cannot unlock it from the client.
- **Pre-grouped + insufficient LogicSig resources or fees → rejected.** Submit
  ungrouped.
- **All-foreign sign/plan requests are rejected.**
- **Refresh after external or unconfirmed rekeys, or a reported cache refresh
  failure.**
- **Some commands require dedicated tools or a terminal.** Check the
  [blocked-command table](#commands-blocked-from-execute) before using `execute`.
- **Amounts: human units in the shell, microAlgos in JS** (`algo()` /
  `microalgos()`).
- **Asset names resolve per network.** Inspect with `plan()` and remember that
  `simulate` requests executable signatures before anything irreversible.

---

## Related documentation

- [ARCH_SHELL.md](ARCH_SHELL.md#mcp-surface) — MCP server, tool surface, routing
- [ARCH_SHELL.md](ARCH_SHELL.md#repl-surface) — command parsing, dispatch, and shared results
- [USER_JSAPI.md](USER_JSAPI.md) — JavaScript API (served by `js_reference`)
- [USER_COMMANDS.md](USER_COMMANDS.md) — shell command grammar and byte encodings
- [ARCH_OVERVIEW.md](ARCH_OVERVIEW.md) — system architecture and identity model
- [ARCH_SIGNING.md](ARCH_SIGNING.md) — transaction/group/signing flow
- [ARCH_POLICY.md](ARCH_POLICY.md) / [USER_POLICY.md](USER_POLICY.md) — policy and approval
- [ARCH_GUARDED.md](ARCH_GUARDED.md) — guarded signing
- [USER_KEYTYPES.md](USER_KEYTYPES.md) / [KEYTYPE_CAPABILITIES.md](KEYTYPE_CAPABILITIES.md) — key types
- [ARCH_PLUGINS.md](ARCH_PLUGINS.md) — plugins
- [USER_QUICKSTART_LOCALNET.md](USER_QUICKSTART_LOCALNET.md) / [USER_QUICKSTART.md](USER_QUICKSTART.md) — getting started
