# apshell Command Reference

Complete command reference for the APlane shell (`apshell`).

---

## Quick Reference

| Category | Commands |
|----------|----------|
| **Transactions** | `send`, `sweep`, `close`, `optin`, `optout`, `keyreg`, `sign`, `validate`, `app` |
| **Information** | `balance`, `holders`, `participation`, `accounts`, `keys`, `status`, `info` |
| **Keys** | `keytypes`, `generate`, `delete` |
| **Aliases & Sets** | `alias`, `sets` |
| **Rekeying** | `rekey list`, `rekey`, `unrekey` |
| **ASA Management** | `asa list`, `asa add`, `asa remove`, `asa clear` |
| **Configuration** | `network`, `connect`, `disconnect`, `request-token`, `endpoints`, `write`, `verbose`, `simulate`, `config` |
| **Automation** | `js`, `jssave`, `jslist`, `script` |
| **Plugins** | `plugins` |
| **Session** | `help`, `clear`, `quit` |

---

## Transaction Commands

### send

Send ALGO or ASA tokens to one or more recipients.

```
send <amount> <asset> from <sender> to <receiver> [options]
```

**Arguments:**
| Argument | Description |
|----------|-------------|
| `<amount>` | Amount to send (e.g., `1.5`, `100`) |
| `<asset>` | `algo` or ASA reference (unit name or ID) |
| `<sender>` | Address, alias, or `@setname` |
| `<receiver>` | Address, alias, or `@setname` |

**Options:**
| Option | Description |
|--------|-------------|
| `note=<text>` | Attach a note to the transaction |
| `fee=<microalgos>` | Custom transaction fee |
| `nowait` | Don't wait for confirmation |
| `atomic` | Send as atomic group (with sets) |
| `arg:name=<value>` | LogicSig argument; see [Byte Encodings](#byte-encodings) for supported forms. Args apply to all LSig senders in the transaction group. |

**Examples:**
```
send 1.5 algo from alice to bob
send 100 usdc from alice to bob note="Payment for services"
send 1 algo from alice to @friends atomic
send 1 algo from [alice bob charlie] to treasury atomic
send 0.5 algo from lsig-htlc to bob arg:preimage=hello
send 0.5 algo from lsig-htlc to bob arg:preimage=hex:abcdef
```

---

### sweep

Sweep assets from multiple accounts to a single destination.

```
sweep <asset> [from [accounts...]] to <dest> [leaving <amount>] [options]
```

**Arguments:**
| Argument | Description |
|----------|-------------|
| `<asset>` | `algo` or ASA reference |
| `<accounts>` | Optional: `[addr1 addr2 ...]` or `@setname` (default: all signable) |
| `<dest>` | Destination address or alias |
| `<amount>` | Amount to leave in each source account (default: `0`, sweep everything else) |

**Options:**
| Option | Description |
|--------|-------------|
| `fee=<microalgos>` | Custom transaction fee |
| `nowait` | Don't wait for confirmation |
| `arg:name=<value>` | LogicSig argument; see [Byte Encodings](#byte-encodings) for supported forms. Args apply to each generated sweep transaction. |

**Examples:**
```
sweep algo to treasury                              # All signable accounts
sweep usdc from [alice bob charlie] to treasury
sweep algo from @team to main leaving 1             # Leave 1 ALGO in each
sweep usdc from @validators to cold leaving 100
sweep algo from @lsigs to treasury arg:preimage=text:secret
```

---

### close

Close an account and send all ALGO to a destination.

```
close <account> to <destination> [options]
```

**Restrictions:** Fails if account is online for consensus or holds any ASAs.

**Options:**
| Option | Description |
|--------|-------------|
| `fee=<microalgos>` | Custom transaction fee |
| `nowait` | Don't wait for confirmation |
| `arg:name=<value>` | LogicSig argument; see [Byte Encodings](#byte-encodings) for supported forms. |

**Examples:**
```
close alice to bob
close temp-account to treasury nowait
```

---

### optin

Opt into an ASA (required before receiving tokens).

```
optin <asset> for <account> [options]
```

**Options:**
| Option | Description |
|--------|-------------|
| `fee=<microalgos>` | Custom transaction fee |
| `nowait` | Don't wait for confirmation |
| `arg:name=<value>` | LogicSig argument; see [Byte Encodings](#byte-encodings) for supported forms. |

**Examples:**
```
optin usdc for alice
optin 31566704 for bob
optin usdc for lsig-account arg:preimage=text:secret
```

---

### optout

Opt out of an ASA and reclaim minimum balance.

```
optout <asset> from <account> [to <dest>] [options]
```

**Note:** If account holds a non-zero balance, you must specify `to <dest>` to transfer the remaining tokens.

**Options:**
| Option | Description |
|--------|-------------|
| `fee=<microalgos>` | Custom transaction fee |
| `nowait` | Don't wait for confirmation |
| `arg:name=<value>` | LogicSig argument; see [Byte Encodings](#byte-encodings) for supported forms. |

**Examples:**
```
optout usdc from alice                    # Must have 0 balance
optout usdc from alice to bob             # Transfer remaining to bob
optout usdc from lsig-account arg:preimage=text:secret
```

---

### keyreg

Register or deregister account for consensus participation.

```
keyreg <account> <online|offline> [options]
keyreg
```

**Online Registration Options:**
| Option | Description |
|--------|-------------|
| `votekey=<base64>` | Voting key (required for online) |
| `selkey=<base64>` | Selection key (required for online) |
| `sproofkey=<base64>` | State proof key (required for online) |
| `votefirst=<round>` | First valid round (default: 0) |
| `votelast=<round>` | Last valid round (default: 3000000) |
| `keydilution=<n>` | Key dilution (default: 10000) |
| `eligible=true` | Mark as incentive-eligible |
| `nowait` | Don't wait for confirmation |
| `arg:name=<value>` | LogicSig argument; see [Byte Encodings](#byte-encodings) for supported forms. |

**Examples:**
```
keyreg alice offline
keyreg alice online votekey=ABC... selkey=DEF... sproofkey=GHI...
keyreg lsig-account offline arg:preimage=text:secret
keyreg alice online votekey=ABC... selkey=DEF... sproofkey=GHI... eligible=true
```

**Paste Mode:** Running `keyreg` with no arguments enters interactive paste mode for the output of `goal account partkeyinfo`.

**Tip:** Copy-paste participation keys from `goal account partkeyinfo` output.

---

### sign

Sign and submit transaction(s) from an external file.

```
sign <file> [nowait]
```

**Supported formats:**
- Base64-encoded unsigned transaction msgpack, either a single transaction or a transaction array
- JSON transaction object or JSON transaction array
- JSON object with `txn` array containing base64-encoded msgpack transactions

**Examples:**
```
sign transaction.txn
sign group.json nowait
```

---

### validate

Validate signing capability by sending 0 ALGO to self.

```
validate <account|@setname> [arg:name=value]
```

**Options:**
| Option | Description |
|--------|-------------|
| `arg:name=<value>` | LogicSig argument; see [Byte Encodings](#byte-encodings) for supported forms. Args apply to each generated validation transaction. |

**Examples:**
```
validate alice
validate @signers
validate lsig-account arg:preimage=text:secret
```

---

## Information Commands

### balance

Show balances for one or more accounts.

```
balance [account|@all|@signers|@setname] [asset]
```

**Arguments:**
| Argument | Description |
|----------|-------------|
| `<account>` | Optional address, alias, `@all`, `@signers`, or `@setname` (default: `@all`) |
| `[asset]` | Optional: `algo`, `asa`, or specific ASA reference |

**Aliases:** `bal`

**Examples:**
```
balance alice
balance @signers algo
balance @validators usdc
bal alice
```

---

### holders

Show accounts with non-zero balance for an asset.

```
holders [asset]
```

**Examples:**
```
holders              # ALGO balances
holders usdc         # USDC holders
```

---

### participation

Show detailed consensus participation status for an account.

```
participation <address|alias>
```

**Examples:**
```
participation alice
participation ABCD1234...
```

---

### accounts

List all known accounts (aliases + signer accounts).

```
accounts
```

---

### keys

List accounts available for signing from the connected Signer.

```
keys
```

---

### status

Show current configuration and connection status.

```
status
```

---

### info

Show detailed information about an ASA.

```
info <asa-id>
```

**Examples:**
```
info 31566704
```

---

### plugins

List external plugins or show details for a specific plugin.

```
plugins [name]
```

**Examples:**
```
plugins                    # List all
plugins my-plugin          # Show details
```

---

## Alias & Set Commands

### alias

Manage address aliases for easier reference.

```
alias                           # Show alias command forms
alias list                      # List all aliases
alias <name> <address>          # Create alias
alias <name>                    # Show specific alias
alias delete <name>             # Delete alias
```

**Examples:**
```
alias
alias list
alias alice ABCD1234...
alias delete alice
```

Alias names may contain only ASCII letters, numbers, `-`, and `_`, and are
stored in lowercase. The command words `list`, `delete`, and `remove` are
reserved.

---

### sets

Manage address sets (collections of addresses).

```
sets                                      # Show sets command forms
sets list                                 # List all sets
sets <name>                               # Show set members
sets <name> <addr1> <addr2> ...           # Create set
sets add <addr>... to <name>              # Add to set
sets remove <addr>... from <name>         # Remove from set
sets delete <name>                        # Delete set
```

**Usage:** Reference sets with `@setname` in commands.

**Examples:**
```
sets
sets list
sets validators alice bob charlie
sets validators [ alice bob charlie ]         # Bracket notation (equivalent)
sets add david to validators
sets remove charlie from validators
sets delete validators
send 1 algo from alice to @validators atomic
```

Set names may contain only ASCII letters, numbers, `-`, and `_`, and are stored
in lowercase. The command words `list`, `add`, `remove`, and `delete` are
reserved, and dynamic set names such as `all` and `signers` are not valid
user-defined sets.

### Bracket Notation

Addresses can be grouped inline using bracket notation `[ addr1 addr2 ... ]`. Brackets can be attached (`[addr1 addr2]`) or standalone (`[ addr1 addr2 ]`). Tab completion works inside bracket groups — press Tab to complete partial addresses.

```
send 1 algo from [alice bob charlie] to treasury atomic
sweep usdc from [ alice bob ] to cold
sets team [ alice bob charlie ]
```

---

## Rekeying Commands

The apshell commands below handle ordinary rekey workflows. Admin-key bounded
accounts are intentionally not completed in apshell or apconsole; use the
dedicated contract-admin client:

```bash
aprekey rekey --key <key.wit> [--client-data <dir>] [--network <name>] [--fee <microalgos>] [--nowait] <account> to <new-authorizer>
aprekey unrekey --key <key.wit> [--client-data <dir>] [--network <name>] [--fee <microalgos>] [--nowait] <account>
```

`APCLIENT_DATA` is used when `--client-data` is omitted. The command connects
to the configured default signer, obtains its approved spending partial, then
opens a separate confirmation and artifact-passphrase prompt. It submits only
after validating and assembling both signatures. Apshell has no private
contract-admin artifact syntax.

For a separate ceremony machine, prepare online, sign offline, then complete
online without contacting the signer again:

```bash
aprekey prepare-rekey --out <request.apbounded-admin-request> [--client-data <dir>] [--network <name>] [--fee <microalgos>] <account> to <new-authorizer>
aprekey prepare-unrekey --out <request.apbounded-admin-request> [--client-data <dir>] [--network <name>] [--fee <microalgos>] <account>
aprekey sign --key <key.wit> --request <request.apbounded-admin-request> --out <response.apbounded-admin-signature>
aprekey complete [--client-data <dir>] [--network <name>] [--nowait] <request.apbounded-admin-request> with <response.apbounded-admin-signature>
```

The request and response files are non-secret, but they authorize one exact,
short-lived finalized transaction. Transfer them through an operator-controlled
channel and retain them as ceremony records. `complete` rejects stale validity
rounds, changed account authority, wrong network/genesis, or a mismatched
response; it does not replan or request a fresh signer approval.

### rekey

Query rekeying status or rekey an account to a new signing authority.

```
rekey                           # Show rekey command forms
rekey list                      # Show all rekeyed accounts
rekey refresh                   # Rebuild auth cache
rekey refresh <address|alias>   # Refresh one auth-cache entry
rekey <account> to <signer> [arg:name=value]  # Rekey account
```

**Options:**
| Option | Description |
|--------|-------------|
| `fee=<microalgos>` | Custom transaction fee |
| `nowait` | Don't wait for confirmation |
| `arg:name=<value>` | LogicSig argument used when the account's current auth address is a LogicSig |

**Examples:**
```
rekey
rekey list
rekey refresh
rekey alice to bob
rekey alice to multisig-addr fee=2000
rekey alice to makman-lsig arg:rekey_preimage=text:secret
```

---

### unrekey

Rekey an account back to itself (restore self-signing).

```
unrekey <account> [options]
```

**Options:**
| Option | Description |
|--------|-------------|
| `fee=<microalgos>` | Custom transaction fee |
| `nowait` | Don't wait for confirmation |
| `arg:name=<value>` | LogicSig argument used when the account's current auth address is a LogicSig |

**Examples:**
```
unrekey alice
unrekey alice arg:preimage=text:secret
```

---

## ASA Management Commands

### asa list

List all ASAs in the local cache.

```
asa list
```

---

### asa add

Add an ASA to the local cache (fetches info from network).

```
asa add <asset-id>
```

**Examples:**
```
asa add 31566704
```

---

### asa remove

Remove an ASA from the local cache.

```
asa remove <asset-id>
```

---

### asa clear

Clear all ASAs from the local cache.

```
asa clear
```

## Configuration Commands

### network

Switch the active network context token.

```
network <network>
```

**Note:** May be restricted by `config.yaml` `networks_allowed` settings.

---

### connect

Connect to `apsigner` for transaction signing.

```
connect [endpoint-alias]
```

With no arguments, `connect` opens the default signer endpoint from
`$APCLIENT_DATA/endpoints.yaml`. Passing an endpoint alias connects to that
named profile. This release does not support top-level `ssh:` or
`signer_port:` routing in client `config.yaml`; write signer routing in
`endpoints.yaml`.

**Examples:**
```
connect
connect primary
```

**Required config:**
- `endpoints.yaml` default signer endpoint with `role: signer`
- endpoint `url: ssh://host[:port]`
- endpoint `identity_file` (defaults to `.ssh/id_ed25519` if omitted)

`known_hosts_path` is optional; if omitted, apshell uses the default client-data known-hosts path.

**Setup:** Obtain a token with `request-token` or place `aplane.token` in your `$APCLIENT_DATA` directory.

---

### disconnect

Close the active signer SSH tunnel.

```
disconnect
```

This is useful before connecting to a different endpoint in scripts.

---

### request-token

Request an API token from the Signer over SSH.

```
request-token
request-token --endpoint <alias>
```

The command always uses the client SSH key and known-hosts path from the
selected endpoint profile. With no arguments, it uses the default endpoint.
With `--endpoint`, it saves the token to that endpoint's token file.
The selected endpoint also supplies the SSH URL, signer REST port, and token
destination.

**Examples:**
```
request-token
request-token --endpoint main
request-token --endpoint local-sentry
```

**Note:** An operator using local `apadmin` must approve the request on the server.
After approval, `apshell` saves the new token. It immediately attempts to
connect only when the selected endpoint is the default signer; sentry
enrollment leaves the primary signer connection unchanged.

The positional one-off host form is no longer supported. Import or configure
the endpoint first, then request its token:

```text
endpoints import --alias main --role signer signer.endpoint.json
request-token
```

The same default signer endpoint and endpoint token obtained here can also be used by remote `apadmin`:

```bash
apadmin --remote --client-data ~/aplane/apclient
```

---

### endpoints

Manage client-local signer and sentry endpoint profiles.

```
endpoints list
endpoints show <alias>
endpoints create --alias <alias> --endpoint <url> --sentryport <port> [--dry-run]
endpoints import --alias <alias> --role signer|sentry [--dry-run] <endpoint-json>
endpoints discover-sentries
endpoints default <alias>
endpoints delete <alias>
```

`endpoints import` reads a public `aplane.endpoint.v1` envelope produced by
`apadmin endpoint export`. Import writes local endpoint routing only:
`endpoints.yaml`. Use `role: signer` for the one primary client signer endpoint
and `role: sentry` for sentry endpoints. Import does not copy tokens or SSH
host trust. On the signer side, `apadmin endpoint export` can derive the URL
from `--host`, use explicit `--url`, or use the running daemon's configured
`endpoint.advertise_url`; it reads endpoint defaults through authenticated
admin IPC rather than traversing the private signer store. Without one of
those inputs, export fails instead of guessing a client-reachable address.
Re-importing with the same alias replaces that alias's endpoint data.

`endpoints create` manually writes a `role: sentry` endpoint profile without an
exported endpoint envelope. `--endpoint` is the client-reachable endpoint URL,
usually `ssh://host[:ssh-port]`; `--sentryport` is the sentry node REST port
behind that endpoint. It writes routing only. Tokens are still obtained with
`request-token --endpoint <alias>`, and SSH host trust still uses the known-hosts
flow.

`endpoints discover-sentries` is a read-only diagnostic. It queries configured
sentry endpoints using their endpoint token files, validates the advertised
Witness Key IDs, and prints live results. It does not update `endpoints.yaml`
or the connected signer's generation catalog. Guarded and bounded-sentry
operations perform this discovery automatically for the keys they require.

**Examples:**
```
endpoints import --alias main --role signer signer.endpoint.json
endpoints import --alias local-sentry --role sentry sentry.endpoint.json
endpoints import --alias main --role signer --dry-run signer.endpoint.json
endpoints create --alias local-sentry --endpoint ssh://127.0.0.1:2223 --sentryport 12270
request-token --endpoint main
request-token --endpoint local-sentry
connect main
endpoints discover-sentries
endpoints list
endpoints show main
endpoints default main
endpoints delete old-signer
```

`endpoints delete` refuses to remove the signer endpoint. Sentry routing has no
persisted key inventory to retain.

---

### app

Read application state, deploy applications, and submit application calls.

```
app read info <app-id>
app read global <app-id>
app read local <app-id> <account>
app read box <app-id> <box-name>
app read boxes <app-id>
app deploy from <account> approval=<path>|approval-teal=<path>|approval-bin=<path> clear=<path>|clear-teal=<path>|clear-bin=<path> global-uint=<n> global-bytes=<n> local-uint=<n> local-bytes=<n> [extra-pages=<n>] [note=<text>] [fee=<microalgos>] [nowait] [arg:name=value]
app call <app-id> <method> --abi <path>|abi=<path> from <account> [--arg <value>|arg=<value> ...] [--pay <microalgos>|pay=<microalgos>] [account=<account> ...] [app=<app-id> ...] [asset=<asset> ...] [box=<name>|<app-id>:<name> ...] [oncomp=<noop|optin|closeout|clear|update|delete>] [approval=<path>|approval-teal=<path>|approval-bin=<path>] [clear=<path>|clear-teal=<path>|clear-bin=<path>] [note=<text>] [fee=<microalgos>] [nowait] [arg:name=value]
app call raw <app-id> from <account> [arg-raw=<bytes> ...] [--pay <microalgos>|pay=<microalgos>] [account=<account> ...] [app=<app-id> ...] [asset=<asset> ...] [box=<name>|<app-id>:<name> ...] [oncomp=<noop|optin|closeout|clear|update|delete>] [approval=<path>|approval-teal=<path>|approval-bin=<path>] [clear=<path>|clear-teal=<path>|clear-bin=<path>] [note=<text>] [fee=<microalgos>] [nowait] [arg:name=value]
```

Byte-oriented values such as app boxes, raw app args, and LogicSig `arg:`
values accept the forms listed in [Byte Encodings](#byte-encodings).
Application update calls (`oncomp=update`) require both approval and clear
program paths. Approval and clear program options are rejected for other
on-completion modes.

**Examples:**
```
app read info 123
app deploy from alice approval=approval.teal clear=clear.teal global-uint=2 global-bytes=2 local-uint=1 local-bytes=0
app deploy from lsig-account approval=approval.teal clear=clear.teal global-uint=2 global-bytes=2 local-uint=1 local-bytes=0 arg:preimage=text:secret
app call 123 deposit --abi ./contract.json from alice --pay 100000
app call raw 123 from alice arg-raw=hex:010203 box=text:counter
```

---

### keytypes

List the key types exposed by the connected Signer.

```
keytypes
```

---

### generate

Generate a new key on the connected Signer.

```
generate <key_type> [param=value ...]
```

**Examples:**
```
generate ed25519
generate aplane.falcon1024.v1
generate aplane.ed25519.v1                                      # after activating from the KeyType Library
generate aplane.htlc.v1 hash=SHA256_HEX recipient=ADDR1 refund_address=ADDR2 timeout_round=50000000
generate aplane.falcon1024-allowlist.v1 recipients="@validators"        # address[] params resolve aliases and sets
generate aplane.falcon1024-allowlist.v2 recipients="@operators"            # after installing/enabling from the KeyType Library
```

Run `keytypes` to see available key types and required generation parameters.
Use the full key type shown by `keytypes`.
For installing or activating optional key types, see
[USER_KEYTYPES.md](USER_KEYTYPES.md).

---

### delete

Delete a key from the connected Signer.

```
delete <address>
```

**Example:**
```
delete ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVWXYZ2345
```

---

### write

Toggle transaction write mode. When enabled, transaction JSON files are saved to `txnjson/`.

```
write                           # Show current state
write on                        # Enable write mode
write off                       # Disable write mode
```

When write mode is active, the prompt shows a `w` flag (e.g., `testnet w>`).

---

### verbose

Toggle detailed signing output. When enabled, shows additional details after signing:
- Fee adjustments (total fee delta across the group)
- Passthrough transaction count (pre-signed transactions included as-is)
- Foreign transaction count (transactions not signed by this signer)
- Dummy transaction count (budget transactions added for LogicSig)

```
verbose [on|off]
```

---

### simulate

Toggle transaction simulation mode (dry-run) or simulate a single transaction
command. In simulate mode, apshell requests ordinary executable signatures from
apsigner, including the normal policy and operator approval path, then sends the
exact signed group to the client-configured algod simulation endpoint instead
of submitting it.

Simulation does not submit the group, but it is not a non-signing preview.
Apshell temporarily holds network-submittable signed bytes, and those bytes
remain valid until the transaction validity window expires. Use the JS
`plan()` operation when canonical group inspection without signing or approval
is required.

```
simulate                        # Show current state
simulate on                     # Enable simulate mode
simulate off                    # Disable simulate mode
simulate <transaction-command>  # One-shot: simulate a single transaction command
```

When simulate mode is active, the prompt shows an `s` flag (e.g., `testnet s>`).

If write mode is also enabled, transaction JSON files are saved with a `.sim.json` suffix.

One-shot `simulate <transaction-command>` accepts registered transaction commands such as `send`, `sweep`, `close`, `optin`, `optout`, `keyreg`, `rekey`, `unrekey`, `validate`, `sign`, and `app`.

**Examples:**
```
simulate on
send 5 algo from alice to bob
simulate off

simulate send 5 algo from alice to bob     # One-shot, no toggle needed
simulate keyreg alice offline
simulate validate @signers
```

**Output format:**

Simulate returns structured output for every transaction:

| Section | When shown | Description |
|---------|-----------|-------------|
| Pass/fail | Always | `✓ Simulation successful` or `✗ Simulation FAILED` with round number |
| Reason | On failure | The rejection reason (e.g., overspend, logic eval error) |
| Failed at | On failure | Path to the failing transaction (e.g., `transaction 0 → inner 1`) |
| Transaction IDs | Always | Computed transaction IDs for the group |
| App budget | App calls | Consumed vs. added opcode budget for the group |
| Logs | App calls | Application log entries (printable text or hex) |
| Global state changes | App calls | Global state writes/deletes from the transaction result |
| Local state changes | App calls | Per-account local state writes/deletes |
| Inner transactions | App calls | Summary of inner transactions with type and amounts |
| Exec trace | App calls / LogicSig | Opcode count per program, state changes from the trace |

Example output for a payment that would fail:
```
Simulating transaction...

✗ Simulation FAILED (round 48320125)
  Reason: overspend (account ALICE...WXYZ, tried to spend 10000000 but only has 5000000)
  Failed at: transaction 0

Transaction IDs:
  1. TXID1234...
```

Example output for an app call:
```
Simulating transaction...

✓ Simulation successful (round 48320125)

Transaction IDs:
  1. TXID1234...

App budget: 150 consumed / 700 added

  Txn 1:
    App budget consumed: 150
    Logs (2):
      [0] "counter updated"
      [1] (8 bytes) 0x0000000000000064
    Global state changes:
      set "counter" = 100
    Approval program: 47 opcodes executed
      State changes:
        global write "counter" = 100
```

Execution traces require algod to support the simulate trace endpoint (AVM v9+). If the node does not support traces, the trace sections are omitted and all other sections still display normally.

Guarded simulation follows the same user and sentry component approval flow as
guarded submission. Without user auto-approval, a connected admin client must
approve the request.

---

### config

Display current configuration from `config.yaml`.

```
config
```

---

## Automation Commands

### js

Execute JavaScript code for transaction automation.

```
js <file.js>                    # Run file
js { <code> }                   # Inline code
js                              # Multi-line mode (end with blank line)
js -help                        # Print the JavaScript API reference
```

**Examples:**
```
js scripts/batch-send.js
js { send("alice", "bob", algo(1)) }
js -help
js
  const recipients = ["bob", "charlie"];
  for (const r of recipients) {
    send("alice", r, 1.0);
  }

```

See `docs/USER_JSAPI.md` for the full JavaScript API, or run `js -help` from the shell.

---

### jssave

Save JavaScript code to a file for later execution with `js <file.js>`.

```
jssave [-f] <filename|/absolute/path.js> <javascript code>
jssave [-f] <filename|/absolute/path.js> -last
```

**Examples:**
```
jssave rebalance.js let keys = keys(); print(keys)
jssave -f workflow.js -last
jssave /abs/path/to/exports/workflow.js -last
```

If the target is a single filename with no `/`, it is saved under the data
directory's `scripts/` directory. Otherwise, the path must be absolute, so `/`
must be the first character. Use `-f` to overwrite an existing file. Use
`-last` to save the most recently executed JavaScript code instead of providing
a new code payload.

---

### jslist

List saved JavaScript scripts in the data directory's `scripts/` folder.

```
jslist                          # Human table: filename, size, mtime
```

**Examples:**
```
jslist
```

---

### script

Execute REPL commands from a file (one command per line).

```
script <file>
```

**Examples:**
```
script setup.txt
```

---

## Session Commands

### help

Show help for commands.

```
help              # List all commands
help <command>    # Show command details
```

**Aliases:** `h`

---

### quit

Exit apshell.

```
quit
```

**Aliases:** `exit`, `q`

---

### clear

Clear the terminal screen.

```
clear
```

**Aliases:** `cls`

---

## Shell Commands

In an interactive shell session, execute shell commands by prefixing with `!`:

```
!ls
!pwd
!cat file.txt
```

---

## Special References

### Address References

| Reference | Description |
|-----------|-------------|
| `alice` | Alias (defined via `alias` command) |
| `ABCD1234...` | Full Algorand address |
| `@setname` | Address set (defined via `sets` command) |
| `@all` | All known accounts (aliases + signers) |
| `@signers` | All accounts from connected Signer |

### Asset References

| Reference | Description |
|-----------|-------------|
| `algo` | Native ALGO currency |
| `usdc` | ASA by unit name (from cache) |
| `31566704` | ASA by ID |

### Byte Encodings

Byte-oriented values — LogicSig `arg:` values, raw app args, app box names,
and similar fields — accept these forms:

| Form | Meaning |
|------|---------|
| `hex:<hex>` | Hex-encoded bytes |
| `b64:<base64>` | Base64-encoded bytes |
| `text:<string>` | UTF-8 text bytes |
| `0x<hex>` | Hex-encoded bytes (alternate prefix) |
| bare value | UTF-8 text bytes |

Examples:

```
arg:preimage=hex:abcdef
arg:preimage=b64:q83v
arg:preimage=text:hello
arg:preimage=0xabcdef
box=text:counter
```

---

## Common Options

Many transaction commands support these options:

| Option | Description |
|--------|-------------|
| `fee=<microalgos>` | Override network-suggested fee |
| `nowait` | Submit without waiting for confirmation |
| `note=<text>` | Attach a note to supported transaction commands, such as `send` and `app` |

---

## Configuration File

Create `config.yaml` in your data directory (`$APCLIENT_DATA`):

```yaml
network: testnet

# Optional: restrict allowed networks
networks_allowed:
  - mainnet
  - testnet
```

Create `endpoints.yaml` for signer routing:

```yaml
schema_version: 1
default: primary
endpoints:
  primary:
    role: signer
    url: ssh://192.168.1.100:1127
    signer_port: 11270
    identity_file: .ssh/id_ed25519
    known_hosts_path: .ssh/known_hosts
    token_file: aplane.token
  local-sentry:
    role: sentry
    url: ssh://192.168.1.101:1127
    signer_port: 11270
    identity_file: .ssh/id_ed25519
    known_hosts_path: .ssh/known_hosts
    token_file: tokens/local-sentry.token
```

See `docs/USER_CONFIG.md` for full configuration options.
