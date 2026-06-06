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
| **Configuration** | `network`, `connect`, `request-token`, `endpoints`, `write`, `verbose`, `simulate`, `config` |
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

**Examples:**
```
sweep algo to treasury                              # All signable accounts
sweep usdc from [alice bob charlie] to treasury
sweep algo from @team to main leaving 1             # Leave 1 ALGO in each
sweep usdc from @validators to cold leaving 100
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

**Examples:**
```
optin usdc for alice
optin 31566704 for bob
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

**Examples:**
```
optout usdc from alice                    # Must have 0 balance
optout usdc from alice to bob             # Transfer remaining to bob
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

**Examples:**
```
keyreg alice offline
keyreg alice online votekey=ABC... selkey=DEF... sproofkey=GHI...
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
validate <account|@setname>
```

**Examples:**
```
validate alice
validate @signers
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

### rekey

Query rekeying status or rekey an account to a new signing authority.

```
rekey                           # Show rekey command forms
rekey list                      # Show all rekeyed accounts
rekey refresh                   # Rebuild auth cache
rekey refresh <address|alias>   # Refresh one auth-cache entry
rekey <account> to <signer>     # Rekey account
```

**Options:**
| Option | Description |
|--------|-------------|
| `fee=<microalgos>` | Custom transaction fee |
| `nowait` | Don't wait for confirmation |

**Examples:**
```
rekey
rekey list
rekey refresh
rekey alice to bob
rekey alice to multisig-addr fee=2000
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

**Examples:**
```
unrekey alice
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
`$APCLIENT_DATA/endpoints.yaml`. Older single-endpoint clients that do not yet
have `endpoints.yaml` derive the default from the `ssh:` block in
`config.yaml`; interactive `apshell` prompts before converting that legacy
primary signer into `endpoints.yaml`. Passing an endpoint alias connects to
that named profile.

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

### request-token

Request an API token from the Signer over SSH.

```
request-token <host> [--ssh-port <port>]
request-token --endpoint <alias>
request-token
```

The command always uses the client SSH key and known-hosts path from the
selected endpoint profile, or from the legacy `ssh:` config block only when no
endpoint registry exists. With no arguments, it uses the default endpoint. With
`--endpoint`, it saves the token to that endpoint's token file.

**Examples:**
```
request-token
request-token --endpoint attestor-local
request-token 192.168.1.100
request-token 192.168.1.100 --ssh-port 2222
```

**Note:** An operator using local `apadmin` must approve the request on the server.
After approval, `apshell` saves the new token and immediately attempts to connect
to the signer with it.

The same default signer endpoint and endpoint token obtained here can also be used by remote `apadmin`:

```bash
apadmin --remote --client-data ~/aplane/apclient
```

---

### endpoints

Manage client-local signer endpoint profiles.

```
endpoints list
endpoints show <alias>
endpoints attestors
endpoints import-public --alias <alias> --role signer|attestor [--dry-run] <endpoint-json>
endpoints sync-attestors [--dry-run] [--yes]
endpoints default <alias>
endpoints delete <alias>
```

`endpoints import-public` reads a public `aplane.endpoint.v1` envelope produced by
`apstore endpoint export`. Import writes local endpoint routing only:
`endpoints.yaml`. If an older client still relies on `config.yaml` for its
primary signer and imports an attestor endpoint, apshell first writes that
legacy primary signer into `endpoints.yaml` as `primary`. The role is
client-local intent: one endpoint should be `signer`, and attestor nodes should
be imported as `attestor`. It does not copy tokens or SSH host trust, and it
does not discover attestor keys. Re-importing with the same alias replaces that
alias's endpoint data. Importing the same URL under a different alias is
allowed only when the role differs, such as a dev node used both as the client
signer and as a local attestor.

`endpoints sync-attestors` queries `/keys` on configured `attestor` endpoints
using each endpoint's token and rebuilds each reachable endpoint's
`published_attestors` inventory in `endpoints.yaml`. If an endpoint is
temporarily unavailable or its signer identity is locked, its existing
published-attestor entries are preserved. Token/auth failures, endpoint config
errors, malformed responses, duplicate public keys, and invalid component-key
metadata fail without writing. The command then shows the attestor component
IDs it is about to publish to the connected signer identity and asks for
confirmation, unless `--yes` is provided. `--dry-run` inspects the discovered
and skipped endpoints without writing files or updating the signer library.

`endpoints attestors` lists the client-local endpoint-discovered attestor
inventory by endpoint alias, component ID, and key type. It does not call
remote endpoints. Use `endpoints show <alias>` to see `last_seen_at` for an
endpoint's published attestors.

**Examples:**
```
endpoints import-public --alias main --role signer signer.endpoint.json
endpoints import-public --alias attestor-local --role attestor attestor.endpoint.json
endpoints import-public --alias attestor-local --role attestor --dry-run attestor.endpoint.json
request-token --endpoint attestor-local
connect main
endpoints sync-attestors
endpoints sync-attestors --yes
endpoints sync-attestors --dry-run
endpoints attestors
endpoints list
endpoints show attestor-local
endpoints default main
endpoints delete old-attestor
request-token --endpoint attestor-local
```

`endpoints delete` refuses to remove the signer endpoint or an endpoint still
referenced by local attestor mappings.

---

### app

Read application state, deploy applications, and submit application calls.

```
app read info <app-id>
app read global <app-id>
app read local <app-id> <account>
app read box <app-id> <box-name>
app read boxes <app-id>
app deploy from <account> approval=<path>|approval-teal=<path>|approval-bin=<path> clear=<path>|clear-teal=<path>|clear-bin=<path> global-uint=<n> global-bytes=<n> local-uint=<n> local-bytes=<n> [extra-pages=<n>] [note=<text>] [fee=<microalgos>] [nowait]
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
generate falcon1024.v1
generate whitelist.v1 recipients="ADDR1, ADDR2"                  # after installing/enabling from the KeyType Library
generate falcon1024-whitelist.v1 recipients="@validators"        # address[] params resolve aliases and sets
```

Run `keytypes` to see available key types and required generation parameters.
APlane key types may be entered with the default-publisher shorthand shown
above; third-party key types keep their publisher prefix.
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
command. In simulate mode, apshell asks apsigner to canonicalize the group, sign
inside the signer process, and run algod simulation without returning reusable
signed transaction bytes.

Signer-managed simulation runs through apsigner's `/simulate` endpoint:
apsigner signs only inside the signer process, calls algod simulate on the
transaction group's configured network, and returns diagnostics plus final
unsigned transaction data. Reusable signed transaction bytes are not returned to
apshell.

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
```

See `docs/USER_CONFIG.md` for full configuration options.
