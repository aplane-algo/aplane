# apshell Command Reference

Complete command reference for the aPlane shell (`apshell`).

---

## Quick Reference

| Category | Commands |
|----------|----------|
| **Transactions** | `send`, `sweep`, `close`, `optin`, `optout`, `keyreg`, `sign`, `validate` |
| **Information** | `balance`, `holders`, `participation`, `accounts`, `keys`, `status`, `info` |
| **Aliases & Sets** | `alias`, `sets` |
| **Rekeying** | `rekey`, `unrekey` |
| **ASA Management** | `asa list`, `asa add`, `asa remove`, `asa clear` |
| **Configuration** | `network`, `connect`, `write`, `verbose`, `simulate`, `config`, `setenv` |
| **Automation** | `js`, `ai`, `jssave`, `script` |
| **Plugins** | `plugins` |
| **Session** | `help`, `quit` |

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
| `arg:name=<value>` | LogicSig argument (string by default, `0x` prefix for hex bytes). Args apply to all LSig senders in the transaction group. |

**Examples:**
```
send 1.5 algo from alice to bob
send 100 usdc from alice to bob note="Payment for services"
send 1 algo from alice to @friends atomic
send 1 algo from [alice bob charlie] to treasury atomic
send 0.5 algo from lsig-hashlock to bob arg:preimage=hello
send 0.5 algo from lsig-hashlock to bob arg:preimage=0xabc123...
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
| `<amount>` | Amount to leave in each source account |

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
| `arg:name=<value>` | LogicSig argument (string by default, `0x` prefix for hex bytes) |

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
optin 312769 for bob
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

**Tip:** Copy-paste participation keys from `goal account partkeyinfo` output.

---

### sign

Sign and submit transaction(s) from an external file.

```
sign <file> [nowait]
```

**Supported formats:**
- Single unsigned transaction (msgpack or base64)
- Transaction group (msgpack or JSON array)

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
balance <account|@all|@signers|@setname> [asset]
```

**Arguments:**
| Argument | Description |
|----------|-------------|
| `<account>` | Address, alias, `@all`, `@signers`, or `@setname` |
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
participation <address>
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
info 312769
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
alias                           # List all aliases
alias <address> <name>          # Create alias
alias remove <name>             # Remove alias
```

**Examples:**
```
alias
alias ABCD1234... alice
alias remove alice
```

---

### sets

Manage address sets (collections of addresses).

```
sets                                      # List all sets
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
sets validators alice bob charlie
sets add david to validators
sets remove charlie from validators
sets delete validators
send 1 algo from alice to @validators atomic
```

---

## Rekeying Commands

### rekey

Query rekeying status or rekey an account to a new signing authority.

```
rekey                           # Show all rekeyed accounts
rekey refresh                   # Rebuild auth cache
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
asa add 312769
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

---

## Configuration Commands

### network

Switch the active Algorand network.

```
network <mainnet|testnet|betanet>
```

**Note:** May be restricted by `config.yaml` settings.

---

### connect

Connect to a Signer server for transaction signing.

```
connect                                         # Use config.yaml
connect <host>                                  # Default ports
connect <host> --ssh-port <port>               # Custom SSH port
connect <host> --signer-port <port>            # Custom signer port
connect localhost                               # Direct (no SSH tunnel)
```

**Default Ports:**
- SSH: 1127
- Signer REST: 11270

**Examples:**
```
connect
connect 192.168.1.100
connect 192.168.1.100 --ssh-port 1127
connect localhost --signer-port 11270
```

**Setup:** Copy `aplane.token` from `$APSIGNER_DATA/<store>/users/default/` to your `$APCLIENT_DATA` directory.

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

Toggle detailed signing output.

```
verbose [on|off]
```

---

### simulate

Toggle transaction simulation mode (dry-run) or simulate a single command. Transactions are signed via apsignerd as normal but sent to the algod simulate endpoint instead of being submitted to the network.

```
simulate                        # Show current state
simulate on                     # Enable simulate mode
simulate off                    # Disable simulate mode
simulate <command>              # One-shot: simulate a single command
```

When simulate mode is active, the prompt shows an `s` flag (e.g., `testnet s>`).

If write mode is also enabled, transaction JSON files are saved with a `.sim.json` suffix.

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

### setenv

Set an environment variable for the session.

```
setenv <name> <value>
```

**Examples:**
```
setenv ANTHROPIC_API_KEY sk-ant-...
```

---

## Automation Commands

### js

Execute JavaScript code for transaction automation.

```
js <file.js>                    # Run file
js { <code> }                   # Inline code
js                              # Multi-line mode (end with blank line)
```

**Examples:**
```
js scripts/batch-send.js
js { send("alice", "bob", 1.0) }
js
  const recipients = ["bob", "charlie"];
  for (const r of recipients) {
    send("alice", r, 1.0);
  }

```

See `doc/ARCH_AI_SCRIPTING.md` for the full JavaScript API.

---

### ai

Generate and execute JavaScript using AI (requires `ANTHROPIC_API_KEY`).

```
ai <prompt>
```

**Examples:**
```
ai send 5 algo from alice to bob
ai distribute 100 usdc equally from treasury to @team
ai opt all signers into usdc
```

---

### jssave

Save the last executed JavaScript (from `js` or `ai`) to a file.

```
jssave <path>
```

**Examples:**
```
jssave scripts/last-run.js
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

## Shell Commands

Execute shell commands by prefixing with `!`:

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
| `312769` | ASA by ID |

---

## Common Options

Most transaction commands support these options:

| Option | Description |
|--------|-------------|
| `fee=<microalgos>` | Override network-suggested fee |
| `nowait` | Submit without waiting for confirmation |
| `note=<text>` | Attach a note to the transaction |

---

## Configuration File

Create `config.yaml` in your data directory (`$APCLIENT_DATA`):

```yaml
network: testnet
signer_port: 11270

# For remote signer (SSH tunnel)
ssh:
  host: 192.168.1.100
  port: 1127
  identity_file: .ssh/id_ed25519
  known_hosts_path: .ssh/known_hosts

# Optional: restrict allowed networks
networks_allowed:
  - mainnet
  - testnet
```

See `doc/USER_CONFIG.md` for full configuration options.
