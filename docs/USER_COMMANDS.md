# apshell Command Reference

Complete command reference for the APlane shell (`apshell`).

---

## Quick Reference

| Category | Commands |
|----------|----------|
| **Transactions** | `send`, `sweep`, `close`, `rotate`, `optin`, `optout`, `keyreg`, `sign`, `validate`, `app` |
| **Information** | `balance`, `holders`, `participation`, `accounts`, `keys`, `status`, `info` |
| **Keys** | `keytypes`, `generate`, `delete` |
| **Aliases & Sets** | `alias`, `sets` |
| **Rekeying** | `rekey list`, `rekey`, `unrekey` |
| **ASA Management** | `asa list`, `asa add`, `asa remove`, `asa clear` |
| **Configuration** | `network`, `connect`, `disconnect`, `enroll`, `endpoints`, `cosigner status`, `write`, `verbose`, `loglevel`, `simulate`, `config` |
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

Each account in a set of senders or receivers gets its own transaction, so a
set that names an account more than once (an alias and its address, or a set
and one of its members listed again) is refused, naming the account, before
anything is sent.

**Options:**
| Option | Description |
|--------|-------------|
| `note=<text>` | Attach a note to the transaction. Written with `=`; the spaced form `note <text>` is not accepted |
| `fee=<microalgos>` | Custom transaction fee |
| `nowait` | Don't wait for confirmation |
| `atomic` | Send as atomic group (with sets) |
| `arg:[<account>:]<name>=<value>` | LogicSig argument: for every transaction the command builds, or, with `<account>:`, for the transactions that account sends. See [LogicSig Arguments](#logicsig-arguments) |

A word a command does not take is refused, on this and every transaction
command, so a mistyped option can't be ignored. A line may end with a
comment: a `#` standing alone, followed by a space, starts one. A word that
begins with `#` is an argument.

**Examples:**
```
send 1.5 algo from alice to bob
send 100 usdc from alice to bob note="Payment for services"
send 1 algo from alice to @friends atomic
send 1 algo from [alice bob charlie] to treasury atomic
send 0.5 algo from lsig-account to bob arg:preimage=hello
send 0.5 algo from lsig-account to bob arg:preimage=hex:abcdef
send 0.5 algo from [hashlock-a hashlock-b] to bob atomic arg:hashlock-a:preimage=text:one arg:hashlock-b:preimage=text:two
```

---

### sweep

Sweep assets from multiple accounts to a single destination.

```
sweep <asset> [from [accounts...]] to <dest> [leaving <amount>] [options]
```

For `algo`, each account sends its balance less the amount to leave, its
transaction's fee, and the fee the signer adds for its authorization, so it is
left with exactly that amount. The fee is the network's suggested fee, or
`fee=`. An account with nothing left to send after those three is skipped.

**Arguments:**
| Argument | Description |
|----------|-------------|
| `<asset>` | `algo` or ASA reference |
| `<accounts>` | Optional: `[addr1 addr2 ...]` or `@setname` (default: all signable) |
| `<dest>` | Destination address or alias |
| `<amount>` | Amount to leave in each source account. Default: for `algo`, each account's own minimum balance, the most an open account can send; for an ASA, nothing. `leaving 0` on `algo` is taken as written and the network refuses it |

**Options:**
| Option | Description |
|--------|-------------|
| `fee=<microalgos>` | Custom transaction fee |
| `nowait` | Don't wait for confirmation |
| `arg:[<account>:]<name>=<value>` | LogicSig argument: for every sweep transaction, or, with `<account>:`, for that source account's only. See [LogicSig Arguments](#logicsig-arguments) |

**Examples:**
```
sweep algo to treasury                              # All signable accounts, each left its minimum balance
sweep usdc from [alice bob charlie] to treasury
sweep algo from @team to main leaving 1             # Leave 1 ALGO in each
sweep usdc from @validators to cold leaving 100
sweep algo from @lsigs to treasury arg:preimage=text:secret
sweep algo from @team to treasury arg:carol:preimage=text:secret   # Only carol's transaction gets it
```

---

### close

Close an account and send all ALGO to a destination.

```
close <account> to <destination> [options]
```

**Restrictions:** Fails if the account is online for consensus, holds any ASAs,
or its minimum balance requirement differs from the base 100,000 microAlgos.
Release outstanding application resources and application size sponsorship
before closing, even if the account has no created or opted-in applications.

**Options:**
| Option | Description |
|--------|-------------|
| `fee=<microalgos>` | Custom transaction fee |
| `nowait` | Don't wait for confirmation |
| `arg:[<account>:]<name>=<value>` | LogicSig argument: for every transaction the command builds, or, with `<account>:`, for the transactions that account sends. See [LogicSig Arguments](#logicsig-arguments) |

**Examples:**
```
close alice to bob
close temp-account to treasury nowait
```

---

### rotate

Rotate a rotating account (`aplane.rotating-triple-xmss.v1`,
`aplane.rotating-triple-slhdsa.v1`, or
`aplane.rotating-triple-wotsc.v1`)
to its next stage, show rotating accounts,
or ask the signer to search for an account's live stage.

```
rotate <account> [nowait]
rotate status [<account>]
rotate recover <account> [--stage N] [--window W] [--max-stages M] [--timeout SECONDS]
rotate recover <account> cancel
```

`rotate <account>` sends a 0-ALGO payment from the account to itself. Like
every spend from a rotating account, it rekeys the account to a fresh stage
that has never revealed its keys. Use it when the signer reports that a
revealed stage still controls an account, for example after a signed
transaction expired without confirming. It needs the usual minimum fee plus
the LogicSig fees for the stage program.

`rotate status` shows each rotating account's current on-chain authorizer,
the signer's own view of it (its live stage and how many stages it has
cached, whether it is locating the stage, preparing its successor, or ready
at the last observation, and any search running
or why the last one stopped), any signer alerts that name it, and notes such
as a release still in flight. With no account it lists every signable
rotating account. The signer refreshes its view about every 30 seconds
while unlocked (longer when chain reads or stage derivation for other
accounts are slow), so an alert can briefly outlive the rotation that
resolved it.

`rotate recover` asks the signer to search for the account's live stage. It
is for the note "authorizer … is not among the N stage addresses this
signer has cached": the signer searched on its own as far as its automatic
allowance goes and stopped. Without options it searches forward from its
last observation, interleaving lower gaps, up to `--max-stages` (default 4096) more stages. With `--stage N`
it derives stage N directly, probes `--window` (default 64) stages either
side of it, and once one matches prepares the successor without rebuilding
the preceding history; a wrong
hint costs time, never a wrong stage. `--timeout` caps the search's
derivation time in seconds (default 300). The command returns at once; the
signer searches in the background, `rotate status` shows the progress, and
`cancel` stops it. No transaction is sent and nothing on chain changes. If
the account was not advanced but handed to another key, the search cannot
succeed; delete the key after confirming that independently.

Ordinary single-transaction commands from a rotating account, such as `send`,
also rotate it. The account must be the only transaction sent, and its
validity window is capped at 100 rounds. If the signer finds the window no
longer current when it signs, for example because approval took long, it
releases no signature, and the command rebuilds the window from the current
round at the full 100 rounds, says so, and asks for approval again; if the
account moved between preparing and signing, it prepares the same
transaction again. It makes at most three attempts. `close` is refused: the stage
program forbids close-out. There is no exit command: to leave the scheme,
move the funds out.

**Examples:**
```
rotate vault
rotate status
rotate status vault
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
| `arg:[<account>:]<name>=<value>` | LogicSig argument: for every transaction the command builds, or, with `<account>:`, for the transactions that account sends. See [LogicSig Arguments](#logicsig-arguments) |

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
| `arg:[<account>:]<name>=<value>` | LogicSig argument: for every transaction the command builds, or, with `<account>:`, for the transactions that account sends. See [LogicSig Arguments](#logicsig-arguments) |

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
| `votefirst=<round>` | First round the participation key is valid for (required for `online`; no default) |
| `votelast=<round>` | Last round the participation key is valid for (required for `online`; no default) |
| `keydilution=<n>` | Key dilution, as reported for the participation key (required for `online`; no default) |
| `eligible=true` | Mark as incentive-eligible, which sets a 2 ALGO fee unless the account is eligible already. Only when going online; refused with `offline`. The value must be `true` or `false` |
| `nowait` | Don't wait for confirmation |
| `arg:[<account>:]<name>=<value>` | LogicSig argument: for every transaction the command builds, or, with `<account>:`, for the transactions that account sends. See [LogicSig Arguments](#logicsig-arguments) |

**Examples:**
```
keyreg alice offline
keyreg alice online votekey=ABC... selkey=DEF... sproofkey=GHI...
keyreg lsig-account offline arg:preimage=text:secret
keyreg alice online votekey=ABC... selkey=DEF... sproofkey=GHI... eligible=true
```

**Incentive fee:** with `eligible=true` the command reads the account's eligibility from algod, and refuses the registration if algod can't answer. After the submission it prints `Incentive eligibility requested: 2 ALGO fee`, or `Already incentive eligible: no incentive fee paid` when the account was eligible already. The read is algod's current view, so two eligible registrations sent before the first confirms each pay the fee.

**Paste Mode:** Running `keyreg` with no arguments enters interactive paste mode for the output of `goal account partkeyinfo`. It asks whether to request incentive eligibility, and the same fee rules apply.

**Tip:** Copy-paste participation keys from `goal account partkeyinfo` output.

---

### sign

Sign and submit transaction(s) from an external file.

```
sign <file> [nowait]
```

**Supported formats:**
- Base64-encoded unsigned transaction msgpack: a single transaction, several written one after another, or a transaction array
- JSON transaction object or JSON transaction array
- JSON object with `txn` array containing base64-encoded msgpack transactions

Several transactions in one file, in any of these formats, are signed and
submitted together as one group.

Only `nowait` may follow the file. The transactions are already built, so a
`fee=`, `note=` or `arg:` word has nothing to apply to, and any other word is
refused.

Every byte of the file has to belong to a transaction. A file with leftover
data, a msgpack transaction that isn't in canonical form, a JSON object that
names the same key twice, a JSON `null`, a transaction with no type, or a
`{"txn": [...]}` file holding any other key is refused, so what is signed is
what the file shows.

A JSON transaction object must state exactly the transaction decoded from
it. Each one is compared, field by field, with the SDK's JSON encoding of
that transaction, and any difference is refused, naming the transaction and
the field: an unknown key, a fixed-size byte field such as `votekey` or
`am` of the wrong length, a number that is not plain digits (`1e3`, `2.0`),
a number written as a string, or bytes written as a list of numbers.
Base64 must be spelled as the SDK spells it: padded, with no line breaks and
no stray bits after the data. Addresses may be base32 or base64, so a file
from [`write`](#write) mode reads back as the same transaction. A field at its zero value (`0`,
`false`, `""`, an empty list or object, a zero address or hash) must be left
out, as the encoding leaves it out: `"amt": ""` and `"fee": 0` are refused.
Inside a list an entry keeps its place, so an empty entry is written as the
SDK writes it (`""`, `0` or `{}`). A JSON file that is not valid UTF-8, or
that holds a `\u` escape for half a surrogate pair (such as `\ud800` alone),
is refused: a decoder would sign other text than the file shows.

Each transaction must be for the network apshell is on: its genesis hash, and
its genesis ID when it has one, must be the active algod's. A file written on
mainnet and signed while apshell is on testnet is refused before the signer
sees it, naming the transaction's zero-based index. Plugin transactions are
checked the same way.

**Examples:**
```
sign transaction.txn
sign group.json nowait
```

---

### validate

Validate signing capability by sending 0 ALGO to self.

```
validate <account|@setname> [arg:[<account>:]<name>=<value>]
```

**Options:**
| Option | Description |
|--------|-------------|
| `arg:[<account>:]<name>=<value>` | LogicSig argument: for every validation transaction, or, with `<account>:`, for that account's only. See [LogicSig Arguments](#logicsig-arguments) |

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
reserved, and a name that is itself an Algorand address (in either case) is
refused. An address always means itself wherever an address is accepted; no
alias can redirect it. An address-named alias left in the cache by an older
version is ignored, with a warning, when the cache loads.

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
rekey <account> to <signer> [arg:[<account>:]<name>=<value>]  # Rekey account
```

The target must sign for itself: the command queries the target on chain and
refuses with `cannot rekey to <target> because it is itself rekeyed to <auth>`
when the target's authority has been moved elsewhere.
Algorand does not follow that chain, so such a rekey would hand the account to
a key the target no longer uses.

A bounded account's program decides which rekeys it takes (see
[Rekey-to lists](USER_KEYTYPES.md#rekey-to-lists)). On a cosigned bounded account,
a rekey to an address on the account's rekey-to list takes the spending key
alone and never asks the cosigner; any other rekey the account allows asks the
cosigner too, whose policy decides the target.

A rekey of any account, its own included, to a generic LogicSig account this
signer holds, such as an `aplane.htlc.v1` account, is refused even though the
signer holds its aplane key: its key type is not a
[valid rekey target](USER_KEYTYPES.md#valid-rekey-targets), because its program
decides what can be signed and anyone who can satisfy it could spend from the
account. The refusal names its reason, `rekey_target_not_valid`, and no policy
setting lifts it, `rekeys: allow_rekeys` and the account's rekey-to list
included. A rekey to a foreign address, one the signer holds no aplane key for,
is decided by the `rekeys` setting as before (see
[USER_POLICY.md](USER_POLICY.md)).

**Options:**
| Option | Description |
|--------|-------------|
| `fee=<microalgos>` | Custom transaction fee |
| `nowait` | Don't wait for confirmation |
| `arg:[<account>:]<name>=<value>` | LogicSig argument, used when the account's current auth address is a LogicSig. See [LogicSig Arguments](#logicsig-arguments) |

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

A rekey back to the account's own address meets the same
`rekey_target_not_valid` refusal as any other rekey: when the signer holds the
account's own aplane key and that key recorded that it is not a valid rekey
target, such as a rotating or `aplane.htlc.v1` account, `unrekey` is refused.
When the signer holds the current authorizer but not the account's own aplane
key, the target is foreign, and the `rekeys` setting decides it.

**Options:**
| Option | Description |
|--------|-------------|
| `fee=<microalgos>` | Custom transaction fee |
| `nowait` | Don't wait for confirmation |
| `arg:[<account>:]<name>=<value>` | LogicSig argument, used when the account's current auth address is a LogicSig. See [LogicSig Arguments](#logicsig-arguments) |

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

The cache is kept per network name. An asset's ID, name, unit name and decimals
never change on a chain, so a cached entry stays right for as long as the
network name means the same chain. Run `asa clear` after a LocalNet reset, or
after pointing a custom network at another chain: the same asset ID can then be
a different asset with other decimals, and an amount typed for it would be
converted with the old ones.

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

**Setup:** Enroll this client's SSH key at the signer with `enroll` after the endpoint has been created or imported.

---

### disconnect

Close the active signer SSH tunnel.

```
disconnect
```

This is useful before connecting to a different endpoint in scripts.

---

### enroll

Ask the Signer to enroll this client's SSH key, over SSH.

```
enroll
enroll --endpoint <alias>
enroll --label <text>
```

The command always uses the client SSH key and known-hosts path from the
selected endpoint profile. With no arguments, it uses the default signer
endpoint. With `--endpoint`, it enrolls the key at that signer or cosigner
endpoint. `--label` is a display name the operator sees next to the key in
apadmin.

**Examples:**
```
enroll
enroll --endpoint main
enroll --label laptop
```

The command returns at once. The node queues the request for its operator and
apshell prints `Enrollment request for client key <fingerprint> is waiting for
the operator at endpoint <alias>`; nothing is stored on the client, and the
shell does not wait. An operator using local `apadmin` (or `apapprover`)
approves or rejects the request whenever convenient: it pops up if they are
connected, is shown again when they log in, and is listed under **Waiting for
approval** on the **Enrolled Clients** screen. They compare the full client
fingerprint printed by apshell with the request before approving. Once
approved, run `connect`; until then the signer refuses the key.

If the key is already enrolled, apshell prints `Client key <fingerprint> is
already enrolled at endpoint <alias>` and, when the endpoint is the default
signer, connects immediately. Enrolling at a cosigner never touches the
primary signer connection. For normal cosigner setup, use
[endpoints add](#endpoints-add), which requests enrollment as part of setup.

A request can also be refused: `enrollment queue is full` means the node
already has 16 keys waiting and the operator must clear some first;
`failed to record enrollment request` means the node could not write its
queue. A request that waits 7 days without an answer lapses; just request
again. Repeating a request before it is answered refreshes the same entry.

The operator can also enroll a key without a request from the client, by
importing its public key file in apadmin (`i` on Enrolled Clients) or with
`apadmin clients import`. `endpoints public-key` prints the client's key in the
form the operator needs, as often as you like, and never creates a key.

The client SSH key must be Ed25519, ECDSA (P-256/384/521), or a
hardware-backed `sk-` Ed25519/ECDSA key. The default generated key is
Ed25519. RSA and DSA keys fail SSH authentication, for `enroll`
and `connect` alike, before any approval prompt.

The positional one-off host form is no longer supported. Import or configure
the endpoint first, then enroll with it:

```text
endpoints import --alias main --role signer signer.endpoint.json
enroll
```

apadmin uses local IPC independently of apshell endpoints and client keys. For
remote administration, log in to the signer host:

```bash
ssh -t user@signer 'apadmin -d /path/to/signer-data'
```

---

### Guided cosigner setup

Creating an account protected by a cosigner takes three actions. The
cosigner's **key file** goes to the signer; each client is given the
cosigner's address:

1. **On the cosigner:** generate a cosigner key and choose **Export Cosigner
   Key**. The file is the key's public reference and nothing else: no
   endpoint or host trust. Use **SHOW JSON** to copy the document
   instead of saving a file. The result screen shows the address clients
   should use, taken from `endpoint.advertise_url` when it is configured.
2. **On the primary signer:** choose a key type that takes a cosigner: a
   plain host, `aplane.falcon1024.v1` (enabled by default, with the Corridor
   preset) or `aplane.ed25519.v1` (enable it first). In apadmin, **Generate
   account**, select that type and a preset (or **No bounds**), open
   **Require a cosigner (Falcon-1024)**, and
   choose **Use key file...** (or **Paste public
   JSON...**). Compare the complete Witness Key ID with the cosigner, then
   import. The account form returns with the cosigner filled in and the other
   parameters kept. A key that is already imported is offered under its
   existing name instead of being imported again.
3. **In apshell:** run `endpoints add <cosigner-url>`. Accept or edit the
   suggested connection name, then approve the **Client Access Request** in
   apadmin on the cosigner after comparing the full client SSH key fingerprint
   with the one apshell shows.

`endpoints add` ends by reporting the connection, how many keys the cosigner
advertises, and the cosigner routes of the accounts on the connected signer.
Run `cosigner status` at any time for the same route view. The client never
handles the cosigner's key: it keeps the list of cosigner connections and
discovers their keys when signing.

Later tasks:

| Task | What to do |
|---|---|
| Another key on a cosigner that is already connected | Generate and export the new key, then choose its file during account creation. No client change is needed |
| Another client machine | Run `endpoints add <cosigner-url>` there |
| Setup was interrupted | Rerun the same command; it resumes |
| The cosigner changed address | `endpoints add <new-url> --alias <existing> --replace` |

The signer reference name and the client connection name are independent.
apadmin stores the public key; apshell configures and checks the connection.
The **Cosigners** manager in apadmin remains available for managing imported
keys directly.

---

### endpoints add

Set up a client connection to a cosigner: write the route, confirm host trust,
obtain access when needed, confirm the node is a cosigner, and report routes.

```text
endpoints add
endpoints add [<cosigner-url>] [--alias <alias>] [--replace] [--dry-run]
```

The URL must be `ssh://host[:port]`. Without
one, an interactive shell prompts for it. For an `ssh://` cosigner the port is
the SSH port; the cosigner's REST port is never given to the client, because
the cosigner's SSH server forwards every channel to its own listener. `--endpoint <url>` is accepted as an
alternative spelling. The command takes no file: the cosigner's key file is
imported on the signer, and giving it to `endpoints add` is refused with that
guidance.

**Connection name.** apshell resolves the destination before asking anything.
If a cosigner connection already exists for that URL it is reused, with no name
prompt and no confirmation:

```text
Already configured as cosigner-example. Checking access...
```

Otherwise the prompt offers a name derived from the endpoint host; press Enter
to accept it. Naming an already configured cosigner differently is refused with
the existing name, because two connections to one cosigner make its keys
ambiguous at signing time.

**The node must be a cosigner.** After access is established, apshell reads the
node role and stops if the endpoint is a signer, or if the role is missing,
unrecognized, or cannot be read. For a signer it prints the signer setup
commands (`endpoints import --role signer`, `enroll`, `connect`).

**Replacing a destination.** Changing the URL of an existing connection
requires interactive replacement consent. The client's enrollment at the old
node is not affected; revoke it there if it is no longer wanted.

**The key is the credential.** Nothing is stored on the client for access:
the node keeps the registry of enrolled keys. `endpoints add`,
`endpoints import`, and `endpoints create` write routing only.

| Situation | Behavior |
|---|---|
| Same URL | The connection is reused with its custom key and known-hosts paths |
| Key not enrolled, `ssh://` | An enrollment request is queued at the cosigner and setup stops with the connection configured; the cosigner's operator approves it later, then rerun setup |
| Key revoked, `ssh://` | Enrollment is requested again the same way |
| Cosigner locked | Configuration is kept; unlock it in apadmin and rerun |
| Cancelled midway | Completed effects are reported and kept for the rerun |

**Results.** Two outcomes are reported separately:

1. *Connection:* reached, authenticated, and reporting the cosigner role, with
   the number of cosigner keys it advertises.
2. *Account routes:* for accounts on the connected signer that require a
   cosigner, how many have exactly one route.

```text
Connection cosigner-example ready; this client's key was enrolled.
2 cosigner key(s) advertised.
Cosigner routes available for 2 of 2 accounts on the connected signer.
```

The command fails only for problems with the connection being added: no access,
a node that is not a cosigner, or a key that this connection and another one
both advertise. Everything else is information, so cosigners can be added one
at a time:

- Accounts that need a different cosigner are listed with their route state.
- A primary signer that is disconnected or locked is reported as "Account
  routes not checked", which is distinct from having no such accounts.
- Another connection that could not be read is named ("Could not read"); routes
  observed through the others still stand, but duplicates there cannot be
  ruled out.
- If the route check stops early, for example on another connection's SSH
  host-key mismatch, the output says "Route check stopped", names that
  connection as a mismatch and the ones never contacted, and makes no route
  claim.

When this run created the connection and it turns out to be a signer or a
duplicate route, apshell offers to remove it. Connections that already existed
are never offered for removal.

`--dry-run` validates the input and reports the proposed route without writing
files, changing host trust, requesting enrollment, or contacting the cosigner.
Script use requires the URL, `--alias` for a new connection, and an already
trusted SSH host. If enrollment is pending, the command returns so the operator
can approve later; rerun setup afterwards.
First-use trust and conflicting replacements require an interactive shell.
`endpoints add` is not available through MCP; the other `endpoints`
subcommands are.

**Examples:**

```text
endpoints add ssh://cosigner.example:1127
endpoints add ssh://cosigner.example:1127 --alias cosigner-lab
endpoints add ssh://cosigner.example:1127 --alias cosigner-lab --dry-run
```

---

### cosigner add

Former name of [endpoints add](#endpoints-add). It still works, prints a
one-line notice, and forwards its arguments unchanged.

---

### cosigner status

Run `cosigner status` in apshell to inspect current cosigner connections and the
primary signer's cosigned-account requirements. It queries configured endpoints
without changing client configuration, credentials, SSH trust, or cached keys.
Unknown SSH hosts require separate interactive setup with `endpoints add`.

Connections show authenticated reachability, advertised Witness Key IDs, and
individual errors. Account requirements show available, missing, or duplicate
routes. If the primary signer is disconnected, locked, or inaccessible, its
account requirements are explicitly unavailable; endpoint observations still
appear. An incomplete sweep or host-key mismatch prevents a positive route
conclusion. Duplicate advertisements are also shown without a connected signer.

This is a point-in-time route check. It does not confirm transaction policy,
operator approval, private-key possession, or on-chain validity. It does not
perform signing. The command uses the normal structured command-result output;
like `endpoints add`, it is not exposed through MCP.

---

### endpoints

Manage client-local signer and cosigner endpoint profiles. For guided cosigner
setup use [endpoints add](#endpoints-add); for route checks use `cosigner status`.

#### Advanced: manual endpoint configuration and discovery

```
endpoints list
endpoints show <alias>
endpoints public-key [<alias>]
endpoints add [<cosigner-url>] [--alias <alias>] [--replace] [--dry-run]
endpoints create --alias <alias> --endpoint <url> [--dry-run]
endpoints import --alias <alias> --role signer|cosigner [--dry-run] <endpoint-json>
endpoints discover-cosigners
endpoints default <alias>
endpoints delete <alias>
```

`endpoints import` reads a public `aplane.endpoint.v1` envelope produced by
`apadmin endpoint export`. Import writes local endpoint routing only:
`endpoints.yaml`. Use `role: signer` for the one primary client signer endpoint
and `role: cosigner` for cosigner endpoints. Import does not enroll the
client's key or copy SSH host trust. On the signer side, `apadmin endpoint export` can derive the URL
from `--host`, use explicit `--url`, or use the running daemon's configured
`endpoint.advertise_url`; it reads endpoint defaults through authenticated
admin IPC rather than traversing the private signer store. Without one of
those inputs, export fails instead of guessing a client-reachable address.
Re-importing with the same alias replaces that alias's endpoint data.

`endpoints create` manually writes a `role: cosigner` endpoint profile without an
exported endpoint envelope. `--endpoint` is the client-reachable endpoint URL,
usually `ssh://host[:ssh-port]`. The cosigner's REST port is not part of the
profile: an `ssh://` node forwards every client channel to its own listener.
It writes routing only. The client's key is still enrolled with
`enroll --endpoint <alias>`, and SSH host trust still uses the
known-hosts flow.

`endpoints discover-cosigners` is a read-only diagnostic. It queries configured
cosigner endpoints over SSH with the client's enrolled key, validates the advertised
Witness Key IDs, and prints live results. It does not update `endpoints.yaml`
or the connected signer's generation catalog. Cosigned and bounded-cosigner
operations perform this discovery automatically for the keys they require.

**Examples:**
```
endpoints import --alias main --role signer signer.endpoint.json
endpoints import --alias local-cosigner --role cosigner cosigner.endpoint.json
endpoints import --alias main --role signer --dry-run signer.endpoint.json
endpoints create --alias local-cosigner --endpoint ssh://127.0.0.1:2223
enroll --endpoint main
enroll --endpoint local-cosigner
connect main
endpoints discover-cosigners
endpoints list
endpoints show main
endpoints default main
endpoints delete old-signer
```

`endpoints delete` refuses to remove the signer endpoint. Cosigner routing has no
persisted key inventory to retain. SSH host trust is left as it is, and the
client's enrollment at that node is not revoked; do that from the node's
apadmin if it is no longer wanted.

---

### apadmin clients

Manage enrolled client keys and the enrollment requests waiting for approval:

```text
apadmin clients list
apadmin clients approve <fingerprint> [--label <text>]
apadmin clients reject <fingerprint>
apadmin clients revoke <fingerprint>
apadmin clients import <public-key-file|-> [--label <text>]
```

`list` prints the requests waiting for approval (fingerprint, key type, label,
origin, and time) followed by the enrolled keys; it needs only a read-only
session. The other verbs take an unlocked session. `approve` enrolls the key
of a waiting request, with `--label` replacing the label the client asked for;
`reject` drops a waiting request; `revoke` removes an enrolled key and closes
its connections. `import` pre-enrolls a client's key from a file holding one
OpenSSH public-key line (such as `id_ed25519.pub`); the line's comment is the
label unless `--label` is given. A line carrying authorized_keys options
(`from=`, `restrict`, ...) is refused: the signer implements none, so import
the bare key instead. With `-` the line is read from stdin, which
then requires `APSIGNER_PASSPHRASE` or a controlling terminal for the
passphrase, as with `cosigner import`. Fingerprints are the `SHA256:` form
apshell prints.

---

### apadmin cosigner

Manage public cosigner witness references used by cosigned-account generation:

```text
apadmin cosigner export <witness-key-id> [output-json]
apadmin cosigner import <public-json|-> <name>
apadmin cosigner list
apadmin cosigner show <name>
apadmin cosigner remove <name>
```

Run `export` against the cosigner node. It asks the daemon to verify and return
the canonical `aplane.witness-key-public.v1` document: the key's public
reference and nothing else, with no endpoint, host trust, policy, or
private material. With an output path, the `apadmin` process writes the public
file on the machine where it runs. Without a path, the JSON is written to
stdout. This file is what the interactive **Export Cosigner Key** screen
writes too.

Run `import` against the primary signer and choose a local alias such as
`lab-cosigner`. The signer validates the key type, public key, and derived
Witness Key ID before storing the public reference. Compare the complete
Witness Key ID displayed by the cosigner and signer before accepting it. A
file that carries anything beyond the public key is refused.

When the source is `-`, stdin is reserved for the bounded JSON document:

```bash
cat lab-cosigner.cos.json | \
  APSIGNER_PASSPHRASE="$APSIGNER_PASSPHRASE" \
  apadmin -d "$SIGNER_DATA" cosigner import - lab-cosigner
```

`stdin` import obtains the store passphrase from `APSIGNER_PASSPHRASE` or a
controlling terminal. Headless combinations that cannot keep the document and
passphrase separate fail before authentication.

The interactive signer-side `apadmin` TUI provides the same public-reference
catalog under `e: Cosigners`. It uses aliases for navigation, shows the complete
grouped Witness Key ID on trust screens, and can start generation of a
compatible cosigned or bounded-cosigner account without exposing a raw Falcon
public-key input. The account-generation **Require a cosigner** field also offers **Use
key file...** and **Paste public JSON...**, which import a key in place and
return to the form with it selected; a key that is already imported is offered
under its existing name.

On a cosigner node, open a witness key and choose `e: Export cosigner key`,
then select **SHOW JSON** for full JSON in the terminal: the console
temporarily suspends and prints the complete document without inserting line
breaks into long values. Select the JSON using the terminal's normal copy
controls and scrollback, then press Enter to return to the export screen.
File export and batch stdout also preserve the original JSON bytes. The
result screen names the address to give clients, from `endpoint.advertise_url`
when it is configured.

To import copied JSON, press `p: Paste JSON` in the Cosigner References manager.
Use your terminal's paste shortcut in the JSON field, then Tab to review or
edit the reference name suggested from the file or Witness Key ID. Continue
to review. The field accepts a complete multiline public witness document, up
to 64 KiB. Pasting again replaces the document; Backspace/Delete clears it.
Compare the full Witness Key ID on the shared import review screen before
importing.

#### Batch export and import

```bash
apadmin -d "$COSIGNER_DATA" cosigner export "$WITNESS_KEY_ID" lab-cosigner.cos.json
apadmin -d "$SIGNER_DATA" cosigner import lab-cosigner.cos.json lab-cosigner
```

Then configure and verify the transaction client in apshell with the
cosigner's address:

```text
endpoints add ssh://cosigner.example:1127
```

Approve any **Client Access Request** in apadmin on the cosigner node. Compare the complete client
SSH key fingerprint shown by apshell with the fingerprint in that request.
This identifies the client key, not a unique request; concurrent requests using
the same key have the same fingerprint. The command verifies the node role
and reports which accounts the advertised witnesses route; trust in a witness
comes from the public key imported on the signer. `endpoints discover-cosigners` remains
available as a read-only diagnostic across every configured cosigner route.
apadmin does not configure or verify client routes.

---

### app

Read application state, deploy applications, and submit application calls.

```
app read info <app-id>
app read global <app-id>
app read local <app-id> <account>
app read box <app-id> <box-name>
app read boxes <app-id>
app deploy from <account> approval=<path>|approval-teal=<path>|approval-bin=<path> clear=<path>|clear-teal=<path>|clear-bin=<path> global-uint=<n> global-bytes=<n> local-uint=<n> local-bytes=<n> [extra-pages=<n>] [note=<text>] [fee=<microalgos>] [nowait] [arg:[<account>:]<name>=<value>]
app call <app-id> <method> --abi <path>|abi=<path> from <account> [--arg <value>|arg=<value> ...] [--pay <microalgos>|pay=<microalgos>] [account=<account> ...] [app=<app-id> ...] [asset=<asset> ...] [box=<name>|<app-id>:<name> ...] [oncomp=<noop|optin|closeout|clear|update|delete>] [approval=<path>|approval-teal=<path>|approval-bin=<path>] [clear=<path>|clear-teal=<path>|clear-bin=<path>] [note=<text>] [fee=<microalgos>] [nowait] [arg:[<account>:]<name>=<value>]
app call raw <app-id> from <account> [arg-raw=<bytes> ...] [--pay <microalgos>|pay=<microalgos>] [account=<account> ...] [app=<app-id> ...] [asset=<asset> ...] [box=<name>|<app-id>:<name> ...] [oncomp=<noop|optin|closeout|clear|update|delete>] [approval=<path>|approval-teal=<path>|approval-bin=<path>] [clear=<path>|clear-teal=<path>|clear-bin=<path>] [note=<text>] [fee=<microalgos>] [nowait] [arg:[<account>:]<name>=<value>]
```

Byte-oriented values such as app boxes, raw app args, and LogicSig `arg:`
values accept the forms listed in [Byte Encodings](#byte-encodings). A
`--pay` companion payment is sent by the same account as the call, so the
call's [LogicSig arguments](#logicsig-arguments) reach both.
An ABI argument (`--arg`) for a `uintN`, `byte` or `ufixedNxM` type must be a
plain decimal number, and for `bool` exactly `true` or `false`. `0100`, `0x10`,
`1_000` and `null` are refused: they are not read as octal, hex, a grouped
number or zero.

An ABI argument for an array or tuple type is a JSON array, such as
`[100,"text:alice"]`, and must start with `[`. A `json:` prefix in front of it
is allowed and changes nothing; the same holds for number, `bool` and
`address` arguments. For a `string` argument, `json:` changes the reading:
bare text is sent as typed, and `json:` reads the rest as JSON. The shell
removes double quotes, so put a JSON value in single quotes.

A `byte[]` or `byte[N]` argument at the top level takes only the
[Byte Encodings](#byte-encodings) forms and reads bare text as text. It has no
number-list form: `--arg '[104,105]'` sends the nine characters `[104,105]`,
so write `hex:6869` for those two bytes. A byte array inside an array or tuple
is a list of byte numbers or a string with an encoding prefix: `hex:`, `b64:`,
`text:`, `str:`, `int:`, `addr:` or `0x`. A bare string there is refused,
because other ABI tools read it as base64. Text that holds the replacement
character U+FFFD is refused too, since invalid UTF-8 and a lone surrogate
escape have already become U+FFFD by then; write those bytes with `hex:` or
`b64:`.

The apps you list with `app=` are sent exactly as typed: in that order, with
any repeats, and with the called app if you list it. A program reads them by
position, so the list is never tidied. A box reference to another app
(`box=<app-id>:<name>`) adds that app at the end only when your list doesn't
already have it.

Each entry uses one of the call's reference slots, repeats and the called app
included, so a call near the network's limit can be rejected by the node.
`app=0` is refused.

A box written without an app ID (`box=<name>`) belongs to the called app and
always points at position 0, whether or not you also list the called app.
A box written with an app ID (`box=<app-id>:<name>`) points at that app's
position in your list, the called app's included; write it that way only when
a program expects the box under the listed position.

Application update calls (`oncomp=update`) require both approval and clear
program paths. Approval and clear program options are rejected for other
on-completion modes.

**Examples:**
```
app read info 123
app deploy from alice approval=approval.teal clear=clear.teal global-uint=2 global-bytes=2 local-uint=1 local-bytes=0
app deploy from lsig-account approval=approval.teal clear=clear.teal global-uint=2 global-bytes=2 local-uint=1 local-bytes=0 arg:preimage=text:secret
app call 123 deposit --abi ./contract.json from alice --pay 100000
app call 123 register --abi ./contract.json from alice --arg '[100,"text:alice"]'
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
generate falcon1024
generate aplane.htlc.v1 hash=SHA256_HEX recipient=ADDR1 refund_address=ADDR2 timeout_round=50000000
generate aplane.falcon1024.v1 spend_effects=pay rekey_authority=spending_key recipients="@validators"   # address[] params resolve aliases and sets
generate aplane.falcon1024.v1 --boundary rules.yaml --result account.json
generate aplane.falcon1024.v1 cosigner=<witness-key-id> rekey_authority=spending_key   # a cosigned account without bounds
generate aplane.ed25519.v1 rekey_authority=only_these rekey_to=ADDR1   # enable aplane.ed25519.v1 first
```

Run `keytypes` to see available key types and required generation parameters.
Use the full key type shown by `keytypes`.
For installing or activating optional key types, and for boundary files, see
[USER_KEYTYPES.md](USER_KEYTYPES.md). `--boundary <file>` and `--result <file>` are
apshell's own flags, written `--flag file` or `--flag=file`; every `param=value` goes to
the signer. A flag never takes a `param=value` as its file, so a forgotten file name stops
the command instead of dropping a parameter; write `--flag=file` for a file name with `=`. `--boundary` needs a type whose requests take the boundary grammar, which
today means the plain hosts (`aplane.falcon1024.v1`, `aplane.ed25519.v1`), and sets every
parameter, so it takes no others. Without it, a plain host takes the same bounds and
overlay parameters directly; a file without `spend` asks for an account without bounds.
With `--boundary`, apshell reads the signer's key types first; if it can't, or the type
takes no boundary file, it stops and generates nothing. `--result` saves what the signer
stored, for any key type. Any other `--` argument is refused.

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
- Passthrough transaction count (pre-signed transactions included as-is)
- Foreign transaction count (transactions not signed by this signer)
- Dummy transaction count (budget transactions added for LogicSig)

A fee the signer raised is shown whether or not verbose is on, once the client
has checked it against the signed bytes.

```
verbose [on|off]
```

To see plugin output, use `loglevel info`.

---

### loglevel

Show or set which diagnostics appear, in `apshell` and in the apconsole shell
pane. Results, prompts, and progress always appear; this only filters logs. The
setting lasts until the program exits.

```
loglevel                        # Show the current level
loglevel error                  # Failures only
loglevel warn                   # Also warnings (default)
loglevel info                   # Also routine detail, including plugin output
loglevel debug                  # Also the client's internal detail
```

Plugin output appears at `info`, as `[plugin name stderr]` lines, with a line
when each plugin starts. Plugins start on first use, so set the level before a
plugin's first command to see its startup output.

At `warn`, plugin output stays hidden unless a plugin fails: its last 20 hidden
lines are then shown as warnings above the error. At `info` the lines were
already shown, so they aren't repeated, and if a very fast burst of output
overflows apconsole's queue, some can be lost.

`apshell --mcp` starts at `info`, so plugin output stays in the MCP host's log.
Setting `APSHELL_DEBUG` to any value starts every mode at `debug`.

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

Cosigned simulation follows the same user and cosigner component approval flow as
cosigned submission. Without user auto-approval, a connected admin client must
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
    send("alice", r, algo(1));
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
jssave rebalance.js const addresses = keys(); print(addresses)
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

### LogicSig Arguments

A LogicSig account's program can read values given when a transaction is
signed: a hashlock account, for example, pays only when given the
`preimage` of its stored hash. A command takes them as `arg:` words, in one
of two forms:

| Form | Goes to |
|------|---------|
| `arg:<name>=<value>` | Every transaction the command builds |
| `arg:<account>:<name>=<value>` | Only the transactions sent by `<account>`, an address or an alias |

The value takes any of the [Byte Encodings](#byte-encodings) and may hold
`:` and `=`; the word is split at its first `=`. Before it, no `:` means no
account, and one `:` separates the account from the name. An argument name
may not contain `:`, and a set (`@name`) cannot be the account.

A command with one sending account needs no account in the word. Name the
account when a command sends from several accounts that take different
arguments, or the same name with different values:

```
send 1 algo from [alice dave] to bob atomic arg:alice:preimage=text:x arg:dave:secret=text:y
send 1 algo from [alice dave] to bob atomic arg:alice:preimage=text:x arg:dave:preimage=text:y
sweep algo from @team to treasury arg:carol:preimage=text:x
myplugin swap arg:alice:preimage=hex:abcd
```

The rules:

- A transaction gets the arguments given with no account and those for its
  sender, and no others. The account is the sender, not the key it is
  rekeyed to; the signer finds the key that signs for it.
- An account that is not one of the accounts the command was asked to send
  from is refused before anything is sent. For a set, the set is expanded
  first, and a `sweep` source that is then skipped (nothing to sweep, not
  opted in, or the destination itself) still counts: its line in the sweep's
  results says why nothing was sent from it.
- A name may be given once for each transaction. The same name twice with no
  account, or twice for one account however it is written (an alias and its
  address, or two aliases), is refused, and so is a name given both with no
  account and for an account. No form overrides another.
- apshell does not look up which names a key takes in order to place an
  argument. Before asking the signer it checks each transaction's arguments
  against the names the key that signs for the sender declares, as far as
  the cached key list says (a plugin's `presign-plan` group skips this
  check), and the signer refuses any argument a key does not take. A native
  key (ed25519, native Falcon) takes none, so an argument given with no
  account over a group or set that includes a native account is refused on
  that account's position: name the LogicSig account instead.
- An atomic `send` to or from a set carries arguments like any other send,
  each position getting its own sender's.
- In a plugin command, the arguments go to the plugin's first result only,
  and the accounts are the senders of the transactions it returns. A first
  result that succeeds with no transactions, an argument that reaches a
  transaction the plugin signs itself (a `presign-plan` slot), and any
  argument for a `pregrouped-signed` result are refused before anything is
  shown or sent. A plugin that fails is reported by its own message.
- Two transactions from the same sender in one command get the same
  arguments.

In scripts, `lsigArgs: { name: value }` on `close()` and `sweep()` is the
form with no account: every transaction the call builds. See
[USER_JSAPI.md](USER_JSAPI.md).

### Byte Encodings

Byte-oriented values — LogicSig `arg:` values, raw app args, app box names,
and similar fields — accept these forms:

| Form | Meaning |
|------|---------|
| `hex:<hex>` | Hex-encoded bytes |
| `b64:<base64>` | Base64-encoded bytes |
| `text:<string>` or `str:<string>` | UTF-8 text bytes |
| `int:<number>` | A decimal unsigned 64-bit number, as 8 big-endian bytes |
| `addr:<address>` | An Algorand address, as its 32-byte public key |
| `0x<hex>` | Hex-encoded bytes (alternate prefix) |
| bare value | UTF-8 text bytes |

A bare value that contains a colon, such as `key:value`, is refused, so a
mistyped or unknown prefix can't be sent as text. Write it as
`text:key:value`.

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

`fee=` sets the client base fee. The signer adds its authorization charge on
top and preserves caller-supplied excess, such as fees for inner transactions;
it is not a final-fee cap. See [FEE_HANDLING.md](FEE_HANDLING.md#fee-ownership).

Many transaction commands support these options:

| Option | Description |
|--------|-------------|
| `fee=<microalgos>` | Override the client base fee in microAlgos |
| `nowait` | Submit without waiting for confirmation |
| `note=<text>` | Attach a note to supported transaction commands, such as `send` and `app` |

An option that takes one value may be given once. A second value is refused
with `<option> given more than once` rather than replacing the first, so
`app call ... --pay 100000 ... pay=10000000` and `... from alice ... from treasury`
are errors. This covers `fee=`, `note=`, an `arg:` name given twice with no
account or twice for one account (see
[LogicSig Arguments](#logicsig-arguments)), the
app call options `from`, `--abi`/`abi=`, `--pay`/`pay=` (one option in either
spelling), `oncomp=`, the approval and clear programs in any of their
spellings, `app deploy`'s schema options and `extra-pages=`, sweep's
`leaving`, keyreg's `key=value` options, `generate` parameters, and the value
flags of `rotate recover`, `enroll` and `endpoints add`. Options that build a
list still repeat: `--arg`/`arg=`, `arg-raw=`, `account=`, `app=`, `asset=`,
`box=`, and `arg:` with different names, or one name for different accounts. Flags without a value, such as
`nowait` and `atomic`, may be repeated and mean the same once or twice.

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
schema_version: 2
default: primary
endpoints:
  primary:
    role: signer
    url: ssh://192.168.1.100:1127
    identity_file: .ssh/id_ed25519
    known_hosts_path: .ssh/known_hosts
  local-cosigner:
    role: cosigner
    url: ssh://192.168.1.101:1127
    identity_file: .ssh/id_ed25519
    known_hosts_path: .ssh/known_hosts
```

See `docs/USER_CONFIG.md` for full configuration options.
