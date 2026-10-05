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
| **Configuration** | `network`, `connect`, `disconnect`, `request-token`, `endpoints`, `cosigner status`, `write`, `verbose`, `simulate`, `config` |
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
```

**Note:** An operator using local `apadmin` must approve the request on the server.
After approval, `apshell` saves the new token. It immediately attempts to
connect only when the selected endpoint is the default signer; cosigner
access provisioning leaves the primary signer connection unchanged. For normal
cosigner setup, use [endpoints add](#endpoints-add), which obtains access as part of setup.

A token is saved only while the endpoint still names the destination that
issued it. If the endpoint was changed or removed while the request was waiting
for approval, the issued token is discarded and the command says so.

The client SSH key must be Ed25519, ECDSA (P-256/384/521), or a
hardware-backed `sk-` Ed25519/ECDSA key. The default generated key is
Ed25519. RSA and DSA keys fail SSH authentication, for `request-token` and
`connect` alike, before any approval prompt.

The positional one-off host form is no longer supported. Import or configure
the endpoint first, then request its token:

```text
endpoints import --alias main --role signer signer.endpoint.json
request-token
```

apadmin uses local IPC independently of apshell endpoints and tokens. For remote
administration, log in to the signer host:

```bash
ssh -t user@signer 'apadmin -d /path/to/signer-data'
```

---

### Guided cosigner setup

Creating an account protected by a cosigner takes three actions. The same
public **setup file** is used on the signer and on each client:

1. **On the cosigner:** generate a cosigner key and choose **Export Setup
   File**. The export always includes the endpoint; enter the client-reachable
   host if `endpoint.advertise_url` is not configured. Use **SHOW JSON** to copy
   the complete document instead of saving a file.
2. **On the primary signer:** in apadmin, **Generate account**, open the
   **Cosigner** field, and choose **Use setup file...** (or **Paste public
   JSON...**). Compare the complete Witness Key ID with the cosigner, then
   import. The account form returns with the cosigner filled in and the other
   parameters kept. A key that is already imported is offered under its
   existing name instead of being imported again.
3. **In apshell:** run `endpoints add <file>`, or `endpoints add` to paste JSON.
   Accept or edit the suggested connection name, then approve the **Client
   Access Request** in apadmin on the cosigner after comparing the full client
   SSH key fingerprint with the one apshell shows.

`endpoints add` ends by reporting the connection, the key from the file, and
the cosigner routes of the accounts on the connected signer. Run
`cosigner status` at any time for the same route view.

Later tasks:

| Task | What to do |
|---|---|
| Another key on a cosigner that is already connected | Generate and export the new key, then choose its file during account creation. No client change is needed; running `endpoints add` again is harmless |
| Another client machine | Run `endpoints add` with a setup file whose key the cosigner still advertises |
| Setup was interrupted | Rerun the same command; it resumes |
| The cosigner changed address | `endpoints add <new-file> --alias <existing> --replace` |

The signer reference name and the client connection name are independent.
apadmin stores the public key; apshell configures and checks the connection.
The client stores no cosigner keys: it keeps the list of cosigner connections
and discovers their keys when signing. The **Cosigners** manager in apadmin
remains available for managing imported keys directly.

---

### endpoints add

Set up a client connection to a cosigner: write the route, confirm host trust,
obtain access when needed, confirm the node is a cosigner, and report routes.

```text
endpoints add
endpoints add [<public-json>] [--alias <alias>] [--endpoint <url>]
  [--cosigner-port <port>] [--replace] [--dry-run]
```

Accepted input:

| Input | Behavior |
|---|---|
| Setup file (`aplane.cosigner-enrollment.v1`) | The normal case: one public key plus the endpoint |
| Key-only file (`aplane.witness-key-public.v1`) | Has no endpoint; supply `--endpoint` or answer the prompt |
| Endpoint-only file (`aplane.endpoint.v1`) | Sets up the connection; there is no key to compare |
| No file, `--endpoint <url>` | Same as an endpoint-only file |
| No file and no `--endpoint` | Bounded multiline paste prompt; it stops as soon as one complete JSON document has been received |

Explicit options override values bundled in a file. A bundled local tunnel port
is rejected because cosigner SSH connections do not use local listeners.

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
commands (`endpoints import --role signer`, `request-token`, `connect`).

**Replacing a destination.** Changing the URL or the SSH-backed API port of an
existing connection requires interactive replacement consent. The token issued
by the previous destination is removed before the new route is written, so it
is never presented to the new one. The same applies to `endpoints import` and
`endpoints create`. If another connection uses the same token file, the
replacement is refused; give the connection its own `token_file` first.

| Situation | Behavior |
|---|---|
| Same URL and API port | The connection is reused with its custom key, token, and known-hosts paths |
| No token, `ssh://` | Access is requested; compare the full client fingerprint with the Client Access Request before approving |
| Stored token rejected, `ssh://` | Explained, with `request-token --endpoint <alias>` to re-enroll |
| No token, HTTPS or loopback HTTP | Install the endpoint token file and rerun; automatic enrollment requires SSH |
| Cosigner locked | Configuration is kept; unlock it in apadmin and rerun |
| Cancelled midway | Completed effects are reported and kept for the rerun |

A connection that this run created never reuses a token file left over under
the same name; over SSH it requests fresh access.

**Results.** Three outcomes are reported separately:

1. *Connection:* reached, authenticated, and reporting the cosigner role.
2. *Key from the file:* found or not found among the keys the cosigner
   advertises. Endpoint-only input has no key to compare.
3. *Account routes:* for accounts on the connected signer that require a
   cosigner, how many have exactly one route.

```text
Connection cosigner-example ready; access token saved.
Key from the setup file found.
Cosigner routes available for 2 of 2 accounts on the connected signer.
```

The command fails only for problems with the connection being added: no access,
a node that is not a cosigner, a file key the cosigner does not advertise, or a
key that this connection and another one both advertise. Everything else is
information, so cosigners can be added one at a time:

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
files, changing host trust, requesting a token, or contacting the cosigner.
File-based script use requires `--alias` for a new connection and an already
trusted SSH host; it may wait for normal cosigner-side token approval. Paste,
first-use trust, and conflicting replacements require an interactive shell.
`endpoints add` is not available through MCP; the other `endpoints`
subcommands are.

**Examples:**

```text
endpoints add lab-cosigner.aplane-cosigner.json
endpoints add witness.json --alias cosigner-lab --endpoint ssh://cosigner.example:1127 --cosigner-port 11270
endpoints add --endpoint ssh://cosigner.example:1127 --alias cosigner-lab
endpoints add lab-cosigner.aplane-cosigner.json --dry-run
```

---

### cosigner add

Former name of [endpoints add](#endpoints-add). It still works, prints a
one-line notice, and forwards its arguments unchanged.

---

### cosigner status

Run `cosigner status` in apshell to inspect current cosigner connections and the
primary signer's guarded-account requirements. It queries configured endpoints
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
endpoints add [<public-json>] [--alias <alias>] [--endpoint <url>] [--cosigner-port <port>] [--replace] [--dry-run]
endpoints create --alias <alias> --endpoint <url> --cosignerport <port> [--dry-run]
endpoints import --alias <alias> --role signer|cosigner [--dry-run] <endpoint-json>
endpoints discover-cosigners
endpoints default <alias>
endpoints delete <alias>
```

`endpoints import` reads a public `aplane.endpoint.v1` envelope produced by
`apadmin endpoint export`. Import writes local endpoint routing only:
`endpoints.yaml`. Use `role: signer` for the one primary client signer endpoint
and `role: cosigner` for cosigner endpoints. Import does not copy tokens or SSH
host trust. On the signer side, `apadmin endpoint export` can derive the URL
from `--host`, use explicit `--url`, or use the running daemon's configured
`endpoint.advertise_url`; it reads endpoint defaults through authenticated
admin IPC rather than traversing the private signer store. Without one of
those inputs, export fails instead of guessing a client-reachable address.
Re-importing with the same alias replaces that alias's endpoint data. If that
changes the destination (the URL, or the SSH-backed API port), the token issued
by the previous destination is removed, and the output says so.

`endpoints create` manually writes a `role: cosigner` endpoint profile without an
exported endpoint envelope. `--endpoint` is the client-reachable endpoint URL,
usually `ssh://host[:ssh-port]`; `--cosignerport` is the cosigner node REST port
behind that endpoint. It writes routing only. Tokens are still obtained with
`request-token --endpoint <alias>`, and SSH host trust still uses the known-hosts
flow.

`endpoints discover-cosigners` is a read-only diagnostic. It queries configured
cosigner endpoints using their endpoint token files, validates the advertised
Witness Key IDs, and prints live results. It does not update `endpoints.yaml`
or the connected signer's generation catalog. Guarded and bounded-cosigner
operations perform this discovery automatically for the keys they require.

**Examples:**
```
endpoints import --alias main --role signer signer.endpoint.json
endpoints import --alias local-cosigner --role cosigner cosigner.endpoint.json
endpoints import --alias main --role signer --dry-run signer.endpoint.json
endpoints create --alias local-cosigner --endpoint ssh://127.0.0.1:2223 --cosignerport 12270
request-token --endpoint main
request-token --endpoint local-cosigner
connect main
endpoints discover-cosigners
endpoints list
endpoints show main
endpoints default main
endpoints delete old-signer
```

`endpoints delete` refuses to remove the signer endpoint. Cosigner routing has no
persisted key inventory to retain.

---

### apadmin cosigner

Manage public cosigner witness references used by guarded-account generation:

```text
apadmin cosigner export <witness-key-id> [output-json]
apadmin cosigner import <public-json|-> <name>
apadmin cosigner list
apadmin cosigner show <name>
apadmin cosigner remove <name>
```

Run `export` against the cosigner node. It asks the daemon to verify and return
the canonical `aplane.witness-key-public.v1` envelope. With an output path,
the `apadmin` process writes the public file on the machine where it runs. Without a path, the JSON is written to stdout.

Interactive export always produces the setup file: the combined cosigner key
document with its endpoint. Batch export includes the endpoint only when asked;
the command for a complete setup file is
`apadmin cosigner enrollment export <witness-key-id> --include-endpoint --out <file>`. Both import command forms accept standalone and combined
documents.

Run `import` against the primary signer and choose a local alias such as
`lab-cosigner`. The signer validates the key type, public key, and derived
Witness Key ID before storing the public reference. Compare the complete
Witness Key ID displayed by the cosigner and signer before accepting it.

When the source is `-`, stdin is reserved for the bounded JSON envelope:

```bash
cat lab-cosigner.aplane-cosigner.json | \
  APSIGNER_PASSPHRASE="$APSIGNER_PASSPHRASE" \
  apadmin -d "$SIGNER_DATA" cosigner import - lab-cosigner
```

`stdin` import obtains the store passphrase from `APSIGNER_PASSPHRASE` or a
controlling terminal. Headless combinations that cannot keep the document and
passphrase separate fail before authentication.

The interactive signer-side `apadmin` TUI provides the same public-reference
catalog under `e: Cosigners`. It uses aliases for navigation, shows the complete
grouped Witness Key ID on trust screens, and can start generation of a
compatible guarded or bounded-cosigner account without exposing a raw Falcon
public-key input. The account-generation **Cosigner** field also offers **Use
setup file...** and **Paste public JSON...**, which import a key in place and
return to the form with it selected; a key that is already imported is offered
under its existing name. On a cosigner node, **Export Setup File** always includes an
endpoint as public metadata: the configured `endpoint.advertise_url`, or a
required client-reachable host field when none is configured. The screen warns
when that endpoint is remote but SSH still listens only on loopback. A combined bundle
review on the signer imports only the public reference. Any endpoint metadata
is ignored by apadmin; use `endpoints add` in apshell to consume it as
client-owned routing metadata.

On a cosigner node, open a witness key and choose `e: Export setup file`, then
select **SHOW JSON** for full JSON in the terminal: the console temporarily
suspends and prints the complete document without inserting line breaks into
long values. Select the JSON using the terminal's normal copy controls and
scrollback, then press Enter to return to the export screen.
File export and batch stdout also preserve the original JSON bytes.

To import copied JSON, press `p: Paste JSON` in the Cosigner References manager.
Use your terminal's paste shortcut in the JSON field, then Tab to review or
edit the reference name suggested from the file or Witness Key ID. Continue
to review. The field accepts a complete multiline public witness document or
combined cosigner key document, up to 64 KiB. Pasting
again replaces the document; Backspace/Delete clears it. Compare the full
Witness Key ID on the shared import review screen before importing. A bundled
endpoint is informational and does not change client configuration.

#### Advanced: batch export with endpoint metadata

These commands remain available for automation and compatibility:

```text
apadmin cosigner enrollment export <witness-key-id> [--include-endpoint] [--host <host> | --url <url>] [--signer-port <port>] --out <file>
apadmin cosigner enrollment import <file|-> --name <reference-name> [--dry-run]
```

The simple `apadmin cosigner export` emits standalone public-key JSON; both
`apadmin cosigner import` and `apadmin cosigner enrollment import` accept standalone
and combined documents.

The `cosigner enrollment` commands use the combined
`aplane.cosigner-enrollment.v1` handoff. Export always includes the verified
public witness reference. An explicit URL/host includes a portable endpoint;
`--include-endpoint` uses configured `endpoint.advertise_url`. It never
includes a token, host trust, client-local alias, policy, or private witness
material.

Import accepts either a combined cosigner key file or the standalone public
witness file. `--name` chooses the signer-local reference alias. `--dry-run`
validates the complete document and previews the reference import without
changing the signer.

```bash
apadmin -d "$COSIGNER_DATA" cosigner enrollment export "$WITNESS_KEY_ID" \
  --host cosigner.example --out lab-cosigner.aplane-cosigner.json
apadmin -d "$SIGNER_DATA" cosigner enrollment import lab-cosigner.aplane-cosigner.json \
  --name lab-cosigner
```

Then configure and verify the transaction client in apshell:

```text
endpoints add lab-cosigner.aplane-cosigner.json
```

If a batch-exported document omitted an endpoint, add
`--endpoint ssh://cosigner.example:1127 --cosigner-port 11270`. Approve any **Client
Access Request** in apadmin on the cosigner node. Compare the complete client
SSH key fingerprint shown by apshell with the fingerprint in that request.
This identifies the client key, not a unique request; concurrent requests using
the same key have the same fingerprint. The command verifies the
expected witness before it succeeds. `endpoints discover-cosigners` remains
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

Guarded simulation follows the same user and cosigner component approval flow as
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
schema_version: 2
default: primary
endpoints:
  primary:
    role: signer
    url: ssh://192.168.1.100:1127
    signer_port: 11270
    identity_file: .ssh/id_ed25519
    known_hosts_path: .ssh/known_hosts
    token_file: aplane.token
  local-cosigner:
    role: cosigner
    url: ssh://192.168.1.101:1127
    signer_port: 11270
    identity_file: .ssh/id_ed25519
    known_hosts_path: .ssh/known_hosts
    token_file: tokens/local-cosigner.token
```

See `docs/USER_CONFIG.md` for full configuration options.
