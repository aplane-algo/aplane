# Key Type And Template Management

This guide explains how operators manage APlane key types. It focuses on
runtime use, not on writing new provider code or authoring TEAL policies.

For development details, see [DEV_KEYTYPES.md](DEV_KEYTYPES.md). For LogicSig
policy design, see [USER_LOGICSIG_GUIDELINES.md](USER_LOGICSIG_GUIDELINES.md).
For the full architecture-level key/keytype state matrix, see
[ARCH_STORE.md](ARCH_STORE.md#keys-and-key-types).

## Concepts

### Authorization types

APlane separates the account authorization mechanism from additional signing
authorities:

| Account authorization type | Meaning | Examples |
|---|---|---|
| **Native** | Protocol account signature without a LogicSig. | `ed25519`, `falcon1024` |
| **DSA LogicSig** | A LogicSig verifies digital signatures and may add transaction policy. | `aplane.falcon1024.v1`, bounded allowlists, guarded accounts |
| **Generic LogicSig** | TEAL-only account with no DSA private key. | `aplane.htlc.v1` |

DSA LogicSigs may use a **plain** signature-only program, a **bounded1** policy,
an expert-mode **custom** schema-v1 composed policy, or a dedicated compiled
provider policy. Cosigner guarding is an additional authority, not a DSA policy
category. Corridor is a bounded1 template that composes this cosigner authority;
it is not a dedicated compiled policy.

| Auxiliary authority type | Meaning |
|---|---|
| **Cosigner witness key** | A signer-managed, non-account witness used through `/sign/component` and assembled into a guarded transaction. |
| **Contract-admin witness key** | The same witness key form in a standalone `.wit` container, used only for a bounded admin operation. It is not imported into the signer. |

Both roles use `aplane.witness-falcon1024.v1` and the same Witness Key ID
derivation. Custody keeps their capabilities separate: hot signer `.cos`
records use durable category `witness` and can sign only the cosigner component
domain; standalone `.wit` files can sign only the bounded admin domain. Never
reuse one witness keypair across these roles. Local generation rejects known
collisions, but cannot detect a key copied or enrolled out of band.

### Definition and availability

APlane has two optional key type paths:

| Kind | Example | Where definition lives | How to enable |
|---|---|---|---|
| Compiled provider | `aplane.falcon1024-cosigner1024.v1` | Go code in the current binary | `apadmin keytype enable` or apadmin KeyType Library |
| YAML template | `aplane.htlc.v1` | Plaintext library YAML, then encrypted product-local `.template` after import | `apadmin template import` or apadmin KeyType Library |

The protocol-native key types, `ed25519` and `falcon1024`, and the general bounded
key type `aplane.bounded.v1` are default-enabled on signer nodes; they are available
without extra steps.
Plain LogicSig providers `aplane.falcon1024.v1` and `aplane.ed25519.v1` are
internal-only. They support templates and existing accounts, but cannot be
enabled, generated as standalone accounts, or imported from mnemonics.
Other compiled account providers, such as the guarded and rotating types, are
library-visible and require product-local enablement. Existing and restored
keys remain visible and signable whether or not their type permits creation.

YAML templates are different: a library YAML file is only an install source. It
does not become an active key type until it is imported into the product store.
New stores install no templates; import any library template explicitly with
the template-management commands below.

## Operator Mental Model

Normal operator screens answer one primary question: can this product runtime create
new keys of this type right now?

| Display | Meaning |
|---|---|
| Enabled | The signer can discover this key type and generate new keys. |
| Disabled | The key type needs to be enabled, imported, or repaired before new keys can be generated. |
| Template mismatch | An existing key has an informational template-provenance note, such as a missing or changed creation template. The precise reason is shown in details. |

Existing keys remain signable from their stored key metadata. A template mismatch note
does not mean the key has stopped working; it means the original creation
template should be reviewed before relying on provenance or creating more keys
of that type.

The apadmin KeyType Library and `apadmin keytype` CLI use `Enable` and
`Disable` for both compiled providers and installed YAML templates. Internally,
compiled providers write or remove a product enablement record, while YAML
templates keep their encrypted `.template` file installed and toggle the
product state record. Operators do not need separate verbs for those storage
details.

## Useful Commands

Use `-d <path>` or `APSIGNER_DATA` to select the signer data directory:

```bash
apadmin -d $APSIGNER_DATA template list
apadmin -d $APSIGNER_DATA template show example.my_escrow.v1 --show-sensitive-template
apadmin -d $APSIGNER_DATA template import library/templates/aplane.htlc.v1.yaml
apadmin -d $APSIGNER_DATA template remove example.my_escrow.v1
apadmin -d $APSIGNER_DATA keytype enable aplane.falcon1024-cosigner1024.v1
apadmin -d $APSIGNER_DATA keytype disable aplane.falcon1024-cosigner1024.v1
```

In `apadmin`, the KeyType Library presents both library-visible compiled
providers and importable YAML templates. It is the normal interactive path for
enabling and disabling key types for generation. Detail and confirmation
screens use `Enable` and `Disable` consistently for both source types.

In `apshell`, use:

```text
keytypes
generate <key_type> [param=value ...]
```

`keytypes` lists only key types currently exposed by the connected signer.
Use the full canonical key type shown by `keytypes`, for example
`aplane.htlc.v1` or `example.my_escrow.v1`. Files, IPC/HTTP
responses, and JSON fields use the same canonical `publisher.family.vN`
identifier.

### Native Falcon versus Falcon LogicSig

The names intentionally describe different account types:

| Key type | Authorization | Recovery | Network requirement |
|---|---|---|---|
| `falcon1024` | Protocol-native top-level `PQsig` | 25-word Algorand mnemonic | this release supports exactly consensus v42 and v43 |
| `aplane.falcon1024.v1` | TEAL v13 LogicSig containing a Falcon signature | Encrypted key file or managed backup | recognized network using supported consensus v42 or v43 |

There is no conversion between them. A mnemonic or backup entry for one type
cannot be imported as the other. Native Falcon transactions also consume a
higher protocol fee; APlane presents and applies the required fee adjustment
before approval.

Use encrypted backups for every LogicSig account. Mnemonic import, export,
and recovery are reserved for native accounts. The two plain LogicSig
providers are internal-only; old enablement records do not restore mnemonic
import eligibility. See [mnemonic backup and recovery](ARCH_KEYTYPES.md#mnemonic-backup-and-recovery).

All bundled APlane LogicSig types are kept off the Ed25519 curve by the TEAL
v13 assembler's salt rule. Provider-backed types compile through algod and
store the compiler's auto-salted bytecode; the rotating account assembles and
salts each stage program locally with the same rule, storing no bytecode
(see [Rotating Accounts](#rotating-accounts)). This was an in-place
pre-release derivation change: delete and regenerate any earlier development
LogicSig keys rather than expecting their old addresses to remain stable.

## Compiled Providers

Compiled providers are registered from Go code when `apsigner` starts. The
protocol-native `ed25519` and `falcon1024` and the general bounded
`aplane.bounded.v1` are default-enabled on signer nodes;
other selectable compiled account providers are library-visible
and require product-local enablement. On cosigner nodes,
`aplane.witness-falcon1024.v1` is default-enabled for witness credentials.

Enable a library-visible compiled provider:

```bash
apadmin -d $APSIGNER_DATA keytype enable aplane.falcon1024-cosigner1024.v1
```

This enables the guarded Falcon account type. A Corridor account needs no
enabling: it is the Corridor preset of `aplane.bounded.v1`.

Before generating a guarded or bounded-cosigner account, choose **Export
Cosigner Key** on the cosigner. On the primary signer, start **Generate
account** in `apadmin`, select the guarded key type or `aplane.bounded.v1`, then
open the **Cosigner** field and choose **Use key file...** or **Paste public
JSON...**. Compare the complete Witness Key ID with the value
shown on the cosigner and import; the form returns with that key selected. A
key that is already imported is offered under its existing name rather than
imported again. The UI submits the stable Witness Key ID and the signer
resolves it to the full public key; the normal workflow does not ask the
operator to paste Falcon hex.

The **Cosigners** manager (`e` in signer-side `apadmin`) remains available for
managing imported keys directly. Press `i` to import a key file or
`p: Paste JSON` to paste the public document using your terminal's paste
shortcut, review or edit the proposed reference name, and compare the full
Witness Key ID. Multiline JSON is accepted up to 64 KiB, with the same
validation and signer-reference import as file import. Choosing
`Generate account` from an imported key shows only enabled account key types
compatible with that witness type.

The key file contains the public key only; it carries no address. Client
routing, client enrollment, and SSH host trust are separate explicit steps
in apshell, which is given the cosigner's address directly.

The cosigner-side `apadmin` export screen also offers **SHOW JSON**, which prints
the full JSON directly in the terminal for manual copying without creating
a file. Press Enter to return to the export screen. This uses terminal
scrollback and natural wrapping without inserting newlines into JSON values.
File export and the batch stdout command also preserve the original JSON bytes.

In apshell, run `endpoints add <cosigner-url>`, using the address the cosigner
export screen showed. Approve the **Client Access Request**
in cosigner-side apadmin after comparing the complete client SSH key
fingerprint on both screens. If enrollment is pending, rerun setup after
approval. Apshell then confirms the node role and advertised witness metadata.
The client does not compare against the exported key file; the signer embeds
that trust anchor. The
client stores the connection, not the key: another key on the same cosigner
needs no client change.

Connect apshell to the primary signer and run `cosigner status` to inspect the
guarded account's cosigner route. apadmin uses local IPC and never reads or
writes the client endpoint registry or SSH identity.

For scripting, batch import/export, and separate endpoint/enrollment operations,
see [the cosigner command reference](USER_COMMANDS.md#apadmin-cosigner) and
[advanced manual endpoint configuration](USER_COMMANDS.md#advanced-manual-endpoint-configuration-and-discovery).

`aplane.ed25519.v1` is an internal LogicSig base. Native `ed25519` remains
available for ordinary account creation and mnemonic import. The internal base
needs no enablement when used by an enabled composed template.

Enabling writes or updates:

```text
identities/default/generations/<selected-generation>/keytypes/<key_type>.json
```

with:

```json
{
  "key_type": "aplane.falcon1024-cosigner1024.v1",
  "source": "compiled",
  "state": "enabled",
  "fingerprint": "1:<behavior-only sha256 hex>",
  "activated_at": "..."
}
```

Disable a library-visible compiled provider:

```bash
apadmin -d $APSIGNER_DATA keytype disable aplane.falcon1024-cosigner1024.v1
```

Disabling removes the product enablement record after checking that no
existing keys use that key type.

`keytype enable` can also re-enable an already-installed disabled YAML template.
It does not import a new YAML source; use `template import` for that.

## Bounded Accounts

`aplane.bounded.v1` is a Falcon-1024 account limited to a fixed list of recipients, a
time before which it cannot spend, or both. It needs no setup: choose the rules when you
generate the account. The rules are compiled
into the account's program, so they cannot change afterwards, and editing a file later
does nothing to an existing account.

### Choosing rules in apadmin

Generate a key and choose `aplane.bounded.v1`, then a preset:

| Preset | What it sets | You supply |
|---|---|---|
| Allowlist | All transfer kinds; the spending key alone can rekey; automatic list encoding | Recipients |
| Locked Allowlist | All transfer kinds; rekey also needs a contract admin; automatic list encoding | Recipients, admin `.wit.json` file |
| Corridor | All transfer kinds; contract-admin rekey; a cosigner on every spend; Merkle list | Recipients, admin `.wit.json` file, cosigner |
| Timelock | All transfer kinds; the spending key alone can rekey, after the unlock round; no recipient list | Unlock round |
| Load boundary file | Whatever the file says | The file |

"All transfer kinds" means `pay`, `axfer`, and `asset_opt_in`. For a narrower list, such as
ALGO only, use a boundary file.

Before generating, apadmin shows what the signer resolved, including the contract admin
and cosigner it will use. Press `d` for every parameter, fingerprint, and recipient.
After generating, press `s` to save a receipt beside where apadmin was started. A receipt
documents the account. It cannot restore one: use encrypted backups for that.

### Boundary files

```yaml
schema: aplane.boundary.v1
spend: [pay, axfer, asset_opt_in]
recipients:
  - EIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRDOHSEZI
  - CEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEI7JH2AYM
encoding: auto
rekey:
  authority: admin_key
  admin_key: ./bounded-admin/operations.wit.json
cosigner: ops-cosigner
```

These addresses are illustrations, not funding destinations.

| Field | Meaning |
|---|---|
| `schema` | Required. Must be `aplane.boundary.v1`. |
| `spend` | Required. Any of `pay`, `axfer`, `asset_opt_in`. |
| `recipients` | Required unless `unlock_round` is set. 1 to 65,536 distinct nonzero addresses, written literally: aliases and sets are not expanded. |
| `encoding` | Optional, and needs a list. `auto` (the default) is inline through 10 recipients and Merkle above that. `inline` accepts at most 30. |
| `unlock_round` | Optional. The first round the account can spend. With no list, the account can pay anyone once unlocked. |
| `rekey.authority` | Required. `spending_key` or `admin_key`. |
| `rekey.admin_key` | The public `.wit.json` file, relative to the boundary file. Required only with `admin_key`. |
| `cosigner` | Optional. A cosigner reference name on the signer, or a Witness Key ID. A cosigner needs `admin_key`. |

With `unlock_round` and `spending_key`, `spend` must include `pay`.

Unknown fields, duplicate keys, YAML aliases, and non-string values are refused, and the
file has no way to carry TEAL, a template, or a fee.

The list's encoding changes what becomes public. Inline shows the whole list once the
program is published. A Merkle spend reveals its recipient and proof, so it reduces
exposure but does not hide the list. An account can also always pay itself, whatever the
list says, subject to its transfer kinds.

### Creating an account from apshell

```
generate aplane.bounded.v1 boundary=rules.yaml
generate aplane.bounded.v1 boundary=rules.yaml result=account.json
generate aplane.bounded.v1 spend_effects=pay rekey_authority=spending_key recipients=ADDR1,ADDR2
```

apshell shows a local summary and asks before creating the account. The signer has not
seen that summary, so a cosigner name in it is unresolved, and editing that reference
before creation changes which cosigner is used. Prefer a Witness Key ID: it can only
select that cosigner, and apshell checks the created account against it. After creation,
apshell shows what the signer actually stored.

`result=<file>` saves that as JSON. It is not a receipt: only apadmin's review can issue one,
with fingerprints and a digest.

### Restricting new accounts

`aplane.bounded.v1` cannot be turned off, but two settings in apadmin's Settings panel set
a minimum for new accounts. `boundary_require_admin_key` refuses spending-key rekey, and
`boundary_require_cosigner` refuses accounts without a cosigner. They apply on every route,
and they do not affect existing accounts or imported templates.

Review these points before funding an account:

- Spending-key rekey can leave the boundary. With an unlock round, it waits for that round.
- Admin rekey still needs the spending signature, and it bypasses the allowlist, any
  cosigner, and the unlock round. Without that path, a mistaken unlock round could not
  be recovered from early.
- An unlock round means a different time on each network. It does not tie the program to
  one network.
- These rules limit recipients and transfer kinds. They do not limit amounts or spending
  speed. Use signer policy for that.

## Falcon Rekey-Locked Allowlist

`aplane.falcon1024-allowlist-lock.v1` is the framework-owned transaction
authorization account. It requires a Falcon spending signature on every
transaction and a separate external Falcon contract-admin signature for a
pure rekey. Its on-chain policy permits only ALGO payments and ASA transfers,
denies all close/clawback effects, and constrains the destination to the sender
or one of 1-30 compiled recipients.

The program doesn't limit which asset moves or how much. One program is valid
on every network, and an asset ID names an asset on one chain only, so set
asset and amount limits per network in [signer policy](USER_POLICY.md). The
signer injects the `bounded_admin_public_key` creation field; it is not a
second signer-held key.

Generate the external contract-admin key first:

```bash
aprekey generate --out /media/cold/bounded-admin
```

Copy the generated public `<WitnessKeyID>.wit.json` file to the machine running
`apadmin`. When generating `aplane.falcon1024-allowlist-lock.v1`, enter that
file's local path in **Contract Admin Reference File (.wit.json)**, or press
`ctrl+o` in that field to browse for it. `apadmin`
validates the public reference and supplies its `public_key_hex` to the signer;
it never reads the private `.wit` file. Keep the `.wit` artifact outside the
signer. Scripted generation still accepts the `bounded_admin_public_key` hex
parameter. Ordinary spends use the normal client flow. Rekey with the dedicated
helper:

```bash
aprekey rekey --client-data "$APCLIENT_DATA" \
  --key /media/cold/bounded-admin/<ID>.wit \
  <account> to <new-authorizer>
```

`<new-authorizer>` must be a key the same signer holds (a native Ed25519 or
Falcon key, or an existing plain `aplane.falcon1024.v1` or `aplane.ed25519.v1`
LogicSig account, including one restored from an encrypted backup; not a
bounded, guarded, composed or generic template); the signer refuses any other
target before asking for approval. The plain LogicSig types are internal-only
and cannot be generated as new standalone accounts. If you need a new target,
create a native `ed25519` or `falcon1024` account. Leaving APlane custody is two
steps: an admin rekey to a local key, then an ordinary `rekey` from that key.

For an air-gapped ceremony, use `prepare-rekey`, move the resulting
`.apbounded-admin-request` to the ceremony machine, run `aprekey sign`,
and return only the `.apbounded-admin-signature` file to `complete`. Loss of
every artifact copy or its passphrase permanently removes the admin-key rekey
path; ordinary policy-compliant spending can continue.

During offline `sign`, built-in network names are verified against their
canonical genesis hashes. Custom network names are marked as not independently
verified offline because their name-to-hash mapping exists only in the online
client configuration. Confirm the displayed genesis hash as part of a custom
network ceremony; `complete` verifies it against the selected configured
network before submission.

The maximum policy cell has 30 recipients. Its resource
profile is path-specific: v42 group size is driven by argument and opcode
capacity, while any excess program bytes are paid through the group fee. The
signer rejects a finalized path whose fee would exceed the compiled 10,000
microAlgo ceiling.

## Rotating Accounts

The rotating key types are library-visible compiled key types for an account
whose address never changes while the program that authorizes it changes on
every spend. They differ in their hash-based key:
[XMSS](#rotating-triple-xmss-accounts),
[SLH-DSA](#rotating-triple-slh-dsa-accounts) or
[WOTS+C](#rotating-triple-wotsc-accounts). The shared workflow applies to
all of them; their signature, resource, and retry differences are described below.
Each program (a *stage*) checks three signatures over the transaction
ID: Falcon-1024, a SHA-256 hash-based signature, and Ed25519. Their keys are derived
from one seed held only by the signer. A stage's
public keys are revealed only when it signs, and the same spend rekeys the
account to the next, never-revealed stage. All three signatures must verify
over the same transaction ID. The live stage remains authorized until a
rotation confirms.

Enable the key type, then generate an account bound to one network:

```bash
apadmin -d $APSIGNER_DATA keytype enable aplane.rotating-triple-xmss.v1
```

In apadmin, **Generate account** asks for one parameter, `network`, and offers
every network the signer knows: the built-in `mainnet`, `testnet` and
`betanet`, plus any configured under `networks.<name>` with a
`genesis_hash`, such as `localnet`. A raw base64 genesis hash is also accepted.
The form pre-selects the signer's only configured custom network when there
is exactly one, and `testnet` otherwise; it never pre-selects `mainnet`.
A rotating account is bound to one network: its stages
are derived with that network's genesis hash, so the same seed gives different
addresses on different networks. The account address is stage 0's program
address. Fund it like any other account.

Spending works through apshell as usual. `send` and other single-transaction
commands route through the `rotating1` flow automatically: the signer reads
which stage currently controls the account from its own node, prepares the
transaction (setting the rekey to the next stage, adding the resource
dummies and the fees), apshell checks and simulates the exact group before
anything is signed, and the signer signs after approval and a fresh read of
the chain. The key type sets the cost. Every spend carries resource dummies
to make room for its three signatures, and pays one minimum fee per transaction:

| Key type | Signature bytes, at most | Transactions per spend | Minimum fee | Stage program |
|---|---|---|---|---|
| XMSS | 4,179 | 5 | 0.005 ALGO | about 2,700 bytes |
| SLH-DSA | 5,887 | 6 | 0.006 ALGO | about 2,800 bytes |
| WOTS+C | 2,115 | 3 | 0.003 ALGO | about 2,500 bytes |

Restrictions:

- A rotating account's transaction is always sent alone; it cannot be part
  of a larger group. Any single transaction type works: payments, asset
  opt-in, transfer and opt-out, application calls, and key registration.
  Rotating accounts are designed for single-transaction use, including
  payments, asset operations, and compatible application calls. Workflows
  that put more than one user transaction in an atomic group, whether a
  second one from the same account or one from another party, run from an
  ordinary account instead. The resource dummies the signer adds around a
  spend are not user transactions.

  "Single-transaction use" is about how each action is composed, not how
  often the account acts. Every action is one transaction from the account,
  standing alone as the only user transaction in its group, and the account
  can take as many such actions as you like, one after another: opt in to an
  asset today, receive it, send some of it tomorrow, each as its own
  transaction and its own rotation. What it rules out is a single atomic
  outcome that needs two user transactions, such as a payment paired with
  the application call that consumes it, extra application calls added for
  opcode budget, or the account's transaction grouped with another party's
  in a swap or an escrow.
- Every spend rekeys the account to its next stage, so a contract that
  refuses calls carrying a rekey rejects every call from a rotating account.
  apshell simulates before anything is signed, so such a call fails without
  consuming a stage.
- Its validity window is at most 100 rounds, and it cannot close out.
- Ordinary `/plan`, `/sign` and plugin signing paths refuse the account with
  `rotating_signing_required`.
- There is no way to hand the account to another key. To leave the scheme,
  move the funds to another account.
- Rotating accounts do not support mnemonic export or import. Back them up
  with a [managed backup](USER_STORE_MGMT.md#managed-backup-with-apadmin). Native-key
  mnemonic export is a separate workflow.

Related commands:

- `rotate <account>` sends a 0-ALGO payment to itself, which only rotates.
- `rotate status [<account>]` shows the on-chain authorizer, the signer's
  view of the account (live stage, cached stages, any search running or
  stopped), alerts and notes.
- `rotate recover <account> [--stage N]` asks the signer to search for the
  account's live stage when it could not place the authorizer on its own
  (see Backups and restore). It issues no transaction.

Alerts: the signer remembers the latest transaction it signed from each
account until it sees the account move past the stage that signed it. While
unlocked, it checks each rotating account after unlock and then about every
30 seconds, and raises an alert
(daemon log, `/status` warnings, the apadmin status bar and `rotate status`)
when a signed transaction expired while its stage still controls the
account. Answer the alert with `rotate <account>`. The memory is rebuilt at
unlock from the signer's audit log. Preserve that log for both release alerts
and XMSS or WOTS+C leaf-use history: losing the history can cause undetected
leaf reuse after a restart or restore. The seed cannot reconstruct it.

Two transactions signed from the same stage both rotate to the same next
stage. The first to confirm wins; the ledger rejects the second because the
account has already moved. If a send fails to submit and you resend it after
another spend went through, expect that rejection; prepare it again.

Each WOTS+C or XMSS leaf must authenticate only one distinct message. A
stage normally signs one spend, but may sign again before a rotation
confirms: for example, an expired transaction may need a repair spend
(`rotate`), or a failed submission may be rebuilt with a fresh validity
window. Each stage has 64 one-time leaves. With intact history, an identical
retry keeps its leaf and a different transaction takes an unused leaf while
one remains.

If a leaf signs two different messages, its one-time security claim is lost;
Falcon-1024 and Ed25519 remain required until the account rotates. When the
signer knows both releases, it reports reuse as a warning ("stage N has
signed more than one transaction") for as long as that stage controls the
account, even while a release is still in flight. Reuse and expired-release
warnings clear once a chain read shows the account has moved. Missing audit
history can prevent detection, so absence of a warning does not prove that
no leaf was reused.

### Rotating triple XMSS accounts

`aplane.rotating-triple-xmss.v1` uses Falcon-1024 and Ed25519 keys per
stage with RFC 8391 XMSS (`XMSS-SHA2_16_256`) as its hash-based key. One
XMSS tree of 65,536 one-time leaves serves 1,024 consecutive stages, and
each stage signs with its own 64 leaves; the stage program refuses a
signature from any other leaf. What that changes for you:

- **Creating the account takes seconds**, not an instant: the signer builds
  the first tree (about 20 seconds on four cores) before it can show the
  address. The next tree is built in the background once the account passes
  the middle of the current one, so rotations never wait for it in normal
  operation.
- **Fees are higher.** The three signatures total up to 4,179
  bytes, so every spend carries four resource dummies and pays five minimum
  fees, two more than the WOTS+C triple; a stage program is about 2,700
  bytes. The verifier's opcode budget fits the same five transactions
  because the stage accepts only signatures whose hashed message meets a
  checksum cap, which the signer satisfies by choosing the randomizer, a
  step invisible to you and to any RFC 8391 verifier.
- **Retries can use separate leaves.** With intact release history, a stage
  can release up to 64 distinct transactions, each on its own leaf, preserving
  the one-time rule. `rotate status` notes the attempt count ("attempt 2 of
  64"). The 65th distinct transaction reuses a leaf; missing history or
  independent signers sharing a seed can cause earlier reuse. The signer
  warns only about reuse it can detect. A reused leaf loses its one-time
  security claim; Falcon-1024 and Ed25519 remain required until rotation.
- **Standards.** The signature format, verifier and parameter set are RFC
  8391 XMSS. The signer manages leaf indices on a best-effort basis through
  its release memory and audit log, as described above, so it does not meet
  the RFC's requirement that an index never be reused and is not a
  conformant stateful XMSS signer in the sense of RFC 8391 or NIST SP
  800-208. The XMSS half is one of three independent hedges.

Everything else is the same: one network per account, the same restrictions,
`rotate`, `rotate status` and `rotate recover`, the alerts, and the backup
and restore rules below.

### Rotating triple WOTS+C accounts

`aplane.rotating-triple-wotsc.v1` uses a tree of 64 WOTS+C one-time keys alongside
Falcon-1024 and Ed25519, with fresh keys per stage. It's the cheapest rotating type:
3 transactions per spend (2 resource dummies), a minimum group fee of 0.003 ALGO,
and a 628-byte hash signature. Its transaction-type, rekey, close-out and validity
restrictions are the same as XMSS.

WOTS+C isn't a standard. A change to this key type would derive different accounts
from the same seed. It uses 16-byte (128-bit) hash outputs,
compared with XMSS's 32-byte outputs. Output size alone does not establish a
security level or equivalence to SLH-DSA. Falcon-1024 and Ed25519 are still
required for every spend.

With intact release history, each stage can sign 64 different transactions on
different leaves. An identical signing retry keeps its recorded leaf; a rebuilt
transaction takes an unused leaf while one remains. Exhaustion itself does not
cause refusal: the 65th different transaction reuses a leaf and is reported until
the account moves past the stage. A failed transaction doesn't cause reuse by
itself, but missing history or two signers sharing a seed can cause earlier reuse.
History can be lost through backup restore, audit rotation, an audit write failure
followed by restart, or an ordinary audit-restore failure. The signer can't report
reuse it can't see, so don't run two signers for one account.

If a leaf has signed two different transactions, send a rotate-only spend promptly. See
[the specification](KEYTYPE_ROTATING_TRIPLE_HYBRID.md#91-failed-transactions-and-leaf-reuse).

### Rotating triple SLH-DSA accounts

`aplane.rotating-triple-slhdsa.v1` uses SLH-DSA alongside Falcon-1024 and
Ed25519, with fresh keys per stage. Its SLH-DSA parameter set is the
SLH-DSA-SHA2-128s construction with a two-layer hypertree, sized for keys
that each sign a few messages; it is not a FIPS 205 parameter set. Its
transaction-type, rekey, close-out and validity restrictions are the same as
XMSS. It uses 6 transactions per spend (5 resource dummies), with a minimum
group fee of 0.006 ALGO. The SLH signature is 4400 bytes, split over two
arguments. The hypertree height is fixed when the signer is built; a build
with the standard SLH-DSA-SHA2-128s height, which exists for evaluation,
derives different accounts from the same seed and needs 10 transactions.
[The evaluation record](SLHDSA_EVALUATION.md) has the measured lifecycle
costs, the lifetime-use assumptions and the review and qualification work
that remains.

SLH-DSA needs no one-time leaf tracking: retries and restored copies do not
exhaust a leaf range. The signer still reports an expired release while its
stage controls the account, and the usual rotation and recovery commands apply.
Stage derivation computes a fresh SLH root for each address actually probed.
Lookahead is capped at two stages, with at most four address derivations per
account per background pass and per request-time discovery. Increasing
`rotating.stage_horizon` cannot override this ceiling; smaller horizons are
honored.

Recovery uses a sparse cache. A matching backup hint or `rotate recover
<account> --stage N` lets the signer derive that stage and its successor
without rebuilding stages 0 through N-1. Without a useful hint, discovery may
need multiple bounded passes. Until the live stage is proven from the seed
and chain, signing returns `rotating_stage_unproven`; inspect `rotate status`
for progress or supply a stage hint.

Stateless signing does not mean unlimited use of one key. The documented
lifetime envelope aggregates signing across restored copies, retries, failed
or discarded attempts and successor self-tests; there is no persistent
signature counter. Ordinary rotation gives each stage a fresh key.

Enable it through apadmin's KeyType Library, or:

```sh
apadmin -d "$APSIGNER_DATA" keytype enable aplane.rotating-triple-slhdsa.v1
```

Then select it when generating a key and choose the bound network, as for
the other rotating accounts. Restart apsigner with the new binary before
looking for the new library entry.

### Backups and restore

The key file contains the seed and network binding needed to derive the
account's stages. On every signing request, the signer checks the current
authorizer against its own algod. It keeps a non-authoritative, sparse cache
of stage addresses and observations under `identities/default/stages/`.
Loaded entries are verified against the seed; a stage must also match the
chain before it can authorize a spend.

Managed backups can carry a recovery hint, not the full cache or audit log.
A matching hint lets a restored signer prepare the live stage and its successor
directly. If the hint is missing or stale, bounded discovery or an explicit
`rotate recover <account> --stage N` may be needed. Until proof succeeds, signing returns
`rotating_stage_unproven`. Use `rotate status` to inspect progress.

The cache can be removed while the signer is stopped without losing the
credential, but this loses recovery hints and may delay signing. Preserve the
audit log separately if release alerts and XMSS or WOTS+C leaf-use history must
survive recovery. `rotating.stage_horizon` in `config.yaml` (default 4096) requests
lookahead past the live stage, subject to family limits (SLH-DSA: at most two).

The background catch-up is bounded. When the signer sees an authorizer it
cannot place, neither a stage it has already derived nor another key it
holds, it searches on its own for at most `rotating.recovery_max_stages`
candidate stages (default 1024), once per account per unlock, within
`rotating.recovery_timeout` of derivation time. Discovery uses available
observations and probes gaps in the sparse cache; the budget limits work,
not the highest stage number that a hint can name.
When that budget is exhausted, `rotate status` shows a note: the authorizer
is not among the stage addresses the signer has cached, and the last search
stopped with its reason. This is the same situation as any other account
that was rekeyed to an address this signer does not hold, and the signer
treats it the same way: it is information, not an alert, and signing from
the account is refused with an explanation until it is resolved. There are
two ways to resolve it, and the signer recommends neither, because it
cannot tell them apart:

- The account was advanced elsewhere, for example by another signer holding
  the same seed while this one was down, or the restored backup is far
  behind. Run `rotate recover <account>` to search further with a budget of
  your choosing (`--max-stages`, default 4096), or, if you know roughly how
  many spends the account has made, `rotate recover <account> --stage N`:
  stage derivation is random access, so the signer derives stage N directly
  and compares it to the chain, probes a few stages either side
  (`--window`, default 64), and once it matches prepares that stage and its
  successor without deriving the entire earlier history. A wrong hint costs
  time, never a wrong stage: a stage is accepted
  only when its derived address equals the chain's authorizer. The search
  runs in the background; `rotate status` shows its progress, and
  `rotate recover <account> cancel` stops it.
- The account no longer belongs to this key. Confirm that independently,
  then delete the key. A failed search is never that confirmation.

Locking and unlocking the signer grants a fresh automatic allowance. Set
`rotating.recovery_max_stages: 0` to turn the automatic search off; operator
recovery and the search a spend request runs for itself keep working.

## YAML Templates

YAML templates define LogicSig key types. Bundled library sources live under:

```text
library/templates/*.yaml
```

Import a YAML template:

```bash
apadmin -d $APSIGNER_DATA template import library/templates/aplane.htlc.v1.yaml
```

Import encrypts the YAML into the product keystore and enables the key type
for the signer.

New stores install no template. For an allowlist, timelock, or Corridor account,
use a [preset of `aplane.bounded.v1`](#bounded-accounts).

### Retired templates

Five templates have left the default library in favor of those presets:

| Template | Replacement preset |
|---|---|
| `aplane.falcon1024-allowlist.v1` | Allowlist |
| `aplane.falcon1024-allowlist.v2` | Allowlist |
| `aplane.falcon1024-allowlist-lock.v1` | Locked Allowlist |
| `aplane.corridor.v1` | Corridor |
| `aplane.falcon1024-timelock.v1` | Timelock |

Existing accounts are unaffected: an installed template keeps working and stays
in the KeyType Library, where its stored YAML can still be viewed. An upgraded
signer may also keep listing the old library files, because the installer does
not delete them.

The files stay available to repair an account, under
`<APSIGNER_DATA>/library/retired/`:

```bash
apadmin -d $APSIGNER_DATA template import $APSIGNER_DATA/library/retired/aplane.corridor.v1.yaml
```

Re-importing matches an installed copy.

Generated provider-backed LogicSig keys store the final compiler-auto-salted
off-curve bytecode and its derivation marker in the `.key` file (rotating
accounts store none; see [Rotating Accounts](#rotating-accounts)); current
auto-salted records omit
`salt_counter`. Compatible manual-counter records retain the counter. Keys also
store the signing-argument schema
as `signing_args`. That schema is captured from the template/provider
`runtime_args` when the key is created. The installed template is required for
additional key creation and provenance checks, but not for signing an existing
key.

Installed template availability is not a revocation mechanism. A
self-contained LogicSig key signs from its stored bytecode and durable signing
metadata even when its template is not installed.

List installed templates:

```bash
apadmin -d $APSIGNER_DATA template list
```

Show installed template YAML:

```bash
apadmin -d $APSIGNER_DATA template show example.my_escrow.v1 --show-sensitive-template
```

The explicit flag is required because template source can contain sensitive
policy material.

Remove an installed template:

```bash
apadmin -d $APSIGNER_DATA template remove example.my_escrow.v1
```

Removal is allowed only when no product keys use that key type, and it
archives the encrypted template rather than discarding it.

The apadmin KeyType Library can also disable and re-enable installed YAML
templates. Disabling keeps the encrypted `.template` file installed but hides
the key type from discovery and generation. Like removal, disable is rejected
when keys of that type exist.

`apadmin keytype enable <key-type>` and
`apadmin keytype disable <key-type>` use the same enable/disable vocabulary for
installed YAML templates as they do for compiled providers. The implementation
handles the storage difference behind the scenes.

For the full filesystem layout and state-record transitions for disable,
enable, remove, and reload, see
[DEV_KEYTYPES.md](DEV_KEYTYPES.md) (Product Filesystem State).

## Worked Example: HTLC

`aplane.htlc.v1` is the bundled example of a generic LogicSig, and shows both kinds
of input a key type can take: creation parameters, fixed into the address when the
account is generated, and runtime arguments, supplied with each transaction.

An HTLC holds ALGO until one of two things happens. The recipient claims the whole
balance with a secret before a timeout, or the refund address reclaims it after.
It has no private key, so anyone may submit either transaction, but the destination
is fixed.

Install the template and generate an account. Take the SHA-256 of your secret:

```bash
apadmin -d $APSIGNER_DATA template import library/templates/aplane.htlc.v1.yaml
printf %s 'open-sesame' | sha256sum
```

```text
generate aplane.htlc.v1 hash=SHA256_HEX recipient=ADDR1 refund_address=ADDR2 timeout_round=50000000
```

`hash`, `recipient`, `refund_address` and `timeout_round` are creation parameters.
In `apadmin` you can type the phrase instead, and it is hashed for you. Fund the
account like any other, on one network only, because a round number means a
different time on each network:

```text
send 1 algo from alice to HTLC_ADDRESS
```

To claim, pass the secret as the `preimage` runtime argument, which can be up to 64
bytes:

```text
close HTLC_ADDRESS to ADDR1 arg:preimage=text:open-sesame
```

To refund once `timeout_round` has passed, no argument is needed:

```text
close HTLC_ADDRESS to ADDR2
```

Use `close`, not `send`. The program accepts only a payment that closes the account,
because a repeatable partial payment would let anyone burn the balance in fees.

The transaction must also fit its window. A claim must expire before `timeout_round`,
and `apshell` uses a validity window of about 1,000 rounds, so start a claim at least
that long before the timeout, and set timeouts well beyond it. An SDK client can set
a shorter window.

A typed phrase is fine for a demonstration, but it can be guessed, and whoever guesses
it can claim. For real use, generate a random 32-byte secret, and use its hash:

```text
close HTLC_ADDRESS to ADDR1 arg:preimage=0xSECRET_HEX
```

For a swap on one chain, use an atomic group instead. An HTLC is for swaps across
chains, where each side locks funds under the same hash, the side holding the secret
sets the longer timeout, and a Bitcoin HTLC normally requires exactly 32 bytes. See
[USER_LOGICSIG_GUIDELINES.md](USER_LOGICSIG_GUIDELINES.md) for the security review.

## Reload Behavior

On unlock or reload, `apsigner`:

1. Reads product key type state records.
2. Skips disabled installed templates.
3. Decrypts enabled installed YAML templates.
4. Registers their providers before scanning keys.
5. Validates compiled-provider enablement records against the current binary.

The state records are what `apsigner` trusts. A stray encrypted `.template`
file without a matching state record is ignored on purpose.

After successful template or key type changes through `apadmin`,
the daemon reloads the product runtime.

## Warnings And Recovery

### Conflicting compiled key type record

Example:

```text
conflicting compiled key type records ignored on reload: [aplane.ed25519.v1]
```

This means the product has an enabled compiled-provider state record whose
stored fingerprint and the current provider fingerprint are the same fingerprint
version but differ — a genuine provider-definition (behavior) change. The
fingerprint is behavior-only and versioned, so a pure rename of a key type,
family, or base key type does not trigger this, and a different-version stored
fingerprint is treated as benign (re-pinned), not a conflict.

Refresh the enablement record:

```bash
apadmin -d $APSIGNER_DATA keytype enable aplane.falcon1024-cosigner1024.v1
```

This updates the state-record fingerprint. It does not rewrite existing key
files.

### Invalid or externally edited YAML template

Reload rejects templates whose encrypted YAML no longer matches the
same-version fingerprint stored in the state record (a behavior change); a
different-version stored fingerprint is treated as benign, not an external edit.

Recovery is to reinstall through the supported import path:

```bash
apadmin -d $APSIGNER_DATA template import path/to/template.yaml
```

Do not edit installed `.template` files in place.

### State record without template file

Reload reports this as an orphaned installed template. Reinstall the template
through `apadmin template import` or remove the broken state record through the
supported template management flow.

## Compatibility Rules

`key_type` names are compatibility boundaries. Do not redefine an existing key
type in place. Use versioned names such as:

```text
example.my_escrow.v1
example.my_escrow.v2
```

For APlane-defined key types, the standard format is:

```text
publisher.family.vN
```

For example:

```text
falcon1024
aplane.falcon1024.v1
aplane.ed25519.v1
aplane.htlc.v1
```

Use the full canonical key type in command input. On disk, in backups, in
policy files, in IPC/HTTP JSON, in SDK-facing fields, and in UI display, the key
type remains canonical.

Existing key files keep their own stored LogicSig bytecode, derivation metadata
(including a manual salt counter only for compatible manual-counter records),
and signing metadata. Enabling, disabling, importing, or removing a
key type controls subsequent discovery and generation; it does not rewrite
existing key files.
