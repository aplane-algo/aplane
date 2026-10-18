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
| Compiled provider | `aplane.ed25519.v1` | Go code in the current binary | `apadmin keytype enable` or apadmin KeyType Library |
| YAML template | `aplane.htlc.v1` | Plaintext library YAML, then encrypted product-local `.template` after import | `apadmin template import` or apadmin KeyType Library |

Default-enabled compiled providers, such as `ed25519`, `falcon1024`, and
`aplane.falcon1024.v1`, are available without extra steps on signer nodes.
Library-visible compiled providers are present in the binary but require a
product-local enablement record before the signer can discover or generate
them.

YAML templates are different: a library YAML file is only an install source. It
does not become an active key type until it is imported into the product store.
Signer stores are initialized with `aplane.falcon1024-allowlist.v1` installed
and enabled from the bundled library source. Any missing library template can
be imported explicitly with the template-management commands below.

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
apadmin -d $APSIGNER_DATA template import library/templates/aplane.falcon1024-allowlist.v1.yaml
apadmin -d $APSIGNER_DATA template remove example.my_escrow.v1
apadmin -d $APSIGNER_DATA keytype enable aplane.ed25519.v1
apadmin -d $APSIGNER_DATA keytype disable aplane.ed25519.v1
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
| `falcon1024` | Protocol-native top-level `PQsig` | 25-word Algorand mnemonic | this release supports exactly consensus v42 |
| `aplane.falcon1024.v1` | TEAL v13 LogicSig containing a Falcon signature | 24-word BIP-39 mnemonic | recognized network using the supported consensus v42 |

There is no conversion between them. A mnemonic or backup entry for one type
cannot be imported as the other. Native Falcon transactions also consume a
higher protocol fee; APlane presents and applies the required fee adjustment
before approval.

All bundled APlane LogicSig types are kept off the Ed25519 curve by the TEAL
v13 assembler's salt rule. Provider-backed types compile through algod and
store the compiler's auto-salted bytecode; the rotating account assembles and
salts each stage program locally with the same rule, storing no bytecode
(see [Rotating Accounts](#rotating-accounts)). This was an in-place
pre-release derivation change: delete and regenerate any earlier development
LogicSig keys rather than expecting their old addresses to remain stable.

## Compiled Providers

Compiled providers are registered from Go code when `apsigner` starts. Some are
default-enabled; others are library-visible and require product-local
enablement.

Enable a library-visible compiled provider:

```bash
apadmin -d $APSIGNER_DATA keytype enable aplane.ed25519.v1
```

Another library-visible compiled provider is the guarded account key type
`aplane.falcon1024-cosigner1024.v1`. Corridor is installed through the template
library instead:

```bash
apadmin -d $APSIGNER_DATA template import library/templates/aplane.corridor.v1.yaml
```

Before generating a guarded or bounded-cosigner account, choose **Export
Cosigner Key** on the cosigner. On the primary signer, start **Generate
account** in `apadmin`, open the **Cosigner** field, and choose **Use key
file...** or **Paste public JSON...**. Compare the complete Witness Key ID with the value
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

`aplane.ed25519.v1` is the LogicSig-wrapped Ed25519 provider; native
`ed25519` remains default-enabled and does not need this activation step.
After activation, `aplane.ed25519.v1` also supports mnemonic import.

Enabling writes or updates:

```text
identities/default/generations/<selected-generation>/keytypes/<key_type>.json
```

with:

```json
{
  "key_type": "aplane.ed25519.v1",
  "source": "compiled",
  "state": "enabled",
  "fingerprint": "1:<behavior-only sha256 hex>",
  "activated_at": "..."
}
```

Disable a library-visible compiled provider:

```bash
apadmin -d $APSIGNER_DATA keytype disable aplane.ed25519.v1
```

Disabling removes the product enablement record after checking that no
existing keys use that key type.

`keytype enable` can also re-enable an already-installed disabled YAML template.
It does not import a new YAML source; use `template import` for that.

## Falcon Rekey-Locked Allowlist

`aplane.falcon1024-allowlist-alock.v1` is the framework-owned transaction
authorization account. It requires a Falcon spending signature on every
transaction and a separate external Falcon contract-admin signature for a
pure rekey. Its on-chain policy permits only ALGO payments and ASA transfers,
denies all close/clawback effects, and constrains the destination to the sender
or one of 1-30 compiled recipients.

Optional creation parameters further constrain ASA IDs and per-transaction
ALGO/ASA amounts. Omitting `asset_ids` allows any ASA ID; omitting an amount
limit leaves that type's amount unrestricted. Asset and amount checks still
apply to self-transfers. The signer injects the `bounded_admin_public_key`
creation field; it is not a second signer-held key.

Generate the external contract-admin key first:

```bash
aprekey generate --out /media/cold/bounded-admin
```

Copy the generated public `<WitnessKeyID>.wit.json` file to the machine running
`apadmin`. When generating `aplane.falcon1024-allowlist-alock.v1`, enter that
file's local path in **Contract Admin Reference File (.wit.json)**. `apadmin`
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
Falcon key, or a plain Falcon or Ed25519 LogicSig account); the signer refuses
any other target before asking for approval. Leaving APlane custody is two
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

The maximum policy cell has 30 recipients and 30 asset IDs. Its resource
profile is path-specific: v42 group size is driven by argument and opcode
capacity, while any excess program bytes are paid through the group fee. The
signer rejects a finalized path whose fee would exceed the compiled 10,000
microAlgo ceiling.

## Rotating Accounts

`aplane.rotating-triple-hybrid.v1` is a library-visible compiled key type for
an account whose address never changes while the program that authorizes it
changes on every spend. Each program (a *stage*) checks three signatures
over the transaction ID, a Falcon-1024, a WOTS-w16 (SHA-256) and an Ed25519
signature, all derived from one seed held only by the signer. A stage's
public keys are revealed only when it signs, and the same spend rekeys the
account to the next, never-revealed stage. Forging a spend from a live stage
needs a break of the Falcon lattice assumption, of SHA-256 and of Ed25519 at
once, within the time between that stage's signature and the confirmation
of its spend.

Enable the key type, then generate an account bound to one network:

```bash
apadmin -d $APSIGNER_DATA keytype enable aplane.rotating-triple-hybrid.v1
```

In apadmin, **Generate account** asks for one parameter, `network`, and offers
every network the signer knows: the built-in `mainnet`, `testnet` and
`betanet`, plus any configured under `networks.<name>` with a
`genesis_hash`, such as `localnet`. A raw base64 genesis hash is also accepted.
The form pre-selects the signer's only configured custom network when there
is exactly one, and `testnet` otherwise; it never pre-selects `mainnet`.
Unlike other key types, a rotating account is bound to one network: its stages
are derived with that network's genesis hash, so the same seed gives different
addresses on different networks. The account address is stage 0's program
address. Fund it like any other account.

Spending works through apshell as usual. `send` and other single-transaction
commands route through the `rotating1` flow automatically: the signer reads
which stage currently controls the account from its own node, prepares the
transaction (setting the rekey to the next stage, adding three resource
dummies and the fees), apshell checks and simulates the exact group before
anything is signed, and the signer signs after approval and a fresh read of
the chain. The three signatures total up to 3,631 bytes, so every spend
carries three resource dummies and pays four minimum fees; a stage program is
about 2,100 bytes.

Restrictions:

- A rotating account's transaction is always sent alone; it cannot be part
  of a larger group. Any single transaction type works: payments, asset
  opt-in, transfer and opt-out, application calls, and key registration.
- Its validity window is at most 100 rounds, and it cannot close out.
- Ordinary `/plan`, `/sign` and plugin signing paths refuse the account with
  `rotating_signing_required`.
- There is no way to hand the account to another key. To leave the scheme,
  move the funds to another account.
- Like every APlane key, its mnemonic is never shown. Back it up with a
  managed backup; mnemonic import is refused.

Related commands:

- `rotate <account>` sends a 0-ALGO payment to itself, which only rotates.
- `rotate status [<account>]` shows the on-chain authorizer, signer alerts
  and notes.

Alerts: the signer remembers the latest transaction it signed from each
account until it sees the account move past the stage that signed it. While
unlocked, it checks each rotating account after unlock and then about every
30 seconds, and raises an alert
(daemon log, `/status` warnings, the apadmin status bar and `rotate status`)
when a signed transaction expired while its stage still controls the
account. Answer the alert with `rotate <account>`. The memory is rebuilt at
unlock from the signer's audit log, so keep the audit log if you want
alerts to survive a restart; the account's safety does not depend on it.

Two transactions signed from the same stage both rotate to the same next
stage. The first to confirm wins; the ledger rejects the second because the
account has already moved. If a send fails to submit and you resend it after
another spend went through, expect that rejection; prepare it again.

A WOTS key must never sign two different messages, and the rotation makes
every stage sign once in normal operation. A stage signs twice only when a
release did not move the account and another was signed from the same
stage: a signed transaction expired without confirming and a repair spend
(`rotate`) followed, or a client whose submission failed rebuilt the
transaction with a fresh validity window and asked again. Until one of
those transactions lands, the stage has lost only its WOTS protection and
rests on Falcon-1024 and Ed25519. The signer reports this as a warning
("stage N has signed more than one transaction") for as long as the stage
still controls the account, alongside the expired-release alert; both clear
once a chain read shows the account has moved. The warning rests on the
signer's release memory, which the audit log rebuilds at unlock: a release
the log has rotated past is unknown, so a reuse older than the retained log
is not reported.

### Backups and restore

The key file is the whole credential. The signer stores nothing else it
needs to sign: it reads the account's current stage from the chain at every
request and keeps only a plaintext cache of stage addresses under
`identities/default/stages/`, which it rebuilds from the seed whenever the
cache is missing or damaged. A key restored from a managed backup signs
again as soon as that cache catches up with the account's live stage,
which the signer does in the background; until then a spend is refused with
`rotating_stage_unproven`, and `rotate status` shows how far the scan has
come. Deleting the `stages/` directory while the signer is stopped is
always safe. `rotating.stage_horizon` in the signer's `config.yaml` (default
4096) sets how many stages past the live one the signer derives ahead.

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

Fresh signer stores already include `aplane.falcon1024-allowlist.v1`;
`template import` remains the path for stores that do not have it
and for the other bundled templates such as `aplane.falcon1024-allowlist.v2`.

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
apadmin -d $APSIGNER_DATA keytype enable aplane.ed25519.v1
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
