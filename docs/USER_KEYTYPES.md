# Key Type And Template Management

This guide explains how operators manage APlane key types. It focuses on
runtime use, not on writing new provider code or authoring TEAL policies.

For development details, see [DEV_KEYTYPES.md](DEV_KEYTYPES.md). For LogicSig
policy design, see [USER_LOGICSIG_GUIDELINES.md](USER_LOGICSIG_GUIDELINES.md).
For the full architecture-level key/keytype state matrix, see
[ARCH_KEY_LIFECYCLE.md](ARCH_KEY_LIFECYCLE.md).

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
provider policy. Sentry guarding is an additional authority, not a DSA policy
category. Corridor is a bounded1 template that composes this sentry authority;
it is not a dedicated compiled policy.

| Auxiliary authority type | Meaning |
|---|---|
| **Sentry witness key** | A signer-managed, non-account witness used through `/sign/component` and assembled into a guarded transaction. |
| **Contract-admin witness key** | The same witness key form in a standalone `.wit` container, used only for a bounded admin operation. It is not imported into the signer. |

Both roles use `aplane.witness-falcon1024.v1` and the same Witness Key ID
derivation. Custody keeps their capabilities separate: hot signer `.sen`
records use durable category `witness` and can sign only the sentry component
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
| `falcon1024` | Protocol-native top-level `PQsig` | 25-word Algorand mnemonic | consensus v42 or an explicitly supported compatible protocol |
| `aplane.falcon1024.v1` | TEAL v13 LogicSig containing a Falcon signature | 24-word BIP-39 mnemonic | recognized consensus-v42-compatible network |

There is no conversion between them. A mnemonic or backup entry for one type
cannot be imported as the other. Native Falcon transactions also consume a
higher protocol fee; APlane presents and applies the required fee adjustment
before approval.

All bundled APlane LogicSig types use TEAL v13 compiler auto-salting. This was
an in-place pre-release derivation change: delete and regenerate any earlier
development LogicSig keys rather than expecting their old addresses to remain
stable.

## Compiled Providers

Compiled providers are registered from Go code when `apsigner` starts. Some are
default-enabled; others are library-visible and require product-local
enablement.

Enable a library-visible compiled provider:

```bash
apadmin -d $APSIGNER_DATA keytype enable aplane.ed25519.v1
```

Another library-visible compiled provider is the guarded account key type
`aplane.falcon1024-sentry1024.v1`. Corridor is installed through the template
library instead:

```bash
apadmin -d $APSIGNER_DATA template import library/templates/aplane.corridor.v1.yaml
```

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

Use the generated result's `public_key_hex` as the Contract Admin Public Key
when generating `aplane.falcon1024-allowlist-alock.v1` in apadmin. Keep the
`.wit` artifact outside the signer. Ordinary spends use the
normal client flow. Rekey with the dedicated helper:

```bash
aprekey rekey --client-data "$APCLIENT_DATA" \
  --key /media/cold/bounded-admin/<ID>.wit \
  <account> to <new-authorizer>
```

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

Generated LogicSig keys store the final compiler-auto-salted off-curve bytecode
and its derivation marker in the `.key` file; current auto-salted records omit
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
[DEV_KEYTYPES.md](DEV_KEYTYPES.md) (Identity Filesystem State).

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
