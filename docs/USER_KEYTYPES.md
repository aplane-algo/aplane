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
| **Native** | Standard protocol account signature without a LogicSig. | `ed25519` |
| **DSA LogicSig** | A LogicSig verifies digital signatures and may add transaction policy. | `aplane.falcon1024.v1`, bounded allowlists, guarded accounts |
| **Generic LogicSig** | TEAL-only account with no DSA private key. | `aplane.allowlist.v1`, `aplane.htlc.v1` |

DSA LogicSigs may use a **plain** signature-only program, a **bounded1** policy,
an expert-mode **custom** schema-v1 composed policy, or a dedicated compiled
provider policy such as Corridor. Sentry guarding is an additional authority,
not a DSA policy category.

| Auxiliary authority type | Meaning |
|---|---|
| **Sentry component key** | A signer-managed, non-account key used through `/sign/component` and assembled into a guarded transaction. |
| **External contract-admin key** | A normally cold key held in an `.apbounded-admin-key` artifact and used only for a bounded admin operation. It is not imported into the signer. |

Sentry component keys appear in the sentry key-type inventory but cannot be
used as spending accounts. External contract-admin keys do not appear in
`keytypes`, `apstore`, or the signer keystore at all. A contract-admin key is
not a sentry component key, and neither authority can substitute for the other.

### Definition and availability

APlane has two optional key type paths:

| Kind | Example | Where definition lives | How to enable |
|---|---|---|---|
| Compiled provider | `aplane.falcon1024_ed25519.v1` | Go code in the current binary | `apstore keytype enable` or apadmin KeyType Library |
| YAML template | `aplane.allowlist.v1` | Plaintext library YAML, then encrypted identity-local `.template` after import | `apstore template import` or apadmin KeyType Library |

Default-enabled compiled providers, such as `ed25519` and
`aplane.falcon1024.v1`, are available without extra steps.
Library-visible compiled providers are present in the binary but require an
identity-local enablement record before that identity can discover or generate
them.

YAML templates are different: a library YAML file is only an install source. It
does not become an active key type until it is imported into an identity store.
New signer stores are initialized with `aplane.falcon1024-allowlist.v1`
already installed and enabled from the bundled library source. Existing stores
can import that template manually if they were created before this default.

## Operator Mental Model

Normal operator screens answer one primary question: can this identity create
new keys of this type right now?

| Display | Meaning |
|---|---|
| Enabled | The identity can discover this key type and generate new keys. |
| Disabled | The key type needs to be enabled, imported, or repaired before new keys can be generated. |
| Template mismatch | An existing key has an informational template-provenance note, such as a missing or changed creation template. The precise reason is shown in details. |

Existing keys remain signable from their stored key metadata. A template mismatch note
does not mean the key has stopped working; it means the original creation
template should be reviewed before relying on provenance or creating more keys
of that type.

The apadmin KeyType Library and `apstore keytype` CLI use `Enable` and
`Disable` for both compiled providers and installed YAML templates. Internally,
compiled providers write or remove an identity enablement record, while YAML
templates keep their encrypted `.template` file installed and toggle the
identity state record. Operators do not need separate verbs for those storage
details.

## Useful Commands

Use `-d <path>` or `APSIGNER_DATA` to select the signer data directory:

```bash
apstore -d $APSIGNER_DATA template list
apstore -d $APSIGNER_DATA template show example.my_escrow.v1 --show-sensitive-template
apstore -d $APSIGNER_DATA template import library/templates/aplane.allowlist.v1.yaml
apstore -d $APSIGNER_DATA template import library/templates/aplane.ed25519-allowlist.v1.yaml
apstore -d $APSIGNER_DATA template remove example.my_escrow.v1
apstore -d $APSIGNER_DATA keytype enable aplane.falcon1024_ed25519.v1
apstore -d $APSIGNER_DATA keytype disable aplane.falcon1024_ed25519.v1
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
`aplane.timed-allowlist.v1` or `example.my_escrow.v1`. Files, IPC/HTTP
responses, and JSON fields use the same canonical `publisher.family.vN`
identifier.

## Compiled Providers

Compiled providers are registered from Go code when `apsigner` starts. Some are
default-enabled; others are library-visible and require identity-local
enablement.

Enable a library-visible compiled provider:

```bash
apstore -d $APSIGNER_DATA keytype enable aplane.falcon1024_ed25519.v1
apstore -d $APSIGNER_DATA keytype enable aplane.ed25519.v1
```

Other library-visible compiled providers include `aplane.ecdsak1.v1` and the
guarded account key types `aplane.falcon1024-sentry-ed25519.v1`,
`aplane.falcon1024-sentry-falcon1024.v1`, and `aplane.corridor.v1`.
`aplane.ed25519.v1` is the LogicSig-wrapped Ed25519 provider; native
`ed25519` remains default-enabled and does not need this activation step.
After activation, `aplane.ed25519.v1` also supports mnemonic import.

Enabling writes or updates:

```text
identities/<identity>/keytypes/<key_type>.json
```

with:

```json
{
  "key_type": "aplane.falcon1024_ed25519.v1",
  "source": "compiled",
  "state": "enabled",
  "fingerprint": "1:<behavior-only sha256 hex>",
  "activated_at": "..."
}
```

Disable a library-visible compiled provider:

```bash
apstore -d $APSIGNER_DATA keytype disable aplane.falcon1024_ed25519.v1
```

Disabling removes the identity enablement record after checking that no
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
apbounded-admin generate --out /media/cold/bounded-admin
```

Use the generated result's `public_key_hex` as the Contract Admin Public Key
when generating `aplane.falcon1024-allowlist-alock.v1` in apadmin. Keep the
`.apbounded-admin-key` artifact outside the signer. Ordinary spends use the
normal client flow. Rekey with the dedicated helper:

```bash
apbounded-admin rekey --client-data "$APCLIENT_DATA" \
  --key /media/cold/bounded-admin/<ID>.apbounded-admin-key \
  <account> to <new-authorizer>
```

For an air-gapped ceremony, use `prepare-rekey`, move the resulting
`.apbounded-admin-request` to the ceremony machine, run `apbounded-admin sign`,
and return only the `.apbounded-admin-signature` file to `complete`. Loss of
every artifact copy or its passphrase permanently removes the admin-key rekey
path; ordinary policy-compliant spending can continue.

During offline `sign`, built-in network names are verified against their
canonical genesis hashes. Custom network names are marked as not independently
verified offline because their name-to-hash mapping exists only in the online
client configuration. Confirm the displayed genesis hash as part of a custom
network ceremony; `complete` verifies it against the selected configured
network before submission.

The maximum policy cell has 30 recipients and 30 asset IDs. It needs an
eight-transaction LogicSig budget group and remains viable under the compiled
10,000 microAlgo fee ceiling only when the network minimum fee is at most
1,250 microAlgos.

## YAML Templates

YAML templates define LogicSig key types. Bundled library sources live under:

```text
library/templates/*.yaml
```

Import a YAML template:

```bash
apstore -d $APSIGNER_DATA template import library/templates/aplane.allowlist.v1.yaml
```

Import encrypts the YAML into the identity's keystore and enables the key type
for that identity.

Fresh signer identities already include `aplane.falcon1024-allowlist.v1`;
`template import` remains the path for existing identities that do not have it
and for the other bundled templates such as `aplane.ed25519-allowlist.v1`.

Generated LogicSig keys store their salted bytecode and selected off-curve
salt counter in the `.key` file. They also store the signing-argument schema
as `signing_args`. That schema is captured from the template/provider
`runtime_args` when the key is created. The installed template is required for
additional key creation and provenance checks, but not for signing an existing
key.

List installed templates:

```bash
apstore -d $APSIGNER_DATA template list
```

Show installed template YAML:

```bash
apstore -d $APSIGNER_DATA template show example.my_escrow.v1 --show-sensitive-template
```

The explicit flag is required because template source can contain sensitive
policy material.

Remove an installed template:

```bash
apstore -d $APSIGNER_DATA template remove example.my_escrow.v1
```

Removal is allowed only when no identity keys use that key type, and it
archives the encrypted template rather than discarding it.

The apadmin KeyType Library can also disable and re-enable installed YAML
templates. Disabling keeps the encrypted `.template` file installed but hides
the key type from discovery and generation. Like removal, disable is rejected
when keys of that type exist.

`apstore keytype enable <key-type>` and
`apstore keytype disable <key-type>` use the same enable/disable vocabulary for
installed YAML templates as they do for compiled providers. The implementation
handles the storage difference behind the scenes.

For the full filesystem layout and state-record transitions for disable,
enable, remove, and reload, see
[DEV_KEYTYPES.md](DEV_KEYTYPES.md) (Identity Filesystem State).

## Reload Behavior

On unlock or reload, `apsigner`:

1. Reads identity key type state records.
2. Skips disabled installed templates.
3. Decrypts enabled installed YAML templates.
4. Registers their providers before scanning keys.
5. Validates compiled-provider enablement records against the current binary.

The state records are what `apsigner` trusts. A stray encrypted `.template`
file without a matching state record is ignored on purpose.

After successful template or key type changes through `apstore` or `apadmin`,
the daemon reloads the identity runtime.

## Warnings And Recovery

### Conflicting compiled key type record

Example:

```text
conflicting compiled key type records ignored on reload: [aplane.falcon1024_ed25519.v1]
```

This means the identity has an enabled compiled-provider state record whose
stored fingerprint and the current provider fingerprint are the same fingerprint
version but differ — a genuine provider-definition (behavior) change. The
fingerprint is behavior-only and versioned, so a pure rename of a key type,
family, or base key type does not trigger this, and a different-version stored
fingerprint is treated as benign (re-pinned), not a conflict.

Refresh the enablement record:

```bash
apstore -d $APSIGNER_DATA keytype enable aplane.falcon1024_ed25519.v1
```

This updates the state-record fingerprint. It does not rewrite existing key
files.

### Invalid or externally edited YAML template

Reload rejects templates whose encrypted YAML no longer matches the
same-version fingerprint stored in the state record (a behavior change); a
different-version stored fingerprint is treated as benign, not an external edit.

Recovery is to reinstall through the supported import path:

```bash
apstore -d $APSIGNER_DATA template import path/to/template.yaml
```

Do not edit installed `.template` files in place.

### State record without template file

Reload reports this as an orphaned installed template. Reinstall the template
through `apstore template import` or remove the broken state record through the
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
aplane.falcon1024.v1
aplane.ed25519.v1
aplane.allowlist.v1
```

Use the full canonical key type in command input. On disk, in backups, in
policy files, in IPC/HTTP JSON, in SDK-facing fields, and in UI display, the key
type remains canonical.

Existing key files keep their own stored LogicSig bytecode, off-curve salt
counter, and signing metadata. Enabling, disabling, importing, or removing a
key type controls subsequent discovery and generation; it does not rewrite
existing key files.
