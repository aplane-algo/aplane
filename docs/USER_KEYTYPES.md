# Key Type And Template Management

This guide explains how operators manage optional APlane key types. It focuses
on runtime use, not on writing new provider code or authoring TEAL policies.

For development details, see [DEV_KEYTYPES.md](DEV_KEYTYPES.md). For LogicSig
policy design, see [USER_LOGICSIG_GUIDELINES.md](USER_LOGICSIG_GUIDELINES.md).

## Concepts

APlane has two optional key type paths:

| Kind | Example | Where definition lives | How to enable |
|---|---|---|---|
| Compiled provider | `aplane.falcon1024_ed25519.v1` | Go code in the current binary | `apstore keytype activate` or apadmin KeyType Library |
| YAML template | `aplane.whitelist.v1` | Plaintext library YAML, then encrypted identity-local `.template` after import | `apstore template import` or apadmin KeyType Library |

Default-enabled compiled providers, such as `ed25519`,
`aplane.falcon1024.v1`, `aplane.attestor-ed25519.v1`,
`aplane.attestor-falcon1024.v1`, `aplane.falcon1024-att-ed25519.v1`, and
`aplane.falcon1024-att-falcon1024.v1`, are available without extra steps when
the identity mode allows that key class.
Library-visible compiled providers are present in the binary but require an
identity-local activation record before that identity can discover or generate
them.

YAML templates are different: a library YAML file is only an install source. It
does not become an active key type until it is imported into an identity store.

## Operator Mental Model

Normal operator screens answer one primary question: can this identity create
new keys of this type right now?

| Display | Meaning |
|---|---|
| Available to create | The identity can discover this key type and generate new keys. |
| Not available to create | The key type needs to be enabled, activated, imported, or repaired before new keys can be generated. |
| Template provenance | An existing key has an informational template-provenance note, such as a missing or changed creation template. The precise reason is shown in details. |

Existing keys remain signable from their stored key metadata. A template provenance note
does not mean the key has stopped working; it means the original creation
template should be reviewed before relying on provenance or creating more keys
of that type.

The precise terms matter in management and authoring workflows:
`activate`/`deactivate` apply to compiled providers, while
`import`/`enable`/`disable`/`remove` apply to YAML templates. Template authors,
including LLM-assisted authors, should use the canonical vocabulary in
this guide, [DEV_KEYTYPES.md](DEV_KEYTYPES.md), and
[USER_LOGICSIG_GUIDELINES.md](USER_LOGICSIG_GUIDELINES.md).

## Useful Commands

Use `-d <path>` or `APSIGNER_DATA` to select the signer data directory:

```bash
apstore -d $APSIGNER_DATA template list
apstore -d $APSIGNER_DATA template show example.my_escrow.v1 --show-sensitive-template
apstore -d $APSIGNER_DATA template import library/templates/aplane.whitelist.v1.yaml
apstore -d $APSIGNER_DATA template remove example.my_escrow.v1
apstore -d $APSIGNER_DATA keytype activate falcon1024_ed25519.v1
apstore -d $APSIGNER_DATA keytype deactivate falcon1024_ed25519.v1
apstore -d $APSIGNER_DATA key export-att a_<sha256-public-key> attestor-public.json
apstore -d $APSIGNER_DATA attestor import attestor-public.json lab-att
apstore -d $APSIGNER_DATA attestor list
```

In `apadmin`, the KeyType Library presents both library-visible compiled
providers and importable YAML templates. It is the normal interactive path for
making key types available to create. Detail and confirmation screens use
the exact action names, such as enable, disable, and activate, so the management
operation is clear.

In `apshell`, use:

```text
keytypes
generate <key_type> [param=value ...]
```

`keytypes` lists only key types currently exposed by the connected signer.
APlane-published key types may be displayed and entered without the leading
`aplane.` publisher, for example `timed-whitelist.v1`; third-party publishers remain
explicit, for example `example.my_escrow.v1`. Files, IPC/HTTP responses, and
JSON fields still use the canonical `publisher.family.vN` identifier.

## Attestor Public Key Export

Attestor component keys, such as `aplane.attestor-ed25519.v1` and
`aplane.attestor-falcon1024.v1`, are not spending accounts. They are selected
locally by their `a_` component-key selector, but attested account generation
needs the full component public key hex.

Use `apstore key export-att` on the attestor signer host to export a public-only
JSON envelope:

```bash
apstore -d $APSIGNER_DATA key export-att a_<sha256-public-key> attestor-public.json
```

If the output path is omitted, the JSON envelope is written to stdout:

```bash
apstore -d $APSIGNER_DATA key export-att a_<sha256-public-key>
```

The command prompts for the store passphrase, decrypts the local key file only
long enough to read its stored public-key metadata, verifies that the selector
matches `a_ + sha256(public_key)`, and writes:

```json
{
  "schema": "aplane.attestor-public-key.v1",
  "component_key": "a_<sha256-public-key>",
  "key_type": "aplane.attestor-falcon1024.v1",
  "public_key_encoding": "hex",
  "public_key_hex": "<full public key hex>",
  "public_key_size": 1793,
  "public_key_sha256": "<sha256-public-key>"
}
```

`public_key_hex` is the value to pass as `attestor_public_key` when generating
an attested account. `component_key` is the local selector used when asking the
attestor signer to produce component signatures. The envelope is not encrypted
and contains no private key material, endpoint credential, policy, or trust
claim.

To avoid pasting large public keys when creating user-side attested accounts,
import the exported envelope into the user signer's attestor reference library:

```bash
apstore -d $USER_APSIGNER_DATA attestor import attestor-public.json lab-att
apstore -d $USER_APSIGNER_DATA attestor list
apstore -d $USER_APSIGNER_DATA attestor show lab-att
```

Imported references are public-only records under the user identity and are
selected by name during generation:

```text
generate aplane.falcon1024-att-ed25519.v1 attestor=lab-att
generate aplane.falcon1024-att-falcon1024.v1 attestor=lab-att
```

The signer resolves `attestor=<name>` to the imported record's
`public_key_hex`, validates that the selected attestor key type matches the
attested account key type, and stores only the resolved `attestor_public_key`
in the generated key file. Supplying both `attestor=<name>` and
`attestor_public_key=<hex>` is rejected.

## Compiled Providers

Compiled providers are registered from Go code when `apsigner` starts. Some are
default-enabled; others are library-visible and require identity activation.

Activate a library-visible compiled provider:

```bash
apstore -d $APSIGNER_DATA keytype activate falcon1024_ed25519.v1
```

Activation writes or updates:

```text
identities/<identity>/keytypes/<key_type>.json
```

with:

```json
{
  "key_type": "aplane.falcon1024_ed25519.v1",
  "source": "compiled",
  "state": "enabled",
  "fingerprint": "<current provider fingerprint>",
  "activated_at": "..."
}
```

Deactivate a library-visible compiled provider:

```bash
apstore -d $APSIGNER_DATA keytype deactivate falcon1024_ed25519.v1
```

Deactivation removes the identity activation record after checking that no
existing keys use that key type.

`keytype activate` is not for YAML templates. It only applies to
library-visible compiled providers.

## YAML Templates

YAML templates define LogicSig key types. Bundled library sources live under:

```text
library/templates/*.yaml
```

Import a YAML template:

```bash
apstore -d $APSIGNER_DATA template import library/templates/aplane.whitelist.v1.yaml
```

Import encrypts the YAML into the identity's keystore and enables the key type
for that identity.

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

For the full filesystem layout and state-record transitions for disable,
enable, remove, and reload, see
[DEV_KEYTYPES.md](DEV_KEYTYPES.md) (Identity Filesystem State).

## Reload Behavior

On unlock or reload, `apsigner`:

1. Reads identity key type state records.
2. Skips disabled installed templates.
3. Decrypts enabled installed YAML templates.
4. Registers their providers before scanning keys.
5. Validates compiled-provider activation records against the current binary.

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

This means the identity has an enabled compiled-provider state record, but the
stored fingerprint does not match the current provider fingerprint in the
binary. This can happen after a development migration or provider-definition
change.

Refresh the activation record:

```bash
apstore -d $APSIGNER_DATA keytype activate falcon1024_ed25519.v1
```

This updates the state-record fingerprint. It does not rewrite existing key
files.

### Invalid or externally edited YAML template

Reload rejects templates whose encrypted YAML no longer matches the fingerprint
stored in the state record.

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
publisher.family.version
```

For example:

```text
aplane.falcon1024.v1
aplane.whitelist.v1
```

In human command input and compact UI display, APlane-published key types may
use the default-publisher shorthand:

```text
falcon1024.v1
whitelist.v1
```

This shorthand is only an alias. On disk, in backups, in policy files, in
IPC/HTTP JSON, and in SDK-facing fields, the key type remains canonical.

Existing key files keep their own stored LogicSig bytecode, off-curve salt
counter, and signing metadata. Enabling, disabling, importing, or removing a
key type controls subsequent discovery and generation; it does not rewrite
existing key files.
