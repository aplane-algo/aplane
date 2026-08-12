# Key Types

Unified developer guide for adding a new signable key type or LogicSig template to
APlane.

This document is the single canonical DEV guide for:

- what kind of key type you are adding
- which registries and packages must change
- what tests and docs must be updated

AI agents generating or reviewing custom templates should also read
[`AGENTS_KEYTYPES.md`](AGENTS_KEYTYPES.md), which gives the operational
safety checklist for user-loaded YAML templates.

For the complete key file and key type state machines, including backup/restore
and disabled/fingerprint-conflict behavior, see
[ARCH_KEY_LIFECYCLE.md](ARCH_KEY_LIFECYCLE.md).

## Signing Authority

**Signing authority lives in the key file, not in the template.** Every
LogicSig key file stores its compiled bytecode, off-curve salt counter, and
signing metadata at creation time. Sign-time code uses that stored metadata;
DSA-backed keys still use the appropriate base signing provider to produce and
pack signatures. Templates are used for generation, discovery, lifecycle, and
provenance, not to reconstruct missing signing metadata. Template provenance
conflicts or absence may warn in inventory but do not by themselves invalidate
a current-format key.

Bounded1 is the framework-enforced execution contract used by every bundled
composed DSA template. Read [ARCH_BOUNDED_DSA.md](ARCH_BOUNDED_DSA.md) before
changing schema-v2 composed templates, transaction-effect classification,
argument slots, Falcon contract-admin signing, or the `bounded1` /
`bounded-sentry1` signing flows.
Admin-capable account files contain the spending key and immutable public
contract-admin metadata; private admin material exists only in the external
`.wit` artifact. Never copy that private key into account
parameters, signer storage, or caller-supplied runtime arguments.

## Key Type Source Model

A key type has two separate classifications:

- **Behavior category**: what kind of signer/account behavior it represents.
- **Definition source**: where the provider or template definition comes from.

The source model is:

| Source | Meaning | Registration time | Scope |
|---|---|---|---|
| Go-defined | Provider/template implemented directly in Go and registered from code | Process startup | Built into the binary; visibility is governed by `internal/keytypecatalog` |
| User-loaded YAML | YAML installed into the signer keystore from the template library or a supplied path | Unlock/reload after the identity keyring is open, unless the installed template is disabled for the identity | Identity-scoped runtime capability |

Built-in compiled key types are Go-defined in the default build. Default-enabled
compiled key types are immediately visible. Library-visible compiled key types
are binary capabilities exposed through the KeyType Library and require
identity-scoped enablement before they appear in generation surfaces.
User-loaded templates are not built-ins; they become available only for the
identity whose keystore contains the encrypted `.template` file and has not
disabled that installed template.

Terminology:

- `family` is the middle segment of `publisher.family.vN`; in YAML templates
  it is the declared `family` field. A composed template has its own `family`
  (e.g. `family: falcon1024-allowlist`) — that names the template's own
  version line, separate from whatever it signs with.
- `base_key_type` is how a composed template names its private signing
  primitive, e.g. `base_key_type: aplane.falcon1024.v1` to produce and pack
  Falcon-1024 signatures.
- `base_key_type` is not the account owner or a universal route for metadata,
  key generation, mnemonic import, TEAL, or guarded assembly. The full
  `key_type` owns those semantics unless a narrower contract explicitly
  delegates one operation.
- `RoutingFamily()` on Go provider types (backed by a `FamilyName` field/constant)
  is the registry routing key used by current registry plumbing; persistent
  identity is always the full `key_type`.

Templates are generation/catalog definitions. The stored signing metadata
referenced above is `signing_metadata_version`, `lsig_derivation`,
`lsig_opcode_profile`, `base_key_type` for DSA LogicSig keys, and optional
`signing_args`.
`lsig_derivation: algod_v13_auto_salt` records that the final TEAL v13 bytecode
was salted by the configured algod compiler; compatible manual-counter records
may instead carry `salt_counter`, but pre-profile development records must be
regenerated. `lsig_opcode_profile` stores only reviewed per-path opcode
ceilings; program length and argument maxima are derived from the final
bytecode and the frozen argument layout. Non-bounded LogicSig keys
use signing-metadata version 1. Bounded keys use version 2 and persist the full
typed `bounded_authorization` contract, including the static base, derived,
runtime, and optional admin argument layout; path masks; profile; public admin
metadata/binding; and maximum signed size. Key files whose stored bytecode
derives an on-curve LogicSig address, or whose derivation marker does not match
their metadata, are rejected during key scan. Key files lacking
`signing_metadata_version` are
rejected when signing or restore would otherwise depend on missing durable
signing metadata.

Off-curve salting is generated by the TEAL v13 assembler, not authored in
templates or reproduced by APlane. APlane persists the final compiled bytecode,
verifies that the compiler-reported address matches it, and rejects an on-curve
address. The derivation mode is part of a versioned provider/template contract:
templates with omitted `derivation_version` are unsalted and compile exactly as
written, succeeding only if the unmodified bytecode already derives an
off-curve LogicSig address. Template `derivation_version: 3` requires TEAL v13
and delegates salting to the compiler, and is the only explicit contract still
accepted. The retired `derivation_version: 1` (stack-neutral generated marker
preamble) and `derivation_version: 2` (trailing dead-code `bytecblock 0x00`
after the program's terminating instruction) are rejected at template
validation; republish such a template with `derivation_version: 3`. Provider-owned
bare DSA versions use compiler auto-salting. Assignments are: omitted
`derivation_version` means unsalted, and explicit `derivation_version: 3` means
compiler-owned TEAL v13 auto-salting.
The bundled `aplane.falcon1024.v1`, `aplane.ed25519.v1`, and dedicated guarded
sentry provider (`aplane.falcon1024-sentry1024.v1`) all use the compiler-owned
mode. User template TEAL cannot choose salt style, must remain relocatable,
and must not depend on absolute constant-block layout or numeric `bytec`/`intc`
indexes.

The public inventory materializes these contracts as
`logic_sig_resources`. Each selected path contains `program_bytes`,
`argument_bytes`, and `max_opcode_cost`. Foreign `/plan` and `/sign` entries use
the same shape under `lsig_resources`. These values are consensus inputs, not
display estimates: derive program length after compiler auto-salting, use a
proven maximum for variable arguments, and demonstrate opcode ceilings against
worst permitted runtime operand sizes.

Every generic or composed template must declare a non-zero top-level
`max_opcode_cost`. Import and library installation reject an omitted value;
there is no inferred or full-group fallback.

For APlane-owned types, add a maximum-input accepted vector to the integration
opcode-ceiling gate. `harness.ValidateDeclaredOpcodeCeiling` simulates the exact
production-generated signed group through the same algod selected by the signer
fixture's `teal_compile_network` and rejects missing/zero cost reporting or
consumption above the declared ceiling. Simulation is evidence for the reviewed
vectors; it is not a general proof over arbitrary TEAL inputs.

Key files may also store `template_fingerprint`, the behavior-only, versioned
compatibility fingerprint of the template or composed provider that created the
key, when known. This is provenance for inventory warnings only; it is not
signing authority and must not override stored bytecode/signing metadata.

Fingerprint authoring rules:

- The fingerprint hashes only behavior-bearing definition fields (TEAL /
  `teal_suffix`, `salt_style`, the base primitive token, `template_mode`,
  `template_variables`, `parameters`, `runtime_args`, and the effective opcode
  profile). Identity, routing, and display fields (`key_type`, `family`,
  `version`, `publisher`, `display_name`, `description`, `display_color`,
  labels/examples) are forbidden from the hash, so an identifier or display
  rename never changes the fingerprint.
- Base key types are projected to a frozen `base_primitive` token namespace
  (`FingerprintBasePrimitive`): add rows, never rename tokens. A base-identifier
  rename adds a new raw->token row pointing at the existing token, so the hash
  stays the same.
- Bump `CompatibilityFingerprintVersion` only on a fingerprint-formula change
  (the canonical field set or hashing/projection rules), and update the goldens
  with it; a rename is not a formula change and must never bump the version. The
  stored form is `"<version>:<sha256hex>"`, and comparisons are version-aware: a
  cross-version or malformed fingerprint is "not comparable" (benign), while only
  a same-version, different-hash pair is a conflict.
- A base-key-type or provider-identifier rename is a separate compatibility
  event from the fingerprint: key files store the raw `base_key_type`, so the
  renamed identifier needs a retained registry alias or those keys cannot sign.
  The `base_primitive` projection stabilizes the fingerprint, not signing.

Credential backups do not bundle template YAML. Restored keys retain durable
signing metadata, and the destination must provide any required signer-side
provider or identity-local template through its normal installation flow.

Shipped YAML template sources live under the top-level `library/templates/`
directory and are installed into an identity before use. Source-tree YAML files
are install sources only; the runtime form is the encrypted identity-local
`.template` file plus key type state record. New signer identities install and
enable `aplane.falcon1024-allowlist.v1` during initialization.

Go-defined key types:

| Key type | Behavior category | Definition source | Catalog visibility | Primary definition |
|---|---|---|---|---|
| `ed25519` | Native signing key | Go-defined | default-enabled | `internal/signing/ed25519`, `internal/keygen/ed25519.go` |
| `falcon1024` | Protocol-native PQ signing key | Go-defined | default-enabled on signer nodes | `internal/signing/falcon1024` |
| `aplane.falcon1024.v1` | DSA LogicSig provider | Go-defined | default-enabled | `lsig/falcon1024/v1/standard.go` |
| `aplane.witness-falcon1024.v1` | Witness key (sentry custody or external contract-admin custody) | Go-defined | default-enabled on sentry nodes | `internal/witness`, `lsig/falcon1024/keygen/witness.go` |
| `aplane.falcon1024-sentry1024.v1` | Guarded-account DSA LogicSig provider | Go-defined | library-visible | `lsig/falcon1024_guarded` |
| `aplane.ed25519.v1` | DSA LogicSig provider | Go-defined | library-visible | `lsig/ed25519lsig` |

Compiled key types can be registered as binary capabilities without being
default-visible for generation. Visibility is recorded in
`internal/keytypecatalog`: `ed25519`, `falcon1024`, `aplane.falcon1024.v1`, and
`aplane.witness-falcon1024.v1` are default-enabled, while
`aplane.falcon1024-sentry1024.v1` and
`aplane.ed25519.v1` are library-visible and not available for generation until
the current identity enables them from the library. `aplane.ed25519.v1` is the Ed25519
LogicSig DSA provider, distinct from the native `ed25519` signing key. See
`docs/ARCH_KEYTYPE_AXES.md` for the exact
split between native `ed25519`, the `aplane.ed25519` LogicSig routing family,
and the concrete `aplane.ed25519.v1` key type.
Opt-in state records are plaintext identity-scoped metadata under
`identities/<identity>/keytypes/<key_type>.json`; they affect discovery and key
creation, not the ability to sign with keys that already exist. Mnemonic import
is additionally gated by the provider's explicit mnemonic-import capability.
The default-enabled `ed25519`, `falcon1024`, and `aplane.falcon1024.v1` providers allow
user-entered mnemonic import without identity-local activation; the
library-visible `aplane.ed25519.v1` provider allows mnemonic import after it is
enabled for the identity. YAML templates and the other library-visible compiled
providers do not allow user-entered mnemonic import. `apstore restore` creates
or enables this state record idempotently when restoring a key for a
library-visible compiled provider.

Native `falcon1024` is not a LogicSig provider. It uses the explicit
`native_pq` authorization kind, a 25-word Algorand mnemonic, top-level
`SignedTxn.PQsig`, and the `internal/signing/falcon1024` signer-only provider.
Do not route it through `lsig/falcon1024` or reuse the 24-word recovery and
derivation contract of `aplane.falcon1024.v1`.

Installed YAML templates use the same state-record model. The encrypted
`.template` file under `identities/<identity>/keytypes/<key_type>.template` is
the durable installed source. The adjacent JSON record stores the source
(`yaml_generic`, `yaml_composed`, or `compiled`), state (`enabled` or
`disabled`), compatibility fingerprint, and enablement timestamp. Removing a YAML
template moves the encrypted template source to the identity-local deleted key
type archive.

## Key Type Terminology

Use these terms consistently:

| Term | Applies to | Meaning |
|---|---|---|
| **Registered provider** | Go-defined or loaded providers | Provider code is present in a process-global registry and can be looked up by key type. For compiled providers this happens at startup; for user-loaded YAML templates it happens on identity reload after installation. |
| **Binary capability** | Compiled providers | The current binary contains and registers the provider code, even if not every identity can create that key type by default. |
| **Default-enabled** | Compiled providers | Catalog availability `default_enabled`; every identity can see and create the key type without an identity-local state record. |
| **Library-visible** | Compiled providers | Catalog availability `library`; the provider is registered in the binary and appears in the KeyType Library, but an enabled identity state record is required before that identity sees it in generation surfaces. |
| **Disabled** | Compiled providers | Catalog availability `disabled`; the provider may exist in source but should not be registered or exposed by the runtime path that owns the catalog entry. |
| **Enabled for identity** | Library-visible compiled providers | The identity has an enabled `source:"compiled"` state record, so that compiled key type is enabled for that identity's discovery and generation surfaces. |
| **Installed** | YAML templates | The identity has an encrypted `.template` file under `identities/<identity>/keytypes/<key_type>.template`; plaintext files under `library/templates/` are only install sources. |
| **Template disabled** | Installed YAML templates | The identity has a `source:"yaml_*"` state record with `state:"disabled"`; the encrypted template remains installed but is hidden from discovery and generation until re-enabled. |
| **Registered on reload** | Enabled installed YAML templates | On unlock/reload, the signer decrypts enabled installed templates and registers their providers before key scanning. Disabled installed templates are skipped. |

Avoid using "inactive" as a durable technical term. Prefer precise phrases
such as "library-visible but not enabled for this identity" or
"installed but disabled for this identity".

Bundled YAML templates, if installed:

| Library key type | Behavior category | Install command | Runtime storage |
|---|---|---|---|
| `aplane.htlc.v1` | Generic LogicSig template | `apstore template import library/templates/aplane.htlc.v1.yaml` | `identities/<identity>/keytypes/aplane.htlc.v1.{json,template}` |
| `aplane.falcon1024-allowlist.v1` | Bounded1 composed DSA template | Installed/enabled during new signer-store initialization; existing stores can run `apstore template import library/templates/aplane.falcon1024-allowlist.v1.yaml` | `identities/<identity>/keytypes/aplane.falcon1024-allowlist.v1.{json,template}` |
| `aplane.falcon1024-allowlist.v2` | Bounded1 composed DSA template | `apstore template import library/templates/aplane.falcon1024-allowlist.v2.yaml` | `identities/<identity>/keytypes/aplane.falcon1024-allowlist.v2.{json,template}` |
| `aplane.falcon1024-allowlist-alock.v1` | Bounded1 composed DSA template | `apstore template import library/templates/aplane.falcon1024-allowlist-alock.v1.yaml` | `identities/<identity>/keytypes/aplane.falcon1024-allowlist-alock.v1.{json,template}` |
| `aplane.falcon1024-timelock.v1` | Bounded1 composed DSA template | `apstore template import library/templates/aplane.falcon1024-timelock.v1.yaml` | `identities/<identity>/keytypes/aplane.falcon1024-timelock.v1.{json,template}` |
| `aplane.corridor.v1` | Bounded1 composed DSA template with sentry-gated spend | `apstore template import library/templates/aplane.corridor.v1.yaml` | `identities/<identity>/keytypes/aplane.corridor.v1.{json,template}` |

These template files are install sources, not product built-ins. They do not
appear in `apshell keytypes` or the `apadmin` generate view until installed into
the active signer identity, enabled for that identity, and loaded by
`apsigner`. New signer identities start with `aplane.falcon1024-allowlist.v1`
already installed and enabled; sentry-role identities do not. The `apadmin`
KeyType Library lists plaintext library entries and also reports installed
identity templates that do not have a matching library YAML source; those
installed-only rows are derived from encrypted `.template`
filenames and may not have parameter metadata.

## Identity Filesystem State

Template key type state is represented by one plaintext state record per
identity/key type, plus an encrypted template body when the source is YAML:

| State | Filesystem representation |
|---|---|
| Not installed | No `identities/<identity>/keytypes/<key_type>.json` state record |
| Installed and enabled | `keytypes/<key_type>.json` has `source:"yaml_generic"` or `source:"yaml_composed"` and `state:"enabled"`; `keytypes/<key_type>.template` holds the encrypted YAML |
| Installed and disabled | Same files, but the state record has `state:"disabled"` |
| Removed | The state record is deleted and the `.template` file has been moved out of active storage to `identities/<identity>/deleted/keytypes/<key_type>.template` |

Filesystem actions for YAML templates:

| Operation | Filesystem action |
|---|---|
| Install | Encrypts YAML into `keytypes/<key_type>.template` and writes an enabled state record |
| Disable | Leaves both files in place and changes the state record to `disabled` |
| Enable | Leaves both files in place and changes the state record to `enabled` |
| Remove | Deletes the state record and moves the active `.template` file to `deleted/keytypes/<key_type>.template` |

Key deletion uses the same identity-local archive root:

```text
identities/<identity>/keys/<address>.key
  -> identities/<identity>/deleted/keys/<address>.key

identities/<identity>/keys/<witness_key_id>.sen
  -> identities/<identity>/deleted/keys/<witness_key_id>.sen
```

Archived keys and templates are outside active key/template scans. A user-requested
template removal must archive the `.template` file; internal rollback after a
failed live install may directly remove a newly written template because it is
undoing an incomplete operation rather than preserving user-deleted history.

Compiled providers use state records rather than moving provider code:

| Operation | Filesystem action |
|---|---|
| Enable library-visible compiled provider | Writes `identities/<identity>/keytypes/<key_type>.json` with `source:"compiled"` and `state:"enabled"` |
| Disable library-visible compiled provider | Deletes `identities/<identity>/keytypes/<key_type>.json` after the unused-key guard passes |

## Step 1: Classify the Key Type

Choose exactly one primary category.

> **Three resolution axes — don't collapse them.** Wiring a key type touches three
> separate mechanisms: **Resolve** (key type → implementation, via family-keyed
> registries), **Classify** (category facts, via string switches in the neutral
> `internal/sentry/keytypes` leaf), and **Behave** (the operation, via
> provider-capability interfaces). They are deliberately distinct because each is
> called from a place with different availability (registry? provider instance?
> neither?). Read [ARCH_KEYTYPE_AXES.md](ARCH_KEYTYPE_AXES.md); routing by
> `BaseKeyType` or moving classification onto provider interfaces violates
> those availability boundaries.

### A. Native Signing Key

Examples:
- `ed25519`

Characteristics:
- native Algorand signature
- signature goes in `SignedTxn.Sig`
- not a LogicSig

Typical code areas:
- `internal/signing/`
- algorithm metadata / keygen / mnemonic registries

### B. Generic LogicSig Template

Example:
- `aplane.htlc.v1`

Characteristics:
- TEAL-only authorization
- no cryptographic signature
- key stores compiled bytecode plus creation params

Typical code areas:
- `library/templates/*.yaml`, installed with `apstore template import`, or
- `lsig/<template>/template.go` only for a true product built-in

Reference implementation: `library/templates/aplane.htlc.v1.yaml`.

### C. DSA LogicSig Provider

Examples:
- `aplane.falcon1024.v1`
- `aplane.ed25519.v1`

Characteristics:
- cryptographic signature verified by TEAL
- signature goes in `LogicSig.Args`
- private key material exists

Typical code areas:
- `lsig/<family>/`
- `internal/logicsigdsa`
- `internal/signing`

Reference implementations: `lsig/falcon1024/` and `lsig/ed25519lsig/`.

### D. Composed DSA Template

Examples:
- `aplane.falcon1024-allowlist.v1`

Characteristics:
- DSA base plus additional TEAL constraints
- creation params feed a TEAL suffix
- can be declared in Go or YAML

Typical code areas:
- `lsig/composeddsa/`
- base-family registration code that calls `composeddsa.RegisterBase`

Reference implementation: `lsig/composeddsa/` plus the Falcon base registration
in `lsig/falcon1024/register.go`.

## Step 2: Choose the Implementation Style

### Generic LogicSig: Go vs YAML

Use **Go** when:
- the template needs custom control flow that is awkward in YAML
- the template has special validation or runtime arg handling
- the template is core enough to justify a built-in provider

Use **YAML generic template** when:
- the template is mostly declarative
- parameters map cleanly to creation-time values
- the TEAL is straightforward and parameterized
- a YAML file under the top-level `library/templates/` directory is the right fit

### DSA Template: Go vs YAML

Use **Go** when:
- the type is a core DSA/base provider
- the derivation behavior is algorithm-specific

Use **YAML composed template** when:
- the base DSA key type already exists
- you are adding a constrained variant by TEAL suffix
- parameters map cleanly to suffix substitution
- a YAML file under the top-level `library/templates/` directory is the right fit

## YAML Template Notes

Optional generic YAML templates live at:

```text
library/templates/<publisher>.<family>.v<version>.yaml
```

Optional composed DSA YAML templates live at paths such as:

```text
library/templates/aplane.falcon1024-<constraint>.v<version>.yaml
```

Composed DSA YAML declares both the generic composed template type and the DSA
base key type. All YAML templates declare a publisher namespace:

```yaml
template_type: composed
base_key_type: aplane.falcon1024.v1
publisher: aplane
family: falcon1024-constraint
version: 1
```

In composed templates, `base_key_type` selects the signing primitive only. It
does not rename the template, collapse its metadata into the base provider, or
make the base provider responsible for the template's TEAL, creation params, or
runtime args.

Files in the top-level `library/templates/` directory are install sources, not
active key types by presence alone. Installing one of these YAML entries through
new signer-store initialization, `apstore template import`, or the
authenticated KeyType Library flow writes an encrypted `.template` file and
adjacent enabled state record under the target identity's `keytypes/`
directory. Enabled installed templates are registered on that identity's
reload/unlock path.

Disabling an installed YAML template is different from removing it. Disable
writes `state:"disabled"` into `identities/<identity>/keytypes/<key_type>.json`
and leaves the encrypted `.template` file in place so the template can be
re-enabled later. Remove deletes the state record and moves the encrypted
`.template` source to `identities/<identity>/deleted/keytypes/<key_type>.template`.

Disabling or removing an installed YAML key type must be treated as
compatibility-sensitive. Disable is a reversible, state-only hide from discovery
and future generation, while remove archives the encrypted `.template` source
and deletes the state record. Both operations scan identity keys with the master
key and reject the operation when the key type is still in use; existing keys
remain signable from their own stored LogicSig bytecode, off-curve salt
counter, and signing metadata.

Compiled-provider disable follows the same in-use rule: deleting an identity
state record is rejected while any key still uses that compiled library-visible
`key_type`. Default-enabled compiled providers do not have a disable transition.

Supported creation parameter types:

- `address`
- `uint64`
- `bytes`
- `address[]`
- `uint64[]`

For `address[]` and `uint64[]`, input is a comma-separated string:

```text
recipients=ADDR1, ADDR2, ADDR3
allowed_optin_assets=123, 456, 789
```

Rules:

- whitespace around items is trimmed
- duplicates are rejected
- item order is canonicalized; `address[]` and `uint64[]` are unordered by definition
- `uint64[]` is canonicalized numerically
- strict templates use `$variable` constant references declared in
  `template_variables`
- generated templates use bounded list expansion before scalar `@variable`
  substitution
- template TEAL must be relocatable: user-authored TEAL may not contain raw
  `bytecblock`/`intcblock` declarations or numeric constant references such as
  `bytec 0`, `intc 0`, `bytec_0`, or `intc_0`; use template variables and
  symbolic references so APlane can own generated constants and any
  derivation-version salt anchor safely

Supported list-expansion construct:

```teal
{{range @recipients}}
...
{{.}}
...
{{end}}
```

Not supported:

- nested ranges
- `if`
- `len`
- arbitrary `{{...}}` constructs

## Provider Interfaces

LogicSig key types register with the unified `internal/lsigprovider` registry.
Native signing keys such as `ed25519` use the native signing, keygen, mnemonic,
and algorithm registries instead. The LogicSig interface hierarchy is
documented in [`ARCH_LSIG_PROVIDER.md`](ARCH_LSIG_PROVIDER.md).

Summary:

- `LSigProvider` — base interface for all LogicSig types (identity, params, args)
- `SigningProvider` — extends LSigProvider with signature metadata and `DeriveLsig`
- `MnemonicProvider` — extends SigningProvider with mnemonic metadata
- `AlgodConfigurable` — implemented by any provider that needs runtime TEAL compilation

Generic LogicSig templates implement `genericlsig.Template` (which extends
`LSigProvider` with `GenerateTEAL` and `Compile`).

DSA providers implement `SigningProvider` and typically `MnemonicProvider` and
`AlgodConfigurable`.

### Client/Signer Boundary For DSA Providers

Provider metadata and LogicSig derivation are client-visible. Private-key
operations are signer-only.

Signer and keygen paths must not call private-key methods through
`internal/logicsigdsa` or the client metadata registry. Instead, signer-side
registrations pass explicit operation handles:

- `internal/signing.NewLogicSigProvider(...)` receives
  `map[keyType]LogicSigSignerOps`.
- `lsig/falcon1024/keygen.NewFalconGenerator(...)` receives
  `map[keyType]LogicSigKeygenOps`.
- provider-specific `signerops` packages own key generation, signing, and
  mnemonic conversion.

The versioned key type should be registered explicitly whenever the key type has
unique key generation or signing behavior. A **shared-ops fallback** is allowed
only when multiple key types share the same private-key operation and only the
LogicSig derivation/TEAL differs: in that case, multiple keys may resolve to one
entry in the ops map instead of each registering its own. For example, Falcon
composed templates such as `aplane.falcon1024-allowlist.v1` may resolve through
the shared-ops fallback to the `aplane.falcon1024.v1` ops entry because they
share key generation and signing with it; the template changes params and TEAL,
not the private-key algorithm.

Do not rely on the shared-ops fallback for a future version with changed seed
derivation, key format, signature format, mnemonic behavior, or signing
semantics. Such a version needs a distinct versioned ops entry, for example
`aplane.falcon1024.v2`.

## Creation Params vs Runtime Args

**Creation params** are provided when the LogicSig is created. They are
substituted into the TEAL source and become part of the compiled bytecode. Once
compiled, they cannot be changed — they define the account address.

**Runtime args** are provided at transaction signing time. They are passed as
`LogicSig.Args` entries (`arg 0`, `arg 1`, etc.) and evaluated by the TEAL
program each time a transaction is submitted.

| | Creation Params | Runtime Args |
|---|---|---|
| When provided | Key generation | Transaction signing |
| Embedded in | TEAL bytecode | LogicSig.Args |
| TEAL access | `$variable` constants in strict mode; `@variable` only in generated mode | `arg 0`, `arg 1`, etc. |
| Affects address | Yes | No |
| Example | recipient address set, unlock round | hashlock preimage |

## YAML Schema

See any existing `.yaml` file in `library/templates/` for the full
schema. The core fields are:

```yaml
schema_version: 1
derivation_version: 3
max_opcode_cost: 20000  # reviewed worst-case cost of every reachable path
template_type: <type>        # generic | composed; optional for generic templates
base_key_type: <key_type>    # composed signing primitive; omitted for generic templates
template_mode: <mode>        # strict | generated
publisher: <namespace>       # lowercase namespace owner, for example aplane
family: <name>              # lowercase, no spaces
version: <int>              # integer version
display_name: "<Name>"      # human-readable
description: "<text>"       # short description
display_color: "<code>"     # ANSI color code (optional)

parameters:
  - name: <id>              # creation-time parameter
    label: "<Label>"        # human-readable
    description: "<text>"   # tooltip
    type: <type>            # address | uint64 | bytes | address[] | uint64[]
    required: true
    # uint64 only:
    min: <n>
    max: <n>
    max_length: <n>          # optional UI/validation length hint
    default: "<value>"       # optional default for optional params
    # list types only:
    min_items: <n>
    max_items: <n>

template_variables:          # strict mode only
  - name: <id>               # used in TEAL as $id
    source: parameter        # runtime args are not creation-time variables
    parameter: <param-name>
    type: <type>             # address | uint64 | bytes
    constant: <kind>         # byte for address/bytes, int for uint64

runtime_args:               # optional
  - name: <id>              # used in CLI tokens as arg:<id>=<value>
    label: "<Label>"
    description: "<text>"
    type: <type>            # bytes | string | uint64
    required: true
    byte_length: <n>        # 0 = variable length

teal: |
  #pragma version 10
  // strict mode: $variable constant references
```

Strict variable constants by type. These constant blocks are emitted by the
APlane renderer alongside any APlane-generated salt anchor; template authors
should still avoid hand-written constant blocks in TEAL source.

| Type | Input | TEAL Output |
|------|-------|-------------|
| `address` | `ABC...XYZ` | decoded 32-byte value in `bytecblock` |
| `uint64` | `12345` | value in `intcblock` |
| `bytes` | `deadbeef` | `0xdeadbeef` in `bytecblock` |

## TEAL Security Patterns

Templates should make security-relevant behavior explicit. For public generic
LogicSigs and self-contained TEAL spending policies, the following are common
conservative patterns. For signer-gated signing primitives or composed
partial-condition templates, a behavior may deliberately be left to signer
approval and local signer policy; document that boundary instead of implying
the TEAL is a full spending policy.

```teal
// Conservative default: prevent RekeyTo takeover in TEAL
txn RekeyTo
global ZeroAddress
==
assert

// Conservative default: prevent unauthorized CloseRemainderTo drain
txn CloseRemainderTo
global ZeroAddress
==
assert

// Conservative default: restrict transaction type
txn TypeEnum
int pay
==
assert

// Time-based check: use txn FirstValid, NOT global Round
// (global Round is restricted in LogicSig mode on some networks)
txn FirstValid
$unlock_round
>=
assert
```

## Go Security Patterns

DSA providers handle private key material and must follow these rules:

```go
// Zero all sensitive data after use
defer crypto.ZeroBytes(privateKey)
defer crypto.ZeroBytes(seed)

// Use crypto/rand for entropy — never math/rand
import "crypto/rand"
_, err := rand.Read(entropy)

// Validate key sizes before operating
if len(publicKey) != family.PublicKeySize {
    return nil, fmt.Errorf("invalid public key size: expected %d, got %d",
        family.PublicKeySize, len(publicKey))
}

// Require algod client before derivation
if a.algodClient == nil {
    return nil, "", fmt.Errorf("algod client not set: configure algod.testnet.server")
}
```

## Common Mistakes

### Wrong: Typo in template variable name

```yaml
parameters:
  - name: recipient
    type: address
teal: |
  $recepient   # TYPO: will fail validation
```

### Wrong: min/max on non-uint64 type

```yaml
parameters:
  - name: addr
    type: address
    min: 1          # ERROR: min/max only valid for uint64
```

### Wrong: Missing TEAL security checks

```teal
// BAD: No RekeyTo check allows account takeover
txn Receiver
$recipient
==
return
```

### Wrong: Using global Round in LogicSig

```teal
// BAD: global Round may not work in LogicSig mode
global Round
$timeout
>=
```

Use `txn FirstValid` instead.

### Wrong: Runtime arg index mismatch

If `BuildArgs` returns `[signature, preimage]`, then:
- `arg 0` = signature
- `arg 1` = preimage

Declaring runtime args in a different order than `BuildArgs` emits them will
silently produce wrong values.

## Complete YAML Example

A full generic template showing all field types and both spending paths:

```yaml
schema_version: 1
derivation_version: 3
max_opcode_cost: 20000
template_type: generic
template_mode: strict
publisher: aplane
family: escrow
version: 1
display_name: "Escrow"
description: "Hold funds until recipient provides approval code, or sender reclaims after timeout"
display_color: "33"

parameters:
  - name: recipient
    label: "Recipient Address"
    description: "Address that can claim funds with the approval code"
    type: address
    required: true
    example: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"
    placeholder: "Enter recipient address"

  - name: approval_hash
    label: "Approval Hash"
    description: "SHA256 hash of the approval code (32 bytes, hex)"
    type: bytes
    required: true
    max_length: 64
    example: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

  - name: timeout_round
    label: "Timeout Round"
    description: "Round after which sender can reclaim funds"
    type: uint64
    required: true
    min: 1
    example: "50000000"

  - name: sender
    label: "Sender Address"
    description: "Original sender who can reclaim after timeout"
    type: address
    required: true

template_variables:
  - name: recipient
    source: parameter
    parameter: recipient
    type: address
    constant: byte
  - name: approval_hash
    source: parameter
    parameter: approval_hash
    type: bytes
    constant: byte
  - name: timeout_round
    source: parameter
    parameter: timeout_round
    type: uint64
    constant: int
  - name: sender
    source: parameter
    parameter: sender
    type: address
    constant: byte

runtime_args:
  - name: approval_code
    label: "Approval Code"
    description: "The secret whose SHA256 hash matches approval_hash"
    type: bytes
    required: false
    byte_length: 0

teal: |
  #pragma version 10
  // Escrow: claim with approval code, or refund after timeout

  // Security: Prevent RekeyTo
  txn RekeyTo
  global ZeroAddress
  ==
  assert

  // Check if timeout passed
  txn FirstValid
  $timeout_round
  >=
  bnz refund_path

  // === CLAIM PATH (before timeout) ===
  arg 0
  sha256
  $approval_hash
  ==
  assert

  txn Receiver
  $recipient
  ==
  assert

  txn CloseRemainderTo
  $recipient
  ==
  txn CloseRemainderTo
  global ZeroAddress
  ==
  ||
  assert

  int 1
  return

  // === REFUND PATH (after timeout) ===
  refund_path:
      txn Receiver
      $sender
      ==
      assert

      txn CloseRemainderTo
      $sender
      ==
      txn CloseRemainderTo
      global ZeroAddress
      ==
      ||
      assert

      int 1
      return
```

## Checklist

Use this checklist for every new key type.

- [ ] Pick the category from Step 1.
- [ ] Choose Go or YAML style from Step 2.
- [ ] Define the final versioned key type string.
- [ ] Define the family string.
- [ ] Confirm whether the type needs runtime args.
- [ ] Confirm whether the type needs creation params only.
- [ ] Add or update tests.
- [ ] Update user-facing docs if the key type is intended for operators.
- [ ] Update architecture/dev docs if the mechanism or supported family set changed.
- [ ] Verify the key type appears in runtime discovery in the right state: immediately for default-enabled types, after enablement for library-visible compiled providers, and after install plus enable/reload for user-loaded templates.

## Naming Checklist

- [ ] Key type is versioned, e.g. `aplane.htlc.v1`.
- [ ] Publisher is a stable lowercase namespace owner, e.g. `aplane`.
- [ ] Family is stable and lowercase, e.g. `allowlist`.
- [ ] Display name is concise and operator-readable.
- [ ] Description is short and accurate.

## Registry Checklist

The exact registries depend on the category.

### Generic LogicSig Template

- [ ] Go-defined templates implement or produce a provider visible through `internal/genericlsig`
- [ ] Go-defined templates register with the unified `internal/lsigprovider` registry
- [ ] Go-defined templates are reachable from an owning startup path such as `lsig.RegisterClient()` or `lsig/signerreg.RegisterSigner()`
- [ ] User-loaded YAML parses from `library/templates/*.yaml` or another supplied path
- [ ] User-loaded YAML installs into the identity-scoped encrypted template store with a key type state record, can be disabled by setting that record to `disabled`, and is not registered directly from startup registration

Common paths:
- `lsig/<template>/template.go`
- `library/templates/*.yaml`
- `internal/templatelibrary/library.go`
- `internal/templatestore/store.go`
- `lsig/all.go`

### DSA LogicSig Provider

- [ ] Registers with `internal/logicsigdsa`
- [ ] Registers algorithm metadata / mnemonic handlers as needed
- [ ] Registers signing provider with explicit signer ops, not by relying on the client metadata provider
- [ ] Registers keygen with explicit keygen ops, not by relying on the client metadata provider
- [ ] Uses versioned ops entries for any version with distinct keygen/signing semantics
- [ ] Uses the shared-ops fallback only when multiple key types share private-key operations and differ only in LogicSig derivation/TEAL
- [ ] Registers key/address processing for the key type
- [ ] Registers product visibility in `internal/keytypecatalog` through `lsig/all.go`
- [ ] Client-safe metadata/derivation is reachable from `lsig.RegisterClient()`
- [ ] Signer-side signing/keygen/mnemonic handlers are reachable from `lsig/signerreg.RegisterSigner()`
- [ ] If library-visible, has enablement/discovery tests before generation is allowed

Common paths:
- `lsig/<family>/register.go`
- `lsig/<family>/keys/register.go`
- `lsig/<family>/signerreg/register.go`
- `lsig/all.go`

### Composed DSA Template

- [ ] Produces a ComposedDSA provider
- [ ] Registers with `internal/logicsigdsa`
- [ ] Keeps `composeddsa.DSAOps` client-safe: metadata, TEAL generation, and signature-argument packing only
- [ ] Supplies private-key operations through signer-side `signerops` packages when needed
- [ ] Go-defined templates are reachable from `lsig/composeddsa` or equivalent composed template registration code
- [ ] Go-defined templates are reachable from an owning startup path such as `lsig.RegisterClient()` or `lsig/signerreg.RegisterSigner()`
- [ ] User-loaded YAML installs into the identity-scoped encrypted template store with a key type state record, can be disabled by setting that record to `disabled`, and is not registered directly from startup registration

## Parameter Checklist

### Creation Params

- [ ] Every creation param is represented in `CreationParams()`
- [ ] `ValidateCreationParams(...)` or shared validation covers every param
- [ ] Strict templates declare every `$variable` in `template_variables`
- [ ] Generated templates keep every `@variable` matched to a creation param
- [ ] Template TEAL is relocatable: no user-authored `bytecblock`,
      `intcblock`, numeric `bytec`/`intc`, `bytec_N`, or `intc_N`
- [ ] Unused creation params are rejected if the path uses strict validation

Supported scalar types:
- `address`
- `uint64`
- `bytes`

Supported list types:
- `address[]`
- `uint64[]`

### Runtime Args

- [ ] Runtime args only exist when needed at signing time
- [ ] `RuntimeArgs()` names match UI/CLI usage
- [ ] `BuildArgs(...)` ordering is correct
- [ ] Required runtime args are enforced

## TEAL Checklist

- [ ] TEAL version is appropriate
- [ ] Rekey behavior is explicit: TEAL-enforced, signer-policy-enforced, or deliberately allowed
- [ ] Close behavior is explicit
- [ ] Transaction type behavior is explicit
- [ ] Runtime arg indexes match the provider's arg layout
- [ ] Creation params are substituted safely
- [ ] The resulting TEAL is understandable and commented when non-obvious

## List Expansion Checklist

Use this only if the template needs repeated checks such as a receiver
allowlist or approved ASA opt-in IDs.

- [ ] Use `address[]` or `uint64[]` only
- [ ] Use `{{range @name}} ... {{.}} ... {{end}}`
- [ ] Keep it creation-time only
- [ ] Do not use nested ranges
- [ ] Do not use unsupported `{{...}}` constructs
- [ ] Validate duplicates and empty items are rejected
- [ ] Treat `address[]` and `uint64[]` as unordered; add a new list type if order ever becomes semantic
- [ ] Remember `uint64[]` items are sorted numerically, not lexically
- [ ] Consider TEAL/program size growth from expansion

## Tests Checklist

At minimum, add focused tests covering:

- [ ] registration / discovery
- [ ] parameter validation
- [ ] TEAL generation
- [ ] runtime args behavior if applicable
- [ ] duplicate registration safety if a runtime-loaded path is involved

Examples:

### Generic LogicSig / Generic Template

- [ ] `go test ./lsig/generictemplate/...`
- [ ] add provider/template unit tests
- [ ] ensure the template appears in template-library tests if shipped under `library/templates/`

### DSA / ComposedDSA

- [ ] `go test ./lsig/<family>/...`
- [ ] add suffix/parameter generation tests
- [ ] verify the composed provider path generates expected TEAL

### TUI / Discovery

- [ ] `go test ./cmd/apadmin/...`
- [ ] ensure default-enabled key types are discoverable without identity-local enablement
- [ ] ensure library-visible compiled providers appear in the KeyType Library and become discoverable after identity-local enablement
- [ ] ensure user-loaded templates appear after installation and identity reload/unlock, disappear when disabled, and reappear when enabled again

## User Docs Checklist

If operators are expected to use the new key type:

- [ ] add at least one `generate` example to [`USER_COMMANDS.md`](USER_COMMANDS.md)
- [ ] update any user guide that depends on the feature

## Architecture Docs Checklist

If the supported key-type catalog changed:

- [ ] update [`ARCH_CRYPTO.md`](ARCH_CRYPTO.md)

If a new mechanism or template capability changed:

- [ ] update the relevant developer guide
- [ ] update architecture docs only if subsystem behavior changed materially

## Runtime Verification Checklist

Before considering the key type complete:

- [ ] build successfully
- [ ] run focused tests
- [ ] confirm default-enabled key types appear in `apshell keytypes`
- [ ] confirm library-visible compiled key types appear in `apshell keytypes` after enablement
- [ ] confirm user-loaded key types appear in `apshell keytypes` after installation, enable, and reload/unlock
- [ ] confirm default-enabled key types appear in `apadmin` generate-key selection
- [ ] confirm library-visible compiled key types appear in `apadmin` generate-key selection after enablement
- [ ] confirm user-loaded key types appear in `apadmin` generate-key selection after installation, enable, and reload/unlock
- [ ] if applicable, confirm it can be generated end-to-end on a signer instance

## Category Routing Summary

If you are adding:

- a hand-written generic TEAL LogicSig:
  - use the **Generic LogicSig Template** path above

- a YAML generic template:
  - use the **Generic LogicSig: Go vs YAML** choice plus the **YAML Template Notes** above

- a new DSA/base provider:
  - use the **DSA LogicSig Provider** path above

- a Falcon/ECDSA constrained variant by TEAL suffix:
  - use the **Composed DSA Template** path above
  - and apply the **YAML Template Notes** if it is YAML-backed
