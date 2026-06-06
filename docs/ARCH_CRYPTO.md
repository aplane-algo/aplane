# Cryptographic Subsystem

This document describes the cryptographic architecture in APlane.
For the detailed key-type workflow and terminology, see
[`DEV_KEYTYPES.md`](DEV_KEYTYPES.md). For compatibility-bearing on-disk
contracts, see [`ARCH_CONTRACTS.md`](ARCH_CONTRACTS.md).

## Overview

APlane supports three authorization categories:

1. `ed25519` native signing keys
2. DSA-backed LogicSig providers such as `aplane.falcon1024.v1`
3. Generic LogicSig template instances such as `aplane.timed-whitelist.v1`

These share storage and runtime plumbing, but not the signing behavior:

- native Ed25519 signs directly into `SignedTxn.Sig`
- DSA-backed LogicSig providers derive LogicSig bytecode and place a
  cryptographic signature in `LogicSig.Args`
- generic LogicSig templates authorize by TEAL only and use runtime args
  without cryptographic key material

## Package Layout

The cryptographic subsystem is split across these packages:

| Area | Primary packages |
|---|---|
| Native signing | `internal/signing`, `internal/signing/ed25519` |
| LogicSig provider interfaces, registry, and salting | `internal/lsigprovider`, `internal/logicsigdsa`, `internal/genericlsig`, `internal/lsigsalt` |
| Built-in LogicSig families | `lsig/`, especially `lsig/falcon1024`, `lsig/falcon1024_ed25519`, `lsig/ecdsak1`, `lsig/composeddsa`, `lsig/generictemplate` |
| Algorithm metadata, keygen, mnemonics | `internal/algorithm`, `internal/keygen`, `internal/mnemonic` |
| Key-type visibility and state | `internal/keytypecatalog`, `internal/keytypestate` |
| Encrypted key/template persistence | `internal/crypto`, `internal/keys`, `internal/keystore`, `internal/templatestore`, `internal/templatelibrary` |
| Signer reload and template registration | `internal/signerapp/templates` |

## Provider Model

Provider registration is explicit and idempotent:

- binary entrypoints call `RegisterProviders()`,
- `lsig.RegisterClient()` aggregates client-safe LogicSig metadata and derivation,
- `lsig/signerreg.RegisterSigner()` adds signer-side LogicSig signing/keygen/mnemonic handlers,
- Ed25519 components are registered separately,
- registries are queried dynamically.

The provider boundary is two-tiered. Client-visible registries describe what
key types exist and how their LogicSig metadata is assembled:
`internal/lsigprovider`, `internal/logicsigdsa`, `internal/genericlsig`,
`internal/algorithm`, `internal/addressderive`, and `internal/keytypecatalog`.
Those registries do not own private-key execution. Signer-side registries own
private-key behavior: `internal/signing`, `internal/keygen`,
`internal/mnemonic`, and key processors under provider-owned packages.

This split is a hard dependency boundary, not only a startup preference:

- `cmd/apshell` calls `lsig.RegisterClient()` and
  `internal/signing/ed25519.RegisterClient()` and must not populate signer-side
  signing, keygen, mnemonic, or key-processor registries.
- `cmd/apsigner`, `cmd/apadmin`, and `cmd/apstore` call
  `lsig/signerreg.RegisterSigner()` plus Ed25519 signer registration.
- `internal/logicsigdsa.LogicSigDSA` is metadata and derivation only; it does
  not expose `GenerateKeypair` or `Sign`.
- `internal/lsigprovider.SigningProvider` and `MnemonicProvider` expose
  compatibility-bearing metadata, not signer execution.
- LogicSig private-key execution is wired through explicit signer-side handles
  such as `internal/signing.LogicSigSignerOps`,
  `lsig/falcon1024/keygen.LogicSigKeygenOps`, and provider `signerops`
  packages.

Client-only binaries can therefore render key-type and LogicSig metadata
without importing Falcon CGO packages, Falcon mnemonic code, or secp256k1
signer implementations.

Provider registries are process-global compatibility registries. Key type names
are globally unique within one `apsigner` process. Identity isolation is
enforced by identity-owned keystores plus identity-local key type state, not by
giving each identity a private provider namespace. Compatible re-registration
of the same template definition is idempotent; conflicting same-`key_type`
definitions are reported/rejected.

Key type strings are canonical compatibility identifiers, not display labels.
Except for the native `ed25519` key type, APlane-defined LogicSig/template and
compiled-provider key types use `publisher.family.vN`, such as
`aplane.falcon1024.v1`, `aplane.htlc.v1`, or
`aplane.falcon1024-whitelist.v1`. Human CLI/TUI surfaces may display or accept
the default-publisher shorthand `family.vN` for `aplane` key types, but storage,
protocol, provider registration, migration code, and SDK-facing fields use the
full canonical identifier.

In this document `family` always refers to the middle segment of
`publisher.family.vN`. Composed templates point at their signing provider via
`base_key_type` (e.g. `base_key_type: aplane.falcon1024.v1` signs with
Falcon-1024); their own identity is still named by the `family` segment of
their canonical `key_type`.

Built-in key types:

- `ed25519`
- `falcon1024`
- `falcon1024_ed25519`
- `ecdsak1`
- optional generic templates like `aplane.timed-whitelist.v1`, `aplane.whitelist.v1`, and `aplane.htlc.v1`
- optional Falcon-composed templates such as `aplane.falcon1024-whitelist.v1`, `aplane.falcon1024-hashlock.v1`, and `aplane.falcon1024-timelock.v1`

Creation parameters are part of the provider boundary. `internal/lsigprovider`
owns shared parameter metadata and normalization helpers used by UI adapters,
admin key operations, key generation, and template expansion. Supported list
creation parameter types include `address[]` and `uint64[]`. `address[]` is
unordered by definition: values are trimmed, validated as comma-separated
address lists, and canonicalized into sorted order before address derivation,
TEAL generation, and key-file persistence. `uint64[]` values are likewise
treated as unordered and canonicalized numerically. Order-sensitive list
semantics require a separate explicit list type rather than changing these
unordered list types. Admin key generation/import canonicalizes provider params
at the admin boundary so persisted key files and API/admin responses are
stable; lower provider and key-generation layers normalize defensively because
they may be called outside the admin service path.

### Native Ed25519

`ed25519` is the native Algorand signing path. Its provider and mnemonic/keygen
components live under `internal/signing/ed25519`, and registration is wired
from binary entrypoints rather than hidden `init()` side effects.

### DSA-backed LogicSig providers

Built-in LogicSig DSA providers live under `lsig/`. The compiled providers are:

| Key type | Key-type family | Availability |
|---|---|---|
| `aplane.falcon1024.v1` | `falcon1024` | default-enabled |
| `aplane.falcon1024-att-ed25519.v1` | `falcon1024-att-ed25519` | library-visible |
| `aplane.falcon1024-att-falcon1024.v1` | `falcon1024-att-falcon1024` | library-visible |
| `aplane.falcon1024_ed25519.v1` | `falcon1024_ed25519` | library-visible |
| `aplane.ecdsak1.v1` | `ecdsak1` | library-visible |

These providers implement the unified `internal/lsigprovider.SigningProvider`
surface. `internal/logicsigdsa` is the DSA-oriented filtered view over
that unified registry.

### Generic LogicSig templates

Generic LogicSig templates are TEAL-only providers. `internal/genericlsig`
provides the template-oriented filtered view over the same unified registry.

Optional template YAML files under top-level `library/templates/` are install
sources, not active key types. They become active only after being installed
into an identity as encrypted `.template` files and then reloaded/unlocked by
the signer.

### Off-curve LogicSig salting

All APlane-generated LogicSig accounts are kept off the Ed25519 curve at
generation time. Straight Falcon, composed DSA templates, and generic templates
reserve a compiler-owned salt slot in generated TEAL. Template-backed programs
use a stack-neutral generated marker preamble
(`byte 0x41504c414e455f4c5349475f53414c545f56315f005f454e44; pop`) so algod
owns constant-block layout; bare compiled DSA programs may use a
fixed provider-owned `bytecblock 0x00` preamble. After algod compilation,
`internal/lsigsalt` patches the salt byte through counters `0..255` and keeps
the first compiled bytecode whose LogicSig address is off-curve. Bytecblock
salting verifies the fixed preamble location, while marker salting matches
exactly one APlane-owned marker rather than a generic `pushbytes 0x00`. The
selected counter is stored in the key file as `salt_counter`; signing
uses the stored bytecode and does not recompute salting from a live template.

## Unified Registry

`internal/lsigprovider` is the single runtime registry for LogicSig providers.
It defines:

- `LSigProvider` for shared identity/display/parameter metadata
- `SigningProvider` for LogicSig DSA signature metadata and derivation
- `MnemonicProvider` for DSA mnemonic metadata

`internal/logicsigdsa` and `internal/genericlsig` are not separate registries.
They are filtered views into `internal/lsigprovider`.

Private-key signing, key generation, and mnemonic generation/import execution
live in signer-side registries, not in `internal/lsigprovider`.

The runtime model:

- compiled providers are registered during process startup
- enabled installed YAML templates are registered during identity reload/unlock
- lookup is by stable versioned `key_type`
- family lookup is metadata, not a second source of truth

## Registration And Visibility

Compiled LogicSig providers are registered through `lsig.RegisterClient()` for
client-safe metadata/derivation and `lsig/signerreg.RegisterSigner()` for
signer-side signing, keygen, and mnemonic handlers. Ed25519 follows the same split through
`internal/signing/ed25519.RegisterClient()` and
`internal/signing/ed25519.RegisterSigner()`.

Compiled provider registration is distinct from default visibility. The
`internal/keytypecatalog` package records whether a compiled key type is
default-enabled, library-visible, or disabled. Registered but non-default
providers remain binary capabilities, but are filtered out of generation
surfaces until an identity activation layer enables them. Terminology is
intentional: **registered** means provider code exists in a process-global
registry; **default-enabled** and **library-visible** are catalog availability
states; **activated** means an identity has opted into a library-visible
compiled provider; **installed** means an identity has an encrypted YAML
template; **enabled** means the key type appears in identity discovery,
generation, and import surfaces. See [DEV_KEYTYPES.md](DEV_KEYTYPES.md) for
the full glossary.

Visibility states recorded by `internal/keytypecatalog`:

- `default_enabled`: visible to every identity
- `library`: compiled capability exists but needs identity activation
- `disabled`: compiled in source, not exposed by the owning runtime path

Identity-scoped key type enable/disable metadata is owned by
`internal/keytypestate`. State records live under
`identities/<identity>/keytypes/<key_type>.json` via
`internal/storepaths.Paths.KeyTypeRecord()`. They make compiled
library-visible providers such as `aplane.falcon1024-att-ed25519.v1`,
`aplane.falcon1024-att-falcon1024.v1`, `aplane.falcon1024_ed25519.v1`, and
`aplane.ecdsak1.v1` available to that identity for key type discovery and
generation when `source:"compiled"` and `state:"enabled"`. Mnemonic import is
gated separately by the provider's explicit mnemonic-import capability.
Installed YAML templates use the same record with `source:"yaml_generic"` or
`source:"yaml_composed"` and store the encrypted template body in the adjacent
`identities/<identity>/keytypes/<key_type>.template` file.

Activation is exposed over the admin protocol with `activate_key_type`; for
compiled providers this writes or enables the compiled state record, and for
installed YAML templates this sets the record state to enabled and reloads the
identity. Deactivation is exposed over the admin protocol with
`deactivate_key_type`; for compiled providers this removes the state record
after verifying that no identity key uses that `key_type`, and for installed
YAML templates this verifies no identity key uses that `key_type`, then sets
the record state to disabled without removing the encrypted template. Removing
a YAML template remains destructive and is also blocked while any stored
identity key depends on that `key_type`. Restoring a key for a library-visible
compiled provider also creates the same identity state record idempotently.

Deletion archives are identity-local. Key deletion moves encrypted key files to
`identities/<identity>/deleted/keys/`; template removal moves encrypted
template files to `identities/<identity>/deleted/keytypes/`. These archives are
outside active key/template scans.

Optional YAML templates have a source-library lifecycle:

- repository and release source files live under the top-level `library/templates/` directory,
- install and test setup flows copy those plaintext YAML files into the signer data root at
  `<APSIGNER_DATA>/library/templates/`,
- `internal/storepaths.Paths.TemplateLibraryDir()` is the source of truth for the signer-data library path,
- library YAML files are reference material only; they are not active key types by being present on disk,
- `apadmin` browses the signer-data library over the admin IPC protocol,
- installing a library template parses and encrypts the YAML into the identity-scoped template store under
  `identities/<identity>/keytypes/<key_type>.template` and writes an enabled state record,
- the identity reload path applies key-type state records, skips disabled installed templates, activates enabled
  installed templates, and registers providers before key scanning.

The user-facing mixed library is the KeyType Library. It can list both YAML
template entries and compiled-provider entries. Template entries are installed
from YAML and can then be enabled or disabled for the identity; compiled-provider
entries are enabled or disabled for the identity.

The encrypted identity-scoped `.template` files are the runtime source of truth
for optional key-type generation and discovery, not for signing already-created
keys. The plaintext `library/templates/` copy is only an install source and may
be refreshed by installer or packaging flows without changing active key types
until an admin installs a template.

Relevant registries:

- client-visible LogicSig metadata: `internal/lsigprovider`,
  `internal/logicsigdsa`, `internal/genericlsig`
- compiled-provider visibility: `internal/keytypecatalog`
- algorithm metadata: `internal/algorithm`
- client-safe address derivation: `internal/addressderive`
- signer-side signing providers: `internal/signing/registry.go`
- signer-side mnemonic handlers: `internal/mnemonic`
- signer-side key generators: `internal/keygen`
- signer-side key processors

## Key-Type Source Model

The key-type source model is:

| Source | Meaning |
|---|---|
| Go-defined compiled provider | Built into the binary and registered at startup |
| User-loaded YAML | Installed into the identity keystore and registered on reload/unlock if enabled |

"Registered" and "visible for generation" are different concepts.
For terminology and lifecycle rules, defer to
[`DEV_KEYTYPES.md`](DEV_KEYTYPES.md).

## Storage And Encryption

### `.keystore`

Keystore metadata is defined in `internal/crypto/encryption.go`.

- new keystores are version 2
- version 1 metadata remains readable for compatibility
- version 2 metadata must include nonzero `kdf_time`, `kdf_memory`, and
  `kdf_threads`
- passphrases are verified and converted into a master key using Argon2id

### `.key`

Encrypted key files hold native keys, DSA-backed LogicSig keys, and generic
LogicSig instances. Compatibility is split across:

- `envelope_version` for the encryption envelope
- `format_version` for the decrypted payload schema

LogicSig entries store salted bytecode, `salt_counter`, signing metadata, and
parameters rather than reconstructing authorization from a live template at
sign time. DSA-backed entries also carry the base signing metadata needed to
produce provider-specific signatures.

### `.template`

Installed template definitions are stored as encrypted YAML. They are the
runtime source of truth for optional installed templates. Template removal moves
the encrypted source into the identity-local deleted-template archive rather
than treating the library YAML as active state.

### Encryption model

`internal/crypto` uses AES-256-GCM for encryption.

- master-key encryption is `envelope_version: 1`
- standalone passphrase-based encryption used for backup/export is
  `envelope_version: 2`

The master key is derived once at unlock time from `.keystore` metadata and is
then reused for key/template decryption until lock.

## Keystore Runtime

`internal/keystore.FileKeyStore` is the concrete keystore.

It owns:

- identity-scoped key directory resolution
- master-key caching and zeroing
- scan-time `address -> KeyScanInfo` caching
- on-demand decryption of specific keys

`internal/keystore.KeySession` is the runtime guard that tracks whether key use
is allowed. The signer's lock/unlock lifecycle uses this split:

- unlock derives the master key, scans templates, scans keys, and activates the
  key session
- lock clears master-key material, destroys the key session, and invalidates
  runtime access

## Signing Behavior

### Native Ed25519

Native keys sign transactions directly using the standard Algorand path.

### DSA-backed LogicSig

LogicSig DSA providers:

- generate or import key material
- derive salted off-curve LogicSig bytecode and address
- sign the provider-specific message
- build `LogicSig.Args` in provider-defined order

The signer server owns canonical group shaping, dummy calculation, fee
pooling, and final transaction assembly.

### Generic LogicSig

Generic templates:

- compile TEAL-derived bytecode and apply off-curve salting at generation time
- validate creation params and runtime args
- build `LogicSig.Args` from runtime args only
- do not use cryptographic private signing keys

## Template Lifecycle

Optional templates follow this lifecycle:

1. plaintext YAML exists in `library/templates/` or another supplied path
2. admin installs it with `apstore template import`
3. installation encrypts the YAML into `keytypes/<key_type>.template` and writes an enabled state record
4. reload/unlock registers enabled installed templates before key scanning
5. disable sets the state record to `disabled` and keeps the encrypted `.template`
6. remove deletes the state record and archives the encrypted `.template`

That lifecycle is compatibility-sensitive. A template-backed `key_type` cannot
be redefined in place. Disabling an installed YAML template is a reversible
state-only hide from future discovery and generation, and removing the encrypted
installed template archives the template file and deletes its state record. Both
operations are blocked while identity keys still depend on that `key_type`;
compiled-provider deactivation uses the same unused-key guard because it removes
the identity's compiled-provider opt-in.

## Security Notes

- Private key material stays on the signer host.
- Passphrases and decrypted key data are zeroed promptly with
  `crypto.ZeroBytes`.
- The master key is cached only while unlocked.
- Template registration happens before key scanning on reload/unlock so key
  discovery sees the correct enabled provider set.
- The versioned `key_type` is the stable compatibility identifier across
  storage, UI, and protocols.

## Source Of Truth Files

Start here when changing the subsystem:

- `internal/lsigprovider/provider.go`
- `internal/lsigprovider/registry.go`
- `internal/logicsigdsa/dsa.go`
- `internal/genericlsig/registry.go`
- `lsig/all.go`
- `internal/keytypecatalog/catalog.go`
- `internal/keytypestate/state.go`
- `internal/crypto/encryption.go`
- `internal/keys/file_types.go`
- `internal/keys/lsig_file.go`
- `internal/keystore/file.go`
- `internal/keystore/session.go`
- `internal/signerapp/templates/reload.go`
- `docs/DEV_KEYTYPES.md`
- `docs/ARCH_SPEC.md`
- `docs/ARCH_CONTRACTS.md`
