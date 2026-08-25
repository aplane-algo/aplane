# Cryptographic Subsystem

This document describes the cryptographic architecture in APlane.
For the detailed key-type workflow and terminology, see
[`DEV_KEYTYPES.md`](DEV_KEYTYPES.md). For compatibility-bearing on-disk
contracts, see [`ARCH_CONTRACTS.md`](ARCH_CONTRACTS.md).

## Overview

APlane supports three authorization categories:

1. `ed25519` native signing keys
2. `falcon1024` protocol-native post-quantum signing keys
3. LogicSig authorization, including DSA-backed providers such as
   `aplane.falcon1024.v1` and generic templates such as `aplane.htlc.v1`

These share storage and runtime plumbing, but not the signing behavior:

- native Ed25519 signs directly into `SignedTxn.Sig`
- native Falcon signs directly into top-level `SignedTxn.PQsig` with scheme
  `f1`; it requires consensus v42 or an explicitly recognized compatible
  protocol and carries a two-base-fee PQ contribution
- DSA-backed LogicSig providers derive LogicSig bytecode and place a
  cryptographic signature in `LogicSig.Args`
- generic LogicSig templates authorize by TEAL only and use runtime args
  without cryptographic key material

## Package Layout

The cryptographic subsystem is split across these packages:

| Area | Primary packages |
|---|---|
| Native signing | `internal/signing`, `internal/signing/ed25519`, `internal/signing/falcon1024` |
| LogicSig provider interfaces, registry, and salting | `internal/lsigprovider`, `internal/logicsigdsa`, `internal/genericlsig`, `internal/lsigsalt` |
| Built-in LogicSig families | `lsig/`, especially `lsig/falcon1024`, `lsig/ed25519lsig`, `lsig/falcon1024_guarded`, `lsig/composeddsa`, `lsig/generictemplate` |
| Algorithm metadata, keygen, mnemonics | `internal/algorithm`, `internal/keygen`, `internal/mnemonic` |
| Key-type visibility and state | `internal/keytypecatalog`, `internal/keytypestate` |
| Encrypted key/template persistence | `internal/crypto`, `internal/keys`, `internal/keystore`, `internal/templatestore`, `internal/templatelibrary` |
| Signer reload and template registration | `internal/signerapp/templates` |

## Provider Model

Provider registration is explicit and idempotent:

- binary entrypoints call `RegisterProviders()`,
- `lsig.RegisterClient()` aggregates client-safe LogicSig metadata and derivation,
- `lsig/signerreg.RegisterSigner()` adds signer-side LogicSig signing/keygen/mnemonic handlers,
- native Ed25519, native Falcon, and the Ed25519 LogicSig provider are
  registered separately,
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
  the client registration for native Ed25519 and Falcon. It must not populate
  signer-side signing, keygen, mnemonic, or key-processor registries or link
  `github.com/algorand/falcon`.
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
without importing Falcon CGO packages or Falcon mnemonic code.

Signer-side key loading has one owner per concern. The keystore
(`internal/keystore`) parses and validates the decrypted canonical payload via
`internal/keys`, resolves the provider through
`signing.GetProviderForKey(keyType, baseKeyType)`, and passes the minimal typed
`signing.ProviderKey` (routing identity plus private key material) to
`Provider.LoadKeyMaterial`. Providers never parse durable storage JSON and
return only the key type and the cryptographic value; the keystore stamps the
storage metadata envelope (category, base key type, public key, bytecode,
parameters, signing args) onto the returned `KeyMaterial`. `ProviderKey` byte
slices are valid only for the duration of the load call — the keystore zeroes
them on return, so providers deep-copy anything they retain.

Provider registries are process-global compatibility registries. Key type names
are globally unique within one `apsigner` process. Availability is enforced by
the product keystore plus product-store key type state rather than a private
provider namespace. Compatible re-registration
of the same template definition is idempotent; conflicting same-`key_type`
definitions are reported/rejected.

Key type strings are canonical compatibility identifiers, not display labels.
Except for the native `ed25519` and `falcon1024` key types, APlane-defined LogicSig/template and
compiled-provider key types use `publisher.family.vN`, such as
`aplane.falcon1024.v1`, `aplane.htlc.v1`, or
`aplane.falcon1024-allowlist.v1`. Human CLI/TUI surfaces, storage, protocol,
provider registration, migration code, and SDK-facing fields use the full
canonical identifier.

In this document `family` always refers to the middle segment of
`publisher.family.vN`. Composed templates point at their signing provider via
`base_key_type` (e.g. `base_key_type: aplane.falcon1024.v1` signs with
Falcon-1024); their own identity is still named by the `family` segment of
their canonical `key_type`.

Built-in and bundled key types include:

- native `ed25519`
- native `falcon1024` (top-level protocol `PQsig`, 25-word recovery)
- plain DSA LogicSigs `aplane.falcon1024.v1` and `aplane.ed25519.v1`
- the Falcon-only dedicated sentry account `aplane.falcon1024-sentry1024.v1`
- the Falcon witness key `aplane.witness-falcon1024.v1`, used under separate
  sentry and contract-admin custody capabilities
- the generic `aplane.htlc.v1` template
- bounded Falcon templates: `aplane.falcon1024-allowlist.v1`,
  `aplane.falcon1024-allowlist.v2`, `aplane.falcon1024-timelock.v1`, and
  `aplane.falcon1024-allowlist-alock.v1`, plus the bounded-sentry
  `aplane.corridor.v1`

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

### Native Falcon-1024

`falcon1024` is Algorand protocol-native post-quantum authorization. Its
client-safe metadata and address derivation live in
`internal/signing/falcon1024`; signer-only generation, payload validation, and
transaction signing live below that package and link `github.com/algorand/falcon`.
Recovery uses a 25-word Algorand mnemonic encoding 32 bytes of entropy. It is
not compatible with the 24-word BIP-39 mnemonic or key material used by the
LogicSig key type `aplane.falcon1024.v1`.

### DSA-backed LogicSig providers

Built-in LogicSig DSA providers live under `lsig/`. The compiled providers are:

| Key type | Key-type family | Availability |
|---|---|---|
| `aplane.falcon1024.v1` | `falcon1024` | default-enabled |
| `aplane.falcon1024-sentry1024.v1` | `falcon1024-sentry1024` | library-visible |
| `aplane.ed25519.v1` | `aplane.ed25519` | library-visible |

These providers implement the unified `internal/lsigprovider.SigningProvider`
surface. `internal/logicsigdsa` is the DSA-oriented filtered view over
that unified registry.

### Generic LogicSig templates

Generic LogicSig templates are TEAL-only providers. `internal/genericlsig`
provides the template-oriented filtered view over the same unified registry.

Template YAML files under top-level `library/templates/` are install sources,
not active key types by presence alone. New signer-role stores initialize with
`aplane.falcon1024-allowlist.v1` installed and enabled as an encrypted
product-store `.template`; other templates become active only after
installation and reload/unlock by the signer.

### Off-curve LogicSig salting

All newly generated APlane LogicSig accounts are kept off the Ed25519 curve at
generation time by the TEAL v13 compiler's auto-salting assembler. Straight
Falcon, Ed25519 LogicSig, guarded sentry, composed DSA, and explicit
`derivation_version: 3` template paths compile through algod, accept the final
compiler-produced bytecode only when the reported address matches it, and
reject an on-curve result. The key file records
`lsig_derivation: algod_v13_auto_salt` and the authoritative final bytecode; it
must not also contain `salt_counter`.

Templates that omit `derivation_version` remain unsalted and succeed only when
their unmodified compiled bytecode already derives an off-curve address. The
retired marker and bytecblock counter styles remain in `internal/lsigsalt` only
for compatibility with already-created manual-counter key files and focused
validation tests. New template definitions reject derivation versions 1 and 2
and must not author a salt marker, salt preamble, or salt-style selector.
Signing always uses the stored final bytecode and never recomputes salting from
a live template.

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
- enabled installed YAML templates are registered during runtime reload/unlock
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

Product-store key type enable/disable metadata is owned by
`internal/keytypestate`. State records live under
`identities/default/keytypes/<key_type>.json` via
`internal/storepaths.Paths.KeyTypeRecord()`. They make compiled
library-visible providers such as `aplane.falcon1024-sentry1024.v1` and
`aplane.ed25519.v1` available to that identity for key type discovery and
generation when `source:"compiled"` and `state:"enabled"`. Mnemonic import is
gated separately by the provider's explicit mnemonic-import capability.
Installed YAML templates use the same record with `source:"yaml_generic"` or
`source:"yaml_composed"` and store the encrypted template body in the adjacent
`identities/default/keytypes/<key_type>.template` file.

The operator-facing CLI and TUI expose these transitions as `Enable` and
`Disable`. The stable admin protocol wire messages remain `activate_key_type`
and `deactivate_key_type`: for compiled providers, enable writes or refreshes
the compiled state record and disable removes it after verifying that no
identity key uses that `key_type`; for installed YAML templates, enable sets
the record state to enabled and disable verifies the same unused-key guard, then
sets the record state to disabled without removing the encrypted template.
Removing
a YAML template remains destructive and is also blocked while any stored
identity key depends on that `key_type`. Restoring a key for a library-visible
compiled provider also creates the same product-store state record idempotently.

Deletion archives are product-store. Key deletion moves encrypted key files to
`identities/default/deleted/keys/`; template removal moves encrypted
template files to `identities/default/deleted/keytypes/`. These archives are
outside active key/template scans.

Optional YAML templates have a source-library lifecycle:

- repository and release source files live under the top-level `library/templates/` directory,
- install and test setup flows copy those plaintext YAML files into the signer data root at
  `<APSIGNER_DATA>/library/templates/`,
- `internal/storepaths.Paths.TemplateLibraryDir()` is the source of truth for the signer-data library path,
- library YAML files are reference material only; they are not active key types by being present on disk,
- new signer-store initialization installs the bundled `aplane.falcon1024-allowlist.v1` YAML into the product store by default,
- `apadmin` browses the signer-data library over the admin IPC protocol,
- installing a library template parses and encrypts the YAML into the product template store under
  `identities/default/keytypes/<key_type>.template` and writes an enabled state record,
- the runtime reload path applies key-type state records, skips disabled installed templates, activates enabled
  installed templates, and registers providers before key scanning.

The user-facing mixed library is the KeyType Library. It can list both YAML
template entries and compiled-provider entries. Template entries are installed
from YAML and can then be enabled or disabled in the product store;
compiled-provider entries use the same product-store state.

The encrypted product-store `.template` files are the runtime source of truth
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

### `keyring.enc`

The keyring is the store's cryptographic root, defined in
`internal/crypto/keyring.go` and `internal/crypto/keyring_store.go`.

- schema `aplane.keyring.v2`, one product-store file beside `.keystore`
- plaintext header: Argon2id parameters and the KEK salt, so the file is
  self-describing
- sealed body: the set of numbered term keys, wrapped under the
  passphrase-derived KEK with AES-256-GCM
- sealed payload fields are `schema`, `current_term`, sorted `terms`, required
  `historical_anchors`, and optional `rotation`; fresh stores write one term
  and no pending rotation, while transition start appends one successor and
  publishes the pending descriptor
- each `HistoricalGenerationAnchor` binds a canonical generation ID to the
  exact byte size and SHA-256 of its pre-retirement generation seal
- a rotation descriptor's snapshot size/digest uses
  `RotationSnapshotReference`, which pins the exact encrypted snapshot under
  an independent 16 MiB cap; the payload validator and runtime enforce the
  same shape for pending multi-term roots
- ordinary envelope and integrity reads authorize exactly the current term
  when settled and the current plus `rotation.from_term` when pending; older
  resident terms are usable only through exact-anchor-gated historical APIs
- `crypto.StartRotation` rejects an existing descriptor, appends exactly one
  successor term, requires the target-term snapshot to be durable first, and
  publishes the descriptor, exact snapshot reference, and historical anchors
  in one root replacement
- `Keyring.RequireSettled` blocks ordinary signing and mutation during that
  descriptor's lifetime; normal reload maps `ErrRotationPending` to recovery,
  and offline passphrase/policy/generation mutation uses the same guard
- `rotationinventory.ResumeRotation` is the explicit internal bypass: it
  reopens the root-pinned snapshot, promotes only exact retiring-term inputs,
  and accepts already-written target-term outputs only after context-bound
  authentication; it does not close the descriptor
- `rotationinventory.CompleteRotation` verifies the final path/authority
  shape and baseline-before-close ordering before calling
  `crypto.CloseRotation`; close preserves terms and anchors while atomically
  removing only the pending descriptor
- a successful unwrap is the passphrase check; there is no separate verifier
- the KEK exists only inside seal and open, and is zeroed before either returns

Term keys are stored random keys, not passphrase-derived values. Fresh stores
start at term 1; multi-term residency does not itself grant current-state
authority.

Sealing and opening the root route term keys through base64 in Go strings,
which are immutable and so cannot be zeroed. Those copies live only inside the
seal and open calls, not for the life of a session, but they are a residual
the passphrase-derived master key did not have: that key was never serialized.
Removing it requires a binary payload layout rather than JSON.

### `.keystore`

`.keystore` is a static marker, defined in `internal/crypto/keyring_store.go`.

- `{"version": 5, "layout": "keyring/v2", "created": ...}`
- it carries no salt, no verifier, and no KDF parameters, so nothing in it can
  disagree with the keyring
- the version gate rejects any store this release did not initialize, before
  anything else is read

### `.key` and `.sen`

Encrypted `.key` files hold Algorand account authority: native keys,
DSA-backed LogicSig keys, and generic LogicSig instances. Encrypted `.sen`
files hold sentry-custodied witness authority. Both use the same keystore
term envelope and canonical payload codec; category determines the sole valid
extension. Compatibility is split across:

- `envelope_version` for the encryption envelope
- `format_version` for the decrypted payload schema

LogicSig entries store final bytecode, the `lsig_derivation` contract, signing
metadata, and parameters rather than reconstructing authorization from a live
template at sign time. Current compiler-auto-salted entries omit
`salt_counter`; compatible manual-counter entries retain it. DSA-backed entries
also carry the base signing metadata needed to produce provider-specific
signatures.

### `.template`

Installed template definitions are stored as encrypted YAML. They are the
runtime source of truth for optional installed templates. Template removal moves
the encrypted source into the product-store deleted-template archive rather
than treating the library YAML as active state.

### Encryption model

`internal/crypto` uses AES-256-GCM for encryption.

- at-rest encryption under a keyring term is `envelope_version: 3`, carrying
  `{envelope_version, term, nonce, ciphertext}`
- standalone passphrase-based encryption used for backup/export is
  `envelope_version: 2`

Standalone version 2 accepts exactly Argon2id time 2, memory 65,536 KiB, and
parallelism 4. The complete encoded envelope is limited to 1 MiB. Missing or
different KDF values require a new envelope version and are rejected before
Argon2id runs.

The term envelope's additional authenticated data binds the term and the
object's logical identity: a class and a canonical selector.

| Class | Selector |
| --- | --- |
| `account-key` | Algorand address |
| `sentry-credential` | Witness Key ID |
| `keytype-template` | key type |
| `rotation-snapshot` | fixed selector `pending` |
| `rotation-baseline` | fixed selector `current` |

The identity is logical, never a path: generations copy ciphertext between
namespaces and into `deleted/` without re-encrypting it. Binding it means a
credential filed under another account or a template opened as a credential
fails to decrypt.

`internal/rotationinventory` uses those contexts to open the same encrypted
buffer it hashes for the Phase 3 K8 inventory. `crypto.EnvelopeTerm` exposes
the envelope header for classification only; it is not authority without that
context-bound open. Snapshot recovery first verifies the pending root's exact
encrypted-file size and digest, then opens that same bounded, no-follow buffer
under `rotation-snapshot:pending`.

The divergence baseline is a separate small current-state authority.
`internal/rotationinventory` bounds its exact encrypted file to 4 KiB,
requires its envelope term to equal the keyring current term, and opens the
same buffer under `rotation-baseline:current` before strictly parsing the
record. Retired-term membership never authorizes a baseline.

Historical generation authority is deliberately separate from ordinary
current-state opening. `VerifyHistoricalGenerationSealIntegrity` verifies only
the generation-seal domain under a resident retired term, and
`OpenHistoricalGenerationEnvelope` opens only an explicitly expected resident
term. Callers do not receive a general retired-term grant:
`internal/genstore` must first match the exact `HistoricalGenerationAnchor`,
verify the anchored seal and exact manifest, and match an exact member
buffer's authenticated size, digest, and term before invoking the historical
open. Neither possession of the retired key nor possession of the anchor alone
is sufficient.

Unlock opens the keyring once and reuses its term keys for key and template
decryption until lock.

## Keystore Runtime

`internal/keystore.FileKeyStore` is the concrete keystore.

It owns:

- fixed product-store key directory resolution
- keyring caching and zeroing
- scan-time `address -> KeyScanInfo` caching
- on-demand decryption of specific keys

`internal/keystore.KeySession` is the runtime guard that tracks whether key use
is allowed. The signer's lock/unlock lifecycle uses this split:

- unlock opens the keyring, scans templates, scans keys, and activates the key
  session
- lock zeroes every term key, destroys the key session, and invalidates runtime
  access

## Signing Behavior

### Native Ed25519

Native keys sign transactions directly using the standard Algorand path.

### DSA-backed LogicSig

LogicSig DSA providers:

- generate or import key material
- compile and validate final off-curve LogicSig bytecode and address
- sign the provider-specific message
- build `LogicSig.Args` in provider-defined order

The signer server owns canonical group shaping, dummy calculation, fee
pooling, and final transaction assembly.

### Generic LogicSig

Generic templates:

- compile TEAL-derived bytecode and validate compiler-owned off-curve salting at
  generation time when derivation version 3 is selected
- validate creation params and runtime args
- build `LogicSig.Args` from runtime args only
- do not use cryptographic private signing keys

## Template Lifecycle

YAML templates follow this lifecycle:

1. plaintext YAML exists in `library/templates/` or another supplied path
2. new signer-store initialization or an admin installs it with `apadmin template import`
3. installation encrypts the YAML into `keytypes/<key_type>.template` and writes an enabled state record
4. reload/unlock registers enabled installed templates before key scanning
5. disable sets the state record to `disabled` and keeps the encrypted `.template`
6. remove deletes the state record and archives the encrypted `.template`

That lifecycle is compatibility-sensitive. A template-backed `key_type` cannot
be redefined in place. Disabling an installed YAML template is a reversible
state-only hide from future discovery and generation, and removing the encrypted
installed template archives the template file and deletes its state record. Both
operations are blocked while identity keys still depend on that `key_type`;
compiled-provider disable uses the same unused-key guard because it removes
the identity's compiled-provider opt-in.

## Security Notes

- Private key material stays on the signer host.
- Passphrases and decrypted key data are zeroed promptly with
  `crypto.ZeroBytes`.
- Term keys are cached only while unlocked.
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
- `internal/crypto/keyring.go`
- `internal/crypto/keyring_store.go`
- `internal/crypto/term_envelope.go`
- `internal/crypto/encryption.go`
- `internal/keys/file_types.go`
- `internal/keys/payload_codec.go`
- `internal/keystore/file.go`
- `internal/keystore/session.go`
- `internal/signerapp/templates/reload.go`
- `docs/DEV_KEYTYPES.md`
- `docs/ARCH_SPEC.md`
- `docs/ARCH_CONTRACTS.md`
