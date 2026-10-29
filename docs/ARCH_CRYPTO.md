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
  `f1`; this release supports consensus v42 and v43 and carries a two-base-fee PQ
  contribution
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
| Built-in LogicSig families | `lsig/`, especially `lsig/falcon1024`, `lsig/ed25519lsig`, `lsig/falcon1024_guarded`, `lsig/composeddsa`, `lsig/generictemplate`, `lsig/rotatingtriplewots`, `lsig/rotatingtriplexmss`, `lsig/rotatingtripleslhdsa`, `lsig/rotatingfamily` |
| Algorithm metadata, keygen, mnemonics | `internal/algorithm`, `internal/keygen`, `internal/mnemonic` |
| Key-type visibility and state | `internal/keytypecatalog`, `internal/keytypestate`, `internal/defaultkeytypes` (new-store default key-type installation) |
| Encrypted key/template persistence | `internal/crypto`, `internal/keys`, `internal/keystore`, `internal/templatestore`, `internal/templatelibrary` |
| Signer reload and template registration | `internal/signerapp/templates` |

## Provider Model

Provider registration is explicit and idempotent:

- binary entrypoints call `RegisterProviders()`,
- `lsig/clientreg.RegisterClient()` aggregates client-safe LogicSig metadata and derivation,
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

- `cmd/apshell` calls `lsig/clientreg.RegisterClient()` and
  the client registration for native Ed25519 and Falcon. It must not populate
  signer-side signing, keygen, mnemonic, or key-processor registries or link
  `github.com/algorand/falcon`.
- `cmd/apsigner`, `cmd/apadmin`, `cmd/apstore`, and local `cmd/apconsole`
  composition call `lsig/signerreg.RegisterSigner()` plus Ed25519 and native
  Falcon signer registration.
- `internal/logicsigdsa.LogicSigDSA` is metadata and derivation only; it does
  not expose `GenerateKeypair` or `Sign`.
- `internal/lsigprovider.SigningProvider` and `MnemonicProvider` expose
  compatibility-bearing metadata, not signer execution.
- LogicSig private-key execution is wired through explicit signer-side handles
  such as `internal/signing.LogicSigSignerOps`,
  `lsig/dsafamily/signerreg.LogicSigKeygenOps`, and provider `signerops`
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

For key-type naming, `family` is the middle segment of
`publisher.family.vN`; compiled providers register a publisher-qualified
`Family` (`publisher.family`), and provider `RoutingFamily()` is a separate
routing key (see [ARCH_KEYTYPES.md](ARCH_KEYTYPES.md#the-three-axes)). Composed templates point at their signing provider via
`base_key_type` (e.g. `base_key_type: aplane.falcon1024.v1` signs with
Falcon-1024); their own identity is still named by the `family` segment of
their canonical `key_type`.

Built-in and bundled key types include:

- native `ed25519`
- native `falcon1024` (top-level protocol `PQsig`, 25-word recovery)
- plain DSA LogicSigs `aplane.falcon1024.v1` and `aplane.ed25519.v1`
- the Falcon-only dedicated cosigner account `aplane.falcon1024-cosigner1024.v1`
- the Falcon witness key `aplane.witness-falcon1024.v1`, used under separate
  cosigner and contract-admin custody capabilities
- the generic `aplane.htlc.v1` template
- bounded Falcon templates: `aplane.falcon1024-allowlist.v1`,
  `aplane.falcon1024-allowlist.v2`, `aplane.falcon1024-timelock.v1`, and
  `aplane.falcon1024-allowlist-alock.v1`, plus the bounded-cosigner
  `aplane.corridor.v1`
- the rotating account `aplane.rotating-triple-wots.v1` (library-visible,
  signer-only)

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

| Key type | Registered family | Availability |
|---|---|---|
| `aplane.falcon1024.v1` | `aplane.falcon1024` | default-enabled |
| `aplane.falcon1024-cosigner1024.v1` | `aplane.falcon1024-cosigner1024` | library-visible |
| `aplane.ed25519.v1` | `aplane.ed25519` | library-visible |

These providers implement the unified `internal/lsigprovider.SigningProvider`
surface. `internal/logicsigdsa` is the DSA-oriented filtered view over
that unified registry.

`aplane.rotating-triple-wots.v1` is also a compiled, library-visible
catalog entry, but it has no client-side LogicSig provider and does not
register in `internal/lsigprovider`; signer binaries register its storage,
stage cryptography, and generator through `lsig/signerreg`.

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
Falcon, Ed25519 LogicSig, guarded cosigner, composed DSA, and explicit
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

The rotating accounts (`aplane.rotating-triple-wots.v1`,
`aplane.rotating-triple-xmss.v1` and `aplane.rotating-triple-slhdsa.v1`) are the one exception to both rules. They
store no bytecode: each stage's
program is assembled locally from a frozen template and the stage's public
constants, and when the unsalted address is on-curve, the stage package
appends `intcblock 1 <salt>` with the lowest salt in `[0, 128)` that gives an
off-curve address, exactly as the TEAL v13 assembler does. Stage derivation
owns this rule because stages must be derived offline, at every request and
in bulk in the background, without trusting a node for addresses. A test
compares the local bytes with algod's assembler output for salted and
unsalted stages.

A WOTS triple stage requires three signatures, each over the TxID: a Falcon-1024
signature, an Ed25519 signature (`ed25519verify_bare`) and a Winternitz
one-time signature (`internal/crypto/wots`): n = 32, w = 16, 64 message
digits and 3 checksum digits, 67 SHA-256 chains of 15 steps, with the
SPHINCS+ "simple" tweakable hash
`F(T, c, j, x) = SHA-256(T || u64be(c*256 + j) || x)` and a per-stage tweak
`T = SHA-256("APLANE_WOTS_V1" || G || tag || u64be(i))`, where the public
account tag is HKDF output of the seed alone. The stage program verifies the
WOTS signature with `sha256`, `itob` and `concat` only. A forgery needs a
break of SHA-256, of the Falcon lattice assumption and of Ed25519 at once.

A WOTS key must sign one message; the rotation makes every stage sign once
in normal operation. A twice-signed stage (after an expired release and its
repair, or a client re-signing a rebuilt transaction) loses only the WOTS
half and still rests on Falcon-1024 and Ed25519 until the next release
lands. Nothing prevents the second signature; the signer reports it
(`ARCH_SIGNING.md`, rotating alerts).

`aplane.rotating-triple-xmss.v1` replaces the per-stage WOTS key with RFC
8391 XMSS (`internal/crypto/xmss`, parameter set `XMSS-SHA2_16_256`: SHA-256,
n = 32, w = 16, h = 16). One tree of 65,536 one-time leaves serves 1,024
consecutive stages, and each stage owns 64 of its leaves: stage `n` uses
tree `n div 1024` and indices `64 (n mod 1024)` onward, a range its stage
program enforces on the index the signature carries. The construction is
the RFC's: a 32-byte hash address per call, `PRF`, `PRF_keygen` as the
reference implementation and SP 800-208 define it, masked WOTS+ chains, an
L-tree over the 67 chain ends, and a 16-level authentication path, with
`H_msg(r || root || idx, TxID)` as the signed message. Public keys and
signatures are byte-compatible with the XMSS reference implementation: the
package's vectors come from an independent implementation checked against
it, and the reference's own SHA-256 vector is reproduced in the tests. The
stage program verifies all of it with `sha256`, `concat`, `extract3`,
`replace3`, `b^` and one subroutine, at 25,507 plus 134 per chain step: the
`toByte(3) || SEED` prefix of every `PRF` call is hoisted into the per-phase
address prefixes, a chain step is kept as `step << 32` so one `itob` yields
both trailing address words, and the chain element and node inputs stay on
the stack.

The stage accepts a signature only when the hashed message's WOTS+ checksum
is at most 511 (`stage.MaxChecksum`). With a, b, d the hexadecimal digits of
the checksum, a verifier runs exactly 45 + 255a + 15b chain steps, so the
cap bounds an accepting run at 525 steps (a checksum of 512 already needs
555) and the program's cost at 25,507 + 134 × 525 = 95,857, which with the
4,179 argument bytes makes a five-transaction group. The signer meets the
cap by choosing the randomizer `r = PRF(SK_PRF, toByte(c, 28) ||
toByte(idx, 4))` for the first counter c = 0, 1, ... (at most 64,
`xmss.SignBounded`) whose message hash qualifies. Counter 0 is RFC 8391's
own input, so about four signatures in five are byte-identical to the RFC
signer's, and every signature verifies under any RFC 8391 verifier, which
reads `r` from the signature: the package's vector file carries 32 bounded
signatures, 10 of them with a searched randomizer, that the independent
oracle verified when it generated the file and that the signer must
reproduce byte for byte. The result is the RFC 8391 XMSS-SHA2_16_256
signature format and verification equations with deterministic
checksum-bounded randomizer selection and a stage-level checksum
constraint; the stage refuses some valid RFC signatures, and the signer
claims no RFC or SP 800-208 conformance for its signing procedure. The cap
does not weaken the one-time signature: a forgery must dominate the
released digits on all 67 chains, dominating the 64 message chains forces
the forger's checksum to be at most the released one, and dominating the
three checksum chains forces it to be at least that, so every digit must be
equal. That argument uses only the monotone checksum encoding, never the
distribution of the released digest, and the cap only removes signatures
the stage would otherwise accept. (The same grinding in a stronger form,
fixing the checksum and dropping its chains, is WOTS+C in the SPHINCS+C
proposal.) A leaf signed twice over different messages is broken with or
without the cap, as the leaf rule documents.

Per tree the signer derives the XMSS secret seed, PRF key and public seed
(HKDF label `APLANE_ROTATING_XMSS_V1`, tags `0x20` to `0x22`, counter = tree
number, genesis hash in every expansion); per stage the Falcon-1024 and
Ed25519 seeds as the triple does. The tree's public nodes (about 4 MiB) are
a cache the signer rebuilds from the seed; no secret is cached.

The claim differs from the triple's in one respect. A leaf must sign one
message, and a stage normally uses one leaf per transaction, so a stage can
release up to 64 distinct transactions before any leaf repeats; the signer
chooses leaves (`ARCH_SIGNING.md`, rotating accounts) and reports a repeat.
A repeated leaf weakens that leaf's one-time property for the rest of the
stage, and the stage rests on Falcon-1024 and Ed25519 until the next
rotation lands, exactly as a twice-signed triple stage does; the successor's
program rejects the retired range, so the exposure ends there. The
signature format, verifier and parameter set are RFC 8391; index
management is best effort, so the signer is not a conformant stateful
XMSS signer in the sense of RFC 8391 or SP 800-208, and makes no such claim.

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

Compiled LogicSig providers are registered through `lsig/clientreg.RegisterClient()` for
client-safe metadata/derivation and `lsig/signerreg.RegisterSigner()` for
signer-side signing, keygen, and mnemonic handlers. Ed25519 follows the same split through
`internal/signing/ed25519.RegisterClient()` and
`internal/signing/ed25519/signerreg.RegisterSigner()`; native Falcon uses
`internal/signing/falcon1024.RegisterClient()` and
`internal/signing/falcon1024/signerreg.RegisterSigner()`.

Compiled provider registration is distinct from default visibility. The
`internal/keytypecatalog` package records whether a compiled key type is
default-enabled, library-visible, or disabled. Registered but non-default
providers remain binary capabilities, but are filtered out of generation
surfaces until the product-store activation layer enables them. Terminology is
intentional: **registered** means provider code exists in a process-global
registry; **default-enabled** and **library-visible** are catalog availability
states; **activated** means the product store has opted into a library-visible
compiled provider; **installed** means the product store has an encrypted YAML
template; **enabled** means the key type appears in product discovery,
generation, and import surfaces. See [DEV_KEYTYPES.md](DEV_KEYTYPES.md) for
the full glossary.

Visibility states recorded by `internal/keytypecatalog`:

- `default_enabled`: visible to the product runtime, subject to node-role gates
- `library`: compiled capability exists but needs product-store enablement
- `disabled`: compiled in source, not exposed by the owning runtime path

Product-store key type enable/disable metadata is owned by
`internal/keytypestate`. State records live under
the selected generation's `keytypes/<key_type>.json` via
`internal/storepaths.GenPaths.KeyTypeRecord()`. They make compiled
library-visible providers such as `aplane.falcon1024-cosigner1024.v1` and
`aplane.ed25519.v1` available to the product runtime for key type discovery and
generation when `source:"compiled"` and `state:"enabled"`. Mnemonic import is
gated separately by the provider's explicit mnemonic-import capability.
Installed YAML templates use the same record with `source:"yaml_generic"` or
`source:"yaml_composed"` and store the encrypted template body in the adjacent
selected-generation `keytypes/<key_type>.template` file.

The operator-facing CLI and TUI expose these transitions as `Enable` and
`Disable`. The stable admin protocol wire messages remain `activate_key_type`
and `deactivate_key_type`: for compiled providers, enable writes or refreshes
the compiled state record and disable removes it after verifying that no
product-store key uses that `key_type`; for installed YAML templates, enable sets
the record state to enabled and disable verifies the same unused-key guard, then
sets the record state to disabled without removing the encrypted template.
Removing
a YAML template remains destructive and is also blocked while any stored
product-store key depends on that `key_type`. Restore preserves credential
signing authority without creating provider activation records; destination
generation/discovery enablement remains local configuration.

Deletion archives are product-store. Key deletion moves encrypted key files to
the selected generation's `deleted/keys/`; template removal moves encrypted
template files to its `deleted/keytypes/`. These archives are
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
  the selected generation's `keytypes/<key_type>.template` and writes an enabled state record,
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
| User-loaded YAML | Installed into the product keystore and registered on reload/unlock if enabled |

"Registered" and "visible for generation" are different concepts.
For terminology and lifecycle rules, defer to
[`DEV_KEYTYPES.md`](DEV_KEYTYPES.md).

## Storage And Encryption

### `store-root.enc` and `.keystore`

`internal/crypto/store_root.go` defines strict `aplane.store-root.v1`. The
record combines the passphrase-wrapped `aplane.keyring.v3` payload with the
selected generation ID and a current-term selection MAC. The MAC includes an
exact digest of the wrapped-keyring subobject, preventing keyring/selector
mix-and-match.

The keyring contains a single current term plus any retained historical terms
and exact generation-seal anchors. Ordinary envelope and integrity operations
authorize only the current term. Retired terms are exposed only through the
anchor-gated historical APIs in `internal/genstore`.

The plaintext root header carries the bounded Argon2id parameters and salt
needed to derive the KEK. The keyring payload is AES-256-GCM sealed; successful
unwrap is the passphrase check. The KEK is zeroed before return and is not
cached. Strict parsing and size/KDF limits run before expensive derivation.

Ordinary generation commits authenticate a fresh exact root read under the
mutation lock, preserve its wrapped-keyring bytes, and recompute only the
selector and MAC. Passphrase change creates a fresh term and publishes the new
wrapped keyring with the successor selector in that same atomic replacement.
There is no pending-term authority or resumable rotation state.

`.keystore` is the static version 6, `store-root/v1` layout gate. Older stores
are rejected with rebuild-from-backup guidance; no in-place migration or
compatibility parser is provided.

Term keys are random stored keys, not passphrase-derived values. JSON base64
encoding creates short-lived immutable string copies during root seal/open;
they do not persist for a session. Eliminating those copies would require a
binary root payload.

### `.key` and `.cos`

Encrypted `.key` files hold Algorand account authority: native keys,
DSA-backed LogicSig keys, and generic LogicSig instances. Encrypted `.cos`
files hold cosigner-custodied witness authority. Both use the same keystore
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
parallelism 4. A single-credential envelope is limited to 1 MiB
(`MaxStandaloneEnvelopeBytes`); larger envelopes, such as the sealed backup
manifest and archived policy documents, pass an explicit bound to
`DecryptStandaloneLimited`. Missing or
different KDF values require a new envelope version and are rejected before
Argon2id runs.

The term envelope's additional authenticated data binds the term and the
object's logical identity: a class and a canonical selector.

| Class | Selector |
| --- | --- |
| `account-key` | Algorand address |
| `cosigner-credential` | Witness Key ID |
| `keytype-template` | key type |
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
operations are blocked while product-store keys still depend on that `key_type`;
compiled-provider disable uses the same unused-key guard because it removes
the product store's compiled-provider opt-in.

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
- `lsig/clientreg/register.go`
- `internal/keytypecatalog/catalog.go`
- `internal/keytypestate/state.go`
- `internal/crypto/keyring.go`
- `internal/crypto/store_root.go`
- `internal/crypto/term_envelope.go`
- `internal/crypto/encryption.go`
- `internal/keys/file_types.go`
- `internal/keys/payload_codec.go`
- `internal/keystore/file.go`
- `internal/keystore/session.go`
- `internal/signerapp/templates/reload.go`
- `docs/DEV_KEYTYPES.md`
- `docs/ARCH_OVERVIEW.md`
- `docs/ARCH_CONTRACTS.md`

## Rotating SLH-DSA triple

`aplane.rotating-triple-slhdsa.v1` is an **experimental**, opt-in compiled implementation of
`rotating1`. Its stage requires Falcon-1024, Ed25519 and SLH-DSA signatures,
the last under a rescaled parameter set: the SLH-DSA-SHA2-128s construction
of FIPS 205 with its hypertree shortened from seven layers of height 9 to
two layers of height 11 (`slhdsa.Rescaled128`). That set is not a FIPS 205
parameter set. `internal/crypto/slhdsa` owns the primitive, which is
parametric in the hypertree shape; `lsig/rotatingtripleslhdsa` owns the
frozen stage, private operations and codec. The primitive's pinned NIST ACVP
vectors run the standard SLH-DSA-SHA2-128s shape through the same code the
rescaled shape uses, covering key generation, deterministic and randomized
signing, and positive/negative verification; the rescaled shape is pinned by
golden vectors of its own.
Independent security review and production qualification are still pending;
passing vectors and pinning compatibility bytes do not establish either.
The [evaluation record](SLHDSA_EVALUATION.md) specifies the lifetime signing
envelope, preparation policy, reproducible lifecycle benchmarks and remaining
qualification gates.

The design record for this new implementation of an established contract:

1. **Identity and authority:** fixed account, fresh stage per spend; reuse
   existing rotating1 prepare/sign endpoints, canonical grouping, signer policy
   and approval. Same transaction types and guards as WOTS/XMSS: rekey away from
   sender, no ALGO close, validity span <=100. Signer derives the next stage and
   proves it opens. No cosigner or external-admin path is introduced.
2. **Cryptography and bindings:** all three signatures bind the raw 32-byte
   TxID, hence sender, genesis, group, next authority and validity window.
   SLH uses the pure external interface with empty context (`0000 || TxID`)
   and deterministic opt_rand = PK.seed. Parameters are n=16, h=22, d=2,
   h'=11, a=12, k=14, w=16: FORS, WOTS+ and every hash function are those
   of SLH-DSA-SHA2-128s; only the hypertree is shorter. The standard set's
   63-level hypertree exists so one key can sign 2^64 messages; a rotating
   stage key signs a handful, and the two-layer tree supports the per-stage
   signing bound stated in [SLHDSA_EVALUATION.md](SLHDSA_EVALUATION.md).
   There is no checksum cap or signature grinding.
3. **Derivation and custody:** existing network-bound HKDF with the distinct
   label `APLANE_ROTATING_TRIPLE_SLHDSA_V1`; per-stage tags 1 (Falcon), 2
   (Ed25519), 3 (SLH SK.seed), 4 (SLH SK.prf), 5 (SLH PK.seed). The stored
   64-byte BIP-39 seed is the sole secret. No new custody boundary or shared
   tree cache. Derived secret material is erased after use.
4. **Durable authority:** unchanged rotating credential shape; the stage-zero
   public record is seed16 || root16 || Falcon1793 || Ed25519 32 = 1857 bytes.
   Parsing rederives the entire stage-zero record; program bytes are derived,
   never persisted. Stage address tables remain reconstructible caches.
5. **Choreography and retries:** existing group-planning, fees, approval,
   dummy signing and recovery helpers. An explicit `StatelessHash` profile
   skips leaf selection/history and one-time reuse warnings. Release/expiry
   observations remain, including audit restoration; legacy audit leaf fields
   are zero placeholders and are discarded on restore for this profile.
   After expensive signing, the signer rereads authorizer and round and checks
   cancellation, unlocked generation and key presence before returning bytes.
   An aged window or changed stage requires fresh preparation. No signature is
   released or recorded on those failures.
6. **Resources and compatibility:** frozen TEAL v13 template, 2834 bytes
   unsalted / 2837 salted, canonical first off-curve salt as other rotating
   stages. Args 0..3 are R+FORS (2928), both HT layers (1472), Ed25519 (64),
   Falcon (<=1423): 5887 bytes total. Each stays below the AVM byte-value
   limit. The exact cost is 26825 + 41 times WOTS chain steps. A layer's
   checksum c lies in 0..480 and requires c + 45 - digitSum16(c) steps, at
   most 510; two layers give a ceiling of 68645, inside four transactions.
   The argument bytes decide the group: planning uses 6 transactions (5
   dummies), with no program surcharge and 6000 microAlgos at minimum fees.
   The key-type ID, derivation labels and tags are unchanged; the stage
   template, stage identities and resource profile changed when the
   hypertree was rescaled, a pre-release freeze decision rather than a
   compatible update. The height is a build-time constant
   (`internal/rotatingkey.RotatingSlhdsaHeight`): the stage package carries a
   frozen verifier, template, argument layout and measured cost model for
   both 22 and 63, and `internal/rotatingkey` the matching literals, so
   changing the constant and rebuilding selects the standard
   SLH-DSA-SHA2-128s shape instead (2863 / 2866 bytes, args R+FORS, four
   HT layers, three HT layers, Ed25519, Falcon, 9343 bytes, cost
   40888 + 41 times steps, ceiling 187258, ten transactions). The two
   heights are different accounts for the same seed; the constant is for
   evaluation while the type is experimental, not an operator setting.
7. **Evidence:** strict parser and salted/unsalted stock-assembler equality;
   pinned stage identities, network separation, per-component signature
   rejection, repeated stateless signing and secret erasure; library
   enablement/generation/storage tests; service rotation, restore, expiry and
   post-sign refusal tests. `TestRotatingSLHTripleOnChain` exercises actual
   transitions, obsolete authorizers, guards, damaged R/FORS/HT components,
   exact lengths and the declared opcode ceiling on both program shapes.
   Node measurements match the affine formula; this does not claim that a
   random signature attains the conservative all-layers maximum.
