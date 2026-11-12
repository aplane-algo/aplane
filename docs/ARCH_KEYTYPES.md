# Key Types

> Key types and LogicSig providers: the dimensions that describe one signing
> authority, the canonical key type identifier, the authorization ontology, the
> three resolution axes, and the LogicSig provider registry, templates, and
> derivation.

This document explains how APlane composes key types, account-authorization
forms, LogicSig policy contracts, auxiliary authorities, signing flows, and
provider implementations. It also explains how the codebase answers questions
about a key type, and **why** there are three separate resolution mechanisms
rather than one. Read this before changing their boundaries (see
[Why not collapse them](#why-not-collapse-them)).

The [LogicSig providers](#logicsig-providers) section is the detailed registry
reference for one of the three axes (Resolve).

## Contents

- [Protocol dimensions and terminology](#protocol-dimensions-and-terminology)
- [Plain hosts](#plain-hosts)
- [Mnemonic backup and recovery](#mnemonic-backup-and-recovery)
- [Designing a new combination](#designing-a-new-combination)
- [Key type identifier contract](#key-type-identifier-contract)
- [Authorization object ontology](#authorization-object-ontology)
- [Key types summary](#key-types-summary)
- [Valid rekey target](#valid-rekey-target)
- [The three axes](#the-three-axes)
- [LogicSig providers](#logicsig-providers)
- [Account generation](#account-generation)
- [See also](#see-also)

## Protocol dimensions and terminology

APlane uses several independently versioned dimensions to describe one signing
authority. They answer different questions and must not be inferred from one
another merely because two dimensions currently use the same string.

| Dimension | Question it answers | Examples | Source of truth |
|---|---|---|---|
| **Key type** | What durable kind of account or witness key is this? | `ed25519`, `aplane.falcon1024.v1`, `aplane.witness-falcon1024.v1` | Stored `key_type`; provider/template definition |
| **Account authorization type** | What protocol-level mechanism authorizes the account? | native signature, DSA LogicSig, generic LogicSig | Key category and stored key material |
| **Authority lifecycle** | How does the account's authorizer evolve over time? | no mandatory rotation; mandatory per-spend rotation to the next stage (`rotating_lsig`) | Key category; for rotating types the `internal/rotatingkey` profile |
| **Authorization contract** | Which reusable, versioned on-chain envelope and metadata vocabulary constrain this LogicSig? | `bounded2` (bounded host), `plain1` (plain host) | Template `bounded.contract` and durable `bounded_authorization.contract` |
| **Policy/profile** | What concrete behavior narrows the account contract? | fixed allowlist, Merkle recipient proof, Corridor composition | Full key-type provider/template plus behavior parameters |
| **Base key type** | Which signature construction produces the account's DSA signature arguments? | `aplane.falcon1024.v1`, `aplane.ed25519.v1` | Stored `base_key_type` and composed provider definition |
| **Auxiliary authority enrollment** | Which additional authority participates, for which role or operation, and under whose custody? | cosigner witness | Embedded public key, durable metadata, and custody-specific message contract |
| **Signing flow** | Which versioned client/server protocol obtains a usable signature for this key? | empty ordinary flow, `bounded1`, `cosigned1`, `rotating1` | Signer-advertised `signing_flow` |
| **Endpoint choreography** | Which ordered calls implement the selected flow for this transaction path? | `/sign`; `/sign/component` then `/sign/assemble`; `/sign/rotating/prepare` then `/sign/rotating/sign` | Flow contract, transaction classification, and HTTP DTOs |
| **Provider and routing family** | Which registered implementation performs keygen, derivation, signing, or assembly? | composed provider routed through `aplane.falcon1024`; the plain host provider (`lsig/plainhost`) | Provider registry and `RoutingFamily()` |
| **Principal authorization** | May the authenticated caller invoke this operation on the target identity/resource? | `sign.request`, `sign.component`, `sign.assemble` | Reserved product principal, closed action allowlist, and HTTP/admin enforcement point |
| **Signer policy domain** | Which off-chain rules gate release of a signature that the key and on-chain program could produce? | client-signing policy, cosigner policy | Node role, the node's policy documents, and the selected policy key |
| **Network context** | Which configured network and network-scoped policy apply to the transaction? | `mainnet`, `voi_mainnet`, `localnet` | Transaction `GenesisHash` resolved to a network context token |

The terms are related, but none is a synonym for another:

- A **key type** is the stable, user-visible and durable identity of a key
  definition. It fixes the provider/template behavior that created the key.
- An **authorization contract** is a reusable versioned contract used by one or
  more key types. `bounded2` is currently the only bounded-authorization
  contract. Many key types may instantiate it with different profiles and
  behavior parameters.
- A **profile** is the concrete policy compiled for a key type or key instance.
  A bounded profile cannot widen the bounded envelope; a dedicated compiled
  policy owns its complete program outside that reusable bounded contract.
- An **auxiliary authority** is not automatically an account key or a policy.
  Its enrollment names a role, message domain, custody boundary, and the paths
  on which its signature is required.
- A **signing flow** is a wire-routing capability, not an on-chain program.
  Clients select it from inventory and must fail closed on unknown values.
- An **endpoint choreography** is the transaction-path-specific sequence inside
  a flow. One key-level flow can have more than one path: under the `bounded1`
  flow, a spend, a spending-key rekey, and a listed rekey all use ordinary
  `/sign`, but under their own argument-slot rules, and a rekey forces review.
- A **provider** is an implementation mechanism. Changing registry ownership or
  routing does not by itself change a key type, authorization contract, or
  signing flow, although behavior-visible changes may require versioning those
  contracts.

Three adjectives recur when combinations are discussed. Each has a narrow
meaning:

- **Nonrotating** means no mandatory per-spend rotation. It does not mean the
  account can never rekey. Rotating accounts keep a fixed address while each
  accepted spend transfers authority to the predetermined next stage.
- **Non-bounded** means outside the `bounded2` contract. It does not mean
  unrestricted: dedicated and custom programs constrain transactions too, and
  the rotating stage programs impose rotation, validity, and transaction-shape
  restrictions without being `bounded2` profiles.
- **Cosigned** means another authority participates in spending under a
  separate custody and authorization role. Falcon plus Ed25519 signatures
  derived from one signer-held seed are a multi-algorithm construction, not a
  cosigner.

The word **contract** has three related but distinct uses in APlane:

- An **authorization contract**, such as `bounded2`, is an on-chain LogicSig
  behavior and its canonical durable metadata vocabulary.
- A **wire or storage contract** is a compatibility-bearing DTO, file shape, or
  behavioral guarantee, indexed in `ARCH_CONTRACTS.md`.
- A **message or transcript contract** is an exact cryptographic encoding and
  domain, such as `APLANE_COSIGNER_V1` or `APLANE_BOUNDED_COSIGNER_ASSEMBLY_V1`.

Likewise, account authorization is distinct from principal authorization and
signer policy. The account key and LogicSig determine what can authorize the
Algorand account; the fixed product principal and closed action allowlist
determine whether the caller may invoke an APlane endpoint; signer or cosigner
policy determines whether that permitted call may release a signature for the
particular transaction.

`bounded2` (the bounded host) and `plain1` (the plain host) are the
authorization-contract identifiers. Their signing-flow labels are `bounded1` for
accounts that need no online cosigner and `cosigned1` for cosigned accounts. Flow labels version the
choreography, not the contract, so they do not follow the contract's number.
`cosigned1` replaced `bounded-cosigner1` when the cosigned flow began to carry
rekeys, so a client that knows only the spend-only choreography refuses a
cosigned key.
The contract identifier selects canonical on-chain and durable metadata
semantics; the flow label tells the client how to route a request. Likewise,
`cosigner1` is the embedded cosigner contract value, while `APLANE_COSIGNER_V1`
is the cryptographic component-message domain the cosigned flow uses. Neither
is a key type. (The retired dedicated cosigned account's signing-flow label was
also `cosigner1`; clients now treat that label as unknown and fail closed.)

### How the dimensions compose

For a generated account key, the relationship is:

```text
full key_type
  -> account authorization type
  -> provider/template and optional base_key_type
  -> optional reusable authorization contract and concrete profile
  -> optional auxiliary authority enrollments
  -> rendered bytecode + durable instance signing metadata
  -> inventory signing_flow and size/routing metadata
  -> client endpoint choreography for the classified transaction path
  -> authentication + principal authorization + signer policy gates
  -> signature release and final on-chain program enforcement
```

The full `key_type` remains the durable account identity throughout this chain.
The stored bytecode and versioned signing metadata, not the currently installed
template, are authoritative for signing an existing LogicSig key. Inventory is
a projection of that authority for clients; it does not replace the key file or
the on-chain program.

Runtime selection follows these rules:

1. The effective signer or `AuthAddr` selects the account key instance.
2. Its full `key_type` and durable metadata select account behavior and the
   implementation needed by the signer.
3. Signer inventory projects a `signing_flow`; the client routes on that field,
   not on key-type naming conventions, `base_key_type`, or provider family.
4. Transaction classification may choose a path-specific choreography inside
   the flow, such as bounded spend versus spending-key or listed rekey.
5. HTTP principal authorization decides whether the caller may invoke the
   endpoint. Signer or cosigner policy independently decides whether the specific
   transaction may receive a signature.
6. Assembly verifies signatures, argument placement, canonical transaction
   bytes, and the effective authorizer. The LogicSig program remains the final
   on-chain authority.

An auxiliary-authority overlay may be combined with a policy form only when an
explicit account contract, durable metadata shape, and signing flow define the
combination. The combination must not be inferred from a key-type substring or
from the presence of a witness key alone.

### Worked compositions

| Key type | Account authorization | Contract/profile | Base primitive | Auxiliary authority | Advertised flow and choreography |
|---|---|---|---|---|---|
| `ed25519` | Native | none | Ed25519, self-owned | none | empty flow; `/sign` |
| `falcon1024` | Native PQ | none | protocol Falcon-1024 scheme `f1`, self-owned | none | empty flow; `/sign`; supported consensus v42 or v43; top-level `PQsig` |
| `aplane.falcon1024.v1`, no parameters | DSA LogicSig | plain DSA program | Falcon-1024, self-owned | none | empty flow; `/sign` |
| `aplane.falcon1024.v1` or `aplane.ed25519.v1`, with a cosigner | DSA LogicSig | plain host `plain1`; any rekey setting | the type itself | signer-custodied Falcon cosigner on every spend and cosigned rekey | `cosigned1`; `/plan`, kind-tagged `/sign/component`, then `/sign/assemble` |
| `aplane.falcon1024.v1` or `aplane.ed25519.v1`, overlays without a cosigner | DSA LogicSig | plain host `plain1`; rekey refused, spending key or only these | the type itself | none | `bounded1`; `/sign` |
| `aplane.falcon1024.v1` or `aplane.ed25519.v1`, Allowlist preset | DSA LogicSig | plain host `bounded2`; framework recipient allowlist; spending-key rekey | the type itself | none | `bounded1`; spend and rekey through `/sign` |
| `aplane.falcon1024.v1`, Corridor preset | DSA LogicSig | plain host `bounded2`; framework Merkle recipient allowlist; rekey only to a listed address (*only these*) | the type itself | signer-custodied Falcon cosigner on spend, never on a listed rekey | `cosigned1`; `/plan`, kind-tagged `/sign/component`, then `/sign/assemble` |
| `aplane.rotating-triple-xmss.v1` | DSA LogicSig (`rotating_lsig`) | dedicated compiled stage program; a new program per spend | Falcon-1024 and Ed25519 stage keys and an RFC 8391 XMSS tree shared by 1,024 stages, derived from one seed | none | `rotating1`; the signer also chooses the stage's one-time leaf |
| `aplane.rotating-triple-slhdsa.v1` | DSA LogicSig (`rotating_lsig`) | dedicated compiled stage program; a new program per spend | Falcon-1024, two-layer SLH-DSA-SHA2-128 and Ed25519 per-stage keys derived from one seed | none | `rotating1`; stateless hash signing, no leaf allocation |
| `aplane.rotating-triple-wotsc.v1` | DSA LogicSig (`rotating_lsig`) | dedicated compiled stage program; a new program per spend | Falcon-1024, Ed25519 and a tree of 64 WOTS+C keys per stage, derived from one seed | none | `rotating1`, as XMSS; the signer chooses the stage's one-time leaf |
| `aplane.htlc.v1` | Generic LogicSig | generic TEAL HTLC policy | none | none | empty flow; ordinary LogicSig assembly through `/sign` |

The examples describe the currently implemented architecture. A future change
that composes dimensions differently must update the relevant contract and flow
rather than silently teaching clients to infer a new combination.

### Independent version boundaries

Version the dimension whose compatibility contract changes:

| Change | Version boundary |
|---|---|
| Concrete program behavior or key-definition semantics | New `key_type` version |
| Bounded envelope, canonical profile, argument-source vocabulary, or admin transcript | New bounded authorization contract, such as `bounded2`, and affected key types |
| Client/server component ordering, required endpoints, or assembly DTO semantics | New `signing_flow` label |
| Cryptographic message shape | New message-domain version and every program/flow that verifies it |
| Template syntax without changing an existing key's durable behavior | Template schema version |
| Durable key signing metadata shape | `signing_metadata_version` |
| HTTP or SDK payload shape | Versioned endpoint/DTO contract according to `ARCH_SIGNING.md` |

These versions may advance independently. A key type version must still pin the
complete behavior it relies on, and compatibility-bearing changes commonly
require advancing more than one dimension together.

## Plain hosts

`aplane.falcon1024.v1` and `aplane.ed25519.v1` are plain hosts
(`lsig/plainhost`, which wraps each family's plain provider). One key type per
base offers every overlay and every bound. `aplane.falcon1024.v1` is
default-enabled on signer nodes, so every signer can create its accounts with no
setup, and it does not appear in the KeyType Library. `aplane.ed25519.v1` is
library-visible: opt-in per node through `apadmin keytype enable` or the KeyType
Library, then created like any other key type.

- **With no parameters** a plain type is the plain program: the bare
  spending-key check. It is the composition base every bounded and composed
  account names as `base_key_type`, the program of restored plain keys, and an
  account of its own. Expert templates name either type as their base without
  enabling it for standalone creation; the template's own enablement applies.
- **With overlay parameters only** (`rekey_authority` `refused`,
  `spending_key`, `only_these` or `plus_cosigned`, and optionally `cosigner=`
  and, for a list option, `rekey_to=`), it renders the `plain1` contract: the
  spending key and the overlays, no fee ceiling, no transaction-type list.
  There are seven arrangements: each rekey setting with or without a cosigner,
  except `plus_cosigned`, which needs one (without it the spending key alone
  rekeys anywhere, which is `spending_key`).
- **With any bounds parameter** (`spend_effects`, `recipients`,
  `recipient_scope`, `list_encoding`, `max_fee`), it renders a `bounded2`
  shape: the bounds beside the same overlays, described in
  [The bounds](#the-bounds) below.

A `plain1` account's every transaction without `RekeyTo` is a spend: any type,
closes and clawback included. A `RekeyTo` passes only as a pure rekey, on the
paths the arrangement gives. A cosigned account signs through `cosigned1`, one
without a cosigner through `/sign` (`bounded1`), and the plain program through
`/sign`. The Ed25519 plain host's spending key is classical; apadmin's review
says so. `/keytypes` reports both types `per_key_contract` with
`boundary_schema` `aplane.boundary.v1`, so a boundary file or a preset can
describe any of their accounts, and apshell also takes the parameters directly.

## Mnemonic backup and recovery

**Native-only mnemonic policy:** user-facing mnemonic
import, export, and recovery apply only to native account types, currently
`ed25519` and `falcon1024`. No LogicSig type offers mnemonic recovery under this
policy, including plain DSA, plain hosts, composed/bounded, rotating, and
generic LogicSigs. Witness credentials continue to use encrypted backups too.

Recover LogicSig accounts from their complete encrypted credentials or managed
backups. A private-key seed alone is not a complete account backup: program
identity, parameters, and signing/derivation metadata also matter. Rotating
accounts additionally retain their existing
[recovery requirements](USER_STORE_MGMT.md#restoring-rotating-accounts),
including stage and leaf-safety checks.

`keymgmt.SupportsMnemonicImport` is true only for native key types; no LogicSig
provider declares mnemonic import. Mnemonic export is native-only and
generation responses omit recovery phrases. Internal seed/mnemonic handlers
remain available to derivation code; their presence is not public eligibility.
Native Falcon export still requires retained recovery entropy; see
[the stored credential format](ARCH_STORE.md#managed-credential-files).

## Designing a new combination

The dimensions above describe what exists. This section is the map for
deciding what kind of key type to build when a request combines capabilities,
and the record to complete before writing code. It is a conceptual map, not a
declaration that every combination is implemented or safe to compose.

### Capability map

For DSA LogicSig accounts, three booleans give a useful overview:
`rotating × bounded × cosigned`. Native accounts and
generic TEAL-only LogicSigs are outside the map. "Bounded" means the
implemented `bounded2` contract; a rotating bounded contract would need its
own explicit definition.

| Rotating | Bounded | Cosigned | Status |
|---|---|---|---|
| No | No | No | **Implemented:** the plain Falcon and Ed25519 programs, and plain hosts without a cosigner |
| No | No | Yes | **Implemented:** plain hosts (`plain1`) with a cosigner, on Falcon-1024 or Ed25519 |
| No | Yes | No | **Implemented:** the plain hosts' `bounded2` shapes without a cosigner: allowlists and limits-only |
| No | Yes | Yes | **Implemented:** the plain hosts' `bounded2` shapes with a cosigner, such as the Corridor preset of `aplane.falcon1024.v1` |
| Yes | No | No | **Implemented:** `aplane.rotating-triple-xmss.v1`, `aplane.rotating-triple-slhdsa.v1`, `aplane.rotating-triple-wotsc.v1` |
| Yes | No | Yes | **Design required:** rotating plus external cosigner |
| Yes | Yes | No | **Design required:** rotating plus bounded policy |
| Yes | Yes | Yes | **Design required:** rotating bounded policy plus cosigner |

"Implemented" names an existing type, not arbitrary combinations of
algorithms and policies. "Design required" makes no claim that the combination is
compatible merely because each capability exists separately.

The map does not say whether rekey is allowed. A bounded profile declares
`rekey: spending_key` or `rekey: refused`, and either may add a rekey-to list.
Beside `refused` the list is *only these*, which lets the spending key alone rekey
only to a listed address. Beside `spending_key` it is *plus cosigned*, offered only
with a cosigner: a listed target takes the spending key alone, any other the
spending key and the cosigner. On a cosigned account a spending-key rekey needs
the cosigner too (a *cosigned rekey*), and a listed rekey never asks it.

### Authority belongs to operations

A boolean says that an authority exists. The contract must say what that
authority can do on each operation and which other signatures stay required.

| Operation | Required design decision |
|---|---|
| Ordinary spending | Spending signature construction, additional cosigner, policy and effect restrictions |
| Mandatory stage transition | Which next authorizer is permitted and how its usability is established |
| Administrative rekey or exit | Whether permitted; which authorities approve; permitted target and transaction form |
| Policy or cosigner replacement | Whether a defined transition allows it; whether it requires a new authorizing program |
| Recovery | What survives loss of each key, unavailable cosigners, cache loss, and restore |

For Corridor, ordinary spending requires the spending key and the cosigner
under the bounded spending policy, and the only rekey is a pure rekey by the
spending key alone to an address on the account's rekey-to list. A lost cosigner
cannot be replaced, so the account can no longer spend, but its listed key can
still take it over.

Current `bounded2` offers a pure rekey by the spending key (with the cosigner on
a cosigned account), a pure rekey by the spending key alone to an address on the
account's rekey-to list, both (*plus cosigned*), or no rekey.
It has no policy-editing or witness-replacement API; rekey can install a new
authorizing program, which is different from mutating an existing program's
policy.

Current rotating contracts permit only the predetermined next-stage
transition. They have no arbitrary exit.
Combining rotation with administrative rekey must reconcile those restrictions
explicitly; it cannot inherit both contracts unchanged.

### Naming a combination

Use **rotating-bounded** for rotation plus a bounded spending envelope and
**rotating-cosigned** for rotation plus a cosigner, an additional spending
authority.

Matching words across layers (capability, authorization contract, key type,
signing flow, implementation) do not make them interchangeable. A `bounded2`
contract with a cosigner advertises `cosigned1`; adding rotation to a
cosigned account needs an explicitly defined choreography, which clients never
infer from a key type's name or by combining two flow labels.

### Signature constructions

A signature construction is an ordered list of primitive components that must all
verify. A single algorithm is a construction of one, and no component is primary:
order sets argument positions and encoding, and every component is required.
`internal/sigconstruction` is the closed, compiled catalog, and it's linked into
clients, so it holds only shapes and verification sequences. Verification is in
`internal/sigconstruction/verify`, which takes public inputs and is signer-side only.

Five ideas stay separate:

- A **primitive profile** is exact verification behavior: key and signature encoding,
  argument slots, and the TEAL that verifies it.
- A **signature construction** is the all-of list of primitives.
- An **authority binding** ties a construction and its keys to a role. The role and the
  contract decide when a proof is required and what message it signs, so spending
  and cosigner proofs each keep their own transcript. An assembly
  receipt is another use of the spending construction.
- **Bounded contract support** says which workflows are reviewed for a construction
  under a contract. It isn't a property of the cryptography, and a matching key size
  proves nothing about it. It has two sides. Admission
  (`boundedSupportPolicy` in `lsig/composeddsa`) decides which new accounts may be
  created, and may narrow over time. Signing keeps its own table of the workflows it
  completes (`boundedSigningConstructions` in
  `internal/signerapp/signing/bounded_construction.go`), so narrowing admission never
  strands an existing account. Admission must stay within the signing table.
- An **account key type** owns account semantics. A construction doesn't.

`base_key_type` keeps its name and now names a construction. Every production base is
a construction of one, and stored data doesn't change. Multi-component constructions
exist only in tests: production has no signature encoding for one, and it can't
register or generate one. Adding a production hybrid needs a reviewed definition, a
signature encoding, credentials, and explicit contract support. `bounded2` freezes
TEAL 13, so an ML-DSA component would also need a new contract.

### Signature construction and custody are separate choices

Multiple required algorithms strengthen one authority without creating
several. The rotating WOTS+C triple requires Falcon, WOTS+C, and Ed25519
signatures, all under stage keys derived from one signer-held seed; an external
cosigner adds a different custody and approval boundary. A rotating-cosigned
design must state whether the witness is fixed or rotates, whether its schedule
follows the spending stages, and who can replace it. An admin-keyed design must
state the admin's lifecycle and permitted operations. None of this follows from
"rotating: yes".

### Design record

Before writing code, complete this record and identify the authoritative
contract for every answer:

1. **Identity and scope:** new key type and version; authorization mechanism;
   existing contracts reused and contracts that must be introduced or changed.
2. **Operation authority:** permitted effects and transitions, required
   signatures per path, policy gates, forbidden operations, and recovery limits.
3. **Cryptography and custody:** algorithms, signature combination, key
   derivation domains, authority separation, witness enrollment and lifecycle.
4. **Bindings:** account, network, stage, transaction/group, next authorizer,
   and relevant policy commitments authenticated by each signature.
5. **Durable authority:** credential schema and validation; what is persisted
   versus derived; which files are reconstructible caches. Ordinary provider
   LogicSigs persist bytecode; current rotating keys derive stage programs.
6. **Choreography:** inventory flow, endpoints, preparation, approval,
   component verification, assembly, and submission. Define retry, expiry,
   partial-signing, concurrent-transition, and restore behavior.
7. **Resources and compatibility:** argument slots and bounds, program size,
   opcode ceilings, fees, canonical encodings, and version boundaries.
8. **Evidence:** positive and negative vectors, cross-account/network/stage
   replay rejection, forbidden-transition tests, next-stage opening tests,
   recovery cases, and maximum-resource checks as applicable.

The record of `aplane.rotating-triple-xmss.v1`, a new implementation of the
established `rotating1` contract: (1) same flow, codec shape and endpoints
as the other rotating types, new family and HKDF label; (2) same operation authority and
policy gates; (3) Falcon-1024, RFC 8391 XMSS-SHA2_16_256 and Ed25519 all
required, tree seeds per tree and stage seeds per stage, no new custody
boundary; (4) each signature binds the TxID, and the program binds the
stage's leaf range and caps the message checksum at 511, which the signer
meets by choosing the randomizer; (5) the key file is unchanged in shape with a 1,921-byte
stage 0 record, and the tree's public nodes are an in-memory cache rebuilt
from the seed; (6) `rotating1` unchanged, with the signer choosing the leaf
and the stage table worker building the next tree from the midpoint of the
live one; (7) 2,664-byte program, 4,179 argument bytes, 95,857 opcode
ceiling, a five-transaction group; (8) oracle and reference vectors, every
tampered field, both range violations, a valid signature above the checksum
cap, tree rollover and the cost model at the step ceiling on LocalNet
(`ARCH_CRYPTO.md`).

The SLH-DSA profile is another implementation of `rotating1`. Its library
description states that its parameter set is not a FIPS 205 parameter set;
its pending independent review and production qualification are recorded in
[SLHDSA_EVALUATION.md](SLHDSA_EVALUATION.md). Its design
record and frozen cryptographic/resource contracts are in
[ARCH_CRYPTO.md](ARCH_CRYPTO.md#rotating-slh-dsa-triple).

The WOTS+C profile is a further implementation of `rotating1`. Its design
record is in [ARCH_CRYPTO.md](ARCH_CRYPTO.md#rotating-wotsc-triple) and its
specification in [KEYTYPE_ROTATING_TRIPLE_HYBRID.md](KEYTYPE_ROTATING_TRIPLE_HYBRID.md#12-wotsc-variant).

Classify the result as an existing supported profile, a new implementation of
an established contract, or a new protocol design. Name unresolved contract
decisions explicitly rather than borrowing semantics from two implementations
that were never specified to compose. The rotating operations interface
returns a complete locally signed stage authorization, while the cosigner flow
separately collects and verifies external components; reusing their primitives
is useful, but their combination needs a defined integration boundary before
it becomes a routine new-type task.

## Key type identifier contract

Every protocol, config, key file, template, and key type state field named
`key_type` carries the canonical identifier, not a presentation label.

Canonical forms:

- native Ed25519 is the single-segment built-in `ed25519`
- native Falcon-1024 is the single-segment built-in `falcon1024`. It is a
  protocol-native post-quantum account and is distinct from every
  `aplane.falcon1024.*` LogicSig key type
- APlane-defined LogicSig, template, and compiled-provider key types use
  `publisher.family.vN`, where `vN` is a literal `v` followed by a positive
  decimal version, for example `aplane.falcon1024.v1`,
  `aplane.ed25519.v1`, and `aplane.htlc.v1`
- witness keys use the same canonical key-type identifier contract,
  currently `aplane.witness-falcon1024.v1`; signer-custodied instances serve
  as cosigner component-signing keys selected by 52-character txid-shaped
  Witness Key IDs, not spending accounts. The
  compatibility wire/storage field name for that selector remains
  `component_key`.
- a cosigned account records its cosigner in durable `bounded_authorization`
  metadata, never in its key type: a cosigned plain host account without bounds
  records `plain1` and the `cosigner1` overlay, and an `aplane.falcon1024.v1`
  Corridor account records `bounded2`, the `cosigner1` overlay, a rekey-to list,
  and the framework Merkle allowlist policy. Clients must not infer those
  dimensions from the key-type string.

YAML templates declare `publisher`, `family`, and integer `version`; the
computed key type is `publisher.family.v<version>`. Clients and tools must send
and persist the full canonical identifier in `key_type` fields. Human-facing
CLI/TUI input and display use the same canonical identifier; publisher
namespaces are not inferred or elided.

Terminology:

- `family` is the middle segment of `publisher.family.vN`. It groups versions
  of one key type or template policy, for example `aplane.htlc.v1` and a
  later `aplane.htlc.v2`.
- `base_key_type` is the field composed DSA templates use to name their
  signature construction. For example,
  `base_key_type: aplane.falcon1024.v1` means the template's DSA signature is
  produced and packed with Falcon-1024, while the account/template identity is
  still named by its own `key_type` and `family` segment (e.g.
  `family: falcon1024-allowlist`).
- `base_key_type` is not a universal owner or routing key. Account semantics,
  creation parameters, TEAL bytecode, metadata, and cosigned assembly remain
  owned by the full `key_type` unless a specific contract says otherwise.
  The plain hosts are the important example: one key type names the plain
  program, every `plain1` arrangement and every `bounded2` shape, so an
  account's semantics, overlays and assembly are its contract's, recorded in
  its durable metadata, not the key type's.
- `RoutingFamily()` on Go provider types is the registry routing key (see
  [Resolve](#resolve--key-type--implementation)), and `Family` / `FamilyName`
  registration fields are registry/display metadata. The family-keyed registry
  fallback is an implementation detail, not a replacement for canonical
  `key_type` identity.

## Authorization object ontology

The resolution mechanisms below are separate from the security ontology. The
ontology first identifies what authorizes an account, then any LogicSig policy
form, and finally any additional authority. These dimensions must not be
collapsed into one flat key-type hierarchy.

### Account authorization types

| Type | Account authority | Signer representation |
|---|---|---|
| **Native** | A protocol-native account signature: Algorand Ed25519 (`ed25519`) or native Falcon-1024 (`falcon1024`, supported consensus v42 or v43). | Encrypted signer `.key` with native private material. |
| **DSA LogicSig** | A LogicSig verifies one or more digital signatures and may enforce additional transaction policy. | Encrypted signer `.key` with DSA private material, compiled bytecode, and signing metadata. |
| **Generic LogicSig** | TEAL predicates alone authorize the account; there is no DSA private key. | Encrypted signer `.key` containing final bytecode, parameters, derivation metadata, and signing metadata but no private signing material. |

An account authorization type identifies the account-level mechanism. It does
not by itself say whether the account is cosigned or which transaction effects a
LogicSig admits.

### DSA LogicSig policy forms

The schema-v2 composed-DSA contract uses **bounded DSA** for DSA-backed LogicSigs
whose admitted transaction effects, maximum fee, argument layout, and rekey
setting are represented by canonical signer metadata and
enforced in both planning and TEAL. Its machine names are `bounded` and
`bounded2`.

DSA LogicSig policy categories are:

- **Plain DSA**: only the DSA verification program, with no composed policy.
- **Plain host**: the DSA verification program with the overlays (`plain1`),
  no host rules.
- **Bounded DSA**: schema-v2 composed policy with a closed framework-enforced
  effect and argument contract.
- **Custom DSA policy**: schema-v1 composed policy authored directly as TEAL.
- **Dedicated compiled policy**: provider-owned LogicSig policy outside the
  composed-template schema, such as the rotating stage programs.

Schema-v1 custom policy remains a fully supported expert mode. "Expert" is a
documentation description, not a feature gate, warning requirement, or reduced
execution mode. Generic LogicSig templates are a separate category. Cosigned
signing is an orthogonal authority axis and may be combined with a DSA account
model without becoming a policy category itself.

### Auxiliary authority types

Auxiliary authority keys do not independently authorize an Algorand account.
They participate in a specific account or operation contract:

| Type | Custody and use | Signer key type? |
|---|---|---|
| **Witness key** | Stored as a cosigner-managed `.cos` credential and used through `/sign/component`; its signature is assembled into a cosigned account's LogicSig, on a plain or bounded host. | Yes. `aplane.witness-falcon1024.v1`, durable category `witness`; never accepted as a spending account by ordinary `/sign`. |

The current authority overlays are therefore **uncosigned** and **cosigner
cosigned**.

A witness key is a cosigner key. The program that embeds its public key names the
account it serves, and the networked signer that holds it may produce only
`APLANE_COSIGNER_V1` component-domain signatures.

Examples of the composed ontology:

| Key type | Account authorization | Policy form | Additional authority |
|---|---|---|---|
| `ed25519` | Native | n/a | none |
| `aplane.falcon1024.v1`, no parameters | DSA LogicSig | Plain DSA | none |
| `aplane.falcon1024.v1` or `aplane.ed25519.v1`, cosigned | DSA LogicSig | Plain host (`plain1`) | signer-custodied Falcon witness enrolled as cosigner |
| `aplane.falcon1024.v1` or `aplane.ed25519.v1`, Allowlist preset | DSA LogicSig | Bounded DSA (`bounded2`) with framework allowlist policy; spending-key rekey | none |
| `aplane.falcon1024.v1`, Corridor preset | DSA LogicSig | Bounded DSA (`bounded2`) with framework Merkle policy; rekey only to a listed address | signer-custodied Falcon cosigner on spend |
| `aplane.htlc.v1` | Generic LogicSig | generic TEAL policy | none |
| `aplane.rotating-triple-xmss.v1` | DSA LogicSig (`rotating_lsig`) | dedicated compiled stage program (Falcon-1024, RFC 8391 XMSS-SHA2_16_256 and Ed25519, all required), a new program per spend; one XMSS tree per 1,024 stages, 64 leaves per stage | none; the signer reads the chain for the live stage (`rotating1` flow) |
| `aplane.rotating-triple-slhdsa.v1` | DSA LogicSig (`rotating_lsig`) | dedicated compiled stage program (Falcon-1024, two-layer SLH-DSA-SHA2-128 and Ed25519, all required), a new program per spend | none; `rotating1`, no one-time leaf state |
| `aplane.rotating-triple-wotsc.v1` | DSA LogicSig (`rotating_lsig`) | dedicated compiled stage program (Falcon-1024, a tree of 64 WOTS+C keys and Ed25519, all required), a new program per spend; each stage is its own tree | none; as XMSS, no public tree cache |

## Key types summary

| Key Type | Key-type family | Category | `valid_rekey_target` | Description |
|----------|--------|----------|----------|-------------|
| `ed25519` | n/a | `ed25519` | true | Native Algorand Ed25519 account; not a LogicSig |
| `falcon1024` | n/a | `native_pq` | true | Native protocol Falcon-1024 account (scheme `f1`, supported consensus v42 or v43); not a LogicSig |
| `aplane.falcon1024.v1` | `aplane.falcon1024` | `dsa_lsig` | true | Default-enabled plain host on signer nodes: the plain Falcon program, one of 7 `plain1` arrangements (a rekey setting, an optional cosigner and an optional rekey-to list), or one of 147 `bounded2` shapes (the bounds beside those overlays); the composition base of composed accounts |
| `aplane.ed25519.v1` | `aplane.ed25519` | `dsa_lsig` | true | Library-visible plain host on Ed25519 (classical), with the same grammar as `aplane.falcon1024.v1`; distinct from native `ed25519` |
| `aplane.htlc.v1` | `htlc` | `generic_lsig` | false | Optional template library: hash time-locked ALGO payment |
| `aplane.rotating-triple-xmss.v1` | `aplane.rotating-triple-xmss` | `rotating_lsig` | false | Library-visible rotating account: Falcon-1024 + RFC 8391 XMSS + Ed25519 stage program, `rotating1` flow; signer-side only (no client provider) |
| `aplane.rotating-triple-slhdsa.v1` | `aplane.rotating-triple-slhdsa` | `rotating_lsig` | false | Library-visible rotating account: Falcon-1024 + two-layer SLH-DSA-SHA2-128 + Ed25519; `rotating1`, signer-side codec and cryptography |
| `aplane.rotating-triple-wotsc.v1` | `aplane.rotating-triple-wotsc` | `rotating_lsig` | false | Library-visible rotating account: Falcon-1024 + WOTS+C + Ed25519 stage program, `rotating1` flow; signer-side only (no client provider) |

`aplane.witness-falcon1024.v1` is not an account; its catalog entry declares
`valid_rekey_target: false`.

## Valid rekey target

Every key type declares a boolean `valid_rekey_target`: the key type author's
declaration that an aplane key of this type may be the signing authority an
account is rekeyed to, its own account included, subject to that key's own
restrictions (its bounds, a cosigner, its program). It is a declaration, not a
guarantee: the signer does not check that an account rekeyed to such a key can
do everything an ordinary account does. A key type whose accounts are
controlled by a DSA private key (`ed25519`, `falcon1024`, and the plain hosts
`aplane.falcon1024.v1` and `aplane.ed25519.v1` with their overlays and bounds)
declares true. A rotating key type declares false; its own signer invariant
also refuses a rekey to a rotating account whatever the setting. A generic
LogicSig template declares what its program allows: `aplane.htlc.v1` forbids
every rekey and allows only a payment that closes the whole balance, never
checks `Sender`, and declares false.

A compiled key type declares the attribute in its `internal/keytypecatalog`
entry. A YAML template declares it as the top-level `valid_rekey_target` field,
which install (`generictemplate.ValidateSpecAdmission`,
`composeddsa.ValidateTemplateAdmission`) requires. `lsigprovider.ValidRekeyTarget`
resolves the declaration, catalog first, then the installed template; an
unknown key type is not a valid rekey target. A provider answers it the same
way: a template-built provider from its YAML, a compiled one, such as a plain
host and each of its programs (`plainhost.Provider`, `ComposedDSA`), from its
catalog entry, the one place a compiled key type declares it.

The declaration is part of a template's definition. The template compatibility
fingerprint covers it beside the program
(`generictemplate.compatibilityFingerprintForSpec`,
`ComposedDSA.CompatibilityFingerprint`), so a template that declares another
value is another definition: install refuses it under an installed key type, as
it refuses any other change to the same version (`installed template does not
match incoming definition`), and reload treats a template file whose
declaration changed as any other changed definition. A compiled key type's
fingerprint does not carry it.

The declaration is read once, when an aplane key is created: every creation
path (generation, mnemonic import) records it in the key record as
`valid_rekey_target` (`keys.Payload.ValidRekeyTarget`). They save the new
record through `keys.SaveNewPayload`, which takes the declaration as a
required argument, so a creation path cannot record a value by omission; a
path that carries an existing record (backup, restore, copy) writes the record
it holds. From then on the key's
recorded value is what counts. The signer reads it from the key, never from the
live registry, so a key keeps its value when its template is disabled or absent
on the node, and backup, restore and copy carry it as part of the record. A
request is judged against the key snapshot it was planned with: the plan
carries the held addresses whose keys record false
(`PlanResult.InvalidRekeyTargets`, beside `KnownAddresses`), and the invariant
and the approval warnings read that.

`/keytypes` reports the declaration and `/keys` the value each key recorded,
both as `valid_rekey_target`. When a key records false, the signer refuses a
rekey of any account to its address, the account's own address included,
under every `rekeys` setting and whatever the account's rekey-to list says: a
signer invariant beside the rotating one
(`signing/invariant_gate.go::rejectRekeyToInvalidTarget`, error code
`rekey_target_not_valid`). The `rekeys` setting decides only about foreign
targets, addresses the signer holds no aplane key for; see
[ARCH_POLICY.md](ARCH_POLICY.md). A per-key override that allows an account's
return to its own address whatever the declaration (for a program that checks
that the sender is its own address) is not built and may be added later.

### Correcting a wrong declaration

No tool edits the value an aplane key recorded, and a compiled key type's value
is fixed in code. A template that declared the wrong value is corrected by
publishing a new version of it (a new key type identifier, such as `.v2`) with
the right declaration and creating new aplane keys from that version. Existing
keys keep the value they recorded.

- A generic LogicSig: with the same program and parameters, the new version
  renders the same TEAL, so its key has the same address
  (`lsig/generictemplate/provider_test.go::TestNewVersionWithCorrectedDeclarationRendersTheSameProgram`).
  Key files are named by address, so generating it writes a record that
  replaces the old version's record for that address; the account does not
  move.
- A template with a DSA private key (a composed template): a new key comes
  from a new random seed, and LogicSig key types take no mnemonic import, so
  it has a new address; move the account's funds to it.
- Deleting an old key needs an unlocked store and checks nothing on chain,
  including the account's balance. The record moves to the selected
  generation's `deleted/keys/` and stays there until `apadmin archive prune`,
  and retained generations keep their copies until they are pruned.

## The three axes

A "key type" (e.g. `aplane.falcon1024.v1`, `aplane.htlc.v1`,
`aplane.witness-falcon1024.v1`) is asked three different *kinds* of
question, and each kind uses a different mechanism because each is callable from
a different place.

| Axis | Question it answers | Mechanism | Owner package(s) |
|---|---|---|---|
| **Resolve** | key type → its implementation | family-keyed registries + a `RoutingFamily` resolver | `internal/lsigprovider`, `internal/logicsigdsa` |
| **Classify** | key type → category facts (which witness form? is it rotating? what key size? which signature construction?) | string switches and closed maps in neutral leaf packages | `internal/witness`, `internal/rotatingkey`, `internal/sigconstruction` |
| **Behave** | do the operation (pack signatures, build assembly args, derive, sign, render verification) | provider-capability interfaces, queried from the resolved provider or composer ops | `internal/signerapp/signing`, `internal/lsigprovider`, `internal/logicsigdsa`, `lsig/composeddsa` (`DSAOps`) |

**The governing rule:** *do not unify mechanisms across axes that have different
call-site availability.* Resolve needs the registry; Classify must work with no
registry at all; Behave needs a concrete provider instance in hand. Those are
different runtime conditions, so they need different mechanisms — collapsing them
forces a call site to depend on something it does not have.

### Resolve — key type → implementation

**Mechanism:** registries keyed by *routing family*, plus the `RoutingFamily`
resolver and the shared `ResolveByKeyType` two-step lookup.

- `internal/lsigprovider/registry.go` — `RoutingFamily(keyType)` looks up the
  registered provider and returns `provider.RoutingFamily()`; for an unregistered
  key type it returns the normalized input.
- `internal/logicsigdsa/registry.go` — `ResolveByKeyType[T]` is the shared
  pattern used by the family-keyed registries: try an **exact key-type** match
  first (native + per-key-type registrations), then fall back to the key type's
  **routing family**.
- `internal/logicsigdsa/dsa.go` — the `LogicSigDSA` contract and package doc.

**Routing key = `RoutingFamily()`, not `BaseKeyType`.** A provider's
`RoutingFamily()` is its declared routing family — the registry key. For a
self-handling DSA that is its own family; for a composed template that delegates
to a base it is the *base's* family (e.g. an imported composed template
`example.falcon1024-allowlist.v1` → `aplane.falcon1024`). That base is a
**registration fact**, not something derivable from the key-type string, and it
is deliberately not the same as the key type's own display label.

> The routing method is named `RoutingFamily()` precisely so it is not confused
> with the other uses of the word "family": the key-type display segment and the
> YAML `family:` / wire `family` fields all carry a *different* value (the key
> type's own label, not its routing key). The method is the only one that is the
> registry routing key, and its name states that role.

Ed25519 is the canonical example because the native key type and the LogicSig
DSA family share the same cryptographic primitive but intentionally use different
registry names:

| String | What it is | Meaning |
|---|---|---|
| `ed25519` | Native key type and native routing family | Standard Algorand Ed25519 account signing. It does not use a LogicSig, is default-enabled, and the key type and family are the same string. |
| `aplane.ed25519` | Qualified LogicSig DSA routing family | APlane's Ed25519-inside-LogicSig registry family. It is not a creatable key type; it is the family-keyed registry bucket for LogicSig metadata, keygen, signing, and mnemonic ops. The `aplane.` qualifier prevents collision with native `ed25519`. |
| `aplane.ed25519.v1` | Versioned concrete LogicSig DSA key type | Version 1 of the APlane Ed25519 LogicSig DSA provider. It remains available for composition and existing credentials, but not standalone creation; it signs with Ed25519, but verification happens inside TEAL via `ed25519verify_bare`. |

For composed templates, the key type's own label and its routing key can differ
again: `example.falcon1024-allowlist.v1` names the allowlist template, while its
`RoutingFamily()` is `aplane.falcon1024` because private-key operations delegate
to the Falcon LogicSig base.

### Classify — key type → category facts

**Mechanism:** pure string switches in neutral leaf packages. Witness form and
identity live in `internal/witness`. Whether an account is cosigned is not a
key-type fact: it is read from the account's durable bounded metadata. Examples:

- `witness.IsKeyType(keyType)`
- `witness.PublicKeySize(keyType)` / `witness.PrivateKeySize(keyType)`
- `sigconstruction.ForBaseKeyType(baseKeyType)` / `sigconstruction.ForWitnessKeyType(keyType)`:
  the signature construction a spending base or witness key type names. Both lookups
  normalize through `keytypecatalog.Canonicalize`. Signing uses the base lookup to
  resolve an existing account's construction from its durable `base_key_type`
  (`internal/signerapp/signing/bounded_construction.go`), with no composer in hand.

**Invariant:** these classifiers import no registry, provider, or
algorithm-family package. This is load-bearing, not incidental.
Classification is consumed from about 20 call-site files across both the signer and the
client, many of which run with **no provider registered**, e.g.
`internal/cosigner/cosignerrefs/cosignerrefs.go`, `internal/keystore/file.go`,
and `internal/cache/signer.go`. Because the answer comes from the string alone,
it is identical in every binary and needs no registration step.

(`internal/witness` takes the frozen Falcon-1024 key/signature sizes from the
leaf `internal/falconparams` (checked against upstream) for the same reason,
with a consistency test against `lsig/falcon1024/family`.)

### Behave — do the operation

**Mechanism:** capability interfaces, type-asserted on the provider instance that
Resolve already produced. The operation runs only where a concrete provider is in
hand (signer-side, at derive/sign/assemble time), so a provider-method dispatch
is the right shape here.

- Core: `LSigProvider` / `SigningProvider`
  (`internal/lsigprovider/provider.go`), `LogicSigDSA`
  (`internal/logicsigdsa/dsa.go`).
- Optional capabilities a resolved provider is asked for, such as
  `InstanceResolver` (a per-key contract), `BoundedOpcodeProfileProvider` (a
  plain host's bounded path ceilings) or the generator's `PrepareRekeyList`.

Cosigned assembly does not use a key-type-specific capability hook. It reads the
durable bounded argument-source contract and dispatches derived arguments by the
closed `kind` vocabulary; Corridor's Merkle proof is therefore a `bounded2`
behavior, not a Corridor provider method.

Composer ops are the Behave side of signature constructions. `DSAOps.Construction()`
(`lsig/composeddsa/composer.go`) names the construction the ops render. The composer
reads it for what it can't get from a name: key separation compares a witness key
against each component of the spending key, and fixture bases outside the catalog
carry their construction only here.

### Which construction is this base?

This question has two answers on two axes, and both stay, because their call sites
have different things available:

| Answer | Axis | Used where |
|---|---|---|
| `sigconstruction.ForBaseKeyType(base_key_type)` | Classify: a closed map, no registry | Signing an existing account, from durable metadata; the generation admission policy |
| `DSAOps.Construction()` | Behave: the ops in hand | The composer: what it renders, and key separation |

They must agree, and neither silently wins. A disagreement is an error:

- `RegisterBase` panics when a base name the catalog knows is served by ops that render
  another construction.
- Bounded generation refuses a directly composed base (`NewComposedDSA`, which skips
  `RegisterBase`) whose ops disagree with its name.
- `TestEveryProductionBaseResolvesToASupportedConstruction` checks every base the
  production client registers.

A base name outside the catalog, such as a test fixture, has no catalog answer to
disagree with, and it can't generate production bounded accounts.

### Why not collapse them

The axes cannot be unified because doing so would force call sites to depend on
information they do not have.

**1. Do not route by `BaseKeyType` instead of `RoutingFamily()`.** Resolve cannot
key off the `BaseKeyType` edge because `BaseKeyType` names a *signing
primitive*, not a routing authority: a composed template's `BaseKeyType` is
`aplane.falcon1024.v1`, but a provider that owns its own keygen and metadata
under its own family would be routed to Falcon's metadata (the wrong signature
size). `BaseKeyType` cannot express the delegate-vs-self distinction;
`RoutingFamily()` can. **Route by `RoutingFamily()`.**

**2. Do not classify by provider capability instead of string switches.** A
provider declaration such as "I am a witness key of size X" cannot serve every
classification call site that has no provider: the client config, the keystore,
the cache. Those run in binaries that may not register those providers at all.
Classification must answer from the string, in any binary. **Classify by string
in the neutral leaf.**

The constraint is the same in both cases: collapsing an axis onto a mechanism
whose precondition (a populated registry / a provider instance) isn't met where
that axis is actually called. The three APIs answer different availability
constraints.

### Not a fourth axis: the LogicSig metadata fallback

`internal/algorithm/metadata.go`'s `GetMetadata` resolves via `ResolveByKeyType`
(the Resolve axis). When that fails it has a best-effort `hasFamilyPrefix`
fallback that substring-matches the key type against registered families. This is
primarily a client compatibility aid for an unregistered LogicSig template (for
example, a keystore template not loaded in this process). Because the returned
metadata also carries authorization and mnemonic semantics, the fallback is
restricted to registered `logic_sig` families. Native Ed25519 and native PQ
families resolve only by exact registered identity and are never inferred from a
third-party key-type substring. Keygen and signer execution still use registered
providers or the stored base key type. This remains a fallback on the Resolve
axis, not a separate resolution mechanism.

## LogicSig providers

### Package map

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          UNIFIED REGISTRY                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│  internal/lsigprovider/     Single registry for ALL LogicSig providers      │
│    ├── provider.go          Interface definitions (LSigProvider, etc.)      │
│    ├── types.go             ParameterDef, RuntimeArgDef, constants          │
│    └── registry.go          Register(), RegisterIfAbsent(), Get(), GetAll() │
└─────────────────────────────────────────────────────────────────────────────┘
         ▲                                              ▲
         │ registers                                    │ registers
         │                                              │
┌────────┴───────────────────┐    ┌─────────────────────┴─────────────────────┐
│   GENERIC TEMPLATES        │    │   DSA PROVIDERS                           │
├────────────────────────────┤    ├───────────────────────────────────────────┤
│ lsig/generictemplate/      │    │ lsig/falcon1024/                          │
│ library/templates/          │    │   ├── v1/standard.go   Pure Falcon DSA    │
│                            │    │   ├── v1/composer.go   Falcon wrapper     │
│ TEAL-only authorization,   │    │   └── register.go      Composed base reg  │
│ no cryptographic keys      │    │                                           │
│                            │    │ lsig/plainhost/          Plain host       │
│                            │    │ lsig/ed25519lsig/        Ed25519 LSig     │
│ Sources:                   │    │ lsig/composeddsa/                         │
│   Optional library YAML    │    │   └── template.go      YAML compositions  │
│   Product key type state   │    │ Shared TEAL substitution:                 │
│                            │    │   tealtemplate scalar helpers               │
│                            │    │                                           │
│ Category: generic_lsig     │    │ Sources:                                  │
└────────────────────────────┘    │   Hardcoded Go (v1)                       │
                                  │   Optional library YAML                   │
                                  │   Product key type state                  │
                                  │                                           │
                                  │ Category: dsa_lsig                        │
                                  └───────────────────────────────────────────┘
```

Compiled DSA providers are registered from code and product visibility is
recorded in `internal/keytypecatalog`. Optional YAML templates are install
sources under `library/templates/`; generic and composed DSA templates are
imported with `apadmin template import`. Installed templates are stored encrypted
under product-store key type state via `internal/templatestore/` and loaded by the
signer template reload coordinator.

**Scoping invariant:** compiled providers are shared product capabilities, while
runtime-added `.template` files belong to the one durable `default` activation set. In practice:

- default-enabled built-in key types are available wherever their providers are registered; only the protocol-native `ed25519` and `falcon1024` and the Falcon plain host `aplane.falcon1024.v1` (signer nodes) and the witness key type `aplane.witness-falcon1024.v1` (cosigner nodes) are default-enabled
- library-visible built-in key types require an enabled product-store state record before generation surfaces expose them
- runtime-added `.template` files live in the selected generation's `keytypes/` with adjacent state records and affect the product runtime when enabled; disabled installed templates remain stored but are skipped during reload

**Schema invariant:** source-tree `.yaml` templates and runtime `.template`
files use the same logical template schema. The difference is representation,
not semantics:

- repo `.yaml` files are plaintext developer/source form under `library/templates/`
- runtime `.template` files are the encrypted on-disk form used under signer data directories, paired with plaintext key type state records

Already-generated keys keep their own stored TEAL/bytecode and do not depend on
later template-source changes.

The `bounded2` extension and its schema-v2 contract are frozen in
[ARCH_BOUNDED_DSA.md](ARCH_BOUNDED_DSA.md). The runtime accepts schema v1 for custom
composed DSA templates and schema v2 for bounded templates; each version rejects
the other's shape.

**Restore invariant:** credential backups do not carry template YAML. Restored
keys retain their durable signing metadata, while any required base signing
provider must already be available on the destination. Credential restore does
not require installing or enabling the creation template.
The key file remains the signing authority: generic v1 signing-metadata keys can
sign from stored bytecode/runtime args, and DSA v1 signing-metadata keys require
the stored `base_key_type` signer-side provider rather than the composed
template provider for their `key_type`.

Filtered views into the registry are provided by `internal/genericlsig`
(Template interface) and `internal/logicsigdsa` (LogicSigDSA interface).
Compiler-owned TEAL v13 auto-salting produces final bytecode;
`internal/lsigsalt` verifies the off-curve postcondition and retains legacy
derivation helpers. `internal/lsigresource` owns consensus resource profiles
and the pure group-size solver. Shared resource-dummy construction lives in
`internal/signing/`; final group and fee planning lives in
`internal/signerapp/signing/`.
Client registration enters through `lsig/clientreg` (`clientreg.RegisterClient`). Signer
registration enters through `lsig/signerreg.RegisterSigner`.

### Package summary

The Package Map above shows the registration topology — which packages plug
into the unified registry and how DSA versus generic-template providers are
organized. The table below names every package involved in the LogicSig
provider stack (including filtered views, template storage, salting, and
signing helpers that the diagram omits) and gives a one-line role for each.

| Package | Role |
|---------|------|
| `internal/lsigprovider` | **Unified registry** for all providers |
| `internal/genericlsig` | Template interface, type-filtered lookups |
| `internal/logicsigdsa` | DSA interface, type-filtered lookups |
| `internal/lsigsalt` | Off-curve verification and legacy derivation compatibility |
| `internal/lsigresource` | Structured program/argument/opcode profiles and consensus group solver |
| `internal/tealtemplate` | Strict `$variable` constant-block template renderer |
| `internal/tealtemplate/legacy.go` | Generated-mode restricted list expansion and scalar substitution utilities |
| `internal/keytypecatalog` | Compiled key type visibility catalog |
| `internal/keytypestate` | Product-store state record format and persistence primitives for library-visible compiled providers and installed templates |
| `internal/templatelibrary` | Library parsing and sole feature-level template/key-type mutation coordinator |
| `internal/templatestore` | Encrypted template file format and persistence primitives |
| `internal/signing` | Resource-dummy construction/signing and common transaction helpers |
| `lsig/composeddsa` | Generic runtime-compiled LogicSig composer used by DSA-backed composed templates, and parser/provider builder for composed DSA YAML templates |
| `lsig/falcon1024` | Falcon-1024 DSA base provider; `v1/composer.go` is the Falcon-specific wrapper over `lsig/composeddsa` |
| `lsig/ed25519lsig` | Ed25519 LogicSig DSA provider, registered as a plain host |
| `lsig/plainhost` | The plain host: wraps a family's plain provider with the overlay arrangements (`plain1`) |
| `internal/witness` | Witness-key vocabulary and identity (key IDs, sizes, public references) |
| `internal/falconparams` | Client-safe Falcon-1024 size constants shared by LogicSig, witness, and signer metadata |
| `internal/boundedmeta` | Durable, non-secret bounded-authorization metadata stored with a LogicSig key |
| `internal/merkleallowlist` | Merkle recipient allowlist construction and proofs used by bounded templates |
| `internal/rotatingkey` | Classify-axis leaf for rotating account key types and their frozen sizes |
| `lsig/rotatingtriplexmss` | Rotating Falcon-1024 + RFC 8391 XMSS + Ed25519 key type: stage program, signer-side operations with the public tree cache, and signer registration |
| `lsig/rotatingtripleslhdsa` | Rotating Falcon-1024 + rescaled SLH-DSA-SHA2-128 + Ed25519 key type: stage program for the built-in hypertree height, signer-side operations, and signer registration |
| `lsig/rotatingtriplewotsc` | Rotating Falcon-1024 + WOTS+C + Ed25519 key type: stage program, signer-side operations, and signer registration |
| `lsig/rotatingfamily` | What the rotating key types share: registration descriptor and generator (`signerreg`), the stage's Ed25519 and Falcon-1024 half (`stagesign`), stage program salt search and strict parse (`stageprog`), and the contract suite each key type runs (`rotatingtest`) |
| `internal/avmsim` | Test support only: the offline TEAL interpreter the rotating stage verifier tests and the bounded planner-program agreement test run programs in |
| `internal/crypto/xmss` | RFC 8391 XMSS-SHA2_16_256: tree generation, signing at a caller-chosen leaf, verification; stateless by design |
| `lsig/dsafamily` | Client-safe registration descriptor shared by DSA families (signer-side descriptor in `lsig/dsafamily/signerreg`) |
| `lsig/signerreg` | Registers all built-in LogicSig signer-side providers with their catalog availability |
| `internal/signerapp/templates` | Read-only keystore template reload coordinator and state/fingerprint policy |
| `lsig/generictemplate` | Parser/provider builder for generic YAML templates |
| `library/templates/` | Optional importable template library |
| `lsig/clientreg` | Client registration entry point |

### Two categories of LogicSigs

| Category | Example Key Types | Has Keys | Signing |
|----------|-------------------|----------|---------|
| `generic_lsig` | `aplane.htlc.v1` after template import | No | TEAL-only authorization |
| `dsa_lsig` | plain hosts `aplane.falcon1024.v1` and `aplane.ed25519.v1`, with or without overlays and bounds; imported composed Falcon templates | Yes | Cryptographic signature |
| `rotating_lsig` | `aplane.rotating-triple-xmss.v1`, `aplane.rotating-triple-slhdsa.v1`, `aplane.rotating-triple-wotsc.v1` | Yes | Per-stage hybrid signatures through the `rotating1` flow; signer-side codec, not an `lsigprovider` provider |

### Interface hierarchy

```
LSigProvider (base interface - ALL providers implement this)
├── Identity
│   ├── KeyType() string        "aplane.falcon1024.v1", "aplane.htlc.v1"
│   ├── RoutingFamily() string  "aplane.falcon1024" (registry routing key; see Resolve above)
│   └── Version() int           1, 2, etc.
├── Category
│   └── Category() string       "generic_lsig" or "dsa_lsig"
├── Display
│   ├── DisplayName() string    "Falcon-1024", "HTLC"
│   ├── Description() string    Short description for UI
│   └── DisplayColor() string   ANSI color code
├── Parameters
│   ├── CreationParams() []ParameterDef
│   └── ValidateCreationParams(params) error
├── Runtime
│   └── RuntimeArgs() []RuntimeArgDef
└── Args Assembly
    └── BuildArgs(signature, runtimeArgs) ([][]byte, error)
          │
          ▼
SigningProvider (extends LSigProvider)
├── CryptoSignatureSize() int
└── DeriveLsig(ctx, publicKey, params) (bytecode, address, error)
```

`LogicSigDSA` also carries `MnemonicScheme()` and `MnemonicWordCount()` for
internal derivation. No LogicSig provider declares user mnemonic import: it is
native-only.

A provider whose contract varies by key also implements `InstanceResolver`:
`CosignerComponentKeyType` runs before references are resolved, `ResolveInstance` selects
the contract for a set of resolved parameters, and `StoredFingerprint` identifies a
stored account's definition from its stored values alone. The plain hosts
implement it. Callers use the package functions of the same names, which adapt
every fixed provider, so they do not need to tell the two kinds apart.

Private-key key generation, signing, and mnemonic conversion are deliberately
outside this client-visible registry. Signer-side startup wires those operations
through the `internal/signing`, `internal/keygen`, and `internal/mnemonic`
registries.

### Unified registry

The `lsigprovider` package is the **single source of truth** for all LogicSig providers:

```go
// Registration - called from provider packages
func Register(p LSigProvider) {
    registerMu.Lock()
    defer registerMu.Unlock()

    // Validates key type, family, version, and category; returns the normalized key type
    keyType := validateProviderContract(p)
    if !providers.Set(keyType, p) {
        panic("duplicate LSig provider registration for key type: " + keyType)
    }

    // Apply stored algod client for late-registered providers
    applyStoredClientIfNeeded(p)
}

// Lookup - returns nil if not found
func Get(keyType string) LSigProvider {
    p, _ := providers.Get(normalize(keyType))
    return p
}

// Lookup with error
func GetOrError(keyType string) (LSigProvider, error) {
    if p, ok := providers.Get(normalize(keyType)); ok {
        return p, nil
    }
    return nil, fmt.Errorf("no LSig provider found for: %s", keyType)
}
```

The `genericlsig` and `logicsigdsa` packages delegate to `lsigprovider` and provide type-filtered views:

```go
// genericlsig.Get returns only Template implementations
func Get(keyType string) Template {
    p := lsigprovider.Get(keyType)
    if t, ok := p.(Template); ok {
        return t
    }
    return nil
}

// logicsigdsa.Get returns only LogicSigDSA implementations
func Get(keyType string) LogicSigDSA {
    p := lsigprovider.Get(keyType)
    if dsa, ok := p.(LogicSigDSA); ok {
        return dsa
    }
    return nil
}
```

### Registration flow

```
lsig/clientreg.RegisterClient()
    │
    ├── keytypecatalog.Register(aplane.falcon1024.v1, default_enabled)
    │   └── falcon.RegisterClient()
    │       ├── plainhost.MustWrap(Falcon1024V1) → the plain host
    │       └── ... (metadata, address derivation, composition base)
    ├── keytypecatalog.Register(aplane.ed25519.v1, library)
    │   └── ed25519lsig.RegisterClient()
    │       └── plainhost.MustWrap(v1.NewProvider()) → the plain host
    ├── keytypecatalog.Register(aplane.rotating-triple-xmss.v1, library)
    │   └── (no client provider)
    ├── keytypecatalog.Register(aplane.rotating-triple-slhdsa.v1, library)
    │   └── (no client provider)
    └── keytypecatalog.Register(aplane.rotating-triple-wotsc.v1, library)
        └── (no client provider)

lsig/signerreg.RegisterSigner()
    ├── lsig/clientreg.RegisterClient()
    ├── family signerreg RegisterSigner() calls add signing, keygen, and mnemonic handlers
    └── rotating signerreg Register() calls add the rotating key file codec,
        stage cryptography, and generator (outside lsigprovider)
```

Runtime templates (from keystore) are loaded after unlock:
```go
signertemplates.NewManager(paths).RegisterKeystoreTemplates(keyring)
```

### Algod client configuration

Providers that need runtime TEAL compilation implement `AlgodConfigurable`:

```go
type AlgodConfigurable interface {
    SetAlgodClient(client *algod.Client)
}

// Called during startup
lsigprovider.ConfigureAlgodClient(client)

// Stored for late-registered providers (e.g., keystore templates)
```

### BuildArgs: explicit arg ordering

The `BuildArgs` method encapsulates LogicSig arg ordering:

| Provider Type | Args Format |
|---------------|-------------|
| Generic (no runtime args) | `[]` |
| Generic (with runtime args) | `[preimage, ...]` |
| DSA (single-signature-arg form, e.g. `aplane.falcon1024.v1`) | `[signature]` |
| DSA (multi-signature-arg form, when declared by a custom provider) | `[r, s]` |
| DSA with runtime args | `[signature args..., runtime args...]` |

**Limits**: the network refuses a LogicSig with more than 255 arguments or with any
argument over 4,096 bytes (node constants, restated as `lsigresource.MaxLogicSigArgs`
and `MaxLogicSigArgBytes`). Each check runs at one point, and none at load:

- At install, template admission (`generictemplate.ValidateSpecAdmission`,
  `composeddsa.ValidateTemplateAdmission`, called by the `templatelibrary` parsers)
  refuses a declaration past either limit: generic and composed `runtime_args`, a
  composed program's signature plus runtime argument count and its base signature
  argument sizes, and every slot of a bounded argument layout.
- At key generation, a bounded account's argument layout is checked again
  (`Metadata.ValidateNetworkLimits`).
- At signing, a supplied runtime argument over 4,096 bytes is refused
  (`lsigprovider.ValidateAndOrderArgs`, and the bounded planner for a bounded account).

Spec validation and provider construction, which a store reload runs through
`PrepareKeystoreTemplateRegistration`, apply no limit, and neither does durable key
validation. An installed template or stored key past a limit still loads, so a store
never fails to load over a limit added later.

**Invariant**: Arg order is determined by `RuntimeArgs()` schema order at key
generation time, not map iteration. v1 signing-metadata key files persist that
runtime arg schema and use the stored copy at signing time. LogicSig key files
whose derivation metadata does not match their bytecode, or whose stored
bytecode derives an on-curve LogicSig address, are rejected during key scan.
LogicSig key files without
`signing_metadata_version` are rejected when signing or restore would otherwise
depend on missing durable signing metadata; the live provider schema is not used
as a fallback.

```go
// Generic template - no signature
func (t *YAMLTemplate) BuildArgs(sig []byte, args map[string][]byte) ([][]byte, error) {
    // sig is ignored for generic templates
    var result [][]byte
    for _, argDef := range t.RuntimeArgs() {  // Schema order is canonical
        if val, ok := args[argDef.Name]; ok {
            result = append(result, val)
        } else if argDef.Required {
            return nil, fmt.Errorf("missing required arg: %s", argDef.Name)
        }
    }
    return result, nil
}

// DSA - provider-specific signature args first, then runtime args
func (c *ComposedDSA) BuildArgs(sig []byte, args map[string][]byte) ([][]byte, error) {
    if sig == nil {
        return nil, fmt.Errorf("signature is required for DSA LogicSig")
    }
    sigArgs := providerSpecificSignatureArgs(sig) // e.g. [sig] or [r, s]
    result := append([][]byte{}, sigArgs...)
    for _, argDef := range c.RuntimeArgs() {  // Schema order is canonical
        if val, ok := args[argDef.Name]; ok {
            result = append(result, val)
        } else if argDef.Required {
            return nil, fmt.Errorf("missing required arg: %s", argDef.Name)
        }
    }
    return result, nil
}
```

**Note**: Runtime arg validation is shared through `lsigprovider.ValidateAndOrderArgs()`.
The engine validates signer-cache runtime arg metadata before submitting, and
providers also validate while assembling args. This keeps ordering deterministic
and rejects unknown or missing required args.

### Composed DSA

The generic `lsig/composeddsa` engine combines a DSA base with an optional TEAL
suffix. Strict template suffixes use declared `template_variables` and `$name`
constant references; generated-mode suffixes keep the restricted list-expansion
path. A bounded template may have no suffix at all, because a framework policy
supplies its Layer 3 (see [Framework Layer 3 policies](#framework-layer-3-policies)).

Three things build a `ComposedDSA`: the Falcon base provider, the Ed25519 base
provider, and the template constructor `NewProviderFromTemplateSpec`. Every
shipped composed policy is a YAML template. No key type ships as a composed policy
defined in Go, though the API allows it. Falcon exposes the engine through
Falcon-specific names in `lsig/falcon1024/v1/composer.go`. This example shows that
API and is not a registered key type:

```go
ExampleFalconHashlock = NewComposedFalcon(ComposedFalconConfig{
    KeyType:     "example.falcon-hashlock.v1",
    FamilyName:  "aplane.falcon1024",
    Version:     1,
    DisplayName: "Falcon-1024 Hashlock",
    Base:        family.FalconBase, // nil also defaults to family.FalconBase
    Params: []lsigprovider.ParameterDef{{
        Name: "hash", Type: "bytes", Required: true, MaxLength: 64,
        InputModes: []lsigprovider.InputMode{
            {Name: "preimage", Label: "Preimage", Transform: "sha256"},
            {Name: "hash", Label: "SHA-256 Hash"},
        },
    }},
    RuntimeArgs: []lsigprovider.RuntimeArgDef{{
        Name: "preimage", Type: "bytes", Required: true,
    }},
    TemplateMode: generictemplate.TemplateModeStrict,
    TemplateVars: []tealtemplate.TemplateVariable{{
        Name: "hash", Source: tealtemplate.SourceParameter,
        Parameter: "hash", Type: "bytes", Constant: tealtemplate.ConstantByte,
    }},
    TEALSuffix: `arg 1
sha256
$hash
==
assert`,
})
```

Generated TEAL structure:
```
#pragma version 13
bytecblock 0x<hash>                // strict template constants

// DSA signature verification (Falcon-1024 native opcode)
txn TxID
arg 0
pushbytes 0x<pubkey>
falcon_verify
assert

// TEAL suffix (with $variables rewritten to constant references)
arg 1; sha256; bytec_0; ==; assert

int 1
return
```

The TEAL above is the semantic renderer output before algod assembly. For
derivation version 3, algod may reuse generated constants or append a
semantically inert constant block while finding an off-curve address; APlane
does not author or patch a salt marker.

The example above is renderer output, not user-authored YAML source. Template
authors write symbolic `$hash` references; validation rejects raw
`bytecblock`/`intcblock` declarations and numeric constant references in
user-authored TEAL so the renderer can own generated constants and any
derivation-version salt anchor layout.

Current bundled address derivation delegates auto-salting to the TEAL v13
compiler. APlane accepts the compiler's final bytecode as authoritative,
checks its reported address and off-curve postcondition, derives resources from
that artifact, and persists it with
`lsig_derivation: algod_v13_auto_salt`. It does not reproduce or patch the
compiler's salt choice. Legacy derivation versions retain their marker,
trailing-block, and counter validation only for compatible stored records;
salt style is not exposed through public wire DTOs.

#### Bounded composer extension

Schema-v2 composed templates add a composer-owned transaction envelope ahead
of Layer 3. Authentication remains first; the fee ceiling and the `RekeyTo`
dispatch are second, so a rekey is accepted or rejected before any Layer 3,
cosigner, or author code; danger-field and type dispatch follow; Layer 3 runs
only on admitted spends. The composer owns all `__aplane_bounded1_` labels and
the `bounded_` parameter namespace.

`GenerateTEAL` emits the program in this order: the pragma, any strict-mode
constants, the base signature verification, the bounded envelope, Layer 3, then
the shared accept block.

##### Framework Layer 3 policies

Layer 3 takes one of three forms:

| Source | Template declares | Stored `layer3_policy` | Bundled example |
|---|---|---|---|
| Framework policy | `bounded.layer3` and no `teal` | `fixed_allowlist` or `merkle_allowlist` | every plain host shape with a list |
| Author TEAL | `teal` and no `bounded.layer3` | `custom` | None |
| Framework allowlist plus author TEAL | `bounded.layer3` and `teal` | `fixed_allowlist_custom` or `merkle_allowlist_custom` | None |

A framework policy is rendered by the composer in `lsig/composeddsa/layer3.go`, so
the template contains no TEAL. `fixed_allowlist` compiles up to 30 recipients inline.
`merkle_allowlist` compiles the root of up to 65,536 recipients and needs a
signer-derived proof. Both check only recipients, and the sender is always a legal
self-recipient. With no `teal`, a parameter or runtime argument the policy does not use
is rejected.

When a template declares both, the composer emits the allowlist first and it falls
through to the author TEAL. Both must pass, so the TEAL can only narrow what the list
admits, and containment rules stop it reaching around the list. It keeps a maintained
recipient check, and may add its own parameters and runtime arguments. The stored value
is derived: a template declares only the plain policy. The framework has no time policy;
a time condition belongs in author TEAL, alone or beside a plain allowlist. See the YAML
contract in
[ARCH_BOUNDED_DSA.md](ARCH_BOUNDED_DSA.md#yaml-contract).

Bounded-capable bases expose a static signature-argument layout. The bounded composer keeps
`LSigProvider.BuildArgs` unchanged, then assembles declared signer-derived and
caller runtime Layer-3 arguments into frozen slots selected by the plan. Durable
key metadata, rather than the installed YAML template, records path routing,
base argument count/sizes, all argument declarations and slots, profile,
optional cosigner authorization, and reviewed per-path opcode ceilings.

Bounded emission uses the template/provider's declared derivation contract; it
does not invent a second bounded salt. Current bundled providers compile TEAL
v13 and persist algod's final auto-salted bytecode. See
[ARCH_BOUNDED_DSA.md](ARCH_BOUNDED_DSA.md).

#### Salting rationale

LogicSig addresses are derived from the compiled program hash. A random program
hash can decode as a valid Ed25519 public key, which would make the LogicSig
address also look like an ordinary signature account address. APlane therefore
treats "off-curve" as a key-file invariant for generated LogicSigs: generation
must produce bytecode whose address cannot correspond to an Ed25519 public key,
and scan/restore paths reject stored LogicSig bytecode that violates that
invariant.

For current bundled providers and `derivation_version: 3` templates, APlane
asks the pinned algod compiler for TEAL v13 bytecode and treats those returned
bytes as authoritative. The compiler may leave an already off-curve program
unchanged, reuse a generated constant block, or append a semantically inert
constant block while searching. APlane does not reproduce that search. It
checks that the compiler-reported address matches the final bytes, verifies the
address is off-curve, derives program length and resource metadata from the
final artifact, and persists it.

Source-to-address golden vectors are pinned to APlane's compiler toolchain,
not promised across arbitrary assembler implementations. Runtime signing is
reproducible from the persisted final bytecode.

Legacy derivation versions remain parseable where required by the on-disk
schema, but all bundled pre-release templates use `derivation_version: 3`.
Previously generated development LogicSig keys must be regenerated; APlane
does not silently reinterpret old bytecode.

**Note**: Falcon-1024 verification uses the native `falcon_verify` opcode (TEAL v12+), which takes:
1. Message (32 bytes) - the transaction ID
2. Signature (variable, at most 1,423 bytes) - deterministic compressed Falcon-1024 signature
3. Public key (1793 bytes) - Falcon-1024 public key

### Template systems

Generic templates use their own schema-v1 contract. Custom composed DSA
templates use composed schema v1 with an explicit `template_mode`. APlane
bundles no composed template. Bounded composed
templates use the separately validated contract described in
[ARCH_BOUNDED_DSA.md](ARCH_BOUNDED_DSA.md); composed schema v1 must reject
`bounded` rather than discard it.

The shared parser first inspects the raw mapping, rejects duplicate/merge keys,
aliases, multiple documents, and invalid schema selectors, then decodes the
selected version with recursive known-field checking. Composed schema v2
requires `bounded`; generic validation rejects schema v2 and all bounded fields.
Installed and library templates use this same parser before encrypted storage
or provider registration.

- `strict` mode declares `template_variables` and uses `$name` references that
  render through generated TEAL constant blocks.
- `generated` mode uses the restricted `@variable` scalar substitution plus
  `{{range @list}} ... {{.}} ... {{end}}` list-expansion grammar; arbitrary
  Go-template syntax is rejected and `template_variables` must not be declared.
  It is available to generic (schema v1) and composed (schema v1 or v2)
  templates, e.g. `aplane.htlc.v1` and the Falcon allowlist templates; it is not
  limited to bounded templates.
- `legacy` (schema v1 only) renders through the same `@variable` substitution
  and list-expansion path as `generated`, but without generated mode's up-front
  list-syntax validation; it is the effective mode for already-stored schema-v1
  templates with no `template_mode`. Template import requires an explicit mode,
  and schema v2 requires `strict` or `generated`.

#### Generic templates (`lsig/generictemplate`)

YAML-based TEAL templates with strict constant substitution:

```yaml
schema_version: 1
derivation_version: 3
template_type: generic
template_mode: strict
publisher: aplane
family: custom-escrow
version: 1
display_name: "Custom Escrow"
valid_rekey_target: false
parameters:
  - name: recipient
    type: address
    required: true
template_variables:
  - name: recipient
    source: parameter
    parameter: recipient
    type: address
    constant: byte
teal: |
  txn Receiver
  $recipient
  ==
```

#### Composed DSA templates (`lsig/composeddsa`)

YAML-based DSA compositions with parameterized TEAL suffixes:

```yaml
schema_version: 1
derivation_version: 3
template_type: composed
base_key_type: aplane.falcon1024.v1
template_mode: strict
publisher: example
family: falcon-hashlock
version: 1
display_name: "Falcon-1024 Hashlock"
description: "Falcon signature with SHA256 hash verification"
# The program forbids every rekey, so an account rekeyed to it could never be
# rekeyed away.
valid_rekey_target: false
parameters:
  - name: hash
    type: bytes
    required: true
    max_length: 64
    label: "SHA256 Hash"
template_variables:
  - name: hash
    source: parameter
    parameter: hash
    type: bytes
    constant: byte
runtime_args:
  - name: preimage
    type: bytes
    label: "Secret Preimage"
teal: |
  txn RekeyTo
  global ZeroAddress
  ==
  assert
  arg 1
  sha256
  $hash
  ==
  assert
```

For composed templates, `base_key_type` selects the signing provider while
the YAML `family` field names the template's own version line. The two are
independent: `base_key_type: aplane.falcon1024.v1` plus
`family: falcon1024-allowlist` yields a `key_type` of
`<publisher>.falcon1024-allowlist.vN` that signs with Falcon-1024, while
`base_key_type: aplane.ed25519.v1` plus `family: ed25519-allowlist`
yields a template key type that signs with Ed25519 inside a LogicSig.

Both composed templates and generic templates are stored by the signer through
`templatelibrary`, which coordinates the primitive `templatestore` and
`keytypestate` writes. The template store's storage
type vocabulary is limited to `generic` and `composed`; compiled providers use
product-store key type state with `SourceCompiled` and are exposed to admin/library
clients as `compiled_provider` without writing an encrypted `.template` file. At runtime
`internal/signerapp/templates` walks the product-store state once, decrypts enabled
installed templates, and dispatches each template to the generic or composed
parser/provider builder.

### Transaction-aware bounded arguments

Most DSA providers produce a fixed argument list from one key. A bounded profile starts
with that base layout, then statically orders signer-derived arguments (Layer 3's,
then the rekey-list proof of an account with a rekey-to list), caller runtime Layer-3
arguments, and an optional final cosigner signature slot (`cosigned1` profiles).
Each slot records its source, maximum size, and spend, spending-rekey, and
listed-rekey requirement. Layer 3 slots are forbidden on both rekey paths; the
cosigner slot is required on spend, and on the spending rekey of an account that
takes one, and forbidden on the listed rekey; the rekey-list proof is required on
the listed rekey only. Interior slots forbidden on a selected path are explicit empty byte
strings; unused trailing slots may be omitted. Callers cannot populate derived
or cosigner slots.

The planner selects the path and freezes its slots. The executor verifies plan
integrity, generates only declared derived arguments, and places caller runtime
arguments only in their declared slots. Durable bounded metadata owns the layout
and per-path maximum signed size. See
[ARCH_BOUNDED_DSA.md](ARCH_BOUNDED_DSA.md).

## Account generation

Every route into account creation reaches `keyadmin.Service.GenerateKey`, which owns
the checks. The route decides what is resolved on the client first.

| Route | Path to `GenerateKey` | Client-side resolution |
|---|---|---|
| apadmin | IPC `generate_key`, `Session.HandleGenerateKey` | Reads a boundary file locally, through `boundary.LoadFile` |
| apshell, MCP, JS | `POST /admin/generate`, `rest.Service.AdminGenerate` | Expands aliases and sets in `address[]` parameters, through `expandGenerateAddressListParams` |
| SDKs | `POST /admin/generate` | None |

`GenerateKey` then runs these steps. The first failure stops generation, and nothing
is saved before the final steps.

`PrepareGenerateKey` runs steps 1 to 5 through the same code, then validates the values
and reports the resolved request, so a review cannot be judged differently from the
generation that follows it. It is local IPC only and creates nothing. Apadmin then
sends the reviewed public keys and the fingerprint it saw, and generation rejects the
request if the definition changed. The fingerprint is a comparison value, not an
authorization: generation repeats every check.

| Step | Work | Owner |
|---|---|---|
| 1 | Check the key type is allowed for the node role | `keyclass.ValidateKeyTypeAllowedForNodeRole` |
| 2 | Resolve rotating network names, and turn a `cosigner` reference into `cosigner_public_key` for a key type that takes a cosigner | `lsigprovider.CosignerComponentKeyType`, `cosignerrefs` |
| 3 | Select the instance the parameters ask for and canonicalize them, including sorting `address[]` values | `lsigprovider.ResolveInstance` |
| 4 | Collect the provider's warnings | `lsigprovider.CreationAdvisor` |
| 5 | Take the mutation lock and refuse a locked signer. Check the key type is enabled, then the signer's generation settings. Then check the request against the keys this signer holds: refuse a rekey-to list that names a rotating account held here, and add a warning for a cosigner key held here | `lockUnlockedMutation`, `keytypestate.CanGenerate`, `checkGenerationRequirements`, `checkAgainstHeldKeys` |
| 6 | Branch: generic LogicSigs go to `generateGenericLSig`; everything else continues below | `genericlsig.IsGenericLSigType` |
| 7 | Choose the family generator | `keymgmt.GenerateKeyWithActivatedContext`, `keygen.GetGenerator` |

The checks against the held keys come last in step 5, under the mutation lock, so the
key list can't change between the check and the write that follows it. Two things
follow from that:

- A request that fails an earlier check is told that first. A locked signer, a key type
  that isn't enabled, and a generation setting (`require_contained`, `require_cosigner`)
  each come before the rekey-to list refusal.
- Preparation and generation each read the key list when they run. If the signer's keys
  change between a review and its generation, the generation can be refused where the
  review was not, or carry a warning the review didn't have. The reviewed fingerprint
  and digest cover the request, not the warnings.

There is one refusal and one warning, in this order:

- **Rekey-to list refusal.** Each `rekey_to` address is looked up in the signer's key
  list. If it is a rotating account, preparation and generation fail with
  `rekey_to: cannot rekey to <address>: it is a rotating account, and its address is a
  one-time stage key; ...`, an invalid-input error. The signer would never sign that
  rekey (see [ARCH_SIGNING.md](ARCH_SIGNING.md)), so the list would hold a way out
  that doesn't exist.
  - It sees only accounts this signer holds, because an address doesn't reveal its key
    type. A rotating account held elsewhere passes.
  - It recognises only the rotating account's own address. The addresses of its later
    stages are one-time keys too, and a list that names one passes. The signing gate has
    the same limit: it refuses a rekey to a held rotating account's address, not to one
    of its stage addresses.
  - It runs at generation only. Nothing rechecks a stored account, so an account
    already stored with such a list still loads.
  - It refuses what it can't check. A list it can't parse, or a signer whose key list
    isn't available, is an error, not a pass.
  - Every list is checked. A request always gives the list as `rekey_to` addresses, and
    generation computes the root from them; a request can't supply a root alone.
- **Cosigner warning.** A cosigner public key equal to a key this signer holds is
  allowed. The request gets the warning "The cosigner is a key this signer holds. It is
  the key of `<selector>`, so the cosigner isn't independent of this signer: whoever
  controls this signer's keys can give both signatures." It names the lowest matching
  selector and comes after the provider's warnings. The comparison covers the public
  keys of the accounts in this signer's key list, not imported cosigner references.
  [ARCH_COSIGNED.md](ARCH_COSIGNED.md#role-separation) says why the two roles can't be
  confused. It also says why the warning is rare: the product has no path that makes
  one keypair both an account key on a signer and a witness key on a cosigner node, so
  the warning fires only when key material was moved outside the product.
- **Kept refusal.** An account's own spending key can't be its cosigner. The composer
  refuses that once the keypair exists (`refuseSharedSpendingKey`).

Warnings refuse nothing. They travel in `PreparedGeneration.Warnings` and
`GenerateResult.Warnings`:

- `PreparedGeneration.Warnings` reaches the apadmin review as
  `prepare_generate_result.warnings`.
- `GenerateResult.Warnings` reaches apadmin as `generate_result.warnings`, which the
  generated-account screen names by first sentence and shows in full on `w`, and an HTTP
  caller as `warnings` in the `/admin/generate` response. apshell prints them, and the
  JavaScript `generateKey()` returns them as `warnings`.

For a DSA LogicSig, `generateKey` in `lsig/dsafamily/signerreg/generator.go` then runs:

| Step | Work | Owner |
|---|---|---|
| 8 | Normalize again, then validate values against the parameter definitions | `ValidateCreationParams` |
| 9 | Generate the keypair from the seed | The family's keygen ops |
| 10 | Render TEAL, compile it, and validate the salted address | `deriveSaltedLogicSig`, `DeriveLsigWithSalt`, `lsigsalt` |
| 11 | Capture the TEAL source and runtime argument definitions | `GenerateTEAL`, `RuntimeArgs` |
| 12 | For an account with a contract (`plain1` or `bounded2`), build it: cosigner ID and argument layout | `BuildBoundedAuthorizationMetadata` |
| 13 | Resolve the reviewed opcode profile | `lsigprovider.ResolveOpcodeProfile` |
| 14 | Build the payload with bytecode, parameters, metadata and the template fingerprint | `keys.NewAutoSaltedDSALSigPayload`, `SetBoundedAuthorization` |
| 15 | Check the payload's selector equals the derived address, then save the new key file with the key type's `valid_rekey_target` | `Payload.Selector`, `keys.SaveNewPayload`, `lsigprovider.ValidRekeyTarget` |

`GenerateKey` finishes by reloading the runtime and writing the audit entry. The seed
and private key are zeroed in `generateKey` on every path.

A generic LogicSig has no keypair, so `GenerateGenericLSig` replaces steps 7 to 15. It
normalizes and validates, compiles with `CompileWithSalt` using the configured
`teal_compile_network`, resolves the opcode profile, and saves through `SaveGenericLSig`.

Three boundaries matter when changing this path:

- **Definition versus instance.** `CreationParams`, `RuntimeArgs` and
  `BoundedAuthorizationMetadata` answer once per key type. Steps 2 to 4 ask
  `lsigprovider` instead, so a provider whose contract varies by key can implement
  `InstanceResolver`, and a fixed provider gets the same answers from its definition.
  `BuildBoundedAuthorizationMetadata` is the per-account step, because it receives the
  public key, parameters and final bytecode.
- **Provenance.** An account records `lsigprovider.CreationFingerprint`, and inventory
  checks it with `CompareAccountProvenance` against that account's own definition.
- **Generation versus signing.** The template, provider and fingerprint matter up to
  step 15. Signing uses the stored bytecode and metadata, and a bounded key finds its
  signature packing through `BaseKeyType`, so a template change does not alter existing
  keys.
- **Budget checks.** Generation does not solve the group or fee budget for templates.
  Fixture templates are proven by `TestBoundedFixtureCompiledBudgetMatrix`, and the signing
  planner never raises a bounded transaction's fee above its ceiling. The plain hosts
  also solve each reachable path at generation, as described below.

### The bounds

A plain host selects an account's program at generation instead of fixing one per
template: the plain program, a `plain1` arrangement, or a `bounded2` shape.
`internal/boundary` holds the family-neutral vocabulary, boundary file grammar,
presets, and receipt, which clients use; `lsig/plainhost` holds the arrangements, the
shapes (`bounds.go`), the request gate (`selection.go`) and the provider. Each shape
composes over the plain host's own base and salt style, under the plain key type's
identity, so a bounded account and a plain key on the same spending key differ only by
their overlays and bounds. Both bases take the same grammar.

A shape is a spend subset, a recipient rule, and an overlay arrangement, compiled
with a fee ceiling. The spend
subsets are the seven non-empty subsets of `pay`, `axfer` and `asset_opt_in`. The
recipient rule is one of three policies: an inline allowlist, a Merkle allowlist, or
limits-only (`layer3_policy: none`, selected by `recipient_scope=any`), which has no
list, so the envelope's fee ceiling and transfer kinds are the whole
spending rule. The arrangements are the seven `plain1` ones, chosen with
`rekey_authority` and the optional cosigner: `refused` without or with a cosigner (no
rekey path at all); `spending_key` without a cosigner (the spending key can rekey to any
address) or with one (a cosigned rekey: the spending key and the cosigner, whose
`rekey_policy` picks the targets); `only_these` without or with a cosigner (the spending
key alone can rekey only to an address on the account's rekey-to list, `rekey_to`,
every other rekey is refused, and the cosigner is not asked); and `plus_cosigned`, which
needs a cosigner (a listed target takes the spending key alone, any other the spending
key and the cosigner).

The grammar is every combination the contracts allow: 3 policies x 7 arrangements x 7
subsets, 147 `bounded2` shapes per base, beside the seven `plain1` arrangements. That
includes a refused rekey and a refused account whose transfer kinds cannot send what
it holds. Which one suits an account is the user's choice; the review says what it
means.

The fee ceiling is a value, not part of the shape:

- `max_fee` is an optional bounds parameter, a whole number of microAlgos. Absent
  means 10,000 (`boundary.DefaultMaxFee`). Any value is valid, 0 included, up to
  2^53 - 1, the largest value every client reads exactly as a JSON number. It is
  written in plain decimal: a sign or a leading zero is refused, by
  `boundary.ParseMaxFee`, which the boundary file parser and the provider share.
- The 147 shapes, and the grammar fingerprint that covers them, are at the default
  ceiling.
- Another ceiling is the same shape compiled with that value: the same shape
  descriptor, its own shape fingerprint and its own boundary digest. The provider
  builds such a program when a request or a stored account first names the
  ceiling, and the grammar fingerprint does not change.
- The presets (Allowlist, Locked Allowlist, Corridor) fill in 10,000, and a sample
  boundary file written from a preset says `max_fee: 10000`.

An `only_these` shape declares `rekey: refused` plus a rekey-to list, and a
`plus_cosigned` shape `rekey: spending_key` plus a rekey-to list. A cosigned shape's
cosigner record names `required_on: [spend]`, or `[spend, spending_rekey]` when the
account takes a spending-key rekey. `Shapes()` is the single enumeration: inline and
Merkle allowlists, then limits-only; within
each, every arrangement in `Arrangements()` order, and within that every transfer
subset. Each shape is an ordinary schema-v2 template spec with no author TEAL, so it
passes every check an imported template passes. The provider holds one composer per
arrangement and per shape at the default ceiling, a bounded cache of the shapes
compiled with another ceiling, and no per-account state.

Generation admission (`lsig/composeddsa/bounded_support.go`) and the signer's
completed workflows (`internal/signerapp/signing/bounded_construction.go`) admit
`bounded2` and `plain1` on Falcon-1024 and Ed25519, with and without a cosigner. The
Ed25519 spending key is classical, which the review says.

| Concern | Rule |
|---|---|
| Boundary file | `boundary.ParseFile` parses `aplane.boundary.v1` strictly: no unknown fields, duplicate keys, aliases, merge keys, extra documents, or non-string scalars, except that `max_fee` may be written as a number. The grammar has no field that can carry TEAL, a template, a base key type, or runtime arguments. A file without `spend` has no bounds: it describes a `plain1` arrangement and may not set `recipients`, `recipient_scope`, `encoding` or `max_fee`. An empty `spend` is refused, not read as none. The file applies to the plain type it is used with; it names no key type. |
| Requests | A request with any bounds parameter goes through `selectShape`, the security gate for file and direct requests alike, and needs `spend_effects`. One with overlay parameters only resolves to a `plain1` arrangement, and one with no parameters to the plain program, which refuses any parameter, so a misspelled one is an error rather than a weaker account. The client sends public values, never a path or the YAML, and a cosigner name stays a name for the signer to resolve. |
| Stored parameters | A shape's canonical values include the selectors `spend_effects`, `rekey_authority`, and `list_encoding`, with `auto` resolved, `recipient_scope` only when it is `any` (`listed` is the default), `max_fee` only when it is not 10,000 (so a request that says `max_fee=10000` and one that leaves it out resolve to the same contract, shape fingerprint and boundary digest), and `rekey_to` in canonical address order for `only_these` and `plus_cosigned`. Generation adds the list's root as `bounded_rekey_to_root`, which no request can set and which does not select the shape. The generator resolves stored values a second time, so they must select the same shape. Only a shape's declared parameters reach its composer, because those enter the canonical behavior encoding. |
| Rekey-to list | `rekey_authority=only_these` or `plus_cosigned` needs `rekey_to`, 1 to 16 distinct nonzero addresses, and `rekey_to` needs one of them. `plus_cosigned` needs `cosigner`; without one the spending key could already rekey anywhere, which is `spending_key`. `refused`, `only_these` and `spending_key` take a cosigner or not. Any address may be listed, even one that can never act on the account (such as a witness key's native address), with one exception: generation refuses a list that names a rotating account this signer holds (see [Account Generation](#account-generation), step 5). Which other addresses to list is the user's choice, and apadmin's review flags a listed key this signer holds. The tree and its proof are in [ARCH_BOUNDED_DSA.md](ARCH_BOUNDED_DSA.md#rekey-to-list-compatibility-contract). |
| Encoding | `auto` is inline through 10 recipients and Merkle from 11. Explicit inline stops at 30. The list holds at most 65,536 distinct nonzero addresses. |
| Recipient scope | Absent or `listed`, a list is required, in the file and the request alike. Leaving the list out never opens an account. `any` must be asked for, and refuses `recipients` (even empty) and `list_encoding`. An empty or unknown scope is an error. The `none` policy is offered only here: an expert template that declares it is refused when parsed. |
| Fee and arguments | A shape's compiled ceiling is the request's `max_fee`, 10,000 microAlgos when absent; a `plain1` arrangement has none. `max_fee` must parse as a `uint64`; no value is refused. There are no runtime arguments. The base is the plain host's own: Falcon-1024 or Ed25519. |
| Resources | `BuildBoundedAuthorizationMetadata` solves the spend path, and each rekey path the account has (`spending_rekey` for `spending_key`, `listed_rekey` for `only_these`, both for `plus_cosigned`), under the current consensus profile and refuses one that cannot run within one transaction's resources, before the key is saved. This is a backstop: signing still checks the actual network. A ceiling below what a path costs when the account pays alone is not refused. |
| Fee warning | The provider implements `lsigprovider.CreationAdvisor`, which preparation and generation each call once. When a path costs more than the ceiling, the one warning names each such path and its cost, and says to batch it with transactions that share the cost or have another account in the group pay. The cost is that of a lone transaction: in a group the account's own transactions can share it. The program doesn't exist at review, so it is sized by what it must hold (the spending public key, the cosigner's on a cosigned account, and an inline recipient list): the cost is a lower bound, a ceiling just above it can still fall short, and signing reports that when it plans the group. The warning reaches the apadmin review as `prepare_generate_result.warnings` and an HTTP caller as `warnings` in the `/admin/generate` response, which apshell prints. It refuses nothing. |
| Mnemonics | No mnemonic import. The account recovers from its encrypted credential or a backup. |

Three identities have separate jobs, and `lsigprovider.Instance` carries each one:

| Identity | Field | Scope |
|---|---|---|
| Selected fingerprint | `Fingerprint` | One arrangement or shape. Stored as the account's `template_fingerprint`. A new rule leaves existing arrangements and shapes alone. |
| Grammar fingerprint | `ReviewFingerprint` | One per base: the labelled, ordered mapping of every arrangement and shape, each with its descriptor. A review sends it back, so generation can refuse if the definition changed. |
| Boundary digest | `BoundaryDigest` | Compares resolved policy and external authorities, under the domain `APLANE_HOST_BOUNDARY_V1` and the schema `aplane.boundary.v1`. It excludes the spending key, so equal digests do not mean equal accounts. Its encoding is in [ARCH_BOUNDED_DSA.md](ARCH_BOUNDED_DSA.md). |

Fingerprints hash configuration, not renderer code, so `lsig/plainhost/fingerprint.go`
declares semantics revisions by hand. `TestBoundsFingerprintGoldens` and
`TestPlainHostGrammarGoldens` fail when rendered output changes, and their comments say
which revision that obligates.

**No separate approval.** Enabling a template approves a definition that lives in an
editable file, so it needs a fingerprint check. The plain hosts' arrangements and shapes
are compiled in, and an account's rules are fixed in its program once created, so a new
shape can only ever create a new account, and it arrives with a release the operator
chose to install. The grammar fingerprint still lets a review detect that the definition
changed before generation, and each account still records its arrangement or shape.

**Generation settings.** `require_contained` (new accounts must be contained:
refuse every rekey, or every rekey but one to a listed address (`only_these`), and hold
a recipient list, `boundedmeta.Metadata.Contained`, so a limits-only account never is,
even with a cosigner, and neither is a `spending_key` or `plus_cosigned` one, which is
only as strong as its two online keys; fees, capped per transaction only, are outside
it) and
`require_cosigner` in the product runtime config apply to the plain hosts, the per-key
types, on every creation route, under the mutation lock, and generation rechecks them
after a review. A `plain1` account is never contained, since its spends are open, and
the plain program has neither a contract nor a cosigner, so either setting refuses it.
They do not reach existing accounts or expert templates. Both are writable admin
settings, shown in apadmin's Settings panel on signer nodes.

**Discovery.** `/keytypes` reports `per_key_contract: true` for a type with an
`InstanceResolver`, with no signing flow or bounded profile, because each account has its
own. It still names the cosigner component type, but does not turn the cosigner field
into a required selector: a cosigner is optional here. A per-key type whose requests a
boundary file grammar describes also reports `boundary_schema`: both plain hosts report
`aplane.boundary.v1`.

**Client routing.** apadmin and apshell choose the preset and boundary-file flows from
`boundary_schema`, never from a key type name or from `per_key_contract` alone.
`TestEveryBoundaryProviderSupportsTheBoundaryWorkflow` pins that every production type
declaring the schema can run those flows. A per-key type without it would take its
parameters directly (apadmin's parameter form, apshell's `generate` arguments), and
apshell refuses `--boundary` for it. This classification only picks a client flow: the signer still resolves the key type and applies the bounded support
policy, so a misclassified request is refused rather than gaining anything.

A failed lookup isn't an answer that a type is ordinary. apadmin shows an error and
reloads instead of opening the plain form, because a compiled list can stand in before
the signer's arrives. apshell's `--boundary` reads the signer's key types before the
file, and stops without a request if the lookup fails or the type has no
`boundary_schema`. apshell's options are flags, so they never collide with a signer
parameter, and no other `generate` needs the lookup.

**Client and signer combinations.** No tagged signer through v0.49.0 has a per-key type,
so a client can read a missing `per_key_contract` as "not per-key" there. Untagged builds
between `8c2c54bf`, which added per-key instances, and `b861ce55`, which added the field,
can have per-key types without reporting them, and they're unsupported.

**apadmin.** Choosing a plain host opens its preset screen, "New <type> Account",
which lists No bounds, the presets, Custom bounds, and Load boundary file.
`boundary.Presets()` is the one definition behind the presets and sample boundary
files: Allowlist is `spending_key`; Locked Allowlist is `only_these` and
asks for `rekey_to`; Corridor is `only_these` with a cosigner and asks for `rekey_to`
too. No bounds and Custom bounds are the screen's own rows: No bounds is the overlay
form without a bounds group (a `plain1` account), and Custom bounds offers every bounds
field without a file, with the transfer kinds required. Load boundary file reads a file and sends its
public values. Every choice but the file opens the overlay form (see
[ARCH_ADMIN.md](ARCH_ADMIN.md#choosing-a-generate-flow)): its bounds, then the cosigner,
the rekey-to list and the rekey choice, which a preset fills in and the operator can
change.
Every parameterized request is prepared first. A bounded
result goes to a review screen that keeps fingerprints and digests in a details view.
For an account with a rekey-to list (`prepare_generate_result.bounded.rekey_list`,
under `only_these` or `plus_cosigned`) it also names every address in the resolved
`rekey_to` and flags those this signer holds; on a post-quantum spending key (a plain
host on a post-quantum base; an expert template's base isn't in the inventory, and
`bounded2` admits Ed25519, so its review makes no such claim and says so) it names the
held targets
whose key type is classical, and asks the operator to confirm the others, since an
address doesn't reveal its key type. The details say which kind of protection the rekey
setting is: a refused rekey and `only_these` are independent of the online keys, while
`plus_cosigned` and a cosigned `spending_key` are only as strong as both online keys,
and an uncosigned `spending_key` as the spending key. The account's own address can't
be on the list at generation, since the spending key doesn't exist yet. These are
statements, never refusals. The Rekey row says which arrangement
applies: "Spending key and cosigner" for a cosigned rekey, and "These N, spending key
alone; others need the cosigner" for `plus_cosigned`. Then
generation sends the exact resolved values with `expected_fingerprint` and
`expected_boundary_digest`, so an edited reference cannot substitute an authority. Any
other result generates as entered. After generation the operator can save a
`aplane.boundary-receipt.v1` receipt beside where apadmin runs. It names the saved
address, documents the account, and cannot restore it.

**apshell.** `generate aplane.falcon1024.v1 --boundary <file>` (or `aplane.ed25519.v1`)
reads the file locally and shows a summary labelled as local, because the guarantee is
weaker than apadmin's review: the signer has not seen it, and a cosigner name stays
unresolved until creation. The summary lists a rekey-to list's addresses and, on a
cosigned account, says the cosigner is not asked for a listed address; for a file
without `spend` it says "Bounds: none". Without `--boundary`, `generate` takes the same
bounds and overlay parameters directly, as `name=value` arguments. A stable Witness Key ID can only select
that authority, and apshell confirms the result
against it, reporting an account it cannot confirm. The file's values are literal, so
they skip this client's alias and set expansion. Results show the parameters the signer
stored and the authority IDs it reports in `/keys`: apshell derives neither, because
routing and identity stay daemon concerns. `--result <file>` saves that as
`aplane.generation-result.v1`, which deliberately has no fingerprints or digest. Only
apadmin's IPC workflow can issue a full receipt. Interactive confirmation is not an
authorization, and unattended callers skip it.

**Labels.** `keytypeux.BoundedLabel` builds descriptions such as `Merkle allowlist · no
rekey · cosigner` from stored metadata, for `keys` and apadmin's key details; an account
with a rekey-to list says `rekey to listed only`, a cosigned spending-key rekey
`cosigned rekey`, and `plus_cosigned` `rekey to listed, or cosigned`. A custom
policy says only that it is custom, because its conditions are the author's code.

## See also

- `docs/ARCH_SIGNING.md` — HTTP DTOs, error codes, and SDK contracts.
- `docs/ARCH_CONTRACTS.md` — compatibility-bearing contracts and pointers to
  their owning documents.
- `docs/ARCH_BOUNDED_DSA.md` — the `bounded2` authorization contract and its
  profile, metadata, and path semantics.
- `docs/ARCH_SECURITY.md` — product-principal and closed-action
  authorization for API and admin operations.
- `docs/ARCH_POLICY.md` — signer and cosigner policy domains that gate signature
  release.
- `docs/ARCH_NETWORKS.md` — network context and genesis-hash resolution.
- `docs/ARCH_COSIGNED.md` — the cosigned/cosigner account choreography.
- `docs/DEV_KEYTYPES.md` — how to add a key type (where these axes become
  concrete decisions).
- [ARCH_CRYPTO.md](ARCH_CRYPTO.md) - Full cryptographic subsystem documentation
