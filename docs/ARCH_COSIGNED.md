# Cosigned Signing

> Cosigned signing: the cosigner subsystem that makes a cosigned account need
> both a user signer and a cosigner signer, and Corridor v1, the bounded preset
> built on it.

This document describes APlane's cosigner subsystem: node roles, cosigner keys,
cosigned accounts, endpoint discovery, cosigned transaction orchestration, and
the trust boundaries between a user signer and a cosigner signer. A cosigned
account is a LogicSig account with the cosigner overlay, on either host: a plain
host (`plain1`: the plain key types `aplane.falcon1024.v1` and
`aplane.ed25519.v1` with overlays only) or a bounded host (`bounded2`: the same
plain key types with bounds, or an expert template). It also describes
[Corridor v1](#corridor-v1), the Corridor preset of `aplane.falcon1024.v1`, which
composes cosigner authorization into `bounded2`.

"Cosigned" is this document's historical name for the cosigned flow; a later
naming pass renames it. The dedicated cosigned account type and its `cosigner1`
flow were retired in phase 5 of the account overlays: the plain host with a
cosigner replaces it.

The component message, the cosigner key file, and the public cosigner
reference library are specified in this document. For exact HTTP wire shapes
and SDK fixtures, see [ARCH_SIGNING.md](ARCH_SIGNING.md#http-api-contract); for the endpoint
registry file, see [ARCH_DATA_MODEL.md](ARCH_DATA_MODEL.md#endpoint-registry).
For cosigner policy verdict semantics, see [ARCH_POLICY.md](ARCH_POLICY.md).
The `bounded2` and `plain1` authorization contracts are
in [ARCH_BOUNDED_DSA.md](ARCH_BOUNDED_DSA.md), key type axes are in
[ARCH_KEYTYPES.md](ARCH_KEYTYPES.md), and the machine-checked
bounded-cosigner choreography is in
[FORMAL_TLA_BOUNDED_COSIGNER_MODEL.md](FORMAL_TLA_BOUNDED_COSIGNER_MODEL.md).

## Contents

- [Status](#status)
- [Roles And Boundaries](#roles-and-boundaries)
- [Key Model](#key-model)
- [Component-Flow Unification Invariants](#component-flow-unification-invariants)
- [Signer-Domain Gating Of Base Components](#signer-domain-gating-of-base-components)
- [Component Message](#component-message)
- [Public Cosigner References](#public-cosigner-references)
- [Endpoint Routing](#endpoint-routing)
- [Cosigned Transaction Flow](#cosigned-transaction-flow)
- [Cosigned Simulation](#cosigned-simulation)
- [Assembly Invariants](#assembly-invariants)
- [Cosigner Policy](#cosigner-policy)
- [Cosigned Authorizers](#cosigned-authorizers)
- [Mixed Groups](#mixed-groups)
- [Failure Model](#failure-model)
- [Audit](#audit)
- [Corridor v1](#corridor-v1)
- [Implementation Map](#implementation-map)

## Status

Cosigner is a first-class signing architecture, not a policy flag on ordinary
signing. It creates a two-party LogicSig authorization path:

- the user signer proves control of the account's spending key and applies
  signer-domain policy and operator approval, and
- the cosigner signer authorizes the transaction facts under cosigner policy.

The client orchestrates both parties but never holds private key material. The
final transaction is submitted only after component signatures are collected,
verified, assembled into LogicSig arguments, and checked against the canonical
transaction bytes.

## Roles And Boundaries

Every signer data root has one root `node.yaml` role:

| Role | May hold | Must not hold |
|---|---|---|
| `signer` | ordinary and cosigned account keys | signer-custodied witness private keys |
| `cosigner` | witness private keys serving the cosigner role and cosigner-domain policy | any spending key, cosigned accounts included |

There is no supported `dual` role: a node holds signing keys or cosigner
witness keys, never both. The reason is operational simplicity, not safety.
One role per node keeps the key inventory, the policy document format and the
HTTP signing dispatch single-purpose. A deployment that wants both on one host
runs two `apsigner` processes with separate data roots.

Whether a cosigner is independent of the signer is a separate question, and
the role split doesn't answer it. Independence comes from who controls each
node and its credentials: two processes on one host under one operator are
not independent.

The node role gates key generation, mnemonic import, restore, key scanning, and
HTTP signing dispatch. Role conflicts fail closed instead of silently skipping
keys.

Primary ownership:

- `internal/noderole`: root role parsing and role integrity.
- `internal/keyclass`: role-versus-key-type classification.
- `internal/signerapp/productruntime`: runtime load/reload with role-aware key scan.
- `internal/signerapp/signing`: signing dispatch and role-specific behavior.

## Key Model

Cosigner uses a witness key as its auxiliary signing authority.

### Cosigner Keys And Witness Key IDs

Cosigner keys are raw witness keys held by cosigner nodes. They are not
Algorand accounts and cannot spend funds directly.

Their canonical private record is
the selected generation's `keys/<WitnessKeyID>.cos`. The `.cos` container uses the
product store's current term key, bound to the credential's Witness Key ID, and a
canonical `category: witness` payload.

Current cosigner key types:

- `aplane.witness-falcon1024.v1`

They are selected by a 52-character uppercase **Witness Key ID** derived from
the length-prefixed domain, key type, and cosigner public key. Cosigner wire
fields retain the name `component_key`. The ID is txid-shaped but is not an
Algorand address.

The raw cosigner public key is the verifier embedded in a
cosigned account's LogicSig bytecode. The selector is a stable lookup handle;
the public key is the cryptographic verifier.

### Cosigned Accounts

A cosigned account is an account-signing LogicSig key held by a signer node
whose durable bounded metadata carries the cosigner overlay: the cosigner
contract `cosigner1`, the component key type, the resolved cosigner public key
and its Witness Key ID, and the paths it signs (`required_on`). The same public
key is compiled into the program. Generation may accept a public cosigner
reference by Witness Key ID, but the durable key stores the resolved public key.
The overlay is the same on both hosts:

- **Plain host** (`plain1`): `aplane.falcon1024.v1` or `aplane.ed25519.v1`
  created with `cosigner=`, a rekey setting and no bounds. Its program checks signatures
  and the overlays only: every transaction without `RekeyTo` is a spend,
  closes and clawback included, and there is no fee ceiling, so the cosigner's
  policy is what restricts what gets signed. The Ed25519 spending key is
  classical.
- **Bounded host** (`bounded2`): `aplane.falcon1024.v1` or `aplane.ed25519.v1`
  created with bounds as well, or an expert template, with its on-chain limits
  and the cosigner. The Ed25519 spending key is classical here too.

A [Corridor](#corridor-v1) account is a bounded host: `aplane.falcon1024.v1`
with a framework Merkle recipient policy, the cosigner, and a rekey-to list
(*only these*). Every cosigned account advertises `signing_flow: cosigned1` and
is discovered from metadata, never from a key-type switch.

The stored `base_key_type` names the spending construction used for the base
component's key material and signature packing. It does not make the base
provider responsible for overlay metadata, creation parameters, TEAL, cosigner
reference resolution, or final LogicSig argument assembly.

Cosigned accounts and cosigner keys are never signed through raw `/sign`:

- a cosigned account's spends, cosigned rekeys and listed rekeys use `/plan`,
  `/sign/component` with a bounded-base target and (except for a listed rekey)
  a cosigner target, then `/sign/assemble` for source-aware final assembly;
- cosigner keys use `/sign/component` with `kind:"cosigner"`;
- ordinary `/sign` rejects cosigner key types and every plan with a cosigned
  account, listed rekeys included.

An account with the overlays but no cosigner (a plain host or bounded account
without one) signs through ordinary `/sign` (`signing_flow: bounded1`), and the
plain program with no overlays signs there as any LogicSig does.

This preserves the two-party invariant: a cosigned account requires both a
spending signature and, on every path but a listed rekey, a cosigner component
signature. The endpoint split is also a contract statement: `/sign` returns
only submittable signed transactions produced by keys this signer can complete
alone, while the component/assembly surface handles partial, multi-party
authorization.

## Component-Flow Unification Invariants

The component-flow migration unifies transport and orchestration, not the
underlying authorization models. `/plan` is the only endpoint that
canonicalizes a group. Component and assembly endpoints accept frozen group
bytes and validate or reject them without mutation; they never plan, add
resource dummies, pool fees, regroup, or otherwise repair the request.

The signer intentionally does not prove that frozen bytes came from `/plan`.
It independently reconstructs signer-owned facts and may accept any canonical,
envelope-valid group that satisfies the same policy, resource, fee, and
signer-owned authorization checks. For a component call, the bytes evaluated by policy, the
bytes rendered for operator approval, and the bytes used to derive component
messages are one and the same. Bounded-cosigner component signing therefore
moves from approving a plan constructed inside the signing call to approving
the supplied frozen group after the signer re-derives its bounded authorization
envelope from durable metadata and validates client-supplied runtime arguments;
the client cannot supply or weaken that envelope.

For every component kind, the declared dummy suffix is checked against the
canonical signer-added dummy form before policy evaluation or key access. The
classification is bidirectional: a declared dummy must be canonical, and a
canonical signer-added dummy suffix cannot be relabeled as caller-supplied
original positions to alter policy or approval semantics.

Assembly authorization is source-aware behind the shared request: a
bounded-cosigner target carries base signatures, a cosigner signature (none on a
listed rekey), and an assembly receipt, and the signer decides the path again
before accepting any of them.

## Signer-Domain Gating Of Base Components

Cosigned signing has two independent authorization gates, one per party:

- the **user signer** gates bounded-base component signing with the same
  signer-domain machinery as ordinary `/sign`: hard policy rejection,
  always-review rules, and blocking operator approval. The cosigned account is
  the per-target policy key (its own policy document, or the signer's node
  default), and every
  non-target position in the canonical group is evaluated as a foreign leg, so
  dangerous fields on co-signed legs (rekey, close, clawback) force operator
  review exactly as they do on `/sign`. The review still says whose such a position
  is: one whose sender's key this signer holds is headed as that, and one that
  only names a held key as its authorizer is reported as the request's claim, here and in
  the later `/sign` request that carries the cosigned targets the same way (see
  [ARCH_SIGNING.md](ARCH_SIGNING.md), step 7). User Auto-Approve satisfies these
  review requirements without a prompt, while hard policy rejection still applies.
- the **cosigner signer** gates cosigner-role component signing with the
  deterministic cosigner policy domain: allow signs, everything else rejects,
  and there is no operator prompt.

The base component therefore expresses both proof of control and a
signer-domain authorization decision; the cosigner signature expresses the
cosigner-domain policy decision. Neither gate replaces the other: a permissive
signer policy still cannot move funds the cosigner policy refuses, and a
compromised client credential cannot drive cosigned sends past the signer's
review rules or operator approval.

First-party client choreography is user-first: it completes the user-side gate
and obtains the bounded base component before requesting a cosigner
component. This avoids cosigner work and ordinary first-party audit events for
transactions the user signer rejects, and it gives submission and simulation
the same predictable operator flow.

The cosigner endpoint does not receive or verify the prior base component. A
client that calls cosigner-role `/sign/component` directly can ask the cosigner to
evaluate the transaction first. The resulting cosigner component is not spending
authority by itself: final assembly and the on-chain program still require the
matching base spending signature and all account/program checks.

The cosigned key is validated against signer inventory metadata — no key
decryption — before the gates run, so a rejected request or an operator prompt
never triggers a private-key operation and approval never precedes a
key-not-found rejection. The key is decrypted only after the gates pass, under
the final execution gate, so shutdown or lock transitions cannot
complete while component key material is in use. In a mixed group the
operator may be prompted twice — once for the bounded-base component request
and once for the ordinary `/sign` legs; both prompts render the full group
context. The `auto_approve_self_noop_transfer` rule never fires for cosigned
groups because they are always pre-grouped, matching `/sign` semantics for
pre-grouped requests.

## Component Message

The cosigner component signature signs the transaction identity under a role
byte:

```text
SHA512_256("APLANE_COSIGNER_V1" || role_byte || txid)
```

`role_byte` is `0x02`, the cosigner role, and is compiled into every cosigned
program. `0x01` was the retired user role of the dedicated cosigned account and
is never reused. `txid` is the canonical 32-byte transaction ID for the frozen
group entry. The spending key signs the raw TxID, as every bounded and plain
host program verifies it, not a component message.

The message deliberately does not contain a separate sender or authorizer
field. Sender and `AuthAddr` consistency are verified from the canonical
transaction bytes during assembly, which requires the account's LogicSig
address, and `AuthAddr` when needed, to equal the requested cosigned account.
The cosigner policy decision is scoped to the transaction facts, not to which
cosigned account acted as authorizer.

Owned primitives:

- `internal/cosigner/message`: message construction. Clients and signers must
  use that shared primitive, or an SDK equivalent with matching vectors, rather
  than reconstructing the message independently.
- `internal/sigconstruction/verify`: component signature verification (signer-side
  only; clients treat component signatures as opaque).
- SDKs must match the same vectors rather than reconstructing a variant.

Changing the message shape is a versioned cryptographic and LogicSig change.
For example, per-authorizer cosigner allowlists would require binding the
authorizer in the signed message and updating the matching on-chain LogicSig
verification path.

### Role Separation

A signature made in one role can't be used in the other, whichever key made
it. That is why generation allows a cosigner public key that is also a key the
signer holds, and only warns about it.

Which keys could be shared at all:

- A cosigner key is Falcon-1024 only (`aplane.witness-falcon1024.v1`). So only
  a Falcon-1024 account key could share a keypair with one: a native
  `falcon1024` account, or the spending key of a Falcon LogicSig account.
- An Ed25519 key can't. Neither can a rotating stage key: stage keys are
  derived per stage from the rotating secret, and are never imported keys.

What a cosigner key signs:

- The 32-byte SHA-512/256 digest above. Its hash input is the 51 bytes
  `"APLANE_COSIGNER_V1" || 0x02 || txid`. The signed message is the digest,
  not those 51 bytes.
- The fixed text `"APLANE_WITNESS_KEY_PAIR_V1"`, when the node checks a loaded
  key pair. That signature is checked and discarded.

What an account key signs:

| Message | Signed by |
|---|---|
| The 32-byte transaction ID, SHA-512/256 of `"TX" \|\| msgpack(txn)` | The key of a LogicSig account, a bounded account's base component, and a rotating account's stage components |
| The unhashed `"TX" \|\| msgpack(txn)` | A native account's key, Falcon-1024 or Ed25519 |
| The SHA-512/256 digest of the [assembly receipt](ARCH_BOUNDED_DSA.md#bounded-cosigner-assembly-receipt) transcript, which begins with a length-prefixed `"APLANE_BOUNDED_COSIGNER_ASSEMBLY_V1"` | A cosigned account's spending key, as well as the transaction ID |
| A fixed 32-byte open-test message, the SHA-256 of a label | A rotating stage's Ed25519 and Falcon keys, before the stage is live. The signatures are never released |

Why none of these can stand in for another:

- The hashed messages are all 32 bytes, so length does not separate them.
  Their hash inputs begin differently: `"TX"`, `"APLANE_COSIGNER_V1"`, and the
  receipt's length prefix. For one to be accepted as another, two different
  inputs would need the same SHA-512/256 digest, a collision.
- The native message is not hashed. It carries a genesis hash, so it is always
  longer than 32 bytes and can't equal a digest.
- The fixed messages are constants, not transaction IDs or cosigner digests.
- No account key signs bytes a caller chooses. There is no data-signing route.

What the choice costs is independence. A cosigner whose private key this signer
holds is not independent of it: whoever controls this signer's keys can give
both signatures. Generation says so in a warning (see
[ARCH_KEYTYPES.md](ARCH_KEYTYPES.md#account-generation)).

The product has no path that makes one keypair both an account key on a signer
and a witness key on a cosigner node:

- A witness key is generated on the cosigner node from a random seed
  (`WitnessFalcon1024Generator.GenerateRandom` in
  `lsig/falcon1024/keygen/witness.go`). The seed is not stored, and mnemonic
  export covers native account keys only.
- A witness key can't be imported from a mnemonic: `GenerateFromMnemonic` in
  the same file refuses.
- A node is one role or the other. A signer holds no witness keys and a
  cosigner holds only witness keys (`keyclass.NodeRoleAllowsKeyType`).

So the warning fires only if key material was copied between nodes by hand,
outside the product.

One rule stays. An account's own spending key can't be its cosigner, because
then one key would give both signatures by construction.

## Public Cosigner References

Signer nodes need public cosigner metadata to generate cosigned accounts, but
they do not need cosigner private keys.

The signer-side cosigner reference catalog is populated by explicit operator
handoff: `apadmin cosigner export` on the cosigner node followed by `apadmin cosigner
import` on the signer node.

The exported file is that canonical `aplane.witness-key-public.v1` document
and nothing else: the cosigner's address is not in it. apadmin imports the
public witness reference through authorized local IPC and refuses a file that
carries anything more. apshell owns endpoint configuration, client enrollment,
host trust, and live discovery, and is given the cosigner's address by the
operator; apadmin does not access client state.

The client-side `endpoints add <url>` workflow (formerly `cosigner add`, which
still forwards to it) takes the cosigner's URL and never a key. The client
stores only the route: it keeps no witness key and no key-to-endpoint mapping,
so the unit it manages is a connection to a cosigner node, and a later key on
the same node needs no client change.

Before prompting, the workflow resolves the destination and reuses a cosigner
profile already configured for that URL; only a new profile needs a name, for
which it suggests one derived from the endpoint host. Under the shared
client-data lock it revalidates and writes only the chosen endpoint alias, then
releases the lock before any SSH trust, enrollment, or network operation.
Setup first tries the connection with the client's key; a node that refuses
the key as unenrolled is asked to enroll it. The request is queued for that
node's operator, so setup stops with the connection configured
(`ErrCosignerSetupEnrollmentPending`) and is rerun once the operator approves;
only a node that answers that the key is already enrolled is tried again at
once. The enrollment request uses a standalone SSH connection and does not
disturb the primary signer tunnel. Cosigner HTTP requests use restricted direct channels on
that authenticated SSH connection instead of a transient local forwarding
listener.

Setup then makes two separate observations on its own connection to the
chosen endpoint:

1. **Node role.** It reads `node_role` from authenticated `/status` and
   continues only for `cosigner`. A `signer`, an absent or unrecognized role,
   or a failed read stops setup. Sweeps and signing do not check the role;
   setup does because an endpoint-only handoff carries nothing else that
   distinguishes a cosigner from a signer.
2. **Inventory.** It validates the `/keys` witness metadata and reports the
   advertised key count. Guided setup takes a URL, not a witness document, so
   there is no input key to compare.
3. **Routes.** It runs the signing resolver's bounded sweep and reports the
   result in the resolver's own classifications. An endpoint that was tried and
   failed is ignored by routing, so routes through answering endpoints stand
   but are qualified. A sweep that stopped early (an SSH host-key mismatch, or
   a timeout) supports no positive route conclusion; the mismatching endpoint
   is reported as a mismatch and the remaining ones as never contacted.

Setup fails only for the connection being added: no access, a node that is not
a cosigner, invalid endpoint inventory, or a witness that this endpoint and
another both advertise. The state of other endpoints, and of
accounts that need other cosigners, is reported without failing it.

Reference aliases are security-bearing generation inputs: resolving
`cosigner=<name>` selects the witness public key embedded into a newly generated
cosigned account. Manual import and removal therefore require an unlocked
product runtime in addition to `cosigners.manage`. Re-importing the identical authority
is idempotent. Rebinding an existing name to another Witness Key ID is rejected;
replacement requires an explicit audited remove followed by import.

Public reference records are stored under:

```text
identities/default/cosigners/
```

They contain public metadata only: Witness Key ID, key type, cosigner public key
hex, and import time. They are not endpoint ownership proofs and do not
authorize a future transaction. The cosigned account's embedded public key is
the trust input that matters after generation.

### Cosigner Key File

`apadmin cosigner export <witness-key-id> [output-json]` and the apadmin TUI's
**Export Cosigner Key** emit the canonical `aplane.witness-key-public.v1`
document and nothing else. The command reads the
`keys/<witness-key-id>.cos.json` sidecar, verifies that `<witness-key-id>`
equals the canonical Witness Key ID derived from the public key, and never reads
or decrypts private key material. If the sidecar is missing or malformed,
export fails closed; the operator must regenerate the cosigner key, or restore
it from a backup, which rewrites the sidecar, before exporting.

The envelope schema is shown below. The Falcon public key hex is abbreviated in
this prose example; persisted envelopes contain all 3,586 hex characters.

```json
{
  "schema": "aplane.witness-key-public.v1",
  "key_type": "aplane.witness-falcon1024.v1",
  "witness_key_id": "ROGAFDACF7ASC3EMZRWNKVM73NXHO4P6O4EB7ZXWER37SM63BMFQ",
  "public_key_hex": "0000...0000"
}
```

`witness_key_id` is the 52-character uppercase base32 selector derived as
`base32_no_padding(SHA512_256(field("APLANE_WITNESS_KEY_ID_V1") ||
field(key_type) || field(canonical_public_key_bytes)))`. It resembles an
Algorand transaction ID and is not a valid Algorand address. Role-specific
wire and cosigner-reference records retain the field name `component_key`.
`public_key_hex` is the raw component
public key encoded in hex; it is the value embedded into cosigned-account
LogicSig bytecode and supplied as `cosigner_public_key` during cosigned account
generation. The envelope makes no endpoint, policy, ownership, freshness, or
trust claim.

The daemon returns the document over the admin protocol already in canonical
form (the field order above, two-space indentation, one trailing newline). The
apadmin TUI validates it, re-serializes it canonically
(`witness.MarshalPublicReference`), and writes it locally with owner-private
permissions. Batch `apadmin cosigner export` writes the daemon's bytes as
received: to the output path with owner-private permissions, or to stdout when
the output path is omitted. The file carries no
endpoint, reference alias, endpoint alias or role, client credential, SSH identity,
`known_hosts` entry, cached live inventory, private witness material, policy,
or proof of endpoint ownership. The cosigner's address is not a file contract
at all: the operator reads it from the export result screen (the configured
`endpoint.advertise_url`, or a placeholder) or from the deployment, and gives
it to each client for `endpoints add <url>`. The earlier
`aplane.cosigner-enrollment.v1` composition envelope, which could carry an
endpoint block, and the `apadmin cosigner enrollment export|import` commands
are gone; the system is unreleased, so no reader for them remains.

### Cosigner Public Key Reference Library

`apadmin cosigner import <public-json|-> <name>` imports an
`aplane.witness-key-public.v1` document into the product store's public
cosigner reference library. The operator-side adapter validates the document,
refusing any field beyond the public reference, and sends its canonical form
through IPC:

```text
identities/default/cosigners/<name>.json
```

Reference names are normalized to lowercase and may contain lowercase letters,
digits, `.`, `-`, and `_`. A name must start with a letter or digit and must
not contain `..`. The persisted record schema is:

```json
{
  "schema": "aplane.cosigner-public-key-ref.v2",
  "name": "lab-cosigner",
  "component_key": "ROGAFDACF7ASC3EMZRWNKVM73NXHO4P6O4EB7ZXWER37SM63BMFQ",
  "key_type": "aplane.witness-falcon1024.v1",
  "public_key_encoding": "hex",
  "public_key_hex": "0000...0000",
  "public_key_size": 1793,
  "public_key_sha256": "d3a3deeec37ef5e50a463a2b1f8c9c6fc934a5c824a0c1cfd027d035a03b923a",
  "imported_at": "2026-06-04T00:00:00Z"
}
```

The catalog is populated only by explicit operator import. Only the version 2
record schema is read; records in any other schema, or carrying fields outside
it, are rejected.
When the source is `-`, stdin is reserved for the bounded public JSON document.
Local operation obtains the store passphrase from `APSIGNER_PASSPHRASE` or a
controlling terminal. Unsupported
headless combinations fail before authentication instead of sharing stdin
between the envelope and passphrase.

Human list output leads with the operator-assigned reference name and a compact
10-leading/10-trailing Witness Key ID. Detailed JSON (`apadmin cosigner show`)
retains the complete ID.

The library is a generation convenience and trust-input inventory for the user
signer. When generating a cosigned account (a plain host, with or without bounds,
or a cosigner-enabled template), callers may provide
`cosigner=<witness-key-id>` instead of `cosigner_public_key=<hex>`.
`cosigner=<name>` is also accepted as a compatibility input. The signer resolves the
Witness Key ID or name to `public_key_hex`, verifies that the reference key type
matches the definition's required cosigner key type,
rejects requests that provide both forms, and persists the resolved
`cosigner_public_key` plus the template's other creation parameters in the key
file. A Corridor account, for example, persists its public recipient list and
complete bounded metadata; later signing reads those, not the shape definition.

Product `/keytypes` metadata may expose imported references as a
creation parameter named `cosigner` with `type:"select"` and `options[]`
containing Witness Key IDs whose cosigner key type matches the type's
cosigner key type. A per-key type (`per_key_contract`), whose cosigner is
optional, is not given the selector. This is UI metadata for generation clients such as `apadmin`;
the durable key file still stores the resolved `cosigner_public_key`; other
provider-specific creation parameters remain exposed normally.

The `apadmin` TUI also receives the optional `cosigner_component_key_type` in
its internal admin key-type projection and joins it with
`list_cosigner_references`. Cosigned generation displays aliases but submits the
canonical Witness Key ID. A sole compatible authority may be preselected;
multiple authorities require an explicit picker choice. When none exists, the
TUI opens an in-flow public-envelope enrollment review instead of exposing a
raw `cosigner_public_key` editor. The review locally validates the envelope and
shows the complete grouped Witness Key ID before the authorized import RPC.
The public `/keytypes` DTO and external SDK contract are unchanged by this TUI
projection.

## Endpoint Routing

Client endpoint routing lives in:

```text
$APCLIENT_DATA/endpoints.yaml
```

### Credential And Destination

The client's enrolled SSH key is its credential at every node, and the node is
where the enrollment lives. An endpoint record therefore carries no
per-destination credential, and no client-side state is created or retired
when an alias is created, re-pointed, or deleted: the route is all the client
keeps. Revoking this client's access to a cosigner is that node operator's
action, in its apadmin, not a client-side edit.

The enrollment request is submitted with the client lock released and answered
at once; the node's operator approves it later. Nothing is written on the
client: the route was published before the request, and the node records the
request and then the enrollment.

Hand-editing `endpoints.yaml` bypasses the write-side locking rules.

The registry may contain one signer endpoint and at most 12 cosigner endpoints.
Endpoint records carry connection metadata only: the `ssh://` URL and the SSH
identity and known-hosts paths. No record names the node's REST port;
the node's SSH server forwards every channel to its own listener.

Runtime cosigned-send routing works like this:

1. Signer inventory labels a cosigned account with `signing_flow: cosigned1`,
   and exposes its `cosigner_component_key_type` and required cosigner public
   key. The client routes on the flow label (key-type strings are opaque to the
   client) and fails fast on flow labels it does not implement, the retired
   `cosigner1` included.
2. The client queries authenticated `/keys` on the configured cosigner endpoints
   with bounded parallelism and validates each advertised Witness Key ID.
3. The client builds an operation-scoped route snapshot and requires exactly
   one endpoint for every required embedded public key.
4. Component signing reuses the already-verified endpoint connection from that
   snapshot.

Endpoint import and `/keys` discovery are routing metadata. They do not prove
ownership. If an endpoint is wrong or stale, assembly or on-chain LogicSig
verification fails unless that endpoint controls the embedded cosigner private
key. Deleting an advertised cosigner key causes cosigned signing to fail before
submission with a missing-advertised-key error.

Use `apshell endpoints add` for guided setup of one cosigner connection. Use
`apshell cosigner status` for point-in-time endpoint observations and account
requirements, including unmatched witnesses. It shares the signing resolver's
bounded sweep and uniqueness rules, closes all probe connections, and does not
persist inventories or routes. Missing primary-signer inventory is explicitly
unavailable, not an empty list of cosigned accounts. Route availability is not
a policy verdict or proof of private-key possession.
`apshell endpoints discover-cosigners` remains the advanced inventory diagnostic.
Signer-side apadmin displays public reference metadata only; it does not
probe endpoints or persist route associations.

## Cosigned Transaction Flow

The client uses cosigned orchestration when any transaction's effective signer
is a cosigned account. The effective signer is the sender unless the sender is
rekeyed, in which case it is the resolved `AuthAddr`. Supported cases include:

- a cosigned account as `txn.Sender`,
- a standard account rekeyed to a cosigned account, where `txn.Sender` is the
  standard account and `AuthAddr` is the cosigned account,
- mixed groups containing cosigned and non-cosigned signer-controlled positions.

The flow is `cosigned1`, a user-first choreography. It carries a cosigned
account's spends (on a `plain1` account, any transaction that doesn't rekey,
closes and clawback included), its cosigned rekeys (spending key and cosigner) and its
listed rekeys (spending key alone):

1. Resolve the bounded target from `signing_flow` and durable inventory.
2. Send the draft group to `/plan`, then pass the exact frozen group plus its
   closed target/context/dummy position partition to `/sign/component` with
   `kind:"bounded-base"`. Every non-cosigned position is sent as the
   signer's own in both requests, since step 3 signs it through `/sign` (a
   group with a position the signer doesn't hold is refused before planning): in sign mode on `/plan`, and
   as a contextual position with `auth_address` on `/sign/component`. The
   signer then sizes it from its own records and can put the group's
   authorization charge on it, by the same payer order as an ordinary `/sign`.
   The signer independently reconstructs the durable bounded authorization and
   validates grouping, resources, fees, policy, and operator approval without
   changing the bytes. It returns base signature args, runtime args, an
   assembly receipt bound to those bytes, and `path`: `spend`,
   `spending_rekey` or `listed_rekey`, the path it classified.
3. Sign any non-cosigned context positions through ordinary `/sign`; the
   cosigner is asked only after the user side is complete. Each cosigned
   position in that request is budgeted on its component's path.
4. Route those exact frozen transactions to the cosigner endpoint and request a
   cosigner-role `/sign/component` signature for every target except a
   `listed_rekey` one. When no target needs the cosigner, no cosigner request
   is sent.
5. Return the base component, receipt, cosigner signature (none for a listed
   rekey), and exact group to the user signer through `/sign/assemble` with
   `kind:"bounded-cosigner"`.
6. The signer classifies each target again from the canonical transaction and
   stored metadata, through the planner's function, and requires a cosigner
   signature on `spend` and `spending_rekey` and refuses one on
   `listed_rekey`. It verifies all sources, derives declared Merkle and list
   proofs, constructs the metadata-declared argument layout, and returns the
   executable group.

The `path` mark is a routing hint. A client that skips the cosigner on a path
that needs it, or asks it on a listed rekey, gets no group from assembly, so a
wrong mark can stall a request but never weaken it.

The first-party client does not ask the cosigner first. Signer endpoints
validate the targets they sign or assemble; they do not infer the flow of
foreign group positions. Non-target positions are carried as exact passthrough
signed bytes in the final assembly request.

A `plain1` account has no fee ceiling, so the client checks a planned fee against an
account's ceiling only on a bounded one (`bounded2`, `max_fee` present); it
caches each account's contract from `/keys` and fails closed on one it doesn't
know.

## Cosigned Simulation

Cosigned simulation follows the complete flow above. The user signer runs
ordinary policy and operator approval before releasing base components; the
cosigner runs its ordinary deterministic policy; local non-cosigned positions
use `/sign`; and the final group is produced by
`/sign/assemble`. Only after assembly and frozen-byte verification does the
client send the exact executable group to its configured algod simulation
endpoint instead of the submission endpoint.

There is no simulation claim at any signer boundary. Apsigner cannot know how
the client will route released signatures, and the client holds a submittable
cosigned group until its validity window expires. Headless simulation therefore
requires the same user auto-approval configuration as headless submission;
otherwise a connected admin client must approve it.

All component signatures and ordinary signatures are over the same frozen
group. This matters for mixed groups: cosigned targets, non-cosigned originals,
and resource-dummy transactions must all agree on transaction bytes, group ID,
selected-path LogicSig resources, and aggregate fee.

## Assembly Invariants

Assembly is the main server-side backstop for cosigner signing. It verifies the
spending-key assembly receipt, the base signature, the cosigner component
signature for role `cosigner` and the target txid against the cosigner public
key in the account's durable metadata, equality of planned and loaded durable
metadata, the frozen base argument layout, the cosigner slot and path mask,
every runtime and derived argument source, and the final LogicSig address; when
`txn.Sender != account`, the signed transaction must carry
`AuthAddr == account`. Passthrough signed bytes are kept only when their decoded
txid matches the canonical entry, a signature is present, and the effective
signer is not a cosigned account this signer holds, which must be assembled
instead (A8, machine-checked in `bounded_cosigner.tla`). It classifies each
target's path again from the canonical transaction and stored metadata, through
the planner's function, and requires a cosigner signature on `spend` and
`spending_rekey` and refuses one on `listed_rekey`; the component's `path` mark
does not decide it. It derives Merkle and rekey-list proofs from stored
parameters; clients cannot supply a derived or cosigner slot through ordinary
LogicSig arguments.

## Cosigner Policy

A cosigner node stores policy exactly as a signer node does, in the
`aplane.policy.v1` format specified in
[ARCH_POLICY.md](ARCH_POLICY.md#the-boundary): one node default,
`default.json`, and zero or one document per cosigner key,
`policies/<WitnessKeyID>.json`, in the selected generation. A `/sign/component`
request's `component_key` selects the policy: a key the node does not hold
fails as a bad request, a held key with a document of its own is governed by
that document alone, and a held key without one is governed by the default.
The shipped cosigner default is deny-all (`transaction_types` `{"*":
"reject"}`, no routes, `reject_rekey: true`), so a new key rejects every
request with `transaction_type:<type>` until it is given a document of its
own or the operator loosens the default. Before any rule, a target whose
genesis hash maps to no known network is rejected as `unknown_genesis_hash`
(see [ARCH_POLICY.md](ARCH_POLICY.md#known-network-gate)). Policy is
evaluated before the cosigner key is loaded. Decode refuses review-producing fields on a cosigner node, so every verdict
is sign or reject. The only cosigner-specific rule ID is
`cosigner_policy:reject_rekey`; every
other verdict uses the common rule IDs in
[ARCH_POLICY.md](ARCH_POLICY.md).

A key's document governs a virtual account set: every account whose program
was composed with that cosigner key, on any signer that holds the key's
public reference. The cosigner does not hold those accounts and cannot
enumerate them; it learns of one when a request names it. The document's
route `sources` are therefore the operator's only control over membership:
`["*"]` accepts every account composed with the key, while named addresses
or sets restrict the key to accounts the operator agreed to witness for. The verdict model is direct
authorization:

- matching deterministic allow policy signs,
- deny guards reject,
- unmatched requests reject,
- manual review and operator default are not valid cosigner outcomes.

The cosigner does not decide whether the user signer is allowed to use a
cosigned account. It decides whether the target transaction facts are allowed
under cosigner policy. Current cosigner policy is transaction-focused and
DSA-agnostic: it examines decoded transaction details and transfer movements,
not which DSA mechanism produced the spending signature. On a `plain1` account,
which has no on-chain limits, it is the policy that restricts what the account signs.

A cosigner is driven entirely by its policy document. `transaction_types`
decides which types it signs, and may allow any of them. Transfer routing is
the allow-list for `pay` and `axfer`: a movement no route covers is rejected.
Any other allowed type is authorized by its type verdict alone. A `keyreg`
with nonparticipation is refused before any policy.
`reject_rekey:true` rejects every rekey the cosigner is asked to sign. If it is
false, a non-zero `RekeyTo` is authorized only when the transaction is a pure
0 ALGO self-payment and `rekey_policy.allowed` contains a matching
sender-to-target edge; an edge may use `*` on either side, and `self` as a
target. Missing `rekey_policy` still fails closed.

A cosigned account asks the cosigner for every spend and every cosigned
rekey (`rekey: spending_key`, or an unlisted target under `plus_cosigned`): such
a rekey reaches the cosigner node as any rekey does, and `reject_rekey`, the
`rekey_policy` edge and the pure-shape check decide. A listed rekey takes the
spending key alone and never reaches the cosigner node, so on an account with a
rekey-to list `reject_rekey:true` does not stop a rekey to a listed address, and
`rekey_policy` picks only cosigned-rekey targets. The list is the owner's
standing statement, fixed in the program.

See [ARCH_POLICY.md](ARCH_POLICY.md) for the rule inventory, domain-specific
schema constraints, route behavior, and reject/review/approve mapping.

## Cosigned Authorizers

A cosigned account can be the effective signer for another account rekeyed to
it. In that case:

```text
Sender = S
AuthAddr = G
LogicSig address = G
```

where `S` is the account whose funds move and `G` is the cosigned account. The
transaction is still `S`'s transaction. Cosigner policy remains scoped to the
transaction facts. Assembly verifies that the LogicSig address and `AuthAddr`
both equal `G`.

Current v1 semantics do not expose an authorizer field to cosigner policy and do
not bind authorizer identity into the cosigner component message. That is
intentional for the transaction-focused model. If a future policy wants
per-authorizer delegation controls, the component message and LogicSig program
must change together so the cosigner's authorizer-conditioned decision is bound
cryptographically.

## Mixed Groups

Mixed cosigned/non-cosigned groups use one canonical group and preserve full
approval context:

- cosigned targets receive a base component and, except on a listed rekey, a
  cosigner component,
- non-cosigned signer targets use ordinary `/sign`, which completes before the
  cosigner is asked, so the user-first choreography covers the whole group and
  a rejected non-cosigned position never reaches the cosigner,
- resource-dummy transactions are included consistently for LogicSig argument
  and opcode capacity,
- signer-side `/sign` sees the complete group context for non-cosigned approval
  and policy,
- `/sign/assemble` receives signed non-cosigned entries as passthrough bytes.

The client supplies accurate selected-path `lsig_resources` for cosigned
positions when it calls ordinary `/sign` for the non-cosigned subset. These
values come from signer inventory, not client estimates. The signer keeps its
normal consensus resource computation as an independent backstop. A mis-sized
client group fails early with a clear immutable-group rejection rather than
later as an opaque algod evaluation failure.

## Failure Model

Cosigner failures are fail-closed:

- signer-domain policy rejection, always-review denial, operator denial, or a
  missing admin client fail bounded-base component signing before any
  private-key operation,
- there is no client-declared simulate mode on any signer endpoint; simulation
  follows the ordinary approval path,
- locked or unreachable cosigner endpoints cannot produce component signatures,
- failed endpoint authentication, trust, or inventory validation contributes
  no route from that endpoint,
- duplicate usable live routes for a required witness fail the operation,
- deleted cosigner keys stop being advertised by `/keys` and cosigned signing
  fails before cosigner signing,
- missing cosigner signatures fail assembly, and so does a cosigner signature
  on a bounded listed rekey, which takes none,
- mismatched spending or cosigner signatures fail assembly,
- stale endpoint routing cannot pass assembly or on-chain LogicSig verification
  without the embedded cosigner private key,
- unsupported cosigner policy outcomes fail closed.

An endpoint that failed its probe may be skipped only when the completed
sweep's remaining usable inventory uniquely resolves every required key;
the failure is reported. This includes unavailable/locked endpoints and
endpoint-specific authentication, configuration, or metadata failures.
An SSH host-key mismatch aborts the whole sweep. Caller cancellation,
incomplete sweeps, duplicate usable routes, and unresolved required keys also
fail the operation. Skipping an endpoint grants no authority from its response.

Runtime routing performs a bounded probe of every configured cosigner endpoint
before selecting an operation-scoped route. It cannot stop at the first match,
because later live endpoints might advertise the same witness and make the
route ambiguous. The sweep uses the configured concurrency and per-endpoint
limits under a 30-second total deadline, so cosigned-signing discovery latency
can include the slowest probe needed to complete that sweep. Non-fatal endpoint
failures are reported after the sweep even when the remaining live inventory
uniquely resolves every required witness.

## Audit

Cosigner component approvals and rejections use existing sign audit events. In
the current projection:

- `txn_auth` carries the Witness Key ID,
- `txn_sender` carries the decoded target sender,
- `policy_rule_id` carries the deterministic cosigner rule when one matched.

This is an MVP projection. It preserves event visibility without introducing a
separate audit event family for component signing.

Rejections are rate limited (a burst of 20, then one per 6 seconds), with the
rest counted in a `COSIGNER_REJECTIONS_SUPPRESSED` entry, so a compromised
signer side cannot provoke enough rejections to rotate the record of what the
cosigner signed out of the audit log. Signatures are always logged
individually.

## Corridor v1

Corridor is the Corridor preset of the Falcon plain host `aplane.falcon1024.v1`,
which composes cosigner authorization into `bounded2`. It is a shape of that
compiled provider, not a separate key type, authorization-contract identifier,
key category, or special transaction classifier.

The dimensions are independent:

| Dimension | Corridor v1 value |
|---|---|
| Full key type | `aplane.falcon1024.v1` |
| Account form | DSA LogicSig |
| Base signing primitive | `aplane.falcon1024.v1`, the key type itself |
| Authorization contract | `bounded2` |
| Layer-3 policy | framework-owned `merkle_allowlist` |
| Spend auxiliary authority | `cosigner1`, Falcon witness, required on spend, never asked for a listed rekey |
| Rekey setting | `refused` plus a rekey-to list (*only these*) |
| Advertised signing flow | `cosigned1` |

Changing one dimension does not reinterpret the others. In particular,
`bounded2` is the on-chain envelope and durable metadata vocabulary, while
`cosigned1` is the client/server choreography used to obtain a complete
spend or listed-rekey signature.

The canonical profile and behavior parameter encodings are frozen by
[Golden vector 3](ARCH_BOUNDED_DSA.md#golden-vector-3-host-boundary-digest),
which uses the *plus cosigned* shape with Corridor's recipient policy and
cosigner. Corridor's profile differs from it only in encoding `rekey: refused`,
`required_on: [spend]`, and a cosigner slot forbidden on `spending_rekey`.

### Accepted Transactions

Every accepted path requires the Falcon spending signature and
`Fee <= max_fee`, which the Corridor preset sets to 10,000 microAlgos. Spend paths admit only:

- pure payments;
- pure asset transfers; and
- asset opt-ins.

A non-self `Receiver` or `AssetReceiver` must have a valid 512-byte proof
against the fixed-depth Merkle root compiled from the durable `recipients`
parameter. Self receivers bypass proof verification. Every spend also requires
the enrolled cosigner's Falcon signature over the `APLANE_COSIGNER_V1` cosigner-role
TxID message.

Root construction, recipient canonicalization, duplicate rejection, padding,
node hashing, and proof order are frozen by the
[bounded Merkle allowlist compatibility contract](ARCH_BOUNDED_DSA.md#merkle-allowlist-compatibility-contract).

A pure rekey (a 0 ALGO payment to itself with no close fields) to an address on
the account's rekey-to list is accepted with the spending signature and a valid
160-byte list proof, without the cosigner; see the
[rekey-to list compatibility contract](ARCH_BOUNDED_DSA.md#rekey-to-list-compatibility-contract).

Corridor rejects every other rekey, close remainder, asset close, clawback,
unsupported transaction types, missing or malformed proofs, missing cosigner
authorization on a spend, and arguments supplied from the wrong source. It
declares `rekey: refused` plus the list, so the listed rekey is its only rekey
path.

### Custody And Generation

Generation resolves two distinct Falcon keypairs:

1. the signer-held spending key; and
2. the cosigner-node `.cos` witness selected by `cosigner` or supplied as
   `cosigner_public_key`.

A cosigner key equal to the spending key rejects. The generated `.key` stores the
resolved public parameters, bytecode, and complete signing-metadata version 2
`bounded_authorization` object. Signing uses that stored authority rather than
the shape definition.

`aplane.falcon1024.v1` is default-enabled, so every signer node can create a
Corridor account without enabling a key type or installing a template.

Both keys are required to spend:

- a stolen spending key cannot spend without the cosigner, and can rekey the
  account only to a listed address, which gains it nothing unless it also holds
  that address's key;
- a lost cosigner key cannot be replaced, so the account can no longer spend,
  but the spending key alone can still hand it to a listed key, which can then
  move the funds;
- a lost spending key cannot be recovered.

Operators must therefore back up the spending key and the cosigner key as
distinct required authorities.

### Spend Choreography

The frozen online flow is:

```text
client -> user signer  POST /plan
client -> user signer  POST /sign/component (kind=bounded-base)
client -> cosigner node  POST /sign/component (kind=cosigner)
client -> user signer  POST /sign/assemble (kind=bounded-cosigner)
client -> algod         submit or simulate exact signed group
```

`/plan` finalizes group bytes and fees. The bounded-base component call
validates those frozen bytes without changing them, applies user-signer policy
and operator approval, and releases the base signature args plus a
spending-key assembly receipt. First-party clients contact the cosigner only after that
release. The cosigner endpoint does not verify a prior base component, so this
order is client choreography for audit quality, efficiency, and predictable
operator UX rather than a cosigner-enforced security property. Final assembly
verifies the base signature, receipt, cosigner signature, durable metadata,
source/path masks, derived Merkle proof, frozen TxID, LogicSig address, and
authorizer binding.

A listed rekey takes the same flow without the cosigner call: the base
component names `path: listed_rekey`, the client sends no cosigner request, and
assembly takes no cosigner signature and adds the list proof. The cosigner node
never sees it, so its `reject_rekey` does not apply. Ordinary `/sign` rejects
every Corridor transaction, spends and listed rekeys alike.

The cosigner component is transaction-scoped: it binds the cosigner role and TxID,
not the Corridor account, authorizer, or program. Final assembly and
the LogicSig perform those account/program checks. Reusing one cosigner key
across Corridor accounts therefore creates a shared transaction-policy domain;
per-authorizer cosigner policy would require a new component-message and LogicSig
version. See [Component Message](#component-message).

### Close And Decommission

Corridor v1 has no close path, and its only rekey path is the listed rekey.
Decommissioning means spending the balance to listed recipients, which leaves
the minimum balance in the account, or handing the account to a listed key,
which can then close it.

`CloseRemainderTo`, `AssetCloseTo`, and `AssetSender` remain zero on every
transaction authorized by Corridor, and `RekeyTo` is zero on every one but a
listed rekey.

### Compiler And Resource Budget

Corridor stores one resource profile over its final compiler-auto-salted
bytecode. Inventory materializes maximum argument bytes and reviewed opcode
ceilings for every bounded path cell (spend, spending-key rekey, and listed
rekey); a resource cell does not authorize a path. Corridor admits spend and
listed rekey. Under v42, argument/opcode capacity determines the minimum group
size; bytecode above
the final group's free program pool contributes to the aggregate fee instead
of manufacturing extra dummies.

Its worst-case spend argument layout is derived from durable bounded metadata.
The planner evaluates the selected
path, adds only required resource dummies, applies the v42 program surcharge,
and rejects the finalized transaction if its fee exceeds the compiled 10,000
microAlgo ceiling. Compiler golden values are toolchain-pinned; the stored
final bytecode is authoritative.

## Implementation Map

Primary packages and files:

- `pkg/signerapi`: HTTP DTOs for component signing, assembly, and key inventory.
- `internal/witness`: witness key-type identifiers, Witness Key ID derivation,
  public identity validation, keypair validation, and custodian capabilities.
- `internal/cosigner/keytypes`: the durable `cosigner_public_key` parameter name.
- `internal/cosigner/message`: the cosigner-role component message.
- `internal/cosigner/canonical`: canonical group decoding and group hashing.
- `internal/sigconstruction/verify`: component signature verification (signer-side
  only).
- `internal/cosigner/cosignerrefs`: public cosigner reference catalog.
- `internal/signerapp/signing`: frozen component validation, bounded
  authorization reconstruction, cosigner policy
  evaluation, signer-domain approval gates (`gate.go`), bounded-base and
  cosigner component signing, assembly, and `/sign` rejection gates.
- `internal/signerapp/rest`: REST service methods backing `/sign/component`,
  `/sign/assemble`, `/keys`, and `/keytypes`.
- `internal/signerapp/daemon`: HTTP runtime (`http_runtime.go`) that registers
  these routes on the signer mux and dispatches them to the `rest` service
  methods.
- `internal/engine/cosigned`: cosigned (`cosigned1`) transaction
  orchestration and cosigner endpoint resolution; `internal/engine` composes
  that owner into the client runtime.
- `internal/config`: endpoint registry parsing (`schema_version` 2 only; retired
  `signer_port`/`local_port`/`token_file` fields are dropped on load).
- `internal/apshellapp`: endpoint commands and read-only cosigner discovery.
- `lsig/plainhost`: the plain host, the plain key types with optional overlays
  and bounds, Corridor's shape among them.
- `lsig/composeddsa`: the cosigner and rekey-to list overlays on both hosts,
  and framework-owned fixed/Merkle Layer-3 policies.
- `internal/boundary`: the boundary file grammar, the presets (Corridor among
  them) and the receipt.
- `internal/apadminapp/catalog.go`: public cosigner export/import/list/show/remove
  workflows used by `apadmin`.
- `internal/signerapp/policycmd`: live and rescue policy workflows through
  `apadmin`, including per-key cosigner document apply and removal.
- `internal/signerapp/policyapply`: shared policy check and generation-commit
  rules.
- `internal/signerapp/signing/cosigner_policy.go`: cosigner key and policy
  selection, and the rejection and audit that act on its verdict.
- `internal/signerapp/policyeval/cosigner.go`: the cosigner verdict: the
  known-network check and each target's rules.

Representative tests:

- `internal/signerapp/signing/component_test.go`
- `internal/policy/doc_v1_test.go`
- `internal/policy/store_v1_test.go`
- `internal/policy/transfer_routing_eval_test.go`
- `internal/engine/cosigned/submit_test.go`
- `internal/apshellapp/endpoints_test.go`
- `internal/apadminapp/catalog_test.go`
- `scripts/docker-local-four-node-smoke.sh`
