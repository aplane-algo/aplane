# Guarded Signing

> Guarded signing: the cosigner subsystem that makes a guarded account need
> both a user signer and a cosigner signer, and Corridor v1, the bundled bounded
> profile built on it.

This document describes APlane's cosigner subsystem: node roles, cosigner keys,
guarded accounts, endpoint discovery, guarded transaction orchestration, and
the trust boundaries between a user signer and a cosigner signer. It also
describes [Corridor v1](#corridor-v1), the first bundled profile that composes
cosigner authorization into `bounded1`.

The component message, the cosigner key file, and the public cosigner
reference library are specified in this document. For exact HTTP wire shapes
and SDK fixtures, see [ARCH_SIGNING.md](ARCH_SIGNING.md#http-api-contract); for the endpoint
registry file, see [ARCH_DATA_MODEL.md](ARCH_DATA_MODEL.md#endpoint-registry).
For cosigner policy verdict semantics, see [ARCH_POLICY.md](ARCH_POLICY.md).
The `bounded1` authorization contract and external contract-admin signing are
in [ARCH_BOUNDED_DSA.md](ARCH_BOUNDED_DSA.md), key type axes are in
[ARCH_KEYTYPES.md](ARCH_KEYTYPES.md), and the machine-checked
bounded-cosigner choreography is in
[FORMAL_TLA_BOUNDED_COSIGNER_MODEL.md](FORMAL_TLA_BOUNDED_COSIGNER_MODEL.md).

## Contents

- [Status](#status)
- [Roles And Boundaries](#roles-and-boundaries)
- [Key Model](#key-model)
- [Component-Flow Unification Invariants](#component-flow-unification-invariants)
- [Signer-Domain Gating Of User Components](#signer-domain-gating-of-user-components)
- [Component Message](#component-message)
- [Public Cosigner References](#public-cosigner-references)
- [Endpoint Routing](#endpoint-routing)
- [Guarded Transaction Flow](#guarded-transaction-flow)
- [Bounded-Cosigner Transaction Flow](#bounded-cosigner-transaction-flow)
- [Guarded Simulation](#guarded-simulation)
- [Assembly Invariants](#assembly-invariants)
- [Cosigner Policy](#cosigner-policy)
- [Guarded Authorizers](#guarded-authorizers)
- [Mixed Groups](#mixed-groups)
- [Failure Model](#failure-model)
- [Audit](#audit)
- [Corridor v1](#corridor-v1)
- [Implementation Map](#implementation-map)

## Status

Cosigner is a first-class signing architecture, not a policy flag on ordinary
signing. It creates a two-party LogicSig authorization path:

- the user signer proves control of the guarded account key and applies
  signer-domain policy and operator approval, and
- the cosigner signer authorizes the transaction facts under cosigner policy.

The client orchestrates both parties but never holds private key material. The
final transaction is submitted only after component signatures are collected,
verified, assembled into LogicSig arguments, and checked against the canonical
transaction bytes.

## Roles And Boundaries

Bounded contract administration is not a cosigner role. A bounded profile may
independently declare a cosigner spend gate and an external contract-admin rekey
authority. The former uses the `bounded-cosigner1` online flow and a
signer-custodied `.cos` witness; the latter uses `/sign/bounded-admin`,
`aprekey`, and a separately held `.wit` artifact without contacting a cosigner.
Both authorities use the witness key form, but their custody and signature
domains are disjoint. An individual keypair should never be enrolled in both
roles.

Every signer data root has one root `node.yaml` role:

| Role | May hold | Must not hold |
|---|---|---|
| `signer` | ordinary account keys and guarded account keys | signer-custodied witness private keys |
| `cosigner` | witness private keys serving the cosigner role and cosigner-domain policy | ordinary account keys or guarded account keys |

There is no supported `dual` role. Development or production co-location uses
separate data roots and separate `apsigner` processes. Same-host co-location
does not create independent trust; independence is an operational property of
who controls the signer and cosigner nodes.

The node role gates key generation, mnemonic import, restore, key scanning, and
HTTP signing dispatch. Role conflicts fail closed instead of silently skipping
keys.

Primary ownership:

- `internal/noderole`: root role parsing and role integrity.
- `internal/keyclass`: role-versus-key-type classification.
- `internal/signerapp/productruntime`: runtime load/reload with role-aware key scan.
- `internal/signerapp/signing`: signing dispatch and role-specific behavior.

## Key Model

Cosigner uses a role-neutral witness key as its auxiliary signing authority. The
same witness key form may be held externally for a bounded contract-admin
role, but an individual keypair should serve only one role for its entire life.

### Cosigner Keys And Witness Key IDs

Cosigner keys are raw witness keys held by cosigner nodes. They are not
Algorand accounts and cannot spend funds directly.

Their canonical private record is
the selected generation's `keys/<WitnessKeyID>.cos`. The `.cos` container uses the
product store's current term key, bound to the credential's Witness Key ID, and a
canonical `category: witness` payload. It is
distinct from the independently encrypted external `.wit` artifact opened only
by `aprekey`; signer scanning never opens `.wit` or `.wit.json` as private state.

Current cosigner key types:

- `aplane.witness-falcon1024.v1`

They are selected by a 52-character uppercase **Witness Key ID** derived from
the length-prefixed domain, key type, and cosigner public key. Role-specific wire
fields retain the name `component_key`. The ID is txid-shaped but is not an
Algorand address.

The raw cosigner public key is the verifier embedded in a
guarded account's LogicSig bytecode. The selector is a stable lookup handle;
the public key is the cryptographic verifier.

### Guarded Account Keys

Guarded account keys are account-signing LogicSig keys held by a signer node.
They name both the account DSA and the required cosigner DSA.

Current guarded account key types:

- `aplane.falcon1024-cosigner1024.v1`

A guarded account key file stores the resolved cosigner public key and embeds
that same public key in its LogicSig bytecode. Generation may accept a public
Cosigner reference by Witness Key ID, but the durable guarded key stores the
resolved public key.

`aplane.corridor.v1` is not a dedicated guarded key-type class. It is an
optional schema-v2 composed template whose durable metadata combines the
`bounded1` authorization contract, the `cosigner1` spend gate, a framework Merkle
recipient policy, and an external-admin pure rekey. It therefore advertises
`signing_flow: bounded-cosigner1`, not `cosigner1`, and is discovered from metadata
rather than a key-type switch. See [Corridor v1](#corridor-v1).

Guarded account identity is the guarded account `key_type`, not the base
signing primitive. The stored `base_key_type` names the private signing
primitive used for the user component key material and signature packing. It
does not make the base provider responsible for guarded metadata, creation
parameters, TEAL, cosigner reference resolution, or final LogicSig argument
assembly.

Dedicated guarded accounts and cosigner keys are never signed through raw
`/sign`:

- guarded account keys use `/sign/component` with `kind:"user"`, then
  `/sign/assemble`,
- cosigner keys use `/sign/component` with `kind:"cosigner"`,
- ordinary `/sign` rejects all guarded account key types and cosigner key types.

Cosigner-enabled bounded spends are also rejected by ordinary `/sign`. They use
`/plan`, `/sign/component` with bounded-base and cosigner targets, and
`/sign/assemble` for source-aware final assembly. Their external-admin
rekey path remains `/sign/bounded-admin` and never contacts the cosigner.

This preserves the two-party invariant: a guarded account requires both a user
component signature and a cosigner component signature. The endpoint split is
also a contract statement: `/sign` returns only submittable signed
transactions produced by keys this signer can complete alone, while the
component/assembly surface handles partial, multi-party authorization.

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

Assembly authorization remains flow-specific behind the shared request:
guarded targets carry user and cosigner signatures; bounded-cosigner targets carry
base signatures, a cosigner signature, and an assembly receipt. No shared route
may allow either target kind to use the other's weaker material.

## Signer-Domain Gating Of User Components

Guarded signing has two independent authorization gates, one per party:

- the **user signer** gates user-role component signing with the same
  signer-domain machinery as ordinary `/sign`: hard policy rejection,
  always-review rules, and blocking operator approval. The guarded account is
  the per-target policy key (its own policy document, or the signer's node
  default), and every
  non-target position in the canonical group is evaluated as a foreign leg, so
  dangerous fields on co-signed legs (rekey, close, clawback) force operator
  review exactly as they do on `/sign`. User Auto-Approve satisfies these
  review requirements without a prompt, while hard policy rejection still applies.
- the **cosigner signer** gates cosigner-role component signing with the
  deterministic cosigner policy domain: allow signs, everything else rejects,
  and there is no operator prompt.

The user component signature therefore expresses both proof of control and a
signer-domain authorization decision; the cosigner signature expresses the
cosigner-domain policy decision. Neither gate replaces the other: a permissive
signer policy still cannot move funds the cosigner policy refuses, and a
compromised client credential cannot drive guarded sends past the signer's
review rules or operator approval.

First-party client choreography is user-first: it completes the user-side gate
and obtains the user or bounded base component before requesting a cosigner
component. This avoids cosigner work and ordinary first-party audit events for
transactions the user signer rejects, and it gives submission and simulation
the same predictable operator flow.

The cosigner endpoint does not receive or verify the prior user component. A
client that calls cosigner-role `/sign/component` directly can ask the cosigner to
evaluate the transaction first. The resulting cosigner component is not spending
authority by itself: final assembly and the on-chain program still require the
matching user or base spending signature and all account/program checks.

The guarded key is validated against signer inventory metadata — no key
decryption — before the gates run, so a rejected request or an operator prompt
never triggers a private-key operation and approval never precedes a
key-not-found rejection. The key is decrypted only after the gates pass, under
the final execution gate, so shutdown or lock transitions cannot
complete while component key material is in use. In a mixed group the
operator may be prompted twice — once for the guarded component request and
once for the ordinary `/sign` legs; both prompts render the full group
context. The `auto_approve_self_noop_transfer` rule never fires for guarded
groups because they are always pre-grouped, matching `/sign` semantics for
pre-grouped requests.

## Component Message

User and cosigner component signatures sign the same transaction identity with
different role separation:

```text
SHA512_256("APLANE_COSIGNER_V1" || role_byte || txid)
```

`role_byte` is `0x01` for the user role and `0x02` for the cosigner role.
`txid` is the canonical 32-byte transaction ID for the frozen group entry.

The message deliberately does not contain a separate sender or authorizer
field. Sender and `AuthAddr` consistency are verified from the canonical
transaction bytes during assembly, which requires the guarded LogicSig address,
and `AuthAddr` when needed, to equal the requested guarded account. The cosigner policy decision is scoped to the
transaction facts, not to which guarded key acted as authorizer.

Owned primitives:

- `internal/cosigner/message`: message construction. Clients and signers must
  use that shared primitive, or an SDK equivalent with matching vectors, rather
  than reconstructing the message independently.
- `internal/cosigner/verify`: component signature verification (signer-side
  only; clients treat component signatures as opaque).
- SDKs must match the same vectors rather than reconstructing a variant.

Changing the message shape is a versioned cryptographic and LogicSig change.
For example, per-authorizer cosigner allowlists would require binding the
authorizer in the signed message and updating the matching on-chain LogicSig
verification path.

## Public Cosigner References

Signer nodes need public cosigner metadata to generate guarded accounts, but they
do not need cosigner private keys.

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
guarded account. Manual import and removal therefore require an unlocked
product runtime in addition to `cosigners.manage`. Re-importing the identical authority
is idempotent. Rebinding an existing name to another Witness Key ID is rejected;
replacement requires an explicit audited remove followed by import.

Public reference records are stored under:

```text
identities/default/cosigners/
```

They contain public metadata only: Witness Key ID, key type, cosigner public key
hex, and import time. They are not endpoint ownership proofs and do not
authorize a future transaction. The guarded account's embedded public key is
the trust input that matters after generation.

### Cosigner Key File

`apadmin cosigner export <witness-key-id> [output-json]` and the apadmin TUI's
**Export Cosigner Key** emit the canonical `aplane.witness-key-public.v1`
document and nothing else. The command reads the
`keys/<witness-key-id>.wit.json` sidecar, verifies that `<witness-key-id>`
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
public key encoded in hex; it is the value embedded into guarded-account
LogicSig bytecode and supplied as `cosigner_public_key` during guarded account
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
signer. When generating a dedicated guarded account or a cosigner-enabled bounded
template, callers may provide
`cosigner=<witness-key-id>` instead of `cosigner_public_key=<hex>`.
`cosigner=<name>` is also accepted as a compatibility input. The signer resolves the
Witness Key ID or name to `public_key_hex`, verifies that the reference key type
matches the definition's required cosigner key type,
rejects requests that provide both forms, and persists the resolved
`cosigner_public_key` plus the template's other creation parameters in the key
file. `aplane.corridor.v1`, for example, persists its public recipient list and
complete bounded metadata; later signing does not require the YAML source to
remain installed.

Product `/keytypes` metadata may expose imported references as a
creation parameter named `cosigner` with `type:"select"` and `options[]`
containing Witness Key IDs whose cosigner key type matches the guarded
account key type. This is UI metadata for generation clients such as `apadmin`;
the durable key file still stores the resolved `cosigner_public_key`; other
provider-specific creation parameters remain exposed normally.

The `apadmin` TUI also receives the optional `cosigner_component_key_type` in
its internal admin key-type projection and joins it with
`list_cosigner_references`. Guarded generation displays aliases but submits the
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

Runtime guarded-send routing works like this:

1. Signer inventory labels a dedicated guarded account with
   `signing_flow: cosigner1`, or a cosigner-enabled bounded account with
   `signing_flow: bounded-cosigner1`. Both expose their
   `cosigner_component_key_type` and required cosigner public key. The client routes
   on the flow label (key-type strings are opaque to the client) and fails fast
   on flow labels it does not implement.
2. The client queries authenticated `/keys` on the configured cosigner endpoints
   with bounded parallelism and validates each advertised Witness Key ID.
3. The client builds an operation-scoped route snapshot and requires exactly
   one endpoint for every required embedded public key.
4. Component signing reuses the already-verified endpoint connection from that
   snapshot.

Endpoint import and `/keys` discovery are routing metadata. They do not prove
ownership. If an endpoint is wrong or stale, assembly or on-chain LogicSig
verification fails unless that endpoint controls the embedded cosigner private
key. Deleting an advertised cosigner key causes guarded signing to fail before
submission with a missing-advertised-key error.

Use `apshell endpoints add` for guided setup of one cosigner connection. Use
`apshell cosigner status` for point-in-time endpoint observations and account
requirements, including unmatched witnesses. It shares the signing resolver's
bounded sweep and uniqueness rules, closes all probe connections, and does not
persist inventories or routes. Missing primary-signer inventory is explicitly
unavailable, not an empty list of guarded accounts. Route availability is not
a policy verdict or proof of private-key possession.
`apshell endpoints discover-cosigners` remains the advanced inventory diagnostic.
Signer-side apadmin displays public reference metadata only; it does not
probe endpoints or persist route associations.

## Guarded Transaction Flow

The client uses guarded orchestration when any transaction's effective signer
is a guarded account. The effective signer is the sender unless the sender is
rekeyed, in which case it is the resolved `AuthAddr`.

Supported guarded cases include:

- guarded account as `txn.Sender`,
- standard account rekeyed to a guarded account, where `txn.Sender` is the
  standard account and `AuthAddr` is the guarded account,
- mixed groups containing guarded and non-guarded signer-controlled positions.

The submit flow is:

1. Resolve effective signers.
2. Classify guarded and non-guarded target positions.
3. Send the draft group to the user signer's `/plan`, which fixes dummy
   transactions, fees, and group ID before any signature is requested.
4. Request user-role component signatures from the primary signer for guarded
   targets. This runs the signer-domain gates and may block on operator
   approval.
5. If the group contains non-guarded signer positions, request ordinary `/sign`
   signatures over the same canonical bytes; a rejection stops the flow before
   the cosigner sees the group.
6. Request cosigner-role component signatures from the routed cosigner endpoint
   for guarded targets.
7. Call `/sign/assemble` on the user signer to verify components, pack LogicSig
   arguments, verify passthrough bytes, and return signed transaction bytes.
8. Route the exact assembled group to algod submission or client-side
   simulation.

## Bounded-Cosigner Transaction Flow

For `bounded-cosigner1`, the first-party client uses a distinct user-first
choreography:

1. Resolve the bounded target from `signing_flow` and durable inventory.
2. Send the draft group to `/plan`, then pass the exact frozen group plus its
   closed target/context/dummy position partition to `/sign/component` with
   `kind:"bounded-base"`.
   The signer independently reconstructs the durable bounded authorization and
   validates grouping, resources, fees, policy, and operator approval without
   changing the bytes. It returns base signature args, runtime args, and an
   assembly receipt bound to those bytes.
3. Sign any non-guarded context positions through ordinary `/sign`; the
   cosigner is asked only after the user side is complete.
4. Route those exact frozen transactions to the cosigner endpoint and request a
   cosigner-role `/sign/component` signature.
5. Return the base component, receipt, cosigner signature, and exact group to the
   user signer through `/sign/assemble` with `kind:"bounded-cosigner"`.
6. The signer verifies all sources, derives declared Merkle proofs, constructs
   the metadata-declared argument layout, and returns the executable group.

The first-party client does not ask the cosigner first. It still rejects a group
that mixes `cosigner1` and `bounded-cosigner1` targets. The wire contracts are now
shared, but the account signer does not yet implement the required multi-gate,
all-target preflight that releases no component unless both guarded-user and
bounded-base authorization complete. The guard remains fail-closed until that
atomicity rule is implemented and tested end to end. This is a client
orchestration constraint, not a cosigner-endpoint or signer-side whole-group
security check.
Signer endpoints validate the targets they sign or assemble; they do not infer
the flow of foreign group positions. Non-target positions are carried as exact
passthrough signed bytes in the final assembly request.

## Guarded Simulation

Guarded simulation follows the complete flow above. The user signer runs
ordinary policy and operator approval before releasing user component
signatures; the cosigner runs its ordinary deterministic policy; local
non-guarded positions use `/sign`; and the final group is produced by
`/sign/assemble`. Only after assembly and frozen-byte verification does the
client send the exact executable group to its configured algod simulation
endpoint instead of the submission endpoint.

There is no simulation claim at any signer boundary. Apsigner cannot know how
the client will route released signatures, and the client holds a submittable
guarded group until its validity window expires. Headless simulation therefore
requires the same user auto-approval configuration as headless submission;
otherwise a connected admin client must approve it.

All component signatures and ordinary signatures are over the same frozen
group. This matters for mixed groups: guarded targets, non-guarded originals,
and resource-dummy transactions must all agree on transaction bytes, group ID,
selected-path LogicSig resources, and aggregate fee.

## Assembly Invariants

Assembly is the main server-side backstop for cosigner signing. Dedicated guarded
assembly verifies:

- the requested guarded key is a local guarded account key,
- the user component signature verifies for role `user` and the target txid,
- the cosigner component signature verifies for role `cosigner` and the target
  txid against the cosigner public key embedded in the guarded account key,
- packed LogicSig arguments match the guarded template's expected layout,
- the resulting LogicSig address equals the guarded account,
- passthrough signed bytes match the canonical transaction IDs,
- when `txn.Sender != guarded_account`, the signed transaction carries
  `AuthAddr == guarded_account`.

These checks are safety-relevant. Supporting guarded authorizers is not a
loosening of the two-party invariant; it replaces a sender-equality shortcut
with explicit authorizer semantics.

Bounded-cosigner assembly additionally verifies the spending-key assembly
receipt, equality of planned and loaded durable metadata, the frozen base
argument layout, the cosigner slot and path mask, every runtime and derived
argument source, and the final bounded LogicSig address. It derives Merkle
proofs from stored public parameters; clients cannot supply a derived or cosigner
slot through ordinary LogicSig arguments.

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
evaluated before the cosigner key is loaded. Decode refuses review-producing fields and refuses
to `allow` any transaction type but `pay` and `axfer` on a cosigner node, so
the only cosigner-specific rule ID is `cosigner_policy:reject_rekey`; every
other verdict uses the common rule IDs in
[ARCH_POLICY.md](ARCH_POLICY.md).

A key's document governs a virtual account set: every account whose guarded
key was composed with that cosigner key, on any signer that holds the key's
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

The cosigner does not decide whether the user signer is allowed to use a guarded
key. It decides whether the target transaction facts are allowed under cosigner
policy. Current cosigner policy is transaction-focused and DSA-agnostic: it
examines decoded transaction details and transfer movements, not which DSA
mechanism produced the user component signature.

Cosigner transfer policy is a positive authorization surface. Supported target
movements include direct transfers that policy routing can evaluate. Target
shapes that cannot be represented as supported cosigner movements fail closed.
For dedicated `cosigner1` rekeys, `reject_rekey:true` is a coarse deny-all
switch. If it is false, a non-zero `RekeyTo` is authorized only when the
transaction is a pure 0 ALGO self-payment and `rekey_policy.allowed` contains a
matching sender-to-target edge. Missing `rekey_policy` still fails closed.
Bounded cosigner v1 deliberately gates spends only. Cosigner-enabled bounded
profiles reject spending-key-authorized rekey at definition and durable
metadata validation, because that path would bypass cosigner control and has no
bounded-cosigner1 endpoint choreography. Their external-admin rekey path forbids
the cosigner slot and does not evaluate cosigner rekey policy.

See [ARCH_POLICY.md](ARCH_POLICY.md) for the rule inventory, domain-specific
schema constraints, route behavior, and reject/review/approve mapping.

## Guarded Authorizers

A guarded account can be the effective signer for another account rekeyed to
it. In that case:

```text
Sender = S
AuthAddr = G
LogicSig address = G
```

where `S` is the account whose funds move and `G` is the guarded account. The
transaction is still `S`'s transaction. Cosigner policy remains scoped to the
transaction facts. Assembly verifies that the guarded LogicSig address and
`AuthAddr` both equal `G`.

Current v1 semantics do not expose an authorizer field to cosigner policy and do
not bind authorizer identity into the cosigner component message. That is
intentional for the transaction-focused model. If a future policy wants
per-authorizer delegation controls, the component message and LogicSig program
must change together so the cosigner's authorizer-conditioned decision is bound
cryptographically.

## Mixed Groups

Mixed guarded/non-guarded groups use one canonical group and preserve full
approval context:

- guarded targets receive user and cosigner component signatures,
- non-guarded signer targets use ordinary `/sign`, which completes before the
  cosigner is asked, so the user-first choreography covers the whole group and
  a rejected non-guarded position never reaches the cosigner,
- resource-dummy transactions are included consistently for LogicSig argument
  and opcode capacity,
- signer-side `/sign` sees the complete group context for non-guarded approval
  and policy,
- `/sign/assemble` receives signed non-guarded entries as passthrough bytes.

The client supplies accurate selected-path `lsig_resources` for guarded
positions when it calls ordinary `/sign` for the non-guarded subset. These
values come from signer inventory, not client estimates. The signer keeps its
normal consensus resource computation as an independent backstop. A mis-sized
client group fails early with a clear immutable-group rejection rather than
later as an opaque algod evaluation failure.

## Failure Model

Cosigner failures are fail-closed:

- signer-domain policy rejection, always-review denial, operator denial, or a
  missing admin client fail user-role component signing before any private-key
  operation,
- there is no client-declared simulate mode on any signer endpoint; simulation
  follows the ordinary approval path,
- locked or unreachable cosigner endpoints cannot produce component signatures,
- failed endpoint authentication, trust, or inventory validation contributes
  no route from that endpoint,
- duplicate usable live routes for a required witness fail the operation,
- deleted cosigner keys stop being advertised by `/keys` and guarded signing
  fails before cosigner signing,
- missing cosigner signatures fail assembly,
- mismatched user or cosigner signatures fail assembly,
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
limits under a 30-second total deadline, so guarded-signing discovery latency
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

`aplane.corridor.v1` is the first bundled profile that composes optional cosigner
authorization into `bounded1`. It is an optional schema-v2 template source at
`library/templates/aplane.corridor.v1.yaml`; it is not a compiled provider,
authorization-contract identifier, key category, or special transaction
classifier.

The dimensions are independent:

| Dimension | Corridor v1 value |
|---|---|
| Full key type | `aplane.corridor.v1` |
| Account form | DSA LogicSig |
| Base signing primitive | `aplane.falcon1024.v1` |
| Authorization contract | `bounded1` |
| Layer-3 policy | framework-owned `merkle_allowlist` |
| Spend auxiliary authority | `cosigner1`, Falcon witness, required on spend |
| Rekey auxiliary authority | distinct offline Falcon contract-admin witness |
| Advertised signing flow | `bounded-cosigner1` |

Changing one dimension does not reinterpret the others. In particular,
`bounded1` is the on-chain envelope and durable metadata vocabulary, while
`bounded-cosigner1` is the client/server choreography used to obtain a complete
spend signature.

### V1 Compatibility Ratification

This schema-v2 bounded template is the first supported
`aplane.corridor.v1`. Earlier development catalog entries used a compiled
guarded provider with different TEAL, address derivation, and choreography;
they were pre-release artifacts and do not define a durable Corridor
compatibility contract. No account generated from that provider is supported
as a production Corridor account. Developer or LocalNet instances must be
discarded or decommissioned and recreated from this template. The key type,
canonical program, metadata, and `bounded-cosigner1` flow documented here become
the Corridor v1 compatibility baseline.

The complete cosigner-bearing profile encoding, behavior parameters, Merkle
root/proof, argument masks, program binding, and admin transcript are frozen
together in
[bounded1 Golden vector 2](ARCH_BOUNDED_DSA.md#golden-vector-2-corridor).

### Accepted Transactions

Every accepted path requires the Falcon spending signature and
`Fee <= 10,000` microAlgos. Spend paths admit only:

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
[bounded1 Merkle allowlist compatibility contract](ARCH_BOUNDED_DSA.md#merkle-allowlist-compatibility-contract).

Corridor rejects close remainder, asset close, clawback, hybrid rekey+spend,
unsupported transaction types, missing or malformed proofs, missing cosigner
authorization, and arguments supplied from the wrong source.

The only administrative operation is the bounded pure-rekey normal form. It
requires the spending signature plus the distinct external contract-admin
signature. It does not require or permit a cosigner signature or Merkle proof.
The admin witness is therefore a rekey co-authorizer, not an independent
spending-key recovery key.

### Custody And Generation

Generation resolves three distinct Falcon keypairs:

1. the signer-held spending key;
2. the cosigner-node `.cos` witness selected by `cosigner` or supplied as
   `cosigner_public_key`; and
3. the offline `.wit` contract-admin witness represented by
   `bounded_admin_public_key`.

Visible collisions reject. The generated `.key` stores the resolved public
parameters, bytecode, and complete signing-metadata version 2
`bounded_authorization` object. Signing uses that stored authority rather than
the installed template. Supported disable/remove operations refuse while a
stored key still uses the template's key type.

The repository YAML is an install source only. Fresh signer identities do not
enable Corridor by default; operators import and enable it through the normal
KeyType Library workflow before generation.

The custody consequences are asymmetric:

- a stolen spending key cannot rekey the account without the admin witness;
- the spending key plus the admin witness can rekey away from an unavailable
  or compromised cosigner or replace the current Corridor program;
- the admin witness cannot recover an account after the spending key is lost.

Operators must therefore back up the spending key and admin witness as distinct
required authorities rather than treating the admin witness as a substitute
for spending-key recovery.

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

Ordinary `/sign` rejects Corridor spends.

The cosigner component is transaction-scoped: it binds the cosigner role and TxID,
not the Corridor account, authorizer, or program binding. Final assembly and
the LogicSig perform those account/program checks. Reusing one cosigner key
across Corridor accounts therefore creates a shared transaction-policy domain;
per-authorizer cosigner policy would require a new component-message and LogicSig
version. See [Component Message](#component-message).

### Close And Decommission

Corridor v1 has no direct close path. Decommissioning is deliberately a
two-step governance action:

1. use the bounded contract-admin ceremony to pure-rekey the account to a
   successor authorizer; then
2. use that successor authorizer to close the ALGO account or asset positions.

Step 1 requires both the existing spending key and the contract-admin witness.
It can escape a failed cosigner or current policy, but it cannot recover a lost
spending key.

`CloseRemainderTo`, `AssetCloseTo`, and `AssetSender` remain zero on every
transaction authorized by Corridor itself.

### Compiler And Resource Budget

Corridor stores one resource profile over its final compiler-auto-salted
bytecode. Inventory materializes maximum argument bytes and reviewed opcode
ceilings for all three bounded path cells (spend, spending-key rekey, and
contract-admin rekey); a resource cell does not authorize a path. Corridor
admits spend and contract-admin rekey, not spending-key-only rekey. Under
v42, argument/opcode capacity determines the minimum group size; bytecode above
the final group's free program pool contributes to the aggregate fee instead
of manufacturing extra dummies.

The pinned one-recipient compiler cell is approximately 5.9 KB of final
bytecode. Its worst-case spend and admin argument layouts remain distinct and
are derived from durable bounded metadata. The planner evaluates the selected
path, adds only required resource dummies, applies the v42 program surcharge,
and rejects the finalized transaction if its fee exceeds the compiled 10,000
microAlgo ceiling. Compiler golden values are toolchain-pinned; the stored
final bytecode is authoritative.

## Implementation Map

Primary packages and files:

- `pkg/signerapi`: HTTP DTOs for component signing, assembly, and key inventory.
- `internal/witness`: witness key-type identifiers, Witness Key ID derivation,
  public identity validation, keypair validation, and custodian capabilities.
- `internal/cosigner/keytypes`: guarded-account key-type mapping and cosigner
  enrollment requirements.
- `internal/cosigner/message`: role-separated component messages.
- `internal/cosigner/canonical`: canonical group decoding and group hashing.
- `internal/cosigner/verify`: component signature verification (signer-side
  only).
- `internal/cosigner/cosignerrefs`: public cosigner reference catalog.
- `internal/signerapp/signing`: frozen component validation, bounded
  authorization reconstruction, cosigner policy
  evaluation, signer-domain approval gates for user components (`gate.go`,
  `component_gate.go`), user/cosigner component signing, assembly, and `/sign`
  rejection gates.
- `internal/signerapp/rest`: REST service methods backing `/sign/component`,
  `/sign/assemble`, `/keys`, and `/keytypes`.
- `internal/signerapp/daemon`: HTTP runtime (`http_runtime.go`) that registers
  these routes on the signer mux and dispatches them to the `rest` service
  methods.
- `internal/engine/guarded`: guarded and bounded-cosigner transaction
  orchestration and cosigner endpoint resolution; `internal/engine` composes
  that owner into the client runtime.
- `internal/config`: endpoint registry parsing (`schema_version` 2 only; retired
  `signer_port`/`local_port`/`token_file` fields are dropped on load).
- `internal/apshellapp`: endpoint commands and read-only cosigner discovery.
- `lsig/falcon1024_guarded`: guarded LogicSig provider and template behavior.
- `lsig/composeddsa`: optional bounded cosigner composition and framework-owned
  fixed/Merkle Layer-3 policies.
- `library/templates/aplane.corridor.v1.yaml`: the canonical optional Corridor
  profile source.
- `internal/apadminapp/catalog.go`: public cosigner export/import/list/show/remove
  workflows used by `apadmin`.
- `internal/signerapp/policycmd`: live and rescue policy workflows through
  `apadmin`, including per-key cosigner document apply and removal.
- `internal/signerapp/policyapply`: shared policy check and generation-commit
  rules.
- `internal/signerapp/signing/cosigner_policy.go`: cosigner key and policy
  selection and evaluation.

Representative tests:

- `internal/signerapp/signing/component_test.go`
- `internal/policy/doc_v1_test.go`
- `internal/policy/store_v1_test.go`
- `internal/policy/transfer_routing_eval_test.go`
- `internal/engine/guarded/submit_test.go`
- `internal/apshellapp/endpoints_test.go`
- `internal/apadminapp/catalog_test.go`
- `scripts/docker-local-four-node-smoke.sh`
