# Cosigner Architecture

This document describes APlane's cosigner subsystem: node roles, cosigner keys,
guarded accounts, endpoint discovery, guarded transaction orchestration, and
the trust boundaries between a user signer and a cosigner signer.

For exact wire shapes, on-disk schemas, endpoint file contracts, and SDK
fixtures, see [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md) and
[ARCH_HTTP_API.md](ARCH_HTTP_API.md). For cosigner policy verdict semantics, see
[ARCH_POLICY.md](ARCH_POLICY.md).

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
rather than a key-type switch. See [ARCH_CORRIDOR.md](ARCH_CORRIDOR.md).

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
bytes and validate them without mutation; they never add resource dummies,
pool fees, regroup, or otherwise repair the request.

The signer intentionally does not prove that frozen bytes came from `/plan`.
It independently reconstructs signer-owned facts and may accept any canonical,
envelope-valid group. For a component call, the bytes evaluated by policy, the
bytes rendered for operator approval, and the bytes used to derive component
messages are one and the same. Bounded-cosigner component signing therefore
moves from approving a plan constructed inside the signing call to approving
the supplied frozen group after the signer re-derives and validates its bounded
authorization envelope.

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
  the per-target policy key (signer `policy.json` key overrides apply), and every
  non-target position in the canonical group is evaluated as a foreign leg, so
  dangerous fields on co-signed legs (rekey, close, clawback) force operator
  review exactly as they do on `/sign`.
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
`txid` is the canonical transaction ID for the frozen group entry.

The message deliberately does not contain a separate sender or authorizer
field. Sender and `AuthAddr` consistency are verified from the canonical
transaction bytes during assembly. The cosigner policy decision is scoped to the
transaction facts, not to which guarded key acted as authorizer.

Owned primitives:

- `internal/cosigner/message`: message construction.
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

The additive `aplane.cosigner-enrollment.v1` public handoff may compose that
same canonical witness-public reference with an optional portable endpoint
envelope. apadmin validates the complete bundle and imports only its public
witness reference through authorized local IPC. Endpoint metadata is
informational; apshell owns endpoint configuration, token enrollment, host
trust, and live discovery. apadmin does not access client state.

The client-side `cosigner add` workflow accepts either public document. It treats
the witness reference as the expected authority and any combined endpoint as a
portable route suggestion. Under the shared client-data lock it revalidates and
writes only the chosen endpoint alias, then releases the lock before any SSH
trust, token enrollment, or network operation. Token enrollment uses a
standalone SSH connection and does not disturb the primary signer tunnel.
Cosigner HTTP requests use restricted direct channels on that authenticated SSH
connection instead of a transient local forwarding listener. Verification
queries only the chosen endpoint and requires its validated, deduplicated
`/keys` inventory to contain the exact key type, public key, and derived
Witness Key ID from the document.

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

## Endpoint Routing

Client endpoint routing lives in:

```text
$APCLIENT_DATA/endpoints.yaml
```

The registry may contain one signer endpoint and at most 12 cosigner endpoints.
Cosigner endpoint records carry connection metadata only and do not accept a
`local_port` setting.

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

Use `apshell cosigner add` for guided setup of one public handoff. Use
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
3. Build one canonical group: dummy transactions, fees, and group ID are fixed
   before any signature is requested.
4. Request user-role component signatures from the primary signer for guarded
   targets. This runs the signer-domain gates and may block on operator
   approval.
5. Request cosigner-role component signatures from the routed cosigner endpoint for
   guarded targets.
6. If the group contains non-guarded signer positions, request ordinary
   signatures over the same canonical bytes.
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
3. Route those exact frozen transactions to the cosigner endpoint and request a
   cosigner-role `/sign/component` signature.
4. Return the base component, receipt, cosigner signature, and exact group to the
   user signer through `/sign/assemble` with `kind:"bounded-cosigner"`.
5. The signer verifies all sources, derives declared Merkle proofs, constructs
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

On a cosigner node, each cosigner key has its own v1 policy document,
`policies/<WitnessKeyID>.json` in the selected generation, specified in
[ARCH_POLICY_FORMAT.md](ARCH_POLICY_FORMAT.md). A `/sign/component` request's
`component_key` selects the document: a key the node does not hold fails as a
bad request, and a held key with no document rejects with
`cosigner_policy:key_has_no_policy`. There is no node-wide cosigner policy, so a
new key rejects every request until its document is applied. Policy is
evaluated before the cosigner key is loaded. The verdict model is direct
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
For dedicated `cosigner1` rekeys, `reject_rekey:true` remains a coarse deny-all
switch. If it is not set, a non-zero `RekeyTo` is authorized only when the
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
- endpoint authentication or host-trust failures block routing,
- malformed or duplicate live cosigner inventory fails the operation,
- deleted cosigner keys stop being advertised by `/keys` and guarded signing
  fails before cosigner signing,
- missing cosigner signatures fail assembly,
- mismatched user or cosigner signatures fail assembly,
- stale endpoint routing cannot pass assembly or on-chain LogicSig verification
  without the embedded cosigner private key,
- unsupported cosigner policy outcomes fail closed.

Unavailable or locked endpoints may be skipped only when the remaining live
results resolve every required key. Authentication failures, malformed
records, duplicate public keys, configuration errors, and SSH host-key
mismatches fail closed.

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
- `internal/engine`: guarded and bounded-cosigner transaction orchestration and
  cosigner endpoint resolution.
- `internal/config`: endpoint registry parsing and bounded v1 read migration.
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
