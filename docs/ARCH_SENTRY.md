# Sentry Architecture

This document describes APlane's sentry subsystem: node roles, sentry keys,
guarded accounts, endpoint discovery, guarded transaction orchestration, and
the trust boundaries between a user signer and a sentry signer.

For exact wire shapes, on-disk schemas, endpoint file contracts, and SDK
fixtures, see [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md) and
[ARCH_HTTP_API.md](ARCH_HTTP_API.md). For sentry policy verdict semantics, see
[ARCH_POLICY.md](ARCH_POLICY.md).

## Status

Sentry is a first-class signing architecture, not a policy flag on ordinary
signing. It creates a two-party LogicSig authorization path:

- the user signer proves control of the guarded account key and applies
  signer-domain policy and operator approval, and
- the sentry signer authorizes the transaction facts under sentry policy.

The client orchestrates both parties but never holds private key material. The
final transaction is submitted only after component signatures are collected,
verified, assembled into LogicSig arguments, and checked against the canonical
transaction bytes.

## Roles And Boundaries

Bounded contract administration is not a sentry role.
Bounded accounts advertise the distinct `bounded1` signing flow, use no sentry
key discovery, and never call `/sign/component`, `/sign/assemble`, or
`/simulate/guarded`. Apsigner produces a spending partial through
`/sign/bounded-admin`; the separately held `.wit` authority is
applied by `aprekey`. Both roles use the witness key form, but the
custodians expose disjoint signature domains. An individual keypair should
never be enrolled in both roles.

Every signer data root has one root `node.yaml` role:

| Role | May hold | Must not hold |
|---|---|---|
| `signer` | ordinary account keys and guarded account keys | signer-custodied witness private keys |
| `sentry` | witness private keys serving the sentry role and sentry-domain policy | ordinary account keys or guarded account keys |

There is no supported `dual` role. Development or production co-location uses
separate data roots and separate `apsigner` processes. Same-host co-location
does not create independent trust; independence is an operational property of
who controls the signer and sentry nodes.

The node role gates key generation, mnemonic import, restore, key scanning, and
HTTP signing dispatch. Role conflicts fail closed instead of silently skipping
keys.

Primary ownership:

- `internal/noderole`: root role parsing and role integrity.
- `internal/keyclass`: role-versus-key-type classification.
- `internal/signerapp/identity`: runtime load/reload with role-aware key scan.
- `internal/signerapp/signing`: signing dispatch and role-specific behavior.

## Key Model

Sentry uses a role-neutral witness key as its auxiliary signing authority. The
same witness key form may be held externally for a bounded contract-admin
role, but an individual keypair should serve only one role for its entire life.

### Sentry Keys And Witness Key IDs

Sentry keys are raw witness keys held by sentry nodes. They are not
Algorand accounts and cannot spend funds directly.

Their canonical private record is
`identities/<identity>/keys/<WitnessKeyID>.sen`. The `.sen` container uses the
identity keystore master key and canonical `category: witness` payload. It is
distinct from the independently encrypted external `.wit` artifact opened only
by `aprekey`; signer scanning never opens `.wit` or `.wit.json` as private state.

Current sentry key types:

- `aplane.witness-falcon1024.v1`

They are selected by a 52-character uppercase **Witness Key ID** derived from
the length-prefixed domain, key type, and sentry public key. Role-specific wire
fields retain the name `component_key`. The ID is txid-shaped but is not an
Algorand address.

The raw sentry public key is still important: it is the verifier embedded in a
guarded account's LogicSig bytecode. The selector is a stable lookup handle;
the public key is the cryptographic verifier.

### Guarded Account Keys

Guarded account keys are account-signing LogicSig keys held by a signer node.
They name both the account DSA and the required sentry DSA.

Current guarded account key types:

- `aplane.falcon1024-sentry1024.v1`
- `aplane.corridor.v1`

A guarded account key file stores the resolved sentry public key and embeds
that same public key in its LogicSig bytecode. Generation may accept a public
Sentry reference by Witness Key ID, but the durable guarded key stores the
resolved public key.

`aplane.corridor.v1` is always Falcon-1024 for both the user component key and
the sentry component key. In addition to `sentry_public_key`, its key file
stores `recipients`, an `address[]` creation parameter compiled into a Merkle
root in the LogicSig. During `/sign/assemble`, the signer appends the recipient
Merkle proof as LogicSig arg 2 for non-self `pay` and `axfer` targets. Pure
0 ALGO self-payment rekeys use no proof; they are authorized by sentry
`rekey_policy` before the sentry component signature is issued.

This is an intentional split in enforcement boundaries. Corridor transfers
have an on-chain floor: even if both the user component key and sentry component
key are compromised, value can move only to recipients in the compiled Merkle
root. Corridor rekeys are different: the LogicSig enforces only the pure rekey
transaction shape, while the allowed rekey target is authorized off-chain by
the sentry key plus sentry `rekey_policy`. A compromised sentry key with a
matching user component signature can therefore authorize any target that the
effective sentry policy permits.

Guarded account identity is the guarded account `key_type`, not the base
signing primitive. The stored `base_key_type` names the private signing
primitive used for the user component key material and signature packing. It
does not make the base provider responsible for guarded metadata, creation
parameters, TEAL, sentry reference resolution, or final LogicSig argument
assembly.

Guarded accounts and sentry keys are never signed through raw
`/sign`:

- guarded account keys use `/sign/component` with role `user`, then
  `/sign/assemble`,
- sentry keys use `/sign/component` with role `sentry`,
- ordinary `/sign` rejects all guarded account key types and sentry key types.

This preserves the two-party invariant: a guarded account requires both a user
component signature and a sentry component signature. The endpoint split is
also a contract statement: `/sign` returns only submittable signed
transactions produced by keys this signer can complete alone, while the
component/assembly surface handles partial, multi-party authorization.

## Signer-Domain Gating Of User Components

Guarded signing has two independent authorization gates, one per party:

- the **user signer** gates user-role component signing with the same
  signer-domain machinery as ordinary `/sign`: hard policy rejection,
  always-review rules, and blocking operator approval. The guarded account is
  the per-target policy key (`policy.yaml` key overrides apply), and every
  non-target position in the canonical group is evaluated as a foreign leg, so
  dangerous fields on co-signed legs (rekey, close, clawback) force operator
  review exactly as they do on `/sign`.
- the **sentry signer** gates sentry-role component signing with the
  deterministic sentry policy domain: allow signs, everything else rejects,
  and there is no operator prompt.

The user component signature therefore expresses both proof of control and a
signer-domain authorization decision; the sentry signature expresses the
sentry-domain policy decision. Neither gate replaces the other: a permissive
signer policy still cannot move funds the sentry policy refuses, and a
compromised client credential cannot drive guarded sends past the signer's
review rules or operator approval.

In the submit flow, gate ordering is user-first: the sentry only evaluates
requests the user side has already committed to, so submit-flow sentry audit
records correspond to user-approved transactions, and sentry component
signatures are not issued for submissions an operator later denies. Contained
simulation is the documented exception: the client fetches sentry component
signatures before the user signer's gates run, so simulation may produce
sentry signatures and sentry audit approvals for transactions the user side
never approves. Those signatures are inert on their own — the matching user
component exists only inside the signer, and a later submit of the same
transaction still passes the full user-side gate.

The guarded key is validated against signer inventory metadata — no key
decryption — before the gates run, so a rejected request or an operator prompt
never triggers a private-key operation and approval never precedes a
key-not-found rejection. The key is decrypted only after the gates pass, under
the runtime operation lease (`BeginOperation`), so decommission cannot
complete while component key material is in use. In a mixed group the
operator may be prompted twice — once for the guarded component request and
once for the ordinary `/sign` legs; both prompts render the full group
context. The `auto_approve_self_no_op_transfer` rule never fires for guarded
groups because they are always pre-grouped, matching `/sign` semantics for
pre-grouped requests.

## Component Message

User and sentry component signatures sign the same transaction identity with
different role separation:

```text
SHA512_256("APLANE_SENTRY_V1" || role_byte || txid)
```

`role_byte` is `0x01` for the user role and `0x02` for the sentry role.
`txid` is the canonical transaction ID for the frozen group entry.

The message deliberately does not contain a separate sender or authorizer
field. Sender and `AuthAddr` consistency are verified from the canonical
transaction bytes during assembly. The sentry policy decision is scoped to the
transaction facts, not to which guarded key acted as authorizer.

Owned primitives:

- `internal/sentry/message`: message construction.
- `internal/sentry/verify`: component signature verification (signer-side
  only; clients treat component signatures as opaque).
- SDKs must match the same vectors rather than reconstructing a variant.

Changing the message shape is a versioned cryptographic and LogicSig change.
For example, per-authorizer sentry allowlists would require binding the
authorizer in the signed message and updating the matching on-chain LogicSig
verification path.

## Public Sentry References

Signer nodes need public sentry metadata to generate guarded accounts, but they
do not need sentry private keys.

There are two ways to populate a signer-side sentry reference catalog:

- manual import with `apstore sentry export` on the sentry node and
  `apstore sentry import` on the signer node,
- endpoint discovery with `apshell endpoints sync-sentries`, which reads
  authenticated `/keys` inventories from configured sentry endpoints and syncs
  public candidates into the connected signer identity.

Public reference records are stored under:

```text
identities/<identity>/sentries/
```

They contain public metadata only: Witness Key ID, key type, sentry public key
hex, source, and timestamps. They are not endpoint ownership proofs and do not
authorize a future transaction. The guarded account's embedded public key is
the trust input that matters after generation.

## Endpoint Routing

Client endpoint routing lives in:

```text
$APCLIENT_DATA/endpoints.yaml
```

The registry may contain one signer endpoint and any number of sentry
endpoints. Sentry endpoint records carry connection metadata plus
`published_sentries`, an endpoint-local inventory keyed by raw sentry public key
hex.

Runtime guarded-send routing works like this:

1. Signer inventory labels the guarded account key with
   `signing_flow: sentry1`, its `sentry_component_key_type`, and the required
   sentry public key. The client routes on the flow label (key-type strings
   are opaque to the client) and fails fast on flow labels it does not
   implement.
2. The client builds an in-memory map from endpoint `published_sentries`.
3. The client selects the sentry endpoint that advertises that public key.
4. Before requesting a sentry component signature, the client verifies the
   endpoint still advertises the expected Witness Key ID.

Endpoint import and `/keys` discovery are routing metadata. They do not prove
ownership. If an endpoint is wrong or stale, assembly or on-chain LogicSig
verification fails unless that endpoint controls the embedded sentry private
key. If a previously discovered sentry key is deleted from the sentry node,
guarded signing fails before submission with a missing-advertised-key error.

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
5. Request sentry-role component signatures from the routed sentry endpoint for
   guarded targets.
6. If the group contains non-guarded signer positions, request ordinary
   signatures over the same canonical bytes.
7. Call `/sign/assemble` on the user signer to verify components, pack LogicSig
   arguments, verify passthrough bytes, and return signed transaction bytes.
8. Submit with algod.

## Contained Guarded Simulation

Simulation does not follow the submit flow. A client-side simulation with real
signatures would make "simulate" a client-claimed label that skips operator
approval while yielding fully submittable bytes. Instead, guarded simulation
is contained inside the user signer via `POST /simulate/guarded`, mirroring
the `/simulate` containment model:

1. The client builds the same frozen canonical group and signs dummies
   locally.
2. The client requests sentry-role component signatures as usual (the sentry
   domain is deterministic and prompt-free).
3. The client calls `/simulate/guarded` with the group, the sentry component
   signatures, signed passthrough entries, and sign-mode entries for local
   non-guarded legs.
4. apsigner runs the signer-domain gates with simulation semantics — hard
   policy rejection still applies; review and operator approval are skipped —
   then produces the user component signatures in-process, signs local
   non-guarded legs through the ordinary simulation path, assembles under the
   full `/sign/assemble` invariants, and simulates against its own algod.
5. Only transaction IDs, final unsigned transactions, and the simulation
   report are returned. Assembled signed bytes and user component signatures
   never leave the signer, so there is nothing to submit and nothing to
   bypass.

Simulation therefore exercises the real LogicSig programs, budgets, and
assembly checks without prompting an operator, and a simulate request can
never be laundered into a submittable transaction.

All component signatures and ordinary signatures are over the same frozen
group. This matters for mixed groups: guarded targets, non-guarded originals,
and dummy transactions must all agree on transaction bytes, group ID, and
LogicSig budget.

## Assembly Invariants

Assembly is the main server-side backstop for guarded signing. It verifies:

- the requested guarded key is a local guarded account key,
- the user component signature verifies for role `user` and the target txid,
- the sentry component signature verifies for role `sentry` and the target
  txid against the sentry public key embedded in the guarded account key,
- packed LogicSig arguments match the guarded template's expected layout,
- provider-generated LogicSig arguments, such as corridor Merkle proofs, match
  the guarded account key type and target transaction,
- the resulting LogicSig address equals the guarded account,
- passthrough signed bytes match the canonical transaction IDs,
- when `txn.Sender != guarded_account`, the signed transaction carries
  `AuthAddr == guarded_account`.

These checks are safety-relevant. Supporting guarded authorizers is not a
loosening of the two-party invariant; it replaces a sender-equality shortcut
with explicit authorizer semantics.

## Sentry Policy

On a sentry node, `policy.yaml` is parsed in the sentry policy domain. It uses
the shared policy grammar, but the verdict model is direct authorization:

- matching deterministic allow policy signs,
- deny guards reject,
- unmatched requests reject,
- manual review and operator default are not valid sentry outcomes.

The sentry does not decide whether the user signer is allowed to use a guarded
key. It decides whether the target transaction facts are allowed under sentry
policy. Current sentry policy is transaction-focused and DSA-agnostic: it
examines decoded transaction details and transfer movements, not which DSA
mechanism produced the user component signature.

Sentry transfer policy is a positive authorization surface. Supported target
movements include direct transfers that policy routing can evaluate. Target
shapes that cannot be represented as supported sentry movements fail closed.
For rekeys, `reject_rekey:true` remains a coarse deny-all switch. If it is not
set, a non-zero `RekeyTo` is authorized only when the transaction is a pure
0 ALGO self-payment and `rekey_policy.allowed` contains a matching
sender-to-target edge. Missing `rekey_policy` still fails closed.
Unlike corridor transfer destinations, rekey targets are not constrained by the
on-chain recipient Merkle root; they rest on sentry key secrecy and the
sentry-domain `rekey_policy`.

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
transaction is still `S`'s transaction. Sentry policy remains scoped to the
transaction facts. Assembly verifies that the guarded LogicSig address and
`AuthAddr` both equal `G`.

Current v1 semantics do not expose an authorizer field to sentry policy and do
not bind authorizer identity into the sentry component message. That is
intentional for the transaction-focused model. If a future policy wants
per-authorizer delegation controls, the component message and LogicSig program
must change together so the sentry's authorizer-conditioned decision is bound
cryptographically.

## Mixed Groups

Mixed guarded/non-guarded groups use one canonical group and preserve full
approval context:

- guarded targets receive user and sentry component signatures,
- non-guarded signer targets use ordinary `/sign`,
- dummy transactions are included consistently for LogicSig budget,
- signer-side `/sign` sees the complete group context for non-guarded approval
  and policy,
- `/sign/assemble` receives signed non-guarded entries as passthrough bytes.

The client supplies accurate LogicSig-size hints for guarded positions when it
calls ordinary `/sign` for the non-guarded subset. The signer keeps its normal
budget computation as an independent backstop. A mis-sized client group should
fail early with a clear pre-grouped budget rejection rather than later as an
opaque algod evaluation failure.

## Failure Model

Sentry failures are fail-closed:

- signer-domain policy rejection, always-review denial, operator denial, or a
  missing admin client fail user-role component signing before any private-key
  operation,
- there is no client-declared simulate mode on `/sign/component`; simulation
  skips prompts only inside `/simulate/guarded`, whose response carries no
  signed bytes,
- locked or unreachable sentry endpoints cannot produce component signatures,
- endpoint authentication or host-trust failures block routing,
- malformed or duplicate sentry inventory leaves endpoint files unchanged,
- deleted sentry keys stop being advertised by `/keys` and guarded signing
  fails before sentry signing,
- missing sentry signatures fail assembly,
- mismatched user or sentry signatures fail assembly,
- stale endpoint routing cannot pass assembly or on-chain LogicSig verification
  without the embedded sentry private key,
- unsupported sentry policy outcomes fail closed.

`apshell endpoints sync-sentries` preserves existing local
`published_sentries` only for temporarily unreachable or locked endpoints.
Authentication failures, malformed records, duplicate public keys, and Sentry
Key ID validation failures are hard errors.

## Audit

Sentry component approvals and rejections use existing sign audit events. In
the current projection:

- `txn_auth` carries the Witness Key ID,
- `txn_sender` carries the decoded target sender,
- `policy_rule_id` carries the deterministic sentry rule when one matched.

This is an MVP projection. It preserves event visibility without introducing a
separate audit event family for component signing.

## Implementation Map

Primary packages and files:

- `pkg/signerapi`: HTTP DTOs for component signing, assembly, sentry sync, and
  key inventory.
- `internal/witness`: witness key-type identifiers, Witness Key ID derivation,
  public identity validation, keypair validation, and custodian capabilities.
- `internal/sentry/keytypes`: guarded-account key-type mapping and sentry
  enrollment requirements.
- `internal/sentry/message`: role-separated component messages.
- `internal/sentry/canonical`: canonical group decoding and group hashing.
- `internal/sentry/verify`: component signature verification (signer-side
  only).
- `internal/sentry/sentryrefs`: public sentry reference catalog.
- `internal/signerapp/signing`: component request planning, sentry policy
  evaluation, signer-domain approval gates for user components (`gate.go`,
  `component_gate.go`), user/sentry component signing, assembly, contained
  guarded simulation assembly (`guarded_simulate.go`), and `/sign` rejection
  gates.
- `internal/signerapp/rest`: REST service methods backing `/sign/component`,
  `/sign/assemble`, `/simulate/guarded`, `/keys`, `/keytypes`, and
  `/admin/sentries/sync`.
- `internal/signerapp/daemon`: HTTP runtime (`http_runtime.go`) that registers
  these routes on the signer mux and dispatches them to the `rest` service
  methods.
- `internal/engine`: guarded transaction orchestration and sentry endpoint
  resolution.
- `internal/config`: endpoint registry parsing and derived sentry endpoint map.
- `internal/apshellapp`: endpoint commands and sentry discovery workflows.
- `lsig/falcon1024_guarded`: guarded LogicSig provider and template behavior.
- `lsig/corridor`: always-sentry corridor LogicSig provider requiring both a
  user component signature and a Falcon-1024 sentry signature.
- `cmd/apstore/sentry.go`: public sentry export/import/list/show/remove.
- `cmd/appolicy`: signer-to-sentry policy conversion and offline validation.

Representative tests:

- `internal/signerapp/signing/component_test.go`
- `internal/policy/role_domains_test.go`
- `internal/policy/sentry_convert_test.go`
- `internal/policy/transfer_routing_eval_test.go`
- `internal/engine/guarded/submit_test.go`
- `internal/apshellapp/endpoints_test.go`
- `cmd/apstore/sentry_test.go`
- `scripts/docker-local-four-node-smoke.sh`
