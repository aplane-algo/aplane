# HTTP API Contract

> Compatibility-bearing wire shapes, fixed runtime binding, and cancellation semantics for the apsigner HTTP surface.
> For overall compatibility scope, see [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md).
> For the explanatory transaction signing flow, see [ARCH_TXNFLOW.md](ARCH_TXNFLOW.md).

This contract is consumed by `apshell`, the in-tree `internal/signerclient`, and external SDK clients in the `aplane-algo/aplanesdk` repo (Go, TypeScript, Python). It documents the request/response wire format, status codes, fixed runtime binding, and the `/sign/cancel` lifecycle.

The current signer HTTP protocol is `2.0`. Version 2 removes the signer-owned
ordinary and guarded simulation endpoints and their DTOs. Simulation-capable
clients must use ordinary signing followed by client-side algod simulation.
This is a coordinated breaking change: clients that call the removed routes
receive `404` and must be upgraded with apsigner.

The product-facing HTTP API is a single-signer API. A request is authenticated
by the SSH connection it arrived on: the enrolled client key that authenticated
that connection becomes the request's `client:<fingerprint>` principal, and
every authenticated handler uses the process-owned product runtime. HTTP requests and authorization
resources carry no runtime or store selector. Status and audit fields identify
request state and principals without a runtime ID.

## Endpoints

| Method | Path | Auth | Requires Unlock |
|--------|------|------|-----------------|
| `GET` | `/health` | no | no |
| `GET` | `/status` | yes | no |
| `GET` | `/keys` | yes | yes |
| `GET` | `/keytypes` | yes | no (but template-backed types appear only after unlock) |
| `POST` | `/sign` | yes | yes |
| `POST` | `/sign/bounded-admin` | yes | yes |
| `POST` | `/sign/component` | yes | yes |
| `POST` | `/sign/assemble` | yes | yes |
| `POST` | `/sign/rotating/prepare` | yes | yes |
| `POST` | `/sign/rotating/sign` | yes | yes |
| `POST` | `/sign/cancel` | yes | no |
| `POST` | `/plan` | yes | yes |
| `POST` | `/admin/generate` | yes | yes |
| `DELETE` | `/admin/keys` | yes | yes |

Method enforcement:

- `/sign`, `/sign/bounded-admin`, `/sign/component`, `/sign/assemble`,
  `/sign/rotating/prepare`, `/sign/rotating/sign`, `/sign/cancel`, `/plan`,
  `/status`, `/admin/generate`, and `/admin/keys` enforce their HTTP method.
- `/keys`, `/keytypes`, and `/health` are operationally `GET` endpoints and accept wrong methods for compatibility.

Transport behavior:

- all responses are `Content-Type: application/json`,
- non-2xx responses use `signerapi.ErrorResponse` with top-level `error` plus
  a stable machine-readable `code` (see `pkg/signerapi/error_codes.go`);
  clients branch on `code`, never on `error` message text,
- request `Content-Type` is not enforced,
- malformed JSON returns `400`,
- oversized bodies return `413`,
- request body limit is 5 MB for POST endpoints.

Error codes:

The stable wire-contract `code` values that SDK clients branch on are defined in
`pkg/signerapi/error_codes.go`; their HTTP status mapping is owned by
`internal/signerapp/svcerr` (`Kind.HTTPStatus()`):

| Code | Meaning | HTTP status |
|------|---------|-------------|
| `bad_request` | malformed or invalid request input | `400` |
| `unauthorized` | missing or invalid authentication | `401` |
| `forbidden` | authenticated request the signer refuses (policy or role) | `403` |
| `locked` | signer keystore is locked | `403` |
| `not_found` | unknown key or resource | `404` |
| `invalid_passphrase` | passphrase verification failure | `403` |
| `unavailable` | temporary inability to serve the request | `503` |
| `cache_refresh` | store mutated but the signer key cache failed to refresh | `500` |
| `internal` | unexpected server-side failure | `500` |
| `bounded_admin_required` | admin-key bounded operation sent to ordinary `/sign` | `400` |
| `bounded_cosigner_required` | cosigner-gated bounded spend sent to ordinary `/sign` | `400` |
| `rotating_signing_required` | rotating account sent to `/plan`, `/sign`, `/sign/bounded-admin` or `/sign/component` | `400` |
| `rotating_stage_unproven` | the signer has not yet found the rotating account's live stage; its background scan continues and a retry usually succeeds | `409` |
| `rotating_stage_changed` | the account's authorizer moved between prepare and sign; nothing was signed, rebuild and prepare again | `409` |

An empty `code` means the server predates code support or the failure had no
specific classification. New codes may be added; existing values must not change
meaning.

Timeout behavior:

- `apsigner` sets HTTP `ReadHeaderTimeout` to 5 seconds, `ReadTimeout` to 30
  seconds, `IdleTimeout` to 120 seconds, and `WriteTimeout` to
  `MaxApprovalWait + 2m` so a valid manual approval wait can complete before
  the server write deadline.
- The REST listener accepts at most 64 concurrent connections; further
  connections wait in the kernel accept queue until one closes. Request
  headers are limited to 64 KiB (`431 Request Header Fields Too Large`
  beyond that). Both bound what unauthenticated loopback clients can make the
  signer allocate; `mlockall` keeps that memory resident.
- Only authenticated requests keep their connection alive. Every response to
  an unauthenticated request (`/health`, authentication failures, unknown
  routes) carries `Connection: close`, so an unauthenticated client holds a
  connection slot for at most one request and its header timeout and cannot
  keep every slot busy with keep-alive requests.
- the repo-owned `internal/signerclient` uses per-request default deadlines:
  `/health` 3 seconds, `/status` 5 seconds, inventory requests 30 seconds,
  mutations 60 seconds, `/plan` 60 seconds,
  `/sign/component` 2 minutes for cosigner targets, `/sign/assemble` 2 minutes,
  and `/sign` or approval-bearing `/sign/component` based on approval wait.
  User and bounded-base `/sign/component` requests can
  block on operator approval and use the same approval-aware deadline as
  `/sign`.
- caller-provided contexts with earlier deadlines are preserved.
- before `/sign`, `internal/signerclient` attempts `/status` discovery; when
  `approval_wait_seconds` is known and valid, the `/sign` deadline is
  `approval_wait + 30s`, otherwise it falls back to 6 minutes.
- external SDK clients should mirror the same effective behavior for `/sign`.
  A fixed SDK default shorter than the product-runtime approval wait is a
  compatibility bug because it can cancel a valid manual approval flow before
  apsigner's approval timeout expires.

Fixed runtime binding:

- HTTP auth resolves the enrolled client key of the request's SSH connection
  to a `client:<fingerprint>` principal; requests carry no credential, and the
  loopback listener answers only `/health`.
- authenticated handlers use the process-owned product runtime; requests carry
  no runtime or store selector.
- missing or invalid credentials return `401`; authorization failures return
  `403`.

## Request/Response Shapes

`/sign` and `/plan` share request type `signerapi.GroupSignRequest`
from `pkg/signerapi/types.go`:

- top-level fields: optional `request_id`, `requests[]`
- each entry is one of:
  - sign: `auth_address`, optional `txn_sender`, `txn_bytes_hex`, optional `lsig_args`, optional `app_call_info`
  - passthrough: `signed_txn_hex`; if the signed envelope uses LogicSig,
    `lsig_resources` is required
  - foreign: `txn_bytes_hex` without `auth_address`, with at most one
    authorization-resource hint: optional `lsig_resources` or native-PQ
    `pq_scheme` (`f1`)

The signer derives authorization shape for locally held keys. An unsigned
foreign native-PQ slot must declare `pq_scheme:"f1"` so pooled protocol fees
are correct. A foreign LogicSig slot declares `lsig_resources` with
`program_bytes`, `argument_bytes`, and `max_opcode_cost`.

A passthrough LogicSig also requires `lsig_resources`. The signer verifies
`program_bytes` and `argument_bytes` against the signed envelope and uses the
declared reviewed `max_opcode_cost`; it never substitutes a guessed minimum for
immutable foreign bytecode. Supplying `lsig_resources` for a non-LogicSig
passthrough is rejected. The retired combined `lsig_size` field is rejected
explicitly rather than ignored, because silently dropping it would understate
LogicSig resources.

`txn_sender` is an advisory display hint for clients. Signer authority,
policy, and audit decisions use the sender decoded from `txn_bytes_hex`.

`app_call_info` is approval-rendering metadata on the shared request DTO:

- `mode`: `raw` or `abi`
- `method`: ABI method signature when `mode:"abi"`

`/sign` uses `app_call_info` to render application-call approval prompts.
`/plan` accepts the same request DTO but does not perform approval or signing.

`request_id` is optional and is used by `/sign` to correlate a live synchronous
sign request with a later `/sign/cancel` request. If absent, apsigner generates
an internal request ID for approval display as before, but external clients
cannot cancel it by ID. Clients that need explicit cancellation should set
`request_id` to an opaque ASCII identifier of at most 128 characters using
letters, digits, `-`, `_`, `.`, or `:`.

See [ARCH_TXNFLOW.md](ARCH_TXNFLOW.md) (Mode Selection) for the foreign/passthrough/sign distinction. The contract surface:

- Both endpoints accept the same per-entry modes; mixing passthrough and foreign in one request is invalid, and all-foreign requests are rejected on both endpoints.
- `/plan` performs canonical group building only. It never touches keys and returns canonical unsigned transactions in `transactions[]`.
- `/sign` performs canonical group building plus approval/signing.
  Signer-controlled guarded account keys are rejected before approval because
  they require the guarded component/assembly endpoints; `/plan` may admit
  them to freeze those guarded workflows. Transaction-level hard policy is
  applied only to signer-controlled slots; passthrough and foreign entries
  contribute to group consistency, approval context, warning analysis, and
  audit visibility.
- `/sign/bounded-admin` performs the same planning, policy, forced review, group
  finalization, and spending-key signing for one admin-key-authorized pure
  rekey, then returns a typed partial for external contract-admin completion.
  It never loads a contract-admin private key and never returns the partial
  through `signed[]`.
- Apsigner has no simulation endpoint or simulation request mode. Full
  simulation obtains an executable group through ordinary `/sign`; guarded
  and bounded-cosigner groups both use `/plan`, `/sign/component`, and
  `/sign/assemble`. The client
  then sends the exact returned group to its configured algod simulate
  endpoint. Apsigner cannot distinguish this from a request whose result will
  be submitted, so policy, review, approval, signing, and audit semantics are
  identical.
- Client simulation fails before requesting signatures when no client algod is
  configured. Once signatures are returned, the client holds reusable,
  network-submittable bytes until their validity window expires.
- Plugin-generated simulation follows the same rule: canonicalize as needed,
  obtain every managed signature through ordinary signing, preserve plugin
  passthrough signatures, and send the exact final group from the client to
  algod simulation.
- First-party client workflows validate the live algod consensus identifier
  before asking apsigner to plan, requesting or releasing signatures, invoking
  plugin signers, or broadcasting/simulating a pregrouped signed group. This is
  an apshell/engine boundary; apsigner's `/plan` endpoint remains
  network-independent and uses its compiled v42 contract without querying
  algod.

`/sign` response (`signerapi.GroupSignResponse`):

- `signed`
- optional `mutations`
- optional `error`

`/sign` response semantics:

- `signed[]` always aligns 1:1 with the finalized group positions.
- sign-mode entries contain hex-encoded signed transaction msgpack blobs.
- passthrough entries contain the original signed transaction bytes, returned unchanged.
- foreign entries contain the empty string `""`.
- server-added dummy slots appear as appended signed dummy transactions.
- The ordinary client `/sign` path treats `mutations` as an authorization to
  transform transaction bodies, not merely as display metadata. Before
  simulation or submission it verifies the report counts and fee delta,
  permits only reported fee increases and group-ID assignment on original
  positions, recomputes the canonical final group ID, and reconstructs every
  appended dummy transaction and its embedded LogicSig authorization. Any
  unreported field change, malformed report, or non-canonical dummy fails
  closed on the client.
- Admin-key bounded operations are rejected with `code:"bounded_admin_required"`;
  pure spends and explicitly spending-key-authorized rekeys return complete
  base-argument LogicSigs from `/sign` only when no cosigner is required.
- Cosigner-enabled bounded spends are rejected with
  `code:"bounded_cosigner_required"`; they must use the `bounded-cosigner1`
  choreography below.
- Rotating accounts (`signing_flow: rotating1`) are rejected before approval
  with `code:"rotating_signing_required"` on `/plan`, `/sign`,
  `/sign/bounded-admin` and `/sign/component`.

`/sign/bounded-admin` request (`signerapi.BoundedAdminRequest`) carries optional
`request_id`, `operation:"rekey"`, and shared `requests[]`. V1 requires exactly
one sign-mode pure rekey, no caller LogicSig arguments, and no passthrough,
foreign, or unrelated signable entries. The signer may append budget dummies.

`/sign/bounded-admin` response (`signerapi.BoundedAdminPartialResponse`) contains:

- `schema:"aplane.bounded-admin-partial.v1"` and `operation:"rekey"`
- finalized TX-prefixed unsigned `transactions[]`
- aligned `partial_signed[]`, with a spending-only LogicSig at `target_index`
  and empty strings in every other slot
- `authorization` with Contract Admin Key ID, public and spending public keys,
  program binding, finalized transaction ID, diagnostic message, base argument
  count, spend effects, and maximum fee
- optional `mutations`

The response is not submission-ready. `message_hex` and every other derived
authorization field must be recomputed by the completing helper from the
finalized transaction, durable metadata, and program contract.

`/sign/component` accepts `signerapi.ComponentRequest`: optional `request_id`,
frozen TX-prefixed `group_bytes_hex[]`, discriminated `targets[]`, foreign-only
`contextual_positions[]`, and a contiguous `dummy_positions[]` suffix. The
three position sets form a closed partition. Target `kind` is `user`, `cosigner`,
or `bounded-base`; kind-specific fields are rejected on other kinds.
Dummy classification is semantic in both directions: every declared dummy must
match the canonical signer-added suffix form, and a canonical dummy suffix may
not be relabeled as caller-supplied original positions.

The endpoint never plans or mutates a group. User and bounded-base targets are
policy- and operator-gated and use the live `/sign/cancel` lifecycle. Cosigner
targets use deterministic cosigner policy without operator approval. Bounded-base
authorization is reconstructed from frozen bytes and signer-held metadata,
including resources, fees, runtime arguments, and the canonical dummy suffix.
The response is `signerapi.ComponentResponse`, with `request_id` and
kind-tagged `components[]`. User/cosigner components carry `signature`; bounded
components carry `auth_address`, `base_signatures[]`, canonical `runtime_args`,
and `assembly_receipt`. Every component carries `target_index`, `kind`, and
`signature_scheme`.

The Falcon-signed bounded assembly receipt commits to the account, target TxID,
normalized durable metadata, and sorted runtime arguments under
`APLANE_BOUNDED_COSIGNER_ASSEMBLY_V1`. It prevents transplanting released base
material into another account, metadata instance, or runtime-argument set.

`/sign/assemble` accepts `signerapi.AssemblyRequest`: optional `request_id`,
the frozen group, discriminated `targets[]`, and optional `passthrough[]`.
Guarded targets carry user and cosigner signatures; bounded-cosigner targets carry
base signatures, runtime arguments, an assembly receipt, and a cosigner
signature. Every position is covered exactly once. The response is
`signerapi.AssemblyResponse` with `request_id` and aligned `signed_group[]`.

Assembly keeps the authorization models distinct. Guarded targets are verified
against their local guarded account key and both component signatures. Bounded
targets reload durable metadata, verify receipt and both authorities against
the frozen TxID, derive only declared signer-generated arguments, and check the
LogicSig address and authorizer. Contract-admin paths never use this endpoint
or contact a cosigner. Assembly request IDs are correlation-only and are not
cancelable through `/sign/cancel`.

### Rotating accounts (`rotating1`)

A rotating account keeps one address while its authorizing stage program
changes on every spend. Stage `n` is a program over the Falcon-1024 and
Ed25519 keys derived for `n` from the account's seed; stage 0's program
address is the account. Both endpoints use the `sign_request` action,
resolve the key by the account address, refuse any account that is not
rotating, and read the account's authorizer and the round from the signer's
own node (see `ARCH_NETWORKS.md`). The signer keeps no durable state for the
account between requests: the chain says which stage is live, the seed says
which stage comes next.

The invariant every release upholds: a signature from stage `n` is released
only while `n` is the authorizer, and its transaction rekeys the account to
stage `n + 1`. So every landed rotation installs a stage that has never
signed, and the keys a signature reveals control the account only until that
transaction, or a later rotation, confirms.

`/sign/rotating/prepare` request (`signerapi.RotatingPrepareRequest`):

- `account`: the rotating account address
- `txn_bytes_hex`: one unsigned, ungrouped, TX-prefixed transaction from the
  account, with no `rekey_to`, no close-out, the account's genesis hash, and a
  validity window of at most 100 rounds
- optional `request_id`

The signer reads the authorizer, finds its stage `n` (through the stage
address table, confirmed by derivation), sets `rekey_to` to stage `n + 1`'s
address derived from the seed, adds the resource dummies the key type's
profile needs (one for the Falcon hybrid, two for the WOTS hybrid), sets fees
and the group ID, and returns the exact unsigned group. It stores nothing.
Preparation needs no approval and reveals nothing secret. An account whose
live stage the signer has not found yet is refused with
`rotating_stage_unproven` after a bounded foreground search (30 s); the
background scan continues and a retry succeeds once it has caught up.

`/sign/rotating/prepare` response (`signerapi.RotatingPrepareResponse`):

- `account`, `rekey_to`
- `stage`: the live stage, which will sign; `target`: always `stage + 1`
- `transactions`: the final unsigned group, TX-prefixed hex
- `mutations`: the ordinary mutation report (dummies, fees, group ID)

Clients simulate exactly these bytes and send them back unchanged.

`/sign/rotating/sign` request (`signerapi.RotatingSignRequest`):

- `account`
- `transactions`: the prepared group
- optional `request_id`, cancelable through `/sign/cancel` while live

The group's `rekey_to` names stage `n + 1`, which fixes `n`; the request
carries no stage of its own and nothing is carried over from prepare. The
signer finds `n + 1` in the table, re-derives stage `n + 1` from the seed
and refuses unless it matches `rekey_to`, and rebuilds the group from the
presented spend: the result must be byte-identical to what was presented,
so the group can only be that spend plus the rotation's own `rekey_to`,
fee, group ID and canonical dummies. The signer keeps nothing from prepare,
so it does not and cannot check that the presented spend is the one the
client prepared: a client may change the spend between the two calls, and
what the signer binds is the presented transaction, which is what policy
evaluates and the operator sees. Preserving the user's intent across
prepare and sign is the client's job (first-party clients verify the
prepared group against the transaction they sent, below). It then runs the
ordinary policy gates and operator approval; the rotation target counts as
the signer's own address, so `reject_foreign_rekey` does not apply to it. After approval, under the
account's lock, it reads the chain again and refuses unless the authorizer
is still stage `n` (`rotating_stage_changed` otherwise: nothing was signed),
`first_valid` is at most 2 rounds ahead of the round read, and at least 10
rounds remain before `last_valid`. It proves stage `n + 1` can sign, signs
the TxID with stage `n`'s two keys (Falcon-1024 and Ed25519, or WOTS and
Ed25519), verifies both,
writes a `ROTATING_RELEASE` audit entry (account, TxID, stage, `last_valid`)
with a durable sync, records the release in memory, and responds. An audit
write failure is logged as a warning and does not withhold the signature:
the entry only feeds the alerts below, so a release missing from the log is
one whose alert cannot be restored after a restart, never a safety gap.

There is no limit on releases per stage. Two spends prepared from the same
stage both rekey to the same `n + 1`; whichever lands second is rejected by
the ledger ("should have been authorized by"), and nothing the signer could
store would change that outcome.

`/sign/rotating/sign` response (`signerapi.RotatingSignResponse`):

- `signed`: the signed group, hex msgpack; the spend carries the stage program
  as its LogicSig and an `auth_address` for stages above 0
- `stage`: the stage whose keys the signature revealed; `target`: `stage + 1`
- `txid`, `group_id`: the identifiers clients use to track the outcome

Creating and using rotating accounts:

- `aplane.rotating-hybrid.v1` (Falcon-1024 + Ed25519 stages) and
  `aplane.rotating-wots-hybrid.v1` (hash-based WOTS + Ed25519 stages) are
  `Library` key types: an operator enables one, then generates with the
  single creation parameter `network`: any network the signer knows
  (built-in or configured, which `/keytypes` lists as the parameter's
  `options`), or a base64 genesis hash. Both use this flow unchanged; they
  differ only in the stage program and its resource profile. Like every key
  type, their recovery material never leaves the signer: neither the admin
  protocol nor HTTP returns the mnemonic, and backups carry the seed.
  Mnemonic import is refused.
- First-party clients route on the sender's own `signing_flow: rotating1`,
  not on its on-chain authorizer, which is a stage address the signer never
  lists. A rotating spend is sent alone; the client caps its validity window
  at 100 rounds and rebuilds it when it has aged, prepares, verifies that the
  prepared group changed only `rekey_to`, the spend's fee, the group ID and
  canonical dummies and that `target` is `stage + 1`, simulates the unsigned
  group, and only then signs and submits exactly the returned bytes. A
  `rotating_stage_changed` or window-timing refusal means nothing was signed,
  and the client rebuilds and prepares again a bounded number of times.
  Simulate-only requests stop before signing, so they reveal no keys.

Restore: a rotating key restored from a backup, rebuilt or re-imported has
everything it needs. The signer reads the live stage from the chain and
rebuilds the stage address table (`ARCH_CONTRACTS.md`, Stage Address
Tables) in the background; until the table reaches the live stage,
requests are refused with `rotating_stage_unproven` and `/status` carries a
note ("stage not yet found, N stages scanned"). No operator recovery step
exists or is needed.

Alerts: the signer remembers the newest release per account (stage, TxID,
`last_valid`) in process memory, rebuilt at unlock from the newest
`ROTATING_RELEASE` audit entry per account (read from the audit log and its
two rotated predecessors; entries the log has rotated past are simply
absent), and checks every rotating account's authorizer on its own node right
after unlock and then about every 30 seconds while unlocked (a nominal
interval: chain reads and paced derivation can stretch it). A release whose
`last_valid` has passed while its stage is still the authorizer raises a
warning: that transaction can never confirm and the revealed keys still
control the account. A release still within its window is a note. A read
that shows the account past the release clears it; a stale read never
erases a newer release. Because only the newest release is kept, an earlier
release from the same stage that expired while a newer one is still within
its window is reported through the newer one: the stage is the same, and
the newer transaction either lands and moves the account or expires and
raises the warning. Warnings appear in the daemon log once when they
appear and once when they clear, in authenticated `/status` `warnings`, in
apadmin's status bar, and in apshell's `rotate status`; notes appear in
`/status` `notes`. The remedy for an expired release is a rotate-only spend
through the endpoints above. Alerts are observational: safety does not
depend on them, on the table, or on the audit log.

`/sign/cancel` request (`signerapi.CancelSignRequest`):

- `request_id`

`/sign/cancel` response (`signerapi.CancelSignResponse`):

- `success`
- `state`
- optional `error`

`/sign/cancel` withdraws a live synchronous `/sign` or approval-bearing
`/sign/component` request. It is idempotent
for client behavior. A valid, authenticated cancel request returns `200` with
`success:true`; cancellation miss is represented in `state`, not as an HTTP
error. Cosigner-only `/sign/component` and `/sign/assemble` request IDs are
correlation fields rather than live cancel handles and return `not_found` if
supplied to `/sign/cancel`.

Cancel response states:

- `canceled`: apsigner accepted cancellation for a matching live request,
  canceled a pending approval prompt, or accepted a duplicate cancel while that
  live request was unwinding.
- `not_found`: no live cancelable request matched the supplied `request_id`.

Invalid `request_id` syntax returns `400`.

## Sign Cancellation Semantics

`/sign` is a synchronous HTTP API. While a request is live,
apsigner tracks its optional `request_id` in memory so `/sign/cancel` can cancel
the request context and withdraw any pending manual approval prompt. This
tracking is not a durable request table, not a polling API, and not an exposed
async signing state machine.

Only live synchronous `/sign` and `/sign/rotating/sign` requests and
approval-bearing user or bounded-base `/sign/component` requests are
cancelable. Cosigner-only component
requests and assembly requests are correlation-only. Once a cancelable request
is no longer live, later `/sign/cancel` calls return `state:"not_found"`.

`/plan` response (`signerapi.GroupPlanResponse`):

- `transactions`
- optional `mutations`
- optional `error`

`MutationReport` fields:

- `dummies_added`
- `group_id_changed`
- `fees_modified`
- `total_fees_delta`
- `original_count`
- `final_count`
- `passthrough_count`
- `foreign_count`
- `reason`

`/keys` response:

- `count`
- `keys[]` with `address`, `public_key_hex`, `key_type`
- optional `authorization_kind` with closed account-authorization values
  `ed25519`, `native_pq`, or `logic_sig`. It is derived from the durable key
  category and is authoritative for choosing the transaction authorization
  envelope. Witness rows omit it because they are not spending accounts.
- optional `signing_flow`: explicit signing choreography label. `cosigner1`
  selects legacy guarded component signing, `bounded1` selects bounded routing
  without an online cosigner, `bounded-cosigner1` selects the user-first bounded
  component/cosigner/assembly flow, `rotating1` selects the rotating account
  prepare and sign flow, and empty means ordinary `/sign`. Clients
  dispatch these cases explicitly and fail closed on labels they do not
  implement.
- optional `cosigner_component_key_type`: the cosigner component key type used by
  this key's `signing_flow` (for `cosigner1` or `bounded-cosigner1`)
- optional `bounded_authorization`: present for `signing_flow: bounded1` and
  `bounded-cosigner1`.
  It contains `contract`, `base_signature_arg_layout`,
  `spend_effects`, `max_fee`, `admin_operations` (including each operation's
  `policy_gate`), `runtime_args`, `derived_args`, the path-specific
  `argument_layout`, and `layer3_policy`. `/keys` also includes instance-only
  `admin_key_id` and `program_binding` when
  applicable. This is routing and assembly metadata, not permission; signer
  classification and stored bytecode remain authoritative.
- optional `logic_sig_resources`, containing final compiled program bytes and
  path-specific argument-byte and maximum-opcode-cost ceilings
- optional `is_generic_lsig`
- optional `is_witness_key` and `is_spending_account`: cosigner-key rows use
  `address` as the Witness Key ID, not as an Algorand spending address.
  Witness Key IDs are always 52-character uppercase base32
  SHA-512/256 digests over the domain-separated key-type/public-key tuple;
  `public_key_hex` carries the full component public key.
- optional `signing_args`: the key file's stored signing schema captured at
  generation time, not the live template/provider schema; this is what the
  signer enforces at sign time for that specific key. SDK consumers must treat
  an absent field the same as an empty list.
- optional `parameters`: non-secret key creation parameters needed by clients
  to orchestrate key-type-specific workflows. For guarded account rows this
  includes `cosigner_public_key`, the cosigner public key embedded in the
  account LogicSig bytecode. Its key family and size are determined by the
  guarded account `key_type`. SDK consumers must treat this as signer-owned
  metadata, not as proof of remote cosigner endpoint ownership.
  Bounded rows expose only the reviewed public parameter projection used by
  the bundled profiles (`recipients`, asset/amount limits, `unlock_round`, and
  framework cosigner/admin public keys). Newly stored bounded parameters are
  omitted until explicitly classified as public; `/keys` never defaults to
  exposing the complete stored creation-parameter map.
- optional `template_provenance_status`, `template_provenance_note`; these are
  informational, version-aware comparisons between stored key template
  provenance and the registered local definition, not signing gates. The
  fingerprint is behavior-only and versioned (`<n>:` prefix), so renaming a
  `key_type`, family, or base key type does not by itself produce a conflict

`template_provenance_status` values:

- `conflict`: the stored `template_fingerprint` and the registered local
  provider/template fingerprint for `key_type` are the **same fingerprint
  version** but differ — a genuine behavior difference
- `unavailable`: no provider/template fingerprint can be resolved for
  `key_type`, **or** the stored and registered fingerprints are a different
  version or malformed (not comparable). A different-version or malformed
  comparison is benign and is never reported as a `conflict`

Absence of `template_provenance_status` means no provenance note is known or no
stored provenance was available. These fields do not change `/sign` behavior.

`/status` response:

- `node_role`: optional signer node role (`signer` or `cosigner`); omitted when unset
- `protocol_version`: signer HTTP API protocol version `{major, minor}`; this
  is diagnostic surfacing, not capability negotiation
- `build_version`: apsigner build string for skew diagnosis
- `state`: lock state (`locked`, `unlocked`, or `unknown`)
- `signer_locked`
- `ready_for_signing`
- `key_count`: number of loaded keys
- `keyset_revision`: process-local unsigned revision counter for the published
  key snapshot. It starts at `0` on process start and increments after each
  successful key reload/snapshot publish. Clients may compare this value across
  status polls to decide whether to refresh `/keys`; it is not a durable
  storage version and must not be compared across apsigner restarts.
- `approval_wait_seconds`: effective manual signing approval wait, in seconds,
  for the product runtime. Clients may use this value to size `/sign`
  request deadlines. Clients must tolerate this field being omitted.
- `warnings`: optional persistent operator-facing health warnings. Clients
  should display non-empty warnings and must tolerate this field being omitted.
  They include rotating account alerts (see Rotating accounts); those name
  accounts and never appear on `/health`.
- `notes`: optional informational lines that need no action, such as a
  rotating account's release still in flight or a live stage the signer is
  still scanning for. Clients must tolerate this field being omitted.

`/keytypes` response:

- `key_types[]` with `key_type`, `family`, `display_name`, `description`, optional `authorization_kind` (`ed25519`, `native_pq`, or `logic_sig`), compatibility field `requires_logicsig`, `mnemonic_word_count`, `mnemonic_import`, `mnemonic_scheme`, optional `signing_flow`, optional `cosigner_component_key_type`, optional definition-level `bounded_authorization`, `creation_params[]`, `runtime_args[]`
- each `creation_params` entry includes `name`, `label`, `description`, `type`, `required`, and optional `max_length`, `input_modes[]`, `options[]`, `min_items`, `max_items`, `min`, `max`, `example`, `placeholder`, `default`
- each `input_modes` entry includes `name` and optional `label`, `transform`, `byte_length`, and `input_type`
- each `runtime_args` entry includes `name`, `label`, `description`, `type`, `required`, and optional `byte_length`

`/keytypes` is a metadata contract. It describes enabled key types and their
creation/runtime argument shapes for new key generation. The
`runtime_args` here come from the live template/provider schema and are
distinct from the per-key snapshot returned by `/keys`, which is the source of
truth for signing an existing key. `mnemonic_import` is the explicit user-facing
mnemonic import capability; clients must not infer importability from
`mnemonic_word_count`. It does not otherwise expose whether the binary
has populated signer-side signing, keygen, mnemonic, or key-processor registries.
Client/signer provider-boundary refactors must preserve this schema and field
meaning. The `family` field carries the middle segment of the canonical
`publisher.family.vN` identifier and is intended for display and grouping;
the canonical `key_type` is what clients send back on subsequent requests and
what they should consult to decide which signing provider a composed template
uses.
For a bounded profile with `authorization: admin_key`, creation metadata includes
the framework-injected scalar `bounded_admin_public_key` (`type:"bytes"`). It
accepts the 1,793-byte Falcon-1024 public key from an external
`.wit.json` reference. The signer derives the Contract Admin Key
ID, which is the enrolled witness's Witness Key ID, and the program binding;
neither is accepted as a separate creation input.

`/admin/generate`:

- request has `key_type`, optional `parameters`
- no `name` field
- response has `address`, optional `public_key_hex`, `key_type`, optional
  `is_witness_key`, optional `is_spending_account`, and optional `parameters`
- no mnemonic in REST response

`/admin/keys`:

- `DELETE` with query param `address`
- success response is `success: true`; non-2xx failures use `ErrorResponse`

`/health`:

- `status` (`healthy` or `degraded`)
- `service`
- `protocol_version`: signer HTTP API protocol version `{major, minor}`; this
  is diagnostic surfacing, not capability negotiation
- `build_version`: apsigner build string for skew diagnosis
- `signer_locked`
- `ready_for_signing`
- `ssh_enabled`
- `ipc_enabled`
- `warnings`: optional persistent operator-facing health warnings. `/health`
  is unauthenticated, so its warnings omit error detail such as store paths
  (the authenticated `/status` warnings keep it), and the store inspection
  behind them is reused for 5 seconds.

## HTTP Status Mapping

| Condition | Status |
|-----------|--------|
| Malformed JSON | 400 |
| Oversized body | 413 |
| Wrong method | 405 |
| Missing/invalid credentials | 401 |
| Product runtime unavailable or locked | 403 |
| Authorization denied by `auth.Authorizer` | 403 |
| Locked signer (handler entry) | 403 |
| Operator/policy rejection | 403 |
| Signer locked after planning | 503 |
| No approval client connected | 503 |
| Approval timeout | 503 |
| Approval wait canceled by request context or deadline | 503 |
| Invalid request shape, hex, msgpack, groups, params | 400 |
| Unknown address / missing key | 400 |
| Missing key on delete | 404 |
| LogicSig key file missing `signing_metadata_version` when used for signing | 500 |
| LogicSig key file has a missing or inconsistent derivation record (`lsig_derivation`, plus `salt_counter` only for compatible manual-counter keys) | Rejected during scan/restore; may surface as unknown address or restore failure |
| LogicSig key file bytecode derives an on-curve address | Rejected during scan/restore; may surface as unknown address or restore failure; if detected during signing, 500 |
| Internal provider failure | 500 |

Additional compatibility-sensitive request failures:

- missing `txn_bytes_hex` for sign mode: `400`
- passthrough entries without an existing group ID: `400`
- passthrough LogicSig entries without `lsig_resources`, with declarations
  whose program/argument sizes differ from the signed envelope, or with
  `lsig_resources` on a non-LogicSig passthrough: `400`
- immutable pre-grouped transactions that would require extra dummies: `400`
- requests whose required dummies would push the group above 16 transactions: `400`
- invalid runtime args or generic LogicSig arg decoding: `400`
- missing TEAL compile algod configuration for generic LogicSig generation: `500`
- missing `address` query parameter on delete: `400`
- all-foreign `/sign` or `/plan` requests: `400` because apsigner has no signer-managed work to perform
