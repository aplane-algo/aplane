# HTTP API Contract

> Compatibility-bearing wire shapes, identity routing, and cancellation semantics for the apsigner HTTP surface.
> For overall compatibility scope, see [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md).
> For the explanatory transaction signing flow, see [ARCH_TXNFLOW.md](ARCH_TXNFLOW.md).

This contract is consumed by `apshell`, the in-tree `internal/signerclient`, and external SDK clients in the `aplane-algo/aplanesdk` repo (Go, TypeScript, Python). It documents the request/response wire format, status codes, identity routing, and the `/sign/cancel` lifecycle.

The product-facing HTTP API is a single-signer API. Internally, successful
token authentication resolves an identity and every authenticated handler routes
to that identity's runtime. In product use this is the product identity
(`default`). Non-product identity routing exists as backend plumbing and test
coverage.

## Endpoints

| Method | Path | Auth | Requires Unlock |
|--------|------|------|-----------------|
| `GET` | `/health` | no | no |
| `GET` | `/status` | yes | no |
| `GET` | `/keys` | yes | yes |
| `GET` | `/keytypes` | yes | no (but template-backed types appear only after unlock) |
| `POST` | `/sign` | yes | yes |
| `POST` | `/sign/cancel` | yes | no |
| `POST` | `/plan` | yes | yes |
| `POST` | `/simulate` | yes | yes |
| `POST` | `/admin/generate` | yes | yes |
| `POST` | `/admin/attestors/sync` | yes | no |
| `DELETE` | `/admin/keys` | yes | yes |

Method enforcement:

- `/sign`, `/sign/cancel`, `/plan`, `/simulate`, `/status`, `/admin/generate`, `/admin/attestors/sync`, and `/admin/keys` enforce their HTTP method.
- `/keys`, `/keytypes`, and `/health` are operationally `GET` endpoints and accept wrong methods for compatibility.

Transport behavior:

- all responses are `Content-Type: application/json`,
- non-2xx responses use `signerapi.ErrorResponse` with top-level `error`,
- request `Content-Type` is not enforced,
- malformed JSON returns `400`,
- oversized bodies return `413`,
- request body limit is 5 MB for POST endpoints.

Timeout behavior:

- `apsigner` sets HTTP `ReadHeaderTimeout` to 10 seconds, `ReadTimeout` to 30
  seconds, `IdleTimeout` to 120 seconds, and `WriteTimeout` to
  `MaxApprovalWait + 2m` so a valid manual approval wait can complete before
  the server write deadline.
- the repo-owned `internal/signerclient` uses per-request default deadlines:
  `/health` 3 seconds, `/status` 5 seconds, inventory requests 30 seconds,
  mutations including `/admin/attestors/sync` 60 seconds, `/plan` 60 seconds,
  `/simulate` 60 seconds, and `/sign` based on approval wait.
- caller-provided contexts with earlier deadlines are preserved.
- before `/sign`, `internal/signerclient` attempts `/status` discovery; when
  `approval_wait_seconds` is known and valid, the `/sign` deadline is
  `approval_wait + 30s`, otherwise it falls back to 6 minutes.
- external SDK clients should mirror the same effective behavior for `/sign`.
  A fixed SDK default shorter than the identity-effective approval wait is a
  compatibility bug because it can cancel a valid manual approval flow before
  apsigner's approval timeout expires.

Identity routing:

- HTTP auth uses the presented `aplane` token to authenticate exactly one
  identity.
- if an endpoint does not carry a separate target resource identity, the target
  resource identity is the authenticated identity.
- if an endpoint does carry a target resource identity, the authenticated
  identity and target resource identity must match.
- missing credentials return `401`; authenticated identities with no registered
  or live runtime return `403`; decommissioned identities return `403`.

## Request/Response Shapes

`/sign`, `/plan`, and `/simulate` share request type `signerapi.GroupSignRequest`
from `pkg/signerapi/types.go` (re-exported internally via `internal/signerapi/types.go`):

- top-level fields: optional `request_id`, `requests[]`
- each entry is one of:
  - sign: `auth_address`, optional `txn_sender`, `txn_bytes_hex`, optional `lsig_args`, optional `app_call_info`
  - passthrough: `signed_txn_hex`
  - foreign: `txn_bytes_hex` without `auth_address`, optional `lsig_size`

`txn_sender` is an advisory display hint for clients. Signer authority,
policy, and audit decisions use the sender decoded from `txn_bytes_hex`.

`app_call_info` is approval-rendering metadata on the shared request DTO:

- `mode`: `raw` or `abi`
- `method`: ABI method signature when `mode:"abi"`

`/sign` uses `app_call_info` to render application-call approval prompts.
`/simulate` uses the same metadata for signer-side inspection before internal
simulation signing. `/plan` accepts the same request DTO but does not perform
approval or signing.

`request_id` is optional and is used by `/sign` to correlate a live synchronous
sign request with a later `/sign/cancel` request. If absent, apsigner generates
an internal request ID for approval display as before, but external clients
cannot cancel it by ID. Clients that need explicit cancellation should set
`request_id` to an opaque ASCII identifier of at most 128 characters using
letters, digits, `-`, `_`, `.`, or `:`.

See [ARCH_TXNFLOW.md](ARCH_TXNFLOW.md) (Mode Selection) for the foreign/passthrough/sign distinction. The contract surface:

- All three endpoints accept the same per-entry modes; mixing passthrough and foreign in one request is invalid, and all-foreign requests are rejected on every endpoint.
- `/plan` performs canonical group building only. It never touches keys and returns canonical unsigned transactions in `transactions[]`.
- `/sign` performs canonical group building plus approval/signing. Transaction-level hard policy is applied only to signer-controlled slots; passthrough and foreign entries contribute to group consistency, approval context, warning analysis, and audit visibility.
- `/simulate` performs canonical group building, signer-side hard policy checks,
  simulation-only signing, and algod simulation on the transaction group's
  configured network. Signed bytes do not leave apsigner. If a group contains
  transactions owned by another signer, those entries must be supplied as
  passthrough signed transactions; unresolved foreign placeholders are rejected.
- Client simulate mode must not call `/sign` for signer-managed simulation. It
  uses `/simulate` so reusable signed transaction bytes remain inside apsigner.
- For plugin-generated groups, mixed signer/plugin simulation uses `/plan` to
  get canonical bytes, signs plugin-owned slots locally, then calls `/simulate`
  with those passthrough signatures so signer-owned slots are also real-signed
  inside apsigner. All-plugin groups assign the group locally, sign locally, and
  call algod simulate without a signer request.

`/sign` response (`signerapi.GroupSignResponse`):

- `signed`
- optional `mutations`
- optional `error`

The older `signerapi.SignResponse` type is retained only for source
compatibility; it is not the `/sign` wire response.

`/sign` response semantics:

- `signed[]` always aligns 1:1 with the finalized group positions.
- sign-mode entries contain hex-encoded signed transaction msgpack blobs.
- passthrough entries contain the original signed transaction bytes, returned unchanged.
- foreign entries contain the empty string `""`.
- server-added dummy slots appear as appended signed dummy transactions.

`/sign/cancel` request (`signerapi.CancelSignRequest`):

- `request_id`

`/sign/cancel` response (`signerapi.CancelSignResponse`):

- `success`
- `state`
- optional `error`

`/sign/cancel` withdraws a live synchronous `/sign` request. It is
idempotent for client behavior. A valid, authenticated cancel request returns
`200` with `success:true`; cancellation miss is represented in `state`, not as
an HTTP error.

Cancel response states:

- `canceled`: apsigner accepted cancellation for a matching live request,
  canceled a pending approval prompt, or accepted a duplicate cancel while that
  live request was unwinding.
- `not_found`: no live cancelable request matched the supplied `request_id`.
  It only means the request is not live and cancelable for the
  authenticated identity.

Invalid `request_id` syntax returns `400`. `/sign/cancel` is scoped to the
authenticated identity; a request ID belonging to another identity is not
visible and behaves as `not_found`.

## Sign Cancellation Semantics

`/sign` is a synchronous HTTP API. While a request is live,
apsigner tracks its optional `request_id` in memory so `/sign/cancel` can cancel
the request context and withdraw any pending manual approval prompt. This
tracking is not a durable request table, not a polling API, and not an exposed
async signing state machine.

Only live synchronous `/sign` requests are cancelable. Once a request is no
longer live, later `/sign/cancel` calls return `state:"not_found"`.

`/plan` response (`signerapi.GroupPlanResponse`):

- `transactions`
- optional `mutations`
- optional `error`

`/simulate` response (`signerapi.GroupSimulateResponse`):

- `tx_ids`
- `transactions`: final TX-prefixed unsigned transaction bytes
- optional `mutations`
- optional `output`: human-readable algod simulation diagnostics
- optional `failed`: true when algod simulation completed and reported an
  execution failure
- optional `error`: transport, validation, configuration, signing, or algod
  availability failure

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
- optional `lsig_size`
- optional `is_generic_lsig`
- optional `is_component_key` and `is_spending_account`: component-key rows use
  `address` as the component-key selector, not as an Algorand spending address.
  Attestor component selectors are always `a_` plus lowercase SHA-256 of the
  canonical component public-key bytes; `public_key_hex` carries the full
  component public key.
- optional `signing_args`: the key file's stored signing schema captured at
  generation time, not the live template/provider schema; this is what the
  signer enforces at sign time for that specific key. SDK consumers must treat
  an absent field the same as an empty list.
- optional `parameters`: non-secret key creation parameters needed by clients
  to orchestrate key-type-specific workflows. For attested account rows this
  includes `attestor_public_key`, the attestor public key embedded in the
  account LogicSig bytecode. Its key family and size are determined by the
  attested account `key_type`. SDK consumers must treat this as signer-owned
  metadata, not as proof of remote attestor endpoint ownership.
- optional `template_provenance_status`, `template_provenance_note`; these are
  informational comparisons between stored key template provenance and the
  registered local definition, not signing gates

`template_provenance_status` values:

- `conflict`: the stored `template_fingerprint` differs from the
  registered local provider/template fingerprint for `key_type`
- `unavailable`: the key has stored template provenance but no
  provider/template fingerprint can be resolved for `key_type`

Absence of `template_provenance_status` means no provenance note is known or no
stored provenance was available. These fields do not change `/sign` behavior.

`/status` response:

- `identity_id`: authenticated identity ID resolved from the `aplane` token
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
  for the authenticated identity. Clients may use this value to size `/sign`
  request deadlines. Older signers may omit this field.

`/keytypes` response:

- `key_types[]` with `key_type`, `family`, `display_name`, `description`, `requires_logicsig`, `mnemonic_word_count`, `mnemonic_import`, `mnemonic_scheme`, `creation_params[]`, `runtime_args[]`
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

`/admin/generate`:

- request has `key_type`, optional `parameters`
- no `name` field
- response has `address`, `key_type`, optional `parameters`
- no mnemonic in REST response

`/admin/attestors/sync`:

- request has `candidates[]`
- each candidate has `endpoint_alias`, `component_key`, `key_type`,
  `public_key_hex`, and optional `last_seen_at`
- response has `added`, `updated`, `removed`, `count`, optional `records[]`,
  and optional `error`
- each record has `name`, `source`, `component_key`, `key_type`,
  `public_key_hex`, and optional `endpoint_alias`, `last_seen_at`, `synced_at`

This endpoint writes public attestor reference records for generation UX only.
It does not require the identity to be unlocked and never carries tokens, SSH
trust, or private key material.

`/admin/keys`:

- `DELETE` with query param `address`
- success response is `success: true`; non-2xx failures use `ErrorResponse`

`/health`:

- `status` (`healthy` or `degraded`)
- `service`
- `signer_locked`
- `ready_for_signing`
- `ssh_enabled`
- `ipc_enabled`

## HTTP Status Mapping

| Condition | Status |
|-----------|--------|
| Malformed JSON | 400 |
| Oversized body | 413 |
| Wrong method | 405 |
| Missing/invalid credentials | 401 |
| Authenticated identity unavailable or decommissioned | 403 |
| Authenticated identity does not match target resource identity | 403 |
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
| LogicSig key file missing `salt_counter` | Rejected during scan/restore; may surface as unknown address or restore failure |
| LogicSig key file bytecode derives an on-curve address | Rejected during scan/restore; may surface as unknown address or restore failure; if detected during signing, 500 |
| Internal provider failure | 500 |

Additional compatibility-sensitive request failures:

- missing `txn_bytes_hex` for sign mode: `400`
- passthrough entries without an existing group ID: `400`
- immutable pre-grouped transactions that would require extra dummies: `400`
- requests whose required dummies would push the group above 16 transactions: `400`
- invalid runtime args or generic LogicSig arg decoding: `400`
- missing TEAL compile algod configuration for generic LogicSig generation: `500`
- missing `address` query parameter on delete: `400`
- all-foreign `/sign` or `/plan` requests: `400` because apsigner has no signer-managed work to perform
