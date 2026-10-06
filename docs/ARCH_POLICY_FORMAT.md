# Policy Document Format v1

## Status

Implemented. This document defines the v1 policy document format that nodes
store and enforce. The decoder, semantic validation, and compiler live in
`internal/policy` (`jsontree.go`, `doc_v1.go`, `doc_v1_compile.go`), storage
and sidecar handling in `internal/policy/store_v1.go`, and the shared
check/commit rules in `internal/signerapp/policyapply`. Every contract fixture
is checked against both the JSON Schema and the decoder. The system is
unreleased, so v1 does not read or migrate `policy.yaml`.

Verdict semantics (Always Deny, Always Review, route matching, strictest-limit
aggregation, close and clawback rules, rule IDs) are unchanged and remain
specified in [ARCH_POLICY.md](ARCH_POLICY.md). This document specifies only the
document format, its storage, and acceptance.

## The Boundary

The policy document is the signer/cosigner interface. A node accepts, signs,
and enforces exactly what this format and its semantic checks admit; it does
not care what produced the document. People, LLMs, scripts, and external tools
are all producers outside the boundary.

Consequences:

- Every rule the node relies on is checked at acceptance (`apadmin policy
  check`/`apply`, `apstore policy check`/`sign`, and every load), never only by
  a producer.
- Errors name the failing location as a JSON Pointer, so any producer can fix
  the exact field.
- The schema is a versioned contract. Changing it is a deliberate new
  `format` version.
- There is no policy editor in the node. Review happens through `check` and
  `diff` before `apply`, which shows the same diff and asks for confirmation.
- Comments are a producer convenience, not part of the format. The apadmin
  policy commands and the apadmin TUI accept `//` and `/* */` comments
  outside strings and remove them (`policyreview.StripComments`) before the
  document is sent, so the node never sees or stores them. `apstore policy
  check|sign` act on documents already in the store, which must be strict
  JSON.

The machine-readable schema is
[`pkg/policyschema/policy.v1.schema.json`](../pkg/policyschema/policy.v1.schema.json)
(JSON Schema 2020-12). Examples are in
[`test/contracts/policy/v1/`](../test/contracts/policy/v1/): valid documents at
the top level, schema-invalid documents in `invalid/`, and documents the schema
accepts but the node's semantic rules reject in `semantic_invalid/`.

## Files

| Node role | Files in the active generation | Governs |
|-----------|--------------------------------|---------|
| signer | `policy.json`, `policy.json.hmac` | All signing on the node |
| cosigner | `policies/<WitnessKeyID>.json`, `policies/<WitnessKeyID>.json.hmac`, one pair per cosigner key | Component signing by that key only |

Files live under `identities/default/generations/<generation-id>/`. A new
signer store starts with `policy.InitialSignerPolicy`: every setting at its
default and routing on with one route, `self-transfer`, which lets any
account send any asset to itself on any network, with `on_no_route: reject`.
Opt-ins and self-sends pass; a transfer to any other address, a close-out, or
a clawback is rejected until a route allows it. A new cosigner store has no
documents, so every cosigner key rejects every request until its document is
applied; the document an operator starts that key from
(`policy.StartingCosignerDocumentV1`) is the same `self-transfer` route and
nothing else. Neither starting document carries a description, which would
outlive the starting state.

`apadmin policy template signer|cosigner` writes the same starting document
as an annotated template (`policyreview.SignerTemplate`,
`policyreview.CosignerTemplate`) with one comment on the self-transfer
route. Stripped of the comment, a template decodes equal to the starting
document it stands for,
which a test enforces, so the apadmin TUI editor opens a starting document as
its template without changing what the policy allows.

Each `.hmac` sidecar authenticates the exact document bytes with the
`internal/integritysidecar` format. The HMAC is
not bound to a file name, so a cosigner document carries a signed `key` field
that must equal the Witness Key ID in its file name; a mismatch is rejected.

Cosigner rules:

- A cosigner request must name a `component_key`. Before any policy
  evaluation, the node rejects the request as a bad request ("Witness Key ID
  not found") unless it holds that key, and rejects it with rule ID
  `cosigner_policy:key_has_no_policy` unless it has a verified policy document
  for that key. Only then is the document evaluated and the key loaded. A key
  without a document rejects everything; there is no node-wide fallback
  policy.
- A document for a key the node does not hold is accepted (policy may be
  installed before its key) and reported by `check`.
- A key's document travels with it in backups and is installed with it on
  restore (see [ARCH_POLICY.md](ARCH_POLICY.md#backup-and-restore)).
- Deleting a cosigner key archives its policy pair under
  `deleted/policies/` with it.
- Changing several keys' documents lands in one generation commit.

## Storage and Acceptance

- Every apply or removal, online or rescue, mints a new generation with
  manifest operation `policy-apply` through `genstore.Mint`. An apply that
  leaves the policy set unchanged commits nothing. Each committed apply
  leaves the outgoing generation retained until explicit generation pruning.
- `policy.json` and `policy.json.hmac` are optional generation authority
  files, present on signer generations, and pinned in the generation
  manifest and seal when present. `policies/` and `deleted/policies/` are
  generation leaf namespaces.
- On load, every document must verify against its sidecar and decode for the
  node role; any failure makes the node refuse to load policy.
- Every digest covers the exact stored bytes; there is no canonical
  re-serialization. `policy_set_sha256` is the lowercase hex SHA-256 over the
  sorted lines `<key> <document sha256>\n`, one per document, where `<key>` is
  the Witness Key ID for a cosigner document and empty for the signer
  document. `apply_policy` requires it as the optimistic-concurrency base.
- Passphrase rotation re-signs every policy sidecar: the signer document,
  every cosigner document, and archived cosigner documents. Rollback restores
  only `keys/` and `keytypes/`, so the outgoing policy is kept.
- Store validation loads and verifies the policy and verifies archived policy
  sidecars.

Operator surfaces: `apadmin policy status|export|check|diff|apply|remove` (online
over admin IPC, or `apadmin policy rescue ...` against a stopped daemon's
store), `apadmin policy template` (local, no node), `apstore policy
check|verify|sign`, and the apadmin TUI Policies view, which lists documents
and can check, diff, and apply one policy file or an in-place edit. Wire messages are `get_policy`, `get_policy_document`,
`check_policy`, and `apply_policy`; see [ARCH_ADMIN_PROTOCOL.md](ARCH_ADMIN_PROTOCOL.md#policy-messages)
and [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md#policy-documents).

## Parsing

- UTF-8 JSON object, at most 1 MiB. No comments: a producer that accepts
  them removes them before sending (see [The Boundary](#the-boundary)).
- Unknown fields are rejected at every level.
- **Duplicate object keys are rejected.** Standard decoders silently keep the
  last value, so the node uses a decoder that detects duplicates.
- Trailing data after the document is rejected.
- `format` is required and selects the document type:
  `aplane.signer-policy.v1` or `aplane.cosigner-policy.v1`. A node rejects a
  document whose type does not match its role.
- Amounts are decimal strings in base units (microAlgos for ALGO, base units
  for an ASA), e.g. `"5000000"`, from `0` through `18446744073709551615`
  (uint64). ASA IDs in `asa:<id>` share that range, starting at `1`. JSON
  numbers are rejected because many producers lose precision above 2^53. The
  schema enforces the exact range, so producers catch overflow before the node
  does.

## Terms

| Term | Syntax | Meaning |
|------|--------|---------|
| Address | 58-character Algorand address | One account; checksum is verified |
| Witness Key ID | 52-character uppercase base32 | One cosigner key |
| Network | `^[a-z0-9][a-z0-9_-]*$`, max 64 | A configured network token, e.g. `mainnet` |
| Asset | `algo` or `asa:<id>` | One asset; ASA IDs are network-specific |
| Set reference | `@<name>` | A named set defined in the same document |
| Wildcard | `*` | Any value in that position |
| `self` | `self` | Destinations only: the movement's own source |

Bare numeric ASA IDs are not accepted; write `asa:<id>`.

## Signer Document

| Field | Type | Default | Meaning |
|-------|------|---------|---------|
| `format` | `"aplane.signer-policy.v1"` | required | Document type |
| `description` | string | none | Notes for reviewers |
| `reject_foreign_rekey` | bool | `true` | Reject a rekey to an address this signer does not hold |
| `reject_close_remainder` | bool | `false` | Reject ALGO close-outs |
| `reject_asset_close` | bool | `false` | Reject ASA close-outs |
| `reject_clawback` | bool | `false` | Reject ASA clawbacks |
| `always_review_warnings` | bool | `false` | Send warning findings to operator review |
| `auto_approve_self_noop_transfer` | bool | `false` | Auto-approve a constrained self no-op transfer |
| `max_fee_microalgos` | amount | no cap | Reject a higher transaction fee |
| `limits` | limits | none | Per-network, per-asset `review_above` / `reject_above` |
| `address_sets` | sets | none | Named address sets for routes |
| `asset_sets` | sets | none | Named asset sets for routes |
| `transfer_policy` | object | routing off | Transfer routing |
| `key_overrides` | map | none | Per-key settings keyed by signing auth address |

`transfer_policy` (signer):

| Field | Type | Meaning |
|-------|------|---------|
| `enabled` | bool, required | Routing on or off |
| `on_no_route` | `reject` \| `review` \| `operator_default` | Required when enabled; verdict for an unmatched movement |
| `close_on_no_route` | same | Default `reject`; verdict for a close-out no route allows |
| `clawback_on_no_route` | same | Default `reject`; verdict for a clawback no route allows |
| `blocked_destinations` | addresses | Always rejected as destinations |
| `routes` | routes | The allow-list |

A key override may set any scalar field above plus `limits`, and nothing
else: no sets, no `transfer_policy`, no nesting. Per-account routing is
expressed with route `sources`.

### Key Override Inheritance

The node resolves each override into one effective policy for its key:

- **Scalar fields** (`reject_*`, `always_review_warnings`,
  `auto_approve_self_noop_transfer`, `max_fee_microalgos`): an override value
  replaces the document value; an omitted field inherits it.
- **`limits`** merge per network, per asset, and per threshold. A threshold
  value in the override replaces the inherited value for exactly that
  `(network, asset, review_above|reject_above)`. Every threshold the override
  does not mention is inherited. A `null` threshold removes the inherited one;
  `null` is valid only in overrides. Loosening therefore always appears
  explicitly in the override and in `diff`.
- **Validation runs on the merged result.** Each key's effective `limits` must
  satisfy `review_above` ≤ `reject_above`, even when the two values come from
  different levels.

Example: the document caps ALGO at `reject_above: "1000000000"` and ASA
`31566704` at `reject_above: "5000000000"`. An override that sets only
`mainnet/algo/review_above: "50000000"` keeps both caps and tightens review; an
override that sets `mainnet/asa:31566704/reject_above: null` removes that one
cap for its key.

## Cosigner Document

| Field | Type | Default | Meaning |
|-------|------|---------|---------|
| `format` | `"aplane.cosigner-policy.v1"` | required | Document type |
| `key` | Witness Key ID | required | The key this document governs; must match the file name |
| `description` | string | none | Notes for reviewers |
| `reject_close_remainder` | bool | `false` | Reject ALGO close-outs |
| `reject_asset_close` | bool | `false` | Reject ASA close-outs |
| `reject_clawback` | bool | `false` | Reject ASA clawbacks |
| `reject_rekey` | bool | `false` | Reject every rekey; when false, `rekey_policy` decides |
| `max_fee_microalgos` | amount | no cap | Reject a higher transaction fee |
| `limits` | limits | none | Per-network, per-asset `reject_above` only |
| `address_sets`, `asset_sets` | sets | none | Named sets, local to this document |
| `transfer_policy` | object | required | The allow-list: `blocked_destinations`, `routes` |
| `rekey_policy` | object | none | `allowed: [{sender, targets}]` rekey edges |

Cosigner policy never produces review verdicts: there is no `review_above`, no
`on_no_route` (an unmatched movement, close-out, or clawback is always
rejected), and no operator setting. Each document is self-contained; sets are
not shared between keys.

## Routes

| Field | Type | Meaning |
|-------|------|---------|
| `id` | `^[a-z0-9][a-z0-9_-]*$` | Unique within the document; appears in rule IDs |
| `description` | string | Notes for reviewers |
| `networks` | `["*"]` or network list | Networks the route applies to |
| `sources` | address terms | Senders the route covers |
| `assets` | asset terms | Assets the route covers |
| `destinations` | address terms or `self` | Receivers the route allows |
| `limits` | limits | Thresholds for this route |
| `allow_close` | bool | Allow close-outs to these destinations |
| `allow_clawback` | bool | Allow clawbacks; requires `asset_sources` |
| `asset_sources` | address terms | Accounts assets may be clawed back from |

## Limits

```json
"limits": {
  "mainnet": {
    "algo":         { "review_above": "100000000", "reject_above": "1000000000" },
    "asa:31566704": { "reject_above": "5000000000" }
  }
}
```

Limits are keyed by network, then by asset, so a threshold always applies to
exactly one asset in its own base units. The same shape is used at document
level, in signer key overrides (where thresholds merge as described in
[Key Override Inheritance](#key-override-inheritance)), and on routes.

Document-level and route-level limits are separate checks and both apply: a
movement is rejected or sent to review if it exceeds the document's threshold
for its asset or the strictest threshold among its matching routes. An asset a
route covers but its `limits` does not mention has no route-level threshold;
document-level limits still apply to it.

## Semantic Rules

Checked at acceptance in addition to the schema:

1. Every address checksum is valid; every amount and ASA ID is within the
   uint64 range (also enforced by the schema).
2. Every `@name` reference resolves to a set of the matching kind in the same
   document.
3. Route IDs are unique.
4. In each threshold, `review_above` ≤ `reject_above` when both are set.
5. Route `limits` name only networks the route covers (any network when
   `networks` is `["*"]`) and only assets the route covers on that network
   (directly, through a referenced set, or through `*`).
6. `allow_clawback` and `asset_sources` appear together; `self` is not
   allowed in `asset_sources` or in a clawback route's destinations.
7. `allow_close` is not combined with wildcard `destinations`.
8. `blocked_destinations` holds addresses only (no sets, `self`, or `*`).
9. A cosigner document's `key` equals its file name, and the node role
   matches `format`.
10. For every signer key override, the merged effective `limits` satisfy
    rule 4 (see [Key Override Inheritance](#key-override-inheritance)).
11. `rekey_policy` references only flat address sets; rekey edges are not
    network-scoped.

Errors report the JSON Pointer of the failing value, for example
`/transfer_policy/routes/1/limits/mainnet/asa:31566704/reject_above`.

## Changes From `policy.yaml`

| `policy.yaml` | v1 |
|---------------|----|
| YAML | JSON with `format` |
| `review_algo_payments`, `max_algo_payments`, `review_asa_amounts`, `max_asa_amounts` | One `limits` field |
| Route `limits` + `limits_by_network`, with a one-asset-per-network rule | Route `limits` keyed by network and asset |
| `transfer_policy.address_sets` / `asset_sets` | Top-level `address_sets` / `asset_sets` |
| `transfer_policy.schema_version` | Removed; `format` versions the document |
| Route `close: {allow}` / `clawback: {allow}` | `allow_close` / `allow_clawback` |
| Route `enabled` | Removed; omit a route to disable it |
| Bare numeric ASA IDs | `asa:<id>` only |
| Cosigner `on_no_route` / `close_on_no_route` / `clawback_on_no_route` (must be `reject`) | Removed; always reject |
| Cosigner `transfer_policy.enabled` | Removed; a cosigner document always enforces its routes |
| One cosigner `policy.yaml` + `key_overrides` by Witness Key ID | One self-contained document per key |
| Signer `key_overrides` with routing | Scalar settings and `limits` only |
| Override per-network maps replace the whole inherited map | Override `limits` merge per threshold; `null` removes one |
| Sidecar `policy_mtime_ns` | Removed (already gone) |
