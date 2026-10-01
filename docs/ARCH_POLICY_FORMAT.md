# Policy Document Format v1

## Status

Specified, not yet implemented. This document defines the v1 policy document
format that replaces `policy.yaml`. Until the implementation lands, the
running system still reads `policy.yaml` as described in
[ARCH_CONTRACTS.md](ARCH_CONTRACTS.md#policy-file-policyyaml) and
[ARCH_POLICY.md](ARCH_POLICY.md). The system is unreleased, so v1 does not
read or migrate `policy.yaml`.

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
  `diff` before `apply`.

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

Each `.hmac` sidecar authenticates the exact document bytes with the
`internal/integritysidecar` format already used for `policy.yaml`. The HMAC is
not bound to a file name, so a cosigner document carries a signed `key` field
that must equal the Witness Key ID in its file name; a mismatch is rejected.

Cosigner rules:

- A cosigner request must name a `component_key`. The node rejects the
  request before any policy evaluation unless it holds that key **and** has a
  verified policy document for it. A key without a document rejects
  everything.
- A document for a key the node does not hold is accepted (policy may be
  installed before its key) and reported by `check`.
- Deleting a cosigner key archives its policy document with it.
- Changing several keys' documents lands in one generation commit.

## Parsing

- UTF-8 JSON object, at most 1 MiB.
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
