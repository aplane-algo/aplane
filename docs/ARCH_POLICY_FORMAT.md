# Policy Document Format v1

## Status

Implemented. This document defines the v1 policy document format
(`aplane.policy.v1`) that nodes store and enforce. The decoder, semantic
validation, and compiler live in `internal/policy` (`jsontree.go`,
`doc_v1.go`, `doc_v1_compile.go`), storage and sidecar handling in
`internal/policy/store_v1.go`, the shipped defaults in
`internal/policy/defaults/`, and the shared check/commit rules in
`internal/signerapp/policyapply`. Every contract fixture is checked against
both the JSON Schema and the decoder. The system is unreleased, so v1 does
not read or migrate `policy.yaml`.

Verdict semantics (Always Deny, Always Review, the transaction-type rule,
route matching, strictest-limit aggregation, close and clawback rules, rule
IDs) remain specified in [ARCH_POLICY.md](ARCH_POLICY.md). This document
specifies only the document format, its storage, and acceptance.

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
- Nothing in a document is implied. Every verdict-bearing field is required,
  and the decoder fills in no defaults. Optional fields are only those whose
  absence means "no such thing": no description, no thresholds, no sets, no
  blocked destinations, no rekey edges.

The machine-readable schema is
[`pkg/policyschema/policy.v1.schema.json`](../pkg/policyschema/policy.v1.schema.json)
(JSON Schema 2020-12). It is a `oneOf` over a signer variant and a cosigner
variant discriminated by `role`, each with `additionalProperties: false`, so
a field the role does not support fails the schema before it reaches the
node. Examples are in
[`test/contracts/policy/v1/`](../test/contracts/policy/v1/): valid documents at
the top level, named for the role and shape they exercise
(`signer_default.json`, `signer_key_full.json`, `signer_key_minimal.json`,
`signer_uint64_max.json`, `cosigner_default.json`, `cosigner_key_full.json`,
`cosigner_key_minimal.json`); schema-invalid documents in `invalid/`; and
documents the schema accepts but the node's semantic rules reject in
`semantic_invalid/`. The fixture test decodes each valid document against the
role its name states.

## Files

Both node roles use the same layout under
`identities/default/generations/<generation-id>/`:

| File | Role | Governs |
|------|------|---------|
| `default.json`, `default.json.hmac` | both | The node default: the complete rulebook for every key that has no document of its own |
| `policies/<selector>.json`, `policies/<selector>.json.hmac` | both | One key, named by its selector: the Algorand address of an account the signer node holds, or the Witness Key ID of a cosigner key the cosigner node holds |
| `deleted/policies/<selector>.json`, `.hmac` | both | The archived pair of a deleted key |

A key is governed by exactly one document. A key with a file of its own uses
that file and nothing else; a key without one follows the default. There is
no inheritance, no merge, and no per-field override: a key's file replaces
the default wholesale, so every field the role requires must be present in
every document. Selection is by signing key, not by transaction sender:
ordinary signing selects by the request `auth_address`, user-role component
signing by the guarded account, and cosigner-role component signing by the
`component_key` Witness Key ID (see
[ARCH_POLICY.md](ARCH_POLICY.md#policy-selection)).

What a document governs differs by role only in how the set of accounts is
defined. On a signer node a key's document covers all signing by that account,
including the user side of a guarded key. On a cosigner node a key's document
covers component signing by that cosigner key for every account whose guarded
key was composed with it, a set the node cannot enumerate; the document's
route `sources` are the operator's only control over membership.

A generation must hold `default.json`; a load without it fails closed. A new
store's `default.json` is seeded from the embedded default for the node role
at `apstore initialize` and `apstore rebuild`
(`policy.WriteEmbeddedDefault`). The embedded documents are reproduced in
[Embedded Defaults](#embedded-defaults). The default can be replaced but
never removed.

`policies/` may hold only `<selector>.json` pairs; the selector is checked by
shape (`storepaths.ValidatePolicySelector`: a 58-character address or a
52-character Witness Key ID) before the decoder checks the checksum and the
role. A document for a key the node does not hold is accepted, so policy can
be installed before its key, and reported by `check` and `status`.

Each `.hmac` sidecar authenticates the exact document bytes with the
`internal/integritysidecar` format. The HMAC is not bound to a file name, so
every document carries a signed `key` field that must equal the file it is
stored as: `default` for `default.json`, the selector for
`policies/<selector>.json`. A mismatch is rejected.

Templates: `apadmin policy template [--key K]` prints the node's current
`default.json` (online, or from the stopped store under `rescue`) with `key`
set to `K`, or annotated as the default itself when `--key` is omitted. A
key that gets a document of its own therefore starts from exactly what it was
already doing. `apadmin policy template --embedded signer|cosigner [--key K]`
prints the shipped default instead and is the only form that needs no node,
store, or passphrase; the online and rescue forms fail rather than fall back
to it, so a customized node default is never silently replaced by the shipped
one. Each template carries a header comment; stripped of it, a template
decodes equal to the document it stands for (`policyreview.Template`,
`policyreview.EmbeddedTemplate`).

Key lifecycle:

- Deleting a key archives its policy pair under `deleted/policies/` in the
  same generation, on both roles.
- A key's document travels with it in backups (`policies/<selector>.apb`) and
  is installed with it on restore; the default is never in a backup (see
  [ARCH_POLICY.md](ARCH_POLICY.md#backup-and-restore)).
- Changing several documents lands in one generation commit.

## Storage and Acceptance

- Every apply or removal, online or rescue, mints a new generation with
  manifest operation `policy-apply` through `genstore.Mint`. An apply that
  leaves the policy set unchanged commits nothing. Each committed apply
  leaves the outgoing generation retained until explicit generation pruning.
- `default.json` and `default.json.hmac` are generation authority files,
  pinned in the generation manifest and seal. `policies/` and
  `deleted/policies/` are generation leaf namespaces.
- On load, every document must verify against its sidecar and decode for the
  node role and its file name; any failure makes the node refuse to load
  policy.
- Every digest covers the exact stored bytes; there is no canonical
  re-serialization. `policy_set_sha256` is the lowercase hex SHA-256 over the
  sorted lines `<key> <document sha256>\n`, one per document, where `<key>`
  is `default` or the selector. `apply_policy` requires it as the
  optimistic-concurrency base.
- A node holds at most 8,192 per-key documents (`policyapply.MaxPolicies`);
  a change past the cap is rejected with `policy_set_too_large` before
  anything is written. The default does not count.
- Passphrase rotation re-signs every policy sidecar: the default, every
  per-key document, and the archived documents under `deleted/policies/`.
  Restore rollback restores `keys/`, `keytypes/`, and `policies/` and keeps
  the outgoing default.
- Store validation loads and verifies the policy and verifies archived policy
  sidecars.

Acceptance of a candidate change (`policyapply.Candidate`, shared by the
daemon, rescue, and `apstore`):

1. The request names at least one document or removal. `default` cannot be
   removed; a removed key must have a document of its own; a key may appear
   only once across documents and removals; every non-default key is a
   well-formed selector.
2. The resulting set holds a default and at most `MaxPolicies` per-key
   documents.
3. Each submitted document decodes for the node role and its key
   ([Parsing](#parsing), [Fields](#fields), [Semantic Rules](#semantic-rules)).
   Decode errors are returned as problems with the document key and the
   JSON Pointer of the failing value.
4. The resulting set compiles.
5. `check` additionally reports warnings, which never block an apply:
   advisories for each submitted document ([Advisories](#advisories)) and
   key coverage, where a document for a key the node does not hold is
   reported as "policy is for a key this node does not hold". A key on the
   default is covered, not a gap.

Operator surfaces: `apadmin policy status|export|check|diff|apply|remove|template`
(online over admin IPC, or `apadmin policy rescue ...` against a stopped
daemon's store), `apadmin policy template --embedded` (local, no node),
`apstore policy check|verify|sign`, and the apadmin TUI Policies view, which
lists the default and every key and can check, diff, and apply one policy file
or an in-place edit. Wire messages are `get_policy`, `get_policy_document`,
`check_policy`, and `apply_policy`; see
[ARCH_ADMIN_PROTOCOL.md](ARCH_ADMIN_PROTOCOL.md#policy-messages) and
[ARCH_CONTRACTS.md](ARCH_CONTRACTS.md#policy-documents).

## Parsing

- UTF-8 JSON object, at most 1 MiB. No comments: a producer that accepts
  them removes them before sending (see [The Boundary](#the-boundary)).
- Unknown fields are rejected at every level, including fields the other
  role supports.
- **Duplicate object keys are rejected.** Standard decoders silently keep the
  last value, so the node uses a decoder that detects duplicates.
- Trailing data after the document is rejected.
- `format` is required and must be `aplane.policy.v1`.
- `role` is required and must be `signer` or `cosigner`, and must equal the
  node role: a signer document is not accepted on a cosigner node, nor the
  reverse. The role selects which fields are required and which are
  rejected.
- `key` is required and must be `default` or the selector of a key the role
  can hold: an Algorand address (checksum verified) on a signer node, a
  Witness Key ID on a cosigner node. It must equal the file name the
  document is stored as, or the key the request names it for.
- Amounts are decimal strings in base units (microAlgos for ALGO, base units
  for an ASA), e.g. `"5000000"`, from `0` through `18446744073709551615`
  (uint64) without leading zeros. ASA IDs in `asa:<id>` share that range,
  starting at `1`. JSON numbers are rejected because many producers lose
  precision above 2^53. The schema enforces the exact range, so producers
  catch overflow before the node does.

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
| Transaction type | `pay`, `axfer`, `acfg`, `afrz`, `keyreg`, `appl`, `stpf`, `hb`, or `*` | A `transaction_types` entry; `*` covers every type the map does not name |

Bare numeric ASA IDs are not accepted; write `asa:<id>`.

## Fields

One document type serves both roles. The role column says whether a field is
required, optional, or rejected on each role; a rejected field fails the
schema and the decoder. Nothing has a default: a required field that is
absent is an error, and an optional field that is absent means none.

| Field | Type | Signer | Cosigner | Meaning |
|-------|------|--------|----------|---------|
| `format` | `"aplane.policy.v1"` | required | required | Document format |
| `role` | `"signer"` \| `"cosigner"` | required | required | Node role the document is for; must equal the node's |
| `key` | `"default"` or selector | required | required | The document this is: the node default, or one key's own; must equal the file name |
| `description` | string, at most 1024 characters | optional | optional | Notes for reviewers |
| `reject_foreign_rekey` | bool | required | rejected | Reject a rekey to an address this signer does not hold |
| `reject_close_remainder` | bool | required | required | Reject ALGO close-outs |
| `reject_asset_close` | bool | required | required | Reject ASA close-outs |
| `reject_clawback` | bool | required | required | Reject ASA clawbacks |
| `reject_rekey` | bool | rejected | required | Reject every rekey; when false, `rekey_policy` decides |
| `always_review_warnings` | bool | required | rejected | Send warning findings to operator review |
| `auto_approve_self_noop_transfer` | bool | required | rejected | Auto-approve a constrained self no-op transfer |
| `max_fee_microalgos` | amount | required | required | Reject a higher transaction fee; `"0"` is no cap |
| `transaction_types` | map | required | required | Per-type verdict, evaluated before every other rule; see [Transaction Types](#transaction-types) |
| `limits` | limits | optional | optional | Per-network, per-asset thresholds: `review_above` and `reject_above` on a signer node, `reject_above` only on a cosigner node |
| `address_sets` | sets | optional | optional | Named address sets for routes and rekey edges |
| `asset_sets` | sets | optional | optional | Named asset sets for routes |
| `transfer_policy` | object | required | required | Transfer routing; see below |
| `rekey_policy` | object | rejected | optional | `allowed: [{sender, targets}]` rekey edges |

`transfer_policy`:

| Field | Type | Signer | Cosigner | Meaning |
|-------|------|--------|----------|---------|
| `on_no_route` | `reject` \| `review` \| `operator_default` | required | rejected | Verdict for an unmatched movement |
| `close_on_no_route` | same | required | rejected | Verdict for a close-out no route allows |
| `clawback_on_no_route` | same | required | rejected | Verdict for a clawback no route allows |
| `blocked_destinations` | addresses | optional | optional | Always rejected as destinations |
| `routes` | routes | required | required | The allow-list; may be empty |

A document always routes: there is no switch that turns routing off. A
signer document that wants routing to decide nothing sets one `*` to `*`
route for every asset and `operator_default` for the three miss actions; a
document with no routes and `on_no_route: reject` rejects every transfer.

A cosigner document can never produce a review verdict: it has no
`review_above`, no `review` type verdict, no `always_review_warnings`, and no
route-miss actions. An unmatched movement, close-out, or clawback on a
cosigner node is always rejected. Each document is self-contained; sets are
not shared between documents, and a key's document does not see the default's
sets.

### Transaction Types

`transaction_types` maps a transaction type, or `*`, to `allow`, `review`,
or `reject`. The `*` entry is required and covers every type the map does not
name. The verdict is evaluated first, before every other rule: `reject` is
Always Deny and `review` is Always Review, both with rule ID
`transaction_type:<type>`; `allow` lets the transaction continue through the
other rules (routing and limits for `pay` and `axfer`). A compiled policy
with no map rejects every type.

On a cosigner node every value is `allow` or `reject`, and `allow` is
accepted only for `pay` and `axfer`, the types routing governs: `*` and every
non-transfer type must be `reject`. Routing is the cosigner's only
authorization surface, and a type permission with no route table behind it
would authorize application calls from any account composed with the key.

```json
"transaction_types": { "*": "reject", "pay": "allow", "axfer": "allow", "keyreg": "review" }
```

## Routes

| Field | Type | Meaning |
|-------|------|---------|
| `id` | `^[a-z0-9][a-z0-9_-]*$`, max 64 | Unique within the document; appears in rule IDs |
| `description` | string | Notes for reviewers |
| `networks` | `["*"]` or network list | Networks the route applies to |
| `sources` | address terms | Senders the route covers |
| `assets` | asset terms | Assets the route covers |
| `destinations` | address terms or `self` | Receivers the route allows |
| `limits` | limits | Thresholds for this route; `reject_above` only on a cosigner node |
| `allow_close` | bool | Allow close-outs to these destinations |
| `allow_clawback` | bool | Allow clawbacks; requires `asset_sources` |
| `asset_sources` | address terms | Accounts assets may be clawed back from |

`id`, `networks`, `sources`, `assets`, and `destinations` are required.

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
level and on routes. Each threshold object sets at least one of
`review_above` and `reject_above`; on a cosigner node `review_above` is
rejected and `reject_above` is required.

Document-level and route-level limits are separate checks and both apply: a
movement is rejected or sent to review if it exceeds the document's threshold
for its asset or the strictest threshold among its matching routes. An asset a
route covers but its `limits` does not mention has no route-level threshold;
document-level limits still apply to it.

## Semantic Rules

Checked at acceptance in addition to the schema:

1. Every address checksum is valid; every amount and ASA ID is within the
   uint64 range (also enforced by the schema).
2. `role` equals the node role, and `key` equals the file name or the key
   the request names the document for.
3. Every `@name` reference resolves to a set of the matching kind in the same
   document.
4. Route IDs are unique.
5. In each threshold, `review_above` ≤ `reject_above` when both are set.
6. Route `limits` name only networks the route covers (any network when
   `networks` is `["*"]`) and only assets the route covers on that network
   (directly, through a referenced set, or through `*`).
7. `allow_clawback` and `asset_sources` appear together; `self` is not
   allowed in `asset_sources` or in a clawback route's destinations.
8. `allow_close` is not combined with wildcard `destinations`.
9. `blocked_destinations` holds addresses only (no sets, `self`, or `*`).
10. `rekey_policy` references only flat address sets; rekey edges are not
    network-scoped.

Errors report the JSON Pointer of the failing value, for example
`/transfer_policy/routes/1/limits/mainnet/asa:31566704/reject_above`.

### Advisories

A valid document can still have a shape that surprises, because one policy
layer cannot weaken another. `check` and `apply` report these as warnings
(`internal/policy/advisory.go`); they never block an apply:

| Rule ID | Condition |
|---------|-----------|
| `policy_overlap:reject_close_remainder:route_close_allow` | `reject_close_remainder` is true and a route sets `allow_close` |
| `policy_overlap:reject_asset_close:route_close_allow` | `reject_asset_close` is true and a route sets `allow_close` |
| `policy_overlap:reject_clawback:route_clawback_allow` | `reject_clawback` is true and a route sets `allow_clawback` |
| `policy_overlap:transaction_types:route_unreachable` | The document has routes but `transaction_types` rejects `pay` or `axfer`, so no route can match that type |
| `policy_fee:cosigner_routes_without_fee_cap` | A cosigner document has routes and `max_fee_microalgos` is `"0"`; a cosigner has no warning review, so a permitted self-payment could carry any fee |

## Embedded Defaults

The shipped defaults live at `internal/policy/defaults/signer.json` and
`internal/policy/defaults/cosigner.json` (`go:embed`, `policy.EmbeddedDefault`)
and are decoded in a test so they can never drift from the format. They seed
`default.json` when a store is created and are what
`apadmin policy template --embedded` prints.

The signer default lets a key with no document of its own behave like most
signers: self-transfers and opt-ins route, every other transfer and every
non-transfer type falls through to the operator default, a foreign rekey is
rejected, and warning-level fields always prompt.

```json
{
  "format": "aplane.policy.v1",
  "role": "signer",
  "key": "default",
  "reject_foreign_rekey": true,
  "reject_close_remainder": false,
  "reject_asset_close": false,
  "reject_clawback": false,
  "always_review_warnings": true,
  "auto_approve_self_noop_transfer": false,
  "max_fee_microalgos": "0",
  "transaction_types": { "*": "allow" },
  "transfer_policy": {
    "on_no_route": "operator_default",
    "close_on_no_route": "operator_default",
    "clawback_on_no_route": "operator_default",
    "routes": [
      {
        "id": "self-transfer",
        "description": "Any account may send any asset to itself",
        "networks": ["*"],
        "sources": ["*"],
        "assets": ["*"],
        "destinations": ["self"]
      }
    ]
  }
}
```

The cosigner default rejects everything: a cosigner has no operator to ask
and no warning review, so a key signs nothing until its operator writes every
allowance, fee ceiling included.

```json
{
  "format": "aplane.policy.v1",
  "role": "cosigner",
  "key": "default",
  "reject_close_remainder": false,
  "reject_asset_close": false,
  "reject_clawback": false,
  "reject_rekey": true,
  "max_fee_microalgos": "0",
  "transaction_types": { "*": "reject" },
  "transfer_policy": {
    "routes": []
  }
}
```

Neither default carries a description, which would outlive the starting
state. The integration test environment (`test/setup-test-env.sh`) replaces
the signer default with a permissive one (every `reject_*` false,
`always_review_warnings` false, `*` allowed, one `*` to `*` route, route
misses `operator_default`) so test keys need no per-key documents.

## Changes From `policy.yaml`

| `policy.yaml` | v1 |
|---------------|----|
| YAML | JSON with `format`, `role`, and `key` |
| `review_algo_payments`, `max_algo_payments`, `review_asa_amounts`, `max_asa_amounts` | One `limits` field |
| Route `limits` + `limits_by_network`, with a one-asset-per-network rule | Route `limits` keyed by network and asset |
| `transfer_policy.address_sets` / `asset_sets` | Top-level `address_sets` / `asset_sets` |
| `transfer_policy.schema_version` | Removed; `format` versions the document |
| Route `close: {allow}` / `clawback: {allow}` | `allow_close` / `allow_clawback` |
| Route `enabled` | Removed; omit a route to disable it |
| `transfer_policy.enabled` | Removed; a document always routes |
| Bare numeric ASA IDs | `asa:<id>` only |
| Cosigner `on_no_route` / `close_on_no_route` / `clawback_on_no_route` (must be `reject`) | Removed; always reject |
| Absent fields resolved through product defaults | Every verdict-bearing field required; nothing implied |
| One document per node with `key_overrides` by address or Witness Key ID | One node default plus zero or one complete document per key; no inheritance |
| Implicit transaction-type behavior | `transaction_types` with a required `*` entry |
| Sidecar `policy_mtime_ns` | Removed (already gone) |
