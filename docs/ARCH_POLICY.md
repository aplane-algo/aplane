# Policy Architecture

This document describes the policy system implemented today. It is the
current-state companion to [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md).

## Scope

Signer policy decides what `apsigner` may sign after request planning has
identified the signer-controlled transactions. Policy is separate from:

- authentication and authorization, which decide who may ask for signing,
- key ownership and unlock state, which decide whether signing keys are usable,
- the operator default, which decides whether unmatched requests need manual
  review.

## Storage

Policy is identity-scoped and stored at:

```text
identities/<identity>/policy.yaml
```

The signer keeps a sibling integrity sidecar:

```text
identities/<identity>/policy.yaml.hmac
```

The HMAC covers the exact `policy.yaml` bytes and uses a key derived from the
identity master key. Sidecar metadata such as signing time, policy SHA-256, and
file mtime is diagnostic; the HMAC is the security check. After the signed
baseline exists, a missing or mismatched sidecar fails closed instead of loading
defaults. On reload failure, the previous in-memory policy remains active.

The sidecar authenticates only the YAML bytes. Diagnostic metadata fields in the
sidecar can be edited without invalidating the policy HMAC; they are not
security inputs to the verification decision.

Identity-scoped runtime settings such as `user_auto_approve`,
`lock_on_disconnect`, and `passphrase_timeout` live separately in:

```text
identities/<identity>/config.yaml
```

`user_auto_approve` is shown in `apadmin` as `User Auto-Approve`. It is not a
policy rule; it is the user/operator default used only when policy has no
matching verdict.

`policy.yaml` is a sparse map at the top level. Absent top-level booleans
resolve through product defaults: `reject_foreign_rekey` defaults to `true`,
while `reject_close_remainder`, `reject_asset_close`, `reject_clawback`,
`always_review_warnings`, and `auto_approve_self_noop_transfer` default to
`false`. An absent `max_fee_microalgos` means no fee ceiling, and absent
transfer-guard maps are empty. `transfer_policy` may be absent entirely; if it
is present, it must satisfy the explicit routing schema below.

## Verdict Model

Policy verdicts override the operator default. Among policy verdicts, the most
restrictive matching verdict wins.

| Tier | Decision owner | Effect |
|------|----------------|--------|
| Always Deny | Policy | Reject the request before approval |
| Always Review | Policy | Require operator approval |
| Always Approve | Policy | Sign without operator approval |
| Operator Default | Admin setting | Review or approve according to `user_auto_approve` |

Precedence:

```text
Always Deny > Always Review > Always Approve > Operator Default
```

Operational flow:

1. Evaluate policy rules.
2. If any Always Deny rule matches, reject.
3. Else if any Always Review rule matches, require approval.
4. Else if any Always Approve rule matches, sign.
5. Else use Operator Default:
   - `user_auto_approve:false` requires approval.
   - `user_auto_approve:true` signs without approval.

This means Always Review blocks both `user_auto_approve:true` and any matching
Always Approve rule.

## Runtime Snapshot Semantics

The identity runtime publishes policy updates atomically. Readers see either
the previous policy snapshot or the replacement snapshot; they must not observe
a partially applied policy.

Each signing request captures the effective policy snapshot when its signing
service is constructed. That snapshot governs the request through policy
evaluation, approval waiting, and final signature execution. A later successful
policy reload or `apadmin` whole-file hot replacement applies only to signing
requests that start after the new snapshot is published. In-flight requests are
not re-evaluated or canceled merely because the policy changed while they were
waiting for approval.

## Always Deny

Always Deny rules are hard safety guards. They cannot be approved by an
operator prompt and are evaluated before all other policy or approval phases.

Current rules:

| Field | Meaning |
|-------|---------|
| `reject_foreign_rekey` | Reject transactions whose non-zero `RekeyTo` target is not held by the current signer identity |
| `reject_close_remainder` | Reject payment transactions with non-zero `CloseRemainderTo` |
| `reject_asset_close` | Reject ASA transfers with non-zero `AssetCloseTo` |
| `reject_clawback` | Reject ASA clawback transactions using `AssetSender` |
| `max_fee_microalgos` | Reject transactions whose raw microAlgo fee exceeds the configured ceiling |
| `max_algo_payments` | Per-network raw microAlgo ceilings for ALGO payments |
| `max_asa_amounts` | Per-network raw unit ceilings for ASA transfers |
| `transfer_policy` | Transfer routing rules whose blocked-destination, route miss, close/clawback, and `reject_above` outcomes reject matching direct transfer movements |

Network-scoped rules derive transaction network identity from `GenesisHash`,
not `GenesisID`. Unknown genesis hashes fail closed when a network-scoped rule
must be evaluated.

`max_algo_payments` and `max_asa_amounts` are the deny side of transfer guards.
If a matching review threshold is also configured, the deny threshold must be
greater than or equal to the review threshold. This invariant is enforced at
config apply time: a `policy.yaml` that violates it fails to load.

`transfer_policy` is a YAML-driven route table for direct `pay` and `axfer`
movements. When enabled, it can reject blocked destinations, route misses,
close-out misses according to `close_on_no_route`, clawback misses according to
`clawback_on_no_route`, matched close-out movements without `close.allow:true`,
matched clawback movements without `clawback.allow:true`, and matching
movements above a route's `reject_above` threshold. Routes never auto-approve a
request; a route match only lets the movement continue through the remaining
policy phases. See [Transfer Routing](#transfer-routing).

## Always Review

Always Review rules force a human approval prompt even when the operator default
is configured to skip review.

Current rules:

| Field | Meaning |
|-------|---------|
| `always_review_warnings` | Require operator review when warning analysis finds risk markers |
| `review_algo_payments` | Per-network raw microAlgo thresholds that require review for ALGO payments |
| `review_asa_amounts` | Per-network raw unit thresholds that require review for ASA transfers |
| `transfer_policy` | Transfer routing rules whose route-miss fallback is `review` or whose `review_above` thresholds force operator review |

`review_algo_payments` and `review_asa_amounts` are the review side of transfer
guards. They are evaluated after Always Deny. For example, an ASA transfer above
`review_asa_amounts.testnet["10458941"]` requires approval unless it has already
been rejected by a matching `max_asa_amounts` threshold.

Unknown genesis hashes trigger a distinct fail-closed rule that forces review
when a configured transfer-guard review threshold cannot be mapped to a network
token. This rule is independent of the configured threshold values.

Transfer routing review outcomes are evaluated after hard-reject policy passes
and before auto-approval. Routing review applies only to signer-controlled
direct transfer movements; passthrough and foreign request slots are not
governed by this signer's route table. See
[Transfer Routing](#transfer-routing).

Warning analysis currently covers:

- rekey fields,
- ALGO close-out fields,
- ASA close-out fields,
- ASA clawback fields,
- unusually high fees above 1 ALGO.

Warnings are still displayed when `always_review_warnings:false`; they simply
do not force review in that mode.

## Always Approve

Always Approve rules are explicit low-risk rules stored in policy. They are
evaluated only after Always Deny and Always Review have not matched.

Current rules:

| Field | Meaning |
|-------|---------|
| `auto_approve_self_noop_transfer` | Auto-approve a tightly constrained self no-op transfer |

`auto_approve_self_noop_transfer` applies only to a single signer-controlled
request with no caller-provided group, no passthrough or foreign slots, no
rekey, no close remainder, no asset close, no clawback sender, no note, no
lease, and normalized fee at most 1000 microAlgos.

The real transaction must be one of:

- a 0 ALGO payment to self,
- a 0-unit ASA transfer to self.

Signer-generated LogicSig-budget dummy transactions are allowed only when they
use APlane's embedded dummy LogicSig address, match the real transaction's
network and validity window, carry no fee, and the real transaction's fee
increase exactly covers those dummies.

The exact self no-op shape, including signer-generated budget dummies, is
exempt from transfer routing regardless of whether
`auto_approve_self_noop_transfer` is enabled. The auto-approval rule still
controls only whether that shape skips manual approval.

## Operator Default

Operator Default is not policy. It is the fallback behavior for requests that
did not match Always Deny, Always Review, or Always Approve.

The setting is:

```yaml
user_auto_approve: false
```

Location:

```text
identities/<identity>/config.yaml
```

Behavior:

- `user_auto_approve:false`: unmatched requests require operator review.
- `user_auto_approve:true`: unmatched requests sign without operator review.

## Transfer Routing

`transfer_policy` is the implemented v1 route table for signer-controlled
direct transfer movements. It lives only in `policy.yaml` and is not projected
through admin IPC. A route match means "allowed to continue through the normal
policy phases"; it does not approve signing and never produces an Always
Approve verdict.

For operator examples and troubleshooting, see
[USER_TRANSFER_ROUTING.md](USER_TRANSFER_ROUTING.md).

Routing's shape is deliberately conservative:

- It produces only Always Deny or Always Review verdicts. A matching route is
  allow-to-continue, not approval, because fee, rekey, close-out, clawback,
  warning, legacy transfer-guard, and Operator Default behavior must still be
  able to apply.
- It denies by absence rather than by general explicit deny routes. In v1,
  operators grant allowed source/asset/destination paths and use `on_no_route`
  to decide what a miss means. The narrow exception is `blocked_destinations`,
  a global concrete-address deny list that runs before route matching. This
  avoids source-scoped and route-local deny/allow precedence rules while
  preserving a clear migration path through `on_no_route: review`.
- It coexists with legacy transfer guards. Existing review/deny thresholds keep
  their behavior and audit rule IDs, and routes cannot weaken them.
- It coexists with legacy close/clawback reject booleans. Route-level
  `close.allow:true` and `clawback.allow:true` permit matching movements only
  within routing; they do not override `reject_close_remainder`,
  `reject_asset_close`, or `reject_clawback`. Stored-policy advisory checks
  flag this overlap as a warning rather than rejecting the policy.
- It rejects mixed-unit limits. ALGO microAlgos and ASA raw units are not
  comparable, so a route with amount limits must resolve to one asset unit per
  network.

Routing is disabled unless `transfer_policy.enabled:true`. If a
`transfer_policy` block is present, `schema_version: 1` and an explicit
`enabled: true` or `enabled: false` are required. Unknown fields under
`transfer_policy` or route entries fail validation. When routing is enabled,
`on_no_route` must be explicit unless the block is a key type override that
inherits an identity-wide `on_no_route` value. `close_on_no_route` and
`clawback_on_no_route` default to `reject` and may be set explicitly to
document or override the stricter close-out and clawback route-miss behavior.

Top-level routing schema:

| Field | Required | Meaning |
|-------|----------|---------|
| `schema_version` | yes | Routing schema version; v1 only |
| `enabled` | yes | Enables routing when `true`; disables routing when `false` |
| `on_no_route` | when enabled | Route-miss verdict: `reject`, `review`, or `operator_default` |
| `close_on_no_route` | no | Close-out route-miss verdict; defaults to `reject` |
| `clawback_on_no_route` | no | Clawback route-miss verdict; defaults to `reject` |
| `blocked_destinations` | no | Global concrete-address deny list evaluated before route matching |
| `address_sets` | no | Named address lists or network-scoped address lists |
| `asset_sets` | no | Named network-scoped ASA ID lists |
| `routes` | no | Ordered route definitions; order does not grant priority |

Route schema:

| Field | Required | Meaning |
|-------|----------|---------|
| `id` | yes | Stable route identifier used in policy rule IDs |
| `description` | no | Operator-facing note |
| `enabled` | no | Defaults to `true`; disabled routes are ignored |
| `networks` | yes | Either `["*"]` or concrete network context tokens |
| `sources` | yes | Sender terms: address, `@address_set`, or `*` |
| `asset_sources` | clawback only | Allowed ASA `AssetSender` terms; requires `clawback.allow:true` |
| `assets` | yes | Asset terms: `algo`, ASA ID, `asa:<id>`, `@asset_set`, or `*` |
| `destinations` | yes | Receiver terms: address, `@address_set`, `self`, or `*` |
| `limits.review_above` | no | Always Review when amount is strictly greater than this raw threshold |
| `limits.reject_above` | no | Always Deny when amount is strictly greater than this raw threshold |
| `limits_by_network` | no | Per-network threshold overrides |
| `close.allow` | no | Allows matching ALGO/ASA close-out movements; defaults to false |
| `clawback.allow` | no | Allows matching ASA clawback movements; defaults to false |

Route IDs must match `^[a-z0-9][a-z0-9_-]*$`. Network names are APlane network
context tokens as defined in [ARCH_NETWORKS.md](ARCH_NETWORKS.md). A route's
`networks` field may be exactly `["*"]` or a list of concrete tokens, but not a
mix of `*` and concrete tokens.

Address sets accept either a flat list, which applies on every network, or a
map keyed by network context token. `*` is not a valid network key inside an
address set; use the flat-list shape for all-network membership. Asset sets
are maps from network context token to ASA IDs; they do not accept a flat-list
shape because ASA IDs are network-local.

`blocked_destinations` is a flat list of concrete Algorand addresses. It does
not accept `self`, `*`, or `@address_set` terms. The list is global in v1:
it is not source-scoped, asset-scoped, or network-scoped. A key type override
inherits the identity-wide blocked list and may add addresses, but it cannot
remove identity-wide blocked destinations.

Routing extracts movements only from direct payment and asset-transfer
transactions:

- `pay` creates a normal ALGO movement from `Sender` to `Receiver`.
- non-zero `CloseRemainderTo` creates an additional `pay_close` movement.
- normal `axfer` creates an ASA movement from `Sender` to `AssetReceiver`.
- an ASA opt-in is represented as `axfer_optin` when the receiver is the
  sender, amount is zero, `AssetSender` is zero, and `AssetCloseTo` is zero.
- non-zero `AssetCloseTo` creates an additional `asset_close` movement.
- clawback is represented as `clawback` when `AssetSender` is non-zero and not
  equal to `Sender`; the route must match `sources`, `asset_sources`, `assets`,
  and `destinations`.

Other transaction types produce no routing movement and continue through the
remaining policy phases. Passthrough and foreign request slots are not governed
by this signer's route table because this signer is not signing them.

For each extracted movement, routing checks `blocked_destinations` before
network-dependent route matching. The block applies to normal ALGO payment
receivers, ALGO close remainder destinations, normal ASA transfer receivers,
ASA close-out destinations, and ASA clawback receivers. ASA opt-ins are not
blocked by this field. Because the blocked list is global, it can reject even
when the transaction `GenesisHash` is unknown.

After that check, routing resolves the transaction `GenesisHash` to a network
token. If the hash cannot be resolved, routing emits
`transfer_policy:unknown_genesis_hash` at the tier selected by `on_no_route`:
Always Deny for `reject`, Always Review for `review`, and no routing verdict
for `operator_default`.

Verdict production for each movement:

1. Routing sits out when `transfer_policy` is absent, disabled, or the movement
   is routing-exempt.
2. If the movement kind is covered by `blocked_destinations` and the movement
   destination is blocked, Always Deny.
3. Matching routes are collected by network, source, asset, destination, and,
   for clawback only, asset source.
4. If no route matches a close-out movement, apply `close_on_no_route`.
5. If no route matches a clawback movement, apply `clawback_on_no_route`.
6. If no route matches any other movement, apply `on_no_route`.
7. A close-out movement with matching routes is Always Deny unless at least one
   matching route has `close.allow:true`.
8. A clawback movement with matching routes is Always Deny unless at least one
   matching route has `clawback.allow:true`.
9. If the amount is known and any matching route has `reject_above`, the lowest
   effective reject threshold wins; amounts strictly greater than that value
   are Always Deny.
10. If the amount is known and any matching route has `review_above`, the lowest
   effective review threshold wins; amounts strictly greater than that value
   are Always Review.
11. Otherwise routing produces no verdict and the request continues to warning
   review, explicit auto-approval, or Operator Default.

`limits_by_network` overrides global `limits` for that network. If both review
and reject thresholds are set, `reject_above` must be greater than or equal to
`review_above`. Amounts are raw on-chain units: microAlgos for ALGO and raw
ASA units for ASAs. A route with active amount limits must resolve to at most
one asset unit per network; wildcard assets and mixed ALGO/ASA units are
invalid with limits.

The exact self no-op shape used by `auto_approve_self_noop_transfer`, including
signer-generated LogicSig-budget dummy transactions, is routing-exempt. Routing
exemption suppresses all routing verdicts for that shape. Non-routing guards
such as warning analysis, fee checks, rekey/close/clawback guards, and the
self no-op auto-approval predicate still apply according to their own rules.

Key type override routing blocks are sparse overlays, except `enabled` must be
explicit in every `transfer_policy` block. Unset `on_no_route`,
`close_on_no_route`, `clawback_on_no_route`, `blocked_destinations`,
`address_sets`, and `asset_sets` inherit from the
identity-wide effective policy. Override `blocked_destinations` are unioned with
the inherited blocked list. Override address and asset sets add to or replace
inherited set names. Routes inherit unless the override explicitly provides a
`routes` field, in which case the override's route list replaces the inherited
route list for that key type.

Routing rule IDs:

- `transfer_policy:blocked_destination`
- `transfer_policy:route_miss`
- `transfer_policy:unknown_genesis_hash`
- `transfer_policy:close_route_miss`
- `transfer_policy:clawback_route_miss`
- `transfer_policy:close_rejected`
- `transfer_policy:clawback_rejected`
- `transfer_policy:<route_id>:close_rejected`
- `transfer_policy:<route_id>:clawback_rejected`
- `transfer_policy:<route_id>:reject_above`
- `transfer_policy:<route_id>:review_above`

The per-route IDs use the stable grammar
`transfer_policy:<route_id>:<outcome>`, where `<outcome>` is one of
`close_rejected`, `clawback_rejected`, `reject_above`, or `review_above`.

## Key Type Overrides

`policy.yaml` may contain `key_type_overrides`, a map from signing key type to
sparse policy blocks. During signing, the effective policy is selected by the
auth address key type, not by transaction sender. This matters for rekeyed
accounts: the key type that will actually sign controls the override.

At the stored-policy level, overrides are sparse: unset fields inherit from the
identity-wide policy. Nested overrides are rejected. If an override includes a
`transfer_policy` block, that block still requires `schema_version` and
explicit `enabled`; the remaining transfer routing fields use the overlay rules
described in [Transfer Routing](#transfer-routing).

## Transaction Scope

Always Deny, Always Review, and Always Approve rules evaluate signer-controlled
request slots only. Passthrough and foreign slots are not signed by this signer,
so they are not evaluated by this signer's transaction-level policy. They still
participate in request planning, group context, warning display, and approval
rendering.

Groups receive group-level approval. A grouped request does not fan out into
separate per-transaction human approvals.

## Admin Surface

`apadmin` exposes a viewer for the active signer-owned stored policy snapshot
and one live mutation: wholesale replacement from a local YAML file. It is not a
field editor and it does not merge policy fragments. The replacement path
requires an unlocked identity, verifies the current sidecar, validates the
submitted YAML with the signer runtime compiler, writes the exact submitted
bytes plus a fresh sidecar, and updates the active runtime policy immediately.
Guided policy edits remain centered on `appolicy`, the local offline policy
editor. This avoids maintaining two mutable operator-facing field-editing
models while transfer routing becomes the canonical configuration surface.

The admin protocol and `internal/signerapp/admin` still retain policy
read/write messages for compatibility and existing service boundaries, plus
`get_policy_snapshot` for live inspection and `replace_policy` for deliberate
whole-file hot replacement. New guided field-editing UI work should target
`appolicy` rather than adding route editors back to `apadmin`.

`transfer_policy` is persisted only in `policy.yaml` in v1. It is validated by
the policy load path, by `apstore policy check/sign/verify`, by the offline
`appolicy` checker/editor, and by apadmin's whole-file replacement path. It is
not projected through the mutable admin IPC policy settings payload and has no
guided `apadmin` editor; the apadmin viewer renders it from the active policy
snapshot.

`appolicy` is the local offline policy editor. In production mode it loads the
identity policy, verifies the HMAC sidecar with the store passphrase, validates
changes through the same runtime compiler as `apsigner`, and applies the draft
to production by saving `policy.yaml` plus a fresh sidecar while holding the
store mutation lock. When opened with a standalone YAML file, it validates the
file without unlocking the production store; applying that file-backed draft to
production is the operation that asks for the passphrase. The TUI exposes
common policy fields as effective values with a source column, such as
`default`, `explicit`, or `absent`, rather than showing YAML-null markers as
values. Values that match the product default can still be omitted from saved
YAML. Transfer settings edit the required binary
`transfer_policy.enabled` switch and the route-miss fallback fields. Guard,
transfer-settings, and asset-set field editors validate and commit successful
edits into the in-memory draft as each field editor closes; applying the draft
to production remains a separate `a` action.

A normal transfer guard is a UI projection of adjacent stored routes with the
same derived guard name and network/source/destination/close shape. Group-level
fields edit the shared shape: guard name, description, enabled, networks,
sources, destinations, and close allowance. The route row table edits one real
route per asset row: asset term and optional review/reject thresholds. Appolicy
derives stored route IDs as `<guard>_<asset>`, with asset-set references using
the set name without `@`. Existing route IDs that do not follow that generated
convention are preserved on no-op guard edits because route IDs are persistent
audit identifiers; changing the guard name or asset row intentionally writes
the generated convention.
The Transfer Guards screen also exposes the global `blocked_destinations` list
and owns an Asset Sets editor for the `asset_sets` map; route asset cells
accept bare set names and store them as `@name` in YAML. New transfer policies
and existing transfer policies with no asset sets are seeded with a `usdc` set
from APlane's built-in mainnet/testnet ASA metadata when the Asset Sets editor
opens. Thresholds are still stored in raw YAML units, but appolicy edits ALGO,
concrete ASA, and eligible single-asset-per-network asset-set thresholds in
display units and uses signer-side ASA metadata to convert ASA values.
Multi-network asset-set guard rows are written as uniform `limits_by_network`
entries.
Advanced routing structures that are not yet surfaced in the guard editor
still round-trip through YAML and can be edited directly with
`apstore policy check/sign/verify`. For non-interactive use,
`APPOLICY_PASSPHRASE` is checked before `APSIGNER_PASSPHRASE`.
`appolicy --sha256` verifies the sidecar and prints the SHA-256 digest of the
exact trusted `policy.yaml` bytes. `appolicy --yaml` verifies the sidecar and
emits those bytes to stdout. `appolicy --save` reads exact replacement YAML
bytes from stdin, parses and runtime-validates them, and writes those bytes
plus a fresh sidecar while holding the same lock.
With a positional YAML file, `--check`, `--yaml`, and `--sha256` parse and
runtime-validate the file without reading the production sidecar or requesting
the store passphrase.
Inside the TUI, `a` applies the current in-memory draft to production. `w`
exports the current draft to an operator-selected YAML file only; it does not
write a sidecar, update the signer store, or mark the draft clean.

The signer retains compatibility support for authenticated admin IPC policy
changes. The identity must be unlocked so the signer can verify the current
policy and write a fresh sidecar. `apadmin` exposes only live snapshot viewing
and whole-file replacement, not direct field editing. Its policy viewer displays
the policy currently held by the signer runtime.
For deliberate direct YAML edits, use `apstore policy check`, review the file,
then run `apstore policy sign`; `apstore policy verify` checks the sidecar with
the store passphrase. `apstore policy sign` is an offline store mutation and
requires the store mutation lock, so direct YAML edits are normally signed while
`apsigner` is stopped or before starting it. Direct YAML edits take effect only
after the next successful reload, unlock, or restart.

## Backup and Restore

Managed backups include a policy snapshot:

```text
policy/policy.yaml
policy/policy.yaml.hmac
```

The backup path verifies the live policy before copying that snapshot. Restore
paths do not install policy files automatically: `apconsole` admin restore and
`apstore restore apply` restore keys and required key-type/template state only.

The archived sidecar is source-store provenance material, not a destination
sidecar. If an operator deliberately restores `policy/policy.yaml`, the restored
YAML must be reviewed, installed explicitly while the destination store is not
being mutated by the signer, re-signed on the destination store with
`apstore policy sign`, and then loaded by a signer reload, unlock, or restart.
Existing destination policy files must not be overwritten implicitly.

## Audit and Observability

Signing outcome audit records carry the matching policy rule in `policy_rule_id`:

- Always Deny matches produce `sign_rejected` records with the rejecting rule.
- Always Review matches produce `sign_approved` or `sign_rejected` records with
  the forcing rule, depending on the operator's decision.
- Always Approve matches produce `sign_approved` records with the approving rule.
- Operator Default outcomes produce records with no `policy_rule_id`.

The signer also prints `[POLICY] ...` lines to its console output for each
policy decision:

- `[POLICY] Group/Txn auto-approved (<rule_id>)` when an Always Approve rule
  matches.
- `[POLICY] Group/Txn requires manual review (<rule_id>)` when an Always Review
  rule forces a prompt.
- `[USER AUTO-APPROVE] ...` when Operator Default approves without prompting.

## Source Files

Implementation source of truth:

- `internal/policy/config.go`: effective and stored policy model.
- `internal/policy/lint.go`: Always Deny transaction checks.
- `internal/policy/review.go`: Always Review transfer guard checks.
- `internal/policy/transfer_routing.go`: transfer routing YAML schema,
  compilation, and validation.
- `internal/policy/transfer_routing_eval.go`: direct transfer movement
  extraction and route evaluation.
- `cmd/appolicy`: offline policy checker/editor binary.
- `internal/policyeditor`: offline policy load, validate, save, and lock
  handling for `appolicy`.
- `internal/policytui`: terminal UI model for offline policy editing.
- `internal/signerapp/signing/always_review.go`: Always Review evaluation.
- `internal/signerapp/signing/approval.go`: approval prompts and operator default behavior.
- `internal/signerapp/signing/service.go`: phase ordering.
- `internal/signerapp/admin/service.go`: compatibility admin policy read/write service.
