# Transfer Routing

Transfer routing is a signer policy for direct ALGO and ASA transfers. It lets
an operator define which signer-controlled source accounts may send which
assets to which destinations, on which networks, and at what amount thresholds.
The stored YAML schema calls these entries `routes`.

This is the transfer-routing deep dive. For the broader signer policy model,
editing workflow, top-level fields, and key override overview, start with
[USER_POLICY.md](USER_POLICY.md).

Routing is configured in the product policy file:

```text
identities/default/generations/<selected-generation>/policy.yaml
```

Write or edit routes in the policy file outside the node, run
`apadmin policy check FILE`, then `apadmin policy apply FILE` while `apsigner`
is running. `apadmin` applies changes as whole-document replacements through
the running signer; it does not merge independent route fragments. Use the
`apadmin policy rescue` forms when the signer is stopped:

A successful policy apply affects new signing requests after the signer
publishes the replacement policy snapshot. Signing requests that are already in
flight, including requests waiting for operator approval, continue under the
policy snapshot they captured when they started.

```bash
apadmin -d "$APSIGNER_DATA" policy rescue check
apadmin -d "$APSIGNER_DATA" policy rescue digest
apadmin -d "$APSIGNER_DATA" policy rescue export > policy.yaml
apadmin policy rescue check policy.yaml
apadmin -d "$APSIGNER_DATA" policy rescue apply policy.yaml
apadmin -d "$APSIGNER_DATA" policy rescue apply - < policy.yaml
```

When `apadmin policy rescue` reads production policy from `APSIGNER_DATA` or
`-d`, it
prompts for the store passphrase and auto-selects the document from
`node.yaml`: signer nodes use `policy.yaml`, cosigner nodes use
cosigner-domain `policy.yaml`. Use `--target signer` or `--target cosigner` to override
auto-selection. Local rescue
automation may use `APSIGNER_PASSPHRASE`; remote policy commands require the
controlling terminal. The `digest` verb verifies the current production
sidecar and prints the SHA-256 digest of the trusted selected document bytes.
The `export` verb writes only those trusted bytes to stdout. With a positional
YAML file, `check`, `export`, and `digest` validate the standalone file without
reading the production sidecar or requesting the store passphrase. `apply`
reads a file (or stdin when the source is `-`), validates it in the selected
policy domain, preserves the submitted YAML bytes, and writes the selected
document plus a fresh sidecar; you do not need to run `apstore policy sign`
afterward.

After direct in-place YAML edits to the selected document, check it, sign it,
and then reload or restart the signer:

```bash
apstore -d "$APSIGNER_DATA" policy check
apstore -d "$APSIGNER_DATA" policy sign
apstore -d "$APSIGNER_DATA" policy verify
```

Direct YAML edits take effect only after the next successful signer reload,
unlock, or restart. `apstore policy sign` and `apadmin policy rescue` saves are offline
store mutations, so the normal workflow is to run them while `apsigner` is
stopped or before starting it.

For the architecture-level policy model, see
[ARCH_POLICY.md](ARCH_POLICY.md#transfer-routing). For network token rules, see
[ARCH_NETWORKS.md](ARCH_NETWORKS.md).

## What Routing Does

Routing applies only to direct signer-controlled transfer movements:

- ALGO payment receivers,
- ALGO close remainder destinations,
- ASA transfer receivers,
- ASA opt-ins,
- ASA close-out destinations,
- ASA clawback receivers.

Routing does not inspect app-call inner transactions and does not decide who is
allowed to request signing. Authentication, authorization, key unlock state,
rekey guards, fee guards, warning review, and auto-approval rules remain
separate policy layers.

`blocked_destinations` is the global deny-list companion to route allowlists.
It rejects covered movements before route matching, so a broad wildcard route
cannot rescue a blocked recipient.

A matching route means "this movement may continue through the normal policy
pipeline." It is not an approval. Routing can reject a movement or force review,
but it never auto-approves signing.

## Getting Started

Start in review mode when you are not yet sure the route table is complete:

```yaml
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: review
  close_on_no_route: reject
  clawback_on_no_route: reject

  address_sets:
    treasury:
      - TREASURYADDRESS...
    operations:
      - OPERATIONSADDRESS...

  routes:
    - id: treasury_to_operations
      description: Treasury can transfer any asset to operations.
      networks: ["*"]
      sources: ["@treasury"]
      assets: ["*"]
      destinations: ["@operations"]
```

With `on_no_route: review`, transfer movements that match no route go to the
operator for approval. After reviewing audit output and adding any missing
routes, switch to `on_no_route: reject` for production allowlist behavior.

Use `operator_default` only when route misses should behave as if routing did
not exist:

```yaml
on_no_route: operator_default
```

That mode still applies matching route thresholds and explicit close/clawback
fallbacks. Close-out and clawback misses are controlled by
`close_on_no_route` and `clawback_on_no_route`, both of which default to
`reject`.

## Minimal Shape

```yaml
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  close_on_no_route: reject
  clawback_on_no_route: reject

  blocked_destinations: []
  address_sets: {}
  asset_sets: {}
  routes: []
```

`schema_version: 1` and an explicit `enabled: true` or `enabled: false` are
required whenever `transfer_policy` is present. `enabled:true` turns routing on.
If `enabled:false`, routing sits out and current non-routing policy behavior is
unchanged.

When routing is enabled, `on_no_route` must be explicit unless the block is a
key override inheriting a product-wide value.

## Schema Walkthrough

Top-level fields:

| Field | Required | Meaning |
|-------|----------|---------|
| `schema_version` | yes | Routing schema version; currently `1` |
| `enabled` | yes | Enables routing when `true`; disables routing when `false` |
| `on_no_route` | when enabled | Route-miss behavior: `reject`, `review`, or `operator_default` |
| `close_on_no_route` | no | Close-out route-miss behavior; defaults to `reject` |
| `clawback_on_no_route` | no | Clawback route-miss behavior; defaults to `reject` |
| `blocked_destinations` | no | Global concrete-address deny list checked before route matching |
| `address_sets` | no | Named address lists or network-scoped address lists |
| `asset_sets` | no | Named network-scoped ASA ID lists |
| `routes` | no | Route definitions; order does not grant priority |

Route fields:

| Field | Required | Meaning |
|-------|----------|---------|
| `id` | yes | Stable lowercase identifier used in audit and policy rule IDs |
| `description` | no | Operator-facing note |
| `enabled` | no | Defaults to `true`; disabled routes are ignored |
| `networks` | yes | Either `["*"]` or concrete network context tokens |
| `sources` | yes | Sender addresses, `@address_set` references, or `*` |
| `asset_sources` | clawback only | ASA `AssetSender` terms; requires `clawback.allow:true` |
| `assets` | yes | `algo`, ASA ID, `asa:<id>`, `@asset_set`, or `*` |
| `destinations` | yes | Receiver addresses, `@address_set` references, `self`, or `*` |
| `limits.review_above` | no | Always Review when amount is strictly greater than this raw threshold |
| `limits.reject_above` | no | Always Deny when amount is strictly greater than this raw threshold |
| `limits_by_network` | no | Per-network threshold overrides |
| `close.allow` | no | Allows matching close-out movements; defaults to false |
| `clawback.allow` | no | Allows matching ASA clawback movements; defaults to false |

Route IDs must match:

```text
^[a-z0-9][a-z0-9_-]*$
```

Do not use `.` or `:` in route IDs. Audit rule IDs compose route IDs into
strings such as `transfer_policy:treasury_algo_payroll:review_above`.

## `on_no_route`

`on_no_route` controls what happens when an in-scope transfer movement matches
no route.

| Value | Effect |
|-------|--------|
| `reject` | Route misses are Always Deny |
| `review` | Route misses are Always Review |
| `operator_default` | Route misses produce no routing verdict |

Think of this as "what should happen when the allowlist does not contain this
movement?" It is not the default decision for all signing requests, and it does
not affect transaction types outside routing's scope.

Close-out and clawback have their own no-route fallbacks because they are more
destructive than ordinary transfers:

```yaml
close_on_no_route: reject
clawback_on_no_route: reject
```

Both fields accept the same values as `on_no_route`. Their default is `reject`.
They apply only when no route matches. If a route matches but does not set
`close.allow:true` or `clawback.allow:true`, the movement is still rejected.

## Blocked Destinations

`blocked_destinations` is an optional flat list of concrete Algorand addresses
that no covered signer-controlled movement may target.

```yaml
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject

  blocked_destinations:
    - SANCTIONEDADDRESS...
    - COMPROMISEDADDRESS...

  routes:
    - id: allow_all_except_blocked
      networks: ["*"]
      sources: ["*"]
      assets: ["*"]
      destinations: ["*"]
```

The example above intentionally makes ordinary routing broad. The block list is
evaluated first, so the wildcard route does not allow transfers to the blocked
addresses.

The predicate is destination-only. It does not care whether the blocked address
is also the sender. A non-zero self-payment whose receiver is blocked is
rejected because the movement destination is blocked. Exact self no-op shapes
remain routing-exempt, as described below.

`blocked_destinations` applies to:

- normal ALGO payment receivers,
- payment close remainder destinations,
- normal ASA transfer receivers,
- ASA close-out destinations,
- ASA clawback receivers.

It does not apply to ASA opt-in movements, because opt-in is a zero-amount
self-directed asset-holding action rather than a transfer to an external
recipient.

`CloseRemainderTo == ZeroAddress` produces no close-out movement and therefore
has no close-out destination to check. `CloseRemainderTo == Sender` is treated
like any other close-out destination: if the sender address is blocked, the
close-to-self movement is rejected unless the transaction shape is otherwise
routing-exempt.

Omitted and empty `blocked_destinations` are equivalent. Entries must be
concrete Algorand addresses. `self`, `*`, and `@address_set` are invalid in
this field.

Adding blocked destinations tightens enforcement. Removing entries loosens
enforcement, so review removals as policy relaxation.

## Address Sets

Address sets define local aliases inside `policy.yaml`. They are not imported
from the apshell address book.

A flat list applies on every network:

```yaml
address_sets:
  payroll:
    - PAYROLL1...
    - PAYROLL2...
```

A network map applies only on named network context tokens:

```yaml
address_sets:
  treasury:
    mainnet:
      - MAINNETTREASURY...
    testnet:
      - TESTNETTREASURY...
```

Routes reference address sets with `@name`:

```yaml
sources: ["@treasury"]
destinations: ["@payroll"]
```

Set names may use lowercase ASCII letters, digits, `_`, and `-`. A single
address set cannot mix flat and network-specific shapes. `*` is not a valid
network key inside an address set; use the flat-list shape when the same
addresses should apply on every network.

## Asset Sets

Asset sets group ASA IDs by network context token:

```yaml
asset_sets:
  stablecoins:
    mainnet:
      - 31566704
    testnet:
      - 10458941
```

Routes reference asset sets with `@name`:

```yaml
assets: ["@stablecoins"]
```

Asset terms:

| Term | Meaning |
|------|---------|
| `algo` | Native ALGO payment, measured in microAlgos |
| `123456` | ASA ID 123456, measured in raw ASA units |
| `asa:123456` | Explicit ASA spelling, equivalent to `123456` |
| `@stablecoins` | Asset set expanded for the transaction network |
| `*` | Any asset, including ALGO and ASAs |

Asset IDs are network-local, so asset sets must use the network-map shape.
There is no flat-list asset-set shape.

Asset set names may use lowercase ASCII letters,
digits, `_`, and `-`. Network rows must use concrete network context tokens,
not `*`, and each row must contain at least one ASA ID. Routes reference a set
as `@stablecoins`.

A `usdc` set for Algorand mainnet and testnet is:

```yaml
asset_sets:
  usdc:
    mainnet:
      - 31566704
    testnet:
      - 10458941
```

## Movement Model

Routing evaluates movements, not raw transactions. A single transaction can
produce more than one movement, and every movement must pass routing.

Payment movement:

| Movement field | Transaction field |
|----------------|-------------------|
| `kind` | `pay` |
| `network` | resolved from `GenesisHash` |
| `source` | `Sender` |
| `asset` | `algo` |
| `destination` | `Receiver` |
| `amount` | `Amount` in microAlgos |
| `amount_known` | `true` |

Payment close-out movement:

| Movement field | Transaction field |
|----------------|-------------------|
| `kind` | `pay_close` |
| `source` | `Sender` |
| `asset` | `algo` |
| `destination` | `CloseRemainderTo` |
| `amount_known` | `false` |

ASA transfer movement:

| Movement field | Transaction field |
|----------------|-------------------|
| `kind` | `axfer` |
| `network` | resolved from `GenesisHash` |
| `source` | `Sender` |
| `asset` | `XferAsset` |
| `destination` | `AssetReceiver` |
| `amount` | `AssetAmount` in raw units |
| `amount_known` | `true` |

ASA opt-in movement:

```text
AssetReceiver == Sender
AssetAmount == 0
AssetSender == ZeroAddress
AssetCloseTo == ZeroAddress
```

The destination is treated as `self`. If routing is enabled and `on_no_route`
is `reject`, add an opt-in route for assets the account may need to hold.

ASA close-out movement:

| Movement field | Transaction field |
|----------------|-------------------|
| `kind` | `asset_close` |
| `source` | `Sender` |
| `asset` | `XferAsset` |
| `destination` | `AssetCloseTo` |
| `amount_known` | `false` |

ASA clawback movement:

| Movement field | Transaction field |
|----------------|-------------------|
| `kind` | `clawback` |
| `source` | `Sender`, the clawback authority |
| `asset_source` | `AssetSender`, the account assets are moved from |
| `asset` | `XferAsset` |
| `destination` | `AssetReceiver` |
| `amount` | `AssetAmount` in raw units |
| `amount_known` | `true` |

`AssetSender == Sender` is treated as a normal ASA transfer. Clawback is only
the case where `AssetSender` is non-zero and different from `Sender`.

## Amount Limits

In `policy.yaml`, amount limits use raw on-chain units:

- ALGO limits are microAlgos.
- ASA limits are raw ASA units.

Threshold comparison is strict greater-than:

```text
amount > threshold
```

For example, `review_above: 250000000` reviews ALGO payments above 250 ALGO,
not exactly 250 ALGO.

```yaml
routes:
  - id: treasury_algo_vendors
    networks: [mainnet]
    sources: ["@treasury"]
    assets: ["algo"]
    destinations: ["@vendors"]
    limits:
      review_above: 250000000
      reject_above: 1000000000
```

If both `review_above` and `reject_above` are present, `reject_above` must be
greater than or equal to `review_above`. Deny is evaluated first, so equal
thresholds reject matching amounts above that value.

Routes with active limits must not mix incompatible units. These are valid:

```yaml
assets: ["algo"]
assets: [31566704]
```

These are not valid with limits:

```yaml
assets: ["algo", 31566704]
assets: ["*"]
```

If you need thresholds for several assets, write separate routes.

Use `limits_by_network` when the same route spans networks with different ASA
IDs or different operational thresholds:

```yaml
routes:
  - id: treasury_stablecoin_vendors
    networks: [mainnet, testnet]
    sources: ["@treasury"]
    assets: ["@stablecoins"]
    destinations: ["@vendors"]
    limits_by_network:
      mainnet:
        review_above: 100000000
        reject_above: 500000000
      testnet:
        review_above: 50000000
        reject_above: 250000000
```

## Close-Out And Clawback

By default, close-out movements are rejected by routing unless a matching route
explicitly sets `close.allow:true`. If no route matches, `close_on_no_route`
controls the fallback and defaults to `reject`.

```yaml
routes:
  - id: customer_asset_close_to_recovery
    networks: [mainnet]
    sources: ["@customers"]
    assets: [31566704]
    destinations: ["@recovery"]
    close:
      allow: true
```

The existing `reject_close_remainder` and `reject_asset_close` guards still
apply independently. If either guard is enabled, it can reject even when a
route allows the close-out movement. Treat that overlap as advisory-level
configuration debt: route permissions cannot weaken top-level reject guards.

By default, clawback movements are rejected unless a matching route explicitly
sets `clawback.allow:true` and defines `asset_sources`. If no route matches,
`clawback_on_no_route` controls the fallback and defaults to `reject`:

```yaml
routes:
  - id: authority_clawback_to_recovery
    networks: [mainnet]
    sources: ["@clawback_authorities"]
    asset_sources: ["@customers"]
    assets: [31566704]
    destinations: ["@recovery"]
    clawback:
      allow: true
```

The existing `reject_clawback` guard still applies independently. If it is
enabled, `clawback.allow:true` documents the route intent but cannot make the
clawback signable.

`self` is not allowed in clawback `destinations` or `asset_sources` in v1.
`self` is ambiguous for clawback because the transaction sender is the clawback
authority, not the asset owner.

## Multiple Matching Routes

More than one route may match a movement. The evaluator combines matching
routes conservatively:

- at least one enabled route must match for the movement to be route-permitted,
- the lowest present `reject_above` among matching routes wins,
- the lowest present `review_above` among matching routes wins,
- close-out is allowed only if at least one matching route has
  `close.allow:true`,
- clawback is allowed only if at least one matching route has
  `clawback.allow:true`.

This lets broad routes set organization-wide ceilings while narrower routes
permit specific destinations. Broad routes can make thresholds stricter, not
looser.

## Route Matching And Evaluation Order

A route matches a movement only when every relevant dimension matches:

- network,
- source,
- asset,
- destination,
- asset source, for clawback movements only.

`@address_set` and `@asset_set` references expand according to the movement's
resolved network. `*` matches any value in that dimension. `self` is evaluated
per movement and means the movement destination equals the movement source.

Evaluation order for each movement:

1. If routing is absent, disabled, or the movement is routing-exempt, routing
   produces no verdict.
2. If the movement kind is covered by `blocked_destinations` and the movement
   destination is blocked, reject.
3. Resolve the network token from transaction `GenesisHash`.
4. Collect matching routes.
5. If no route matches and the movement is close-out, apply
   `close_on_no_route`.
6. If no route matches and the movement is clawback, apply
   `clawback_on_no_route`.
7. If no route matches for any other movement, apply `on_no_route`.
8. If the movement is close-out and no matching route has `close.allow:true`,
   reject.
9. If the movement is clawback and no matching route has
   `clawback.allow:true`, reject.
10. If amount is known and the lowest matching `reject_above` threshold is
   exceeded, reject.
11. If amount is known and the lowest matching `review_above` threshold is
   exceeded, force review.
12. Otherwise routing produces no verdict and the request continues through the
   remaining policy phases.

With the default `close_on_no_route: reject`, a close-out without an explicit
close route is rejected even if `on_no_route` is `review` or
`operator_default`.

## Routing-Exempt Movements

The exact self no-op shapes used by `auto_approve_self_noop_transfer` are
exempt from routing:

- a 0 ALGO payment to self,
- a 0-unit ASA transfer to self,
- signer-generated LogicSig-budget dummy transactions using APlane's embedded
  dummy LogicSig address.

The exemption is shape-based and does not depend on whether
`auto_approve_self_noop_transfer` is enabled. Routing exemption suppresses all
routing verdicts for that shape. Non-routing guards such as fee, rekey,
close-out, clawback, warning analysis, dummy validation, and the self no-op
auto-approval predicate still apply.

## Grouped Transactions

Routing evaluates every signer-controlled direct transfer in a signing request.
Passthrough and foreign group members remain visible as group context, but this
signer's route table does not decide whether other signers should participate.

For a grouped request:

- one routing deny rejects the whole signing request,
- one routing review forces review for the whole signing request,
- route-permitted movements do not approve the request by themselves,
- v1 does not perform group netting or balance-flow analysis.

## Common Patterns

### One Source Can Send To One Destination Or Itself

```yaml
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject

  routes:
    - id: source_to_partner_or_self
      description: Source may transfer only to partner or itself.
      networks: ["*"]
      sources:
        - SOURCEADDRESS...
      assets: ["*"]
      destinations:
        - PARTNERADDRESS...
        - self
```

With `on_no_route: reject`, `SOURCEADDRESS...` cannot send to any other
destination. Other signer-controlled accounts also need routes, or their
direct transfers will miss and be rejected.

### Preserve Existing Keys During A Narrow Rollout

v1 has no negative source matching. If you want one source to be tightly
restricted while existing sources keep broad routing, enumerate the existing
sources in an address set:

```yaml
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject

  address_sets:
    other_existing_keys:
      - AAAAA...
      - BBBBB...
      - CCCCC...

  routes:
    - id: restricted_source
      networks: ["*"]
      sources: ["SOURCEADDRESS..."]
      assets: ["*"]
      destinations:
        - PARTNERADDRESS...
        - self

    - id: other_existing_keys_passthrough
      networks: ["*"]
      sources: ["@other_existing_keys"]
      assets: ["*"]
      destinations: ["*"]
```

New keys added later are not automatically included in
`other_existing_keys`. Update and re-sign policy when adding keys that should
retain broad routing.

### Treasury Pays Payroll In ALGO

```yaml
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject

  address_sets:
    treasury:
      - TREASURY...
    payroll:
      - PAYROLL1...
      - PAYROLL2...

  routes:
    - id: treasury_algo_payroll
      networks: [mainnet]
      sources: ["@treasury"]
      assets: ["algo"]
      destinations: ["@payroll"]
      limits:
        review_above: 250000000
        reject_above: 1000000000
```

This reviews payroll payments above 250 ALGO and rejects payments above 1000
ALGO.

### Treasury Pays Vendors In A Specific ASA

```yaml
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject

  address_sets:
    treasury:
      - TREASURY...
    vendors:
      - VENDOR1...
      - VENDOR2...

  routes:
    - id: treasury_usdc_vendors
      networks: [mainnet]
      sources: ["@treasury"]
      assets: [31566704]
      destinations: ["@vendors"]
      limits:
        review_above: 100000000
        reject_above: 500000000
```

The ASA thresholds are raw asset units. For a 6-decimal asset, `100000000`
means 100 display units.

### Permit ASA Opt-In

```yaml
asset_sets:
  stablecoins:
    mainnet:
      - 31566704

routes:
  - id: treasury_stablecoin_optin
    networks: [mainnet]
    sources: ["@treasury"]
    assets: ["@stablecoins"]
    destinations: ["self"]
```

Without this route, an ASA opt-in can be a route miss when routing is enabled.

### Global "No One Can Send To X"

Use `blocked_destinations` for a small concrete list of recipients that should
always be denied, regardless of source or route.

```yaml
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: operator_default

  blocked_destinations:
    - X...
    - Y...
    - Z...
```

With `on_no_route: operator_default`, ordinary route misses behave as if
routing had no opinion. Attempts to send to X, Y, or Z are still Always Deny.
Close-out and clawback misses still use `close_on_no_route` and
`clawback_on_no_route`.

## Per-Account Routing

Signer `key_overrides` cannot carry `transfer_policy`; a signer document that
puts routing inside an override is rejected. Express per-account routing in the
product-wide route list with route `sources`, typically through address sets:

```yaml
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  address_sets:
    treasury:
      - TREASURY...
    ops:
      - OPS...
  routes:
    - id: treasury_to_ops_algo
      networks: [mainnet]
      sources: ["@treasury"]
      assets: ["algo"]
      destinations: ["@ops"]
    - id: ops_usdc_payouts
      networks: [mainnet]
      sources: ["@ops"]
      assets: [31566704]
      destinations: ["*"]
      limits:
        reject_above: 1000000000
```

Routes match on the transaction sender, so each account is governed by the
routes whose `sources` include it, and every route is validated against the
same sets it is evaluated with.

## Validation Rules

Policy load fails closed on routing errors. The previous in-memory policy
remains active if reload fails.

Common validation failures:

- missing `schema_version` under a present `transfer_policy`,
- missing `enabled` under a present `transfer_policy`,
- unsupported `schema_version`,
- unknown fields under `transfer_policy`,
- unknown fields under any route,
- invalid `on_no_route`,
- invalid `close_on_no_route`,
- invalid `clawback_on_no_route`,
- invalid `blocked_destinations` value shape,
- duplicate route IDs,
- route IDs that do not match `^[a-z0-9][a-z0-9_-]*$`,
- invalid Algorand addresses,
- `self`, `*`, or `@address_set` terms in `blocked_destinations`,
- invalid network tokens,
- `*` used as a network key in `address_sets` or `asset_sets`,
- invalid ASA IDs,
- mixed flat-and-network address-set shape in one address set,
- empty address sets or asset sets,
- unresolved `@address_set` or `@asset_set` references,
- `reject_above < review_above`,
- active amount limits on routes that can match mixed asset units,
- global `limits` on an asset set that resolves to different ASA IDs across
  route networks,
- `limits_by_network` keys outside the route's networks, unless the route uses
  `networks: ["*"]`,
- `asset_sources` without `clawback.allow:true`,
- `clawback.allow:true` without `asset_sources`,
- `self` in clawback routes,
- `close.allow:true` with wildcard destinations.

`default` and `on_route_miss` are not valid field names. Use `on_no_route`.

## Audit Rule IDs

Routing policy records stable rule IDs:

```text
transfer_policy:blocked_destination
transfer_policy:route_miss
transfer_policy:unknown_genesis_hash
transfer_policy:close_route_miss
transfer_policy:clawback_route_miss
transfer_policy:close_rejected
transfer_policy:clawback_rejected
transfer_policy:<route_id>:close_rejected
transfer_policy:<route_id>:clawback_rejected
transfer_policy:<route_id>:reject_above
transfer_policy:<route_id>:review_above
```

`transfer_policy:route_miss` may appear at deny or review tier depending on
`on_no_route`. `transfer_policy:close_rejected` and
`transfer_policy:clawback_rejected` preserve the default no-route reject rule
IDs for close-out and clawback. `transfer_policy:close_route_miss` and
`transfer_policy:clawback_route_miss` are used when the corresponding no-route
fallback forces review.

Threshold-map transfer guards retain their own rule IDs. For example, a
`max_algo_payments` rejection is reported as a threshold-guard rejection, not
as a synthetic routing threshold.

Blocked-destination denials do not enter the approval queue. Operators who need
active alerts for blocked attempts should alert on
`transfer_policy:blocked_destination` audit or log events.

## Troubleshooting

### `unknown field "default"`

Use `on_no_route`, not `default`:

```yaml
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
```

### `unknown field "on_route_miss"`

The field is `on_no_route`.

### Policy Check Passes But The Signer Uses Different Behavior

Run `apstore policy sign` after editing, then reload, unlock, or restart the
signer. A valid YAML file without a matching HMAC sidecar is not accepted after
the signed baseline exists.

### A Route-Permitted Transfer Still Rejects

Routing is only one policy layer. Check for:

- `blocked_destinations`,
- `reject_foreign_rekey`,
- `reject_close_remainder`,
- `reject_asset_close`,
- `reject_clawback`,
- `max_fee_microalgos`,
- `max_algo_payments` or `max_asa_amounts`,
- warning review settings.

Routes cannot weaken those guards.

### A Wildcard Route Still Rejects A Destination

Check `blocked_destinations`. The block list is evaluated before route
matching, so `destinations: ["*"]` cannot allow a blocked address.

### A Payment At The Threshold Was Not Reviewed Or Rejected

Thresholds use strict greater-than. A payment equal to `review_above` or
`reject_above` does not trip that threshold.

### ASA Opt-In Is Rejected As A Route Miss

Add a route with `destinations: ["self"]` for the asset or asset set.

### Close-Out Is Rejected Even Though A Route Matches

Close-out requires `close.allow:true` on a matching route. The existing
`reject_close_remainder` and `reject_asset_close` guards can still reject
independently.

### Clawback Is Rejected Even Though A Route Matches

Clawback requires:

- `clawback.allow:true`,
- an `asset_sources` list,
- matching `sources`, `asset_sources`, `assets`, and `destinations`,
- `reject_clawback:false` when the independent clawback guard should not reject.

### Unknown Genesis Hash

Routing resolves the transaction `GenesisHash` to a network token before route
matching. Built-in Algorand networks are known automatically. Custom and
localnet networks must be configured under signer `networks.<token>.genesis_hash`.

If the hash cannot be resolved, routing emits
`transfer_policy:unknown_genesis_hash` using the `on_no_route` tier:

- `reject` rejects,
- `review` forces review,
- `operator_default` produces no routing verdict.

