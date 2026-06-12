# Transfer Routing

Transfer routing is a signer policy for direct ALGO and ASA transfers. It lets
an operator define which signer-controlled source accounts may send which
assets to which destinations, on which networks, and at what amount thresholds.
The stored YAML schema calls these entries `routes`; the `appolicy` TUI presents
normal adjacent routes with the same network/source/destination shape as a
single transfer guard with an asset threshold table.

This is the transfer-routing deep dive. For the broader signer policy model,
editing workflow, top-level fields, and key override overview, start with
[USER_POLICY.md](USER_POLICY.md).

Routing is configured in the identity policy file:

```text
identities/<identity>/policy.yaml
```

Use `apadmin` for online guided routing edits while `apsigner` is running: open
the policy editor from the main key list with `p`, or from Settings with the
`Policy` row. `apadmin` applies changes as whole-document replacements through
the running signer; it does not merge independent route fragments. Use
`appolicy` for the offline TUI/checker when you want guided editing of common
policy, transfer settings, blocked destinations, and transfer guards without a
running signer:

A successful policy apply affects new signing requests after the signer
publishes the replacement policy snapshot. Signing requests that are already in
flight, including requests waiting for operator approval, continue under the
policy snapshot they captured when they started.

```bash
appolicy -d "$APSIGNER_DATA"
appolicy -d "$APSIGNER_DATA" -check
appolicy -d "$APSIGNER_DATA" --sha256
appolicy -d "$APSIGNER_DATA" --yaml > policy.yaml
APPOLICY_PASSPHRASE="$passphrase" appolicy -d "$APSIGNER_DATA" --save < policy.yaml
appolicy draft-policy.yaml
```

When `appolicy` opens production policy from `APSIGNER_DATA` or `-d`, it
prompts for the store passphrase and auto-selects the document from
`node.yaml`: signer nodes edit `policy.yaml`, sentry nodes edit
sentry-domain `policy.yaml`. Use `--target signer` or `--target sentry` to override
auto-selection. When it opens a standalone YAML file, it validates that file
without unlocking the store; if the file-backed draft is later applied to
production with `a`, the passphrase prompt happens at apply time. For
automation, `APPOLICY_PASSPHRASE` wins over `APSIGNER_PASSPHRASE`. `--sha256`
verifies the current production sidecar and prints the SHA-256 digest of the
trusted selected document bytes. `--yaml` verifies the current sidecar and
writes only those trusted bytes to stdout. With a positional YAML file,
`--check`, `--yaml`, and `--sha256` validate that file directly and do not
verify or update the production sidecar. `--save` reads policy YAML from stdin,
validates it in the selected policy domain, preserves the submitted YAML bytes,
and writes the selected document plus a fresh sidecar. Because stdin is the
policy stream for `--save`, provide the passphrase through the environment or
an interactive terminal.

Inside the TUI, `a` applies the current draft to production by writing
the selected policy document plus a fresh sidecar. `w` writes the current
draft to a YAML file you choose without applying it to the identity store or
writing a sidecar. Use this when you want to inspect or hand off a modified
policy draft before production apply.

When you apply from the `appolicy` TUI or use `appolicy --save`, it writes
the selected policy document and a fresh sidecar itself; you do not need to run
`apstore policy sign` afterward.

In the Transfer Guards screen, the list is grouped by guard name plus
network/source/destination shape and shows the global blocked-destination list
above the route list. Press `b` from that screen to edit blocked destinations.
Selecting a guard opens group-level fields for `Name`, `Description`,
`Networks`, `Sources`, `Destinations`, `Enabled`, and `Close Allow`, plus an
asset row table with `Asset`, `Review Above`, and `Reject Above` columns. Each
asset row is saved as one real route in the selected policy document; appolicy
derives the stored route ID as `<guard>_<asset>`, for example `test_algo` and
`test_usdc` for guard `test`. `Asset` may be `algo`, an ASA ID, `asa:<id>`,
cached symbol, asset set name, or `*`. Asset-set route IDs use the set name
without `@`, and appolicy stores asset-set rows in YAML as `@name`. If an
existing route ID does not follow the generated convention, appolicy preserves
it on no-op guard edits;
renaming the guard or changing an asset row writes the generated convention.

For `algo`, concrete ASA IDs, and eligible asset-set rows, `Review Above`
and `Reject Above` use display units just like the old apadmin transfer guard
editor. `50` means 50 ALGO for `algo`; `5` means 5 display units of the selected
ASA or asset set. `appolicy` still writes raw base units to the selected policy
document. This is the recommended UI path for rules such as "source A may send
ALGO to B up to 50 ALGO" and "source A may send USDC to B up to 5 USDC."

`Enter` opens a field-specific editor. Text and numeric fields open a
single-line text popup, tri-state fields open a choice popup, and list fields
open a multi-entry list editor. `Sources` and `Destinations` show the number of
entries currently defined. Closing a field editor validates and saves the
change into the in-memory draft; press `a` from the main policy screens to
apply that draft to production. In the asset table, `n` adds an asset row and
`x` deletes the selected asset row.

From the Transfer Guards screen, press `t` to edit Asset Sets. The Asset Sets
screen lists each named set, the number of network mappings, the total number
of ASA IDs, and a compact preview. `Enter` edits the selected set, `n` creates
a new set, `c` clones the selected set, and `d` deletes the selected set after
validation. Inside the asset-set editor, `Name` and `Network` use text popups,
and `ASA IDs` is a comma-separated text field. Asset-set field edits are also
validated and saved into the in-memory draft when the field editor closes.
Transfer guard asset rows accept the bare set name, such as `usdc`; appolicy
saves the route asset as `@name` in YAML.

When `appolicy` initializes a new transfer policy, it includes a default
`usdc` asset set using APlane's built-in Algorand mainnet and testnet USDC ASA
metadata. If an existing transfer policy has no asset sets, opening the Asset
Sets screen seeds the draft with the same `usdc` set so it appears in the list.

Advanced route shapes remain supported by YAML but are read-only in the guard
editor. The TUI marks these as YAML-only and offers the full policy YAML view.
Use `--yaml`/`--save` or direct selected-document YAML edits for non-uniform
`limits_by_network`, multi-asset route entries, clawback routes, and other
advanced fields. After direct in-place YAML edits, check it, sign it, and then
reload or restart the signer:

The guided transfer settings editor also leaves
`transfer_policy.clawback_on_no_route` YAML-only. It preserves an existing YAML
value during unrelated settings edits, but does not show a choice field for it.

```bash
apstore -d "$APSIGNER_DATA" policy check
apstore -d "$APSIGNER_DATA" policy sign
apstore -d "$APSIGNER_DATA" policy verify
```

Direct YAML edits take effect only after the next successful signer reload,
unlock, or restart. `apstore policy sign` and `appolicy` saves are offline
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

Start in review mode if you are migrating an existing signer and are not yet
sure the route table is complete:

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
key override inheriting an identity-wide value.

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

In `appolicy`, open Transfer Guards and press `t` to maintain this table
without editing YAML by hand. Asset set names may use lowercase ASCII letters,
digits, `_`, and `-`. Network rows must use concrete network context tokens,
not `*`, and each row must contain at least one ASA ID. When editing a guard's
`Asset` cell, use either `@stablecoins` or the bare set name `stablecoins`;
appolicy stores the route asset as `@stablecoins` in YAML and drops the `@` in
the generated route ID.

The default `usdc` set is:

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

In the `appolicy` Transfer Guards screen, amount fields use display units for
`algo`, concrete ASA IDs, and eligible asset sets. For ASAs, appolicy resolves
decimals from the signer-side ASA metadata cache or, for numeric ASA IDs, from
the configured algod endpoint when available. Cached symbols such as `USDC` are
accepted when they resolve to one ASA on the guard's single concrete network;
appolicy saves the numeric ASA ID back to YAML.

For asset-set rows, display-unit editing is available when every selected
concrete network resolves the set to exactly one ASA and all of those ASAs use
the same decimals. When the guard spans multiple networks, appolicy writes the
thresholds as uniform `limits_by_network` entries so the stored policy remains
valid even though ASA IDs are network-local. Asset-set rows that do not meet
those constraints are YAML-only.

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
IDs or different operational thresholds. `appolicy` can generate the uniform
case for eligible asset-set guard rows; use YAML for intentionally non-uniform
thresholds:

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

## Key Overrides

`key_overrides` can provide sparse routing policy for one concrete signing key.
Use an Algorand auth address as the override key:

```yaml
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  blocked_destinations:
    - BLOCKEDFORALL...
  address_sets:
    treasury:
      - TREASURY...
    ops:
      - OPS...
  routes:
    - id: default_treasury_route
      networks: [mainnet]
      sources: ["@treasury"]
      assets: ["algo"]
      destinations: ["@ops"]

key_overrides:
  SIGNINGAUTHADDRESS...:
    transfer_policy:
      schema_version: 1
      enabled: true
      blocked_destinations:
        - BLOCKEDFORFALCON...
      routes:
        - id: falcon_whitelist_asa_route
          networks: [mainnet]
          sources: ["@treasury"]
          assets: [31566704]
          destinations: ["@ops"]
```

Inheritance rules:

- `enabled` must be explicit in every `transfer_policy` block,
- unset scalar fields such as `on_no_route`, `close_on_no_route`, and
  `clawback_on_no_route` inherit,
- `blocked_destinations` inherit and are unioned; overrides may add blocked
  destinations but cannot remove identity-wide blocked destinations,
- `address_sets` and `asset_sets` inherit by name,
- override set names replace inherited set names with the same name,
- `routes`, when present in the override, replaces the inherited route list,
- `routes`, when absent, inherits the identity route list,
- nested `key_overrides` are rejected.

The effective override is selected by the auth address that will actually
sign, not necessarily by the transaction sender.

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

Legacy transfer guard rule IDs are preserved. For example, a
`max_algo_payments` rejection remains a legacy transfer-guard rejection rather
than being rewritten as a synthetic routing threshold.

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

### Policy Check Passes But The Signer Still Uses Old Behavior

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
- legacy `max_algo_payments` or `max_asa_amounts`,
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
- `reject_clawback:false` if the legacy clawback guard would otherwise reject.

### Unknown Genesis Hash

Routing resolves the transaction `GenesisHash` to a network token before route
matching. Built-in Algorand networks are known automatically. Custom and
localnet networks must be configured under signer `networks.<token>.genesis_hash`.

If the hash cannot be resolved, routing emits
`transfer_policy:unknown_genesis_hash` using the `on_no_route` tier:

- `reject` rejects,
- `review` forces review,
- `operator_default` produces no routing verdict.

### A Key Override Removed My Base Routes

If an override contains a `routes` field, that list replaces inherited routes
for that key. Omit `routes` to inherit the identity-wide route list.
