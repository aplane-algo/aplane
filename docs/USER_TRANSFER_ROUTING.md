# Transfer Routing

Transfer routing is a signer policy for direct ALGO and ASA transfers. It lets
an operator define which signer-controlled source accounts may send which
assets to which destinations, on which networks, and at what amount thresholds.
The policy document calls these entries `routes`.

This is the transfer-routing deep dive. For the broader signer policy model,
editing workflow, top-level fields, and key override overview, start with
[USER_POLICY.md](USER_POLICY.md). The document format itself is specified in
[ARCH_POLICY_FORMAT.md](ARCH_POLICY_FORMAT.md).

Routing is configured in the node's v1 JSON policy document. A signer node has
one document; a cosigner node has one document per cosigner key:

```text
identities/default/generations/<selected-generation>/policy.json
identities/default/generations/<selected-generation>/policies/<WitnessKeyID>.json
```

Write or edit routes in a policy file outside the node, run
`apadmin policy check FILE`, then `apadmin policy apply FILE` while `apsigner`
is running. `apadmin` applies changes as whole-document replacements through
the running signer; it does not merge independent route fragments. Every apply
commits a new store generation.

```bash
apadmin policy status
apadmin policy export > policy.json
apadmin policy check policy.json
apadmin policy apply policy.json
```

A successful policy apply affects new signing requests after the signer
publishes the replacement policy snapshot. Signing requests that are already in
flight, including requests waiting for operator approval, continue under the
policy snapshot they captured when they started.

Use the `apadmin policy rescue` forms when the signer is stopped:

```bash
apadmin -d "$APSIGNER_DATA" policy rescue status
apadmin -d "$APSIGNER_DATA" policy rescue export > policy.json
apadmin -d "$APSIGNER_DATA" policy rescue check policy.json
apadmin -d "$APSIGNER_DATA" policy rescue apply policy.json
apadmin -d "$APSIGNER_DATA" policy rescue apply - < policy.json
```

`apadmin policy rescue` reads the store directly, prompts for the store
passphrase, and follows the node role recorded in the store: a signer node
takes one `policy.json` document, and on a cosigner node each file names its
key in its `"key"` field. Local rescue automation may use
`APSIGNER_PASSPHRASE`; remote policy commands require the controlling
terminal. `status` lists the stored documents with their SHA-256 digests, and
`export` writes the trusted bytes of one document to stdout (`--key ID`
selects a cosigner key's document). `apply` reads a file (or stdin when the
source is `-`), checks it with the same rules as the running daemon, preserves
the submitted bytes, and commits the document plus a fresh sidecar as a new
generation; you do not need to run `apstore policy sign` afterward.

After hand-placing or editing a document in the selected generation while the
signer is stopped, check it, sign it, and then start the signer:

```bash
apstore -d "$APSIGNER_DATA" policy check
apstore -d "$APSIGNER_DATA" policy sign
apstore -d "$APSIGNER_DATA" policy verify
```

Hand edits take effect only after the next successful signer start, reload, or
unlock. `apstore policy sign` and `apadmin policy rescue apply` are offline
store mutations, so run them while `apsigner` is stopped.

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

```json
{
  "format": "aplane.signer-policy.v1",
  "address_sets": {
    "treasury": ["TREASURYADDRESS..."],
    "operations": ["OPERATIONSADDRESS..."]
  },
  "transfer_policy": {
    "enabled": true,
    "on_no_route": "review",
    "close_on_no_route": "reject",
    "clawback_on_no_route": "reject",
    "routes": [
      {
        "id": "treasury_to_operations",
        "description": "Treasury can transfer any asset to operations.",
        "networks": ["*"],
        "sources": ["@treasury"],
        "assets": ["*"],
        "destinations": ["@operations"]
      }
    ]
  }
}
```

With `"on_no_route": "review"`, transfer movements that match no route go to
the operator for approval. After reviewing audit output and adding any missing
routes, switch to `"on_no_route": "reject"` for production allowlist behavior.

Use `operator_default` only when route misses should behave as if routing did
not exist:

```json
"on_no_route": "operator_default"
```

That mode still applies matching route thresholds and explicit close/clawback
fallbacks. Close-out and clawback misses are controlled by
`close_on_no_route` and `clawback_on_no_route`, both of which default to
`reject`.

## Minimal Shape

```json
{
  "format": "aplane.signer-policy.v1",
  "transfer_policy": {
    "enabled": true,
    "on_no_route": "reject",
    "close_on_no_route": "reject",
    "clawback_on_no_route": "reject",
    "blocked_destinations": [],
    "routes": []
  }
}
```

`enabled` is required whenever `transfer_policy` is present. `"enabled": true`
turns routing on. With `"enabled": false`, routing sits out and non-routing
policy behavior is unchanged.

When routing is enabled, `on_no_route` is required.

## Schema Walkthrough

`transfer_policy` fields in a signer document:

| Field | Required | Meaning |
|-------|----------|---------|
| `enabled` | yes | Enables routing when `true`; disables routing when `false` |
| `on_no_route` | when enabled | Route-miss behavior: `reject`, `review`, or `operator_default` |
| `close_on_no_route` | no | Close-out route-miss behavior; defaults to `reject` |
| `clawback_on_no_route` | no | Clawback route-miss behavior; defaults to `reject` |
| `blocked_destinations` | no | Global concrete-address deny list checked before route matching |
| `routes` | no | Route definitions; order does not grant priority |

Named sets are top-level document fields, beside `transfer_policy`:

| Field | Required | Meaning |
|-------|----------|---------|
| `address_sets` | no | Named address lists or network-scoped address lists |
| `asset_sets` | no | Named network-scoped asset lists |

Route fields:

| Field | Required | Meaning |
|-------|----------|---------|
| `id` | yes | Stable lowercase identifier used in audit and policy rule IDs |
| `description` | no | Operator-facing note |
| `networks` | yes | Either `["*"]` or concrete network context tokens |
| `sources` | yes | Sender addresses, `@address_set` references, or `*` |
| `asset_sources` | clawback only | ASA `AssetSender` terms; requires `"allow_clawback": true` |
| `assets` | yes | `algo`, `asa:<id>`, `@asset_set`, or `*` |
| `destinations` | yes | Receiver addresses, `@address_set` references, `self`, or `*` |
| `limits` | no | Per-network, per-asset `review_above` / `reject_above` thresholds |
| `allow_close` | no | Allows matching close-out movements; defaults to `false` |
| `allow_clawback` | no | Allows matching ASA clawback movements; defaults to `false` |

To disable a route, remove it from the document.

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

```json
"close_on_no_route": "reject",
"clawback_on_no_route": "reject"
```

Both fields accept the same values as `on_no_route`. Their default is `reject`.
They apply only when no route matches. If a route matches but does not set
`"allow_close": true` or `"allow_clawback": true`, the movement is still
rejected.

## Blocked Destinations

`blocked_destinations` is an optional flat list of concrete Algorand addresses
that no covered signer-controlled movement may target.

```json
{
  "format": "aplane.signer-policy.v1",
  "transfer_policy": {
    "enabled": true,
    "on_no_route": "reject",
    "blocked_destinations": ["SANCTIONEDADDRESS...", "COMPROMISEDADDRESS..."],
    "routes": [
      {
        "id": "allow_all_except_blocked",
        "networks": ["*"],
        "sources": ["*"],
        "assets": ["*"],
        "destinations": ["*"]
      }
    ]
  }
}
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

Address sets define local aliases in the top-level `address_sets` field of the
policy document. They are not imported from the apshell address book.

A flat list applies on every network:

```json
"address_sets": {
  "payroll": ["PAYROLL1...", "PAYROLL2..."]
}
```

A network map applies only on named network context tokens:

```json
"address_sets": {
  "treasury": {
    "mainnet": ["MAINNETTREASURY..."],
    "testnet": ["TESTNETTREASURY..."]
  }
}
```

Routes reference address sets with `@name`:

```json
"sources": ["@treasury"],
"destinations": ["@payroll"]
```

Set names may use lowercase ASCII letters, digits, `_`, and `-`. A single
address set cannot mix flat and network-specific shapes. `*` is not a valid
network key inside an address set; use the flat-list shape when the same
addresses should apply on every network.

## Asset Sets

Asset sets group assets by network context token in the top-level
`asset_sets` field:

```json
"asset_sets": {
  "stablecoins": {
    "mainnet": ["asa:31566704"],
    "testnet": ["asa:10458941"]
  }
}
```

Routes reference asset sets with `@name`:

```json
"assets": ["@stablecoins"]
```

Asset terms:

| Term | Meaning |
|------|---------|
| `algo` | Native ALGO payment, measured in microAlgos |
| `asa:123456` | ASA ID 123456, measured in raw ASA units |
| `@stablecoins` | Asset set expanded for the transaction network |
| `*` | Any asset, including ALGO and ASAs |

Bare numeric ASA IDs are not accepted; write `asa:<id>`.

Asset IDs are network-local, so asset sets must use the network-map shape.
There is no flat-list asset-set shape.

Asset set names may use lowercase ASCII letters, digits, `_`, and `-`. Network
rows must use concrete network context tokens, not `*`, and each row must
contain at least one asset (`algo` or `asa:<id>`). Routes reference a set as
`@stablecoins`.

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

Amounts in the policy document are decimal strings in raw on-chain units:

- ALGO limits are microAlgos.
- ASA limits are raw ASA units.

JSON numbers are rejected; write `"250000000"`, not `250000000`.

Threshold comparison is strict greater-than:

```text
amount > threshold
```

For example, `"review_above": "250000000"` reviews ALGO payments above 250
ALGO, not exactly 250 ALGO.

Route `limits` are keyed by network, then by asset, so every threshold applies
to exactly one asset in its own units:

```json
{
  "id": "treasury_algo_vendors",
  "networks": ["mainnet"],
  "sources": ["@treasury"],
  "assets": ["algo"],
  "destinations": ["@vendors"],
  "limits": {
    "mainnet": {
      "algo": { "review_above": "250000000", "reject_above": "1000000000" }
    }
  }
}
```

If both `review_above` and `reject_above` are present, `reject_above` must be
greater than or equal to `review_above`. Deny is evaluated first, so equal
thresholds reject matching amounts above that value.

A route's `limits` may name only networks the route covers (any network when
`networks` is `["*"]`) and only assets the route covers on that network,
directly, through a referenced asset set, or through `*`. One route can carry
thresholds for several assets, and a route that spans networks with different
ASA IDs lists each network's asset under its own network key:

```json
{
  "id": "treasury_stablecoin_vendors",
  "networks": ["mainnet", "testnet"],
  "sources": ["@treasury"],
  "assets": ["@stablecoins"],
  "destinations": ["@vendors"],
  "limits": {
    "mainnet": {
      "asa:31566704": { "review_above": "100000000", "reject_above": "500000000" }
    },
    "testnet": {
      "asa:10458941": { "review_above": "50000000", "reject_above": "250000000" }
    }
  }
}
```

An asset the route covers but its `limits` does not mention has no route-level
threshold.

Document-level `limits` use the same shape at the top level of the document.
They are a separate check: a movement is rejected or sent to review if it
exceeds the document's threshold for its asset or the strictest threshold
among its matching routes.

## Close-Out And Clawback

By default, close-out movements are rejected by routing unless a matching route
explicitly sets `"allow_close": true`. If no route matches,
`close_on_no_route` controls the fallback and defaults to `reject`.

```json
{
  "id": "customer_asset_close_to_recovery",
  "networks": ["mainnet"],
  "sources": ["@customers"],
  "assets": ["asa:31566704"],
  "destinations": ["@recovery"],
  "allow_close": true
}
```

The `reject_close_remainder` and `reject_asset_close` guards still apply
independently. If either guard is enabled, it can reject even when a route
allows the close-out movement. `apadmin policy check` reports that overlap as a
warning: route permissions cannot weaken top-level reject guards.

By default, clawback movements are rejected unless a matching route explicitly
sets `"allow_clawback": true` and defines `asset_sources`. If no route
matches, `clawback_on_no_route` controls the fallback and defaults to
`reject`:

```json
{
  "id": "authority_clawback_to_recovery",
  "networks": ["mainnet"],
  "sources": ["@clawback_authorities"],
  "asset_sources": ["@customers"],
  "assets": ["asa:31566704"],
  "destinations": ["@recovery"],
  "allow_clawback": true
}
```

The `reject_clawback` guard still applies independently. If it is enabled,
`"allow_clawback": true` documents the route intent but cannot make the
clawback signable; `check` reports that overlap as a warning too.

`self` is not allowed in clawback `destinations` or `asset_sources` in v1.
`self` is ambiguous for clawback because the transaction sender is the clawback
authority, not the asset owner.

## Multiple Matching Routes

More than one route may match a movement. The evaluator combines matching
routes conservatively:

- at least one route must match for the movement to be route-permitted,
- the lowest present `reject_above` for the movement's asset among matching
  routes wins,
- the lowest present `review_above` for the movement's asset among matching
  routes wins,
- close-out is allowed only if at least one matching route has
  `"allow_close": true`,
- clawback is allowed only if at least one matching route has
  `"allow_clawback": true`.

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
8. If the movement is close-out and no matching route has
   `"allow_close": true`, reject.
9. If the movement is clawback and no matching route has
   `"allow_clawback": true`, reject.
10. If amount is known and the lowest matching `reject_above` threshold for
   the movement's asset is
   exceeded, reject.
11. If amount is known and the lowest matching `review_above` threshold for
   the movement's asset is
   exceeded, force review.
12. Otherwise routing produces no verdict and the request continues through the
   remaining policy phases.

With the default `"close_on_no_route": "reject"`, a close-out without an explicit
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

```json
{
  "format": "aplane.signer-policy.v1",
  "transfer_policy": {
    "enabled": true,
    "on_no_route": "reject",
    "routes": [
      {
        "id": "source_to_partner_or_self",
        "description": "Source may transfer only to partner or itself.",
        "networks": ["*"],
        "sources": ["SOURCEADDRESS..."],
        "assets": ["*"],
        "destinations": ["PARTNERADDRESS...", "self"]
      }
    ]
  }
}
```

With `"on_no_route": "reject"`, `SOURCEADDRESS...` cannot send to any other
destination. Other signer-controlled accounts also need routes, or their
direct transfers will miss and be rejected.

### Preserve Existing Keys During A Narrow Rollout

v1 has no negative source matching. If you want one source to be tightly
restricted while existing sources keep broad routing, enumerate the existing
sources in an address set:

```json
{
  "format": "aplane.signer-policy.v1",
  "address_sets": {
    "other_existing_keys": ["AAAAA...", "BBBBB...", "CCCCC..."]
  },
  "transfer_policy": {
    "enabled": true,
    "on_no_route": "reject",
    "routes": [
      {
        "id": "restricted_source",
        "networks": ["*"],
        "sources": ["SOURCEADDRESS..."],
        "assets": ["*"],
        "destinations": ["PARTNERADDRESS...", "self"]
      },
      {
        "id": "other_existing_keys_passthrough",
        "networks": ["*"],
        "sources": ["@other_existing_keys"],
        "assets": ["*"],
        "destinations": ["*"]
      }
    ]
  }
}
```

New keys added later are not automatically included in
`other_existing_keys`. Update and apply the policy when adding keys that should
retain broad routing.

### Treasury Pays Payroll In ALGO

```json
{
  "format": "aplane.signer-policy.v1",
  "address_sets": {
    "treasury": ["TREASURY..."],
    "payroll": ["PAYROLL1...", "PAYROLL2..."]
  },
  "transfer_policy": {
    "enabled": true,
    "on_no_route": "reject",
    "routes": [
      {
        "id": "treasury_algo_payroll",
        "networks": ["mainnet"],
        "sources": ["@treasury"],
        "assets": ["algo"],
        "destinations": ["@payroll"],
        "limits": {
          "mainnet": {
            "algo": { "review_above": "250000000", "reject_above": "1000000000" }
          }
        }
      }
    ]
  }
}
```

This reviews payroll payments above 250 ALGO and rejects payments above 1000
ALGO.

### Treasury Pays Vendors In A Specific ASA

```json
{
  "format": "aplane.signer-policy.v1",
  "address_sets": {
    "treasury": ["TREASURY..."],
    "vendors": ["VENDOR1...", "VENDOR2..."]
  },
  "transfer_policy": {
    "enabled": true,
    "on_no_route": "reject",
    "routes": [
      {
        "id": "treasury_usdc_vendors",
        "networks": ["mainnet"],
        "sources": ["@treasury"],
        "assets": ["asa:31566704"],
        "destinations": ["@vendors"],
        "limits": {
          "mainnet": {
            "asa:31566704": { "review_above": "100000000", "reject_above": "500000000" }
          }
        }
      }
    ]
  }
}
```

The ASA thresholds are raw asset units. For a 6-decimal asset, `"100000000"`
means 100 display units.

### Permit ASA Opt-In

Add an asset set and a route to `self` (shown as a fragment of the document):

```json
"asset_sets": {
  "stablecoins": {
    "mainnet": ["asa:31566704"]
  }
},
"transfer_policy": {
  "enabled": true,
  "on_no_route": "reject",
  "routes": [
    {
      "id": "treasury_stablecoin_optin",
      "networks": ["mainnet"],
      "sources": ["@treasury"],
      "assets": ["@stablecoins"],
      "destinations": ["self"]
    }
  ]
}
```

Without this route, an ASA opt-in can be a route miss when routing is enabled.

### Global "No One Can Send To X"

Use `blocked_destinations` for a small concrete list of recipients that should
always be denied, regardless of source or route.

```json
{
  "format": "aplane.signer-policy.v1",
  "transfer_policy": {
    "enabled": true,
    "on_no_route": "operator_default",
    "blocked_destinations": ["X...", "Y...", "Z..."]
  }
}
```

With `"on_no_route": "operator_default"`, ordinary route misses behave as if
routing had no opinion. Attempts to send to X, Y, or Z are still Always Deny.
Close-out and clawback misses still use `close_on_no_route` and
`clawback_on_no_route`.

## Per-Account Routing

Signer `key_overrides` cannot carry `transfer_policy`; a signer document that
puts routing inside an override is rejected. Express per-account routing in the
document's route list with route `sources`, typically through address sets:

```json
{
  "format": "aplane.signer-policy.v1",
  "address_sets": {
    "treasury": ["TREASURY..."],
    "ops": ["OPS..."]
  },
  "transfer_policy": {
    "enabled": true,
    "on_no_route": "reject",
    "routes": [
      {
        "id": "treasury_to_ops_algo",
        "networks": ["mainnet"],
        "sources": ["@treasury"],
        "assets": ["algo"],
        "destinations": ["@ops"]
      },
      {
        "id": "ops_usdc_payouts",
        "networks": ["mainnet"],
        "sources": ["@ops"],
        "assets": ["asa:31566704"],
        "destinations": ["*"],
        "limits": {
          "mainnet": {
            "asa:31566704": { "reject_above": "1000000000" }
          }
        }
      }
    ]
  }
}
```

Routes match on the transaction sender, so each account is governed by the
routes whose `sources` include it, and every route is validated against the
same sets it is evaluated with.

## Cosigner Documents

A cosigner node holds one self-contained document per cosigner key, in
`policies/<WitnessKeyID>.json`. Its `transfer_policy` has only
`blocked_destinations` and `routes`: there is no `enabled` switch and no
`on_no_route` family, because an unmatched movement, close-out, or clawback is
always rejected. Cosigner route and document `limits` accept only
`reject_above`. A cosigner key that has no document rejects every request.

```json
{
  "format": "aplane.cosigner-policy.v1",
  "key": "MYJZE3UF7G4JXR5STMQK5TSL5FNE7PE224BSKLZ2H4AJWJIPBEBQ",
  "address_sets": {
    "treasury": ["TREASURY..."],
    "exchange": ["EXCHANGE..."]
  },
  "transfer_policy": {
    "routes": [
      {
        "id": "treasury_to_exchange",
        "networks": ["mainnet"],
        "sources": ["@treasury"],
        "assets": ["algo"],
        "destinations": ["@exchange"],
        "limits": {
          "mainnet": {
            "algo": { "reject_above": "1000000000" }
          }
        }
      }
    ]
  }
}
```

The `key` field must equal the Witness Key ID the document is stored under.
On a cosigner node, `apadmin policy apply` takes one file per key and leaves
documents for other keys unchanged; `apadmin policy remove ID` deletes one
key's document.

## Validation Rules

`apadmin policy check` and `apply` reject an invalid document before anything
is written, and a stored document that fails its sidecar check or does not
decode makes the node refuse to load. Errors name the failing field as a JSON
Pointer, for example
`/transfer_policy/routes/1/limits/mainnet/asa:31566704/reject_above`.

Common validation failures:

- unknown fields at any level, duplicate object keys, or trailing data,
- a missing or wrong `format` for the node role,
- missing `enabled` under a present signer `transfer_policy`,
- missing `on_no_route` while routing is enabled,
- invalid `on_no_route`, `close_on_no_route`, or `clawback_on_no_route`,
- duplicate route IDs,
- route IDs that do not match `^[a-z0-9][a-z0-9_-]*$`,
- invalid Algorand addresses or checksums,
- `self`, `*`, or `@address_set` terms in `blocked_destinations`,
- invalid network tokens, including `*` as a network key in `address_sets`,
  `asset_sets`, or `limits`,
- bare numeric ASA IDs, or ASA IDs and amounts outside the uint64 range,
- amounts written as JSON numbers instead of decimal strings,
- mixed flat-and-network address-set shape in one address set,
- empty address sets or asset sets,
- unresolved `@address_set` or `@asset_set` references,
- `reject_above < review_above`,
- route `limits` naming a network or asset the route does not cover,
- `asset_sources` without `"allow_clawback": true`,
- `"allow_clawback": true` without `asset_sources`,
- `self` in clawback routes,
- `"allow_close": true` with wildcard destinations.

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

Document-level `limits` retain their own rule IDs. For example, an ALGO
payment above a document-level `reject_above` is reported as
`max_algo_payment_exceeded`, not as a synthetic routing threshold.

Blocked-destination denials do not enter the approval queue. Operators who need
active alerts for blocked attempts should alert on
`transfer_policy:blocked_destination` audit or log events.

## Troubleshooting

### `unknown field "default"`

Use `on_no_route`, not `default`:

```json
"transfer_policy": {
  "enabled": true,
  "on_no_route": "reject"
}
```

### `unknown field "on_route_miss"`

The field is `on_no_route`.

### Policy Check Passes But The Signer Uses Different Behavior

`apadmin policy check` only validates a file; run `apadmin policy apply` to
install it. For a document hand-placed in the store, run `apstore policy sign`
and then start the signer. A stored document without a matching HMAC sidecar
makes the node refuse to load.

### A Route-Permitted Transfer Still Rejects

Routing is only one policy layer. Check for:

- `blocked_destinations`,
- `reject_foreign_rekey`,
- `reject_close_remainder`,
- `reject_asset_close`,
- `reject_clawback`,
- `max_fee_microalgos`,
- document-level `limits`,
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

Close-out requires `"allow_close": true` on a matching route. The
`reject_close_remainder` and `reject_asset_close` guards can still reject
independently.

### Clawback Is Rejected Even Though A Route Matches

Clawback requires:

- `"allow_clawback": true`,
- an `asset_sources` list,
- matching `sources`, `asset_sources`, `assets`, and `destinations`,
- `"reject_clawback": false` when the independent clawback guard should not reject.

### Unknown Genesis Hash

Routing resolves the transaction `GenesisHash` to a network token before route
matching. Built-in Algorand networks are known automatically. Custom and
localnet networks must be configured under signer `networks.<token>.genesis_hash`.

If the hash cannot be resolved, routing emits
`transfer_policy:unknown_genesis_hash` using the `on_no_route` tier:

- `reject` rejects,
- `review` forces review,
- `operator_default` produces no routing verdict.

