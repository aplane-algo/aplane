# Signer Policy

Signer policy is the product-scoped safety layer that decides whether a
signing request should be rejected, forced through operator review, explicitly
approved, or left to the operator default.

Policy is a v1 JSON document stored beside the product keys in the selected
store generation. The node role decides which documents exist:

```text
# signer node: one document governs all signing
identities/default/generations/<selected-generation>/policy.json
identities/default/generations/<selected-generation>/policy.json.hmac

# cosigner node: one document per cosigner key
identities/default/generations/<selected-generation>/policies/<WitnessKeyID>.json
identities/default/generations/<selected-generation>/policies/<WitnessKeyID>.json.hmac
```

Each `.hmac` sidecar authenticates the exact document bytes. A missing or
mismatched sidecar, or a document that does not decode, makes the node refuse
to load rather than silently loading defaults.

A new signer store starts with the empty signer document
`{"format": "aplane.signer-policy.v1"}`, which applies product defaults. A new
cosigner store has no policy documents, so every cosigner key rejects every
request until its policy is applied. Deleting a cosigner key archives its
policy document with it.

The document format, field types, and acceptance rules are specified in
[ARCH_POLICY_FORMAT.md](ARCH_POLICY_FORMAT.md); the machine-readable schema is
[`pkg/policyschema/policy.v1.schema.json`](../pkg/policyschema/policy.v1.schema.json).

## What Policy Controls

Policy applies after request planning has identified the transactions this
signer controls. It is separate from:

- authentication and authorization, which decide who may ask for signing,
- key unlock state, which decides whether signing keys are usable,
- `user_auto_approve`, the operator default used only when policy has no
  stronger verdict,
- app-call inner transaction behavior, which is not inspected by transfer
  routing.

Policy verdicts are ordered conservatively:

```text
Always Deny > Always Review > Always Approve > Operator Default
```

This means a reject rule cannot be approved through an operator prompt, and a
review rule blocks both `user_auto_approve:true` and any matching auto-approval
rule.

## Editing Policy

Write or edit the policy file outside the node, review it with
`apadmin policy check FILE`, then install it with `apadmin policy apply FILE`.
While `apsigner` is stopped, use the `apadmin policy rescue` forms instead.

`apadmin policy` connects through authenticated local admin IPC, follows the
daemon's node role, unlocks the product when required, and never needs
filesystem access to the private signer store.

```bash
apadmin policy status
apadmin policy export > policy.json
apadmin policy check policy.json
apadmin policy apply policy.json
apadmin policy apply - < policy.json
```

`apadmin policy` requires a verb:

| Verb | Meaning |
|------|---------|
| `status` | List the node's policy documents with size, SHA-256, and applied time, the cosigner key coverage, and the `policy_set_sha256` of the whole set |
| `export [--key ID]` | Write one stored document to stdout exactly as stored; on a cosigner node, `--key` selects the Witness Key ID |
| `check FILE...` | Validate files against the node without writing; `-` reads one file from stdin |
| `diff FILE...` | Show how the files differ from the active policy, marking each change tightened, loosened, or changed |
| `apply FILE...` | Check, show the diff, ask for confirmation, then install the files in one commit; `-` reads one file from stdin |
| `remove ID...` | Show the diff, ask for confirmation, then delete cosigner keys' documents (cosigner nodes only) |

`apply` and `remove` ask "Apply these changes?" on the terminal. Pass `--yes`
to skip the question in scripts; without a terminal and without `--yes` they
refuse. Reformatting a file changes nothing, so applying it reports
`policy unchanged`. The other verbs are noninteractive. A signer node takes exactly one file. On a
cosigner node, each file is one key's document and names that key in its
`"key"` field; `apply` adds or replaces the listed keys' documents and leaves
documents for other keys unchanged.

`check` prints errors with the JSON Pointer of the failing field and prints
warnings that do not block an apply: cosigner keys the node holds that would
have no policy, documents for keys the node does not hold, and reject settings
that override a route's `allow_close` or `allow_clawback`.

`apply` runs `check` first, prints its warnings, and stops on errors. It then
applies the change against the `policy_set_sha256` it read at the start, so the
signer rejects the change if the active policy changed in the meantime. On
success the signer writes the exact submitted bytes plus fresh sidecars as a
new store generation and activates the resulting runtime policy immediately;
`apply` prints the new generation ID and `policy_set_sha256`. Each apply leaves
a retained generation until explicit generation pruning; see
[USER_STORE_MGMT.md](USER_STORE_MGMT.md).

Every online verb authenticates first; if the daemon is locked, even the
read-only `status`, `export`, and `check` commands unlock it before reading
policy state and are therefore not guaranteed to preserve the daemon's lock
state.

### Migration from the retired policy binary

The former `appolicy` binary is no longer installed. Replace its command shapes
as follows:

| Former command | Current command |
|---|---|
| `appolicy --online` | `apadmin policy export`, edit the file, then `apadmin policy check FILE` and `apadmin policy apply FILE` |
| `appolicy --online --check FILE` | `apadmin policy check FILE` |
| `appolicy --online --yaml FILE` | `apadmin policy export` |
| `appolicy --online --sha256 FILE` | `apadmin policy status` |
| `appolicy --online --save` | `apadmin policy apply -` |
| `appolicy FILE` | `apadmin policy rescue check FILE`, then `apadmin policy rescue apply FILE` |
| `appolicy --check FILE` | `apadmin policy rescue check FILE` |
| `appolicy --yaml FILE` | `apadmin policy rescue export` |
| `appolicy --sha256 FILE` | `apadmin policy rescue status` |
| `appolicy --save` | `apadmin policy rescue apply -` |

There is no wrapper or automatic online-to-rescue fallback.

`apadmin policy rescue` is the stopped-service rescue command family. It takes
the same verbs, reads the store named by `APSIGNER_DATA` or `-d` directly, and
follows the node role recorded in the store. Reads (`status`, `export`,
`check`) hold the shared store lock; `apply` and `remove` hold the exclusive
store lock and require a stopped daemon. Rescue applies use the same check and
commit rules as the daemon and also commit a new generation. On a systemd
store, run rescue as root only while `apsigner` is stopped.

Rescue commands need the store passphrase to verify the sidecars:

```bash
apadmin -d "$APSIGNER_DATA" policy rescue status
apadmin -d "$APSIGNER_DATA" policy rescue export > policy.json
APSIGNER_PASSPHRASE="$passphrase" apadmin -d "$APSIGNER_DATA" policy rescue apply - < policy.json
```

`APSIGNER_PASSPHRASE` supplies the passphrase for local IPC and rescue policy
commands. A command that reads its policy from a named file may also read one
passphrase line from nonterminal stdin. `check -` and `apply -` reserve stdin
for the document and require the environment passphrase or a controlling
terminal. For remote administration, SSH into the signer machine and run
apadmin there; all named paths then refer to that machine.

For documents placed or edited by hand in the selected generation:

```bash
apstore -d "$APSIGNER_DATA" policy check
apstore -d "$APSIGNER_DATA" policy sign
apstore -d "$APSIGNER_DATA" policy verify
```

`apstore policy check` validates the stored documents without verifying their
sidecars and warns about cosigner keys without policies and policies for keys
the node does not hold. `apstore policy sign` writes fresh sidecars for the
stored documents (`policy.json` on a signer node, every `policies/*.json` on a
cosigner node). `apstore policy verify` verifies every sidecar and compiles the
policy. These are offline maintenance operations; stop `apsigner` and use
`sudo` for a systemd store. Hand edits take effect only after the next
successful signer start, reload, or unlock. Normal production changes should
use `apadmin policy check` and `apadmin policy apply`.

## Top-Level Fields

Policy documents are sparse. Omitted fields resolve through product defaults.
Amounts are decimal strings in base units, and ASA IDs are written `asa:<id>`.

Signer document (`"format": "aplane.signer-policy.v1"`):

| Field | Meaning |
|-------|---------|
| `format` | Required document type. |
| `description` | Notes for reviewers. |
| `reject_foreign_rekey` | Reject txns whose non-zero `RekeyTo` target is not held by this signer product. Defaults to `true`. |
| `reject_close_remainder` | Reject payment txns with non-zero `CloseRemainderTo`. Defaults to `false`. |
| `reject_asset_close` | Reject ASA transfer txns with non-zero `AssetCloseTo`. Defaults to `false`. |
| `reject_clawback` | Reject ASA clawback txns using `AssetSender`. Defaults to `false`. |
| `always_review_warnings` | Require operator review for warning-level findings. Defaults to `false`. |
| `auto_approve_self_noop_transfer` | Auto-approve exact low-risk 0-amount self-transfer shapes. Defaults to `false`. |
| `max_fee_microalgos` | Reject txns whose fee exceeds this raw microAlgo ceiling. Omitted means no ceiling. |
| `limits` | Per-network, per-asset `review_above` / `reject_above` thresholds in base units. |
| `address_sets` | Named address sets for routes. |
| `asset_sets` | Named per-network asset sets for routes. |
| `transfer_policy` | Source/asset/destination route table for direct ALGO and ASA movements. |
| `key_overrides` | Advanced per-key settings keyed by signing auth address. |

Cosigner document (`"format": "aplane.cosigner-policy.v1"`), one per key:

| Field | Meaning |
|-------|---------|
| `format` | Required document type. |
| `key` | Required Witness Key ID this document governs; must equal the file name. |
| `description` | Notes for reviewers. |
| `reject_close_remainder`, `reject_asset_close`, `reject_clawback` | As for signer documents. |
| `reject_rekey` | Coarse deny-all switch for txns with non-zero `RekeyTo`. Defaults to `false`; missing `rekey_policy` still denies rekeys. |
| `max_fee_microalgos` | Reject txns whose fee exceeds this raw microAlgo ceiling. |
| `limits` | Per-network, per-asset `reject_above` thresholds only. |
| `address_sets`, `asset_sets` | Named sets, local to this document. |
| `transfer_policy` | Required allow-list: `blocked_destinations` and `routes`. |
| `rekey_policy` | Allow-list for pure 0 ALGO self-payment rekeys by sender and target. |

Cosigner policy never produces review verdicts: there is no `review_above`, no
`on_no_route` (an unmatched movement, close-out, or clawback is always
rejected), and no operator setting.

Limits are keyed by network, then by asset:

```json
"limits": {
  "mainnet": {
    "algo": { "review_above": "100000000", "reject_above": "1000000000" },
    "asa:31566704": { "reject_above": "5000000000" }
  }
}
```

Document-level and route-level limits are separate checks and both apply.

For cosigner rekey authorization, set `"reject_rekey": true` for a coarse
deny-all policy. To authorize a controlled rekey, omit `reject_rekey` or set it
to `false`, and add `rekey_policy.allowed` entries:

```json
"rekey_policy": {
  "allowed": [
    { "sender": "SENDERADDR...", "targets": ["TARGETADDR..."] }
  ]
}
```

Each `sender` and `targets` item may be an Algorand address or a reference to
a flat `address_sets` entry such as `@corridor_accounts`. Network-specific
address sets are not accepted for rekey policy. The target transaction must be
a pure 0 ALGO self-payment with non-zero `RekeyTo` and no close remainder.

`rekey_policy` applies to dedicated `cosigner1` guarded accounts. Corridor v1's
cosigner is spend-only; its pure rekey instead requires the separate offline
contract-admin witness and does not contact the cosigner.

## Basic Example

```json
{
  "format": "aplane.signer-policy.v1",
  "reject_foreign_rekey": true,
  "reject_close_remainder": true,
  "reject_asset_close": false,
  "reject_clawback": false,
  "always_review_warnings": true,
  "auto_approve_self_noop_transfer": false,
  "max_fee_microalgos": "1000000"
}
```

This rejects foreign rekeys and ALGO close-outs, forces review for warning-level
findings, and rejects any transaction fee above 1 ALGO.

## Transfer Routing

`transfer_policy` is the route table for direct signer-controlled ALGO and ASA
movements. It can constrain:

- source account,
- asset,
- destination,
- network,
- amount thresholds,
- close-out and clawback behavior.

A matching route means the movement may continue through the remaining policy
pipeline. It is not an approval. Routing can reject a movement or force review,
but it never auto-approves signing.

Minimal signer shape:

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

`on_no_route` controls in-scope transfer movements that match no route:

| Value | Meaning |
|-------|---------|
| `reject` | Route misses are rejected. This is the allowlist mode. |
| `review` | Route misses require operator review. This is useful during rollout. |
| `operator_default` | Route misses produce no routing verdict. |

`close_on_no_route` and `clawback_on_no_route` accept the same values, but
default to `reject`. They make the stricter close-out and clawback fallback
explicit. They apply only when no route matches; a matching route that lacks
`"allow_close": true` or `"allow_clawback": true` still rejects.

`blocked_destinations` is checked before route matching, so a wildcard route
cannot rescue a blocked recipient.

For detailed route fields, movement extraction, amount unit rules, close-out
and clawback behavior, grouped transactions, cosigner documents, and routing
audit IDs, see [USER_TRANSFER_ROUTING.md](USER_TRANSFER_ROUTING.md).

## Common Allowlist Example

This pattern allows all direct ALGO and ASA transfers to two approved
recipients and denies direct transfers to all other recipients:

```json
{
  "format": "aplane.signer-policy.v1",
  "transfer_policy": {
    "enabled": true,
    "on_no_route": "reject",
    "close_on_no_route": "reject",
    "clawback_on_no_route": "reject",
    "routes": [
      {
        "id": "approved_recipients_all_assets",
        "description": "Allow all assets to approved recipients.",
        "networks": ["*"],
        "sources": ["*"],
        "assets": ["*"],
        "destinations": ["APPROVEDADDRESS1...", "APPROVEDADDRESS2..."]
      }
    ]
  }
}
```

With `"on_no_route": "reject"`, any covered transfer movement that does not
match the route is rejected. Non-transfer policy layers still apply
independently.

The cosigner equivalent is one document per key, with `transfer_policy`
holding only `routes` and `blocked_destinations`:

```json
{
  "format": "aplane.cosigner-policy.v1",
  "key": "MYJZE3UF7G4JXR5STMQK5TSL5FNE7PE224BSKLZ2H4AJWJIPBEBQ",
  "transfer_policy": {
    "routes": [
      {
        "id": "approved_recipients_all_assets",
        "networks": ["*"],
        "sources": ["*"],
        "assets": ["*"],
        "destinations": ["APPROVEDADDRESS1...", "APPROVEDADDRESS2..."]
      }
    ]
  }
}
```

## Key Overrides

Signer documents may carry `key_overrides`, which let one concrete signing key
use tighter or looser settings than the rest of the document. The override is
selected by the auth address that will actually sign, not necessarily by the
transaction sender. Cosigner documents have no overrides; each key already has
its own document.

Example:

```json
{
  "format": "aplane.signer-policy.v1",
  "reject_foreign_rekey": true,
  "reject_asset_close": false,
  "max_fee_microalgos": "10000",
  "limits": {
    "mainnet": {
      "algo": { "reject_above": "1000000000" }
    }
  },
  "key_overrides": {
    "SIGNINGAUTHADDRESS...": {
      "reject_asset_close": true
    },
    "OTHERAUTHADDRESS...": {
      "max_fee_microalgos": "5000",
      "limits": {
        "mainnet": {
          "algo": { "review_above": "50000000" }
        }
      }
    }
  }
}
```

Override rules:

| Field kind | If omitted in override | If present in override |
|------------|------------------------|------------------------|
| Scalar fields | Inherit the document value | Replace the document value |
| `limits` thresholds | Inherit each `(network, asset, threshold)` | Replace exactly that threshold; `null` removes it |
| `transfer_policy`, `address_sets`, `asset_sets` | Inherit document routing | Rejected |
| `key_overrides` | Not applicable | Rejected |

In the example, `OTHERAUTHADDRESS...` adds a 50 ALGO review threshold on
mainnet and keeps the document's 1000 ALGO reject cap. Validation runs on each
key's merged result, so its effective `review_above` must not exceed its
effective `reject_above`.

Overrides never carry transfer routing. Express per-account routing in the
document's `transfer_policy` with route `sources`, for example a route whose
`sources` is `["@treasury"]`. Every key is then routed by the same, fully
validated route list.

Use overrides when one key has materially different signing settings, such as
a stricter fee cap. Avoid overrides when the document-wide settings can express
the rule; simpler policy is easier to audit.

## Validation Checklist

Before relying on a policy:

1. Run `apadmin policy check FILE` (or `apadmin policy rescue check FILE`
   while the daemon is stopped) and read its warnings.
2. Confirm the route miss behavior is intentional, especially
   `"on_no_route": "reject"`, `"close_on_no_route": "reject"`, and
   `"clawback_on_no_route": "reject"`.
3. Confirm address and asset set names resolve on the intended networks.
4. Confirm amounts are decimal strings in raw base units.
5. On a cosigner node, confirm `apadmin policy status` shows every held key as
   `active`; a key with no policy rejects every request.
6. Install the policy with `apadmin policy apply FILE`, which signs the
   sidecar and activates the policy. For hand-placed documents, run
   `apstore policy sign` and start the signer.

## Troubleshooting

| Symptom | Likely cause |
|---------|--------------|
| Edited policy has no effect | The file was checked but not applied, or a hand-placed document was signed while the signer was running and it has not restarted since. |
| Signer refuses to load policy | A sidecar is missing or does not match its document, or a document does not decode. |
| `apply` fails with `policy_snapshot_changed` | The active policy changed after `apply` read it; check the current state with `apadmin policy status` and apply again. |
| A cosigner request is rejected with `cosigner_policy:key_has_no_policy` | The cosigner key has no policy document; apply one for that Witness Key ID. |
| A transfer is rejected unexpectedly | `"on_no_route": "reject"`, a blocked destination, close/clawback denial, or a stricter matching route threshold. |
| A route does not match an ASA | ASA IDs are network-local; check the transaction network and any `asset_sets` mapping. |
| A key override cannot change routing | Overrides carry only scalar settings and `limits`; express per-account routing with route `sources`. |

For implementation-level details, see [ARCH_POLICY.md](ARCH_POLICY.md). For
network token rules, see [ARCH_NETWORKS.md](ARCH_NETWORKS.md).
