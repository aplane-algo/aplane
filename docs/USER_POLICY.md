# Signer Policy

Signer policy is the identity-scoped safety layer that decides whether a
signing request should be rejected, forced through operator review, explicitly
approved, or left to the operator default.

Policy is stored beside the identity keys:

```text
identities/<identity>/policy.yaml
identities/<identity>/policy.yaml.hmac
```

`policy.yaml` controls account signing on signer nodes and attestor component
signing on attestor nodes. Its `.hmac` sidecar authenticates the exact YAML
bytes. After the signed baseline exists, a missing or mismatched sidecar fails
closed rather than silently loading defaults.

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

Use `apadmin` for online guided policy edits while `apsigner` is running. From
the main key list, press `p`, or open Settings and choose `Policy`. `apadmin`
targets the node-role policy domain automatically: signer nodes edit
signer-domain `policy.yaml`, and attestor nodes edit attestor-domain
`policy.yaml`. It validates drafts with the running signer, applies changes as
whole-document replacements, writes the fresh sidecar, and activates the
resulting runtime policy immediately.

Use `appolicy` for offline or scriptable policy work. With `--target auto` (the
default), `appolicy` reads `$APSIGNER_DATA/node.yaml`: signer nodes edit
signer-domain `policy.yaml`, and attestor nodes edit attestor-domain
`policy.yaml`.

```bash
appolicy -d "$APSIGNER_DATA"
appolicy -d "$APSIGNER_DATA" -check
appolicy -d "$APSIGNER_DATA" --sha256
appolicy -d "$APSIGNER_DATA" --target signer
appolicy -d "$APSIGNER_DATA" --target attestation
appolicy draft-policy.yaml
```

Inside the TUI, `a` applies the current draft to production by writing
the selected policy document plus a fresh sidecar. `w` writes the current
in-memory policy draft to a YAML file you choose. This is an export only: it
does not update production policy, does not write a sidecar, and does not clear
the modified state.

When `appolicy` opens production policy from `APSIGNER_DATA` or `-d`, it needs
the store passphrase to verify the sidecar. When it opens a standalone YAML
file, it validates that file without unlocking the store. If that file-backed
draft is later applied to production with `a`, `appolicy` asks for the store
passphrase at apply time.

For byte-preserving scripted edits:

```bash
appolicy -d "$APSIGNER_DATA" --yaml > selected-policy.yaml
APPOLICY_PASSPHRASE="$passphrase" appolicy -d "$APSIGNER_DATA" --save < selected-policy.yaml
```

`appolicy --sha256` verifies the current sidecar and prints the SHA-256 digest
of the trusted selected document bytes. `appolicy --yaml` verifies the current
sidecar and emits those trusted bytes. `appolicy --save` reads replacement YAML
from stdin, validates it in the selected policy domain, writes the selected
document, and writes a fresh sidecar. Use `--target signer` or
`--target attestation` to override auto-selection. Because stdin is the
document stream for save modes, provide the passphrase through the environment
or an interactive terminal.

With a positional YAML file, `appolicy --check draft.yaml`,
`appolicy --yaml draft.yaml`, and `appolicy --sha256 draft.yaml` validate the
file itself and do not verify or update the production sidecar.

For deliberate direct YAML edits:

```bash
apstore -d "$APSIGNER_DATA" policy check
apstore -d "$APSIGNER_DATA" policy sign
apstore -d "$APSIGNER_DATA" policy verify
```

Direct YAML edits take effect only after the next successful signer reload,
unlock, or restart. These are offline store mutations, so the normal workflow
is to run them while `apsigner` is stopped or before starting it.

The `apadmin` editor shows the policy currently loaded by `apsigner`. Applying
from the editor is a whole-file replacement, not a merge. The signer must be
unlocked; it verifies the current sidecar for the selected document, validates
the submitted YAML with the signer runtime compiler, writes the exact submitted
bytes plus a fresh sidecar, and activates the resulting policy immediately. The
request includes the SHA-256 of the snapshot you were editing, so the signer
rejects the replacement if the active policy changed before the upload was
applied.

## Top-Level Fields

`policy.yaml` is sparse. Omitted fields resolve through product defaults.

| Field | Meaning |
|-------|---------|
| `reject_foreign_rekey` | Reject txns whose non-zero `RekeyTo` target is not held by this signer identity. Defaults to `true`. |
| `reject_close_remainder` | Reject payment txns with non-zero `CloseRemainderTo`. Defaults to `false`. |
| `reject_asset_close` | Reject ASA transfer txns with non-zero `AssetCloseTo`. Defaults to `false`. |
| `reject_clawback` | Reject ASA clawback txns using `AssetSender`. Defaults to `false`. |
| `always_review_warnings` | Require operator review for warning-level findings. Defaults to `false`. |
| `auto_approve_self_noop_transfer` | Auto-approve exact low-risk 0-amount self-transfer shapes. Defaults to `false`. |
| `max_fee_microalgos` | Reject txns whose fee exceeds this raw microAlgo ceiling. Omitted or `0` means no ceiling. |
| `review_algo_payments` | Legacy per-network raw microAlgo review thresholds for ALGO payments. |
| `max_algo_payments` | Legacy per-network raw microAlgo reject thresholds for ALGO payments. |
| `review_asa_amounts` | Legacy per-network raw ASA unit review thresholds. |
| `max_asa_amounts` | Legacy per-network raw ASA unit reject thresholds. |
| `transfer_policy` | Source/asset/destination route table for direct ALGO and ASA movements. |
| `key_overrides` | Advanced per-key policy overlays. YAML-only. |

New operator-facing transfer policy should prefer `transfer_policy` over the
legacy payment and ASA threshold maps.

## Basic Example

```yaml
reject_foreign_rekey: true
reject_close_remainder: true
reject_asset_close: false
reject_clawback: false
always_review_warnings: true
auto_approve_self_noop_transfer: false
max_fee_microalgos: 1000000
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

Minimal shape:

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

`on_no_route` controls in-scope transfer movements that match no route:

| Value | Meaning |
|-------|---------|
| `reject` | Route misses are rejected. This is the allowlist mode. |
| `review` | Route misses require operator review. This is useful during rollout. |
| `operator_default` | Route misses produce no routing verdict. |

`close_on_no_route` and `clawback_on_no_route` accept the same values, but
default to `reject`. They make the stricter close-out and clawback fallback
explicit. They apply only when no route matches; a matching route that lacks
`close.allow:true` or `clawback.allow:true` still rejects.

`blocked_destinations` is checked before route matching, so a wildcard route
cannot rescue a blocked recipient.

For detailed route fields, movement extraction, amount unit rules, close-out
and clawback behavior, grouped transactions, and routing audit IDs, see
[USER_TRANSFER_ROUTING.md](USER_TRANSFER_ROUTING.md).

## Common Allowlist Example

This pattern allows all direct ALGO and ASA transfers to two approved
recipients and denies direct transfers to all other recipients:

```yaml
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  close_on_no_route: reject
  clawback_on_no_route: reject

  routes:
    - id: approved_recipients_all_assets
      description: Allow all assets to approved recipients.
      networks: ["*"]
      sources: ["*"]
      assets: ["*"]
      destinations:
        - APPROVEDADDRESS1...
        - APPROVEDADDRESS2...
      close:
        allow: false
```

With `on_no_route: reject`, any covered transfer movement that does not match
the route is rejected. Non-transfer policy layers still apply independently.

## Appolicy Guard Shape

The `appolicy` Transfer Guards screen presents the common route shape as a
guard with guard-level fields and an asset table.

Guard-level fields include:

- `Name`,
- `Description`,
- `Networks`,
- `Sources`,
- `Destinations`,
- `Enabled`,
- `Close Allow`.

Each asset row becomes one stored route in the selected policy document. The
TUI derives the route ID as `<guard>_<asset>`, for example `test_algo` and
`test_usdc` for a guard named `test`. Asset-set rows accept either `@usdc` or
`usdc`; appolicy stores the route asset as `@usdc` and uses `test_usdc` as the
route ID.
Field edits validate and save into the in-memory draft when the field editor
closes. Press `a` from the main policy screens to apply that draft to
production.

For `algo`, concrete ASA IDs, and eligible asset sets, amount fields in the TUI
use display units. Policy YAML stores raw on-chain units: microAlgos for ALGO
and raw ASA units for ASAs.

Advanced route shapes remain YAML-only, including multi-asset routes,
non-uniform `limits_by_network`, clawback `asset_sources`, and some wildcard or
asset-set amount-limit combinations.

## Key Overrides

`key_overrides` is an advanced YAML-only feature. The appolicy UI does not
edit overrides.

Overrides let one concrete signing key use tighter or looser policy than the
identity-wide policy. The override is selected by the auth address that will
actually sign, not necessarily by the transaction sender.

Example:

```yaml
reject_foreign_rekey: true
reject_asset_close: false

transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  routes:
    - id: base_algo_ops
      networks: [mainnet]
      sources: ["*"]
      assets: ["algo"]
      destinations: ["OPSADDRESS..."]

key_overrides:
  SIGNINGAUTHADDRESS...:
    reject_asset_close: true

  OTHERAUTHADDRESS...:
    max_fee_microalgos: 5000
    transfer_policy:
      schema_version: 1
      enabled: true
      routes:
        - id: falcon_usdc_ops
          networks: [mainnet]
          sources: ["*"]
          assets: [31566704]
          destinations: ["OPSADDRESS..."]
```

Override rules:

| Field kind | If omitted in override | If present in override |
|------------|------------------------|------------------------|
| Scalar fields | Inherit identity-wide value | Replace identity-wide value |
| `transfer_policy.enabled` | Invalid if `transfer_policy` is present | Required explicit `true` or `false` |
| `transfer_policy.on_no_route` | Inherit identity-wide value | Replace identity-wide value |
| `transfer_policy.close_on_no_route` | Inherit identity-wide value | Replace identity-wide value |
| `transfer_policy.clawback_on_no_route` | Inherit identity-wide value | Replace identity-wide value |
| `transfer_policy.routes` | Inherit identity-wide routes | Replace the entire route list |
| `transfer_policy.routes: []` | Not applicable | Clear all inherited routes for that key |
| `address_sets` and `asset_sets` | Inherit by name | Add new names or replace matching names |
| `blocked_destinations` | Inherit identity-wide list | Add to the inherited list |
| Nested `key_overrides` | Not applicable | Rejected |

The sharp edge is inheritance. If an override omits `routes`, it still uses the
identity-wide routes. If it sets `routes`, the listed routes are a replacement,
not an append. If it sets `routes: []` while inheriting `on_no_route: reject`,
then covered transfer movements for that key have no matching routes and
are rejected, except for routing-exempt self no-op shapes.

`blocked_destinations` can only become stricter in an override. An override can
add blocked destinations but cannot remove identity-wide blocked destinations.

Use overrides when one key has materially different signing constraints, such
as a LogicSig account whose TEAL enforces a separate whitelist. Avoid overrides
when normal identity-wide routes can express the rule; simpler policy is easier
to audit.

## Validation Checklist

Before relying on a policy:

1. Run `appolicy -d "$APSIGNER_DATA" -check` or
   `apstore -d "$APSIGNER_DATA" policy check`.
2. Confirm the route miss behavior is intentional, especially
   `on_no_route: reject`, `close_on_no_route: reject`, and
   `clawback_on_no_route: reject`.
3. Confirm address and asset set names resolve on the intended networks.
4. Confirm amount thresholds use raw units in YAML.
5. Sign the policy sidecar with `appolicy --save` or `apstore policy sign`.
6. Reload, unlock, or restart the signer so the new verified policy is active.

## Troubleshooting

| Symptom | Likely cause |
|---------|--------------|
| Edited policy has no effect | The running signer has not reloaded, unlocked, or restarted since the edit. |
| Signer refuses to load policy | The sidecar is missing or does not match `policy.yaml`, or validation failed. |
| A transfer is rejected unexpectedly | `on_no_route: reject`, a blocked destination, close/clawback denial, or a stricter matching route threshold. |
| A route does not match an ASA | ASA IDs are network-local; check the transaction network and any `asset_sets` mapping. |
| A key override still uses base routes | The override omitted `transfer_policy.routes`; omitted routes inherit. |
| A key override cannot unblock an address | `blocked_destinations` are inherited and unioned. Overrides cannot remove base blocked destinations. |

For implementation-level details, see [ARCH_POLICY.md](ARCH_POLICY.md). For
network token rules, see [ARCH_NETWORKS.md](ARCH_NETWORKS.md).
