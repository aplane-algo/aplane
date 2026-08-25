# Signer Policy

Signer policy is the product-scoped safety layer that decides whether a
signing request should be rejected, forced through operator review, explicitly
approved, or left to the operator default.

Policy is stored beside the product keys in the product store:

```text
identities/default/policy.yaml
identities/default/policy.yaml.hmac
```

`policy.yaml` controls account signing on signer nodes and sentry component
signing on sentry nodes. Its `.hmac` sidecar authenticates the exact YAML
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
signer-domain `policy.yaml`, and sentry nodes edit sentry-domain
`policy.yaml`. It validates drafts with the running signer, applies changes as
whole-document replacements, writes the fresh sidecar, and activates the
resulting runtime policy immediately.

Use `apadmin policy` for a standalone guided or scriptable production client.
It connects through authenticated admin IPC (or SSH with the normal
`apadmin --remote` flag), selects the daemon's node role, unlocks the product
when required, and never needs filesystem access to the private signer store.

```bash
apadmin policy edit
apadmin policy check
apadmin policy export > selected-policy.yaml
apadmin policy apply - < selected-policy.yaml
apadmin policy edit draft-policy.yaml
apadmin policy rescue edit draft-policy.yaml
```

`apadmin policy` with no verb is the same as `apadmin policy edit`. A draft
passed to `edit` is validated through the daemon and uses the current live
snapshot as its optimistic-concurrency base. The `check`, `export`, `digest`,
`apply`, and `to-sentry` verbs are noninteractive batch operations. Every
online verb authenticates first; if the daemon is locked, even the read-only
`check`, `export`, and `digest` commands unlock it before reading policy state
and are therefore not guaranteed to preserve the daemon's lock state.

### Migration from the retired policy binary

The former `appolicy` binary is no longer installed. Replace its command shapes
as follows:

| Former command | Current command |
|---|---|
| `appolicy --online` | `apadmin policy edit` |
| `appolicy --online --check FILE` | `apadmin policy check FILE` |
| `appolicy --online --yaml FILE` | `apadmin policy export FILE` |
| `appolicy --online --sha256 FILE` | `apadmin policy digest FILE` |
| `appolicy --online --save` | `apadmin policy apply -` |
| `appolicy FILE` | `apadmin policy rescue edit FILE` |
| `appolicy --check FILE` | `apadmin policy rescue check FILE` |
| `appolicy --yaml FILE` | `apadmin policy rescue export FILE` |
| `appolicy --sha256 FILE` | `apadmin policy rescue digest FILE` |
| `appolicy --save` | `apadmin policy rescue apply -` |

There is no wrapper or automatic online-to-rescue fallback.

`apadmin policy rescue` is the stopped-service rescue command family. With
`--target auto` it reads `$APSIGNER_DATA/node.yaml`. On a systemd store, run
store-backed rescue as root only while `apsigner` is stopped. A positional
standalone draft does not read the signer store or sidecar.

Inside the online TUI, or rescue mode opened without a positional file, `a`
applies the current draft to production by writing the selected policy document
plus a fresh sidecar. In `apadmin policy rescue edit FILE`, `a` instead saves
only that standalone draft file; it does not update production policy, request
a store passphrase, or create a sidecar. The editor labels these two actions
differently. In either mode, `w` writes the current in-memory policy draft to a
separate YAML file. This is an export only and does not clear the modified
state.

When `apadmin policy rescue` opens production policy from `APSIGNER_DATA` or
`-d`, it needs the store passphrase to verify the sidecar. When it opens a
standalone YAML file, it validates and saves that file without unlocking the
store. To publish a standalone draft later, run `apadmin policy rescue apply
FILE` explicitly while the signer is stopped.

For byte-preserving offline rescue edits:

```bash
apadmin -d "$APSIGNER_DATA" policy rescue export > selected-policy.yaml
APSIGNER_PASSPHRASE="$passphrase" apadmin -d "$APSIGNER_DATA" policy rescue apply - < selected-policy.yaml
```

`apadmin policy rescue digest` verifies the current sidecar and prints the
SHA-256 digest of the trusted selected document bytes.
`apadmin policy rescue export` verifies the current sidecar and emits those
trusted bytes. `apadmin policy rescue apply -` reads replacement YAML
from stdin, validates it in the selected policy domain, writes the selected
document, and writes a fresh sidecar. Use `--target signer` or
`--target sentry` to override auto-selection. Because stdin is the document
stream for `apply -`, provide its passphrase through the local-only environment
source or an interactive terminal.

`APSIGNER_PASSPHRASE` is accepted only for explicit local IPC and rescue policy
commands. Remote policy commands ignore it so an ambient secret for a local
signer cannot be offered silently to another host. A local or remote command
whose policy comes from the active document or a named file may read one
passphrase line from nonterminal stdin. For example, scripted remote apply uses
a named policy file so stdin remains available for authentication:

```bash
printf '%s\n' "$remote_passphrase" | apadmin --remote policy apply selected-policy.yaml
```

Remote `apply -` reserves stdin for policy YAML and therefore requires a
controlling terminal for the passphrase. Without one, it fails before consuming
the YAML and directs the operator to the named-file form above.

With a positional YAML file, `apadmin policy rescue check draft.yaml`,
`apadmin policy rescue export draft.yaml`, and
`apadmin policy rescue digest draft.yaml` validate the file itself and do not
verify or update the production sidecar. Their non-rescue equivalents validate
through the running daemon; `apadmin policy edit draft.yaml` opens the
validated draft for online editing.

For deliberate direct YAML edits:

```bash
apstore -d "$APSIGNER_DATA" policy check
apstore -d "$APSIGNER_DATA" policy sign
apstore -d "$APSIGNER_DATA" policy verify
```

These direct commands are offline maintenance operations; stop `apsigner` and
use `sudo` for a systemd store. Normal production edits should use `apadmin` or
`apadmin policy edit`.

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
| `reject_foreign_rekey` | Signer-domain only. Reject txns whose non-zero `RekeyTo` target is not held by this signer product. Defaults to `true`. |
| `reject_rekey` | Sentry-domain only. Coarse deny-all switch for txns with non-zero `RekeyTo`. Defaults to `false`; missing `rekey_policy` still denies rekeys. |
| `rekey_policy` | Sentry-domain only. Allow-list for pure 0 ALGO self-payment rekeys by sender and target. YAML-only. |
| `reject_close_remainder` | Reject payment txns with non-zero `CloseRemainderTo`. Defaults to `false`. |
| `reject_asset_close` | Reject ASA transfer txns with non-zero `AssetCloseTo`. Defaults to `false`. |
| `reject_clawback` | Reject ASA clawback txns using `AssetSender`. Defaults to `false`. |
| `always_review_warnings` | Require operator review for warning-level findings. Defaults to `false`. |
| `auto_approve_self_noop_transfer` | Auto-approve exact low-risk 0-amount self-transfer shapes. Defaults to `false`. |
| `max_fee_microalgos` | Reject txns whose fee exceeds this raw microAlgo ceiling. Omitted or `0` means no ceiling. |
| `review_algo_payments` | Compatibility per-network raw microAlgo review thresholds for ALGO payments. |
| `max_algo_payments` | Compatibility per-network raw microAlgo reject thresholds for ALGO payments. |
| `review_asa_amounts` | Compatibility per-network raw ASA unit review thresholds. |
| `max_asa_amounts` | Compatibility per-network raw ASA unit reject thresholds. |
| `transfer_policy` | Source/asset/destination route table for direct ALGO and ASA movements. |
| `key_overrides` | Advanced per-key policy overlays. YAML-only. |

Use `transfer_policy` for route-based operator policy. The payment and ASA
threshold maps remain accepted compatibility fields.

Clawback controls are YAML-only in the guided policy editor. `reject_clawback`,
`transfer_policy.clawback_on_no_route`, and clawback routes using
`asset_sources` / `clawback.allow` remain valid in `policy.yaml`, but the
shared `apadmin` policy TUI does not expose controls to change them. Existing
YAML-authored clawback settings are preserved by unrelated guided edits.

Sentry rekey authorization is YAML-only. Set `reject_rekey: true` for a coarse
deny-all policy. To authorize a controlled rekey, omit `reject_rekey` or set it
to `false`, and add `rekey_policy.allowed` entries:

```yaml
rekey_policy:
  allowed:
    - sender: "SENDERADDR..."
      targets: ["TARGETADDR..."]
```

Each `sender` and `targets` item may be an Algorand address or a flat
`transfer_policy.address_sets` reference such as `@corridor_accounts`.
Network-specific address sets are not accepted for rekey policy. The target
transaction must be a pure 0 ALGO self-payment with non-zero `RekeyTo` and no
close remainder.

`rekey_policy` applies to dedicated `sentry1` guarded accounts. Corridor v1's
sentry is spend-only; its pure rekey instead requires the separate offline
contract-admin witness and does not contact the sentry.

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

## Guided Editor Guard Shape

The shared policy editor's Transfer Guards screen presents the common route shape as a
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
`usdc`; the editor stores the route asset as `@usdc` and uses `test_usdc` as the
route ID.
Field edits validate and save into the in-memory draft when the field editor
closes. Press `a` from the main policy screens to apply that draft to
production.

For `algo`, concrete ASA IDs, and eligible asset sets, amount fields in the TUI
use display units. Policy YAML stores raw on-chain units: microAlgos for ALGO
and raw ASA units for ASAs.

Advanced route shapes remain YAML-only, including multi-asset routes,
non-uniform `limits_by_network`, clawback `asset_sources` /
`clawback.allow`, and some wildcard or asset-set amount-limit combinations.

## Key Overrides

`key_overrides` is an advanced YAML-only feature. The guided editor does not
edit overrides.

Overrides let one concrete signing key use tighter or looser policy than the
product-wide policy. The override is selected by the auth address that will
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
| Scalar fields | Inherit product-wide value | Replace product-wide value |
| `transfer_policy.enabled` | Invalid if `transfer_policy` is present | Required explicit `true` or `false` |
| `transfer_policy.on_no_route` | Inherit product-wide value | Replace product-wide value |
| `transfer_policy.close_on_no_route` | Inherit product-wide value | Replace product-wide value |
| `transfer_policy.clawback_on_no_route` | Inherit product-wide value | Replace product-wide value |
| `transfer_policy.routes` | Inherit product-wide routes | Replace the entire route list |
| `transfer_policy.routes: []` | Not applicable | Clear all inherited routes for that key |
| `address_sets` and `asset_sets` | Inherit by name | Add new names or replace matching names |
| `blocked_destinations` | Inherit product-wide list | Add to the inherited list |
| Nested `key_overrides` | Not applicable | Rejected |

The sharp edge is inheritance. If an override omits `routes`, it still uses the
product-wide routes. If it sets `routes`, the listed routes are a replacement,
not an append. If it sets `routes: []` while inheriting `on_no_route: reject`,
then covered transfer movements for that key have no matching routes and
are rejected, except for routing-exempt self no-op shapes.

`blocked_destinations` can only become stricter in an override. An override can
add blocked destinations but cannot remove product-wide blocked destinations.

Use overrides when one key has materially different signing constraints, such
as a LogicSig account whose TEAL enforces a separate allowlist. Avoid overrides
when normal product-wide routes can express the rule; simpler policy is easier
to audit.

## Validation Checklist

Before relying on a policy:

1. Run `apadmin policy check` (or an offline rescue check while the daemon
   is stopped).
2. Confirm the route miss behavior is intentional, especially
   `on_no_route: reject`, `close_on_no_route: reject`, and
   `clawback_on_no_route: reject`.
3. Confirm address and asset set names resolve on the intended networks.
4. Confirm amount thresholds use raw units in YAML.
5. Sign the policy sidecar with `apadmin policy rescue apply -` or `apstore policy sign`.
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
