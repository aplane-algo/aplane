# Signer Policy

Signer policy is the product-scoped safety layer that decides whether a
signing request should be rejected, forced through operator review, explicitly
approved, or left to the operator default.

Policy is stored beside the product keys in the product store:

```text
identities/default/generations/<selected-generation>/policy.yaml
identities/default/generations/<selected-generation>/policy.yaml.hmac
```

`policy.yaml` controls account signing on signer nodes and cosigner component
signing on cosigner nodes. Its `.hmac` sidecar authenticates the exact YAML
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

Write or edit the policy file outside the node, review it with
`apadmin policy check FILE`, then install it with `apadmin policy apply FILE`.
While `apsigner` is stopped, use the `apadmin policy rescue` forms instead.

`apadmin policy` connects through authenticated local admin IPC, selects the
daemon's node role, unlocks the product when required, and never needs
filesystem access to the private signer store. Signer nodes target
signer-domain `policy.yaml`, and cosigner nodes target cosigner-domain
`policy.yaml`.

```bash
apadmin policy export > selected-policy.yaml
apadmin policy check selected-policy.yaml
apadmin policy apply selected-policy.yaml
apadmin policy digest
apadmin policy apply - < selected-policy.yaml
```

`apadmin policy` requires a verb: `check`, `export`, `digest`, `apply`, or
`to-cosigner`. All verbs are noninteractive. A file passed to online `check`
is validated through the running daemon. Online `apply` validates the file
with the running signer, uses the current live snapshot as its
optimistic-concurrency base, replaces the whole document, writes the fresh
sidecar, and activates the resulting runtime policy immediately. Every
online verb authenticates first; if the daemon is locked, even the read-only
`check`, `export`, and `digest` commands unlock it before reading policy state
and are therefore not guaranteed to preserve the daemon's lock state.

### Migration from the retired policy binary

The former `appolicy` binary is no longer installed. Replace its command shapes
as follows:

| Former command | Current command |
|---|---|
| `appolicy --online` | `apadmin policy export`, edit the file, then `apadmin policy check FILE` and `apadmin policy apply FILE` |
| `appolicy --online --check FILE` | `apadmin policy check FILE` |
| `appolicy --online --yaml FILE` | `apadmin policy export FILE` |
| `appolicy --online --sha256 FILE` | `apadmin policy digest FILE` |
| `appolicy --online --save` | `apadmin policy apply -` |
| `appolicy FILE` | `apadmin policy rescue check FILE`, then `apadmin policy rescue apply FILE` |
| `appolicy --check FILE` | `apadmin policy rescue check FILE` |
| `appolicy --yaml FILE` | `apadmin policy rescue export FILE` |
| `appolicy --sha256 FILE` | `apadmin policy rescue digest FILE` |
| `appolicy --save` | `apadmin policy rescue apply -` |

There is no wrapper or automatic online-to-rescue fallback.

`apadmin policy rescue` is the stopped-service rescue command family. With
`--target auto` it reads `$APSIGNER_DATA/node.yaml`. On a systemd store, run
store-backed rescue as root only while `apsigner` is stopped. A positional
standalone file passed to `check`, `export`, or `digest` does not read the
signer store or sidecar.

When `apadmin policy rescue` reads production policy from `APSIGNER_DATA` or
`-d`, it needs the store passphrase to verify the sidecar. To publish a
standalone file, run `apadmin policy rescue apply FILE` explicitly while the
signer is stopped.

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
`--target cosigner` to override auto-selection. Because stdin is the document
stream for `apply -`, provide its passphrase through the local-only environment
source or an interactive terminal.

`APSIGNER_PASSPHRASE` supplies the passphrase for local IPC and rescue policy
commands. A command whose policy comes from the active document or a named file
may also read one passphrase line from nonterminal stdin. `apply -` reserves
stdin for YAML and requires the environment passphrase or a controlling terminal.
For remote administration, SSH into the signer machine and run apadmin there;
all named paths then refer to that machine.

With a positional YAML file, `apadmin policy rescue check draft.yaml`,
`apadmin policy rescue export draft.yaml`, and
`apadmin policy rescue digest draft.yaml` validate the file itself and do not
verify or update the production sidecar. Their non-rescue equivalents validate
through the running daemon.

For deliberate direct YAML edits:

```bash
apstore -d "$APSIGNER_DATA" policy check
apstore -d "$APSIGNER_DATA" policy sign
apstore -d "$APSIGNER_DATA" policy verify
```

These direct commands are offline maintenance operations; stop `apsigner` and
use `sudo` for a systemd store. Normal production changes should use
`apadmin policy check` and `apadmin policy apply`.

Direct YAML edits take effect only after the next successful signer reload,
unlock, or restart. These are offline store mutations, so the normal workflow
is to run them while `apsigner` is stopped or before starting it.

Online `apadmin policy apply` is a whole-file replacement, not a merge. The
signer must be unlocked; it verifies the current sidecar for the selected
document, validates the submitted YAML with the signer runtime compiler, writes
the exact submitted bytes plus a fresh sidecar, and activates the resulting
policy immediately. The request includes the SHA-256 of the snapshot loaded at
the start of the apply, so the signer rejects the replacement if the active
policy changed before the upload was applied.

## Top-Level Fields

`policy.yaml` is sparse. Omitted fields resolve through product defaults.

| Field | Meaning |
|-------|---------|
| `reject_foreign_rekey` | Signer-domain only. Reject txns whose non-zero `RekeyTo` target is not held by this signer product. Defaults to `true`. |
| `reject_rekey` | Cosigner-domain only. Coarse deny-all switch for txns with non-zero `RekeyTo`. Defaults to `false`; missing `rekey_policy` still denies rekeys. |
| `rekey_policy` | Cosigner-domain only. Allow-list for pure 0 ALGO self-payment rekeys by sender and target. |
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
| `key_overrides` | Advanced per-key policy overlays. |

Use `transfer_policy` for route-based operator policy. The payment and ASA
threshold maps remain accepted compatibility fields.

For cosigner rekey authorization, set `reject_rekey: true` for a coarse
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

`rekey_policy` applies to dedicated `cosigner1` guarded accounts. Corridor v1's
cosigner is spend-only; its pure rekey instead requires the separate offline
contract-admin witness and does not contact the cosigner.

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

## Key Overrides

Overrides let one concrete signing key use tighter or looser settings than the
product-wide policy. The override is selected by the auth address that will
actually sign, not necessarily by the transaction sender.

Example:

```yaml
reject_foreign_rekey: true
reject_asset_close: false
max_fee_microalgos: 10000

key_overrides:
  SIGNINGAUTHADDRESS...:
    reject_asset_close: true

  OTHERAUTHADDRESS...:
    max_fee_microalgos: 5000
    review_algo_payments:
      mainnet: 50000000
```

Override rules:

| Field kind | If omitted in override | If present in override |
|------------|------------------------|------------------------|
| Scalar fields | Inherit product-wide value | Replace product-wide value |
| Per-network maps (`review_*`, `max_*`) | Inherit product-wide map | Replace the product-wide map |
| `transfer_policy` | Inherit product-wide routing | Rejected |
| `reject_rekey`, `rekey_policy` | Not applicable | Rejected (cosigner-only fields) |
| Nested `key_overrides` | Not applicable | Rejected |

Overrides never carry transfer routing. Express per-account routing in the
product-wide `transfer_policy` with route `sources`, for example a route whose
`sources` is `["@treasury"]`. Every key is then routed by the same, fully
validated route list.

Use overrides when one key has materially different signing settings, such as
a stricter fee cap. Avoid overrides when product-wide policy can express the
rule; simpler policy is easier to audit.

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
