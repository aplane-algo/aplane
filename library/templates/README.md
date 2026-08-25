# Template Library

This directory contains LogicSig templates that users can import into a signer
keystore through `apadmin`.

Templates in this directory are plaintext install sources. Presence here does
not make a key type active by itself. New signer stores automatically install
and enable `aplane.falcon1024-allowlist.v1`; existing stores and the other
templates use the normal import flow. After importing a template, unlock or
reload `apsigner` before using the new key type.

## Install

Generic LogicSig templates are TEAL-only accounts with no private key:

```bash
apadmin template import library/templates/aplane.htlc.v1.yaml
```

Falcon-1024 composed templates combine a Falcon signature with additional TEAL checks:

```bash
apadmin template import library/templates/aplane.falcon1024-timelock.v1.yaml
apadmin template import library/templates/aplane.falcon1024-allowlist.v2.yaml
apadmin template import library/templates/aplane.corridor.v1.yaml
```

For existing stores that were initialized before this default was added:

```bash
apadmin template import library/templates/aplane.falcon1024-allowlist.v1.yaml
```

## Generic Templates

| Key type | File | Purpose | Creation params | Runtime args |
|---|---|---|---|---|
| `aplane.htlc.v1` | `aplane.htlc.v1.yaml` | Hash time-locked contract for ALGO or ASA transfers: recipient can claim before timeout with a preimage; refund address can reclaim after timeout; optional parameterized ASA opt-in is available for approved asset IDs only. | `hash` (default input mode: preimage), `recipient`, `refund_address`, `timeout_round`, `allowed_optin_assets` (`uint64[]`, optional) | `preimage` |

## Falcon-1024 Composed Templates

| Key type | File | Purpose | Creation params | Runtime args |
|---|---|---|---|---|
| `aplane.falcon1024-allowlist.v1` | `aplane.falcon1024-allowlist.v1.yaml` | Bounded1 Falcon spending with an inline recipient allowlist; close, clawback, hybrid effects, and non-transfer types reject. Pure rekey requires the spending key. | `recipients` (`address[]`, 1-30) | None |
| `aplane.falcon1024-allowlist.v2` | `aplane.falcon1024-allowlist.v2.yaml` | Bounded1 Falcon spending with a fixed-depth Merkle recipient allowlist. Pure rekey requires the spending key and no proof. | `recipients` (`address[]`, 1-65536) | None; signer generates the optional 512-byte spend proof |
| `aplane.falcon1024-allowlist-alock.v1` | `aplane.falcon1024-allowlist-alock.v1.yaml` | Framework-owned bounded1 ALGO/ASA allowlist with optional asset-ID and per-type amount limits; pure rekeys additionally require an external Falcon contract-admin signature. | `recipients` (`address[]`, 1-30), optional `asset_ids` (`uint64[]`, 1-30), optional `max_payment_amount`, optional `max_asset_amount`, framework-injected `bounded_admin_public_key` | None |
| `aplane.falcon1024-timelock.v1` | `aplane.falcon1024-timelock.v1.yaml` | Bounded1 Falcon spending and spending-key pure rekey, both requiring `FirstValid >= unlock_round`. | `unlock_round` | None |
| `aplane.corridor.v1` | `aplane.corridor.v1.yaml` | Bounded1 Falcon spending with a framework Merkle recipient allowlist and sentry authorization; pure rekey requires a separate external Falcon contract-admin witness. | `recipients` (`address[]`, 1-65536), framework-resolved `sentry_public_key`, framework-injected `bounded_admin_public_key` | None; signer generates the 512-byte spend proof and bounded assembly supplies the sentry slot |

## Notes

- `address[]` parameters are unordered by definition. Input order is
  canonicalized, so the same address set produces the same LogicSig address.
- `uint64[]` parameters are canonicalized numerically, so the same approved ASA
  set produces the same LogicSig address regardless of input order.
- Template key types are compatibility boundaries. Do not change the behavior of
  an installed key type in place; create a new versioned key type instead.
- `max_opcode_cost` is optional. Omission uses the numeric one-transaction
  opcode ceiling shared by every consensus version APlane currently supports:
  20,000. An explicit value is an absolute reviewed worst-case cost of the
  final compiled and auto-salted program across every permitted authorization
  path and runtime input; an explicit zero is rejected. APlane-owned library
  templates keep explicit reviewed declarations and maximum-input simulation
  vectors even when their ceiling equals the default.
- Imported templates are enabled in the product store and become available to
  its signer runtime.

### Merkle allowlist proof format

`aplane.falcon1024-allowlist.v2` and `aplane.corridor.v1` store the public
recipient allowlist in the encrypted key file and commit the LogicSig TEAL to a
fixed-depth 16 Merkle tree derived from that list:

1. Decode each allowlisted Algorand address to its 32-byte public key.
2. Reject duplicates, sort the unique public keys lexicographically ascending,
   and compute each real leaf as `sha256(0x00 || pubkey)`.
3. Pad the leaf list to 65,536 entries with the empty leaf `sha256(0x00)`.
4. Build 16 levels by pairing adjacent nodes. Each parent is
   `sha256(0x01 || min(left,right) || max(left,right))`, where `min` and `max`
   use lexicographic byte ordering.
5. For a non-self `pay` or `axfer`, the signer generates the 16 sibling hashes
   for the receiver address and appends them as a 512-byte LogicSig argument.

The caller does not supply this proof. Self transfers and ASA opt-ins are
allowed without a proof. Corridor additionally requires its sentry signature
on every spend; its external-admin rekey forbids both proof and sentry slots.

## Authoring rules: rekey and close-remainder

Templates fall into two classes with different obligations for blocking
`txn.RekeyTo` and `txn.CloseRemainderTo` (and the asset equivalents
`txn.AssetCloseTo` and `txn.AssetSender`).

**Generic templates** (`template_type: generic`, no `base_key_type`) authorize
transactions purely on TEAL predicates with no signature-over-txid binding.
A missing `RekeyTo` or `CloseRemainderTo` guard means an attacker who satisfies
the template's predicate (knows the hashlock preimage, hits the timelock
round, is on the allowlist) can also rekey the account away or drain it
via close-remainder. Generic templates therefore **MUST** include both
guards in their `teal:` block:

```text
txn RekeyTo
global ZeroAddress
==
assert

// for receiver-style templates such as htlc:
//   apply the allowlist to CloseRemainderTo / AssetCloseTo too;
// for predicate-only templates with no receiver concept:
//   txn CloseRemainderTo
//   global ZeroAddress
//   ==
//   assert
```

This applies to `aplane.htlc.v1` and any new generic template.

**Custom composed templates** (`schema_version: 1`) are expert-mode DSA
policies. The base signature binds every transaction field, but the author TEAL
must still reject any intentionally signed effect it does not want to permit.

**Bounded composed templates** (`schema_version: 2`) place the composer-owned
bounded1 envelope between base verification and Layer 3. That envelope admits
only declared pure payment, pure asset transfer, asset opt-in, and pure rekey
paths; it rejects close, clawback, hybrids, and non-transfer types. Layer 3 can
narrow those paths but cannot broaden them. All APlane-bundled composed
templates use this form. Runtime and signer-derived arguments must be declared
inside `bounded`, and the resulting static slot layout is durable key metadata.

The composed wrap order is locked in by
`TestComposerVerifierAssertsBeforeUserSuffix` (in `lsig/composeddsa/`) and
`TestBundledComposedTemplatesBindTxIDBeforeSuffix` (in `lsig/`). Any
refactor that changes that wrap will fail those tests before a silent
rekey-guard regression can ship.

### Summary

| Template class | `txn RekeyTo == 0` | `CloseRemainderTo` policy |
|---|---|---|
| Generic (`template_type: generic`) | Required | Required (zero, or allowlisted per template semantics) |
| Custom composed (schema v1) | Author decision; all fields are signature-bound | Author decision |
| Bounded composed (schema v2) | Pure rekey only when declared | Always zero in bounded1 |
