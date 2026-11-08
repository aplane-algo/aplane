# Template Library

This directory contains LogicSig templates that users can import into a signer
keystore through `apadmin`.

Templates in this directory are plaintext install sources. Presence here does
not make a key type active by itself, and new signer stores install none of
them. After importing a template, unlock or reload `apsigner` before using the
new key type.

For an allowlist, timelock, or Corridor account, use a preset of
`aplane.falcon1024-b.v1`. It needs no import.

## Install

Generic LogicSig templates are TEAL-only accounts with no private key:

```bash
apadmin template import library/templates/aplane.htlc.v1.yaml
```

## Generic Templates

| Key type | File | Purpose | Creation params | Runtime args |
|---|---|---|---|---|
| `aplane.htlc.v1` | `aplane.htlc.v1.yaml` | Hash time-locked ALGO contract: recipient can claim the whole balance before timeout with a preimage; refund address can reclaim the whole balance after timeout. | `hash` (default input mode: preimage), `recipient`, `refund_address`, `timeout_round` | `preimage` |

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

The Merkle encoding of `aplane.falcon1024-b.v1` stores the public
recipient allowlist in the encrypted key file and commits the LogicSig TEAL to a
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
allowed without a proof. Corridor additionally requires its cosigner signature
on every spend.

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
`bounded2` envelope between base verification and Layer 3. That envelope admits
only declared pure payment, pure asset transfer, and asset opt-in paths, plus a
pure rekey when the template declares `rekey: spending_key`; it rejects close,
clawback, hybrids, and non-transfer types. A rekey is accepted or rejected
before Layer 3 runs. Layer 3 can narrow the spend paths but cannot broaden
them, and it never applies to a rekey. Runtime and signer-derived arguments
must be declared inside `bounded`, and the resulting static slot layout is
durable key metadata.

The composed wrap order is locked in by
`TestComposerVerifierAssertsBeforeUserSuffix` (in `lsig/composeddsa/`). Any
refactor that changes that wrap will fail it before a silent rekey-guard
regression can ship.

### Summary

| Template class | `txn RekeyTo == 0` | `CloseRemainderTo` policy |
|---|---|---|
| Generic (`template_type: generic`) | Required | Required (zero, or allowlisted per template semantics) |
| Custom composed (schema v1) | Author decision; all fields are signature-bound | Author decision |
| Bounded composed (schema v2) | Pure rekey only with `rekey: spending_key` | Always zero in `bounded2` |
