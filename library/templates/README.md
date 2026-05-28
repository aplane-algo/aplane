# Template Library

This directory contains optional LogicSig templates that users can import into a
signer keystore with `apstore`.

Templates in this directory are not built into APlane and are not active by
default. After importing a template, unlock or reload `apsigner` before using
the new key type.

## Install

Generic LogicSig templates are TEAL-only accounts with no private key:

```bash
apstore template import library/templates/aplane.timelock.v1.yaml
apstore template import library/templates/aplane.whitelist.v1.yaml
apstore template import library/templates/aplane.htlc.v1.yaml
```

Falcon-1024 composed templates combine a Falcon signature with additional TEAL checks:

```bash
apstore template import library/templates/aplane.falcon1024-whitelist.v1.yaml
apstore template import library/templates/aplane.falcon1024-hashlock.v1.yaml
apstore template import library/templates/aplane.falcon1024-timelock.v1.yaml
```

## Generic Templates

| Key type | File | Purpose | Creation params | Runtime args |
|---|---|---|---|---|
| `aplane.timelock.v1` | `aplane.timelock.v1.yaml` | Allows ALGO or ASA transfers to one recipient after `unlock_round`; optional parameterized ASA opt-in is available for approved asset IDs only. | `recipient`, `unlock_round`, `allowed_optin_assets` (`uint64[]`, optional) | None |
| `aplane.whitelist.v1` | `aplane.whitelist.v1.yaml` | Allows ALGO or ASA transfers only to a fixed unordered recipient address set; optional parameterized ASA opt-in is available for approved asset IDs only. | `recipients` (`address[]`), `allowed_optin_assets` (`uint64[]`, optional) | None |
| `aplane.htlc.v1` | `aplane.htlc.v1.yaml` | Hash time-locked contract for ALGO or ASA transfers: recipient can claim before timeout with a preimage; refund address can reclaim after timeout; optional parameterized ASA opt-in is available for approved asset IDs only. | `hash`, `recipient`, `refund_address`, `timeout_round`, `allowed_optin_assets` (`uint64[]`, optional) | `preimage` |

## Falcon-1024 Composed Templates

| Key type | File | Purpose | Creation params | Runtime args |
|---|---|---|---|---|
| `aplane.falcon1024-whitelist.v1` | `aplane.falcon1024-whitelist.v1.yaml` | Requires a Falcon signature and restricts ALGO/ASA transfer destination fields to a fixed unordered recipient address set or the sender itself; non-transfer transaction types keep the base Falcon authorization surface. | `recipients` (`address[]`) | None |
| `aplane.falcon1024-hashlock.v1` | `aplane.falcon1024-hashlock.v1.yaml` | Requires a Falcon signature plus a SHA256 preimage check. | `hash` | `preimage` |
| `aplane.falcon1024-timelock.v1` | `aplane.falcon1024-timelock.v1.yaml` | Requires a Falcon signature and `FirstValid >= unlock_round`; after the unlock round, transaction policy matches the base Falcon key type. | `unlock_round` | None |

## Notes

- `address[]` parameters are unordered by definition. Input order is
  canonicalized, so the same address set produces the same LogicSig address.
- `uint64[]` parameters are canonicalized numerically, so the same approved ASA
  set produces the same LogicSig address regardless of input order.
- Template key types are compatibility boundaries. Do not change the behavior of
  an installed key type in place; create a new versioned key type instead.
- Imported templates are identity-scoped. Installing a template for one signer
  identity does not make it available to other identities.

## Authoring rules: rekey and close-remainder

Templates fall into two classes with different obligations for blocking
`txn.RekeyTo` and `txn.CloseRemainderTo` (and the asset equivalents
`txn.AssetCloseTo` and `txn.AssetSender`).

**Generic templates** (`template_type: generic`, no `base_key_type`) authorize
transactions purely on TEAL predicates with no signature-over-txid binding.
A missing `RekeyTo` or `CloseRemainderTo` guard means an attacker who satisfies
the template's predicate (knows the hashlock preimage, hits the timelock
round, is on the whitelist) can also rekey the account away or drain it
via close-remainder. Generic templates therefore **MUST** include both
guards in their `teal:` block:

```text
txn RekeyTo
global ZeroAddress
==
assert

// for receiver-style templates (whitelist, htlc, timelock-with-recipient):
//   apply the whitelist to CloseRemainderTo / AssetCloseTo too;
// for predicate-only templates with no receiver concept:
//   txn CloseRemainderTo
//   global ZeroAddress
//   ==
//   assert
```

This applies to `aplane.timelock.v1`, `aplane.whitelist.v1`, `aplane.htlc.v1`,
and any new generic template.

**Composed templates** (`template_type: composed`, with `base_key_type` pointing
at a registered DSA family — e.g. `aplane.falcon1024.v1`) are wrapped by
`lsig/composeddsa`. The composer emits the base provider's verifier TEAL
first (which signs `txn TxID`), then an `assert`, then the template's user
suffix. Because `TxID` covers every transaction field including `RekeyTo`
and `CloseRemainderTo`, any change to those fields invalidates the
signature and the program halts at the `assert` before the user suffix
runs. Composed templates therefore do **NOT** need to include
`txn RekeyTo == ZeroAddress` as defense in depth; doing so is redundant
with the base signature binding.

However, composed templates that implement *whitelist semantics* — i.e.
the predicate restricts which addresses can receive transfer value — still need
to enforce the whitelist on destination-like fields explicitly. A user who
intentionally signs a payment with `CloseRemainderTo = attacker` would bind the
signature correctly, but the whitelist would be bypassed if the template only
checked `Receiver`. The composed `aplane.falcon1024-whitelist.v1` template
therefore checks `Receiver` and `CloseRemainderTo` for payments, and
`AssetReceiver` and `AssetCloseTo` for ASA transfers. The sender itself is
allowed as a destination; non-`pay`/`axfer` transaction types and clawback
source selection through `AssetSender` remain governed by the base Falcon
signature and signer policy.

The composed wrap order is locked in by
`TestComposerVerifierAssertsBeforeUserSuffix` (in `lsig/composeddsa/`) and
`TestBundledComposedTemplatesBindTxIDBeforeSuffix` (in `lsig/`). Any
refactor that changes that wrap will fail those tests before a silent
rekey-guard regression can ship.

### Summary

| Template class | `txn RekeyTo == 0` | `CloseRemainderTo` policy |
|---|---|---|
| Generic (`template_type: generic`) | Required | Required (zero, or whitelisted per template semantics) |
| Composed (`template_type: composed`) | Not needed (bound via base signature over `txn TxID`) | Required when the template implements receiver-whitelist semantics; otherwise not needed |
