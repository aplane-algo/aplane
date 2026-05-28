<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# User LogicSig Guidelines

> **TL;DR**
> - The LogicSigs bundled with APlane (Falcon hashlock, Falcon timelock,
>   Falcon whitelist, and the signer-gated Falcon providers) are safe to fund
>   and use as documented.
> - Anything you compile yourself — your own TEAL, your own YAML template, or
>   an externally-supplied LogicSig — needs to pass the full review checklist
>   below before you fund the account.
> - See [Security Review Checklist](#security-review-checklist) for the
>   review items.

This document is a general-purpose security and design guide for LogicSig TEAL.
It is intended for users, operators, and template authors who want to design,
review, or reason about LogicSig-based policies.

It is not a point-in-time audit of the current repository contents. Instead, it
captures the review criteria and risk areas that should be applied to any
LogicSig TEAL policy, whether it is:

- a generic TEAL-only LogicSig
- a signer-gated DSA LogicSig
- a composed DSA LogicSig with extra TEAL conditions

## Table of Contents

- [Signing Authority](#signing-authority)
- [Scope](#scope)
- [LogicSig Categories](#logicsig-categories)
- [Interpretation Rules](#interpretation-rules)
- [Security Review Checklist](#security-review-checklist)
- [Common Pitfalls](#common-pitfalls)
- [Design Guidance](#design-guidance)
- [Review Expectations](#review-expectations)
- [Suggested Author Workflow](#suggested-author-workflow)
- [Bundled LogicSigs In APlane](#bundled-logicsigs-in-aplane)
- [How To Use Bundled LogicSigs Safely](#how-to-use-bundled-logicsigs-safely)
- [Appendix: Strict-Fee Generic LogicSigs](#appendix-strict-fee-generic-logicsigs)
- [Related Documents](#related-documents)

## Signing Authority

**Signing authority lives in the key file, not in the template.** Every
LogicSig key file stores its compiled bytecode, off-curve salt counter, and
signing metadata at creation time. Sign-time code uses that stored metadata;
DSA-backed keys invoke the appropriate base signing provider to produce and
pack signatures. Templates are used for generation, discovery, lifecycle, and
provenance, not to reconstruct missing signing metadata. Template provenance
conflicts or absence may warn in inventory but do not by themselves invalidate
a valid key.

## Scope

Use this guidance for:

- new generic LogicSig templates
- new Falcon or other DSA-composed templates
- review of existing LogicSig TEAL
- user-supplied or library-supplied YAML templates

Use it before funding a LogicSig account, before enabling a template for
production use, and before approving a new built-in LogicSig provider or
template family.

## LogicSig Categories

### Generic LogicSig

A generic LogicSig is TEAL-only authorization. Once the account is funded, any
network participant may be able to submit transactions that satisfy the TEAL.

This means TEAL itself must fully express the intended spending policy. Do not
assume an off-chain operator, wallet UI, or signer approval layer will always
be present.

### Signer-Gated DSA LogicSig

A signer-gated LogicSig uses TEAL to verify one or more cryptographic
signatures, typically over `txn TxID`, with signatures carried in
`LogicSig.Args`.

This model is often safer when policy review and transaction approval remain in
the signer. But it also means some protections may live outside TEAL. Be clear
about which rules are enforced in TEAL and which are enforced by signer policy.

### Composed DSA LogicSig

A composed DSA LogicSig combines a DSA verification base with additional TEAL
constraints such as whitelists, timelocks, or hashlocks.

These policies should be reviewed both as cryptographic verification logic and
as TEAL spending policy.

## Interpretation Rules

Use the following two rules when reading the rest of this document and the
per-key-type notes below:

1. Generic, DSA-less LogicSigs are public once funded. Their security must be
   carried by TEAL itself, because any network participant may be able to
   exercise any path the TEAL permits.
2. Signer-gated DSA LogicSigs rely primarily on the signer authorization
   boundary. For those key types, TEAL restrictions may be present as an
   additional safeguard, but the signer approval path remains the main security
   control unless the key type explicitly claims a stronger self-contained
   on-chain policy.

## Security Review Checklist

Apply this checklist to every LogicSig policy.

### 1. Authorization Model

- Is the LogicSig signatureless once funded, or does it require signer-gated
  DSA signatures?
- If signer-gated, what protection remains in signer approval rather than TEAL?
- If signatureless, can any network participant trigger every allowed path?
- Is that public executability acceptable for the account being funded?

### 2. Fee Drain

- Does TEAL cap `txn Fee`?
- Does it handle grouped transactions and fee pooling intentionally?
- Can an attacker submit a valid transaction with an excessive fee and drain the
  account?
- Are helper paths such as key registration or ASA opt-in subject to the same
  fee protections?

Signatureless LogicSigs are especially exposed here. If TEAL permits a path and
does not cap fees, anyone may be able to spend the account down through fees
alone.

### 3. Rekey Protection

- Is rekey forbidden, restricted, or allowed by design?
- If rekey is restricted in TEAL, are helper and alternate paths covered, not
  just the main spend path?
- If the LogicSig is signer-gated, is rekey intentionally left to signer policy?

Public generic LogicSigs usually should not allow unconstrained rekey, because
anyone who can exercise an allowed path may be able to transfer account control.
Signer-gated LogicSigs may instead rely on signer approval and local policy for
rekey decisions.

### 4. Close-Out Protection

For ALGO payments:

- Is `CloseRemainderTo` forbidden, restricted to intended recipients, or allowed?
- If it is not enforced in TEAL, is the signer-policy or workflow boundary clear?

For ASA transfers:

- Is `AssetCloseTo` forbidden, restricted to intended recipients, or allowed?
- If it is not enforced in TEAL, is the signer-policy or workflow boundary clear?

Check all paths consistently:

- normal sends
- claim paths
- refund paths
- helper transactions
- signer-gated paths

### 5. Asset Clawback Protection

- Is clawback sender use through `AssetSender` forbidden, restricted, or allowed?
- If clawback behavior is restricted in TEAL, are asset helper paths covered by
  the same rule?
- If it is not enforced in TEAL, is the signer-policy or workflow boundary clear?

### 6. Transaction Type Allowlist

- Does the LogicSig reject unexpected transaction types, or is transaction-type
  control intentionally left to signer policy?
- Are app calls, asset config, asset freeze, and other irrelevant types
  explicitly excluded when the TEAL is meant to be self-contained?
- Are intentionally allowed types documented?

Prefer explicit `txn TypeEnum` checks for public or self-contained TEAL policies.
Signer-gated signing primitives may deliberately leave transaction type control
to signer approval and local policy.

### 7. Key Registration And Opt-In Paths

- Are `keyreg` and ASA opt-in paths intentionally allowed?
- If the template is signatureless, is it acceptable that anyone can submit
  those transactions?
- Can public opt-in increase minimum balance requirements or clutter state?
- Can public key registration alter participation state in an unintended way?

If these paths are not a clear product requirement, remove them.

### 8. Time Semantics

- Are round checks based on the correct transaction field?
- Should the policy depend on `FirstValid`, `LastValid`, or both?
- Can a transaction created before a timeout remain valid after the timeout due
  to a wide validity window?

For LogicSig timelocks, prefer deliberate use of transaction validity fields.
Do not assume a single round comparison captures the intended before/after
behavior.

### 9. Group Semantics

- Does correctness depend on `GroupSize`, `GroupIndex`, or specific companion
  transactions?
- If grouped transactions are allowed, can another group member make the
  LogicSig transaction dangerous?
- Does fee pooling introduce drain risk?
- Are dummy transactions or signer-side group mutation compatible with the TEAL
  policy?

Grouped behavior should be modeled intentionally, not assumed safe.

### 10. Runtime Args

- Are all runtime args validated in TEAL?
- Are missing args rejected?
- Are wrong lengths rejected?
- Are extra args harmless or rejected?
- Are alternate encodings handled consistently?

Remember: LogicSig args are not part of `txn TxID`. The signature covers the
transaction, not mutable LogicSig args. Treat every runtime arg as attacker
controlled unless TEAL fully validates it.

### 11. Template Substitution

- Are all template variables declared?
- Are they validated by type and format?
- Are addresses canonicalized so equivalent inputs derive the same address?
- For composed DSA templates, does the suffix avoid an unintended `return`?
  APlane's composed-DSA generator rejects `return` in YAML suffixes and appends
  its own final return after DSA verification and suffix checks. When reviewing
  standalone or externally generated TEAL, a stray `return` can
  short-circuit the intended verification flow.
- Does substitution yield TEAL literals of the intended type for addresses,
  byte strings, integers, and lists?
- Does the template TEAL avoid raw `bytecblock`/`intcblock`, numeric `bytec N`
  or `intc N`, and short forms such as `bytec_0` or `intc_0` so APlane can own
  the generated off-curve salt slot?

Template substitution mistakes can silently change the policy being deployed.

### Non-Relocatable Template TEAL

APlane-generated LogicSigs must derive off-curve account addresses. The
concrete salt style is chosen by APlane as part of the versioned
provider/template derivation contract, not by user YAML. Templates with omitted
`derivation_version` are unsalted and compile exactly as written, succeeding
only if the unmodified bytecode already derives an off-curve LogicSig address.
New template-derived key types use `derivation_version: 2`, which appends a
trailing dead-code `bytecblock 0x00` after the program's terminating
instruction. User-authored template TEAL must not hand-write raw `bytecblock`
or `intcblock` declarations, numeric `bytec` or
`intc` references, or short forms such as `bytec_0` or `intc_0`. Use declared
template variables, symbolic `$name` references, and generated-mode list
expansion instead.

### 12. Signature Binding

For DSA LogicSigs:

- Does the verifier sign the intended message (`txn TxID`)?
- Is the public key embedded correctly?
- Are signature args ordered correctly?
- Are signature lengths and formats validated consistently with the TEAL opcode?

If the message binding is wrong, the LogicSig may verify a signature that does
not actually authorize the intended transaction.

## Common Pitfalls

These are recurring failure modes to watch for.

### Public Fee-Griefable Generic LogicSigs

A generic LogicSig that allows a valid path but does not cap `txn Fee` can be
drained by anyone willing to submit valid transactions with excessive fees.

This includes helper paths, not just normal send paths.

### Public Helper Paths With Real Cost

Public key registration and public ASA opt-in may be technically valid yet
unsafe in practice because they:

- consume fees
- may increase minimum balance
- can clutter the account state
- may alter participation state unexpectedly

### Incomplete Close-Out Controls

A policy may block `CloseRemainderTo` but forget `AssetCloseTo`, or vice versa.
Review both ALGO and ASA close-out behavior explicitly.

### Over-Reliance On Signer Policy

A signer-gated LogicSig may enforce only "signature present" plus one extra
condition, while all other transaction safety relies on signer-side approval.

This can be acceptable, but it should be a deliberate design choice. Do not
mistake a signer-policy-dependent template for a self-contained TEAL spending
policy.

### Timeout Window Mistakes

A policy that checks only one validity field can accidentally allow a claim or
spend created before a timeout to remain valid after the timeout.

Always test transactions whose validity window crosses the boundary.

## Design Guidance

### Prefer Explicit Safety Checks

Every LogicSig should make deliberate choices about:

- transaction types
- fees
- rekey
- ALGO close-out
- ASA close-out
- clawback behavior
- helper paths

If a behavior is not explicitly intended, reject it.

### Treat Generic LogicSigs As Public Programs

Once funded, a generic LogicSig is effectively a public on-chain program.
Assume any allowed path may be exercised by an arbitrary third party.

For bundled generic LogicSigs, a strong default is to require an exact minimal
fee such as `txn Fee == 1000`. This prevents the LogicSig account from becoming
an open-ended fee payer.

### Be Clear About The Security Boundary

For signer-gated LogicSigs, decide whether the template is:

- a complete spending policy in TEAL, or
- an extra condition layered on top of signer approval

Document that choice and review the template accordingly.

### Keep Policy Consistent Across Paths

Many bugs come from enforcing safety rules only on the main payment path while
helper, refund, opt-in, or alternate paths remain less restricted.

Check every branch.

## Review Expectations

Before relying on a LogicSig in production, verify both positive and negative
cases.

Positive cases should show intended behavior succeeds, such as:

- transfer to an allowed recipient
- close-out to an explicitly allowed close address
- hashlock spend with the correct preimage
- timelock spend after the unlock condition

Negative cases should show forbidden behavior fails, such as:

- rekey attempt
- send to an unapproved recipient
- ALGO close-out to an unapproved address
- ASA close-out when not explicitly allowed
- clawback path when not explicitly allowed
- missing or malformed runtime args
- timeout-crossing cases that should be rejected

## Suggested Author Workflow

When designing or reviewing a LogicSig TEAL policy:

1. Classify it as generic, signer-gated DSA, or composed DSA.
2. Write down the intended authorization boundary.
3. Review the policy against every checklist section above.
4. Test both valid and invalid transactions, including edge cases.
5. Fund and deploy only after the policy is explicit about fees, rekey,
   close-out, clawback, helper paths, and timing behavior.

## Bundled LogicSigs In APlane

APlane bundles both signer-gated LogicSig providers and optional template
library entries. Users should understand the security model of each one before
funding or relying on it.

### Signer-Gated Compiled Providers

These are Go-defined LogicSig DSA providers. Their TEAL is generated in code
and compiled through algod at derivation time.

#### `aplane.falcon1024.v1`

- pure Falcon-1024 LogicSig DSA
- signer-gated
- best understood as a signing primitive rather than a full TEAL spending
  policy

This provider verifies a Falcon signature over the transaction. Transaction
policy is expected to live primarily in signer approval and local signer policy.

#### `aplane.falcon1024_ed25519.v1`

- dual Falcon-1024 plus Ed25519 LogicSig DSA
- signer-gated
- best understood as a signing primitive rather than a full TEAL spending
  policy

This provider strengthens signature requirements but relies mainly on the
signer-side policy boundary for transaction controls.

#### `aplane.ecdsak1.v1`

- ECDSA secp256k1 LogicSig DSA
- signer-gated
- best understood as a signing primitive rather than a full TEAL spending
  policy

This provider verifies an ECDSA secp256k1 signature over the transaction. Like
the other signer-gated compiled providers, transaction policy is expected to
live primarily in signer approval and local signer policy.

### Optional Template Library

These ship as plaintext YAML templates for optional installation into an
identity keystore.

#### Generic Templates

These are signatureless once funded. If the TEAL permits a path, any network
participant may be able to exercise it.

##### `aplane.timelock.v1`

- generic TEAL-only timelock
- public once funded
- strict fixed fee
- no key registration path
- optional parameterized ASA opt-in only for explicitly approved asset IDs

Leaving `allowed_optin_assets` empty disables only the public ASA opt-in helper
path. It does not make the account ALGO-only: if the LogicSig account already
holds an ASA, the normal asset-transfer path can send or close that ASA to the
configured recipient after `unlock_round`. That distinction is intentional:
third parties must not be able to opt the escrow into arbitrary new assets, but
the timelock applies to existing ASA holdings.

##### `aplane.whitelist.v1`

- generic receiver-whitelist style template
- public once funded
- strict fixed fee
- no key registration path
- optional parameterized ASA opt-in only for explicitly approved asset IDs

Receiver restrictions alone are not the full policy surface. Rekey, ALGO
close-out, ASA close-out, clawback behavior, and any approved helper paths must
also be understood.

Leaving `allowed_optin_assets` empty disables only the public ASA opt-in helper
path. It does not make the account ALGO-only: if the LogicSig account already
holds an ASA, the normal asset-transfer path can send or close that ASA to one
of the whitelisted recipients. That distinction is intentional: third parties
must not be able to opt the account into arbitrary new assets, but the whitelist
applies to existing ASA holdings.

##### `aplane.htlc.v1`

- generic hash-time-lock style template
- public once funded
- strict fixed fee
- no key registration path
- optional parameterized ASA opt-in only for explicitly approved asset IDs

HTLC-style policies should be reviewed with special care around validity-window
crossing behavior and preimage handling.

In `aplane.htlc.v1`, `timeout_round` is enforced in TEAL using `txn FirstValid`:

- refund path requires `txn FirstValid >= timeout_round`
- claim path requires `txn FirstValid < timeout_round`

In other words, `timeout_round` is the first round at which a refund
transaction may begin its validity window, and claim transactions must begin
their validity window before that round.

Leaving `allowed_optin_assets` empty disables only the public ASA opt-in helper
path. It does not make the account ALGO-only: if the LogicSig account already
holds an ASA, the claim and refund paths can send or close that ASA to the
configured recipient or refund address according to the HTLC timing rules. That
distinction is intentional: third parties must not be able to opt the escrow
into arbitrary new assets through helper transactions that are unrelated to the
hashlock policy itself.

#### Falcon-Backed Composed Templates

These are signer-gated templates built by combining Falcon signature
verification with a YAML-defined TEAL suffix. Their YAML uses
`template_type: composed` and `base_key_type: aplane.falcon1024.v1`.

##### `aplane.falcon1024-hashlock.v1`

- Falcon signature-gated plus hashlock condition
- partly TEAL-enforced, partly signer-policy-enforced

This template adds only the hash condition on top of Falcon signature
verification. It should be treated as an extra signer-gated condition, not a
self-contained spending policy. If a self-contained spending policy is
intended, add and review explicit transaction restrictions beyond the hash
check.

##### `aplane.falcon1024-timelock.v1`

- Falcon signature-gated plus timelock condition
- partly TEAL-enforced, partly signer-policy-enforced

This template enforces only `FirstValid >= unlock_round` and otherwise behaves
like the base Falcon key type once the target round has passed. It does not
restrict transaction type, recipient, amount, fee, rekey, ALGO close-out, ASA
close-out, or clawback sender use. Treat it as an extra signer-gated condition
unless additional TEAL is added for the intended spending policy.

##### `aplane.falcon1024-whitelist.v1`

- Falcon signature-gated plus recipient whitelist condition
- more restrictive than a pure signer primitive, but signer-gated

This template can be a good fit when users want both signer-side approval and
an on-chain whitelist constraint. Its TEAL applies the whitelist only to
destination-like fields on ALGO payments and ASA transfers: `Receiver` and
`CloseRemainderTo` for payments, and `AssetReceiver` and `AssetCloseTo` for ASA
transfers. The sender itself is also allowed as a destination. Other transaction
types, and clawback source selection through `AssetSender`, remain governed by
the base Falcon signature and signer policy rather than additional whitelist
TEAL.

## How To Use Bundled LogicSigs Safely

Before funding or using a bundled LogicSig:

1. Determine whether it is public-once-funded or signer-gated.
2. Review fee behavior explicitly.
3. Review rekey, ALGO close-out, ASA close-out, and clawback behavior.
4. Review helper paths such as key registration and asset opt-in.
5. For time-based policies, test boundary and crossing-window cases.
6. For runtime-arg policies, test missing, malformed, and extra args.
7. Do not assume a bundled template is safe for your exact use case without
   checking its full transaction policy.

Backup import verifies that bundled template YAML reproduces the bundled key's
stored LogicSig bytecode when compiled with the key's stored creation
parameters. That is a provenance check, not a semantic security review; review
the template policy before funding or depending on the LogicSig.

## Appendix: Strict-Fee Generic LogicSigs

For DSA-less generic LogicSigs, APlane uses a strict-fee model as the safe
default:

- the generic LogicSig pays only the minimal fixed transaction fee
- the TEAL does not allow flexible or escalated fee payment by the escrow

This is intentional. Public generic LogicSigs should not carry open-ended fee
liability, because any allowed caller may otherwise turn the escrow into an
economic sink.

### Why Strict Fee Is The Default

There is a real tradeoff between:

- strict fee enforcement, which prevents fee drain but may be less flexible
- flexible fee allowance, which helps liveness under congestion but reintroduces
  fee abuse risk

For public generic LogicSigs, APlane resolves this in favor of safety:

- exact fee checks remove fee-griefing against the LogicSig account
- they also avoid accidentally turning reusable public templates into
  user-funded fee pools

### Design Principles

- use strict fixed fees as the default for public generic LogicSigs
- only allow sponsored-fee grouped execution through explicit, carefully
  designed TEAL rules
- keep template TEAL relocatable: do not depend on raw `bytecblock`/`intcblock`
  layout or numeric `bytec`/`intc` references, because APlane owns a generated
  salt slot to keep generated LogicSig addresses off-curve

## Related Documents

- [DEV_KEYTYPES.md](DEV_KEYTYPES.md) — key type categories, registries, YAML
  schema, and tests
- [AGENTS_KEYTYPES.md](AGENTS_KEYTYPES.md) — agent checklist for safe key type
  and LogicSig template work
- [ARCH_LSIG_PROVIDER.md](ARCH_LSIG_PROVIDER.md) — LogicSig provider
  architecture
- [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md) — compatibility-bearing contracts,
  including LogicSig-facing surfaces
