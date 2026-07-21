<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# User LogicSig Guidelines

> **TL;DR**
> - The LogicSigs bundled with APlane (Falcon timelock, Falcon inline and
>   Merkle allowlists, the rekey-locked Falcon allowlist, HTLC, and the
>   signer-gated DSA providers) are safe to fund and use as documented.
> - Anything you compile yourself — your own TEAL, your own YAML template, or
>   an externally-supplied LogicSig — needs to pass the full review checklist
>   below before you fund the account.
> - See [Security Review Checklist](#security-review-checklist) for the
>   review items.

This document is a security and design guide for APlane LogicSig key type
templates and LogicSig-backed key types. It is intended for users, operators,
and template authors who want to design, review, or reason about
template-derived LogicSig policies.

It is not a point-in-time audit of the current repository contents. Instead, it
captures the review criteria and risk areas that should be applied to any
templated LogicSig TEAL policy, whether it is:

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
- [Security Profiles And Claims](#security-profiles-and-claims)
- [Concrete TEAL Safeguard Patterns](#concrete-teal-safeguard-patterns)
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

This is not a general Algorand application-contract guide. Application-only
topics such as app update/delete authorization and inner transaction fee
management are outside this document unless a LogicSig template explicitly
checks grouped application-call transactions.

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
constraints such as allowlists, timelocks, or hashlocks.

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

Apply this checklist to every LogicSig policy. Some sections are conditional:
if the template does not use a feature such as time, app-call companions, or
batch ASA distribution, mark that section not applicable rather than inventing
irrelevant checks.

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

### 6. Asset ID Protection

- For every ASA transfer path, does TEAL check `txn XferAsset` against the
  intended asset or an explicit allowlist?
- Are ASA opt-in helper paths restricted to the same approved asset set?
- Does an empty asset allowlist disable the helper path rather than allowing
  arbitrary assets?
- If asset ID checks are left to signer policy, is that boundary clear and is
  the template signer-gated?

Any public LogicSig that checks amount and receiver but not `XferAsset` may
authorize the wrong asset.

### 7. Transaction Type Allowlist

- Does the LogicSig reject unexpected transaction types, or is transaction-type
  control intentionally left to signer policy?
- Are app calls, asset config, asset freeze, and other irrelevant types
  explicitly excluded when the TEAL is meant to be self-contained?
- Are intentionally allowed types documented?

Prefer explicit `txn TypeEnum` checks for public or self-contained TEAL policies.
Signer-gated signing primitives may deliberately leave transaction type control
to signer approval and local policy.

### 8. Key Registration And Opt-In Paths

- Are `keyreg` and ASA opt-in paths intentionally allowed?
- If the template is signatureless, is it acceptable that anyone can submit
  those transactions?
- Can public opt-in increase minimum balance requirements or clutter state?
- Can public key registration alter participation state in an unintended way?

If these paths are not a clear product requirement, remove them.

### 9. Time Semantics And Replay

Apply this section only when the template uses round checks, expirations,
unlock rounds, refund/claim windows, or one-spend-per-period behavior.

- Are round checks based on the correct transaction field?
- Should the policy depend on `FirstValid`, `LastValid`, or both?
- Can a transaction created before a timeout remain valid after the timeout due
  to a wide validity window?
- If the template claims one spend per period, does it require a nonzero
  deterministic `txn Lease`?
- If repeated execution within a time window is intended, is that documented?

For LogicSig timelocks, prefer deliberate use of transaction validity fields.
Do not assume a single round comparison captures the intended before/after
behavior. First/last-valid checks alone do not make smart-signature execution
single-use: a caller can vary unchecked fields and produce multiple valid
transaction IDs in the same period unless the lease or another explicit
mechanism enforces mutual exclusion.

### 10. Group Semantics

Apply this section when the template permits grouped execution, depends on
other transactions, uses `Gtxn` or `GroupIndex`, supports sponsored fees, or
must remain compatible with APlane dummy transactions.

- Does correctness depend on `GroupSize`, `GroupIndex`, or specific companion
  transactions?
- If grouped transactions are allowed, can another group member make the
  LogicSig transaction dangerous?
- Does fee pooling introduce drain risk?
- Are dummy transactions or signer-side group mutation compatible with the TEAL
  policy?
- If the template uses `Gtxn`, relative group indexes, companion app calls, or
  sponsored fees, does it assert the expected group size or otherwise prove the
  allowed group shape?

Grouped behavior should be modeled intentionally, not assumed safe.

### 11. App-Call Companion Checks

Apply this section only when the stateless LogicSig template validates grouped
application-call transactions. LogicSigs cannot read application state, but they
can inspect app-call transaction fields in the same group.

- If the LogicSig validates a companion application call, does it check
  `OnCompletion`?
- Does it require the intended application ID?
- Does it require the intended method selector or application arguments?
- Does it reject `ClearState` calls when the policy expects approval-program
  execution?

Checking only `TypeEnum == appl` is not enough when correctness depends on the
approval program running. A `ClearState` application call executes the clear
state program instead.

### 12. ASA Distribution Liveness

Apply this section only when the LogicSig template coordinates a grouped ASA
distribution or requires multiple ASA transfers as part of its policy.

- Does the policy push ASAs to multiple recipients in one group?
- Can one receiver who has not opted in cause every transfer in the operation
  to fail?
- Can the design use pull-over-push instead, where each receiver claims
  independently after opting in?
- If push distribution is required, can failures be isolated per recipient
  rather than blocking the whole group?

This is primarily a liveness and denial-of-service concern, but it matters for
LogicSig designs that coordinate batch ASA movement.

### 13. Runtime Args

- Are all runtime args validated in TEAL?
- Are missing args rejected?
- Are wrong lengths rejected?
- Are extra args harmless or rejected?
- Are alternate encodings handled consistently?

Remember: LogicSig args are not part of `txn TxID`. The signature covers the
transaction, not mutable LogicSig args. Treat every runtime arg as attacker
controlled unless TEAL fully validates it.

### 14. Template Substitution

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

### 15. Signature Binding

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

### Time-Based Replay Without Lease

For templates that intend to allow only one spend per period, checking
`FirstValid` and `LastValid` is not enough. A caller can create multiple
transactions that all satisfy the same round checks but differ in unchecked
fields, producing distinct transaction IDs. Use a deterministic nonzero lease
for single-use periodic authorization.

### Asset Substitution

ASA transfer TEAL that checks receiver and amount but not `XferAsset` may
authorize a different asset than the one the template designer intended.
Every ASA path should either bind the exact asset ID or use an explicit
creation-time allowlist.

### Missing Group Shape Checks

Templates that inspect companion transactions with `Gtxn` can be abused when
they do not also constrain the group shape. If the policy assumes exactly one
companion payment or app call, assert that shape instead of relying only on
fixed indexes.

### ClearState Companion Calls

When a LogicSig template checks that another transaction is an application
call, it must also check the `OnCompletion` mode if it depends on
approval-program behavior. A `ClearState` call executes the clear state
program, not the approval program.

### Push-Based ASA Distribution DoS

For templates that coordinate batch ASA movement, pushing ASA transfers to
multiple recipients in one atomic operation can make the whole operation depend
on every receiver being opted in. Prefer pull-based claim flows or isolate
failures so one recipient cannot block all recipients.

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

### Prefer Pull Over Push For ASA Distribution

When a LogicSig template coordinates ASA distribution, a pull design is usually
safer than one transaction group that pushes assets to many recipients. In a
pull design, each recipient opts in first and then claims independently. That
avoids turning one missing opt-in into a denial of service against the whole
operation.

### Use Leases For Single-Use Periodic Authorization

If a LogicSig template is meant to authorize one transaction per time period,
use a deterministic nonzero `txn Lease` tied to the period and template
domain. Round checks define when a transaction is valid; a lease prevents
multiple different transaction IDs from being accepted for the same sender and
period.

## Security Profiles And Claims

Template authors should be able to state which security profile a LogicSig
claims and which controls are TEAL-enforced versus signer-policy-owned. This
does not replace code review, but it prevents ambiguity.

### Public Generic Strict

Use this profile for generic TEAL-only templates that may be funded directly.
The template should enforce:

- transaction type allowlist
- exact fee or explicitly modeled sponsored-fee group
- `RekeyTo == ZeroAddress`
- payment close-out policy
- asset close-out policy
- asset sender / clawback policy
- asset ID allowlist for every ASA path
- group shape checks whenever group fields are used
- lease checks when single-use or periodic behavior is claimed
- runtime argument length and type checks
- no public key registration path unless deliberately declared
- no arbitrary ASA opt-in path

### Composed Signer-Gated

Use this profile for composed DSA templates where signer approval is the main
authorization boundary. The template should enforce:

- signature verification over `txn TxID`
- runtime argument validation
- no early `return` in the TEAL suffix
- complete TEAL coverage for any extra policy it claims, such as allowlist,
  hashlock, or timelock behavior

Fields intentionally left to signer policy should be listed explicitly:
fee, rekey, payment close-out, asset close-out, asset sender, transaction type,
group shape, asset IDs, and any app-call completion or lease behavior that is
in scope for the template.

### Self-Contained Composed

Use this profile only when a DSA-composed template claims both signer-gating and
a full on-chain spending policy. It should satisfy the public-generic controls
for the transaction behavior it permits, plus the DSA signature-binding
requirements.

## Concrete TEAL Safeguard Patterns

These snippets are patterns for review. Template mode, generated variables, and
branch structure may change the exact form, but the policy intent should remain
visible in TEAL.

### Rekey

```teal
txn RekeyTo
global ZeroAddress
==
assert
```

### Strict Fee

```teal
txn Fee
int 1000
==
assert
```

If fee pooling is required, constrain the group shape and prove which
transaction pays the fee. Do not let a public LogicSig account pay unbounded
fees.

### Payment Close-Out

```teal
txn CloseRemainderTo
global ZeroAddress
==
assert
```

Allowlist policies may instead allow zero, self, or the same approved
destination set used for `Receiver`.

### Asset Close-Out

```teal
txn AssetCloseTo
global ZeroAddress
==
assert
```

Allowlist policies may instead allow zero, self, or the same approved
destination set used for `AssetReceiver`.

### Asset Sender / Clawback

```teal
txn AssetSender
global ZeroAddress
==
assert
```

Only omit this when clawback sender use is an explicit, reviewed part of the
template.

### Asset ID

```teal
txn XferAsset
int <asset_id>
==
assert
```

For multiple assets, generate canonical membership checks from a `uint64[]`
creation parameter. Empty allowlists should disable the ASA helper path, not
allow every asset.

### Group Shape

```teal
global GroupSize
int <expected_size>
==
assert
```

When using relative indexes, also prove the current `GroupIndex` and referenced
indexes have the intended transaction types and cannot be out of bounds.

### Lease

```teal
txn Lease
byte <domain_separated_period_lease>
==
assert
```

The lease must be nonzero and deterministic. Do not accept an arbitrary caller
provided lease when the template's purpose is replay prevention.

### App-Call Completion

```teal
gtxn <index> TypeEnum
int appl
==
assert

gtxn <index> OnCompletion
int NoOp
==
assert
```

Also check the intended application ID and method selector when policy depends
on a specific application method.

## Review Expectations

Before relying on a LogicSig in production, verify both positive and negative
cases.

Positive cases should show intended behavior succeeds, such as:

- transfer to an allowed recipient
- close-out to an explicitly allowed close address
- hashlock spend with the correct preimage
- timelock spend after the unlock condition

Negative cases should show forbidden behavior fails, such as:

- excessive fee on a public generic LogicSig
- rekey attempt
- send to an unapproved recipient
- ALGO close-out to an unapproved address
- ASA close-out when not explicitly allowed
- clawback path when not explicitly allowed
- transfer or opt-in of an unapproved ASA ID
- wrong group size or wrong companion transaction type
- `ClearState` companion app call where `NoOp` is required
- missing or wrong lease for a single-use periodic policy
- missing or malformed runtime args
- timeout-crossing cases that should be rejected

## Suggested Author Workflow

When designing or reviewing a LogicSig TEAL policy:

1. Classify it as generic, signer-gated DSA, or composed DSA.
2. Choose the security profile it claims: public generic strict, composed
   signer-gated, or self-contained composed.
3. Write down the intended authorization boundary and which fields are
   TEAL-enforced versus signer-policy-owned.
4. Review the policy against every checklist section above.
5. Test both valid and invalid transactions, including edge cases.
6. Fund and deploy only after the policy is explicit about fees, rekey,
   close-out, clawback, helper paths, asset IDs, group shape, app-call
   completion, lease behavior, and timing behavior.

## Bundled LogicSigs In APlane

APlane bundles both signer-gated LogicSig providers and template library
entries. New signer stores install the Falcon allowlist v1 template by default;
the Ed25519 allowlist v1 is an optional import. Users should understand the
security model of each one before funding or relying on it.

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

#### `aplane.ed25519.v1`

- Ed25519 LogicSig DSA
- library-visible and signer-gated
- best understood as a LogicSig signing primitive rather than a full TEAL
  spending policy

This provider verifies an Ed25519 signature over the transaction inside a
LogicSig. It is distinct from the native `ed25519` key type: native `ed25519`
signs as a normal Algorand account, while `aplane.ed25519.v1` derives an
off-curve LogicSig account whose program performs Ed25519 verification.
Transaction policy is expected to live primarily in signer approval and local
signer policy.

#### Bounded Authorization Allowlist

`aplane.falcon1024-allowlist-alock.v1` is a schema-v2 composed account with
Falcon-1024 spending and external Falcon contract-admin authorization. The
composer-owned `bounded1` envelope admits only pure payments, pure asset
transfers, independently authorized asset opt-ins, or a pure self-payment
rekey, caps the protected transaction fee, and denies close and clawback
effects before Layer 3. A rekey requires both the spending
signature and an external contract-admin signature through
`POST /sign/bounded-admin` and `apbounded-admin`.

Its framework-owned `fixed_allowlist` policy handles all admitted spend effects
without author TEAL. It constrains `Receiver`/`AssetReceiver`, optionally
constrains `XferAsset`, `Amount`, and `AssetAmount`, and compiles canonical
recipient/asset lists inline with an audited maximum of 30 entries each. It
uses no runtime proof or signer-derived LogicSig argument. The external private
key exists only in a `.wit` artifact; losing all copies removes
the admin-key rekey path but does not stop policy-compliant spending. See
[ARCH_BOUNDED_DSA.md](ARCH_BOUNDED_DSA.md).

#### Guarded Sentry Providers

APlane also ships Go-defined, library-visible guarded sentry account providers:
`aplane.falcon1024-sentry1024.v1` and `aplane.corridor.v1`. These require
the guarded signing assembly flow (a user component signature plus a sentry
component signature). For the plain guarded provider, the on-chain LogicSig does not restrict transaction shape
once both signatures verify, so the sentry policy is the spending boundary.
`aplane.corridor.v1` additionally embeds a recipient-corridor allowlist and a
sentry-authorized rekey path in its LogicSig. See
[KEYTYPE_CAPABILITIES.md](KEYTYPE_CAPABILITIES.md) for the per-operation matrix
and [ARCH_SENTRY.md](ARCH_SENTRY.md) for the guarded-signing model.

### Template Library

These ship as plaintext YAML templates. Some are installed into new signer
identities by default; others require explicit installation into an identity
keystore before generation.

#### Generic Templates

These are signatureless once funded. If the TEAL permits a path, any network
participant may be able to exercise it.

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
verification with a bounded schema-v2 policy. Their YAML uses
`template_type: composed`, `base_key_type: aplane.falcon1024.v1`, and a
`bounded` block. The composer rejects close, clawback, non-transfer transaction
types, mixed-effect rekeys, and fees above the declared ceiling before running
the template's Layer 3 condition.

##### `aplane.falcon1024-timelock.v1`

- bounded Falcon payments, asset transfers, and asset opt-in
- `FirstValid >= unlock_round` required for spend and pure spending-key rekey

The account cannot be rekeyed before the unlock round, including as an
emergency response to spending-key compromise. This preserves the timelock as
an authority condition; use the external-admin allowlist or a reviewed custom
policy when an earlier independent recovery path is required.

##### `aplane.falcon1024-allowlist.v2`

- bounded Falcon payments and asset transfers with a Merkle recipient allowlist
- asset opt-in and pure spending-key rekey remain available without a proof

This template stores the public receiver allowlist in the encrypted key file
and commits the LogicSig to a fixed-depth Merkle root derived from that list.
The root is built from unique address public keys sorted ascending, with leaves
`sha256(0x00 || pubkey)`, padding to 65,536 leaves with `sha256(0x00)`, and
internal nodes `sha256(0x01 || min(left,right) || max(left,right))`. For a
non-self destination, the signer generates the 512-byte proof and appends it to
the LogicSig arguments; callers do not pass `arg:proof`.

Payment and asset receivers may be the sender itself without a proof. The
bounded envelope rejects payment close, asset close, clawback, all non-transfer
transaction types, and rekey combined with another effect. Pure rekey uses the
spending key and does not run the Merkle proof policy.

##### `aplane.falcon1024-allowlist.v1`

- bounded Falcon payments and asset transfers with an inline recipient allowlist
- asset opt-in and pure spending-key rekey remain available

This template can be a good fit when users want both signer-side approval and
an on-chain allowlist constraint. The bundled template accepts 1-30 recipient
addresses. Payment and asset receivers must be the sender or allowlisted. The
bounded envelope rejects payment close, asset close, clawback, all non-transfer
transaction types, and rekey combined with another effect. Pure rekey uses the
spending key and does not run the allowlist policy.

## How To Use Bundled LogicSigs Safely

Before funding or using a bundled LogicSig:

1. Determine whether it is public-once-funded or signer-gated.
2. Review fee behavior explicitly.
3. Review rekey, ALGO close-out, ASA close-out, and clawback behavior.
4. Review helper paths such as key registration and asset opt-in.
5. Review asset ID checks for every ASA path.
6. Review group shape and companion app-call completion checks when grouped
   logic or app calls are involved.
7. For time-based policies, test boundary and crossing-window cases; for
   single-use periodic policies, require a lease.
8. For runtime-arg policies, test missing, malformed, and extra args.
9. Do not assume a bundled template is safe for your exact use case without
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
- bind every ASA path to an intended `XferAsset` or approved asset allowlist
- use deterministic nonzero leases for single-use periodic LogicSig templates
- check `OnCompletion` for companion app calls that must run approval logic
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
- Trail of Bits / Crytic
  [Algorand Not So Smart Contracts](https://github.com/crytic/building-secure-contracts/tree/master/not-so-smart-contracts/algorand)
  — external examples covering rekeying, fee drain, close-out, group size,
  replay, asset ID, ASA liveness, and app-call completion pitfalls
