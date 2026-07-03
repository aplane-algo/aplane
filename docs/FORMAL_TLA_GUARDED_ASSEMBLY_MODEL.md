# Guarded Assembly Machine-Checkable Model

> Status: TLC checked with `MaxEntries = 2`; the recorded run generated
> 270,920 distinct reachable states (one-shot, depth 1) and found no
> counterexamples for `Safety`.

This is the ninth machine-checkable artifact under the M4 milestone in
[FORMALIZATION_ROADMAP.md](FORMALIZATION_ROADMAP.md). It machine-checks the
assembly-verification core of
[FORMAL_GUARDED_SIGNING_MODEL.md](FORMAL_GUARDED_SIGNING_MODEL.md) — the
first A-series invariants to get a TLA+ representation.

The spec lives at [formal/guarded_assembly.tla](formal/guarded_assembly.tla).

## What it covers

| Invariant | Source | TLA+ predicate |
|---|---|---|
| A1: role domain separation | FORMAL_GUARDED_SIGNING_MODEL.md | `A1_RoleDomainSeparation` |
| A6: user signature verified against stored user key | FORMAL_GUARDED_SIGNING_MODEL.md | `A6_UserSignatureVerified` |
| A7: sentry signature verified against embedded sentry key | FORMAL_GUARDED_SIGNING_MODEL.md | `A7_SentrySignatureVerified` |
| A8: passthrough transaction-ID binding | FORMAL_GUARDED_SIGNING_MODEL.md | `A8_PassthroughTxidBound` |
| A14: assembled txn preserves canonical txid + sender/AuthAddr binding | FORMAL_GUARDED_SIGNING_MODEL.md | `A14_AssembledTxnBound` |
| abort-on-first-failure | `assembleDecodedGuarded` | `NoPartialOutput` |

These five were chosen because they are the finite, combinatorial core of
the guarded trust story (signature/role/txid binding checks over a small
group) and were previously anchored only by Go tests. The rest of the
A-series is endpoint routing, key loading, policy ordering, and client
shape checks (A2-A5, A9-A13, A15) — different machinery, deliberately out
of scope here.

## What TLC actually verifies

A one-shot enumeration in the `sign_boundary.tla` style: `Init` enumerates
groups of 1..2 entries, each a **target** (presented user and sentry
component signatures with right/wrong key, role domain, and txid binding,
plus address / sender / post-sign-txid check outcomes) or a **passthrough**
(decoded-txid binding, signature presence, locally-guarded-sender flag).
The `Assemble` decision procedure transcribes
`internal/signerapp/signing/component_assemble.go`'s per-entry checks;
signature verification is abstracted to token equality
(`keyOK /\ role match /\ txid match`) — the model checks the checks, not
Falcon-1024.

## Mutation validation

- Dropping the role check from `Verifies` (accepting a signature regardless
  of its domain-separation role byte) violates `Safety` in an initial state
  — the cross-role replay A1 exists to kill.
- Dropping the decoded-txid comparison from `PassthroughKept` violates
  `Safety` in an initial state — the A8 substitution case.

The restored spec passes.

## Honest gaps (mirrored from the code, not claimed by the model)

- **Parameter↔bytecode consistency is trusted**: the sentry public key
  verified at assembly comes from the stored `Parameters`; the chain
  enforces the key compiled into the bytecode. Generation binds them; the
  assembly does not re-check (explicit assumption in the prose model).
- Passthrough signatures are presence-checked only; the chain verifies.
- No group-level semantics (fees, dummy budget); no replay protection for
  identical component signatures (txid-bound, so re-assembly reproduces the
  same transaction); sentry policy runs at component-sign time (A4), not at
  assembly.
- The user-side verify is hardcoded Falcon-1024 in the code; the model
  reflects that as a single abstract key check, not a scheme parameter.

## How to check

```sh
java -jar tla2tools.jar -config docs/formal/guarded_assembly.cfg \
    docs/formal/guarded_assembly.tla
```

Expected: `Model checking completed. No error has been found.`, 270,920
distinct states, depth 1, a few seconds' runtime. `make formal-test`
includes the module.

## What this proves vs. doesn't

It proves that over every combination of presented component signatures and
binding-check outcomes for groups of up to two entries, the modeled assembly
never emits output resting on a wrong-key, wrong-role, or wrong-txid
signature, never keeps passthrough bytes that do not bind to the canonical
entry, and never emits a partially assembled group. The fairness of the
abstraction (token equality standing in for Falcon/ed25519 verification) and
the mapping to the Go code are code-review responsibilities, anchored by the
Go tests in the traceability A rows
(`TestAssembleDecodedGuardedRejectsWrongUserSignature`,
`...RejectsWrongSentrySignature`, `...RejectsMismatchedPassthrough`,
`...VerifiesAndBuildsSignedGroup`,
`TestPrepareComponentSigningUsesSentryRoleDomain`).

## Linking back

- Prose model: [FORMAL_GUARDED_SIGNING_MODEL.md](FORMAL_GUARDED_SIGNING_MODEL.md)
  (A-series definitions and the full assembly check order).
- Component-sign-time invariants (A3-A5) and endpoint routing (A9, A12,
  A15) remain prose + Go tests; a sentry-sign-time module is the natural
  next step if one is ever needed.
- Traceability rows: A1, A6, A7, A8, A14 in
  [FORMAL_TRACEABILITY.md](FORMAL_TRACEABILITY.md) (now marked
  machine-checked).
