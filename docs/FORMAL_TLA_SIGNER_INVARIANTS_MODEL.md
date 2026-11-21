# Signer Invariants Machine-Checkable Model

> Status: TLC checked; the recorded positive run generated 101,040 distinct
> states at depth 2 with no counterexamples (groups of up to three
> positions), and the deep run 2,021,040 at depth 2 (up to four). Three
> expected-failure negative controls must keep producing their
> counterexamples. Two fail on `SI1_NoReleaseWithInvalidRekeyTarget`:
> `signer_invariants_negative_order.cfg` (`InvariantsBeforePolicy = FALSE`)
> after 50,536 distinct states at depth 2, and
> `signer_invariants_negative_positions.cfg`
> (`TargetJudgesEveryPosition = FALSE`) after 50,560 at depth 2. The third,
> `signer_invariants_negative_external.cfg` (`ExternalAfterPolicy = FALSE`),
> fails on `SI6_NoLookupForARefusedRequest` after 50,522 at depth 2.

The signer invariants are refusals no policy lifts: no rekey to a held
aplane key that is not a valid rekey target, no rekey to a rotating account,
no nonparticipating keyreg. This model states where they stand in the gate
sequence and which positions of a group each one judges. On a cosigner, the
document's external checks follow the policy verdict; the model also states
that they can only refuse and that a request an earlier gate refuses makes
no lookup.

The spec lives at [formal/signer_invariants.tla](formal/signer_invariants.tla).

## What it covers

| Invariant | Meaning | TLA+ predicate |
|---|---|---|
| SI1 | No signature is released for a group in which any position rekeys an account to a held aplane key that is not a valid rekey target | `SI1_NoReleaseWithInvalidRekeyTarget` |
| SI2 | No signature is released for a group in which a position this signer signs breaks a signed-position invariant | `SI2_NoReleaseWithSignedBreach` |
| SI3 | A group an invariant refuses reaches neither the policy verdict nor the operator | `SI3_RefusalBeforePolicy` |
| SI4 | A refusal by the valid-target invariant names the first position that breaks it | `SI4_RefusalNamesFirstPosition` |
| SI5 | No signature is released for a request unless the policy would sign it and its external checks, if it has any, pass: the external answer can remove a signature, never add one | `SI5_ExternalChecksOnlyRefuse` |
| SI6 | A request the invariants or the policy refuse makes no external lookup | `SI6_NoLookupForARefusedRequest` |

## What TLC actually verifies

`Decide` transcribes
`internal/signerapp/signing/invariant_gate.go::rejectSignerInvariants` and
its place in `gate.go::runApprovalGates` and
`cosigner_policy.go::runCosignerGates`: the valid-target invariant
first (`rejectRekeyToInvalidTarget`, over every position of the group as it
will go on chain), then the signed-position invariants
(`rejectRekeyToRotating`, `rejectNonparticipation`, over
`signerPositions`), and only then the policy verdict and the approval that
follows it.

A group is a sequence of positions, each with a class (a position this
signer signs, passthrough, foreign, contextual, or a signer dummy) and two
flags: it rekeys to a held aplane key that is not a valid rekey target, and
it breaks a signed-position invariant. The policy verdict and the operator
are one free oracle, `would_sign`: the claim is that the invariants hold
whatever they answer, an approving rule and User Auto-Approve included.

The last step of `Decide` transcribes
`internal/signerapp/signing/external_checks.go::runExternalChecks`, the last
gate of `runCosignerGates`. A second free oracle, `external`, is what the
request's external checks would answer: `"none"`, `"pass"` or `"refuse"`.
`"none"` stands for a request with no external checks: every signer-role
request, since `gate.go::runApprovalGates` has none, and a cosigner request
whose document lists none (`runExternalChecks` returns at once and looks
nothing up). A lookup is recorded (`looked_up`) only for a request that has
checks and that the invariants and the policy would sign; the signature is
released only if, in addition, the answer is not `"refuse"`. The answer
enters the release as a conjunct, so it can refuse a signature the earlier
gates allowed and cannot release one they refused (SI5).

The three constants are the three guards, each load-bearing, confirmed by
mutation:

| Mutation | Result |
|---|---|
| `InvariantsBeforePolicy = FALSE` (negative control) | SI1 fails: an approval releases a group that carries the rekey |
| `TargetJudgesEveryPosition = FALSE` (negative control) | SI1 fails: the rekey sits at a passthrough position and the signer signs the rest of the group |
| `ExternalAfterPolicy = FALSE` (negative control) | SI6 fails: a request the policy refuses is still looked up |

SI5 has no constant of its own, since its guard is the shape of the release
rather than an order or a scope. It was checked by hand against two
mutations of that conjunct in a scratch copy: releasing whatever the
external answer (SI5 fails on a request whose checks refuse), and letting a
passing answer release a request the policy refused (SI5 fails on
`would_sign = FALSE`).

## Modeling choices and limits

- `policy_precedence.tla` derives the policy verdict and `sign_boundary.tla`
  the output per slot class. Neither is repeated here.
- The key set the valid-target invariant reads is the key snapshot the
  request was planned with. That is a Go-level contract
  (`TestValidTargetInvariantJudgesThePlansKeySet`).
- The rotating invariant is folded into the signed-position flag. Every
  rotating aplane key records that it is not a valid rekey target, so the
  valid-target invariant refuses a rekey to one first, at any position; the
  rotating check is a second line that reads the key type.
- A cosigner holds no account aplane keys, but an Ed25519 cosigner key has an
  address, so on a cosigner the valid-target invariant reads the addresses of
  the Ed25519 cosigner keys the node holds (`cosignerKeyAddresses`) and
  refuses a rekey to one at any position. Its signed-position invariants run
  before its policy as on a signer. The cosigner's key lookup, transaction
  bounds validation and the building of that address set run before the
  invariants and are not modeled; a set that cannot be built refuses the
  request.
- A position outside the group fails closed in the code
  (`positionOutsideGroup`); the model's positions are the group's by
  construction.
- A request without external checks is modeled as the answer `"none"` with
  no lookup, rather than as a passing answer, so that SI6 can say no lookup
  is made at all. A separate "has checks" flag beside a boolean answer would
  give the same behaviors with a third more states, since the answer of a
  request without checks would be a free variable that changes nothing.
- The external checks are one answer per request. What each check looks
  up, how many lookups a request makes and the order the checks run in are
  not modeled; the runner stops at the first refusal, and the lookup count
  is a Go-level detail of the audit record
  (`TestCosignerSignsWhenExternalChecksPass`). A lookup that fails, a node
  that cannot run its document's checks
  (`TestCosignerRefusesWhenItCannotRunExternalChecks`), a lock and a
  canceled request all end the step without a signature, and the model
  counts each as the answer `"refuse"`. A node that cannot run the checks
  makes no lookup in the code; the model records one for it, which SI6 does
  not read, since that request passed the policy.
- What the requester and the audit record are told of an external refusal
  is a Go-level contract
  (`TestCosignerExternalCheckRefusalKeepsTheAnswerInTheAuditRecord`).
- The external step holds a key use while it runs, so a lock ends its
  lookups and waits for it before the source tokens are cleared. Key uses
  and the lock are `key_use_lock.tla`'s subject, not this model's.

## How to check

```sh
make formal-test
make formal-test-deep
```

For the focused runs:

```sh
java -jar tla2tools.jar -config docs/formal/signer_invariants.cfg \
  docs/formal/signer_invariants.tla
java -jar tla2tools.jar -config docs/formal/signer_invariants_negative_order.cfg \
  docs/formal/signer_invariants.tla
java -jar tla2tools.jar -config docs/formal/signer_invariants_negative_positions.cfg \
  docs/formal/signer_invariants.tla
java -jar tla2tools.jar -config docs/formal/signer_invariants_negative_external.cfg \
  docs/formal/signer_invariants.tla
```
