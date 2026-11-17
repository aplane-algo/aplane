# Signer Invariants Machine-Checkable Model

> Status: TLC checked; the recorded positive run generated 33,680 distinct
> states at depth 2 with no counterexamples (groups of up to three
> positions), and the deep run 673,680 at depth 2 (up to four). Two
> expected-failure negative controls must keep producing their
> counterexamples, both on `SI1_NoReleaseWithInvalidRekeyTarget`:
> `signer_invariants_negative_order.cfg` (`InvariantsBeforePolicy = FALSE`)
> after 16,846 distinct states at depth 2, and
> `signer_invariants_negative_positions.cfg`
> (`TargetJudgesEveryPosition = FALSE`) after 16,854 at depth 2.

The signer invariants are refusals no policy lifts: no rekey to a held
aplane key that is not a valid rekey target, no rekey to a rotating account,
no nonparticipating keyreg. This model states where they stand in the gate
sequence and which positions of a group each one judges.

The spec lives at [formal/signer_invariants.tla](formal/signer_invariants.tla).

## What it covers

| Invariant | Meaning | TLA+ predicate |
|---|---|---|
| SI1 | No signature is released for a group in which any position rekeys an account to a held aplane key that is not a valid rekey target | `SI1_NoReleaseWithInvalidRekeyTarget` |
| SI2 | No signature is released for a group in which a position this signer signs breaks a signed-position invariant | `SI2_NoReleaseWithSignedBreach` |
| SI3 | A group an invariant refuses reaches neither the policy verdict nor the operator | `SI3_RefusalBeforePolicy` |
| SI4 | A refusal by the valid-target invariant names the first position that breaks it | `SI4_RefusalNamesFirstPosition` |

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

The two constants are the two guards, each load-bearing, confirmed by
mutation:

| Mutation | Result |
|---|---|
| `InvariantsBeforePolicy = FALSE` (negative control) | SI1 fails: an approval releases a group that carries the rekey |
| `TargetJudgesEveryPosition = FALSE` (negative control) | SI1 fails: the rekey sits at a passthrough position and the signer signs the rest of the group |

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
- A cosigner holds no account aplane keys, so the valid-target invariant
  finds nothing there; its signed-position invariants run before its policy
  as on a signer. The cosigner's key lookup and transaction bounds
  validation run before the invariants and are not modeled.
- A position outside the group fails closed in the code
  (`positionOutsideGroup`); the model's positions are the group's by
  construction.

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
```
