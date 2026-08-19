# Plugin Signing Machine-Checkable Model

> Status: TLC checked with `MaxSlots = 3`; the recorded run generated 3,852
> distinct reachable states (one-shot, depth 1) and found no counterexamples
> for `Safety`.

This is the tenth machine-checkable artifact under the M4 milestone in
[FORMALIZATION_ROADMAP.md](FORMALIZATION_ROADMAP.md), and the machine-checked
counterpart to [FORMAL_PLUGIN_SIGNING_MODEL.md](FORMAL_PLUGIN_SIGNING_MODEL.md).
It checks the plugin signing trust boundary's decision procedure: which
combinations of validation outcomes and gate decisions allow a plugin-produced
group to reach submission.

The spec lives at [formal/plugin_signing.tla](formal/plugin_signing.tla).

## What it covers

| Invariant | Source | TLA+ predicate |
|---|---|---|
| PS2: Group Digest Integrity | FORMAL_PLUGIN_SIGNING_MODEL.md | `PS2_GroupDigestVerified` |
| PS3: Mandatory Decoded Review, Fail-Closed | FORMAL_PLUGIN_SIGNING_MODEL.md | `PS3_MandatoryReviewFailClosed` |
| PS4: Plan Preservation | FORMAL_PLUGIN_SIGNING_MODEL.md | `PS4_PlanPreserved` |
| PS5: Signed-Slot Byte Match + Index Discipline | FORMAL_PLUGIN_SIGNING_MODEL.md | `PS5_SignedSlotByteMatch` |
| PS6: Managed Slots Approval-Gated | FORMAL_PLUGIN_SIGNING_MODEL.md | `PS6_ManagedApprovalGated` |
| PS7: No Ungated Submission (central) | FORMAL_PLUGIN_SIGNING_MODEL.md | `PS7_NoUngatedSubmission` |

**PS1 (Constructor Byte Binding) is deliberately not here**: it is a property
of the Go type — `PregroupedSignedGroup`'s unexported fields and sole
constructor pair the validated decodes with the exact submitted bytes. A TLC
predicate would restate the construction; the check is code review plus the
constructor's tests.

## What TLC actually verifies

This is a one-shot enumeration in the `sign_boundary.tla` style: `Init`
enumerates every combination of mode (pregrouped-signed / presign-plan),
per-slot validation outcomes (plan preservation, byte match, ownership mix),
group-shape and digest outcomes, and gate decisions (interactive review
outcome including the non-interactive context; apsigner authorization outcome);
`Submitted` is a transcription of the code's accept/reject logic
(`apshellcli/external_plugins.go`, `engine/plugin_pregrouped.go`,
`engine/plugin_presign.go`, `engine/plugin_signing.go`). TLC verifies that no
enumerated combination reaches submission without satisfying every named
invariant. A dropped check in `Submitted` — the model's stand-in for a
regression in the code path it transcribes — surfaces as a counterexample.

Validation outcomes are abstracted to booleans: the model checks the checks
and their gating, not msgpack or cryptography.

## Mutation validation

- Removing the `digestOK` conjunct from `PregroupedSubmitted` (the group-ID
  recomputation) violates `PS2_GroupDigestVerified` in an initial state.
- Removing the `review = "approved"` conjunct violates
  `PS3_MandatoryReviewFailClosed` (and `PS7`) — the model's reproduction of
  the removed-`localSigners`-era bypass class: bytes reaching submission with
  no human gate.

The restored spec passes.

## Modeling choices

- **Two modes, disjoint record shapes.** `PregroupedCase` and `PresignCase`
  are a union so TLC does not enumerate irrelevant fields; slots are likewise
  a `PluginSlot \cup ManagedSlot` union.
- **Presign-plan requires both slot classes** (`ValidPresignSlots`): all-plugin
  groups are rejected toward pregrouped-signed by the code, so the model
  excludes them from the domain rather than modeling the redirect.
- **The presign client review is `# "rejected"`, not `= "approved"`**: that
  path deliberately proceeds without a prompt in non-interactive contexts
  because apsigner's policy/approval pipeline is the authoritative gate — the asymmetry with
  pregrouped-signed (which fails closed) is the deliberate design, and PS7
  rests on the apsigner authorization outcome for this mode. That abstract
  `approved` outcome includes explicit policy, operator approval, or the
  ordinary `user_auto_approve:true` default.
- **Group-level abstraction for pregrouped.** Reorder, subset, substitution,
  and injection all manifest as the recomputed-digest mismatch, so a single
  `digestOK` boolean is the honest abstraction; the concrete cases are
  enumerated in the Go tests (`plugin_pregrouped_test.go`).

## Test-gap found while anchoring

Writing the PS3 traceability row surfaced that `reviewPregroupedSigned`'s
fail-closed and mandatory-review behavior had **no Go test**. Added in the
same change: `internal/apshellcli/plugin_pregrouped_review_test.go`
(`TestReviewPregroupedSignedFailsClosedWhenAutoConfirm`,
`TestReviewPregroupedSignedIgnoresRequiresApprovalFalse`,
`TestReviewPregroupedSignedRendersDecodedGroupAndApproves`).

## How to check

```sh
java -jar tla2tools.jar -config docs/formal/plugin_signing.cfg \
    docs/formal/plugin_signing.tla
```

Expected: `Model checking completed. No error has been found.`, 3,852
distinct states, depth 1, sub-second runtime. `make formal-test` includes the
module.

## What this proves vs. doesn't

It proves that over every enumerated combination of validation outcomes and
gate decisions, the modeled decision procedure never lets plugin-produced
bytes reach submission without group-digest integrity, plan preservation,
byte-matched plugin slots, and the mode's authorization gate. The
pregrouped-signed gate is necessarily human; the presign-plan gate is the
ordinary signer policy/approval pipeline. It does not prove the
Go code implements the procedure (code-review responsibility, anchored by
the PS traceability rows), and it does not claim anything about the honest
gaps recorded in FORMAL_PLUGIN_SIGNING_MODEL.md (no local signature
cryptography, fee exemption, self-consistent malicious groups, non-canonical
encoding).

## Linking back

- Prose model: [FORMAL_PLUGIN_SIGNING_MODEL.md](FORMAL_PLUGIN_SIGNING_MODEL.md).
- The generic passthrough machinery (I7/I8) is
  [formal/sign_boundary.tla](formal/sign_boundary.tla); apsigner's approval
  pipeline is [formal/approval_coordinator.tla](formal/approval_coordinator.tla)
  and the composition modules.
- Traceability rows: PS1-PS7 in [FORMAL_TRACEABILITY.md](FORMAL_TRACEABILITY.md).
