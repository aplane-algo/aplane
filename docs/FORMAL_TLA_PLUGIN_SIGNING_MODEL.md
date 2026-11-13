# Plugin Signing Machine-Checkable Model

> Status: TLC checked with `MaxSlots = 3`; the recorded run generated 29,208
> distinct reachable states (one-shot, depth 1) and found no counterexamples
> for `Safety`. The deep configuration (`MaxSlots = 4`) generated 422,424.

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
| PS8: No Rekey To A Held Aplane Key That Is Not A Valid Rekey Target | FORMAL_PLUGIN_SIGNING_MODEL.md | `PS8_NoRekeyToInvalidTarget` |

**PS1 (Constructor Byte Binding) is deliberately not here**: it is a property
of the Go type — `PregroupedSignedGroup`'s unexported fields and sole
constructor pair the validated decodes with the exact submitted bytes. A TLC
predicate would restate the construction; the check is code review plus the
constructor's tests.

## What TLC actually verifies

This is a one-shot enumeration in the `sign_boundary.tla` style: `Init`
enumerates every combination of mode (pregrouped-signed / presign-plan),
per-slot validation outcomes (plan preservation, byte match, rekey target,
ownership mix), group-shape, digest and rekey target outcomes, and gate
decisions (interactive review
outcome including the non-interactive context; apsigner authorization outcome);
`Submitted` is a transcription of the code's accept/reject logic
(`apshellcli/external_plugins.go`, `apshellapp/submission.go`,
`engine/plugin_pregrouped.go`, `engine/plugin_presign.go`,
`engine/plugin_signing.go`), which every entry point reaches through
`external_plugins.go::processPluginResultStructured`: the REPL and MCP, and JS
`plugin()` (`apshellcli/script_runtime.go`). The client's network precondition
(`engine/active_network.go::checkActiveNetwork`) is a further refusal the model
does not transcribe, and it runs after the rekey judgments and the review: in
`checkReadyToSign` before `/sign` (default flow), in
`SignAndSubmitWithPluginSigners` before `/plan` (presign-plan), and in
`SubmitPregroupedSigned` before the group is broadcast (pregrouped-signed),
each after the submit function's second rekey judgment. It is checked by Go
tests, not modeled. So are the refusals of a step's LogicSig arguments
(`arg:` words), which the model does not transcribe either and which change
none of its gates: `CheckPluginGroup` refuses any for a pregrouped-signed
group, and an argument whose account is not a sender of the group or whose
name repeats for one transaction (`apshellapp/lsig_args.go::resolveLsigArgs`),
after the decode and the non-interactive refusal and before the first rekey
judgment; `processPluginResultStructured` refuses arguments for a successful
first result with no transactions; and `SignAndSubmitWithPluginSigners` refuses an argument
placed on a plugin-signed slot, after its slot-ownership checks and before the
network precondition and `/plan`. TLC verifies that no
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
- Removing the `rekeyTargetsOK` conjunct from `PregroupedSubmitted`, or the
  per-slot `rekeyTargetOK` conjunct from `PresignSubmitted`, violates
  `PS8_NoRekeyToInvalidTarget` in an initial state, and no other invariant:
  no gate stands in for the refusal, since a plugin-signed slot never reaches
  the signer.

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
- **The rekey target check is per slot in presign-plan and per group in
  pregrouped-signed.** Every pregrouped slot is plugin-signed, so one boolean
  says whether any of them rekeys to a held aplane key that is not a valid
  rekey target. In presign-plan each slot of either class carries its own
  outcome, so a check that skipped the plugin slots, which the signer never
  judges, is a counterexample. The default flow is not enumerated; it applies
  the same refusal (`apshellapp/submission.go`), anchored by Go tests.
- **The key list, and the check and submission as two steps, are not
  modeled.** The model has no state for the signer's key list or whether
  apshell could fetch it, and no step between the check and submission.
  apshell applies the rule at the check and again at submission, each time
  against a list fetched for it, and a group with a rekey that cannot be
  checked against a current list is refused; `rekeyTargetsOK` and
  `rekeyTargetOK` stand for both judgments passing, so a refusal at either
  is a case where they are false. The fetches, their failures and the
  recheck are anchored by Go tests.

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

Expected: `Model checking completed. No error has been found.`, 29,208
distinct states, depth 1, sub-second runtime. `make formal-test` includes the
module; `make formal-test-deep` runs `plugin_signing_deep.cfg` (422,424
distinct states).

## What this proves vs. doesn't

It proves that over every enumerated combination of validation outcomes and
gate decisions, the modeled decision procedure never lets plugin-produced
bytes reach submission without group-digest integrity, plan preservation,
byte-matched plugin slots, the mode's authorization gate, and a group with
no rekey to a held aplane key that is not a valid rekey target. The
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
- Traceability rows: PS1-PS8 in [FORMAL_TRACEABILITY.md](FORMAL_TRACEABILITY.md).
