# Formalization Roadmap

> Status: draft assurance plan. This is not a machine-checked proof.
> It defines the order and scope for turning APlane's architecture contracts into
> precise models.

## Purpose

This roadmap keeps formal-assurance work bounded. The goal is not to prove the
entire Go daemon, every transport, operator behavior, or algod itself. The goal
is to model the security-critical semantics that APlane already treats as
architectural and compatibility contracts, then connect those models to tests
and, later, machine-checkable specifications.

Formalization artifacts live beside the architecture docs. They do not replace
[ARCH_SPEC.md](ARCH_SPEC.md), [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md), or the
subsystem-specific documents. The architecture docs remain the engineering map;
formalization docs define narrower state, transition, and invariant surfaces.

## Source Documents

Primary sources for the first tranche:

- [ARCH_TXNFLOW.md](ARCH_TXNFLOW.md): transaction request modes, planning,
  signing flow, dummy insertion, fee adjustment, passthrough, and foreign slots.
- [ARCH_HTTP_API.md](ARCH_HTTP_API.md): HTTP endpoint contracts, response
  alignment, status behavior, and `/sign/cancel`.
- [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md): compatibility-bearing policy,
  lifecycle, reload, key-file, SDK, and backup/restore contracts.
- [ARCH_SENTRY.md](ARCH_SENTRY.md):
  guarded-account component signing, sentry endpoint routing, assembly
  verification, and node role separation.
- [ARCH_POLICY.md](ARCH_POLICY.md): current signer policy verdict model,
  precedence, sentry component policy, snapshot semantics, and rule
  inventory.
- [ARCH_AUTHORIZATION.md](ARCH_AUTHORIZATION.md): principal/action authorization
  and sensitive-operation attribution.
- [ARCH_NETWORKS.md](ARCH_NETWORKS.md): genesis-hash network identity and
  policy network lookup.
- [ARCH_DATA_MODEL.md](ARCH_DATA_MODEL.md) and
  [ARCH_DATA_CATALOG.md](ARCH_DATA_CATALOG.md): durable and in-memory objects
  that cross subsystem boundaries.

## Scope

The formalization work should proceed in small, composable models:

1. Transaction planning and signing boundary.
2. Policy precedence and approval outcomes.
3. LogicSig key-file signing authority.
4. Runtime lifecycle and decommission signing-stop behavior.
5. Guarded account component signing, sentry policy, endpoint routing, and
   assembly verification.
6. LogicSig template and bytecode-generation invariants.
7. Machine-checkable models for the highest-value surfaces.

Each model should state:

- source documents,
- abstract objects,
- transition rules,
- invariants,
- assumptions,
- non-goals,
- code/test anchors,
- known model-to-code gaps.

The pseudo-formal snippets in `FORMAL_*_MODEL.md` files are relational
pseudocode, not the syntax of a target prover. `Reject(...)` means no successful
state transition/result exists for that input. Before translating a model to
TLA+, Alloy, or another notation, normalize each snippet into that tool's
state/result vocabulary.

## Non-Goals

Initial models should not include:

- SSH tunneling,
- HTTP parsing details,
- JSON/msgpack parser correctness,
- fsnotify event ordering,
- full filesystem crash recovery,
- terminal UI behavior,
- operator behavior,
- algod consensus correctness,
- plugin group-mode flows `presign-plan` (a plugin signs its own slots by
  callback; the signer plans them as foreign slots) and `pregrouped-signed`
  (the plugin submits a complete signed group, bypassing the signer),
- approval coordinator cancellation/timeout state machines (picked up as the M3
  companion [FORMAL_APPROVAL_COORDINATOR_MODEL.md](FORMAL_APPROVAL_COORDINATOR_MODEL.md);
  excluded only from the first-wave models),
- LogicSig budget computation internals,
- LogicSig template and bytecode-generation semantics,
- future registration, witness, compliance-signer, or profile-trust concepts
  that are not current sentry contracts.

Those areas can be connected later through assumptions or separate models if
their contracts become security-critical.

## Milestones

### M1: Precise English Models

Deliver:

- [FORMAL_TXN_PLANNING_MODEL.md](FORMAL_TXN_PLANNING_MODEL.md)
- [FORMAL_POLICY_MODEL.md](FORMAL_POLICY_MODEL.md)
- [FORMAL_SIGNING_AUTHORITY_MODEL.md](FORMAL_SIGNING_AUTHORITY_MODEL.md)
- [FORMAL_LIFECYCLE_MODEL.md](FORMAL_LIFECYCLE_MODEL.md)
- [FORMAL_GUARDED_SIGNING_MODEL.md](FORMAL_GUARDED_SIGNING_MODEL.md)

Done means each document has concrete invariants and a clear source-of-truth
mapping back to existing docs and code owners.

This milestone deliberately excludes the separate LogicSig template/bytecode
generation model and machine-checkable models. Those are later milestones, not
omissions from M1.

### M2: Implementation Test Alignment

For each invariant, identify or add tests that exercise the corresponding Go
behavior. These tests do not prove the model, but they reduce the model-to-code
gap. The concrete backlog with per-gap test sketches lives at
[FORMAL_TEST_GAPS.md](FORMAL_TEST_GAPS.md). That backlog is currently empty;
new entries should be added there only when the traceability table downgrades
an invariant to `implemented*`, `intended`, or `deferred`.

Preferred test targets:

- planner request-mode validation,
- `/plan` and `/sign` planning parity,
- passthrough byte preservation,
- foreign-slot non-signing,
- policy precedence,
- key-file metadata rejection,
- decommission signing-stop behavior,
- client simulation boundary: ordinary signing and approval, exact signed-group
  algod routing, no signer simulation endpoint, and pre-sign algod checks,
- `auth_address` -> key file resolution via runtime index.
- guarded signing assembly: wrong user signature rejection, wrong sentry
  signature rejection, passthrough transaction-ID binding,
- sentry endpoint routing: explicit mismatch hard-fails without fallback,
  malformed component responses reject, unavailable endpoint sync preserves
  prior inventory while hard failures write nothing.

### M3: Deferred Companion English Models

Add precise English models for surfaces that are important but intentionally
outside M1:

- approval coordinator state, including manual approval, cancellation, timeout,
  and decommission failure — **delivered** as
  [FORMAL_APPROVAL_COORDINATOR_MODEL.md](FORMAL_APPROVAL_COORDINATOR_MODEL.md);
  its TLA+ module is Track B2,
- plugin group modes, including the `presign-plan` plugin-callback flow (the
  plugin signs its own slots, which the signer plans as foreign slots), and the
  `pregrouped-signed` all-plugin server-bypass flow — **delivered** as
  [FORMAL_PLUGIN_SIGNING_MODEL.md](FORMAL_PLUGIN_SIGNING_MODEL.md);
  machine-checked subset in `plugin_signing.tla`,
- LogicSig budget computation,
- LogicSig template and bytecode generation.

### M4: Machine-Checkable Model

Start with a small TLA+ or Alloy model for transaction planning and policy
precedence. The first machine-checked model should avoid cryptographic
algorithms and model only control-flow and authorization semantics.

The first machine-checkable invariant should be narrower than "APlane signs only
safe groups." A better first target is:

```text
For every accepted sign request, every signer-produced output belongs either to
a sign-mode input slot or to a signer-generated dummy slot; passthrough slots
are preserved and foreign slots produce no signature.
```

The starting artifact is [formal/sign_boundary.tla](formal/sign_boundary.tla),
described in
[FORMAL_TLA_SIGN_BOUNDARY_MODEL.md](FORMAL_TLA_SIGN_BOUNDARY_MODEL.md). It
covers I1-I3, I7-I8, deny-output suppression, output alignment, and the
M4 target invariant above. It has been checked with TLC under
`MaxRequestEntries = 3` and `MaxDummies = 2`; no counterexamples were
found in the recorded bounded run.

The second module is [formal/policy_precedence.tla](formal/policy_precedence.tla),
described in
[FORMAL_TLA_POLICY_PRECEDENCE_MODEL.md](FORMAL_TLA_POLICY_PRECEDENCE_MODEL.md).
It derives the policy verdict from rule application instead of treating
it as an oracle, which makes P4-P7 + I9 (Hard Deny Dominance)
TLC-checkable claims. No bounds are needed; every domain is finite by
construction. The recorded run generated 64 distinct initial states,
reached depth 1, and found no counterexamples for `Safety`.

The third module is [formal/composition.tla](formal/composition.tla),
described in
[FORMAL_TLA_COMPOSITION_MODEL.md](FORMAL_TLA_COMPOSITION_MODEL.md).
It joins the first two modules: the verdict that sign-boundary
treats as a free oracle is here derived by running
policy-precedence on rule matches and operator default, and the joint
Init feeds that derived outcome into sign-boundary's output
computation. The bridge invariant `PolicyOutcomeBindsOutput` ties
policy decisions to signing output; `HardDenyProducesNoOutput`
promotes sign-boundary's by-construction
`DenyOutputSuppression` into a derived consequence of running real
policy precedence. TLC checked under `MaxRequestEntries = 3` and
`MaxDummies = 2`; the recorded run generated 84,096 distinct initial
states, reached depth 1, and found no counterexamples for `Safety`.

The fourth module is [formal/lifecycle.tla](formal/lifecycle.tla),
described in
[FORMAL_TLA_LIFECYCLE_MODEL.md](FORMAL_TLA_LIFECYCLE_MODEL.md). It is
the first module with real `Next`-relation transitions rather than a
one-shot `Init`: two signer processes and one admin process race over
a writer-priority RWMutex. It covers L4-L7 (lease gates signing,
decommission waits for held lease, decommission wins race before
lease, registry removal does not prevent completion). TLC checked
under `SignerProcs = {s1, s2}`, `admin = a`, `NONE = none`, with
symmetry over signers; the recorded run generated 48 distinct
reachable states, reached depth 10, and found no counterexamples for
`Safety`. L5 was validated by a mutation test (removing the
`readers = {}` guard from `AdminAcquireWrite` produces a
counterexample).

Next likely modules:

1. **Guarded signing and assembly.** Translate
   [FORMAL_GUARDED_SIGNING_MODEL.md](FORMAL_GUARDED_SIGNING_MODEL.md) into a
   small one-shot module. The first version should abstract cryptographic
   verification as predicates and check that successful assembly requires the
   local user key, the embedded sentry key, exact target coverage, and
   passthrough transaction-ID binding.
2. **Endpoint routing state.** Model client endpoint inventory separately if
   the guarded module becomes too large: explicit mismatch hard-fails, self
   fallback is only available when no explicit route exists, and hard discovery
   failures do not partially rewrite routing state.
3. **Lifecycle-aware composition.** *Shipped* as
   `lifecycle_composition.tla`: a lease-gated signing step on the lifecycle
   race, machine-checking that lifecycle unavailability (decommission) admits
   no new signer output. The temporal-vs-one-shot reconciliation was resolved
   by consuming the policy decision as a boolean rather than merging the
   one-shot pipeline transition-by-transition.
4. **Approval coordinator state machine.** *Shipped* as
   `approval_coordinator.tla` (Track B2): pending approvals, timeouts,
   cancellations, and mid-flight decommission, machine-checking L8.
5. **Liveness on lifecycle.** Add weak fairness on
   `AdminAcquireWrite` and `AdminMarkDecommissioned`; verify
   `Decommission` eventually completes given fair admin progress.

### M5: Traceability

The traceability table is now an ongoing M1 deliverable rather than a
deferred milestone, because the S13 incident showed that invariant status
must be tracked alongside the invariant prose to avoid silent drift. The
table lives at [FORMAL_TRACEABILITY.md](FORMAL_TRACEABILITY.md) and tracks:

- invariant,
- status (implemented, implemented*, intended, derived, assumption, deferred),
- source doc section,
- implementation files,
- unit/integration/property tests,
- machine-checkable model reference, if any.

The ownership principle: every invariant should have a status and either a
test, an assumption, or a deliberate deferral. Adding or modifying an
invariant in a `FORMAL_*_MODEL.md` doc requires updating the table in the
same change.

## Current State

Invariant status is tracked in
[FORMAL_TRACEABILITY.md](FORMAL_TRACEABILITY.md). Open gaps, if any, are listed
under "Open Cross-Cutting Gaps" in that file. At the time of this roadmap
snapshot, no actionable test gaps or deferred decision gaps remain in
[FORMAL_TEST_GAPS.md](FORMAL_TEST_GAPS.md).

The current precise English model set starts with
[FORMAL_TXN_PLANNING_MODEL.md](FORMAL_TXN_PLANNING_MODEL.md), which covers the
shared `/plan` and `/sign` group-building boundary, request modes, pre-grouped
immutability, dummy/fee mutation, policy-on-finalized-data, response alignment,
and client-side simulation composition after ordinary executable signing.

[FORMAL_POLICY_MODEL.md](FORMAL_POLICY_MODEL.md) captures the policy precedence
model that gates the finalized planned group before final signing, including
the snapshot-stability story for both `policy.yaml` fields and the identity's
`user_auto_approve` setting.

[FORMAL_SIGNING_AUTHORITY_MODEL.md](FORMAL_SIGNING_AUTHORITY_MODEL.md) captures
the existing-key authority model for native keys and LogicSig keys, including
how the runtime index resolves `auth_address` to a key file and how the
selected key's stored key type drives policy overrides.

[FORMAL_LIFECYCLE_MODEL.md](FORMAL_LIFECYCLE_MODEL.md) captures runtime
decommission and lifecycle lease semantics that gate final signing, the
read/write lock relationship between `BeginOperation` and `Decommission`,
and the fixed reload step order.

[FORMAL_GUARDED_SIGNING_MODEL.md](FORMAL_GUARDED_SIGNING_MODEL.md) captures
the guarded-account co-signing workflow: role-separated component messages,
sentry transfer policy, endpoint routing as non-trust metadata, local
assembly verification against stored key-file anchors, passthrough binding,
endpoint sync behavior, and node role gates.

[FORMAL_APPROVAL_COORDINATOR_MODEL.md](FORMAL_APPROVAL_COORDINATOR_MODEL.md)
captures the runtime approval coordinator (the first M3 companion model): the
per-request approval lifecycle, single-delivery-turn serialization, the
operator approve/reject/timeout/cancel/fail-all outcomes, the fail-all mechanism
behind lifecycle L8, and how those outcomes refine the four-valued `approval`
input that `policy_precedence.tla` currently treats as a free oracle.

## Handoff Notes

This section exists so a team picking up the formalization track later can
orient quickly without reading every model doc. It records the milestone
status as of the recorded HEAD commit, the load-bearing decisions taken
during the first iteration, how to reproduce the machine-checked work,
and the relationship between the Non-Goals list above and M3.

### Snapshot HEAD

The first-wave formalization snapshot corresponded to commit
**`89decbb`** ("Close lifecycle formalization test gaps") on `main`.
The current roadmap has since been extended for the guarded signing system.
If the repository has moved since the guarded signing update, run `git log --oneline`
from the relevant formalization commit to see what changed.

**Drift review (2026-06-29, HEAD `0568e343`).** A re-sync confirmed the models
still track the code after ~360 commits of movement: all seven TLA+ modules
re-check green under TLC at the recorded state counts (2,628 / 64 / 84,096 /
48 / 196 / 47,304 / 226); the [FORMAL_TRACEABILITY.md](FORMAL_TRACEABILITY.md) anchors were
re-validated across all 65 invariants (six stale code/line anchors corrected,
no invariant lost its test); and two code changes since the snapshot were
reconciled — the then-guarded account key type `aplane.corridor.v1` (since
migrated to the separately tested `bounded-sentry1` choreography) and the plugin
`presign-plan` / `pregrouped-signed` group-mode
flows (named in Non-Goals; `presign-plan` plugin slots are modeled as foreign
slots in [FORMAL_TXN_PLANNING_MODEL.md](FORMAL_TXN_PLANNING_MODEL.md)). No
invariant changed; coverage milestones (M3 companion models, the unmodeled
S/A-series) are unchanged.

**Drift review (2026-07-21, HEAD `7d6347a0`).** Re-checked after 137 commits —
a window that added three TLA+ modules (`session_ownership`, `guarded_assembly`,
`plugin_signing`), the bounded1 framework, witness-key unification, and the
`.sen` credential split. All 13 standard and 11 deep TLC runs pass at the
recorded metrics. Diff-driven correspondence holds in every anchored area:
the decommission approval recheck (added with spec/doc in lockstep in
`1faa4775`), the session-ownership guards (`PromoteToActive` →
`FailAllPendingApprovals("apadmin displaced")` → `DisplaceSession` ordering
verified at `daemon/ipc.go`), guarded assembly (check order, role-domain/txid
binding, sender binding, abort-on-first-failure; the witness rename and
Falcon-only change already absorbed by the specs), lifecycle (decommission
step order, `BeginOperation` lease release at all sites, RWMutex
writer-priority), and plugin signing (`localSigners` removal already reflected;
`pregrouped-mixed` is not on `main`). Anchors: two stale line references
corrected (S2, L9), one imprecise test citation replaced (I10); all other
~120 file, ~95 function, ~150 test, and all TLA predicate anchors resolve.
Reconciled in this pass: the user-role `/sign/component` signer-domain gate is
now named in [FORMAL_GUARDED_SIGNING_MODEL.md](FORMAL_GUARDED_SIGNING_MODEL.md)
(narrowing-only, tracked in [FORMAL_TEST_GAPS.md](FORMAL_TEST_GAPS.md)); the
code-side canonical passthrough re-encoding check is listed in
`guarded_assembly.tla`'s intentional omissions (conservative direction); and
the lock-during-unlock generation counter is recorded as a new
[FORMAL_TEST_GAPS.md](FORMAL_TEST_GAPS.md) model-drift entry. The bounded1
planning/argument-assembly and guarded simulation surfaces were already
tracked there before this review. No spec guard diverged from code; no
invariant weakened.

**Drift review (2026-07-22, HEAD `26a5dff3`).** Re-checked after 11 commits —
the client-side signed-simulation change (PR #13) plus documentation-only
commits. All 13 standard and 11 deep TLC runs pass at the recorded metrics;
`metrics.json` is untouched in the window. Only two anchored areas moved,
both in PR #13, and both correspond: the sign boundary lost its
simulation-only authorization path (the `Simulation` gate branch,
`SignGroupForSimulationWithContext`, and the signer `/simulate` endpoints are
fully removed; mode validation, foreign/passthrough output rules, and verdict
precedence are untouched), and the plugin presign flow now routes the signed
group to client-side algod simulation (the plugin model contains no reference
to the removed branch, so nothing went stale). The approval-coordinator
fairness assumption that the ApprovalWait timer always eventually fires
strengthened rather than weakened: the removed simulation branch was the one
path that bypassed delivered-request approval. PR #13 updated
`sign_boundary.tla`'s scope note (comment-only; state space unchanged),
[FORMAL_TXN_PLANNING_MODEL.md](FORMAL_TXN_PLANNING_MODEL.md), traceability,
and correctly inverted the guarded-simulation containment gap in
[FORMAL_TEST_GAPS.md](FORMAL_TEST_GAPS.md) to "every released guarded group
passed the same user gate regardless of submit or simulate."
`pkg/signerapi/sentry.go` survives with the component-sign DTOs (only the
simulate DTOs were deleted), so the A11 anchor remains valid. Approval,
session-ownership, lifecycle, and guarded-assembly areas had no commits.
Nothing required correction in this pass.

**Bounded-sentry extension (2026-07-22).** The `bounded-sentry1` implementation
adds `bounded_sentry.tla`, a depth-4 transition model for user-first base
release, sentry request/release, final bounded assembly, and the separate
sentry-free external-admin branch. BS1-BS7 are anchored in
[FORMAL_TRACEABILITY.md](FORMAL_TRACEABILITY.md), and the former bounded DSA
planning/argument-assembly drift entry is closed in
[FORMAL_TEST_GAPS.md](FORMAL_TEST_GAPS.md). All 14 standard and 11 deep TLC runs
pass at recorded metrics; the new standard cell covers 99,584 distinct states.
The model has no deep target-count variant because its predicates are
group-wide and that input only duplicated identical states.

**Drift review (2026-07-24, HEAD `1462f3e5`).** Re-checked after 36 commits —
the bounded-sentry v1 implementation (PR #14), the endpoint-only enrollment
refactor (PR #15), and the Corridor contract-clarification docs (PR #16). All
14 standard and 11 deep TLC runs pass at recorded metrics. The dominant new
surface, bounded sentry, was modeled inside the same window
(`bounded_sentry.tla` plus BS1-BS7 anchors, added in `a4f83f4b` and trimmed in
`92438404`), and the hardening commits that landed after the model
(`1dedff71`, `3312b7e2`, `d4f1beea`, `b1e5160d`) only add validation — the
transcribed choreography still holds: base components are released only after
policy and operator approval (`approveGroupWithPlanContext`, the same gate as
ordinary signing, so the ApprovalWait fairness assumption carries over), the
frozen plan is validated before the sentry sees the group, and assembly binds
both authorities. Sign-boundary changes are conservative: ordinary `/sign` now
fail-closes on bounded-sentry keys via `boundedSentryRequired()` before mode
validation, and the guarded passthrough rejection extends to
bounded-sentry-authorized keys; the deleted `AssemblyExtraArgsProvider` hook
(Corridor migration) appears in no spec or formal doc. Session-ownership area
moved only in RPC surface (scalar policy RPCs removed, nil admin protocol
version now rejected at handshake — before the modeled auth step); unlock at
auth, disconnect-defer cleanup, `PromoteToActive`, and `DisplaceSession` had
zero diff. Approval, lifecycle, and plugin areas had no commits. Full anchor
sweep of [FORMAL_TRACEABILITY.md](FORMAL_TRACEABILITY.md) passed;
`metrics.json` matches the module table and every model-doc status header.
Nothing required correction in this pass.

### Milestone status

| Milestone | Status | Notes |
|---|---|---|
| M1: Precise English Models | Complete and active | Five `FORMAL_*_MODEL.md` docs now cover the original signing boundary plus guarded signing. |
| M2: Implementation Test Alignment | Complete and active | All numbered invariants `implemented`, `derived`, or `assumption`. `FORMAL_TEST_GAPS.md` reports no actionable gaps. |
| M3: Deferred Companion English Models | In progress | Approval coordinator and cooperative/plugin signing delivered (`FORMAL_APPROVAL_COORDINATOR_MODEL.md`, `FORMAL_PLUGIN_SIGNING_MODEL.md`). LogicSig budget and template/bytecode generation models still pending. |
| M4: Machine-Checkable Model | First wave complete | Thirteen TLA+ modules shipped. ~39 of 88 numbered invariants are machine-checked; `approval_composition.tla` adds the end-to-end approval seam, `lifecycle_composition.tla` the end-to-end lifecycle gate, `approval_coordinator.tla` carries the first liveness check (`Progress` under fairness), `session_ownership.tla` guards the admin unlock-ownership invariant, `guarded_assembly.tla` checks legacy component assembly, `bounded_sentry.tla` checks user-first bounded assembly and the sentry-free admin branch (BS1-BS7), `plugin_signing.tla` checks the plugin trust boundary (PS2-PS7), `generation_commit.tla` checks the generation commit protocol against crashes at every step (G1-G5), and `rotation_transition.tla` checks R1-R5 of the proposed key-term rotation against crashes, resume, and a filesystem attacker. Its standard negative-control config proves the pending-transition guard is load-bearing by requiring the unguarded resume mutation to violate R5. The signing-authority S-series is unmodeled **by decision** (see FORMAL_TRACEABILITY.md "Unmodeled invariants"). |
| M5: Traceability | Complete and active | `FORMAL_TRACEABILITY.md` is the durable home for invariant status. |

Machine-checked invariants by module:

| Module | Invariants covered | Recorded states | Depth |
|---|---|---|---|
| `sign_boundary.tla` | I1, I2, I3, I7, I8, output alignment, M4 target | 2,628 | 1 |
| `policy_precedence.tla` | P4, P5, P6, P7, I9, ApprovalResolution | 64 | 1 |
| `composition.tla` | 3 seam claims + 2 sign-boundary rechecks under derived verdict | 84,096 | 1 |
| `lifecycle.tla` | L4, L5, L6, L7, RWMutex exclusion, state consistency; Progress (liveness, no-symmetry config with SignerRestart: 150 states) | 48 | 10 |
| `approval_coordinator.tla` | AP4, AP5, AP6, AP7, L8, turn/state consistency; Progress (liveness, separate no-symmetry config: 833 states) | 196 | 11 |
| `approval_composition.tla` | approval-seam claims (AP2 / L8 / I9 end to end) | 47,304 | 1 |
| `lifecycle_composition.tla` | L4-L7 + lifecycle-output seam (decommission => no output); Progress (liveness, no-symmetry config: 392 states) | 226 | 12 |
| `session_ownership.tla` | SO1, SO2 (admin unlock ownership: no stranded unlock), state consistency | 90 | 8 |
| `guarded_assembly.tla` | A1, A6, A7, A8, A14, no-partial-output (component assembly verification) | 270,920 | 1 |
| `bounded_sentry.tla` | BS1-BS7 (user-first ordering, authority/source/byte checks, atomic output, admin sentry bypass) | 99,584 | 4 |
| `plugin_signing.tla` | PS2-PS7 (plugin trust boundary: digest, review fail-closed, plan preservation, byte match, approval gates) | 3,852 | 1 |
| `rotation_transition.tla` | R1-R5 (key-term rotation: live data never stranded, no laundering of injected material into the new term, completed rotation leaves rollback available, divergence never erased, resume never appends a second term) | 52 | 9 |
| `rotation_transition.tla` (`rotation_transition_negative.cfg`) | R5 negative control: unguarded resume must append T3 and violate `R5_NoSecondAppend` | 21 before expected violation | 4 |
| `generation_commit.tla` | G1-G5 (generation commit under crash: pointer never names an unpublished generation, parent sealed before flip, uncommitted attempts discarded at reconcile on an undamaged store, durability-unknown blocks signing, reconcile restores durable CURRENT) | 41 | 10 |

Not yet machine-checked: S1-S13 (entire signing-authority surface), the
guarded signing invariants not covered by
`guarded_assembly.tla` (A2-A5, A9-A13, and A15), AP1-AP3 (approval
coordinator; modeled by construction), I4-I6, CS1-CS4, P1-P3, P8-P10, L1-L3,
L9-L11.

### Verification methodology by module

The thirteen shipped modules are not all the same kind of check, and the
distinction matters when judging what TLC has and has not done:

- **`sign_boundary.tla`, `policy_precedence.tla`, `composition.tla`,
  `approval_composition.tla`, `guarded_assembly.tla`, and
  `plugin_signing.tla`** are one-shot specs: `Init` enumerates every valid input combination and
  `Next == UNCHANGED vars`. TLC's recorded depth of 1 reflects this — no
  temporal transitions are explored, because none are defined. What TLC
  verifies is that every invariant in `Safety` holds across the full
  finite product of input domains (bounded by `MaxRequestEntries`,
  `MaxDummies`, `MaxEntries`, or `MaxSlots` where applicable). This is
  **exhaustive enumeration over bounded finite domains**, expressed in
  TLA+ notation. It is a real check — a missed case in `Decide`,
  `ApplyApproval`, the output-binding seam, `Assemble`'s signature/txid
  checks, or `Submitted`'s gate conjuncts would surface as a
  counterexample (the guarded-assembly mutations drop the role check and
  the passthrough txid comparison; the plugin-signing mutations drop the
  digest and review conjuncts — all four produce initial-state
  violations) — but it does not exercise concurrency, interleaving, or
  temporal properties.

- **`lifecycle.tla`, `approval_coordinator.tla`, `lifecycle_composition.tla`,
  `session_ownership.tla`, `bounded_sentry.tla`, `generation_commit.tla`, and
  `rotation_transition.tla`** are temporal-transition specs with real
  `Next` relations and genuine state-space exploration across action
  sequences or interleavings. `bounded_sentry.tla` explores the depth-4
  base-release, sentry-release/skip, and final-output sequence; the remaining
  modules explore concurrent or crash-interleaved state machines.
  `lifecycle.tla` races two signer processes and one admin
  over a writer-priority RWMutex (depth 10); its L5 mutation test (removing
  the `readers = {}` guard from `AdminAcquireWrite`) confirms it would catch
  a lock-ordering regression. `approval_coordinator.tla` interleaves several
  approval requests over a shared single-delivery turn through to a terminal
  outcome (depth 11); its mutation tests confirm it would catch an approval
  granted after decommission (removing the `~decommissioned` guard from
  `Deliver` violates L8), a delivered prompt orphaned by client displacement
  (reverting `Displace` to the pre-fix leave-it-in-place semantics violates
  AP7), and a delivered request with no guaranteed exit (dropping the
  `Timeout` fairness conjunct violates the `Progress` liveness property with
  a lasso counterexample). Three temporal modules carry **liveness
  checks** in separate no-`SYMMETRY` configs (symmetry reduction is unsound
  for TLC liveness): `approval_coordinator_liveness.cfg` runs `LiveSpec`
  (weak fairness on `Deliver`, `Timeout`, and the decommission drain —
  guarantees the code makes; operator decisions carry no fairness) and
  verifies `Progress`: every request that reaches the coordinator eventually
  terminates. `lifecycle_liveness.cfg` adds `SignerRestart` (recurring
  signing operations — one-shot signers make writer starvation
  unfalsifiable) and verifies writer-priority starvation freedom; its
  mutation (removing `~WriterPending` from `SignerAcquire`) produces a lasso
  where reader churn starves a queued decommission forever.
  `lifecycle_composition_liveness.cfg` verifies every held lease eventually
  completes (no request left forever neither signed nor rejected); its
  mutation drops the `SignerSign` fairness conjunct.
  `lifecycle_composition.tla` adds a lease-gated signing
  step to the lifecycle race (depth 12); its mutation test (signing
  regardless of the policy decision) confirms it would catch output produced
  without a signing policy. `session_ownership.tla` interleaves admin
  sessions (authenticate-unlocks-first, atomic owner swap, uniform
  disconnect-defer exit) against one identity (depth 8); its mutation test
  (reverting the cleanup condition to the pre-fix
  `authenticated && wasActiveClient`) reproduces the stranded-unlock audit
  finding as a three-state SO2 violation, and the pre-fix displacement
  ordering under the fixed condition shows the over-lock the atomic swap
  avoids. `generation_commit.tla` explores crash and reconciliation around
  publication and the durable `CURRENT` flip. `rotation_transition.tla`
  explores append, per-object rewrap, baseline, close, crash/resume, and
  attacker injection at depth 9. Its separate depth-4 negative config is an
  expected-failure check: removing the pending guard appends T3 and violates
  R5. All seven are **true model checking** — invariants are evaluated at
  every reachable state in the transition graph.

Why call this out: TLA+ tooling does not distinguish the two styles, so
a state-count or depth number alone does not tell a reader which kind
of evidence the module provides. Treat the one-shot specs as machine-
checked case analysis over finite input domains; treat the lifecycle
and approval-coordinator specs as concurrency model checks. Both kinds
are useful; they answer different questions.

### Decisions taken during the first iteration

These are load-bearing choices that shaped the current state. Future
maintainers should know they exist before changing related code or specs.

1. **S13 was reframed from "address collision rejection" to "canonical
   filename binding."** The earlier framing imagined symmetric rejection of
   both colliding files at scan time and write-time preflight on every save.
   The reframing observes that production-code writes always use the
   canonical category-selected filename (`{address}.key` for account authority,
   `{witness_key_id}.sen` for sentry witness authority), so collisions can only
   arise from non-canonical placement. The scan now skips selector mismatches
   and category/extension mismatches with typed diagnostics;
   selector-collision rejection remains as a defensive fallback for
   impossible-state regressions. The write-time preflight was removed.

2. **S10 cross-read atomicity was resolved by materializing a per-request
   key-index snapshot.** Planning now reads key files, key types, LogicSig
   sizes, and signer-local known-address set from one copied snapshot
   (`KeyIndexSnapshot`) rather than from separate live runtime reads. A
   reload after the snapshot is captured applies only to later requests.

3. **`composition.tla` copies operators from its component modules rather
   than `INSTANCE`-importing them.** Both `sign_boundary.tla` and
   `policy_precedence.tla` declare a `verdict` variable, which would
   collide on `EXTENDS`; `INSTANCE` with renaming adds machinery for a
   small spec. TLC cannot detect drift between the copies and the
   originals — that is a code-review responsibility, not a machine-checked
   property. If mechanical linkage becomes important, extract shared
   operators into a fourth module and have all three `INSTANCE`-import.

4. **`lifecycle.tla` is the first temporal-transition spec.** The earlier
   three modules are one-shot `Init`-only specs. Lifecycle has a real
   `Next` relation with two signer processes and one admin process racing
   over a writer-priority RWMutex. The cfg sets `CHECK_DEADLOCK FALSE`
   because the workflow naturally terminates. The model encodes Go's
   writer-priority semantics via a `WriterPending` predicate; the Go test
   `TestDecommissionWaitingBlocksNewOperation` pins the assumption.

5. **L8 (Pending Approvals Fail On Successful Decommission) was deferred to
   the approval-coordinator companion model, now shipped.** It crosses the
   lifecycle/approval boundary and could not be machine-checked without
   modeling the pending-approval state machine; `approval_coordinator.tla`
   (Track B2) supplies that state machine and machine-checks L8 via the
   `badApproveAfterDecommission` history flag. The Go test
   `TestDecommissionFailsPendingApprovals` covers the implementation.

6. **The traceability table was promoted from a deferred milestone to an
   active M1 deliverable** after the S13 incident demonstrated that
   invariant status drifts silently when not tracked alongside the prose.
   The "ownership principle" is now part of M5: every invariant has a
   status, plus either a test, an assumption, or a deliberate deferral.

### TLC reproducibility

Tools used during the first iteration:

- **TLC**: TLA+ tools release v1.8.0 (`tla2tools.jar`, TLC version 2.19 of
  8 August 2024). The Formal Models CI job pins this release, downloading
  https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar
  into `.tools/tla2tools.jar`; the first iteration fetched the `releases/latest`
  jar instead.
- **Java**: CI runs the modules under Java 21 (Temurin); the first iteration
  used OpenJDK 17 (any Java 11+ should work).

Convention used during this work: the jar lives at `~/tla/tla2tools.jar`.
Adjust paths if you put it elsewhere.

The authoritative run list (spec, config, expected outcome, and expected state
counts/depths) is `docs/formal/metrics.json` — `make formal-test` runs it via
`scripts/run-formal-tests.py` and fails on any outcome or metric drift, so a
spec edit that changes the result or state space must consciously update the
recorded entry and this document's module table. `make formal-test-deep` does
the same
with larger bounds (`docs/formal/metrics_deep.json`, `*_deep.cfg`) for
pre-release or scheduled runs; `guarded_assembly` has no deep variant
(its per-entry checks are independent and `MaxEntries = 3` exceeds TLC's
set-enumeration limit — nothing new is exercised beyond `MaxEntries = 2`).
The equivalent manual commands:

```sh
java -jar ~/tla/tla2tools.jar -config docs/formal/sign_boundary.cfg        docs/formal/sign_boundary.tla
java -jar ~/tla/tla2tools.jar -config docs/formal/policy_precedence.cfg    docs/formal/policy_precedence.tla
java -jar ~/tla/tla2tools.jar -config docs/formal/composition.cfg          docs/formal/composition.tla
java -jar ~/tla/tla2tools.jar -config docs/formal/lifecycle.cfg            docs/formal/lifecycle.tla
java -jar ~/tla/tla2tools.jar -config docs/formal/approval_coordinator.cfg docs/formal/approval_coordinator.tla
java -jar ~/tla/tla2tools.jar -config docs/formal/approval_composition.cfg docs/formal/approval_composition.tla
java -jar ~/tla/tla2tools.jar -config docs/formal/lifecycle_composition.cfg docs/formal/lifecycle_composition.tla
java -jar ~/tla/tla2tools.jar -config docs/formal/session_ownership.cfg    docs/formal/session_ownership.tla
java -jar ~/tla/tla2tools.jar -config docs/formal/guarded_assembly.cfg     docs/formal/guarded_assembly.tla
java -jar ~/tla/tla2tools.jar -config docs/formal/bounded_sentry.cfg      docs/formal/bounded_sentry.tla
java -jar ~/tla/tla2tools.jar -config docs/formal/plugin_signing.cfg       docs/formal/plugin_signing.tla
java -jar ~/tla/tla2tools.jar -config docs/formal/approval_coordinator_liveness.cfg docs/formal/approval_coordinator.tla
java -jar ~/tla/tla2tools.jar -config docs/formal/lifecycle_liveness.cfg    docs/formal/lifecycle.tla
java -jar ~/tla/tla2tools.jar -config docs/formal/lifecycle_composition_liveness.cfg docs/formal/lifecycle_composition.tla
java -jar ~/tla/tla2tools.jar -config docs/formal/generation_commit.cfg     docs/formal/generation_commit.tla
java -jar ~/tla/tla2tools.jar -config docs/formal/rotation_transition.cfg   docs/formal/rotation_transition.tla
java -jar ~/tla/tla2tools.jar -noGenerateSpecTE -config docs/formal/rotation_transition_negative.cfg docs/formal/rotation_transition.tla
```

Expected results match the table above. Every positive configuration reports
"Model checking completed. No error has been found." The final negative
configuration must instead report that `R5_NoSecondAppend` is violated.
Sub-second runtime for sign_boundary, policy_precedence, and lifecycle;
~1 second for composition because of the larger joint state space.

`docs/formal/states/` is TLC scratch state created by each run. It is not
tracked in git and is regenerated on each invocation.

### Non-Goals vs M3

The Non-Goals section above lists several items ("plugin group-mode flows,"
"approval coordinator cancellation/timeout state machines," "LogicSig budget
computation internals," "LogicSig template and bytecode-generation semantics")
that also appear as M3 companion-model targets. The distinction is intentional:

- **In Non-Goals**: these are excluded from the *initial* English models
  (M1) and from the first wave of machine-checkable work (M4 first slice).
  The reason is bounded scope.
- **In M3**: the same surfaces are scheduled for later companion English
  models, once they become security-critical or once the first-wave
  machine-checked work is judged stable.

A returning team should read the Non-Goals list as "not in the first
wave" rather than "permanently out of scope." If you start an M3
companion model, the corresponding entry should move from Non-Goals to
the M3 deliverables list as part of the same change.

### How to pick up next

The approval-coordinator track is complete (`approval_coordinator.tla` +
`approval_composition.tla`, Tracks B2/B3), and lifecycle-aware composition has
shipped as `lifecycle_composition.tla` — an end-to-end machine-checked claim
that lifecycle unavailability (decommission) admits no new signer output. If
you want to extend the machine-checked surface area further, the highest-value
next slices are:

- **Signing-authority TLA+ module.** A new TLA+ artifact covering S*
  invariants — canonical filename binding, key-selection-from-`auth_address`,
  the deferred S13 fallback path. Would close the largest remaining
  unmodeled surface.
- **Liveness on lifecycle.** Add weak fairness on the admin actions;
  verify `Decommission` eventually completes. Genuinely different
  property class.

The previous operational cleanup is complete: `docs/formal/states/` is ignored,
and the Formal Models CI job runs all thirteen shipped TLC modules, three
additional liveness configs, and the R5 expected-failure negative control
through `make formal-test`, which also verifies the recorded outcomes, state
counts, and depths against `docs/formal/metrics.json`. The TLC jar
is vendored at `.tools/tla2tools.jar` (provenance and update procedure in
`.tools/README.md`): the upstream v1.8.0 release asset is re-published under
the same tag on every upstream build, so neither its URL nor a pinned
checksum of it is stable — a hash pin broke CI within a day. The vendored
jar is immutable, used by CI and local `make formal-test` alike (the
Makefile's jar lookup prefers `.tools/`), and updates land as reviewed
commits. The
signing-authority TLA+ module was evaluated and **declined by decision**
(2026-07-03; rationale in FORMAL_TRACEABILITY.md "Unmodeled invariants" —
S13 is the sole revisit-candidate). If you only have time for one new
formalization piece, the remaining M3 English models (LogicSig budget,
template/bytecode generation) are the open front.
