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
- cooperative signing and all-plugin signer-bypass behavior,
- approval coordinator cancellation/timeout state machines,
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
- `/simulate` boundary: hard-policy enforcement, no signed bytes in response,
  foreign-slot rejection, decommission/lock rejection,
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
  and decommission failure,
- cooperative signing, including `/plan` to local plugin signing to `/sign`
  passthrough flow and all-plugin server bypass,
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
3. **Lifecycle-aware composition.** Compose the temporal lifecycle
   model with the existing one-shot sign-boundary, policy-precedence,
   and composition modules. Requires reconciling temporal-transition
   state with one-shot Init state — non-trivial but valuable.
4. **Approval coordinator state machine.** State machine for pending
   approvals, timeouts, cancellations, and mid-flight decommission.
   Would compose with this lifecycle module to verify L8.
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
shared `/plan`, `/sign`, and `/simulate` group-building boundary, request modes,
pre-grouped immutability, dummy/fee mutation, policy-on-finalized-data, response
alignment, and the `/simulate`-specific contract (hard-policy-only gating, no
signed bytes in the response, foreign-slot rejection).

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

### Milestone status

| Milestone | Status | Notes |
|---|---|---|
| M1: Precise English Models | Complete and active | Five `FORMAL_*_MODEL.md` docs now cover the original signing boundary plus guarded signing. |
| M2: Implementation Test Alignment | Complete and active | All numbered invariants `implemented`, `derived`, or `assumption`. `FORMAL_TEST_GAPS.md` reports no actionable gaps. |
| M3: Deferred Companion English Models | Not started | Approval coordinator, cooperative/plugin signing, LogicSig budget, and template/bytecode generation models still pending. |
| M4: Machine-Checkable Model | First wave complete | Four TLA+ modules shipped. ~14 of 63 numbered invariants are machine-checked. |
| M5: Traceability | Complete and active | `FORMAL_TRACEABILITY.md` is the durable home for invariant status. |

Machine-checked invariants by module:

| Module | Invariants covered | Recorded states | Depth |
|---|---|---|---|
| `sign_boundary.tla` | I1, I2, I3, I7, I8, output alignment, M4 target | 2,628 | 1 |
| `policy_precedence.tla` | P4, P5, P6, P7, I9, ApprovalResolution | 64 | 1 |
| `composition.tla` | 3 seam claims + 2 sign-boundary rechecks under derived verdict | 84,096 | 1 |
| `lifecycle.tla` | L4, L5, L6, L7, RWMutex exclusion, state consistency | 48 | 10 |

Not yet machine-checked: S1-S13 (entire signing-authority surface), A1-A13
(guarded signing), I4-I6, IS1-IS6, P1-P3, P8-P10, L1-L3, L8-L11.

### Verification methodology by module

The four shipped modules are not all the same kind of check, and the
distinction matters when judging what TLC has and has not done:

- **`sign_boundary.tla`, `policy_precedence.tla`, `composition.tla`** are
  one-shot specs: `Init` enumerates every valid input combination and
  `Next == UNCHANGED vars`. TLC's recorded depth of 1 reflects this — no
  temporal transitions are explored, because none are defined. What TLC
  verifies is that every invariant in `Safety` holds across the full
  finite product of input domains (bounded by `MaxRequestEntries` and
  `MaxDummies` where applicable). This is **exhaustive enumeration over
  bounded finite domains**, expressed in TLA+ notation. It is a real
  check — a missed case in `Decide`, `ApplyApproval`, or the
  output-binding seam would surface as a counterexample — but it does
  not exercise concurrency, interleaving, or temporal properties.

- **`lifecycle.tla`** is a temporal-transition spec: two signer
  processes and one admin process race over a writer-priority RWMutex
  via a real `Next` relation. TLC's recorded depth of 10 reflects
  genuine state-space exploration across action interleavings. This is
  **true model checking** — invariants are evaluated at every reachable
  state in the transition graph, and the L5 mutation test (removing the
  `readers = {}` guard from `AdminAcquireWrite`) confirms the model
  would catch a regression in the lock-ordering logic.

Why call this out: TLA+ tooling does not distinguish the two styles, so
a state-count or depth number alone does not tell a reader which kind
of evidence the module provides. Treat the one-shot specs as machine-
checked case analysis over finite input domains; treat the lifecycle
spec as a concurrency model check. Both are useful; they answer
different questions.

### Decisions taken during the first iteration

These are load-bearing choices that shaped the current state. Future
maintainers should know they exist before changing related code or specs.

1. **S13 was reframed from "address collision rejection" to "canonical
   filename binding."** The earlier framing imagined symmetric rejection of
   both colliding files at scan time and write-time preflight on every save.
   The reframing observes that production-code writes always use the
   canonical `{address}.key` filename, so collisions can only arise from
   non-canonical placement (manual file copies, legacy artifacts). The scan
   now skips filename-vs-payload mismatches with a `KeyScanWarningFilenameAddressMismatch`
   warning; address-collision rejection remains as a defensive fallback for
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

5. **L8 (Pending Approvals Fail On Successful Decommission) is deferred to
   the approval-coordinator companion model.** It crosses the
   lifecycle/approval boundary and cannot be machine-checked meaningfully
   without modeling the pending-approval state machine. The Go test
   `TestDecommissionFailsPendingApprovals` covers the implementation; the
   TLA+ check is deferred, not abandoned.

6. **The traceability table was promoted from a deferred milestone to an
   active M1 deliverable** after the S13 incident demonstrated that
   invariant status drifts silently when not tracked alongside the prose.
   The "ownership principle" is now part of M5: every invariant has a
   status, plus either a test, an assumption, or a deliberate deferral.

### TLC reproducibility

Tools used during the first iteration:

- **TLC**: version 2.19 of 8 August 2024 (`tla2tools.jar`), downloaded from
  https://github.com/tlaplus/tlaplus/releases/latest/download/tla2tools.jar.
- **Java**: OpenJDK 17 (any Java 11+ should work).

Convention used during this work: the jar lives at `~/tla/tla2tools.jar`.
Adjust paths if you put it elsewhere.

Run all four modules in sequence from the repo root:

```sh
java -jar ~/tla/tla2tools.jar -config docs/formal/sign_boundary.cfg     docs/formal/sign_boundary.tla
java -jar ~/tla/tla2tools.jar -config docs/formal/policy_precedence.cfg docs/formal/policy_precedence.tla
java -jar ~/tla/tla2tools.jar -config docs/formal/composition.cfg       docs/formal/composition.tla
java -jar ~/tla/tla2tools.jar -config docs/formal/lifecycle.cfg         docs/formal/lifecycle.tla
```

Expected results match the table above. Each module reports "Model
checking completed. No error has been found." Sub-second runtime for
sign_boundary, policy_precedence, and lifecycle; ~1 second for
composition because of the larger joint state space.

`docs/formal/states/` is TLC scratch state created by each run. It is not
tracked in git and is regenerated on each invocation.

### Non-Goals vs M3

The Non-Goals section above lists several items ("cooperative signing and
all-plugin signer-bypass behavior," "approval coordinator
cancellation/timeout state machines," "LogicSig budget computation
internals," "LogicSig template and bytecode-generation semantics") that
also appear as M3 companion-model targets. The distinction is intentional:

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

If you want to extend the machine-checked surface area, the highest-value
next slice is:

- **Approval coordinator companion model (M3).** Closes L8's
  machine-checked gap and refines the four-valued `approval` input used by
  `policy_precedence.tla` and `composition.tla`. Probably the
  highest-leverage single piece of remaining work.

Alternatives, in rough order of value:

- **Lifecycle-aware composition.** Joins `lifecycle.tla` (temporal) with
  the existing one-shot composition module. Non-trivial because it
  requires reconciling temporal-transition state with one-shot Init state,
  but unlocks an end-to-end machine-checked claim about "lifecycle
  unavailability implies empty signer output."
- **Signing-authority TLA+ module.** A fifth TLA+ artifact covering S*
  invariants — canonical filename binding, key-selection-from-`auth_address`,
  the deferred S13 fallback path. Would close the largest remaining
  unmodeled surface.
- **Liveness on lifecycle.** Add weak fairness on the admin actions;
  verify `Decommission` eventually completes. Genuinely different
  property class.

The previous operational cleanup is complete: `docs/formal/states/` is ignored,
and the Formal Models CI job runs all four shipped TLC modules through
`make formal-test`. If you only have time for one new formalization piece, start
with the approval coordinator companion model.
