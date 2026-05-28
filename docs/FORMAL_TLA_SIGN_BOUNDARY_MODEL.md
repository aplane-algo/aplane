# Sign Boundary TLA+ Model

> Status: TLC checked with `MaxRequestEntries = 3` and `MaxDummies = 2`;
> the recorded bounded run found no counterexamples.

The roadmap's M4 milestone calls for a "small TLA+ or Alloy model for
transaction planning and policy precedence." This document tracks the
first machine-checkable artifact: a narrow TLA+ module that encodes the
request modes, the request-to-finalized mapping, and the output
behavior for each slot class. It also checks deny-output suppression,
but does not yet model hard-deny dominance.

The spec lives at [formal/sign_boundary.tla](formal/sign_boundary.tla).

## What it covers

| Invariant | Source | TLA+ predicate |
|---|---|---|
| I1: Mode Totality | FORMAL_TXN_PLANNING_MODEL.md | Structural via `RequestMode` partition |
| I2: Passthrough-Foreign Exclusion | FORMAL_TXN_PLANNING_MODEL.md | `ValidRequest` clause |
| I3: All-Foreign Rejection | FORMAL_TXN_PLANNING_MODEL.md | `ValidRequest` clause |
| I7: Foreign Slots Are Never Signed | FORMAL_TXN_PLANNING_MODEL.md | `ForeignSlotsEmpty` |
| I8: Passthrough Byte Preservation | FORMAL_TXN_PLANNING_MODEL.md | `PassthroughPreserved` |
| Output alignment | Signing Output Rules | `OutputAligned` |
| M4 target | FORMALIZATION_ROADMAP.md | `SignerOutputBelongsToOwnedClass` |

The module also defines `DenyOutputSuppression` (verdict = "deny" =>
output = <<>>), but this is *not* a check of I9 (Hard Deny Dominance).
In the current spec `verdict` is a free oracle and `output` is
computed from it directly, so `DenyOutputSuppression` is true by
construction of `Init`. Verifying real I9 requires a future module
that derives verdicts from policy rule tiers; see the Extension plan
below.

## What it deliberately does not cover

The TLA+ slice is the M4 *first* target. It excludes anything not
strictly needed for the covered predicates above:

- Cryptographic correctness (Ed25519, Falcon, signature validity).
- Algorand transaction layout, msgpack decode, group-ID computation.
- LogicSig budget, fee adjustment, group-ID regrouping.
- `/simulate` boundary (separate module if/when needed).
- Approval coordinator: always-review tier, operator decisions,
  timeouts.
- Lifecycle leases, decommission, identity routing.
- Filesystem reload, key scan, snapshot consistency.
- HTTP authentication, principal authorization.
- Network selection from `GenesisHash` (modeled as out-of-band).

If you find yourself adding any of these to `sign_boundary.tla`, stop
and create a separate module instead. The point of M4 is to demonstrate
that *one* invariant can be machine-checked, not to model the whole
daemon.

## Modeling choices

### One-shot vs stuttering specification

The module is one-shot: `Init` enumerates every valid
(request, dummies, verdict) combination, and `Next` is a stutter that
leaves state unchanged. This works because the checked predicates are
about a single accepted (or rejected) `/sign` execution, not about
sequences of executions. If a future invariant requires reasoning
across requests (e.g. snapshot stability across approval-wait), the
spec will need real next-state transitions.

### Opaque payloads

`signed_id : 1..3` is a finite token domain that stands in for
`signed_txn_hex`. The model never inspects bytes; it only checks that
passthrough output equals the token-derived string. This decouples I8
from any claim about Algorand encoding.

### Dummy count is nondeterministic

`Plan(r, d)` accepts any dummy count `d \in 0..MaxDummies`. The model
does not encode budget calculation; doing so would conflate I7/I8/I9
with the LogicSig budget invariants, which the planning model treats
as an assumed-correct primitive.

### Verdict is an oracle

`verdict \in {"deny", "approve"}` is a free input, not derived from
rules. This isolates I9 from the full policy decision procedure. A
later module can refine the oracle to the verdict-precedence ladder
from FORMAL_POLICY_MODEL.md.

## How to check

The spec is written in standard TLA+ syntax. To check it manually:

1. Install the TLA+ Toolbox or the `tla2tools` jar.
2. A ready-to-use TLC config lives at
   [formal/sign_boundary.cfg](formal/sign_boundary.cfg). It declares
   `SPECIFICATION Spec`, sets `MaxRequestEntries = 3` and
   `MaxDummies = 2`, and asks for `INVARIANT Safety`. `SPECIFICATION
   Spec` is required; without it TLC has no temporal formula to
   model-check against.

3. Run TLC, e.g.:

   ```
   java -cp tla2tools.jar tlc2.TLC -config docs/formal/sign_boundary.cfg docs/formal/sign_boundary.tla
   ```

   With those bounds, the model has a small enough state space to
   enumerate completely.

The recorded TLC run at these bounds generated 2,628 distinct initial
states, reached depth 1, and found no counterexamples for `Safety`.
Depth 1 is expected: this is a one-shot model where `Next` only
stutters. The value is in *re-running* TLC when the spec changes —
drift in the model that violates I7 or I8 will surface as a
counterexample trace.

## Linking back

- Every invariant in this module has a row in
  [FORMAL_TRACEABILITY.md](FORMAL_TRACEABILITY.md); when a TLA+ check
  exists for an invariant, that row should reference this file.
- The roadmap's M4 milestone in
  [FORMALIZATION_ROADMAP.md](FORMALIZATION_ROADMAP.md) tracks broader
  goals; this document is the first concrete artifact under that
  milestone.

## Extension plan

Already shipped:

- **Policy precedence (M4 extension).**
  [formal/policy_precedence.tla](formal/policy_precedence.tla) derives
  `verdict` from rule application and verifies P4-P7 + a real I9 (Hard
  Deny Dominance). See
  [FORMAL_TLA_POLICY_PRECEDENCE_MODEL.md](FORMAL_TLA_POLICY_PRECEDENCE_MODEL.md).
- **Composition with policy_precedence.**
  [formal/composition.tla](formal/composition.tla) joins the two
  modules. The verdict that this module treats as a free oracle is
  here derived through `policy_precedence`, and the joint Init feeds
  that derived outcome into `SignOutput`. The bridge invariant
  `PolicyOutcomeBindsOutput` ties policy outcome to signing output;
  `HardDenyProducesNoOutput` promotes `DenyOutputSuppression` from a
  by-construction placeholder into a derived consequence. See
  [FORMAL_TLA_COMPOSITION_MODEL.md](FORMAL_TLA_COMPOSITION_MODEL.md).

Already shipped (continued):

- **Lifecycle lease.** [formal/lifecycle.tla](formal/lifecycle.tla)
  models `BeginOperation` / `Decommission` as real transitions and
  verifies L4-L7 plus the writer-priority RWMutex ordering. See
  [FORMAL_TLA_LIFECYCLE_MODEL.md](FORMAL_TLA_LIFECYCLE_MODEL.md).

Next likely modules, in order of value:

1. **Lifecycle-aware composition.** Compose the temporal lifecycle
   model with the existing one-shot sign-boundary / policy-precedence
   / composition modules so that lifecycle unavailability forces
   empty signer output. Requires reconciling temporal-transition
   state with one-shot Init state.
2. **Approval coordinator (M3 prerequisite).** State machine for
   pending approvals, including timeout and cancellation. Would refine
   the four-valued `approval` input in `policy_precedence.tla` (and
   inherited by `composition.tla`).
3. **Reload-during-request stability.** Adds real transitions to
   composition so that reloads between approval and final-sign do not
   change the snapshot used by the request. This is the P2 leg covered
   by `TestSignGroupWithPlanDoesNotReevaluatePolicyAfterApproval` in
   Go; promoting it into a TLA+ refinement check is the natural future
   move.

The current `sign_boundary.tla` should not absorb any of these; each
gets its own module and either composes or refines.
