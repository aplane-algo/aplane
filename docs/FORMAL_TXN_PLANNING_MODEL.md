# Formal Transaction Planning Model

> Status: precise English model, not machine-checked.
> This document formalizes the current transaction planning and signing-boundary
> semantics described by APlane's architecture docs.
> Invariant status (implemented / intended / deferred / etc.) is tracked in
> [FORMAL_TRACEABILITY.md](FORMAL_TRACEABILITY.md).

## Sources

Normative inputs:

- [ARCH_TXNFLOW.md](ARCH_TXNFLOW.md): request modes, group canonicalization,
  pre-grouped immutability, dummies, fee adjustment, and response alignment.
- [ARCH_HTTP_API.md](ARCH_HTTP_API.md): `/plan`, `/sign`, and `/simulate`
  contract surface.
- [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md): approval/policy compatibility,
  lifecycle, and signing-authority contracts.
- [ARCH_POLICY.md](ARCH_POLICY.md): policy verdict precedence and snapshot
  semantics.
- [ARCH_NETWORKS.md](ARCH_NETWORKS.md): transaction `GenesisHash` resolution for
  policy and planning.
- [FORMAL_POLICY_MODEL.md](FORMAL_POLICY_MODEL.md): policy precedence semantics
  applied after planning.
- [FORMAL_SIGNING_AUTHORITY_MODEL.md](FORMAL_SIGNING_AUTHORITY_MODEL.md):
  sign-mode authority requirements.
- [FORMAL_LIFECYCLE_MODEL.md](FORMAL_LIFECYCLE_MODEL.md): final signing
  lifecycle lease semantics.

This model intentionally stays below the full daemon and above concrete Go code.
It describes what must be true of accepted transaction-planning and signing
requests, not how every byte parser or goroutine implements it.

## Notation

Pseudo-formal snippets in this document are relational pseudocode. `Reject(...)`
means no successful result exists for that input. `Sign(...) = signed` means the
request completed successfully with result `signed`.

## Abstract Objects

### Transaction

`Txn` is an Algorand transaction after successful decoding. The model observes:

- `group_id`
- `genesis_hash`
- `genesis_id`
- `sender`
- `auth_address`, as resolved for signer-owned signing work
- `fee`
- transaction fields relevant to warnings and policy, such as rekey, close,
  clawback, amount, asset ID, note, and lease

The model treats msgpack decoding, transaction ID calculation, and Algorand
signature verification as external primitives.

### Request Entry

Every request entry has exactly one mode:

| Mode | Fields | Meaning |
|------|--------|---------|
| `sign` | `auth_address` and `txn_bytes_hex` | signer-controlled slot that may be signed by this signer |
| `passthrough` | `signed_txn_hex` | already-signed slot preserved by this signer |
| `foreign` | `txn_bytes_hex` without `auth_address`; optional `lsig_size` | context slot owned by another signer |

Invalid field combinations reject before planning starts.

### Request

`Request` is the ordered list of request entries plus endpoint metadata such as
`request_id`. Request entry order is the caller's intended group order before
server-added dummy slots.

### Planning Snapshot

`PlanningSnapshot` contains the stable runtime data needed for one planning
attempt:

- signer identity,
- key metadata needed to classify signer-owned slots and LogicSig budgets,
- network genesis-hash resolver,
- dummy transaction template and size/budget rules,
- fee-pooling rules,
- policy snapshot for `/sign` and `/simulate` policy phases.

For plan/sign parity, two snapshots are equivalent only when all values that can
affect planning are equal, including key metadata, LogicSig budget inputs, dummy
template fields, fee-pooling rules, network resolver, and group construction
rules.

The snapshot abstracts over locks and reload mechanics. Runtime snapshot
semantics are modeled separately by the policy and lifecycle models.

### Planned Group

`PlannedGroup` is the finalized unsigned group after successful planning:

- caller-requested transactions in finalized order,
- any server-added dummy transactions appended to the group,
- final group IDs,
- final fees,
- slot class for each finalized position (one of `sign`, `passthrough`,
  `foreign`, or `dummy`); the first three classes carry the request's
  `Mode` value verbatim, the fourth marks server-added positions,
- `RequestToFinalized`, a total mapping from each caller request index to the
  corresponding finalized group index,
- `FinalizedToRequest`, a partial inverse for finalized positions that came
  from caller request entries,
- mutation metadata such as dummies added, fees changed, group ID changed,
  passthrough count, and foreign count.

Server-added dummy positions are appended after caller request positions and
have no request index. Therefore:

```text
FinalizedIndex(i) = RequestToFinalized[i]
RequestIndex(j) = FinalizedToRequest[j] when j is not a dummy position
```

`/plan` returns the finalized unsigned transaction bytes from this object.
`/sign` uses this same object as its pre-approval, pre-signing input.

## Endpoint Abstraction

Define:

```text
Plan(snapshot, request)                          -> PlannedGroup | Reject
Sign(snapshot, request, approval_result)         -> SignedGroup  | Reject
Simulate(snapshot, request)                      -> SimulateResult | Reject
```

`Sign` is decomposed as:

```text
planned   = Plan(snapshot, request)
decision  = PolicyAndApproval(snapshot.policy, planned, approval_result)
signed    = ExecuteSigning(snapshot, planned, decision)
```

`Simulate` is decomposed as:

```text
planned   = Plan(snapshot, request)                       // same as /plan
if ExistsForeign(planned): reject                         // IS5
hardOnly  = HardPolicyOnly(snapshot.policy, planned)      // IS2
if hardOnly rejects: reject
internal  = ExecuteSigning(snapshot, planned, hardOnly)   // never exposed; IS4
result    = AlgodSimulate(internal)                       // unsigned bytes + diagnostics
```

Planning always runs first; rejection decisions in IS2 and IS5 occur after
planning has produced a finalized group. Implementations may detect foreign
content earlier or later than the current `internal/signerapp/rest/simulate.go`
ordering as long as planning still yields the canonical group for IS1's
purposes.

`Plan` performs group building only. It does not approve a request, produce
signatures, or assemble final LogicSig authorizations. `/plan` may still require
unlocked signer metadata because LogicSig budget calculation depends on key
metadata.

`Plan` is deterministic for a fixed request and equivalent planning snapshot:

```text
EquivalentSnapshot(s1, s2) =>
  Plan(s1, request) = Plan(s2, request)
```

Any dummy transaction generated by planning must be a deterministic function of
the request and planning snapshot. The model excludes random nonces, wall-clock
timestamps, or other ambient process state from dummy generation.

### Cross-Endpoint Snapshot Divergence

`/plan` and `/sign` arrive as separate HTTP requests and therefore observe
separate planning snapshots `s_plan` and `s_sign`. The model does not require
the caller to prove `EquivalentSnapshot(s_plan, s_sign)`; instead it requires
that `/sign` re-plans against its own snapshot and uses *that* result for
policy, approval, and signing. A `/sign` request that observed a tighter
policy or a different lifecycle/lock state since `/plan` may therefore reject,
require review, or produce different mutation metadata even when the
caller-supplied request bytes are byte-identical to the earlier `/plan` call.
There is no caller-presented "plan token" that binds a `/plan` snapshot into
a later `/sign`.

Plan/sign planning parity (I4) is therefore a property of equivalent snapshots,
not a property of separate HTTP calls. Implementations may not skip `/sign`'s
own planning step.

## Planning Rules

### Mode Validation

1. Every entry must classify as exactly one of `sign`, `passthrough`, or
   `foreign`.
2. Passthrough and foreign entries must not appear in the same request.
3. All-foreign requests reject because the signer has no managed work to
   perform.
4. Sign-mode entries must resolve to signer-managed signing authority.
5. Foreign entries are never signer-owned work, even when they participate in
   planning context.

### Decode and Network Validation

1. Sign and foreign entries decode unsigned transaction bytes from
   `txn_bytes_hex`.
2. Passthrough entries decode signed transaction bytes from `signed_txn_hex`.
3. Decode failures reject.
4. Every transaction must resolve through the configured `GenesisHash` network
   resolver.
5. All transactions in one request must have the same `GenesisHash`.
6. `GenesisID` is display and diagnostic data only; it is not the authority for
   planning or policy network lookup.

### Pre-Grouped Immutability

1. A request with a pre-existing group ID is immutable.
2. Immutable requests must preserve transaction order, fees, and group IDs.
3. If an immutable request would require dummy insertion, fee adjustment, or
   group-ID recomputation, planning rejects.
4. Passthrough requests require a pre-formed group shape because existing
   signatures would be invalidated by mutation.

### Ungrouped Canonicalization

For accepted ungrouped requests:

1. The server determines the finalized group shape.
2. LogicSig budget is computed for sign-mode entries and for foreign entries
   that provide `lsig_size`.
3. Required dummy transactions are generated deterministically from the request
   and planning snapshot, then appended to the finalized group.
4. Dummy insertion that would exceed Algorand group-size limits rejects.
5. Fees are adjusted or pooled according to the finalized group.
6. The group ID is computed over the finalized unsigned transactions.
7. `RequestToFinalized` maps every original request position to its finalized
   group position.
8. Mutation metadata records every dummy, fee, or group-ID change.

Single ungrouped requests with no large LogicSig budget requirement may remain
ungrouped, matching the current transaction-flow contract.

## Policy and Approval Boundary

Planning precedes policy and approval for `/sign` and `/simulate`.

Policy evaluation observes the finalized planned data:

- final fees,
- final group IDs,
- server-added dummy effects,
- signer-owned slots,
- passthrough and foreign slots as group context.

Transaction-level hard policy applies only to signer-controlled sign-mode slots.
Passthrough and foreign slots are not signed by this signer, but they remain
visible to group consistency checks, approval context, warning analysis, and
audit.

Policy verdict precedence is:

```text
Always Deny > Always Review > Always Approve > Operator Default
```

Therefore:

1. Any Always Deny match rejects before approval.
2. Any Always Review match requires operator approval and blocks Always Approve
   and `user_auto_approve:true`.
3. Always Approve can sign without operator approval only when no Always Deny
   or Always Review rule matched.
4. `user_auto_approve` is only the fallback after policy verdicts.

## Signing Output Rules

For an accepted `/sign` request:

1. `signed[]` aligns 1:1 with finalized group positions.
2. Sign-mode slots contain newly signed or assembled transaction bytes.
3. Passthrough slots contain exactly the original `signed_txn_hex` bytes.
4. Foreign slots contain `""`.
5. Server-added dummy slots contain signer-generated signed dummy transactions.
6. No output signature may be produced for a foreign slot.
7. No passthrough output may be altered by the signer.

## Invariants

### I1: Mode Totality

Every accepted request entry has one and only one mode.

```text
Accepted(request) =>
  forall entry in request.entries:
    CountTrue(IsSign(entry), IsPassthrough(entry), IsForeign(entry)) = 1
```

### I2: Passthrough-Foreign Exclusion

No accepted request mixes passthrough and foreign modes.

```text
Accepted(request) =>
  not (ExistsPassthrough(request) and ExistsForeign(request))
```

### I3: All-Foreign Rejection

No all-foreign request is accepted.

```text
Accepted(request) => not AllEntriesAreForeign(request)
```

### I4: Plan/Sign Planning Parity

For the same request and equivalent planning snapshot, `/plan` and `/sign`
produce the same finalized unsigned group before `/sign` runs policy and
signing.

```text
EquivalentSnapshot(plan_snapshot, sign_snapshot) and
Plan(plan_snapshot, request) = planned =>
  SignPlanningStage(sign_snapshot, request) = planned
```

The invariant is about finalized unsigned transaction contents and group
position metadata, not about `/sign` response bytes after signatures are added.

### I5: Pre-Grouped Immutability

Accepted pre-grouped requests are never mutated.

```text
Accepted(request) and PreGrouped(request) =>
  planned.order = request.order and
  planned.fees = request.fees and
  planned.group_ids = request.group_ids and
  planned.dummies_added = 0
```

If those equalities cannot hold because LogicSig budget requires mutation,
planning rejects.

### I6: Finalized Data Is Reviewed

Any policy, warning, approval, or signing decision observes the planned
transaction data, not the caller's pre-planning draft.

```text
Sign(snapshot, request, approval) = signed =>
  PolicyInput(Sign) = Plan(snapshot, request).finalized_group
```

### I7: Foreign Slots Are Never Signed

For every accepted `/sign` request, foreign group positions produce no signer
signature.

```text
signed = Sign(snapshot, request, approval) =>
  forall i in RequestPositions(request):
    ModeAtRequest(i) = foreign =>
      signed.output[RequestToFinalized[i]] = ""
```

### I8: Passthrough Byte Preservation

For every accepted `/sign` request, passthrough bytes are returned unchanged.

```text
signed = Sign(snapshot, request, approval) =>
  forall i in RequestPositions(request):
    ModeAtRequest(i) = passthrough =>
      signed.output[RequestToFinalized[i]] = request.entries[i].signed_txn_hex
```

### I9: Hard Deny Dominance

An Always Deny policy match cannot be overridden by operator approval, Always
Approve, or `user_auto_approve:true`.

```text
Plan(snapshot, request) = planned and
AlwaysDenyMatches(snapshot.policy, planned) =>
  forall approval: Sign(snapshot, request, approval) rejects
```

### I10: Network Hash Authority

Planning and policy network selection are determined by `GenesisHash` alone.
`GenesisID` is not an input to network selection.

```text
forall txn1, txn2:
  txn1.genesis_hash = txn2.genesis_hash =>
    NetworkForPlanning(txn1) = NetworkForPlanning(txn2) and
    NetworkForPolicy(txn1)   = NetworkForPolicy(txn2)
```

In particular, varying only `genesis_id` while holding `genesis_hash` constant
must not change the selected network bucket. Unknown genesis hashes reject
before policy can select the wrong bucket.

## Simulate Endpoint Invariants

`/simulate` is a separate boundary from `/sign` even though it reuses the same
request grammar and shares planning. The invariants below describe what
`/simulate` must and must not do.

### IS1: Simulate Plans Like Sign

`/simulate` runs the same canonical group-building procedure as `/plan` and
`/sign`. The invariant is about the planning *step* inside `/simulate`, not
about the overall `/simulate` result; `/simulate` may still reject after
planning (for foreign placeholders per IS5, or for hard-policy/lifecycle
reasons per IS2 and IS6).

```text
EquivalentSnapshot(s_plan, s_sim) and
SimulatePlanningStage(s_sim, request) = planned_sim =>
  planned_sim = Plan(s_plan, request)
```

This decouples the planning equivalence from the rest-of-simulate gate:
implementations may not skip planning, and the planning output must match
`/plan`, but a `/simulate` accept additionally requires the request to
satisfy IS2, IS5, and IS6.

### IS2: Simulate Enforces Hard Policy

Always Deny policy verdicts reject before any signing or algod simulation.

```text
AlwaysDenyMatches(snapshot.policy, Plan(snapshot, request)) =>
  Simulate(snapshot, request) rejects
```

### IS3: Simulate Does Not Wait For Operator Approval

`/simulate` does not block on operator approval. Always Review matches
proceed to internal signing without prompting; the entire procedure is
self-contained inside the signer process.

```text
AlwaysReviewMatches(snapshot.policy, Plan(snapshot, request)) =>
  Simulate(snapshot, request) does not enqueue a PendingApproval
```

This compensates for the response never exposing signed bytes (see IS4): an
operator review prompt for a simulation that no one signs would be pure
friction. Implementations that change this trade-off must update IS3.

### IS4: Simulate Never Exposes Signed Bytes

The `/simulate` response contains only finalized unsigned transaction bytes
and diagnostics. No element of the response contains a signature produced by
this signer.

```text
Simulate(snapshot, request) = result =>
  forall i: result.transactions[i] is an unsigned transaction encoding and
            contains no signer-produced signature
```

The internally generated signed bytes used by algod simulation are
process-local; they do not appear in any wire response.

### IS5: Simulate Rejects Unresolved Foreign Slots

Foreign-mode entries provide unsigned bytes from another signer. `/sign` may
accept them as context-only slots. `/simulate` cannot, because algod
simulation needs every group position to carry a usable signature. The caller
must instead supply the corresponding signed bytes as a passthrough entry.

```text
ExistsForeign(request) => Simulate(snapshot, request) rejects
```

### IS6: Simulate Honors Lifecycle And Unlock State

A decommissioned or locked identity rejects `/simulate` for the same reasons
it rejects `/sign`.

```text
runtime.decommissioned or not runtime.unlocked =>
  Simulate(snapshot, request) rejects
```

## Assumptions

This model assumes:

- Algorand transaction decoding is deterministic.
- Algorand group ID calculation is deterministic and correct.
- Cryptographic signing primitives satisfy their normal correctness properties.
- The planning snapshot is internally consistent for the duration of one
  request.
- The implementation's key metadata accurately reports LogicSig budget
  requirements for signer-owned slots.
- LogicSig budget computation is an assumed-correct primitive in this model; a
  later companion model should cover the budget calculation itself.
- Foreign `lsig_size` is advisory and may be wrong; this model only requires
  that the planner uses the hint consistently.

## Non-Goals

This model does not prove:

- correctness of Ed25519 or Falcon algorithms,
- TEAL semantics,
- operator choices during manual approval,
- HTTP authentication or authorization,
- request cancellation behavior,
- filesystem reload ordering,
- decommission lifecycle races,
- backup/restore behavior,
- future witness or compliance-sentry semantics.

Those belong in separate models or assumptions.

## Code and Test Anchors

These anchors are advisory pointers for traceability. They are not part of the
model and should be refreshed when code is renamed or ownership moves.

Implementation areas that should remain aligned with this model:

- `internal/signerapp/signing/planner.go`
- `internal/signerapp/signing/service.go`
- `internal/signerapp/signing/execution.go`
- `internal/signerapp/signing/approval.go`
- `internal/signerapp/signing/always_review.go`
- `internal/signerapp/signing/simulation.go`
- `internal/signerapp/rest`
- `pkg/signerapi`
- `internal/signerclient`

High-value test anchors:

- mode classification rejects invalid combinations,
- passthrough and foreign cannot mix,
- all-foreign rejects,
- pre-grouped groups requiring dummies reject,
- `/plan` and `/sign` share the same finalized unsigned group,
- policy thresholds use adjusted fees,
- foreign slots return `""`,
- passthrough bytes return unchanged,
- Always Deny wins over every later approval path,
- `/simulate` produces the same finalized unsigned group as `/plan`,
- `/simulate` rejects on Always Deny without invoking algod,
- `/simulate` rejects requests containing foreign-mode entries,
- `/simulate` response never contains signer-produced signed bytes,
- `/simulate` rejects decommissioned or locked identities.

## Open Questions

These are not blockers for the model, but they should be resolved before a
machine-checkable version:

1. Define the smallest implementation-level representation of an "equivalent
   planning snapshot" for `/plan` and `/sign` parity tests.
2. Decide whether passthrough `/plan` responses should be modeled as unsigned
   transaction projections only, or whether signed-byte preservation should be a
   `/sign`-only invariant.
3. Identify all current tests that already cover each invariant before adding
   new test cases.
