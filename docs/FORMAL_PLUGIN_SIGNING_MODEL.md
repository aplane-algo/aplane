# Plugin Signing Model

> Status: precise English model (M3 companion). Machine-checked subset in
> [formal/plugin_signing.tla](formal/plugin_signing.tla) (see
> [FORMAL_TLA_PLUGIN_SIGNING_MODEL.md](FORMAL_TLA_PLUGIN_SIGNING_MODEL.md)).

This model covers the cooperative/plugin signing surface: transaction groups
built (and partially signed) by an external plugin process, submitted through
apshell. It was the M3 backlog item "cooperative/plugin signing"; it is also
the model that would have made the since-removed `localSigners` review bypass
visible as a missing guard, which is why its central claim is stated first.

## Central claim

**PS7 (No Ungated Submission).** No plugin-produced transaction bytes reach
submission unless they passed exactly one of the two human gates:

- **pregrouped-signed**: a mandatory interactive review of the *decoded actual
  bytes* on the client, which the plugin cannot waive and which fails closed
  in non-interactive modes; or
- **presign-plan**: apsigner's approval pipeline over the canonical group,
  which displays every slot (including the plugin's passthrough slots) and
  disables auto-approval for such groups.

The legacy third path (`localSigners`, plugin-supplied keys signing locally
with a plugin-controlled, content-free prompt) violated this claim and was
removed; `apshellapp/submission.go` now rejects it outright.

## Scope

Two surviving plugin group modes plus the shared trust machinery:

- **pregrouped-signed** (`GroupModePregroupedSigned`): the plugin delivers a
  complete, fully signed group; apsigner is not involved; the client
  validates, reviews, and submits byte-verbatim.
- **presign-plan** (`GroupModePresignPlan`): the plugin declares callback
  signers; the group is planned by the signer (`/plan`), plugin slots are
  signed by the plugin against the canonical bytes, managed slots by apsigner
  (`/sign`), and the results are merged and submitted.

Out of scope: the plugin process protocol itself (JSON-RPC, sandboxing,
manifests — `docs/ARCH_PLUGINS.md`), guarded-account component assembly
([FORMAL_GUARDED_SIGNING_MODEL.md](FORMAL_GUARDED_SIGNING_MODEL.md)), and the
generic passthrough machinery already modeled in
[FORMAL_TXN_PLANNING_MODEL.md](FORMAL_TXN_PLANNING_MODEL.md) (I7/I8).

## Abstract objects

- **Intent**: a plugin-produced transaction, `type:"raw"` (unsigned draft) or
  `type:"signed"` (finished bytes). Mode dispatch is total: signed intents
  are accepted only by the pregrouped-signed path
  (`internal/engine/plugin_transactions.go` accepts only `"raw"`).
- **PregroupedSignedGroup**: decoded transactions paired with the exact raw
  byte blobs they were decoded from. Both fields are unexported and
  `DecodePregroupedSigned` is the sole constructor
  (`internal/engine/plugin_pregrouped.go`), so the validated/displayed view
  and the submitted bytes cannot be paired with unrelated data.
- **Canonical group**: the `/plan` response — the transactions that will
  actually be signed and submitted in presign-plan mode.
- **Gates**: the client's interactive review, and apsigner's approval
  pipeline.

## Invariants

### PS1: Constructor Byte Binding (structural)

What pregrouped-signed submits is exactly `raw[i]` — the blobs whose decodes
were validated and rendered. Binding is decode provenance enforced by the
type (unexported fields, sole constructor), not a runtime comparison.
Anchor: `plugin_pregrouped.go` (fields, constructor, byte-verbatim
submission via `SubmitTransactionsWithContext(ctx, g.raw, ...)`).

### PS2: Group Digest Integrity

A pregrouped group is accepted only if recomputing the group ID over the
presented transactions (with `Group` cleared) equals the digest embedded in
every slot; all slots must carry the same non-zero group field, and the
group must have 2..MaxTxGroupSize members. This catches reordering, subsets,
substituted or injected transactions — any presented set differing from the
one the digest was computed over. apsigner independently runs the same
recomputation on pre-grouped passthrough groups
(`internal/signerapp/signing/planner.go` "claimed group ID does not match").
Anchors: `plugin_pregrouped.go` (size, uniform group, `ComputeGroupID`
comparison), `planner.go`.

### PS3: Mandatory Decoded Review, Fail-Closed

Pregrouped-signed review is unconditional: the plugin's `RequiresApproval`
flag is ignored, the rendering decodes the actual bytes (sender, type, fee;
pay amount/receiver/close-to; app id with args marked opaque; other types
marked opaque — opacity is displayed, never hidden), and non-interactive
contexts (`AutoConfirm`, MCP) fail closed with an explicit error. Validation
precedes rendering: the review path itself constructs the
`PregroupedSignedGroup`, so an undecodable or digest-tampered group errors
before anything is shown. Anchors: `internal/apshellcli/external_plugins.go`
(`reviewPregroupedSigned`), `plugin_group_review.go`.

### PS4: Plan Preservation

In presign-plan mode, `/plan` may change **only** the group ID and the fee.
For every slot — plugin and managed alike — the draft and the canonical
transaction, each with `Group` and `Fee` zeroed, must be msgpack-byte-equal;
any other change (sender, validity window, lease, note, amount, receiver,
app id, args, rekey, positional reorder) rejects with "plan modified ...
slot". Anchor: `internal/engine/plugin_presign.go`
(draft-vs-canonical comparison, applied to both slot classes).

### PS5: Signed-Slot Byte Match and Index Discipline

A plugin-returned signed slot is accepted only if the transaction inside it
is msgpack-byte-equal to the canonical transaction at that index — the
plugin cannot substitute what it signs. The returned set must have exactly
the requested count, no duplicate indices, and no unexpected indices; a
plugin cannot inject slots, and every declared plugin signer must own at
least one slot by sender address. Anchor: `plugin_presign.go`
(`validatePluginSignedSlot`, count/duplicate/unexpected-index checks,
signer-slot matching).

### PS6: Managed Slots Are Approval-Gated

Managed slots are signed only by apsigner through its normal pipeline over
the canonical group: plugin-signed and dummy slots ride in the same `/sign`
request as passthrough, every slot is displayed in the approval prompt
(passthrough slots labeled `[PASSTHROUGH]` with their decoded fields
rendered), auto-approval is disabled for any group containing
passthrough/foreign/pre-grouped slots, and dangerous fields (rekey, close,
clawback) on a passthrough slot force operator review. Anchors:
`plugin_presign.go` (slot partitioning into the `/sign` request),
`internal/signerapp/signing/approval.go` (mixed-mode display, auto-approval
disable), `always_review.go` (dangerous-field forcing).

### PS7: No Ungated Submission (central)

Every plugin-produced submission passed PS3's review (pregrouped-signed) or
PS6's approval pipeline (presign-plan). Mode dispatch is total
(`external_plugins.go` switches on `GroupMode`; signed intents outside
pregrouped-signed fail `ProcessTransactionIntents`; `localSigners` is
rejected at `apshellapp/submission.go`), so there is no third path.

## Assumptions and honest gaps

- **No local cryptographic verification** of plugin or passthrough
  signatures (sig/msig/lsig contents), on either the client or the signer;
  the chain validates at submit. A plugin substituting *signature* bytes
  (not transaction bytes) produces a group that fails at algod, not before.
- **Fees are exempt from PS4** by design: `/plan` exists to set fees. Managed
  slot fees are bounded by apsigner policy and shown at approval;
  plugin-slot fees are re-signed by the plugin against the canonical bytes,
  so the plugin sees what it pays.
- **A self-consistent malicious group passes PS2** — the digest check proves
  internal consistency, not benignity. Catching a bad-but-consistent group
  is exactly what PS3's decoded review and PS6's approval display are for.
- **No canonical re-encode round-trip** on pregrouped raw bytes: `raw` is
  decoded but not re-encoded and compared, so non-canonical msgpack could in
  principle make the displayed decode differ from what algod decodes.
  Tracked as a hardening candidate, not claimed by any invariant.
- **Plugin sender claims are not authenticated**: in presign-plan a plugin
  may declare any sender address as its own; the slot then goes foreign at
  `/plan` and apsigner never signs it, so the only effect is a group that
  fails signature validation at the chain.
- The client's review renders decoded values but enforces no numeric bounds;
  bounds are the operator's judgment (pregrouped) or apsigner policy
  (managed slots).

## Test anchors

- Pregrouped validation/rendering/fail-closed:
  `internal/engine/plugin_pregrouped_test.go`,
  `internal/apshellcli/plugin_group_review_test.go` and
  `external_plugins_test.go` (mandatory review, AutoConfirm rejection).
- Presign preservation/byte-match/index discipline:
  `internal/engine/plugin_presign_test.go`.
- Mixed passthrough display and auto-approval disable:
  `internal/signerapp/signing/approval_test.go`, `always_review_test.go`;
  end-to-end `test/integration` Passthrough* tests.
- `localSigners` rejection: `internal/apshellapp/submission_test.go`.

(Exact test names are pinned in [FORMAL_TRACEABILITY.md](FORMAL_TRACEABILITY.md)
PS rows.)

## Machine-checkable successor

[formal/plugin_signing.tla](formal/plugin_signing.tla) machine-checks
PS2-PS7 as a one-shot enumeration over both modes (PS1 is structural — a
property of the Go type, checked by construction and code review). See
[FORMAL_TLA_PLUGIN_SIGNING_MODEL.md](FORMAL_TLA_PLUGIN_SIGNING_MODEL.md).
