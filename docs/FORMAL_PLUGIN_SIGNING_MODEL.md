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
submission unless they passed exactly one of the two authorization gates:

- **pregrouped-signed**: a mandatory interactive review of the *decoded actual
  bytes* on the client, which the plugin cannot waive and which fails closed
  in non-interactive modes; or
- **presign-plan**: apsigner's policy and approval pipeline over the canonical
  group, which includes every slot (including plugin passthrough slots) in
  policy/review context. The ordinary product operator default still applies:
  `user_auto_approve:true` satisfies any review requirement for a non-rejected
  group without a prompt. Hard rejection rules still apply.

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

Every entry point runs a plugin's steps through one loop,
`internal/apshellcli/external_plugins.go::processPluginResultStructured`, which
reviews each step (`reviewPluginTransactions`) before it submits it and follows
continuations: the REPL and MCP through `execPlugin`, and JS `plugin()`
through `script_runtime.go::PluginExecutorAdapter.ExecutePlugin`. JS
`plugin()` is therefore an entry into the modeled path, not a third one.

Out of scope: the plugin process protocol itself (JSON-RPC, sandboxing,
manifests — `docs/ARCH_PLUGINS.md`), cosigned-account component assembly
([FORMAL_TLA_BOUNDED_COSIGNER_MODEL.md](FORMAL_TLA_BOUNDED_COSIGNER_MODEL.md)), and the
generic passthrough machinery already modeled in
[FORMAL_TXN_PLANNING_MODEL.md](FORMAL_TXN_PLANNING_MODEL.md) (I7/I8).

## Abstract objects

- **Intent**: a plugin-produced transaction, `type:"raw"` (unsigned draft) or
  `type:"signed"` (finished bytes). Mode dispatch is total: signed intents
  are accepted only by the pregrouped-signed path
  (`internal/engine/plugin_transactions.go` accepts only `"raw"`). A raw
  intent is decoded with the canonical decoder: one that is not exactly the
  canonical encoding of one transaction is refused, so the draft is what the
  plugin's bytes say.
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
type (unexported fields, sole constructor), not a runtime comparison. The
decode itself is the canonical decoder: a blob that is not exactly the
canonical encoding of what it decodes to (trailing data, a second
transaction, a repeated field) is refused, so the rendered decode is also
what algod decodes. Anchor: `plugin_pregrouped.go` (fields, constructor,
`decodeSignedTxnIntents`, byte-verbatim submission via
`SubmitTransactionsWithContext(ctx, g.raw, ...)`).

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
flag is ignored, the rendering decodes the actual bytes (per slot: the role
and type; then the description `internal/txnreview` builds, the same one the
signer's approval prompt shows, with the network named from the genesis hash;
then every finding the signer's warning rules produce for those bytes, each
marked `!!`; a type the describer does not know is shown with a line saying
its fields are not shown, so opacity is displayed, never hidden; what a rekey
finding says of its target comes from the signer's key list fetched for the
PS8 check, the facts the check judged from, `PluginGroup.RekeyTargets`: the
addresses the signer holds an aplane key for, of any key type, a generic
LogicSig included, and those of them whose aplane key records that it is not
a valid rekey target, with the key type; a group with no rekey has no rekey
finding and needs neither; a rekey to a held address is shown as keeping control, and
a rekey to an account signable only through its auth address, or to an
address the signer lists nothing for, warns of losing control. Those are the
facts the review shares with the signer's prompt; the signer also knows each
account's rekey-to list and the review does not, so a rekey to a listed
address the signer does not hold reads as losing control here), and
non-interactive contexts (`AutoConfirm`, MCP) fail closed with an explicit
error: the review tells `apshellapp.CheckPluginGroup` whether it can ask the
user, and the check refuses a pregrouped-signed group for a review that
cannot, once it is decoded and before any key list is fetched, so that
refusal comes before PS8's. Validation precedes rendering: the review takes
the group from `CheckPluginGroup`, which constructs the
`PregroupedSignedGroup`, so an undecodable or digest-tampered group errors
before anything is shown, and a group refused under PS8 is refused before
anything is shown. Anchors: `internal/apshellcli/external_plugins.go`
(`reviewPluginTransactions`, `reviewPregroupedSigned`),
`plugin_group_review.go`, `internal/apshellapp/submission.go`
(`CheckPluginGroup`, `PluginCheckOptions`).

### PS4: Plan Preservation

In presign-plan mode, `/plan` may only set a canonical group ID over the final
group, raise the fees its mutation report lists (each strictly upward, summing
without overflow to a `total_fees_delta` that is not negative), and append
canonical budget dummies; the report's counts must match the group. For every
original slot — plugin and managed alike — any other change (sender, validity
window, lease, note, amount, receiver, app id, args, rekey, positional
reorder) rejects with "plan modified ... slot". Anchor:
`internal/engine/plugin_presign.go::validatePluginPlan` (applied to both slot
classes), whose fee and field reconciliation is the ordinary `/sign` path's
`internal/clientsign/verify.go::ValidateOriginalPositions`. The draft it
compares against is the one reading of the plugin's raw intents
(`internal/engine/plugin_transactions.go::DecodePluginDraft`: canonical
decode, group ID cleared, a discarded one reported), which
`internal/apshellapp/submission.go::CheckPluginGroup` reads once for both the
client review and submission, so the review shows what is planned and
preservation holds from the plugin's own bytes, not from one lenient reading
of them. Once the plan passes, the dummies
it appended and the fee raise it reports are recorded in the command's output,
which is shown when the command ends, with the submission or with the error of
a later step; this is output, not a guard, and adds nothing to the checks or
their order.

After `/sign` and before broadcast, `verifySignedAgainstPlan` also requires
every managed slot to sign exactly its canonical transaction, in bytes that
are the canonical encoding of it, and every passthrough slot (plugin-signed
or dummy) to come back byte-for-byte as sent.
The TLA model has no conjunct or dummy slot class for this post-sign check;
it is a candidate model extension (2026-10-16 drift review).

### PS5: Signed-Slot Byte Match and Index Discipline

A plugin-returned signed slot is accepted only if the transaction inside it
is msgpack-byte-equal to the canonical transaction at that index — the
plugin cannot substitute what it signs. The code also refuses a slot whose signed
bytes are not themselves canonical (trailing data, a repeated field): an
encoding check ahead of the byte match, outside the model, which abstracts
msgpack away. The returned set must have exactly
the requested count, no duplicate indices, and no unexpected indices; a
plugin cannot inject slots, and every declared plugin signer must own at
least one slot by sender address. Anchor: `plugin_presign.go`
(`validatePluginSignedSlot`, count/duplicate/unexpected-index checks,
signer-slot matching).

### PS6: Managed Slots Are Approval-Gated

Managed slots are signed only by apsigner through its normal pipeline over
the canonical group: plugin-signed and dummy slots ride in the same `/sign`
request as passthrough, every slot is displayed in the approval prompt
(passthrough slots labeled `[PASSTHROUGH]` with their decoded fields rendered)
when a prompt is required, and dangerous fields (rekey, close,
clawback) on a passthrough slot force operator review. Anchors:
`plugin_presign.go` (slot partitioning into the `/sign` request),
`internal/signerapp/signing/approval.go` (mixed-mode display, auto-approval
disable), `always_review.go` (dangerous-field forcing).

### PS7: No Ungated Submission (central)

Every plugin-produced submission passed PS3's interactive review
(pregrouped-signed) or PS6's signer authorization pipeline (presign-plan).
The latter may resolve through explicit policy, forced review, or the ordinary
operator default. Mode dispatch is total
(`apshellapp.CheckPluginGroup` switches on `GroupMode` and refuses a mode it
does not know before decoding, for the review and for submission, which also
refuses one; signed intents outside pregrouped-signed fail
`DecodePluginDraft`, with which `CheckPluginGroup` reads the presign-plan and
default-flow drafts, and a pregrouped-signed intent that is not signed is
refused there too; `localSigners` is rejected at `apshellapp/submission.go`),
so there is no third path. The REPL, MCP and JS `plugin()` all reach
submission through the same review-then-submit loop (see Scope).

### PS8: No Rekey To A Held Aplane Key That Is Not A Valid Rekey Target

A plugin-built group is refused, in every mode, when any of its
transactions, at any position and whoever signs it, rekeys an account to an
address the signer holds an aplane key for whose recorded
`valid_rekey_target` is false, the account's own address included, or that
is a rotating account, whatever its record says. It is the rule the signer
applies at every position of a group it signs into
(`rejectRekeyToInvalidTarget`, code `rekey_target_not_valid`, with its
rotating check as a second line); a plugin-signed slot may never reach the
signer, so apshell applies it itself. Both sides find the position with one
function and word the refusal with one core
(`internal/txnreview/findings.go::FirstRekeyToInvalidTarget`,
`::RekeyTargetNotValidText`). The refusal names the position, the target and
its key type. It comes before
anything is shown or prompted for, before `/plan` or `/sign`, and before
anything is submitted. It is applied twice. One step,
`apshellapp.CheckPluginGroup`, decodes the result for its mode and applies
it, and the review of every mode starts with that step. Submission
(`SubmitPluginTransactions`, which the REPL, MCP and JavaScript all submit
through) takes only the group the step returned, frozen at the check, and
applies the rule again, since a key can be created on the signer while the
user reviews the group: in the default flow before the group goes to the
signer, which then applies the same rule at every position; for
pregrouped-signed before the group is broadcast; for presign-plan at the
start of submission, before `/plan`, the plugin's signing callback and the
signer's approval, none of which apshell judges again. A rekey to a foreign
address, one the signer holds no aplane key for, is not refused; the review
warns about it.

Each time, a group in which any transaction rekeys is judged against the
signer's key list fetched for that judgment (`engine.CurrentKeys`, which
reads and writes no cache), and the held set and the not-valid set are built
from the records that fetch returned (`engine.RekeyTargetsFromKeys`, from
each record's key type, generic LogicSig flag and `valid_rekey_target`; a
rotating key type, `rotatingkey.IsRotatingKeyType`, is not a valid rekey
target whatever its record says).
Nothing is read back from the signer cache, so an empty, stale or reset
cache cannot make a held aplane key read as foreign. The review's rekey
findings show the facts the check judged from, carried on the group. When no
current list can be had, because apshell is not connected to the signer, the
signer is locked, the request fails, or the answer disagrees with itself (a
`count` other than its number of records, a record with no address, an
address listed twice), the group is refused with an error saying so. The
signer, for its part, never answers `/keys` with a list shortened by a lock:
a lock while it builds the list makes it answer as locked
(`internal/signerapp/rest/inventory.go::keysAnswer`). A group with no rekey fetches nothing and needs no connection, so
a pregrouped-signed group with no rekey still submits without one. Anchors:
`internal/apshellapp/submission.go` (`CheckPluginGroup`, `judgeRekeys`,
`SubmitPluginTransactions`), `internal/apshellcli/external_plugins.go`
(`reviewPluginTransactions`), `internal/engine/accounts.go` (`CurrentKeys`,
`RekeyTargetsFromKeys`, `keyInfoFromSigner`), `internal/engine/results.go`
(`KeyInfo.IsGenericLsig`, `KeyInfo.ValidRekeyTarget`),
`internal/txnreview/findings.go` (`FirstRekeyToInvalidTarget`,
`RekeyTargetNotValidText`). The checked group keeps its transactions as
their encoding and decodes them afresh for every use, so what is submitted is
what was reviewed.

## Assumptions and honest gaps

- **No local cryptographic verification** of plugin or passthrough
  signatures (sig/msig/lsig contents), on either the client or the signer;
  the chain validates at submit. A plugin substituting *signature* bytes
  (not transaction bytes) produces a group that fails at algod, not before.
- **Reported fee increases are allowed by PS4** by design: `/plan` exists to set fees. Managed
  slot fees are bounded by apsigner policy and shown at approval;
  plugin-slot fees are re-signed by the plugin against the canonical bytes,
  so the plugin sees what it pays.
- **A self-consistent malicious group passes PS2** — the digest check proves
  internal consistency, not benignity. Catching a bad-but-consistent group
  is exactly what PS3's decoded review and PS6's approval display are for.
- **Canonical encoding is checked, not modeled.** Pregrouped blobs, plugin
  callback slots, the managed slots `/sign` returns and every raw intent (the
  presign-plan draft and the default flow) are decoded with the canonical
  decoder, which refuses any bytes that do not re-encode to themselves, so a
  displayed or checked decode cannot differ from what algod decodes, and a
  draft cannot differ from what the plugin's bytes say. The model abstracts
  msgpack away and claims nothing about it; the Go tests in
  `plugin_pregrouped_test.go`, `plugin_presign_test.go` and
  `plugin_transactions_test.go` cover it.
- **The network precondition is checked, not modeled.** Before `/plan`
  (presign-plan, in `internal/engine/plugin_presign.go::SignAndSubmitWithPluginSigners`
  before the plan requests are built) and before a pregrouped-signed group is sent to algod
  (`internal/engine/plugin_pregrouped.go::SubmitPregroupedSigned`), the client
  refuses any transaction whose genesis hash, or set genesis ID, is not the
  active algod's (`internal/engine/active_network.go::checkActiveNetwork`). It
  adds a refusal ahead of the modeled gates and changes none of them; the model
  carries no network and claims nothing about it. Go tests:
  `internal/engine/active_network_test.go`.
- **Plugin sender claims are not authenticated**: in presign-plan a plugin
  may declare any sender address as its own; the slot then goes foreign at
  `/plan` and apsigner never signs it, so the only effect is a group that
  fails signature validation at the chain.
- The client's review renders decoded values but enforces no numeric bounds;
  bounds are the operator's judgment (pregrouped) or apsigner policy
  (managed slots).
- **PS8 trusts the signer's `/keys` answer of the moment.** apshell does not
  see a key the signer creates after the second judgment, for any position,
  plugin-signed ones included; in presign-plan that judgment comes before
  `/plan`, the plugin's signing and the signer's approval wait. In the default
  flow and presign-plan the signer applies its own rule, from its own list,
  at every position of the group it signs into, plugin-signed positions
  included; a pregrouped-signed group never reaches the signer, so nothing
  judges it after apshell's second judgment. The default flow, which the TLA
  model does not enumerate, applies the same refusal.

## Test anchors

- Pregrouped validation/rendering/fail-closed:
  `internal/engine/plugin_pregrouped_test.go` and
  `internal/apshellcli/plugin_pregrouped_review_test.go` (mandatory review,
  AutoConfirm rejection).
- Raw intent decoding (canonical, raw-only, group ID cleared and its discard
  reported) and the review of the drafts:
  `internal/engine/plugin_transactions_test.go`;
  `internal/apshellcli/plugin_approval_test.go` (the default flow's decoded
  draft, whose prompt stays the plugin's `requiresApproval`; the presign-plan
  draft review; the refusal of an unknown `groupMode`; what each mode's review
  says of a rekey target from the fetched key list, its refusal of a rekey to
  a held aplane key that is not a valid rekey target or of a rekey that cannot
  be checked, and a fetch at the review and another at submission).
- PS8 at the check and at submission, with nothing sent to the signer's other
  endpoints or the node: the verdict follows the fetched records, not a cache
  that says otherwise, and the cache is left as it was; a key created after
  the check is refused at submission; no connection or a locked signer
  refuses a rekey; a group with no rekey fetches nothing; the checked group is
  frozen: `internal/apshellapp/submission_test.go`; the fetch and the two
  sets: `internal/engine/accounts_test.go`.
- Presign preservation/byte-match/index discipline:
  `internal/engine/plugin_presign_test.go`.
- Mixed passthrough display and auto-approval disable:
  `internal/signerapp/signing/approval_test.go`, `always_review_test.go`;
  end-to-end `test/integration` Passthrough* tests.
- `localSigners` rejection: `internal/apshellapp/submission_pregrouped_test.go`.
- JS `plugin()` through the shared loop (continuations, a later step's error,
  the mandatory pregrouped review, the IDs a failed run lists, a failed run's
  REPL and MCP record unchanged):
  `internal/apshellcli/plugin_continuation_test.go`.
- Network precondition: `internal/engine/active_network_test.go`,
  `internal/apshellapp/submission_network_test.go`.

(Exact test names are pinned in [FORMAL_TRACEABILITY.md](FORMAL_TRACEABILITY.md)
PS rows.)

## Machine-checkable successor

[formal/plugin_signing.tla](formal/plugin_signing.tla) machine-checks
PS2-PS8 as a one-shot enumeration over both modes (PS1 is structural — a
property of the Go type, checked by construction and code review). See
[FORMAL_TLA_PLUGIN_SIGNING_MODEL.md](FORMAL_TLA_PLUGIN_SIGNING_MODEL.md).
