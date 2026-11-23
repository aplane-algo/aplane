# Formalization Roadmap

Status: active assurance inventory. Architecture documents remain the product
contracts; these models cover narrower security-critical transitions.

## Current machine-checked inventory

| Module | Primary subject |
|---|---|
| `sign_boundary.tla` | request modes, planning, and signing output |
| `policy_precedence.tla` | deny/review/approve precedence |
| `composition.tla` | policy-to-signing composition |
| `approval_coordinator.tla` | delivery, cancellation, timeout, fail-all, displacement, and progress |
| `approval_composition.tla` | approval outcome to signer output |
| `session_ownership.tla` | scalar pending/active admin ownership |
| `plugin_signing.tla` | plugin signing trust boundary |
| `bounded_cosigner.tla` | cosigned1 composition: spends, cosigned rekeys and listed rekeys, and passthrough binding (A8), on a bounded or a plain host |
| `store_root_commit.tla` | atomic generation/key-authority commit, exact-input promotion, crash classification, and quarantine |
| `enrollment_queue.tla` | client enrollment registry and queue under the applied-vs-durable publication rule |
| `recovery_binding.tla` | which generation the runtime binds, serves, and maintains after a failed post-commit reload |
| `rotating_leaf_release.tla` | one-time leaf choice for a rotating leaf-family stage: release memory, audit restore after unlock, and the status-pass clear |
| `key_use_lock.tla` | how a lock ends every key use outside a session: registration, drain, session clear, and what a rotating sign or mnemonic export may still release; what an unlock may publish, load and clear beside a lock, a recovery and a session in service |
| `setting_publish.tla` | when a writable setting's change takes effect relative to its save: restrictive before, anything else after |
| `signer_invariants.tla` | the signer invariants ahead of the policy verdict, the positions each one judges, and a cosigner document's external checks after the verdict |

The single-product runtime has no decommission state or operation lease, so the
formal inventory contains no lifecycle model for those concepts. Runtime
reload order is tracked as RL1 in `FORMAL_TRACEABILITY.md` and its Go regression
tests.

## Working rules

Every model change must update, in the same commit:

- its prose companion and `FORMAL_TRACEABILITY.md` anchors;
- normal and deep configurations where the model has scalable bounds; a model
  whose normal configuration already exhausts its full finite state space
  needs no deep configuration and records that fact in its prose companion;
- `formal/metrics.json` and `formal/metrics_deep.json` state counts;
- copied-operator drift checks when operators are duplicated; and
- mutation rationale for history flags or other load-bearing guards.

Safety and liveness inventories are distinct. Request symmetry may be used for
safety, but never for TLC temporal checking. Liveness assumptions must describe
runtime mechanisms (for example delivery retry and approval timeout), not
operator choices.

## Next priorities

1. Promote reload-during-request snapshot stability from Go tests into a small
   temporal model if that race changes materially.
2. Extend `key_use_lock.tla` to shutdown if `Runtime.Destroy` ever runs while a
   service can still start a key use, or if request-drain ordering changes
   again.
3. Extend key-generation crash models only when new durable transitions are
   introduced.
4. Keep native signing authority and bounded-cosigner refinements aligned with
   their architecture contracts.

## Gates

```bash
make formal-copy-sync-check
make formal-test
make formal-test-deep
```

The metrics JSON files are the authoritative run inventories. Expected-failure
negative controls, such as the store-root exact-input mutation, must remain explicitly
marked rather than being treated as successful safety runs.

## Drift reviews

Drift review (2026-08-19, HEAD `ea4f0347`): first recorded review; baseline
established. `make formal-test` (13 runs) and `make formal-test-deep` (7 runs)
passed with all metrics matched. Anchor sweep over `FORMAL_TRACEABILITY.md`:
all 128 file anchors exist; three stale test anchors fixed in the same commit
(I5 `TestCalculateDummies_PreGroupedImmutability` →
`TestCalculateLogicSigResourcesRejectsUnderprovisionedImmutablePassthrough`
after the legacy LogicSig size plumbing removal — I5 enforcement is now
reject-on-underprovision rather than no-mutation; S7
`TestPayloadV1AlgodAutoSaltRoundTrip` →
`TestAutoSaltedLogicSigPayloadContract`; S13 restore-side contradictory-class
test → `internal/keys/managed_files_test.go::TestManagedCredentialDestinationRejectsContradictoryClass`
after the backup/restore simplification). Code movement in modeled areas since
`docs/formal/` was last touched (92f6b598): three commits — an apshellcli
rendering refactor (plugin review dispatch untouched; PS3/PS6/PS7 hold),
adminserver doc-comment and test-only changes. Spot-checked transcriptions
hold: SO2 disconnect-cleanup condition and ClearActive ordering, AP7
fail-all-before-displacement, PS3 fail-closed AutoConfirm review, guarded
assembly abort-on-first-failure. Bookkeeping consistent: `metrics.json` state
counts match the model-doc status headers and traceability prose. No new
unmodeled surface found in the range.

Drift review (2026-08-27, HEAD `92940382`): range `ea4f0347..92940382` (~40
commits: single-tenant/fixed-runtime cleanup, atomic store root #50, FNet
removal). `make formal-test` (12 runs) and `make formal-test-deep` (7 runs)
passed with all metrics matched; the run count moved 13→12 with the
lifecycle-model retirement and `store_root_commit` addition. Every modeled
guard verified against current code and HOLDS: approval fail-all triggers
(disconnect/displacement/lock; no shutdown or decommission caller remains),
delivery-turn release and post-turn rechecks, ApprovalWait defaulting (three
independent floors), SO2 disconnect-cleanup condition, PromoteToActive atomic
swap, displacement-after-promotion ordering, guarded assembly check order and
abort-on-first-failure, bounded-cosigner gate order, sign-boundary mode
trichotomy and foreign/passthrough output rules, policy verdict precedence
ladder, plugin digest recomputation / fail-closed pregrouped review / plan
preservation / mode-dispatch totality, and the full `store_root_commit`
protocol transcription against `genstore` (stage→validate→sync→publish→seal→
single root rename; recovery-block on unconfirmed replacement; quarantine of
complete ambiguous publications). The in-range identity-locator removal was
parameter-threading only; no modeled guard changed. New-surface scan clean
(`auth_only`, the maintenance fence, and `recovery_blocked` all predate the
range; the only wire change is `StatusResponse.IdentityID` removal plus
optional `warnings`). Fixed in this commit: traceability anchors
A1/A4/BS4/BS5/BS7 (component/assembly symbols unexported or unified into
`AssembleWithContext`/`assembleBoundedTarget`), AP6 stale "and shutdown",
PS6/I8/S2 line numbers, store-root positive state count (12@d7 → 14@d9),
`assembleDecodedGuarded` → `assembleDecoded` in `guarded_assembly.tla` and
its model doc, the `session_ownership.tla` `cleanupRuntime` comment, and the
plugin model's `external_plugins_test.go` test anchor. Flagged, not fixed
(model-extension / bookkeeping candidates, out of scope here): (1) the
bounded assembly receipt is a real acceptance guard in code but unmodeled in
`bounded_cosigner.tla` — a limits note was added to its model doc; (2)
`store_root_commit` is missing its prose companion doc, header code anchors,
and a deep configuration/`metrics_deep.json` entry required by the working
rules; (3) `FORMAL_TLA_APPROVAL_COORDINATOR_MODEL.md` lacks the status-header
convention the other TLA docs use. Behavioral wart noted (sound under SO1/SO2):
displacement is offered before auth reveals a newcomer is `auth_only`, so an
owner can confirm displacement and never be displaced.

Follow-up (2026-08-27, same day): flagged items (1)-(3) addressed. The
bounded assembly receipt is now modeled in `bounded_cosigner.tla` as an
abstract `receipt` input consumed by `AssembleStep` and required by
`BS3_SpendAuthoritiesVerified` (199,168 distinct states at depth 4, metrics
updated; removing the receipt check from assembly now violates BS3).
`store_root_commit.tla` gained header code anchors and its prose companion
`FORMAL_TLA_STORE_ROOT_COMMIT_MODEL.md`. The working rules now state that a
model whose normal configuration exhausts its full finite state space needs
no deep configuration and records that in its prose companion, which
resolves the deep-config gap for `store_root_commit` and `bounded_cosigner`
truthfully rather than with duplicate runs.
`FORMAL_TLA_APPROVAL_COORDINATOR_MODEL.md` gained the standard status
header quoting its four recorded runs.

Drift review (2026-10-07, HEAD `09e24050`): range `92940382..09e24050` (184
commits: v1 JSON policy documents and the YAML model's removal, the
sentry→cosigner rename, shared guarded/bounded client flow steps, keys-only
client auth with the asynchronous enrollment queue, SSH admin subsystem
removal, recovery-binding and generation-validation fixes). `make formal-test`
(12 runs) and `make formal-test-deep` (7 runs) passed with all metrics
matched; the negative control still fails on `S5_NoUnpinnedPromotion`. Every
modeled guard re-read against current code HOLDS: coordinator cancel/ctx/
hasClient rechecks after the delivery turn, turn release on every terminal
path, fail-all callers (disconnect, displacement, lock; still no shutdown or
decommission caller); SO2 cleanup condition with `cleanupRuntime` set at
auth, `PromoteToActive` before `DisplaceSession`; staged mint order (Mint now
refuses a request without candidate validation, a strengthening), single
durable root rename, non-destructive quarantine; `assembleDecoded` check order
and abort-on-first-failure (rename only, plus one added fail-closed check on
unsupported witness key types); bounded base gate order
(frozen-context → plan → policy/approval → sign) and the client choreography
(base components, then non-guarded positions, then the cosigner, then
assembly with receipt); plugin files changed by import path only; sign modes
unchanged, verdict ladder in `gate.go` unchanged, ApprovalWait floors intact.
Bookkeeping consistent (ten modules in the table, `metrics.json` matches every
status header). Fixed in this commit: AP4 traceability row cited the removed
`TestCoordinatorSerializesAcrossApprovalTypes` and described FIFO across
token requests; `FORMAL_TLA_APPROVAL_COORDINATOR_MODEL.md` gained a drift
pointer. REPORTED, not fixed: `approval_coordinator.tla` still models token
requests, `Preempt`, and AP8 (added in `0e05c41d`), which `a7ccb7eb` removed
from the coordinator; the signing half of the model still matches, so no
guard is lost, but the spec over-approximates. Options: reduce the model to
signing-only (drop `TokenRequests`/`Preempt`/AP8, re-record four runs) or keep
the historical second kind with the drift notes. Flagged for model extension:
(1) the persisted enrollment queue (`enrollqueue`: request → pending →
approved/rejected/expired/removed, durable publish with the
applied-not-durable rule, `MaxPending`, 7-day TTL) is a new approval-adjacent
lifecycle no spec covers; (2) `b0e51275` binds recovery maintenance to the
authenticated store-root selection even when that generation fails
validation, a selection-authority property outside `store_root_commit.tla`;
(3) per-witness-key cosigner policies with a missing entry rejecting every
request are a fail-closed refinement of A4 covered by tests only. Code tidy
noted (not formal drift): `deliveryWaiter.signing` and the non-signing
queue branch are vestigial, and `SessionManager.RegisterPending` has no
production caller.

Follow-up (2026-10-07, same day): the reported divergence is resolved by
reducing `approval_coordinator.tla` to signing-only, the shape it had before
`0e05c41d`: `TokenRequests`, `Preempted`, `Preempt`, `SigningQueued`,
`tokenOvertookSigning`, and AP8 are gone, the four configurations declare
`SignRequests` only, and the recorded runs return to 112 (depth 10) and 294
(depth 13) for `Safety` and 490 (depth 10) and 3,773 (depth 13) for
`Progress`; both suites match. Both model docs lost their drift notes and
token prose and now say that enrollment never takes the delivery turn. The
enrollment queue remains flagged above as a model-extension candidate.

Follow-up (2026-10-07, same day): flagged item (1), the enrollment queue, is
now modeled. `enrollment_queue.tla` covers the enrolled-key registry and the
pending-enrollment queue under the applied-vs-durable publication rule:
three publish outcomes (synced, failed before the rename, failed after it),
the view following the file, resync before the next operation, crash
reverting to the durable content, request/refresh with the cap, approve
(registry before queue), reject (refused for an enrolled key), import, revoke,
and lapse. EQ1-EQ6 hold over 2,340 states (depth 11; deep 12,168 at depth
15), and the negative control `RequireDurableAck = FALSE` violates EQ2 after
175 states at depth 3 (167 once import followed the approval rule). Prose companion
`FORMAL_TLA_ENROLLMENT_QUEUE_MODEL.md`; traceability rows and module section
added. Items (2) and (3) remain flagged.

Follow-up (2026-10-07, same day): flagged items (2) and (3) closed.
`recovery_binding.tla` models the post-commit reload: the keystore binding,
the key cache, and recovery maintenance against the root selection, with the
three code guards as constants (bind before validate, maintenance reads the
root, recovery before lock release). RB1-RB4 hold over 45 states at depth
10; the negative control disables the first two guards, the shape before
`b0e51275`, and reproduces that bug as an RB1 violation in five steps. Each
guard is load-bearing for a different invariant (recorded in the prose
companion `FORMAL_TLA_RECOVERY_BINDING_MODEL.md`). The per-witness-key
cosigner policy selection stays a test-level contract by decision, recorded
on the A4 traceability row. No flagged items remain from this review.

Drift review (2026-10-14, branch `feat/per-key-policy` on HEAD `cdfa8055`,
scoped to the per-key policy redesign): both node roles now store a node
default (`default.json`) plus optional per-key documents
(`policies/<selector>.json`), each with its own `.hmac` sidecar; a key's own
document replaces the default wholesale (`PolicyFor(key) = own[key] if
present else default`); `key_overrides`, the signer `policy.json`, and the
cosigner-only rule ids (`cosigner:non_transfer`,
`cosigner:deterministic_routing`, `cosigner:transfer_policy_required`,
`cosigner_key_has_no_policy`) are gone; every document carries a
`transaction_types` verdict map whose `reject` and `review` entries are
evaluated first inside Always Deny and Always Review (`transaction_type:
<type>`). `policy_precedence.tla` abstracts the rule inventory as deny,
review, and approve families and models neither document selection nor
individual rules, so selection and the type rule add members to existing
families without touching the spec; no module, configuration, or metrics
change. Prose updated: `FORMAL_POLICY_MODEL.md` (snapshot as one
`NodePolicy`, per-file sidecars failing the whole load closed, selection
section and P10 restated over `PolicyFor`, Transaction Type Rule section,
anchors), `FORMAL_GUARDED_SIGNING_MODEL.md` (`CosignerPolicyFor` resolves to
the key's own document or the deny-all cosigner default; `NoPolicy` only when
no snapshot is loaded, an internal error; rejections expressed as
`transaction_type:<type>`, `cosigner_policy:reject_rekey`, and
`transfer_policy:route_miss`), `FORMAL_SIGNING_AUTHORITY_MODEL.md` (S12
restated over document selection). The 2026-10-07 closing note that a missing
per-witness-key entry rejects every request is superseded: a cosigner key
with no document of its own follows the node default, which is deny-all as
shipped but operator-replaceable. The P10 and S12 rows in
`FORMAL_TRACEABILITY.md` were not refreshed on the reviewed branch, which
still cited `policy.Config.ForKey`,
`TestEvaluateAlwaysReviewRulesUsesKeyOverride`, and
`TestEvaluateAutoRejectionRulesAppliesKeyOverrides`; they were refreshed when
the redesign merged (`407db644`). Both rows now cite
`policyruntime.NodePolicy.PolicyFor` and
`signing.authPolicyKeysFromRequest`, and anchor tests that exist:
`always_review_test.go::TestEvaluateAlwaysReviewRulesResolvesPolicyPerKey`
and `service_test.go::TestEvaluateAutoRejectionRulesResolvesPolicyPerKey` in
`internal/signerapp/signing`, with P10 also citing
`test/integration/policy_per_key_test.go`.

Drift review (2026-10-16, HEAD `9fbbb5a6`): range `09e24050..9fbbb5a6` (110
commits; the 2026-10-14 review was scoped to per-key policy, so this one
covers the whole range since the last full review). `make formal-test` (16
runs) and `make formal-test-deep` (8 runs) match their recorded outcomes and
metrics; metrics, the roadmap table, and every model header agree. The
approval coordinator, session ownership, store-root commit, enrollment queue,
guarded assembly, bounded cosigner, sign boundary, policy precedence, and
composition transcriptions hold. Notable range commits checked: shutdown now
cancels every HTTP request context (`41fdf774`), so parked approvals end
through `Cancel`, not a new fail-all caller; prompts carry server-generated IDs
(`fd176e8f`, AP3 wording updated); the signer refuses to sign anything other
than the approved plan (`ea4a9ec3`, a fail-closed conjunct inside the approval
and base gates); import clears a waiting request on an applied-not-durable
registry write (`9a46af3f`, modeled in the same commit); per-key policy
documents sit in existing generation leaf namespaces and are re-signed inside
the passphrase-change mint; rotating stage tables are a derivable cache
outside the generation; `rejectRekeyToRotating` is an unconfigurable Always
Deny member ahead of the policy document. Fixed here: two stale
`FORMAL_TRACEABILITY.md` test anchors (P2, A4 and its selection note), the
P10/S12 rows flagged on 2026-10-14 (already corrected), PS4 plan-preservation
wording (`validatePluginPlan`: canonical group ID, reported fee increases
only, canonical dummies) in `plugin_signing.tla` comments,
`FORMAL_PLUGIN_SIGNING_MODEL.md`, and `ARCH_PLUGINS.md`, AP3 and shutdown
notes, the enrollment notification scope note, the deny-source list in
`FORMAL_POLICY_MODEL.md`, rotating-key scope in
`FORMAL_SIGNING_AUTHORITY_MODEL.md`, planning anchors, the bounded base-gate
binding note, and the `CommitRoot` operation list (policy apply refused in
recovery; changepass leaves the runtime locked, not in recovery).

Open divergences (reported, not fixed; both predate or sit outside the
modeled guards and no signature is produced):
(1) RB4 on policy apply's uncertain commit: `policyapply.Commit` returning
`policy_commit_uncertain` makes `ApplyPolicy` enter recovery, but
`commitAndReload` returns before `ir.Reload()`, so the keystore stays bound to
the old generation while the root may select the new one; restore reloads in
the same case (`direct_restore.go`). RB1-RB3 hold. Options: reload whenever a
generation ID was minted (code), or model an uncertain commit that enters
recovery without binding and weaken RB4 to `~recovery => bound = root`.
Related edge: `ErrStoreRootCommitStateUnknown` is classified as a pre-commit
failure on apply and restore, so a root that did land would not enter
recovery.
(2) I10 on the rotating flow: `/sign/rotating/*` never calls
`validateKnownNetwork`; genesis must equal the key's bound network, and the
configured-network check happens only at the chain read, which on sign runs
after the approval gates, so an unconfigured network reaches policy and the
operator prompt before failing unavailable. Options: call
`validateKnownNetwork` before the gates in both rotating paths (code), or
document key-bound genesis plus the chain read as the rotating network
authority and scope I10.
Both resolved in code on branch `fix/drift-rb4-i10`: `commitAndReload` now
enters recovery and then reloads after an uncertain commit, as restore does
(`TestPolicyApplyUncertainCommitReloadsAndEntersRecovery`,
`TestUncertainPolicyCommitBlocksExecutionBeforeReload`), and both rotating
paths call `validateKnownNetwork` before any gate or chain read
(`TestRotatingRefusesANetworkThisNodeIsNotConfiguredFor`). The
`ErrStoreRootCommitStateUnknown` edge remains open.

Drift review (2026-10-31, HEAD `343fdd36`): range `9fbbb5a6..343fdd36` (100
commits). `make formal-test` (16 runs) and `make formal-test-deep` (8 runs)
match their recorded outcomes and metrics; both negative controls still fail
on their named properties. The traceability anchor sweep found every cited
file and named test present. The range did not touch the approval coordinator,
session ownership, store-root commit, enrollment queue, recovery binding, or
guarded assembly code (`approval/`, `adminserver/`, `genstore/`, `storepass/`,
`enrollqueue/`, `enrollment/`, `templates/`, `backupadmin/`, `keystore/file.go`
are unchanged); `productruntime/runtime.go` and `daemon/server.go` gained only
rotating status and recovery state, not queue or registry publication. The
`d2bd5ea5` uncertain-commit recovery order was resolved in the previous
review. Checked in modeled signing areas: `04291e8c` makes `user_auto_approve`
satisfy every forced review requirement (`requestGroupApprovalWithContext`,
single-transaction and component gates) while hard rejections still run first,
which `policy_precedence.tla` and `composition.tla` already express
(`Decide`: deny, then review satisfied by auto-approve) and the spec comment
was updated in that commit; protocol rekeys to a signer-proved rotation stage
are excluded from warning analysis, which only removes a review trigger inside
the review family. `655349ae`/`30fc4766`/`edfa993d` add a bounded-admin rekey
target refusal before policy and again at release; it is an extra fail-closed
conjunct on the admin path and does not change the base-gate order or the
sentry-bypass property in `bounded_cosigner.tla`. `76769767` hardens the
rotating single-transaction planner and approval binding; rotating remains
outside the models. No divergence found; nothing to fix.

New-surface candidates (no spec covers them): the rotating flow has grown
since the last review (`rotate recover` with per-unlock recovery grants keyed
by the lock generation, one-time leaf choice and release memory with
leaf-family spend holds during restore, SLH-DSA stateless stages), adding to
the already listed rotating model-extension candidate; the release-memory
rebuild from the audit log at unlock and the recovery allowance reset on
lock-generation change are the durable and runtime transitions a rotating
model would need first.

Follow-up (2026-10-31): `rotating_leaf_release.tla` models the rotating
leaf-family release memory, the first rotating-flow model (it narrows the
rotating model-extension candidate below to the leaf choice; the prepare-time
`rekey_to` mutation, stage-proof, timing, and open-test refusals, and the
stage-table recovery grants remain unmodeled). LF1-LF3 hold over 6,868,682
states (depth 34; deep 46,925,814 at depth 38) with the stated loss sources
(failed audit write, rotated log, failed restore) tagged and excluded from the
claim. Two negative controls each violate LF1: `WaitForRestore = FALSE`
(sign before the post-unlock restore) in 259 states at depth 6, and
`SeqGuard = FALSE` (a stale status observation erases a newer release) in
1,918 states at depth 9. Prose companion
`FORMAL_TLA_ROTATING_LEAF_RELEASE_MODEL.md`; traceability section added. The
gap found while writing it, that no Go test drove `SignRotatingWithContext`
through the restore wait, is closed by
`TestRotatingLeafSignWaitsForTheReleaseRestore` (verified to fail with the
`AwaitRestored` call removed). The check at leaf choice later made that test
pass without the wait, so `TestRotatingSignWaitsForARestoreAndThenSigns` now
detects the removal.

Model-extension candidates: the rotating flow (`/sign/rotating/prepare` and
`/sign/rotating/sign`: same slot classes and gates, but a prepare-time
`rekey_to` mutation and post-approval stage-proof, timing, and open-test
refusals that no model represents); plugin presign-plan's post-sign
`verifySignedAgainstPlan` check (no conjunct or dummy slot class in
`plugin_signing.tla`); the approval-binding refusal after Approve in
`approval_composition.tla` (currently a sound over-approximation); and the
coordinator's Queued-to-failed path when the post-turn client recheck or the
send fails (folded into Cancel/Failed today).

Drift review (2026-11-03, HEAD `c6ffc6b7`): range `343fdd36..c6ffc6b7` (168
commits, 137 non-merge). `make formal-test` (19 runs) and `make
formal-test-deep` (9 runs) match their recorded outcomes and metrics; all four
negative controls still fail on their named properties. `metrics.json` matches
every model status header. The range did not touch the approval coordinator,
guarded assembly, bounded cosigner, or plugin signing code. Checked: `23b494e2`
adds a two-minute pre-auth login deadline (`AuthOutcomeTimedOut`); it fires
only on a read, so always before a passphrase verifies, and leaves through the
same disconnect defer as a failed auth with `cleanupRuntime` false, which
`session_ownership.tla`'s `Exit` already covers (comment updated). `62ca8e6e`
makes `asa_set.json` and its sidecar optional generation authority, pinned in
the inventory and seal like `default.json` and re-signed inside the staged
generation on passphrase rotation; the mint order, exact-input pinning, and
single root rename in `store_root_commit.tla` are unchanged. `22e65243` adds a
new store-commit caller, `admin/asaset.go::mutateASASet` (ASA confirm/remove):
it refuses in recovery and calls `SetRecovery` inside `WithStoreMutation` on an
uncertain commit (then reloads) and on a failed reload, matching
`recovery_binding.tla`'s `CommitRoot`/`ReloadFail`; added as a stand-in in the
model doc and the RB2 anchors. No Go test pins its recovery-before-release
order the way `TestPolicyApplyEntersRecoveryBeforeReleasingTheLock` does for
policy apply; that is a test gap, not a divergence. `productruntime/runtime.go`
gained ASA set, policy alert, and stage-work wake state only; queue and
registry publication are unchanged. `44156763`/`84e8c055` move client and
cosigner verdicts into `policyeval.Evaluate` (Deny, then `ReviewRule`, then
`ApprovalRule`, then the operator default; cosigner Approve/Reject only),
which is `policy_precedence.tla`'s `Decide`; `ec685803` drops the self no-op
routing exemption so routing (deny tier) judges it before auto-approval, which
only removes a bypass of the deny tier. The rotating sparse-recovery commits
(`0ae80999`, `31389c1a`, `934e20b1`) do not change the leaf-release guards:
`ObservedSeq` is still read before the chain read, the sign path still calls
`AwaitRestored`, and release memory feeds stage search only as a candidate,
never as an observation. The audit bounding commits (`1aa80b46`, `c13a7e56`,
`d4729f33`) bound string fields only (transaction IDs and addresses fit), so
`ROTATING_RELEASE` entries keep their leaf fields and still load at unlock, and
oversized refused requests can no longer rotate release history out of the log
(one of `rotating_leaf_release.tla`'s tagged loss sources). Anchor sweep: one
stale anchor fixed: PS6 cited `signing/approval.go::EvaluateAutoApprovalRules`,
removed by `44156763`; it now cites `policyeval/policyeval.go::ApprovalRule`
fed by `approval.go::planFacts`. Every other cited file and named test exists.
No divergence found.

Drift review (2026-11-07, HEAD `f6385272`): range `c6ffc6b7..f6385272` (142
commits, 103 non-merge). `make formal-test` (21 runs) and `make
formal-test-deep` (9 runs) match their recorded outcomes and metrics; all seven
negative controls still fail on their named properties. `metrics.json` matches
the model status headers. Call sites of the store-root commit, `storemut`,
`BindStoreRootSelection`, session displacement and promotion, approval fail-all,
assembly, and `PublishSnapshot` are unchanged, and the range did not touch the
approval coordinator or plugin signing code. Checked: `49a60365` routes guarded
and bounded verification through `sigconstruction`; check order and failure
outcomes are unchanged, an unsupported base is refused where a failed
verification was, and bounded classification did not change, so
`guarded_assembly.tla` and `bounded_cosigner.tla` hold. `56eefed1` touched
session code only to zero serialized responses, and its `ParseStoredPayload`
keeps every strict decode check (S9 anchor updated). The rotating restore and
reset changes (`236cf13e`, `cad57882`, `e6a6e982`, `11504a8a`) updated
`rotating_leaf_release.tla` in the same commits, and `2651c553`'s
`!StatelessHash` test selects the same families as the model's leaf family.
`prepare_generate_key` (`3ed5a757`) is read-only and grants nothing, because
generation repeats every check. #209 and #210 changed filenames and client file
guards, outside every model apart from the anchors they updated.

Model-extension candidates: (1) the rotating sign path's lock gate (`0ece719a`):
`keyUse` cancels on lock, lock waits for holders, and `releaseRefused` runs again
after the seed closes and after the last audit write. `rotating_leaf_release.tla`
checks leaf reuse and models `Lock` only through release memory, so "no rotating
signature leaves after a lock" is covered by `rotating_lifecycle_gate_test.go`
alone. Recommended: extend that spec with this property. (2) Mnemonic export
(`56eefed1`), a new secret release ordered as fresh passphrase, mutation lock,
key-use window, full `ParsePayload`, delivery, then audit: record as out of
model unless the key-use property lands, which would cover its lock step.
(3) `rebuildPreparedRotatingGroup` (`2fa04553`) and the bounded templates, general
provider, and timelocks (`cbd0ed0b`, `b5cc35b4`, `4c4cfeb7`, `864520ac`): out of
model. The first is a deterministic pre-release check, and the others are
on-chain program properties that the golden and AVM tests own. Follow-up (same
day): candidate (1) is modeled in `key_use_lock.tla` rather than as an
extension of `rotating_leaf_release.tla`, whose state space is already in the
millions; the lock path is shared with mnemonic export and the stage table
worker, so the new module covers candidate (2) too.

New-surface candidates: the policy apply reviewed-snapshot precondition
(`1f6fde35`, `policy_snapshot_changed`) is a pre-commit compare-and-swap that
only refuses, outside every model's scope. The rotating stage tables are now
sparse and recover a live stage without rebuilding history, and restore
publishes rotating stage hints after a successful mutation; both extend the
already listed rotating stage-table recovery candidate rather than adding a
new one.

2026-11-08, account overlays phase 5: the dedicated cosigned account type
(flow `cosigner1`) retired, and
`guarded_assembly.tla` with it, along with its cfg, its metrics row and both
companions (`FORMAL_TLA_GUARDED_ASSEMBLY_MODEL.md` and the English
`FORMAL_GUARDED_SIGNING_MODEL.md`). A8, the one assembly check the cosigned
flow keeps, moved into `bounded_cosigner.tla` as `A8_PassthroughTxidBound`:
the abstract `passthrough` input became the code's three checks (decoded
txid, signature present, no locally held cosigned signer). TLC: 2,127,872
distinct states, depth 4; dropping any one of the three conjuncts violates
`Safety`. A1, A3, A6, A7 and A14 described the dedicated account's user
component and its assembly and retired with it. A2, A4, A5, A9-A13 and A15
moved to the Bounded Cosigner section of `FORMAL_TRACEABILITY.md`, their prose
to the bounded cosigner companion; A2 now covers cosigned accounts on a plain
or bounded host, with a new test (`TestPlainSignRefusesACosignedAccount`). The
plain host (`plain1`) and the lifted product restrictions change no model: the
cosigned flow's paths and gates are the same on either host, which differs only
in which transactions classify onto the spend path, abstracted as `classified`.

Drift review (2026-11-09, HEAD `b27b250e`): range `f6385272..b27b250e` (69
commits, 63 non-merge: the account-overlays stack, phases 2 to 6.5, PRs
#217-#224, and `key_use_lock.tla`). `make formal-test` (26 runs) and `make
formal-test-deep` (10 runs) match their recorded outcomes and metrics; all
twelve negative controls still fail on their named properties. The range did
not touch the approval coordinator, store-root commit, enrollment queue,
plugin signing, or rotating leaf-release code. Session ownership code
(`ipc.go`, `session.go`, `displacement.go`, `manager.go`) is unchanged; the
admin protocol major version moved to 8, rejected before the passphrase as
before. `keystore/file.go`, `PublishSnapshot` and the planner snapshot gained
only a `BaseKeyType` field, and `admin/service.go` renamed the generation
settings, which write `config.yaml`, not the store root, so
`recovery_binding.tla` holds. `ApprovalWait` wiring is unchanged.
`key_use_lock.tla` landed in the range (`6e2b5d2e`) and holds against
`KeyUseContext` (refuses while locked, under `keyUseMu`), `drainKeyUsers`
(cancel, then wait), `performLockCleanup` (drain before the session clear),
`SignRotatingWithContext` (lock generation captured, `releaseRefused` before
the seed is used, seed closed and key use ended before the audit write, a
final `releaseRefused`) and `ExportKey` (a context check on each side of the
read, delivery inside the key use). `bounded_cosigner.tla` changed in the
range with its bookkeeping (`5b44df67` admin key removed, `61c00b9c` and
`74e8f042` cosigned and listed rekeys, `0a68bbcc` A8) and holds against the
code after phases 6 and 6.5: the base gate runs `ValidateFrozenComponentContext`,
`validateBoundedComponentPlan`, `approveGroupWithPlanContext` and
`checkApprovalBinding` before `signBoundedBaseComponent`; the client asks the
cosigner only after every base component and context position, and only for
paths that need it; assembly decides the path again through
`boundedAccountPath`, requires the receipt, the base signature and on a
cosigned path the cosigner signature, refuses a presented cosigner signature
on a listed rekey, and `validateCosignedPassthrough` keeps the three A8
conjuncts; any failure returns no group. Phase 6.5's Ed25519 bounded2 account
with a cosigner (`bounded_construction.go`, `composeddsa/bounded_support.go`)
adds a base to the same flow, verified through the base's construction, which
`receipt` and `baseSig` abstract. The sign boundary, policy precedence and
composition models see removals only (the bounded admin route and
`PrepareBoundedAdminWithContext` in `5b44df67`, the user component role and
`cosigner1` in `23550e0d`); the three-way `rekeys` setting (`efd15370`, where
an unset value rejects every rekey), the listed-rekey warning scope
(`dfe5408d`) and `bounded_rekey_requires_review` (every bounded rekey,
satisfied by user auto-approve) change members of the deny and review
families, not their order. Anchor sweep: every cited file, named function and
named test in `FORMAL_TRACEABILITY.md` exists. Fixed here: the bounded cosigner
companion's status header still gave phase 4's 531,968 states (now 2,127,872,
as `metrics.json` and its own body say), and it and a `bounded_cosigner.tla`
comment described a Falcon-signed receipt minted during spend signing (it is
signed by the account's base, Falcon or Ed25519, on all three paths since
phase 5); the companion no longer calls the retired assembly model a
complement; `FORMAL_TEST_GAPS.md`'s user-component gating entry, which cited
the deleted `component_gate.go` and the retired `cosigner1` choreography,
moved to the closed notes; `FORMAL_SIGNING_AUTHORITY_MODEL.md` no longer says
no model covers the rotating flow; `FORMAL_TXN_PLANNING_MODEL.md` names the
one cosigned flow. No divergence found.

New-surface candidates: none needs a model. Recorded as out of model, each a
single fail-closed check pinned by Go tests: a listed rekey on ordinary
`/sign` (`c9ac91db`) is refused at classification before policy when its
target is not listed, and at release the list is rebuilt from the spending key
and its root compared again; the signer's completed-workflow table is kept
apart from generation admission (`ba635f3a`) and refuses at release, through
`boundedSpendingProofVerifies`, a base its workflow cannot complete; a key
record whose rekey-to list root disagrees with its metadata is refused at
load (`74e8f042`). apadmin's archive and generations discard routing
(`c2386189`) reaches the existing RB1-anchored handlers and adds no daemon
caller.

Follow-up (2026-11-15): `rotating_leaf_release.tla` gained a lagging node. A
status pass's chain read may now show any stage the account has already left
(`NodeMayLag`), and the clear is guarded by `NextStageGuard`: the memory is
forgotten only when the read shows the stage the remembered release hands the
account to (`RotatingStatus`, `rec.NextAddr`). An external audit found the gap
the old model could not show, because its `Observe` always read the true
chain: a read made after a release, from a node that was behind, showed an
earlier stage, cleared the live stage's history, and the next transaction
reused a leaf. LF1-LF3 hold over 7,871,090 states (depth 34; deep 54,796,612
at depth 38). The new negative control `rotating_leaf_release_negative_lag.cfg`
(`NextStageGuard = FALSE` with a lagging node) violates LF1 in 9,542 states at
depth 12. `_negative_seq.cfg` now turns `NextStageGuard` off as well and has
no lagging node (9,273 states at depth 12, unchanged): with `NextStageGuard`
on, a read made before a release never shows the stage that release hands the
account to, so the sequence guard decides nothing in this model; the code
keeps it. The other controls moved with the larger state space (`_wait` 813,
`_recheck` 493, `_cut` 6,629). Out of model, pinned by Go tests:
`ReleaseMemory.record` never lets an earlier stage's release replace a later
stage's history (a sign on a lagging read is not modeled), and the stage table
worker publishes a pass's status only in the lock generation the pass ran in
(`lockRuntime.WhileGeneration`, a read-side check that adds no transition to
`key_use_lock.tla`).

Follow-up (2026-11-15, recovery): entering recovery from the unlocked state
now ends the unlocked session (`runtime.Runtime.SetRecovery` and
`TryRecovery` advance the session generation, a counter kept apart from the
one the unlock fence compares, and `productruntime` cancels the key uses the
session handed out; nothing is cleared, since recovery keeps the keyring). Before, an
unlocked, recovery, unlocked round trip left no trace: a rotating signature
was returned across it during the audit write, where the equivalent lock
round trip withheld it, and an account the session's restore had skipped
could come back through the reconcile and sign with its leaf history missing.
`key_use_lock.tla` gained `EnterRecovery`, `LeaveRecovery`, a ghost `ended`
and the guard `RecoveryEndsSession`; KU1 now covers a recovery as well as a
lock: 587 states at depth 13 (deep 886 at depth 15), and
`key_use_lock_negative_recovery.cfg` violates KU1 in 270 states at depth 8.
The depths fell although the model grew, because a recovery and its
reconcile are two steps where a lock and an unlock are four, so the bound on
transitions is reached sooner. Its other controls
moved with the state space (`_recheck` 165, `_generation` 267, `_drain` 105,
`_register` 137, `_register_export` 479). `rotating_leaf_release.tla` gained
an account that may be absent at an unlock (`absent`), a `Recover` round trip
and the same guard, standing there for the generation advance together with
the memory serving only the session it was restored for
(`ReleaseMemory.ServeSession`): 14,592,306 states at depth 31 (deep
100,666,564 at depth 35), and `rotating_leaf_release_negative_recovery.cfg`
violates LF1 in 12,942 states at depth 12 (`_wait` 605, `_recheck` 468, `_cut`
3,085, `_seq` 14,863, `_lag` 15,008). Out of model, by the user's decision a
documented operator step and not a guard: an account that returns by a plain
reload in the same session (a restore that commits cleanly, or an import,
after the session's restore skipped the account) has no hold;
`USER_STORE_MGMT.md` says to lock and unlock after it. Also out of model: the
sign reads its session before its approval, so a recovery during a pending
approval withholds the signature (a Go test pins it), and the rotating
recovery memory's grants and allowances, keyed by the same generation, begin
afresh after a recovery. `AGENTS.md` names `SetRecovery` in
the `key_use_lock.tla` row.

Drift review (2026-11-16, HEAD `e2377660`): range `b27b250e..e2377660` (386
commits, 285 non-merge: the restrictions work, the transaction and Codex
audit fixes, LogicSig argument targets, the rotating stage constant and
Indexer lookup, and PRs #292-#294). `make formal-test` (29 runs) and `make
formal-test-deep` (10 runs) match their recorded outcomes and metrics; all
fifteen negative controls still fail on their named properties. The range did
not touch the approval coordinator, session ownership, store-root commit or
enrollment queue code (`productruntime/runtime.go` changed only outside the
registry and queue publication; `ErrAppliedNotDurable` is still the queue's
own, apart from the settings' `fsutil.ErrPublishedNotDurable`). `ApprovalWait`
is still always set (60 seconds when unset, 30 seconds to 30 minutes when
configured, not writable from apadmin). `bounded_cosigner.tla` holds: the base
gate order, the cosigner asked only after the base components, assembly's
receipt, base and cosigner requirements, the refused cosigner signature on a
listed rekey, atomic output and the three A8 conjuncts are in place; the
passthrough decode moved to `canonical.DecodeSignedTxn` with the checks in the
same order, and `signedTxnHasSignature` now refuses a multisig with no signed
subsignature. `plugin_signing.tla` changed in the range with its bookkeeping
(PS8, the rekey target rule) and holds; the non-interactive refusal for a
pregrouped-signed group moved from `reviewPregroupedSigned` into
`CheckPluginGroup`, before rendering, and the plan check moved into
`clientsign.ValidateOriginalPositions`. The sign boundary, policy precedence
and composition specs are unchanged and hold: three request modes with unknown
JSON fields now refused by the handler's decoder, the deny, review, approve,
default order in `policyeval`, and reject before any approval in `gate.go`;
the signer invariants (`rejectSignerInvariants`) run before policy as members
of the always-deny class. `recovery_binding.tla` has no code movement in the
range. `rotating_leaf_release.tla` and `key_use_lock.tla` hold against the
code after #292 and #293, guard by guard; the Indexer lookup adds no source of
an observed stage (its candidate is derived from the seed and accepted only
when it equals the authorizer the worker read from algod, and the sign path
never calls it); the `KeyUseContext` callers are the export and
`RotatingDeps.keyUse`, the latter reached from the sign, the stage deriver and
`treeFrontier`. Anchor sweep: every cited file, named function and named test
in `FORMAL_TRACEABILITY.md` and the companions exists. Fixed here: row KU1
named `lockGen` for `Lock` and `SetRecovery` (the session counter since #293,
advanced by `TryRecovery` too); row KU2 and the key-use companion did not name
`treeFrontier`, a registered key use; row I2 placed the mixed-mode refusal in
`planner.go` (it is in `GroupSignRequest.Validate`); row RB2 did not name
`direct_rollback.go`; `plugin_signing.tla` and its companion still listed
non-canonical encoding as a gap (it is checked, and not modeled) and the spec
comment placed the fail-closed refusal in `reviewPregroupedSigned`;
`rotating_leaf_release.tla`'s comment on `RecoveryEndsSession` now names
`TryRecovery`.

Open, older than this range, reported and not changed here:

- RB4 does not hold for one path. A restore rollback whose commit is
  uncertain and whose root is visibly the new generation enters recovery
  without reloading (`backupadmin/direct_rollback.go`), so the binding stays
  on the old generation until a reconcile. Restore and policy apply reload
  first. Signing is refused in recovery and maintenance authenticates the
  root itself, so RB1 to RB3 are unaffected.
- `rotating_leaf_release.tla` starts with the memory held. In the code a
  zero-value `ReleaseMemory` is open until the stage table worker's goroutine
  runs its first `Reset`, and a signer with a passphrase helper is unlocked
  before that goroutine is started. The HTTP listeners start after it, so a
  sign would have to arrive before the goroutine's first statement runs.
- `ReconcileStore` enters recovery on a failed reconcile after the store
  mutation lock is released; whether a stale cache can be served in that
  interval was not established.
- `key_use_lock.tla`'s `Unlock` needs `Wipe` done; nothing found in the lock
  runtime stops an unlock that begins after `Lock` moved the state while
  `performLockCleanup` is still running. Not established either way.

New-surface candidates, none modeled here: the settings rule that a
restrictive boolean is published before its save and reported unsaved
(`admin/service.go::updateAdminSettingLocked`), a publish-then-save ordering
no formal document mentions (new small model: the value in effect is never
more permissive than the file's); the signer invariants before policy, of
which the valid rekey target one judges every position, passthrough, foreign,
contextual and dummy included (`policy_precedence.tla` or `sign_boundary.tla`:
no group is released with a rekey to a held invalid target at any position).
Recorded as out of model, each a single fail-closed check pinned by Go tests:
a contextual position naming a held account is sized from the signer's
records on `/sign/component` and stays foreign to that request
(`ValidateFrozenComponentContext`); a transaction the network never accepts is
refused before key lookup (`validateTransactionBounds`); the Indexer stage
candidate, as above; the stage number is checked before any key signs
(`stagesign.CheckStage`). The default plugin flow is still not enumerated in
`plugin_signing.tla`, though it now shares `CheckPluginGroup` and PS8.

Follow-up to the 2026-11-16 review, decided the same day. Fixed in the code:
a restore rollback whose commit is uncertain now reloads after entering
recovery, as restore and policy apply do, so RB4 holds on that path
(`TestDirectRollbackReportsVisibleDurabilityUnknownAndEntersRecovery` counts
the reload); the stage table worker's service holds the release memory in
its `Start`, before the worker goroutine exists, so the memory is never open
ahead of the worker's first step
(`TestStageTableWorkerServiceHoldsTheMemoryBeforeTheWorkerRuns`), and `Run`
holds it when it creates the signer, so the hold does not depend on the order
the services start in. Settled
without a change: a failed `ReconcileStore` on an unlocked signer serves
nothing stale in the interval before it enters recovery, because a reconcile
never moves the root (it quarantines non-authoritative generations and
discards staging residue), every failure path of the reload either leaves the
cache of the still-selected generation or publishes an empty one, and the
late `SetRecovery` only adds a refusal. Both candidates are now models:
`setting_publish.tla` (SP1 to SP4, two negative controls) and
`signer_invariants.tla` (SI1 to SI4, two negative controls, with a deep
configuration). They are separate modules because `sign_boundary.tla` and
`policy_precedence.tla` each say to add one rather than grow, and
`composition.tla` copies their operators. `make formal-test` now has 35 runs
and `make formal-test-deep` 11; nineteen negative controls.

Established by this follow-up and fixed on 2026-11-17 (below): `key_use_lock.tla`'s
`Unlock` is enabled only once `Wipe` is done, and the code does not enforce
that. `runtime.Lock` advances `lockGen` and releases the state mutex before
its cleanup runs, and `TryUnlock` reads `lockGen` when it starts, so an unlock
that begins during the cleanup's drain passes the fence and publishes the
unlocked state. `KeyUseContext` refuses only by that state, so a key use then
registers during the drain with a context the lock never cancels, the lock
waits for it as well, and the cleanup then clears the session and the
keystore of a signer that reports unlocked (KU2's register guard does not
hold on this path). The entry is a lock on disconnect with a new admin
session authenticating before the drain ends. No key material outlives a
session it was not loaded in, since the late key use belongs to an
authenticated unlock, but the signer is left unlocked with no keys until a
lock and unlock. Options: make `TryUnlock` and `TryRecovery` wait for a
cleanup in progress before they read `lockGen`, or refuse while one runs;
then add the mutation to the spec (`Unlock` from `draining`) as a negative
control.

Fixed 2026-11-17: `TryUnlock`, `TryRecovery` and `FinishMaintenance` now wait
for every on-lock cleanup already decided to return before they read
`lockGen` (`awaitCleanups`), so an unlock can no longer begin between a
lock's state change and its session clear. A cleanup is counted in the same
critical section that moves `lockGen`, including the one an unlock runs when
it loses to a racing lock. `key_use_lock.tla` gained the guard
`UnlockWaitsForCleanup`, the property KU4 (the session is never cleared while
the signer is unlocked) and the negative control
`key_use_lock_negative_unlock.cfg` (111 states at depth 5); its positive runs
are unchanged at 587 and 886 states. `make formal-test` now has 36 runs,
twenty of them negative controls.

Drift review (2026-11-17, HEAD `6265bbf5`): range `e2377660..6265bbf5` (53
non-merge commits: the signing request review, the Ed25519 cosigner key type,
and the three follow-ups above). `make formal-test` (36 runs) and `make
formal-test-deep` (11 runs) match their recorded metrics. The anchor sweep is
clean, and `metrics.json` agrees with the module table and the status
headers.

Hold against the range: `approval_coordinator.tla` and
`approval_composition.tla` (the prompt gained a typed review as data; the
rechecks, the turn release and the three fail-all callers are unchanged, and
the approval wait still cannot be zero through `ParseApprovalWait`,
`NewRuntimeConfig` and `approvalWait`); `sign_boundary.tla`,
`policy_precedence.tla` and `composition.tla` (`gate.go`, `execution.go` and
`policyeval/` have no change; the notice severity is display only, since
policy counts findings and never reads severity); `bounded_cosigner.tla` (an
Ed25519 cosigner takes the same component, gate and assembly path, and the
receipt binds the cosigner key type); `plugin_signing.tla` (the lookalike
lines are printed, not decided on); `rotating_leaf_release.tla` (the order in
`SignRotatingWithContext` is intact and the memory is held from the signer's
creation); `recovery_binding.tla`; `signer_invariants.tla`;
`setting_publish.tla`. `session_ownership.tla`, `store_root_commit.tla` and
`enrollment_queue.tla` had no code movement.

Fixed here: the signer invariants companion and `ARCH_SIGNING.md` said a
cosigner has nothing for the valid-target invariant to refuse. Since
`b5c1d834` and `7a80e62a` it reads the addresses of the node's own Ed25519
cosigner keys and refuses a request whose set it cannot build; both passages
now say so, and SI1's row names `runCosignerGates`, `cosignerKeyAddresses`
and the cosigner test. The spec is unchanged: it takes the invalid-target
flag as given.

Divergence, open: KU4 does not hold on two paths `fcd3f2b7` left, and the
note above overstates that fix. Both were reproduced against the lock
runtime alone; neither releases a signature, and both end with the signer
reporting unlocked over a cleared session, as before the fix.

- A losing unlock's cleanup. `TryUnlock` and `TryRecovery`, on finding that
  `lockGen` moved, run the on-lock cleanup without moving `lockGen`
  themselves. A `Lock` on an already locked signer moves `lockGen` with no
  cleanup, so a second unlock that starts after it finds no cleanup to wait
  for, reads the same `lockGen` the first unlock is about to lose to, and
  publishes unlocked; the first unlock's cleanup then clears that session, or
  already has. `awaitCleanups`' comment, that a cleanup beginning after it
  returns moves `lockGen` first, is false for this cleanup. The spec has no
  action for it. Options: make the losing unlock a full lock (state, `lockGen`
  and session move in the critical section that decides its cleanup), which
  the spec's `LockState` already describes; or downgrade KU4 to the path the
  spec models and say so.
- Recovery during a cleanup. `SetRecovery` moves a locked signer to recovery,
  a cleanup in progress included, and `PromoteRecoveryToUnlocked` then
  publishes unlocked without waiting. The spec's `EnterRecovery` is enabled
  only from the unlocked state. Whether an admin session can reach a
  store-commit failure and then a reconcile while a lock drains is not
  established. Options: `SetRecovery` acts only on an unlocked or recovering
  signer, with `EnterRecovery`'s guard as its transcription; or the promotion
  waits for cleanups and the spec gains `EnterRecovery` from the locking
  states with a negative control.

New surface, none needing a model: the review an operator sees and the
approval digest are computed from one plan in one function
(`approveGroupWithPlanContext`) and each signer rechecks the binding before
it signs, a Go-level contract no spec states; lookalike findings are shown
and never force a review; the review's chain read runs after every gate and
decides nothing; the Ed25519 cosigner's other rules run at generation or key
decode. Out of model by design: a listed rekey to the account's own Ed25519
cosigner address is warned about at generation and never reaches the
cosigner. Not established: whether every cosigner key's public key reaches
the planner snapshot; if one does not, a cosigned rekey is refused, not
passed. Stale and harmless: `signing/approval.go`'s fallback
`defaultApprovalWait` is still 60 seconds.

Fixed 2026-11-18: a losing unlock's cleanup (the first open divergence
above). A `TryUnlock` or `TryRecovery` that finds `lockGen` moved now locks
the runtime as `Lock` does, moving `lockGen` and the session in the critical
section that decides its cleanup (`lockForCleanupLocked`), so a session
another attempt published ends, and an attempt still in flight loses too.
`FinishMaintenance` now publishes unlocked only if the signer was unlocked
when the maintenance began, so a lock that landed just before it stays in
force, and a maintenance that ends locked clears what it reloaded the same
way, since no later `Lock` of a locked signer would. `key_use_lock.tla`
splits `Unlock` into `UnlockStart` and `UnlockFinish` over two attempts,
which may start from any state with no cleanup running, lets `LockState`
start from locked (`BeginMaintenance`, and a maintenance that ends locked),
adds `LockInactive` (a `Lock` on a signer already locked) and the guard
`LoserLocks`, and gains the negative control
`key_use_lock_negative_loser.cfg` (2700 states at depth 10). The positive
runs grow to 3616 states at depth 18 and, deep, 5588 at depth 19, and every
other key-use negative control still fails on its own property.
Republication is not modeled; three Go tests pin it. `make formal-test` now
has 37 runs, twenty-one of them negative controls.

Aligned 2026-11-18: the recovery reconcile now enters recovery before it
releases the store mutation lock, the order `BeginReload` and `ReloadFail`
with `RecoveryBeforeRelease` transcribe. `ReconcileStore` used to call
`SetRecovery` after `reconcileReloadAndPromote` had returned. The 2026-11-16
review above settled that interval as harmless (a reconcile never moves the
root, and every failed reload leaves the selected generation's cache or an
empty one), and that still holds: this is a transcription alignment, not a
safety fix. `reconcileLocked`, the locked work, enters recovery itself. The
recovery-exit rescan after a restore or rollback passes
`enterRecoveryOnFailure=false`: it starts in recovery, so a failure leaves
it there, and a lock that came in meanwhile stands, as it does anyway now
that `SetRecovery` leaves a locked signer locked (the "Recovery during a
cleanup" fix below). A promotion refused after a clean reload enters no
recovery. The spec is unchanged; RB2's row names `reconcileLocked`,
`TestAFailedReconcileEntersRecoveryBeforeReleasingTheLock` and
`TestARecoveryExitRescanKeepsALockThatCameFirst`.

Fixed 2026-11-18: recovery during a cleanup (the second open divergence
above). `SetRecovery` now does nothing on a locked signer, a lock's cleanup
in progress included, since `Lock` sets the state first; that is
`EnterRecovery`'s guard, so the spec is unchanged. A store mutation that a
lock overtook leaves the signer locked, which refuses signing and key writes
as recovery does (RB2, RB3).
`TestALockDuringAnAdminOperationUnderTheKeyringCompletes` pins it.

Fixed 2026-11-18: the `ErrStoreRootCommitStateUnknown` edge (open since the
RB4 and I10 divergences above). Policy apply, the ASA set, restore and
rollback classified a root commit whose root could not be read back, or
matched neither the old record nor the candidate, as a failure before
commit, so a root that had landed was served from the old generation
without recovery. They now treat it as uncertain
(`genstore.RootCommitUncertain`), as for unconfirmed durability: recovery,
and a reload where the caller already reloads. A passphrase change in that
state still ends locked, and its error now says the new passphrase may be in
effect. The spec is unchanged: `CommitRoot` already stands for every commit
that may have moved the root. RB2's row names the four new tests.

Changed 2026-11-18: `enrollment_queue.tla`'s `Reject` now requires the
registry synced, as `RejectEnrollment` re-publishes a registry left unsynced
before its already-enrolled check (`ensureRegistryDurableLocked`). The check
read the runtime's registry, which after a failed publish whose file could
not be read back was an empty placeholder, so the request of an enrolled key
could be dropped (EQ6). That unreadable state stays outside the model; the
companion describes how the code now handles it. The positive runs drop to
2216 states at depth 11 and, deep, 11581 at depth 15; the negative control
is unchanged.

Fixed 2026-11-21: an unlock in flight published over a recovery entered
after it began. `TryUnlock` fenced its publish on `lockGen` only, and
entering recovery moves the session, not `lockGen`, so a second unlock of
an unlocked signer, or one begun in recovery, published unlocked over the
recovery an uncertain policy, ASA set or rollback commit entered while it ran
its passphrase checks and reload. `TryUnlock` now reads the session with
`lockGen` and, when only the session moved, publishes nothing, runs no
cleanup, and answers `RecoveryDuringUnlockMessage`, which `UnlockIdentity`
reports as `recovery_blocked`; `enterRecoveryLocked` moves the session on
every entry, one from recovery included. `commitAndReload`'s second
`SetRecovery` is gone. `key_use_lock.tla` gains `ulRecov`, a ghost
`overRecovery`, `EnterRecovery` from recovery, the guard
`UnlockFencesRecovery` in `UnlockFinish`, the property KU5 and the negative
control `key_use_lock_negative_publish.cfg` (88 states at depth 4). The
companion's note that a winning `TryUnlock` publishes over any state is
replaced. The positive runs grow to 6748 states at depth 18 and, deep, 10957
at depth 19; KU1 to KU4 still hold, and every other key-use negative control
still fails on its own property (counts in `metrics.json`).
`recovery_binding.tla` is unchanged. Model-extension candidate: an unlock
that begins in recovery reconciles under the store mutation lock, then
reloads and publishes outside it, a way out of recovery no model has.
`make formal-test` now has 38 runs, twenty-two of them negative controls.

Changed 2026-11-21: KU5's ghost read the flag its guard reads, so a mutation
of `EnterRecovery` that moved the session only from the unlocked state (the
old `enterRecoveryLocked`) still passed `Safety` at the same 6748 states.
`key_use_lock.tla` now gives KU5 its own history, `ulSawRecov` (recovery was
entered since the attempt began, whatever moved), splits the guard into
`UnlockFencesRecovery` (the fence) and `RecoveryReentryMovesSession` (an
entry from recovery moves the session), and gains the negative control
`key_use_lock_negative_reentry.cfg` (243 states at depth 5). The positive
runs are unchanged at 6748 states at depth 18 and, deep, 10957 at depth 19;
`key_use_lock_negative_recovery.cfg` grows to 1366 states at depth 8, where
the ghost and the fence's flag now differ, and still fails KU1. `make
formal-test` now has 39 runs, twenty-three of them negative controls.

Changed 2026-11-21: an unlock request on a signer already unlocked ran a
full reload under the session in service. The reload replaced the keyring,
and one that failed after opening it closed it again, so the signer said
unlocked and could not sign; it also republished the policy, the key maps
and the source token index over changes made since it read them.
`UnlockIdentity` now answers such a request from the session
(`AnswerIfUnlocked`, which holds the store mutation lock across the check and
the request's reconcile, and `AnswerFromSession`, which answers only for a
session the signer stays unlocked in from before the passphrase check to
after it; nothing is reconciled, loaded or published), and a request whose
reconcile or load fails asks the session again before it enters recovery.
`productruntime.TryUnlock` runs attempts one at a time (`unlockMu`), asks
the session again under the store mutation lock before it loads, and holds
that lock to the end of the load; an attempt the session answers ends
there, before the fence (`errAnsweredFromSession`). `UnlockCheck` is the
confirmation that the session still holds. The recovery reconcile's locked
work (`reconcileLocked`) now refuses a signer neither unlocked nor in
recovery, as restore and rollback do.
`key_use_lock.tla` splits the unlock into `UnlockStart`, `UnlockCheck`,
`UnlockLoaded` and `UnlockFinish`, gives `TryRecovery` actions of its own
(`RecoveryStart`, `RecoveryFinish`, the branch from the locked state
included), which run outside `unlockMu`, and gains the guards
`AnswersFromSession`, `AnswerEndsAtCheck`, `UnlocksOneAtATime` and
`LoadHoldsStoreLock`, the properties KU6 (no load runs under a session in
service) and KU7 (an unlock that answered from the session never locks or
clears), and four negative controls: `key_use_lock_negative_answer.cfg`
(KU6, 35 states at depth 3), `key_use_lock_negative_serial.cfg` (KU6, 6247
at depth 8), `key_use_lock_negative_storelock.cfg` (KU6, 423 at depth 5) and
`key_use_lock_negative_answer_fence.cfg` (KU7, 498 at depth 5). The header's
"Two unlocks may run at once" is gone: two unlocks no longer overlap, and the
`LoserLocks` and `UnlockWaitsForCleanup` controls now fail through recovery
unlocks. The positive runs grow to 25296 states at depth 22 and, deep, 43105
at depth 22; KU1 to KU5 still hold, and every earlier negative control still
fails on its own property (counts in `metrics.json`). `recovery_binding.tla`
is unchanged; its companion now says that a second unlock of an unlocked
signer rebinds nothing, and that an unlock begun in recovery reloads under
the store mutation lock and publishes after releasing it. `make formal-test`
now has 44 runs, twenty-eight of them negative controls.

Changed 2026-11-20: `signer_invariants.tla` gains a cosigner document's
external checks, the last gate of `runCosignerGates`
(`external_checks.go::runExternalChecks`). A second free oracle, `external`
(none, pass or refuse), sits beside `would_sign`; none stands for a
signer-role request and for a cosigner document without checks. The guard
`ExternalAfterPolicy` makes a lookup only for a request the invariants and
the policy would sign. SI5 (the external answer can refuse a signature,
never add one) and SI6 (a request an earlier gate refuses makes no lookup)
join SI1 to SI4, which are unchanged. The negative control
`signer_invariants_negative_external.cfg` violates SI6 after 50522 states
at depth 2. The positive runs grow to 101040 states and, deep, 2021040, both
at depth 2, and the two earlier negative controls still fail on SI1, now
after 50536 and 50560 states. `make formal-test` now has 38 runs,
twenty-two of them negative controls.

Changed 2026-11-22: `recovery_binding.tla` follows the reload that builds
first and publishes last, for the commit callers and the reconcile
(`productruntime.Runtime.reloadView`). `ReloadBind` became `Build`, which
reads and authenticates the root and installs nothing; the binding now
moves only when a view is published. `ReloadFail` publishes recovery's view
bound to the build's selection (`RecoveryBindsSelection`, the old
`BindBeforeValidate`), and the new `ReloadKeep` keeps the view in service
only while the root still selects its generation (`KeepNeedsBoundSelection`).
The negative control `recovery_binding_negative_keep.cfg` keeps the view
whatever the root selects and violates RB4 after 10 states at depth 4 (RB2
and RB3 too). The positive run grows to 52 states at depth 11; the RB1
control is unchanged at 15 states. `make formal-test` now has 46 runs. The
reloads not yet built this way (the watcher's, an in-place write's) keep the
view when the root stops authenticating, with the binding cleared, where the
model takes `ReloadFail`: a model-extension candidate until they follow the
failure rule.
