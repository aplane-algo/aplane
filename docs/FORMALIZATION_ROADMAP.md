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
| `guarded_assembly.tla` | guarded component assembly |
| `plugin_signing.tla` | plugin signing trust boundary |
| `bounded_cosigner.tla` | bounded-cosigner composition |
| `store_root_commit.tla` | atomic generation/key-authority commit, exact-input promotion, crash classification, and quarantine |

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
2. Add a lock/unlock and server-shutdown ownership model if request-drain or
   runtime-destruction ordering changes.
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
