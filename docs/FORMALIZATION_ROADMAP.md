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
| `bounded_sentry.tla` | bounded-sentry composition |
| `store_root_commit.tla` | atomic generation/key-authority commit, exact-input promotion, crash classification, and quarantine |

The single-product runtime has no decommission state or operation lease, so the
formal inventory contains no lifecycle model for those concepts. Runtime
reload order is tracked as RL1 in `FORMAL_TRACEABILITY.md` and its Go regression
tests.

## Working rules

Every model change must update, in the same commit:

- its prose companion and `FORMAL_TRACEABILITY.md` anchors;
- normal and deep configurations;
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
4. Keep native signing authority and bounded-sentry refinements aligned with
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
abort-on-first-failure, bounded-sentry gate order, sign-boundary mode
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
`bounded_sentry.tla` — a limits note was added to its model doc; (2)
`store_root_commit` is missing its prose companion doc, header code anchors,
and a deep configuration/`metrics_deep.json` entry required by the working
rules; (3) `FORMAL_TLA_APPROVAL_COORDINATOR_MODEL.md` lacks the status-header
convention the other TLA docs use. Behavioral wart noted (sound under SO1/SO2):
displacement is offered before auth reveals a newcomer is `auth_only`, so an
owner can confirm displacement and never be displaced.
