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
