# Atomic Store-Root Commit Machine-Checkable Model

> Status: TLC checked over the full finite state space; the recorded positive
> run generated 14 distinct reachable states at depth 9 with no
> counterexamples. The expected-failure negative control
> (`store_root_commit_negative.cfg`, `VerifyPins = FALSE`) violates
> `S5_NoUnpinnedPromotion` after 13 distinct states at depth 7 and must keep
> producing that exact counterexample.

This model checks the atomic store-root commit protocol introduced by the
generation store: one durable `store-root.enc` record carries generation
selection, keyring epoch, and current term, and a mint becomes authoritative
only through a single root replacement after staged validation, publication
durability, and the outgoing-generation seal.

The spec lives at [formal/store_root_commit.tla](formal/store_root_commit.tla).

## What it covers

| Invariant | Meaning | TLA+ predicate |
|---|---|---|
| S1 | The selected root is one coherent authority: generation, epoch, and term always agree | `S1_OneSelectedAuthority` |
| S2 | Cutover is atomic: epoch and term move together, never separately | `S2_AtomicCutover` |
| S3 | The new generation is selectable only after its publication is durable | `S3_PublishedCompleteness` |
| S4 | The new generation is always selected under the new current term | `S4_NewTermCurrentState` |
| S5 | Promotion requires exact-input pinning: a substituted input can never reach the root | `S5_NoUnpinnedPromotion` |
| S13 | Quarantine is non-destructive and happens only while the old root is authoritative | `S13_NonDestructiveAmbiguity` |
| S14 | A quarantined publication is never the selected authority | `S14_QuarantineNonAuthority` |

## What TLC actually verifies

The transitions transcribe the commit protocol in `internal/genstore`:

- `Publish`, `SyncPublication`, and `SealOutgoing` are the staged mint in
  `internal/genstore/commit.go`: validate the complete candidate copy, sync
  the tree bottom-up, rename into `generations/`, sync the parent directory,
  then seal the outgoing generation.
- `SubstituteInput`, `BuildCandidate`, `RenameRoot`, and `SyncRoot` are
  `internal/genstore/root_commit.go`: `ValidateSealed` before a fresh exact
  reread, `AuthenticateStoreRoot`, the outgoing-generation equality check,
  and one `fsutil.WriteFileDurable` root replacement. The exact-input MAC
  binding over generation, term, and the wrapped-keyring digest lives in
  `internal/crypto/store_root.go`.
- `CrashBeforeRename`, `ReconcileOldRoot`, and `RestoreAuthenticOldRoot` are
  `internal/genstore/reconcile.go` and `internal/genstore/quarantine.go`: a
  crash before the root rename leaves the old root authoritative, and a
  complete non-current, unsealed, unreferenced publication is quarantined
  intact — never deleted, resumed, or adopted. `RestoreAuthenticOldRoot`
  additionally models an operator restoring an older authentic root file
  after a successor committed; the newer complete directory then has the
  same shape as a crashed-mint publication and must be quarantined.

The negative control is a first-class run: with `VerifyPins = FALSE`,
`BuildCandidate` accepts a substituted input, clears `promotionPinned`, and
`RenameRoot` promotes it — the counterexample TLC must find. The harness
(`scripts/run-formal-tests.py`) requires exactly that
`S5_NoUnpinnedPromotion` violation, so the exact-input pinning check cannot
silently stop being load-bearing.

## Modeling choices and limits

- The instantiated cutover is the changepass shape from
  `internal/storepass/rotate.go`, where generation, epoch, and term all move
  together. The ordinary `CommitStoreRoot` reselect keeps the term; it has no
  separate configuration because it exercises a strict subset of the modeled
  transitions.
- The model seals the outgoing generation after publication durability,
  matching `internal/genstore/commit.go`. Changepass pre-seals before staging
  and revalidates the seal during commit; the `BuildCandidate` conjunction
  (durable publication and outgoing seal both required) holds for both
  orderings.
- Durability, validation, sealing, MAC verification, and quarantine
  classification are abstract booleans. The concrete cryptography, strict
  parsing, and filesystem sync behavior are covered by `internal/genstore`,
  `internal/crypto`, and the store integration/crash harnesses
  (`make store-lifecycle-test`, `make store-crash-test`).
- The normal configuration already exhausts the model's full finite state
  space, so no deep configuration exists for this module; this note is the
  record required by the roadmap working rules.
- Recovery-blocked signing after an unconfirmed root replacement is a runtime
  consequence enforced in `internal/signerapp/backupadmin` and the product
  runtime; the model covers the durable-authority side (no blind retry can
  make an unconfirmed root authoritative by itself).

## How to check

```sh
make formal-test
```

For the focused runs:

```sh
java -jar tla2tools.jar -config docs/formal/store_root_commit.cfg \
  docs/formal/store_root_commit.tla
java -jar tla2tools.jar -config docs/formal/store_root_commit_negative.cfg \
  docs/formal/store_root_commit.tla
```

The negative run is expected to fail with an `S5_NoUnpinnedPromotion`
counterexample; the make harness asserts that expectation.

## Linking back

- Architecture: [ARCH_GENERATIONS.md](ARCH_GENERATIONS.md) and
  [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md) (Store Root and Generation Store).
- Traceability: the Atomic store-root module section in
  [FORMAL_TRACEABILITY.md](FORMAL_TRACEABILITY.md).
- Concrete tests: `internal/genstore` package tests and the
  `test/storeintegration` lifecycle/crash harnesses.
