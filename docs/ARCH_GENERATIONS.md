# Architecture Decision: Generation-Based Active Storage (v1)

**Status:** Accepted Jul 27 2026 (rollout gate 1). Implementation tracked on `feat/generation-storage`.
Written Jul 27 2026 against
`backup-recovery-batches` @ `5c77ab5e`; every path and consumer claim below was
verified against that tree, not assumed.

**Goal:** replace the Tier-1 activation journal/snapshot machinery with one
commit primitive — stage a complete generation, seal the outgoing one, flip a
pointer — so multi-file active-store transactions stop being guarded
reconstructions and become atomic by construction. Simplification is the
point: at gate 6 the rollback snapshot, `restoreActivationDirectory`, the
ownership sets, and the resume/rollback journal semantics are deleted.

---

## 1. Layout and the generational boundary

```
identities/<identity>/
  keyring.enc                  # cryptographic root (aplane.keyring.v2)
  .keystore                    # static marker: version 5 + keyring/v2
  CURRENT                      # one line: the active generation ID
  generations/
    <generation-id>/
      manifest.json            # immutable at-mint operation record (§5)
      seal.json                # final content record, written before flip-away (§5)
      keys/                    # *.key *.sen *.wit.json
      keytypes/                # *.json records, *.template
  recovered/  deleted/  sentries/  .ssh/  files/
  policy.yaml  policy.yaml.hmac  node.yaml.hmac  config.yaml
  unlock.yaml  aplane.token  passphrase  passphrase.cred
```

**Generational (exactly two namespaces):** `keys/` and `keytypes/` — i.e.
`storepaths.KeysDir`, `KeyTypeRecordsDir`, `KeyTypeRecord`, `KeyTypeTemplate`,
and the `internal/keys` file constructors rooted at them
(`CanonicalManagedCredentialPath`, `AccountKeyFilePath`,
`SentryCredentialFilePath`, `WitnessPublicMetadataPath`).

**Non-generational (everything else), decided per the verified inventory:**

| Paths | Why they stay outside |
|---|---|
| `recovered/**` (batches, entries, activation state) | must survive pointer changes; own durability machinery |
| `deleted/keys/`, `deleted/keytypes/` | tombstone namespace, not active state; a deleted key is *supposed* to reappear on generation rollback — the prior generation's copy is the rollback semantic, the tombstone is just an archive |
| `keyring.enc` and `.keystore` | the cryptographic root and its format marker are identity-scoped, not generation-scoped |
| `policy.yaml(+.hmac)`, `node.yaml.hmac`, `config.yaml`, `unlock.yaml`, `aplane.token`, `.ssh/`, `sentries/`, `files/`, `passphrase*` | not part of any activation transaction |
| `<root>/backups`, `<root>/library`, `<root>/node.yaml` | not identity-active state |

**Generation ID:** `gen-<unix-seconds>-<8 hex random>` — sortable, no
collision coordination needed. New `storepaths` validator
(`^gen-[0-9]+-[0-9a-f]{8}$`), same panic-on-invalid convention as restore IDs.
`CURRENT` contains exactly the ID and a trailing newline; anything else is
malformed.

## 2. Atomic commit unit

**The commit unit is one complete generation plus one `CURRENT` rename.**
Nothing else. No directory exchange, no partial-namespace commits, no
cross-file ordering inside the store beyond this protocol:

1. Create staging dir `generations/.staging-<gen-id>` (same filesystem by
   construction — it is inside `generations/`).
2. Copy every unchanged current file into staging as an **independent regular
   file** (never `os.Link`; `fsutil.WriteFile`'s foreign-uid in-place fallback
   must never be able to reach an inode shared with a prior generation).
3. Apply the transaction's changes in staging.
4. Validate the complete staged namespaces with the strict validator (§6).
5. Write `manifest.json` (completion state included) in staging.
6. fsync every staged file; fsync nested dirs bottom-up.
7. Rename staging → `generations/<gen-id>`; **fsync `generations/`**
   (mandatory — journaling filesystems do not order cross-directory renames;
   skipping this recreates P1c inside its own fix).
8. **Seal the outgoing current generation**: write its `seal.json` via
   `fsutil.WriteFileDurable`. Sealing happens while it is still current, so
   post-flip immutability is never violated.
9. Write `CURRENT.tmp` (new ID only), fsync, rename over `CURRENT`, fsync the
   identity dir.
10. Resolve, reload, validate.

Crash before step 9's rename: old generation is authoritative and the attempt
is discarded (§7). Crash after: new generation is authoritative. There is no
in-between by construction of `rename(2)` on a single filesystem.

Generations are minted only for multi-file transactions (v1: restore
activation; later: anything that needs one). Single-file operations mutate the
current generation in place (§4).

## 3. Path-resolution lifetime

`internal/storepaths` becomes two-phase:

- `Paths` keeps every non-generational method unchanged.
- New: `Paths.ResolveGeneration(identityID) (GenPaths, error)` reads and
  validates `CURRENT` once and returns a `GenPaths` carrying the resolved
  generation-qualified `KeysDir`/`KeyTypeRecordsDir`/`KeyTypeRecord`/
  `KeyTypeTemplate`. The legacy methods on `Paths` for those four are removed
  at gate 5 (compile-time discovery of every unconverted consumer, instead of
  silently resolving stale paths).

**Lifetime rule: resolve once per operation, under the identity mutation
lock, and pass `GenPaths` down. Never re-resolve mid-operation.** The lock
tables stay as they are: `Signer.storeMutationLocks[identityID]` guards
resolution+mutation; `ResolveGeneration` without the lock is permitted only
for read-only display surfaces that tolerate staleness (key list rendering),
never for anything that writes or that feeds a write.

Verified consumer surface that converts to `GenPaths` (complete list from the
inventory): `internal/keys` scan/save/witness-sidecars, `internal/keystore`
(plus: `FileKeyStore` caches **absolute** `KeyFile` paths in its scan cache —
the cache must be invalidated on every pointer change; the reload that
follows each flip already rebuilds it, and the dead `keysDir` field gets
deleted), `internal/keytypestate`, `internal/templatestore`,
`internal/templatelibrary`, `internal/defaultkeytypes`,
`internal/backup` (export src dirs, restorer destinations),
`internal/keymgmt`, `internal/signerapp/{storemut,keyadmin,templateadmin,templates}`,
`internal/storepass.scanTargets`, `cmd/apstore` offline commands
(`keys list`, `rebuild`, `changepass`, `sentry export`). Roughly 30 call
sites; each is mechanical once `GenPaths` exists.

## 4. Current-generation mutability

The current generation is **mutable through durable single-file operations**
(temp-write → fsync → rename → dir-sync): key generate/import, key delete
(the existing `os.Rename` into `deleted/keys/` plus a source-dir sync — the
cross-directory rename stays same-filesystem because both live under the
identity dir), keytype record Put/SetState/Delete, template install/remove.
These do not mint generations; kilobyte-sized full copies are cheap but a
generation per keystroke-level admin action is noise.

After a pointer flip, the prior generation is immutable; its `seal.json`
(written pre-flip) is the last write it ever receives. **No in-place
fallback for generational files**: writers use `fsutil.WriteFileDurable` or
fail; `fsutil.WriteFile`'s foreign-uid unsynced fallback is prohibited on
generational paths (it is unsynced, non-atomic, and with copies its blast
radius is confined to the current generation — but a torn current credential
is still a defect).

The one repo-wide guard to add: the arch test suite gains a
`TestNoOsLinkInStoreCode` (mirroring `managed_credential_files_test.go`'s
AST-walk pattern) proving no `os.Link` call exists in the tree.

## 5. Manifest and seal

`manifest.json` — immutable at-mint operation record:
`schema "aplane.generation-manifest.v1"` (following the
`aplane.backup.manifest.v1` precedent), schema_version, generation ID, parent
generation ID, created_at, operation type + stable operation ID, source
restore ID and review-token digest when applicable, rollback source generation
when a mint reconstructs older content, at-mint inventory and digests,
completion state (written before publication). It describes **the
minting transaction, not the live directory** — single-file mutations after
mint do not falsify it. `CURRENT` answers *which state committed*; the
manifest answers *which operation produced it* (post-crash idempotency and
audit correlation — the operation ID is what unlock-time reconciliation logs).

`seal.json` — final content authority, schema
`aplane.generation-seal.v2`: generation ID, sealed_at, SHA-256 of the exact
immutable `manifest.json` bytes, explicit integrity term, full inventory with
digests and member terms, and a domain-separated HMAC over a canonical
length-prefixed encoding of every security-bearing seal field except the MAC
itself. An inventory entry's `term` is zero for plaintext and the positive
term-envelope term otherwise. Written durably **before every pointer flip**
(commit step 8; rollback does the same for its outgoing generation).
Prior-generation and rollback-target validation require the identity keyring
and use the authenticated seal, never the at-mint manifest inventory — a
legitimately mutated generation would fail an at-mint check the moment it
becomes prior. An unanchored seal is current authority only: its seal term and
all term-bearing entries must equal the current keyring term. A non-current
generation **without** a seal is, by construction, an uncommitted attempt
(§7).

Historical consumers operate on one read of each file:
`ParseManifestBytes` validates the exact manifest buffer,
`ParseSealBytes` binds that exact manifest buffer to the exact seal buffer,
and `VerifyBytesAgainstSeal` checks the exact namespace-member buffer before
it is consumed. Validating a path and then reading it again is not a historical
integrity boundary.

Before a seal term retires, `BuildHistoricalAnchor` performs ordinary
current-authority validation and pins the exact seal byte size and SHA-256.
Later historical access is deliberately two-level: anchored seal validation
first checks that exact root anchor and then verifies the seal MAC using the
retained term; `ReadAnchoredBytes` checks one exact member buffer against its
authenticated size, digest, and term before `OpenAnchoredEnvelope` may decrypt
it through the specialized historical path. Inventory scans use
`OpenAnchoredEnvelopeBytes` to apply the same anchor/seal/member checks to the
exact member buffer they already hashed. A retained term key alone does not
authorize a historical generation, and an anchor alone cannot replace the key.

`CanonicalInventoryDigest` supplies the Phase 3 rollback-authority digest. It
hashes a domain string and a length-prefixed encoding of the sorted inventory
entries `(path, decoded SHA-256, size, term)` rather than JSON bytes, so
manifest and rotation-baseline authorities use one formatting-independent
definition.

`rotation.baseline.enc` is the optional post-rewrap authority for the one
rollback-eligible current generation. `internal/rotationinventory` strictly
parses the bounded `aplane.rotation-baseline.v1` plaintext, requires its
envelope to use the current term and fixed `rotation-baseline:current`
context, and compares its entry count and canonical inventory digest. A
matching authenticated baseline supersedes the at-mint manifest only for the
clean/diverged comparison; a missing, malformed, wrong-term, or
wrong-generation baseline cannot assert cleanness. Rotation preflight keeps a
valid matching baseline, durably removes a valid stale one, and preserves
invalid evidence while blocking. Rotation completion now writes a required
clean baseline before closing the pending root and never writes one for a
cutover already recorded as diverged. Restore rollback consumes only a
matching authenticated baseline; missing, invalid, unauthorized, or stale
records cannot assert cleanness.

## 6. Strict generation validator

Fail-closed and explicitly **not** the tolerant runtime reload
(`FileKeyStore.Scan` records warnings and succeeds; reload audits rejected
keys — those semantics cannot back "selected generation fails validation →
recovery"). The structural validator rejects: malformed/missing `CURRENT`
values, traversal or symlinks or non-directories anywhere in the resolved
path, missing namespace directories, incomplete manifests, unexpected
entries at the generation root, and (for sealed generations) any
seal/inventory mismatch. Orphaned durable-write temp files
(`seal.json.tmp-*`) are tolerated — the committing rename is atomic, so
residue never carries state — and reconciliation garbage-collects them.
Content-level defects (undecryptable or malformed keys, template and
key-type record defects, unexpected or noncanonical namespace filenames)
are enforced by the fail-closed reload gate with the term key.

- **Current generation at startup:** manifest schema + completion state, then
  a strict scan of live files. No at-mint digest equality (mutable current);
  any stale seal is ignored.
- **Prior generations / rollback targets:** full seal-inventory and digest
  equality.
- Any validation failure of the *selected* generation → recovery mode. Never
  silently select a different generation.

## 7. Post-crash reconciliation — discard, don't resume

`CURRENT` is the sole commit record. At startup/unlock, under the store and
identity mutation locks, before any new operation:

- `CURRENT` names the new generation → committed; keep, validate, finish
  runtime/audit reconciliation via the manifest's operation ID.
- `CURRENT` names the old generation → the attempt never committed; delete it
  and require a fresh review/activation. Nothing irreplaceable is lost (the
  pre-state *is* the current generation; the source recovered batch outlives
  the attempt), and auto-flipping would commit a destructive activation
  without operator review.
- `CURRENT` missing/invalid → recovery mode; delete nothing.

Discard eligibility is structural and reachability-based: not current, not in
the retained rollback set, not referenced by incomplete-operation or audit
recovery metadata, and unsealed (every committed-then-superseded generation
has a seal). `.staging-*` directories are unconditionally garbage. fsync
`generations/` after removals; audit the abort with the manifest's operation
ID. This pre-unlock classification checks seal presence only; it never grants
rollback authority from an unauthenticated seal. Published-but-uncommitted
generations are **never resumed**.

## 8. Release compatibility (no migration)

Every release is incompatible with every prior release and documented as
such. A store is readable only by the release that initialized it:
`.keystore` carries exactly one supported metadata version
(`checkKeyringMarker` rejects everything else with a restore-from-backup
remediation), and no layout-migration or downgrade machinery exists. Key
transfer between releases is by backup archive — standalone
release-independent encryption — restored into a freshly initialized store.
The pre-generation flat layout, the Tier-1 activation protocol, and the
`migrate-layout` transaction were removed with this policy.
## 9. Rollback and GC

Restore rollback = compare the mutable current generation with its effective
manifest/baseline authority → validate the target against its authenticated
seal or exact historical anchor → reconstruct only seal-pinned target members
into an empty staging generation, re-encrypting every envelope under the
current term → commit the fresh generation through the ordinary mint protocol
→ remove the superseded baseline after the `CURRENT` flip → reload. The new
manifest keeps the outgoing current generation as `parent_id` and separately
records `rollback_source_generation_id`; rollback never makes historical
ciphertext current again. Rollback and retained-parent pruning require an open
identity keyring. Retention: current + the previous valid generation +
anything referenced by incomplete-operation or audit recovery metadata. GC resolves
references under the mutation lock, never runs during
activation/rotation/reload/migration, fsyncs `generations/` after removals,
and starts at exactly current+previous — no age/operator policies until
reference safety has soaked.

## 10. Concurrency and watchers

- All resolution+mutation under `storeMutationLocks[identityID]` (unchanged
  hierarchy, documented in ARCH_SPEC).
- `identity.Runtime.EnsureKeyWatcher` currently watches three dirs (identity
  dir, `keys/`, `keytypes/`) and `internal/signerapp/filewatcher` is
  **non-recursive** with only pre-listed pending dirs auto-added — new
  generation directories would be invisible. Change: watch the identity dir
  for `CURRENT` replacement (rename events are already reload candidates);
  bind the `keys/`/`keytypes/` watches to the *resolved current generation*;
  on a pointer change, one coordinated reload under the mutation lock
  re-resolves and **re-arms the watcher on the new generation's dirs**
  (fsnotify watches inodes, not names). `.staging-*` and non-current
  generation events are ignored by path prefix.
- `FileKeyStore` cache invalidation on flip (§3).
- The rescue surface stays admin-protocol-owned; offline `apstore` commands
  take the store lock exactly as today.

## 11. Rotation boundary

The accepted Phase 3 design replaces bulk passphrase rotation with numbered
key terms. Guarded transition start inventories both current and retained
generation namespaces, authenticates retained members through their exact
root-pinned historical seals, and durably writes a target-term cutover
snapshot before atomically publishing the pending root. Retained generations
therefore do not require prune-all-priors quiescence and are not silently
stranded on an unauthorized term.

Generation mutation and transition start still require the same identity
mutation lock so the snapshot is taken against a cooperating-mutation-stable
view. Direct filesystem changes are handled by exact input digests and the
required final path/target-authority comparison, not by the lock. While the
root is pending, normal signer reload and key scans fail closed until the
snapshot-pinned lifecycle completes. The internal resume pass now preserves
root-anchored prior generations byte-for-byte while rewrapping only exact
pinned mutable current-generation envelopes; target outputs are authenticated
and accepted idempotently after a crash. The completion pass performs
pre/post-baseline final scans, writes a clean cutover's post-rewrap baseline
before atomically closing the root, and only then removes the snapshot.
Rollback consumption is implemented; operator wiring remains Phase 3 work; see
[PHASE3_ONBOARDING.md](PHASE3_ONBOARDING.md).

## 12. Filesystems, crash ordering, ownership

- Supported: Linux and Darwin on a **single filesystem per identity store**
  (already assumed by five existing cross-directory `os.Rename` sites). This
  is a documented store requirement, not probed at runtime: a store that
  violates it fails its first commit's publish rename with `EXDEV` before
  anything durable refers to the staged generation.
- Durability primitives: `fsutil.WriteFileDurable`/`SyncDir`/`RemoveDurable`
  exclusively for commit-path writes; `fsutil.TestHook` is the crash-matrix
  injection seam.
- Ownership: copies preserve mode and group per `WriteFileDurable` semantics;
  `normalizeManagedStoreOwnership`'s `WalkDir` + `Lchown` covers
  `generations/**` automatically (verified symlink-safe).
- The `.key`/`.sen` literal ownership arch test constrains new code to route
  filenames through `internal/keys` (verified constraint, kept).

## 13. Verification (crash matrix and tests)

The commit protocol is machine-checked by `docs/formal/generation_commit.tla`
(run by `make formal-test`). It models the mint sequence against a crash at
every step and a filesystem that may lose any write whose fsync has not
completed, and checks that CURRENT never names an unpublished generation
(G1), the parent is sealed before the child becomes current (G2),
reconciliation discards uncommitted attempts on an undamaged store (G3), a commit with unconfirmed
durability blocks signing (G4), and reconciliation restores a durable
pointer (G5). The model is the exhaustive companion to the fault-injection
tests below, which check chosen interruption points; it does not model
content validity, which is a reload-gate concern.

Fault injection via `fsutil.TestHook` at every §2/§8 boundary; after every
simulated interruption, startup selects the complete old or complete new
state — never a mixture, never missing. Additional required tests, per the
plan plus inventory findings: inode independence across generations;
no-`os.Link` arch test; single-file mutation then mint; pointer rollback;
malformed/missing/truncated/traversal `CURRENT`; manifest and seal
corruption; unsealed-non-current discard including superseded-parent
collection; watcher re-arm across a flip (extending
`daemon/key_watcher_test.go`); `FileKeyStore` cache invalidation across a
flip; migration retry at every interruption; old-binary rejection
(`TestOpenKeyringStoreRejectsUnsupportedMarkerVersion` already proves the
mechanism — add the migrated-store end-to-end case); rebuild/changepass/
`keys list` offline resolution; rotation-quiescence refusal; ownership of
copied files; Linux+Darwin. The ~25 hardcoded-layout test fixtures found in
the inventory are updated at gate 5.

## 14. Rollout gates (unchanged from the plan)

1. This document accepted.
2. Resolver (`GenPaths`) + strict validator, behind tests.
3. New-store creation generational.
4. Migration passes the crash matrix.
5. All consumers generation-qualified (legacy `Paths` methods deleted).
6. Activation moves to the generation commit; Tier-1 journal/snapshot,
   `restoreActivationDirectory`, ownership sets, and
   `activationSnapshotDirectories` are retired.
7. Rotation epochs only after a separately accepted Phase-B design.

## 15. Explicitly rejected alternatives

Hardlinked generations (in-place fallback would mutate shared inodes);
directory-exchange/renameat2 intermediate (two platform-conditional swaps vs
one portable commit point, and two migrations); generation-per-mutation
(manifest immutability is achieved by the seal split instead); resuming
uncommitted generations (auto-commits a destructive activation without
review); a separate layout-version marker file (the `.keystore` version gate
already exists, is enforced by every binary, and avoids a second commit
record).
