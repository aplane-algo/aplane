# Proposal: Key-Term Rotation (Lazy Re-Encryption)

Status: **proposal — open questions resolved, ready for acceptance review**.

Refreshed against the tree after the generation-storage branch merged: the
design core is unchanged, but the version gate no longer needs a migration
(the release policy retired in-place upgrades) and the sequencing note is
spent. All five open questions below are now decided, with the reasoning
recorded inline. What remains before implementation is an acceptance review
of those decisions, not further scoping.

## Problem

`apstore changepass` re-encrypts every managed file under the new master key
using a two-phase `.new`/`.old` swap (`internal/storepass/rotate.go`). Review
finding (migration/CLI round): a crash during phase 2 leaves the current
generation with **mixed-key content** — some files under the old key, some
under the new — and no supported recovery path. The documented sibling-retry
reconciliation covers recovered-batch files only
(`internal/backup/recovered/rotation.go`); managed keys, templates, and
`.keystore` itself have none. On a generational store, strict validation then
fails closed into recovery whose only exit is restore-from-backup.

The root cause is structural: bulk re-encryption makes "every file under
exactly one key" a *global* invariant that a crash can violate. HashiCorp
Vault's barrier keyring avoids the class entirely: rotation appends a key
*term*; every entry records the term that encrypted it; old terms remain
decryptable forever. Rotation is O(1) metadata, and the mixed-"key" state is
simply the normal state — always readable.

## Design sketch

### Key hierarchy (two layers where there is currently one)

```
passphrase --KDF--> KEK (key-encryption key)
KEK        --wraps--> keyring file: [{term: 1, key: ...}, {term: 2, key: ...}]
term key   --encrypts--> individual store files
```

- `keyring.enc` lives beside `.keystore` in the identity metadata directory,
  encrypted under the KEK. `.keystore` continues to carry KDF parameters,
  verifier, version/layout gate.
- Every encrypted file gains a small header field `term: N` (the current
  AES-GCM envelope already has a versioned header to extend).
- **Passphrase change** = re-derive KEK, rewrap `keyring.enc`. One durable
  single-file write (`fsutil.WriteFileDurable`) — atomic today, no new
  machinery. Data files untouched.
- **Master-key rotation** = append term N+1 to the keyring. New/updated files
  encrypt under the newest term. Old terms are never deleted while any file
  references them.

### Interaction with generations (the part Vault doesn't have)

- Seals hash **ciphertext**. A sealed prior must therefore never be
  rewrapped — and never needs to be: its old terms stay in the keyring, so
  rollback targets remain readable under any number of subsequent rotations.
- Only the **current** generation (mutable by contract) may be lazily
  rewrapped, one file at a time via the existing durable single-file write
  primitive. A crash mid-rewrap leaves each file wholly under one term —
  always decryptable, never a defect.
- **The rotation quiescence requirement dissolves.** Today `changepass`
  demands `prune --all-priors` (abandoning every rollback fallback) precisely
  because bulk re-encryption would strand priors under the old key. With
  retained terms, priors and rotation coexist; the prune-then-rotate workflow
  and its content-validation gate become unnecessary.
- `apstore generations prune` naturally garbage-collects term references;
  a term unreferenced by any live generation can be dropped from the keyring
  (optional hygiene, not required for correctness).

### Version gate

The keyring layout is a store-format change: bump `.keystore` to version 4
(`keyring/v1`). Old binaries reject v4 exactly as pre-keyring binaries
reject v3.

**There is no v3→v4 migration, and none should be written.** The release
policy is that a store is readable only by the release that initialized it;
`internal/storemigrate`, `apstore migrate-layout`, and the
migration-in-progress completion hook this proposal originally planned to
reuse were all deleted with it. A v4 store is initialized as v4, and
existing stores move across by exporting a backup archive and restoring it
into a fresh store — the same path every other release boundary uses.

That removes the riskiest workstream the proposal originally carried: a
metadata migration with its own crash matrix. It also means the v4 envelope
does not need to stay readable by v3 or vice versa, which simplifies the
header change (see open question 3).

The operational consequence is worth stating plainly: shipping v4 obsoletes
every store initialized by an earlier release. That is free today — there
are no operators — and it is the cost the no-backcompat policy already
accepts everywhere else.

## What this retires

- The `pendingFile` two-phase swap machinery and its unrecoverable crash
  window (rotate.go), including `rollbackPendingFiles`/`swapPendingFiles`.
- The recovered-batch sibling reconciliation special case.
- `requireGenerationQuiescence` and the `prune --all-priors` prerequisite,
  along with the destructive-prune confirmations and rollback-history
  warnings that exist only because rotation forces that prune today.
- The rotation/generation-rollback unreadability hazard noted at
  rotate.go's quiescence comment.

## Open questions (resolved)

1. ~~**Backup format.**~~ **Answered: independent.** `.apb` payloads are
   sealed with `crypto.EncryptStandalone` (envelope v2) under the export
   passphrase, and the archive's sealed manifest uses the same envelope and
   passphrase. Neither touches the store master key, and restore
   re-encrypts under the destination's key on the way in. Archives are
   therefore unaffected by terms, and remain the transfer path across the
   v4 boundary.
2. ~~**Memory handling.**~~ **Decided: the keyring exposes operations, not
   key material. `WithMasterKey` is replaced by `WithKeyring`.**

   ```go
   WithKeyring(func(kr *crypto.Keyring) error {
       sealed, err := kr.Seal(plaintext)    // newest term, stamps the header
       plain,  err := kr.Open(sealed)       // reads the header, selects the term
       hk,     err := kr.IntegrityKey(term) // sidecar sign/verify
   })
   ```

   The ~99 non-test `WithMasterKey` call sites almost all open a closure
   purely to obtain bytes for `crypto.EncryptWithMasterKey`. Handing them an
   operation instead makes them shorter, makes term selection impossible to
   get wrong at a call site (encrypt is always newest; decrypt always reads
   the header), and collapses zeroing discipline from every caller to a
   single owner. Raw key bytes stop leaving `internal/crypto` at all, which
   is an improvement independent of rotation.

   The existing lock property carries over unchanged: `WithKeyring` holds
   the cache read lock for the callback's duration, so no term can be zeroed
   mid-use, exactly as `WithMasterKey` does today.

   Two findings shaped this:

   - **The master key has two uses, not one.** Besides encryption, it is an
     HKDF input for integrity HMACs (`DerivePolicyIntegrityKey`,
     `DeriveNodeRoleIntegrityKey`). Verification must use the term that
     signed, so sidecars need term identification too. Both
     `IntegritySidecar` types already carry `Version` and `KeyID`; add an
     explicit `Term` field and bump the sidecar version rather than
     overloading `KeyID`, which is a constant scheme tag exact-matched on
     load. Absent `Term` fails closed — with no migration, a v4 sidecar
     always carries one.
   - **Mandatory rewrap bounds the resident key set.** Once the rewrap pass
     completes, the previous term is unreferenced and can be dropped from
     the keyring. The steady state is one term, briefly two during a change
     — today's single key plus a transient second, not an unbounded set.

   This is the same refactor as open question 3; they are one workstream.
3. ~~**Blast-radius review of `crypto.EncryptWithMasterKey` call sites.**~~
   **Decided: three phases, gated by an arch test.**

   Measured, not estimated:

   | Ring | Count | Change |
   |---|---|---|
   | Direct `Encrypt`/`DecryptWithMasterKey` | 18 sites, 9 files | `kr.Seal` / `kr.Open` |
   | Functions threading `masterKey []byte` | 103 signatures, ~15 packages | take `*crypto.Keyring` |
   | `WithMasterKey` callers | 99 | `WithKeyring` |

   `EncryptedDataMasterKey` already carries `envelope_version: 1`, so the
   term is a header field added beside it. With no migration the envelope
   need not stay backward-readable: v4 reads only what v4 wrote.

   Correction to the original scoping: **caches are not in the blast
   radius.** `internal/cache` generates its own `.cache_key` and never
   touches the master key.

   Done as one change, a single missed call site writes a file under a term
   nothing records — silent, and only manifesting after the first rotation.
   Sequencing removes that risk:

   1. **Keyring with exactly one term.** `.keystore` bumps to v4;
      `keyring.enc` holds term 1 wrapping today's master key. Existing call
      sites keep working through a compatibility accessor, because with one
      term "newest" *is* "the only key" and every decrypt finds term 1. No
      behavior change, no term append. Independently shippable, and the
      easiest part to review carefully.
   2. **Migrate call sites package by package** to `WithKeyring`. Each
      package is separately reviewable, and a missed site is harmless while
      only one term exists.
   3. **Enable term append**, gated on the migration being complete.

   The gate is mechanically enforceable: an arch test asserting no non-test
   code outside `internal/crypto` calls the compatibility accessor. The
   repo already pins boundaries this way in `test/arch/`
   (`guarded_surface_test.go`), so it is a familiar pattern that runs in CI.

   In a big-bang change a missed site is a latent data-loss bug; in this
   sequencing it is a no-op until phase 3, and phase 3 does not start until
   nothing is missed.
4. ~~**KDF/KEK caching** in the daemon unlock path.~~ **Decided: cache the
   unwrapped keyring; do not cache the KEK.**

   Outside `internal/crypto` the passphrase becomes a key in exactly two
   places: `FileKeyStore.InitializeMasterKey` (daemon unlock) and
   `policyeditor/store.go` (offline, per-invocation, no caching). Today the
   first derives the master key and holds it in `f.masterKey` for the
   session, zeroed by `ClearMasterKey` on lock under `cacheLock`.

   The keyring takes that slot: derive the KEK, unwrap `keyring.enc`, zero
   the KEK before returning, and cache the unwrapped terms where the master
   key lives today — same lifetime, same lock discipline, same zero-on-lock
   (`ClearMasterKey` becomes `ClearKeyring`, iterating terms).

   Nothing after unlock needs the KEK. It unwraps the keyring at unlock, and
   rewraps it on passphrase change or term append — both of which happen
   inside `changepass`, which holds the passphrases and can re-derive. Not
   caching it means a memory disclosure of the running daemon yields term
   keys, exactly as it yields the master key today, but not the ability to
   unwrap a future keyring.

   Two things this resolves:

   - **KDF cost is unchanged.** Argon2id (64 MiB, t=2) runs once per unlock
     today and once per unlock after; the keyring adds one AES-GCM unwrap.
     There is no performance argument for caching the KEK.
   - **Passphrase verification is untouched.** The admin `VerifyPassphrase`
     path checks `.keystore`'s verifier via
     `crypto.VerifyPassphraseWithMetadata` and never consults the keyring.

5. ~~**Whether master-key rotation is even exposed** initially.~~
   **Decided: term append ships from the start, and `changepass` rewraps
   the current generation before returning.**

   Deferring term rotation is not the free simplification it looks like.
   Today `changepass` derives a new master key and re-encrypts every
   managed file, so afterwards nothing in the store is readable with the
   old passphrase. KEK-rewrap alone would not preserve that: an attacker
   who knew the old passphrase and kept a copy of `keyring.enc` can unwrap
   it, recover the term keys, and decrypt every data file — including files
   written *after* the passphrase change, since no new term exists. That is
   precisely the person a passphrase change is performed for, so shipping
   rewrap-only would silently redefine the operation.

   Appending a term protects new writes; rewrapping the current generation
   under the new term restores today's end state completely. The difference
   from today is that reaching that state is no longer atomic — and no
   longer needs to be, because a partially rewrapped store is a legal
   state: every file is wholly under one term at every instant, so an
   interrupted rewrap is resumable rather than damage.

   The rewrap is mandatory rather than an opt-in follow-up command. That
   choice costs nothing: `changepass` already runs a synchronous pass over
   every file and reports per-category counts, so the command, the wait,
   and the output shape are unchanged. It is also less filesystem work than
   the two-phase swap it replaces (one durable write per file instead of a
   `.new` write plus two renames). An opt-in `rewrap` command would instead
   add a new command, a "partially rewrapped" store state needing its own
   status surface, and an operator-facing explanation of the security
   consequence of not running it.

   Sealed priors are never rewrapped — their seals hash ciphertext — and do
   not need to be: their terms stay in the keyring, so they remain readable
   as rollback targets.

   Interrupted rewrap should report how many files remain on the previous
   term, and re-running `changepass` (or the same pass) finishes the job.

## Rough effort

- Envelope header + keyring type + v4 metadata/migration: the core, touching
  `internal/crypto` and every encrypt/decrypt call site. Largest and
  riskiest part; needs its own review cycle and crash matrix.
- changepass rewrite: net-negative code (deletes the swap machinery).
- Daemon/keystore plumbing (keyring in place of master key): mechanical but
  wide.
- Not a patch: this is a Phase-4-sized change and should not ride along with
  the current branch. Recommended sequencing: land the current branch
  (rotation refuses the crash window, fail-closed), then propose this as its
  own reviewed migration.

## Rough effort

- Envelope header + keyring type + v4 metadata: the core, touching
  `internal/crypto` and every encrypt/decrypt call site. Largest and
  riskiest part; needs its own review cycle and crash matrix. Smaller than
  originally scoped, since no migration is written.
- changepass rewrite: net-negative code (deletes the swap machinery).
- Daemon/keystore plumbing (keyring in place of master key): mechanical but
  wide.
- Not a patch: this remains a Phase-4-sized change. Its blocking
  predecessor — the generation-storage branch — has merged, so this is now
  the next substantial piece of work rather than something to sequence
  behind anything.

## Suggested approach

The archive-manifest change (`PROPOSAL_ARCHIVE_MANIFEST.md`) is the closest
precedent and went from proposal to merged cleanly. What made it work, and
is worth repeating here:

- **Settle the open questions explicitly before writing code**, and record
  the answers in this document. The manifest change resolved five questions
  up front; reviewers then argued about the design rather than about what
  the design was. Done — see the resolved questions above.
- **Write the trust and lifecycle model down first.** For the keyring that
  means stating plainly what a term is, what compromise of one term does
  and does not imply, and what rotation is and is not claimed to
  accomplish. Rotation is easy to over-read as revocation; it is not.
- **Model the commit protocol.** `docs/formal/generation_commit.tla` covers
  the generation flip under crashes; keyring rewrap and term append deserve
  the same treatment, and the existing module is a working template.
- **Expect the envelope change to be the risk**, not the keyring type. It
  touches every encrypt/decrypt call site, and a missed one is a file
  written under a term nothing records.
