# Proposal: Key-Term Rotation (Lazy Re-Encryption)

Status: **proposal — not yet accepted; amended after two design reviews**.

Refreshed against the tree after the generation-storage branch merged: the
design core is unchanged, but the version gate no longer needs a migration
(the release policy retired in-place upgrades) and the sequencing note is
spent. All five open questions below are decided, with the reasoning recorded
inline. Two design reviews then found three defects that the decisions had
not covered, all now folded in: the cryptographic root was split across two
files and could not be changed atomically; retained terms would have stayed
authorized for current state, losing a property the store has today; and the
term reference inventory reached past generations to recovered batches,
sidecars, and deleted archives.

One question is deliberately left open for the next review rather than
decided here: **rollback semantics** — whether repointing `CURRENT` at an
older-term generation is acceptable, or whether rollback should mint a fresh
generation re-encrypted under the current term. It interacts with the
post-activation divergence guard and deserves its own argument.

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

- `keyring.enc` is the store's **single cryptographic root** and is
  self-contained: plaintext KDF parameters and salt, plus the AEAD-sealed
  term set. `.keystore` is reduced to a static version/layout marker.

  This is a correction to an earlier draft, which kept KDF parameters and
  the passphrase verifier in `.keystore` while wrapping terms in
  `keyring.enc` — and then called passphrase change "one durable
  single-file write." It is not: changing the passphrase changes the
  verifier (and possibly the salt) *and* rewraps the keyring, so two files
  must agree. A crash between them leaves new `.keystore` with an
  old-wrapped keyring, or the reverse, and neither passphrase necessarily
  unlocks that pairing. A proposal whose premise is eliminating a
  multi-file crash window must not introduce one at the most critical file
  in the store.

  Making the keyring self-contained also removes the separate verifier
  entirely: a successful AEAD unwrap *is* the passphrase check. One file,
  one atomic durable write, one thing to get right.
- Every encrypted file gains a small header field `term: N` (the current
  AES-GCM envelope already has a versioned header to extend).
- **Passphrase change** = re-derive the KEK from the new passphrase and
  rewrap `keyring.enc`. Genuinely one durable single-file write
  (`fsutil.WriteFileDurable`) now that the keyring is the only root — atomic
  today, no new machinery. Data files untouched by the passphrase change
  itself; the term append and rewrap that accompany it are separate steps
  (open question 5).
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
- **Term garbage collection needs care, and cannot ride along with prune.**
  Dropping a term rewrites `keyring.enc`, which requires the KEK — and the
  KEK is never cached (open question 4), while plain `apstore generations
  prune` never prompts for a passphrase. Only `prune --all-priors` does, and
  only because it decrypt-validates. So prune *computes and records* the
  now-unreferenced terms; the drop happens inside the next `changepass`, or
  an explicit passphrase-prompting command. Term GC is optional hygiene, so
  deferring the drop costs nothing.
- **A generation references a set of terms, not one term.** `Mint` copies
  the parent byte-for-byte, so a child minted from a partially rewrapped
  parent inherits files under mixed terms and is sealed that way. Term
  references are therefore per file. `BuildInventory` already walks every
  file at mint: have it collect the term set into the manifest, so GC reads
  authenticated metadata instead of rescanning headers — and the seal covers
  the term inventory for free.
- **"Referenced" must mean every retained durable object, not every
  retained generation.** Generations are only part of the inventory:
  - sealed priors kept as rollback targets, the `RetainedUnsealedParent`
    damage case, and anything in the recovery-metadata `referenced` set;
  - **recovered batches**, which are encrypted under the destination master
    key (`internal/backup/recovered/store.go`) and are not generation
    content at all;
  - **policy and node-role sidecars**, which reference an integrity term;
  - **`deleted/` archives**, which need an explicit keep-or-
    cryptographically-erase classification rather than being overlooked.

  Dropping a term any of these needs destroys the object silently.
- **Defer term deletion out of the first implementation.** Term GC is
  optional hygiene, the reference inventory spans four object classes, and
  the cost of getting it wrong is unrecoverable. Removal should land only
  once generation deletion is durable and a fail-closed scan proves no
  supported durable object references the term. Until then the keyring
  grows by one entry per passphrase change, which is bounded by operator
  action and harmless.

### What terms do and do not accomplish (trust model)

One fact drives most of the consequences below, and it is easy to lose
track of: **sealed priors are never rewrapped, so they pin the terms they
were written under, and a pinned term keeps its data readable to anyone who
can reconstruct that term.**

- A term is a data-encryption key, not an identity or a capability. Files
  record the term that encrypted them; the keyring maps term to key.
- **Rotation is not revocation.** Appending a term protects *subsequent*
  writes. It does nothing to material already written under earlier terms
  until that material is rewrapped — and sealed generations are never
  rewrapped by design, because their seals hash ciphertext.
- The attacker this matters for is the one a passphrase change exists to
  address: someone who knew the old passphrase and kept copies of
  `keyring.enc` and `.keystore` (the latter carries the KDF salt). They can
  re-derive the old KEK, unwrap their copy of the keyring, and read anything
  still encrypted under a term it contains — in their retained copies, and
  in the live store wherever an unrewrapped file remains.
- Because `Mint` copies the parent's namespaces byte-for-byte
  (`copyNamespaces`: `ReadRegularFile` then `WriteFile`, ciphertext
  verbatim), a retained sealed parent holds substantially the same
  credentials as the current generation, under its original terms.
  Rewrapping only the current generation therefore does not remove that
  material from reach.
- Consequently a term is referenced until **every** generation that retains
  a file under it is gone. Term retention is bounded by generation
  retention, not by rewrap.

### Decryptable is not authorized

A term being *readable* must not make it *acceptable for current state*.
This is a distinct rule from retention, and omitting it would lose a
property the store has today.

`ValidateCurrent` checks structure and manifest completeness only — its own
comment notes that a stale seal is ignored — so content placed into the
current generation is not caught by content validation. If `Open` accepted
whatever term an envelope named, an attacker holding an old term key could
write a credential under that term into the current generation and have it
become an active signing key. **Today that attack fails**: `changepass`
re-encrypts everything under the new master key, so old-key files simply do
not decrypt. Term-scoped authority is therefore not defense in depth here;
it is required to avoid regressing.

The keyring exposes distinct authorities rather than one `Open`:

| Context | Authorized terms |
|---|---|
| New and current-generation writes | newest only |
| Reads during a durable `rewrap_pending` window | newest plus the terms being retired |
| Opening a **validated sealed** generation | the historical terms that generation's seal covers |
| Live policy / node-role sidecars | the designated current integrity term only |

Verification of a live sidecar must require the current integrity term, not
accept any retained term the sidecar names — otherwise an attacker who
captured an old term forges sidecars indefinitely.

One scoping note, so the risk is not overstated: *replaying* an existing
ciphertext from a retained prior into the current generation already works
today, since priors share the current master key. That is a pre-existing
consequence of retaining generations, not something terms introduce. The
new exposure is *forgery* under a retained term, which term-scoped authority
closes.

**Rollback needs a decision here too.** Repointing `CURRENT` at a generation
written under an older term reauthorizes that term wholesale for current
state. The safer semantics is to mint a fresh generation from the validated
sealed target, re-encrypted under the current term, rather than repointing
at the old one. That interacts with the post-activation divergence guard
(`recovered_rollback_diverged`) and should be settled before implementation.

Three sections below follow directly from these two: what `changepass` can
honestly claim (open question 5), what term garbage collection must treat as
a reference (open question 4), and what phase 1 does before term append
exists (open question 3).

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
       sealed, err := kr.Seal(plaintext)          // newest term, stamps the header
       plain,  err := kr.OpenCurrent(sealed)      // newest term only
       plain,  err := kr.OpenSealed(gen, sealed)  // historical terms, validated generation
       mac,    err := kr.SignIntegrity(domain, b) // current integrity term
       err          = kr.VerifyIntegrity(domain, b, mac, term)
   })
   ```

   An earlier draft had `IntegrityKey(term) []byte`, which contradicts the
   principle it was written under: it hands back raw derived key material.
   Sidecar signing and verification are operations too, and the derived key
   should be zeroed inside the keyring rather than handed out. The read path
   is likewise split so the caller states which authority it is exercising —
   see "Decryptable is not authorized".

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

     Per-term derivation is deliberate: a fixed integrity root would make
     forgery ability permanent, since anyone who obtained it once could
     forge policy and node-role HMACs forever with no rotation able to help.
     Deriving per term ties forgery to term lifetime. State the limit
     plainly, though: verification accepts any term still in the keyring, so
     rotation revokes forgery only as terms are dropped — which, per the
     trust-model section, is bounded by generation retention, not by the
     rotation itself.
   - **The resident key set is bounded by generation retention, not by
     rewrap.** An earlier draft claimed the previous term becomes
     unreferenced once the rewrap completes, so the steady state is one
     term. That is false whenever a prior exists: retained sealed priors are
     never rewrapped and pin the terms they hold (see the trust-model
     section). The true bound is *terms referenced by retained generations,
     plus the current one* — small, since retention is current + parent +
     referenced, and converging to one only after priors are pruned or
     superseded and collected. An implementer following the earlier wording
     literally would drop a term a rollback target still needs.

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

   1. **Keyring with exactly one term.** The store bumps to v4;
      `keyring.enc` becomes the self-contained root holding term 1, which
      wraps today's master key. Existing call sites keep working through a
      compatibility accessor, because with one term "newest" *is* "the only
      key" and every decrypt finds term 1. Independently shippable, and the
      easiest part to review carefully.

      **`changepass` in phases 1-2 keeps today's semantics**: with append
      disabled there is only ever one term, so it re-derives the KEK,
      rewraps the keyring, and performs the existing bulk re-encryption of
      data files. That preserves the current guarantee exactly while the
      refactor is in flight — the two-phase swap and its crash window are
      retired at phase 3, not before, and the proposal should not claim the
      crash-safety win until then.
   2. **Migrate call sites package by package** to `WithKeyring`. Each
      package is separately reviewable, and a missed site is harmless while
      only one term exists.
   3. **Enable term append**, gated on the migration being complete.

   **The gate must be stronger than an arch test over the accessor alone.**
   Three holes to close:

   - **Fence all three surfaces, not one.** Fencing the compatibility
     accessor misses passphrase-to-key derivation: `policyeditor/store.go`
     calls `meta.VerifyAndDeriveMasterKey` directly, and any code holding
     the resulting `masterKey []byte` and calling `EncryptWithMasterKey`
     passes an accessor-only gate while being exactly the missed site the
     gate exists to catch. Fence the accessor, the raw-key
     `Encrypt`/`DecryptWithMasterKey` entry points, and derivation outside
     the two sanctioned sites.
   - **Prefer the compiler to a test.** At the end of phase 2, delete or
     unexport the compatibility accessor and the raw-key encrypt/decrypt
     functions. Completeness then fails the build rather than a check
     someone can skip or forget to extend. Reserve the arch test for what
     the compiler cannot see — the derivation discipline.
   - **Build the tagged tree.** This repo has production code behind
     `//go:build testmode` (`cmd/apadmin/batch.go`), invisible to untagged
     builds. A gate that does not build with `-tags testmode` can pass while
     a tagged call site survives into phase 3.
   - **Add an artifact-class test.** The gates above prove no code takes the
     old path; they do not prove every written artifact carries a term. A
     test that creates each durable class — managed keys, installed
     templates, recovered batches, policy and node-role sidecars — and
     asserts each carries a term closes that gap from the data side.

   **Phase 1 invariant to state explicitly:** the term stamp belongs to the
   envelope writer, not to `Keyring.Seal`. Every v4 write stamps `term: 1`
   regardless of which path produced it, and v4 decrypt fails closed on an
   absent term. Otherwise files written through the compatibility path in
   phases 1-2 carry no term and become unreadable at phase 3.

   In a big-bang change a missed site is a latent data-loss bug; in this
   sequencing it is a no-op until phase 3, and phase 3 does not start until
   the build says nothing is missed.
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
   under the new term removes the live active store from reach. Reaching
   that state is no longer atomic — and no longer needs to be, because a
   partially rewrapped store is a legal state: every file is wholly under
   one term at every instant, so an interrupted rewrap is resumable rather
   than damage.

   **It does not restore today's end state completely, and the proposal
   must not claim it does.** Today `changepass` requires
   `prune --all-priors` first, so it ends with no priors at all and nothing
   anywhere readable under old material. Once quiescence dissolves, a
   retained sealed parent survives the passphrase change unrewrapped, and
   (per the trust-model section) it holds substantially the same credentials
   as the current generation. The attacker described above reads the
   retained prior and obtains current key material regardless of the rewrap.

   Two ways to resolve it:

   - **(a)** have `changepass` also prune priors, converging on today's
     guarantee — at the cost of reimporting a milder version of the
     quiescence requirement this design exists to remove;
   - **(b)** accept the weaker guarantee and state it, with `changepass`
     reporting exactly what remains: *"N prior generation(s) remain readable
     under pre-change terms; run `apstore generations prune --all-priors` to
     remove them."*

   **Choose (b).** It keeps the rollback-safety win that motivates the whole
   design, tells the operator the truth, and leaves them one documented
   command from (a) when their threat model calls for it. What is not
   acceptable is claiming the stronger guarantee while shipping the weaker
   one.

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
