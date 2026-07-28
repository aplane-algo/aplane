# Proposal: Key-Term Rotation (Lazy Re-Encryption)

Status: **proposal — scoping only, not accepted**

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

The keyring layout is a store-format change: bump
`.keystore` to version 4 (`keyring/v1`). Old binaries reject v4 exactly as
pre-generation binaries reject v3. Migration v3→v4: wrap the existing single
master key as term 1 — metadata-only, no data rewrite, same
flip-then-bump discipline as the layout migration (and it should adopt the
migration-in-progress completion hook added for that window).

## What this retires

- The `pendingFile` two-phase swap machinery and its unrecoverable crash
  window (rotate.go), including `rollbackPendingFiles`/`swapPendingFiles`.
- The recovered-batch sibling reconciliation special case.
- `requireGenerationQuiescence` and the `prune --all-priors` prerequisite.
- The rotation/generation-rollback unreadability hazard noted at
  rotate.go's quiescence comment.

## Open questions (to resolve before acceptance)

1. **Backup format.** `.apb` bundles and `apstore rebuild` decrypt with the
   export passphrase — confirm they are independent of master-key terms
   (expected: yes; they re-encrypt on restore).
2. **Memory handling.** The keyring holds multiple live keys; zeroing
   discipline (`crypto.ZeroBytes`) must extend to the full term set, and
   `WithMasterKey` call sites need a term-aware lookup (decrypt path selects
   by header term; encrypt path always uses newest).
3. **Blast-radius review of `crypto.EncryptWithMasterKey` call sites**
   (~keys, templatestore, recovered, cache) — each needs the term header on
   write and term lookup on read; the envelope change must stay
   backward-readable during the v3→v4 transition.
4. **KDF/KEK caching** in the daemon unlock path (today the master key is
   cached; becomes the keyring).
5. **Whether master-key rotation is even exposed** initially. Passphrase
   change (KEK rewrap) covers the common operational need; term rotation can
   ship later without format changes.

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
