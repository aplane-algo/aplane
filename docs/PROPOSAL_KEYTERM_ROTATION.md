# Proposal: Key-Term Rotation (Lazy Re-Encryption)

Status: **phases 1, 2, and 3 implemented and merged.** Phase 3 landed as eleven
slices, described below; term GC is deferred out of this implementation and
retained priors remain readable under pre-change terms by design. The formal R5
prerequisite is complete, and the first implementation slice writes the strict
v2 keyring/v5 marker shape while
initially retaining the one-term runtime gate. A second slice adds
keyring-confined integrity operations, generation seal v2, and explicit-term
policy/node-role sidecar v2. A third slice adds the canonical K8 artifact
taxonomy and settled-store scanner with exact-buffer context opening and its
durable-class mutation matrix. A fourth slice adds the strict sealed cutover
snapshot codec, durable bounded storage, canonical rollback-authority digest,
and exact encrypted-file reference validation, without enabling a pending
root. A fifth slice records and authenticates each generation member's term,
pins exact pre-retirement generation seals with historical anchors, and
provides a separate anchor-gated retired-term open path. A sixth slice adds
the strict bounded divergence-baseline record, effective-authority cutover
decision, and fail-closed stale/malformed preflight reconciliation. A seventh
slice adds guarded multi-term acceptance, the exact settled/pending
current-state authority sets, durable snapshot-before-root publication with
the complete historical-anchor set, and the R5 no-second-append guard. A
pending root now fails closed into recovery before runtime state is
published. An eighth slice adds the snapshot-pinned, idempotent rewrap/resume
loop: retained anchored generations remain exact, mutable retiring-term
envelopes are promoted only from their pinned bytes, integrity sidecars are
re-signed over pinned documents, and authenticated target outputs are
accepted after a crash. A ninth slice adds the completion boundary: two fresh
final scans enforce exact path and target-authority shape, a clean cutover's
post-rewrap baseline is durable before atomic root close, divergence never
creates a new baseline, and the root-referenced snapshot is removed only
after close. A tenth slice makes restore rollback consume the matching
authenticated baseline, preserve divergence refusal, and mint the sealed
target's content into fresh current-term envelopes rather than reauthorizing
an older generation. An eleventh slice rewrites `changepass` onto that durable
transition, makes helper failure a post-commit warning, reports retained
priors, and automatically completes pending rotation during interactive and
headless unlock before runtime publication. This document is the design record
behind it. Amended across six rounds of review by two independent reviewers,
both of whom now call the design settled.

> The recovered-batch references below describe a retired pre-release restore
> design. Admin protocol v4 restores validated credentials directly through a
> generation transaction, so recovered batches are no longer store artifacts
> or rotation-inventory members. The current contract is in
> [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md).

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

Subsequent rounds found that the term-scoped authority rule had consequences
of its own: the rotation transition needs a durable state
machine, the rewrap window
belongs inside `keyring.enc` rather than in a second record, phase 1-2
`changepass` must *replace* the term key rather than rewrap it, and the
seal — not the immutable at-mint manifest — is the term authority for a
sealed generation. Rollback is no longer deferred: the authority rule
decides it, and rollback mints a fresh generation rather than repointing.

Later rounds turned the transition into a specified state machine and then
found what that machine still admitted. **Phase 1 is design-ready and
reviewable on its own. Phase 3 is blocked on three items, all recorded
below:** (Review-round record; all three, and the fourth noted after them,
have since shipped — see the status header.)

- **the cutover snapshot** — without an authenticated record of exactly what
  the rewrap may consume, an attacker holding a retired term can inject
  material during the window and have the rewrap launder it into the new
  term;
- **historical anchors** — generation seal v2 is now keyed, but a holder of a
  retired term can forge a new valid MAC under that retired key unless the
  root pins the exact pre-retirement seal bytes;
- **the divergence baseline** — mandatory rewrap changes every ciphertext
  digest and so trips the post-activation rollback guard, which compares
  those digests against the at-mint manifest.

A fourth blocker joined them: **generations contain plaintext members**
(key-type state and witness public metadata). Generation seal v2 now closes
the pre-rotation no-key forgery by MACing the complete inventory, exact
manifest digest, and integrity term. Rotation still has to inventory those
members and anchor retained historical seals before their signing term
retires.

The envelope's AAD context question that briefly gated phase 1 is decided:
the context ships in phase 1, because it touches only the 18 direct
encryption sites and each already holds the identity it needs. Phase 1 is
ready to implement.

The attacker model is also scoped explicitly: AEAD makes the root
authentic but not fresh, so replacing `keyring.enc` with an older authentic
copy is store substitution rather than injection, and is outside what
in-store cryptography can detect.

The passphrase-helper contract and the resume path are decided, not blocked.

## Problem

Before phase 3, `apstore changepass` re-encrypted every managed file under the
new master key using a two-phase `.new`/`.old` swap
(`internal/storepass/rotate.go`). Review
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
  today, no new machinery. This bullet describes the root write in
  isolation, as a decomposition aid — it is not a shippable operation on its
  own. A passphrase change always appends a term and rewraps (open question
  5), and step 1 of "The rotation transition" fuses the append into this
  same single write.
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
- **A generation references a set of terms, not one term** — and the
  manifest cannot be the authority for it. `Mint` copies the parent
  byte-for-byte, so a child minted from a partially rewrapped parent
  inherits files under mixed terms. Term references are therefore per file.
  But the manifest is an immutable at-mint record while the current
  generation keeps changing under it — files added, removed, and rewrapped —
  so a mint-time term set goes stale immediately. Authority by object:
  - **sealed generations**: the term set fixed at seal time — but recorded
    as a `Term` on each applicable `InventoryEntry`, **not** as a standalone
    `Terms` field. An earlier draft claimed a standalone field would be
    covered by "the seal's own digest"; there is no such digest.
    `ValidateSealed` rebuilds the inventory and compares it entry by entry
    (`slices.Equal(live, seal.Inventory)`), so a term carried inside each
    entry is verified by that existing comparison, while a separate field
    would be trusted unverified. GC must never trust a standalone `Terms`
    value merely because it appears in a seal;
  - **the current generation**: a live scan, since it is mutable;
  - **`RetainedUnsealedParent`**: a live scan too — not because it is
    mutable, but because being unsealed it has no seal-time term record at
    all;
  - **recovered batches, sidecars, and recoverable `deleted/` objects**:
    their own scans.

  Manifest term data, if recorded at all, is at-mint diagnostics only.
  Deletion must rescan under the identity mutation lock; a candidate list
  recorded earlier by a passphrase-less prune is a hint, never deletion
  authority.
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
  address: someone who knew the old passphrase and kept a copy of
  `keyring.enc`. Since the keyring is self-contained — it carries its own
  KDF parameters and salt — that single file is sufficient; no companion
  artifact is needed. They re-derive the old KEK, unwrap their copy, and
  read anything
  still encrypted under a term it contains — in their retained copies, and
  in the live store wherever an unrewrapped file remains.
- Because `Mint` copies the parent's namespaces byte-for-byte
  (`copyNamespaces`: `ReadRegularFile` then `WriteFile`, ciphertext
  verbatim), a retained sealed parent holds substantially the same
  credentials as the current generation, under its original terms.
  Rewrapping only the current generation therefore does not remove that
  material from reach.
- Consequently a term is referenced until **every durable object** holding a
  file under it is gone — retained generations, but also recovered batches,
  policy and node-role sidecars, and any recoverable `deleted/` object. Term
  retention is bounded by that whole inventory, not by rewrap.

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
| New and current-generation writes | `current_term` only |
| Reads and sidecar verification during the rewrap window | `current_term` plus `retiring_terms` |
| Opening a **validated sealed** generation | the historical terms its seal covers — **and** the anchor rule below, which conditions this row |
| Live policy / node-role sidecars | the designated current integrity term only |

Verification of a live sidecar must require the current integrity term, not
accept any retained term the sidecar names — otherwise an attacker who
captured an old term forges sidecars indefinitely.

**The rewrap window is state inside `keyring.enc`, not a second record.**
The keyring is the single root, and that principle applies to the window
itself: it records `{terms, current_term, retiring_terms}`. Otherwise a
crash between appending a term and creating a separate pending marker
leaves a current generation full of no-longer-current files that
current-only authority rejects — the store fails closed on every read, a
two-record crash window at the same root this design just consolidated.

Keeping the window in the keyring makes each step individually crash-safe
and gives resumption a single source of truth: whoever reads the keyring
sees the pending transition. `retiring_terms` is a set for reserved generality — every path this document
defines produces exactly one retiring term, since appending while a window
is open is forbidden and windows close before the next append. A future
term-GC pass folding several retirements into one transition would produce
more; nothing today does.

`OpenCurrent` is therefore defined as *consulting the durable current
authority* — `current_term` plus any `retiring_terms` — not as a literal
"newest term only".

One scoping note in both directions. *Replaying* an existing ciphertext from
a retained prior into the current generation already works today, since
priors share the current master key — a pre-existing consequence of
retaining generations, not something terms introduce. The new exposure is
*forgery* under a retained term, which term-scoped authority closes. But
current-term authority also **improves** on today's replay story: once a
rotation has completed, a replayed old-term file is rejected by the current
generation's authority rule, which nothing rejects today.

### The rotation transition (durable state machine)

`changepass` is a transition with durable intermediate state, not a single
step. Ordering matters because current-term-only authority makes each
half-finished state visible to the next reader.

1. Under the identity mutation lock, atomically write the keyring under the
   new KEK with the appended term **already promoted**. Budget this step as
   a full-store scan rather than a metadata write: it hashes every retained
   sealed generation (for anchors) and every mutable consumer (for the
   cutover snapshot) before the commit, all under the lock. The write itself
   is atomic; the preparation is not cheap:
   `current_term = to`, `retiring_terms = {from}`, `rewrap_pending`. One
   durable write. From this instant `Seal` and `SignIntegrity` use the
   target term, and the window authorizes reads and sidecar verification
   under `current_term ∪ retiring_terms`.

   Promotion belongs here, not at the end. An earlier draft appended at
   step 1 and promoted at step 5, which left steps 3-4 with no coherent
   write authority: writing the target term would violate "current only,"
   and writing the old current term would make the rewrap a no-op.
2. Coordinate the passphrase helper. **Step 1 is the point of no return** —
   once the root is committed the transition is only ever completed, never
   reversed, because reversing it would mean rewrapping the root back under
   the old KEK and un-appending the term, a compensating write with its own
   crash story and no safe answer for a crash midway through it. A helper
   write that fails after step 1 is a **post-commit warning, never a
   barrier**: the cryptographic transition completes using the manually
   supplied new passphrase, and auto-unlock stays unavailable until the
   helper is repaired separately. Making helper success a prerequisite for
   resume would deadlock the identity — every mutation except resume is
   blocked while the window is open, so a broken helper could leave a store
   that can neither finish rotating nor repair the helper. The crash
   boundary is stated rather than hidden: a crash after the root commits but
   before the helper updates leaves auto-unlock failing until the helper is
   refreshed, and manual entry of the **new** passphrase resumes.

   (The alternative — write the helper before step 1 — is also defensible,
   since helper-new/root-old is recoverable by falling back to prompting.
   What is not available is the pre-amendment behavior of restoring the
   prior state, which the atomic root makes impossible.)
3. Re-sign the live integrity sidecars under the target term.
4. Rewrap every mutable live consumer — the current generation's keys and
   templates, recovered batches, and any other object encrypted under a
   term (see the reference inventory).

   Steps 3 and 4 may run in either order. The window authorizes retiring
   terms for both file reads and sidecar verification, so neither ordering
   fails closed at an intervening unlock; the binding invariant is simply
   that **both are on the target term before the window closes**. An
   earlier draft justified sidecars-first by a fail-closed risk that the
   window's own coverage had already eliminated.
5. Complete, in this durable order:
   1. verify the transformation against the cutover snapshot;
   2. durably write the post-rewrap divergence baseline for every generation
      the snapshot recorded as clean before the cutover;
   3. only then atomically clear `retiring_terms` and `rewrap_pending`.

   The order matters: clearing the window first would leave a rotated store
   whose current generation matches neither its at-mint manifest nor any
   baseline, so every subsequent rollback would be refused as diverged —
   permanently. This step promotes nothing; promotion happened at step 1.

After a crash the new passphrase **resumes the existing transition** — it
must not append a further term. Resume runs automatically at unlock, before
the identity is enabled, rather than through an operator command:
`changepass` rejects an unchanged passphrase
(`storeadmin/service.go`: "new passphrase must be different from current
passphrase"), so "re-run changepass" is not actually available as a resume
path. If resume fails, the identity surfaces a rotation-pending recovery
status.

**An open window blocks every identity mutation, not only signing.** Signing
is blocked because the window deliberately authorizes retiring terms, which
is the exposure current-term authority exists to close. But a mint during
the window would copy mixed-term files into a child under ambiguous write
authority, and a rollback-mint "re-encrypted under the current term" is
ambiguous while `retiring_terms` is non-empty. Resuming the rewrap is the
only mutation an open window permits.

This is also the ordering the promised TLA+ module should check; the
generation commit model is a working template for exactly this shape.

### The cutover snapshot

Three separate problems below want the same record, so the design commits
one authenticated **cutover snapshot** as part of step 1's atomic write.

It must be atomic with step 1 — that is what makes it a cutover — but it
must not bloat the root, which the divergence-baseline section deliberately
kept O(terms) rather than O(store). Resolve both by indirection: write the
snapshot body to its own file sealed under the target term, and have step
1's root commit carry only its digest. The root stays small, the commit
stays atomic, and a missing or mismatched body fails closed into
rotation-pending recovery — never into a false-clean state.

The ordering must be explicit, or "fails closed" turns an ordinary rotation
crash into permanent recovery: write and rename the snapshot body durably,
sync its directory, and only then commit `keyring.enc` with its digest. A
crash before the root commit leaves a removable orphan; after it, the
referenced body is always present.

**Why it is required (the laundering attack).** The window deliberately
authorizes retiring terms for reads, so the rewrap pass will decrypt
anything encrypted under one. An attacker holding a compromised old term
and filesystem write access can therefore write a forged credential or
template under the retiring term, let the rewrap pass decrypt it, and have
the pass re-seal it under the new term — after which it passes the final
"everything is on the target term" check and is permanently blessed under
the uncompromised term. Blocking daemon mutations does not help: an attacker
writing files directly bypasses the daemon entirely.

The snapshot defines the security cutover. It records, AEAD-authenticated:

- the exact paths and digests of everything the transition may touch,
  distinguishing two kinds because they are not transformed the same way:
  **term-encrypted objects** (current-generation keys and templates,
  recovered batches) are decrypted and re-encrypted, while
  **plaintext-plus-sidecar objects** (policy and node-role documents) carry
  no term on their content and are only *re-signed* under the new integrity
  term. Both need pinning — an integrity input is as forgeable as a
  ciphertext one — but an implementer enumerating "objects encrypted under a
  term" would otherwise hunt for a term header on `policy.yaml` and not find
  one;
- for each generation, the **clean-or-diverged decision made before any
  rewrap** (see the divergence guard below);
- the effective starting baseline for that decision.

Rewrap then accepts only those exact bytes. Anything added, removed, or
altered after the snapshot fails closed.

The completion check needs care about what it can actually prove. Outputs
cannot be pinned at snapshot time — every rewrap output carries a fresh
random nonce — so a naive check can only establish that every snapshot input
was consumed and every expected path now holds *some* target-term
ciphertext. That leaves output swapping: two valid target-term envelopes
exchanged between paths. **Extend the GCM additional authenticated data to
include the object's logical identity** alongside the term header.

That identity must be *logical*, never a physical path. Ciphertext moves
without re-encryption all over this system: `copyNamespaces` copies a parent
generation's files byte-for-byte into a child, staging directories are
renamed into place, `DeleteKey` renames a key into `deleted/keys`, and
recovered batches are staged then published. Binding a path into the AAD
would make every one of those moves produce undecryptable data. Bind a
class-scoped logical context instead — `(artifact class, canonical
selector)` for managed credentials and templates, `(restore ID, entry ID)`
for recovered entries — explicitly excluding generation IDs and any
staging, current, or deleted directory component. A swapped output then fails authentication on open, the one-to-one
property becomes cryptographic rather than asserted, and it costs one more
field in an envelope change already committed to happen. Without that, the
completion check must be described as "all inputs consumed, all outputs on
the target term" and swap detection left to the reload gate's
selector-versus-filename validation, which covers keys but is thinner for
templates and recovered batches. Compromise *before* the
snapshot is not defended against — that is what the cutover means — but
nothing injected after it can be laundered into the new term.

Recording the clean/diverged decision here is also what makes resume
correct: a crash mid-rewrap leaves ciphertext matching neither the manifest
nor the final baseline, so without a durable decision the resuming process
cannot tell whether recording a clean baseline would erase pre-existing
divergence.

### The root is authenticated but not fresh — scope the claim

AEAD proves a `keyring.enc` was produced by someone holding the KEK. It
does not prove it is the *current* one. The Q5 attacker holds an old,
perfectly authentic root — so with filesystem write access they can simply
**put their old copy back**, which erases the pending state, the anchors,
and the promotion, restoring the old `current_term` and making their
old-term forgeries current-authorized again.

No in-store mechanism fixes this. A freshness counter would live in a file
the same attacker can replace; anything strong enough (hardware-backed
monotonic state) is outside this design. So the claim must be scoped rather
than defended: **the cutover guarantees that nothing injected after it can
be laundered into a store whose root is the one the transition committed.**
Replacing the root is not injection into the store — it is substitution of
the store, which no in-store cryptography detects.

Three things make that boundary tolerable, and the third is the strongest.
Root replacement is loud: the operator's new passphrase stops working, since
the reverted root only opens with the old one. An attacker with write access
to the identity directory can already substitute the entire store, so root
replacement grants nothing whole-store substitution did not.

And a reverted root is **store-breaking, not quietly subversive**. From step
1 onward the live store progressively moves onto the target term, and after
step 5 all of it is there — but a reverted root does not contain the target
term key, so every current-generation file fails to decrypt and the daemon
fails closed everywhere. The attacker does not gain a store operating under
old-term authority; they gain a store that will not open. To get the former
they would have to revert the files as well as the root, which is exactly
whole-store substitution, already excluded.

State it in the threat model rather than leaving "nothing can be laundered"
to be read as unconditional.

### Retained sealed generations need an authenticity anchor

Adding `Term` to each `InventoryEntry` prevents accidental GC mistakes. It
does not by itself prevent malicious modification. Before generation seal v2,
`WriteSeal` wrote unauthenticated JSON and `ValidateSealed` merely recomputed
the inventory and compared it. Generation seal v2 now authenticates the exact
manifest digest, integrity term, and canonical inventory. That is sufficient
while the seal's term is current, but a future holder of a retired term could
forge both content and a valid old-term MAC — and mint-on-rollback would then
launder the forgery under the current term unless the exact historical seal
was anchored before retirement.

At step 1 of the rotation, anchor every retained sealed generation —
authenticated digests recorded in the new `keyring.enc` — **before** its
term becomes retiring. Carry those anchors forward while the generation is
retained.

The rule must be conditional, not absolute. A generation sealed since the
last rotation has no anchor and is not suspect: its terms have never been
retired, so no retired key can forge it. Requiring an anchor unconditionally
would make such a generation unrollbackable-to, and anchoring at every mint
would mean rewriting the root at every mint — which needs the KEK that is
deliberately not cached.

- **Anchored generation**: require exact anchor equality, in addition to
  ordinary seal validation.
- **Unanchored generation**: the rule cannot be "every inventory entry is on
  the current term," because not every entry carries a term. Generations
  hold plaintext members — key-type state records and witness public
  metadata are both `json.MarshalIndent` to `WriteFileDurable`, with no
  encryption. The seal therefore needs keyed integrity over the whole
  inventory; a digest-only seal would let a filesystem attacker holding
  **no keys at all** alter a plaintext entry and recompute the seal to match.

  **Seal the seal (implemented by generation seal v2).** At seal time, MAC the canonical seal with the current
  term's integrity key. Then an unanchored generation is accepted when its
  seal MAC verifies under the current integrity term *and* its term-bearing
  entries are on the current term — which covers plaintext members too,
  since the MAC spans the whole inventory. At rotation, step 1 pins the
  seal-and-MAC digest into the new root, so once the former current term is
  retired and possibly compromised, the root anchor rather than the MAC is
  authoritative.

  This also closes a weakness that predates rotation: an unkeyed seal has
  never protected a sealed prior against an attacker with filesystem write
  access, and rollback trusts sealed priors.

  The proposal must therefore classify inventory entries as term-bearing or
  plaintext wherever it reasons about terms; several statements above are
  written as if every entry has one.

**Opening must bind bytes, not just validate the generation.** An
`OpenSealed(gen, ciphertext)` that takes arbitrary bytes leaves a TOCTOU
window: validation reads the files, then rollback reads them again, and the
filesystem attacker swaps one in between. Current validation already
performs separate reads, and even `VerifyFileAgainstSeal` hashes a file
without returning the bytes it verified. Historical opening must therefore
hash the exact buffer it is about to decrypt and match it against a
per-file entry — whole-generation validation is not sufficient under this
attacker model.

**Anchoring is two-level, and the levels must not be confused.** Putting
per-file entries in the root would make it O(files across every retained
generation), which is precisely the growth the cutover snapshot was
restructured to avoid. Instead:

- the **root** anchors one digest per retained sealed generation — that of
  its `seal.json` (with the seal MAC, above);
- the **anchor-verified seal's own `Inventory`** supplies the per-file
  `(path, digest, size, term)` entries;
- historical opening hashes the buffer it will decrypt and matches that
  per-file entry.

Same binding, small root. An implementer reading only one of the two
paragraphs above could have built either level, so both are named here.

**Anchor lifecycle:** pruning a generation cannot drop its anchor, since
prune has no KEK. Stale anchors accumulate in the root until the next
passphrase-holding operation clears them. Harmless, but stated so it is not
mistaken for a leak.

This is the same shape as the cutover snapshot — the store's authenticated
root vouching for material that unkeyed integrity checks cannot.

### Rewrap versus the rollback divergence guard

These two mechanisms collide, and the collision is silent. The guard added
for post-activation divergence compares the current generation's live
inventory against its immutable at-mint manifest — and inventory entries are
digests of *ciphertext*
(`activation_generational.go`: `inventoriesEqual(manifest.Inventory,
BuildInventory(gen))`). A rewrap changes every file's key and nonce, so
every digest changes, so after any `changepass` an otherwise untouched
restore activation reports `recovered_rollback_diverged` and rollback is
refused. Choosing mint-over-repoint does not help: the refusal happens
before any mint begins.

The guard must therefore distinguish **semantic** divergence — an operator
generated a key or installed a template after the activation — from
**cryptographic** rewrap, which changes bytes while changing nothing the
guard exists to protect. The rewrap pass:

- determines the generation's clean/diverged state **before** rewrapping;
- if it was clean, records an authenticated post-rewrap baseline keyed by
  generation ID;
- if it was already diverged, records nothing: a diverged generation must
  never become clean again;
- and the guard consults that effective baseline rather than the manifest
  whenever one exists.

**The baseline must be unforgeable in a specific direction.** An earlier
draft justified authentication by "divergence becomes assertable by anyone
who can write to the store" — but forged *divergence* only denies rollback,
which is fail-closed and harmless. The dangerous forgery is asserting
*cleanness* over a genuinely diverged generation: rollback would then
proceed and silently discard credentials generated after the activation,
which is exactly what the guard exists to prevent. Authentication is
required in that direction.

**Where it lives is a real choice.** Inside `keyring.enc` the root becomes
O(current-generation inventory) rather than O(terms), and the root is
rewritten atomically on every transition. A separate file sealed under a
term key avoids that growth, and the two-record objection does not apply
here: its absence fails closed, since the guard falls back to the manifest
and refuses. Given the size implication, prefer the separate sealed file and
keep the root small; either is defensible, but the choice should be
conscious.

**Lifecycle:** a baseline is superseded at the next mint, when the fresh
manifest resumes authority, and baselines for superseded generations are
dropped.

A plaintext semantic inventory would also work but needs leakage analysis
first — it would describe active credential structure in the clear.

**This is a phase-3 blocker.** It cannot be discovered by unit-testing
either mechanism alone; only exercising rotation and rollback together
surfaces it. `docs/formal/rotation_transition.tla` now checks the resulting
rule mechanically: R3 fails if the rewrap window is closed before the
baseline is durable, which is the state where every later rollback is
refused permanently.

**Rollback: mint, do not repoint.** This was left open in an earlier draft,
but the authority rule decides it. `RollbackTo` repoints `CURRENT` directly,
so rolling back to a generation written under an older term would
reauthorize that term for mutable current state — contradicting
current-term-only authority in the one operation most likely to be run
after a compromise. Rollback therefore:

- validates the sealed target as today;
- preserves the existing post-activation divergence guard
  (`recovered_rollback_diverged`);
- mints a **new** generation whose content comes from that target, decrypted
  through historical authority and re-encrypted under the current term;
- records the rollback source generation in the new manifest.

The content rolls back; the cryptographic epoch does not.

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
  Note the timing: phases 1-2 deliberately keep the swap (it is what gives
  `changepass` today's semantics before term append exists), so this retires
  at phase 3.
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
       plain,  err := kr.OpenCurrent(sealed)      // the durable current authority
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
     `DeriveNodeRoleIntegrityKey`). A sidecar must record its term, and
     verification compares that record against the current authority — the
     current integrity term, plus retiring terms only while the rewrap
     window is open — rather than trusting whichever term the sidecar
     names. Both
     `IntegritySidecar` types already carry `Version` and `KeyID`; add an
     explicit `Term` field and bump the sidecar version rather than
     overloading `KeyID`, which is a constant scheme tag exact-matched on
     load. Absent `Term` fails closed — with no migration, a v4 sidecar
     always carries one.

     Per-term derivation is deliberate: a fixed integrity root would make
     forgery ability permanent, since anyone who obtained it once could
     forge policy and node-role HMACs forever with no rotation able to help.
     Deriving per term ties forgery to term lifetime, and pairing it with
     current-term-only verification (see "Decryptable is not authorized")
     makes the revocation immediate rather than eventual: a holder of a
     retired term cannot derive the current integrity key, so they cannot
     forge a sidecar that verifies at all. A fixed root would validate a
     forgery that simply labels itself with the current term.
   - **The *required* term set is bounded by generation retention, not by
     rewrap** — and required is not the same as resident. Since term
     deletion is deferred out of the first implementation, the resident
     keyring grows by one entry per passphrase change regardless of what
     retention allows; only the required set shrinks. An earlier draft claimed the previous term becomes
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
   term is a header field added beside it. Bind the header into the GCM
   additional authenticated data while making that change: header integrity
   is otherwise only emergent (tampering surfaces as a failed decrypt under
   the wrong key), and AAD binding makes it cryptographic for one line in an
   envelope change that is happening anyway. With no migration the envelope
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

      **Decided: the object context ships in phase 1.** The alternative —
      versioning the AAD mode and accepting context-free term-1 files until
      their first rewrap — was rejected.

      The decisive fact is that this change touches **ring 1 only**. The 18
      direct `Encrypt`/`DecryptWithMasterKey` sites *are* the class-specific
      persistence layer, and each already holds the identity it needs:
      `keys/save.go` has the payload (hence `Selector()` and `Category`),
      `templatestore` has the key type, and both `recovered/store.go` sites
      have the restore ID and entry. The wide rings — 99 `WithMasterKey`
      callers, 103 signature-threading functions — do not encrypt; they pass
      a key around, and are untouched by the AAD change. So supplying the
      context does **not** pull phase 2's refactor forward; the two are
      nearly disjoint.

      Three further reasons:

      - A mode-versioned envelope leaves mode-0 files swap-vulnerable until
        their first mandatory rewrap, which happens at the first passphrase
        change — and a store whose operator never rotates would stay that
        way permanently. "Temporarily weaker" is not bounded here.
      - A mode marker means two reader paths forever, and two states that
        must agree. This design has spent its entire review removing exactly
        that construct: the split cryptographic root, the separate pending
        marker, the standalone `Terms` field. Reintroducing one to save 18
        call sites is a poor trade.
      - Version negotiation exists to protect an installed base. The release
        policy already says a store is readable only by the release that
        initialized it, so there is none; and if phases 1 and 3 ever ship as
        separate releases, phase 3 cannot read a phase-1 store at all,
        making the compatibility question moot in production.

      **A context-free encrypt is a compile error, not a runtime default.**
      Then "did every write site supply an identity?" is answered by the
      build, consistent with the phase-2/3 gate philosophy.

      One item to confirm during implementation rather than assume: four of
      the eighteen sites were checked directly. The archive paths
      (`backup/copy.go`, `backup/restore.go`) use `EncryptStandalone` under
      the *export* passphrase and carry no term, so they are outside term
      AAD entirely — the sealed manifest already binds those members by path
      and digest. The remaining master-key sites should be confirmed to have
      identity in hand; a site that genuinely does not is the only case that
      would justify a narrow mode marker.

      **`changepass` in phases 1-2 keeps today's semantics, which requires
      replacing the term key — not merely rewrapping it.** Today's master
      key is *derived* from the passphrase, so changing the passphrase
      changes the key for free. Once the key is *stored* in a keyring,
      changing the passphrase changes only the KEK; the term key underneath
      is unchanged, which would make the bulk re-encryption a cryptographic
      no-op and leave the Q5 attacker — old passphrase plus a copy of
      `keyring.enc` — able to read every post-change write. Phase 1-2
      `changepass` must therefore generate a **fresh term-1 key**,
      re-encrypt every file from the old key to the new one through the
      existing swap, and rewrap the keyring holding the new key under the
      new KEK.

      The two-phase swap and its crash window are retired at phase 3, not
      before; the proposal must not claim the crash-safety win until then.
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
     `Encrypt`/`DecryptWithMasterKey` entry points, and passphrase-to-key
     derivation.

     State the derivation rule structurally rather than by counting sites,
     which has already been miscounted once: after the refactor, derivation
     exists **only** inside `internal/crypto`'s keyring-open constructor,
     and every consumer — daemon unlock, `changepass`, the per-invocation
     offline commands — calls that. The arch test then asserts no KDF or
     derivation call outside `internal/crypto`, which stays true however
     many callers there are.
   - **Prefer the compiler to a test.** At the end of phase 2, delete or
     unexport the compatibility accessor and the raw-key encrypt/decrypt
     functions. Completeness then fails the build rather than a check
     someone can skip or forget to extend. Reserve the arch test for what
     the compiler cannot see — the derivation discipline.
   - **Build the tagged tree.** This repo has production code behind
     `//go:build testmode` (`cmd/apadmin/batch.go`), invisible to untagged
     builds. A gate that does not build with `-tags testmode` can pass while
     a tagged call site survives into phase 3.
   - **Current status.** The compiler gate and the KDF-confinement
     architecture test are in place: no code outside `internal/crypto`
     receives a raw term key, imports a KDF, or adopts raw bytes as a keyring.
     `internal/rotationinventory` now supplies the canonical cross-artifact
     taxonomy and settled-store scan, including exact-buffer logical-context
     opening and mutation-tested durable-class coverage. The sealed snapshot,
     per-member seal terms, exact historical anchors, and anchor-gated
     retired-term opening are also implemented as foundations. The guarded
     transition start now pins the durable snapshot and complete anchor set in
     the same atomic root publication. Snapshot-pinned rewrap/resume and the
     final exact-path/target-authority completion boundary now consume them;
     rollback consumption, `changepass` integration, and automatic
     pre-publication unlock resume are implemented.
   - **Add an artifact-class test.** The gates above prove no code takes the
     old path; they do not prove every written artifact carries a term. A
     test that creates each durable class — managed keys, installed
     templates, recovered batches, policy and node-role sidecars — and
     asserts each carries a term closes that gap from the data side.

     If contextual AAD is adopted, term presence is not enough: the test
     must also show that the correct logical context decrypts, that a
     different selector or class fails, and that generation copy and the
     supported archival moves (`deleted/`, staging publication) preserve
     the intended context. Compiler gates prove which code path ran; only
     this proves callers supplied the right logical identity.

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

   An earlier draft claimed the passphrase becomes a key in exactly two
   places outside `internal/crypto`. That was wrong — measured, there are
   six such sites across five files: `keystore/file.go`
   (`InitializeMasterKey`, the daemon unlock path),
   `storepass/rotate.go` (two), `policyeditor/store.go`,
   `cmd/apstore/policy.go`, and `cmd/apstore/generations.go`. Only the first
   caches; the rest derive per invocation. This widens the derivation gate
   in open question 3 but does not change the caching decision, which
   concerns the one caching site.

   Today that site derives the master key and holds it in `f.masterKey` for
   the session, zeroed by `ClearMasterKey` on lock under `cacheLock`.

   The keyring takes that slot: derive the KEK, unwrap `keyring.enc`, zero
   the KEK before returning, and cache the unwrapped terms where the master
   key lives today — same lifetime, same lock discipline, same zero-on-lock
   (`ClearMasterKey` becomes `ClearKeyring`, iterating terms).

   Nothing after unlock needs the KEK, with one bounded exception: an unlock
   that resumes an interrupted rotation must clear `rewrap_pending`, which
   rewrites the root. Define unlock as **incomplete until resume finishes** —
   the KEK is retained inside that operation until the final root write and
   zeroed immediately after, and it never enters the session cache. Outside
   that window the KEK unwraps the keyring at unlock and is rewrapped only
   during `changepass`, which holds the passphrases and can re-derive. Not
   caching it means a memory disclosure of the running daemon yields term
   keys, exactly as it yields the master key today, but not the ability to
   unwrap a future keyring.

   Two things this resolves:

   - **KDF cost is unchanged.** Argon2id (64 MiB, t=2) runs once per unlock
     today and once per unlock after; the keyring adds one AES-GCM unwrap.
     There is no performance argument for caching the KEK.
   - **Passphrase verification moves to the keyring.** An earlier draft said
     this path was untouched, which the single-root consolidation made
     false: the separate verifier is gone, so `VerifyPassphrase` attempts a
     keyring unwrap and succeeds exactly when the AEAD authenticates. Two
     consequences to handle: the unwrap briefly materializes term keys, so
     they must be zeroed on the verify-only path, and the unlock
     rate-limiter keys off decrypt failure, which is unchanged.

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

   Appending a term protects new writes; rewrapping removes the mutable live
   store from reach: the current generation's keys and templates and recovered
   batches are re-encrypted, and the policy and node-role sidecars are
   re-signed under the new integrity term. Reaching
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
   costs no new *operator surface*: `changepass` already runs a synchronous
   pass over every file and reports per-category counts, so the command, the
   wait, and the output shape are unchanged. It is not free in
   implementation, though — an earlier draft overstated this. It requires
   the durable transition state, resume-after-crash behavior, passphrase
   helper coordination, and status reporting described under "The rotation
   transition". It is also less filesystem work than
   the two-phase swap it replaces (one durable write per file instead of a
   `.new` write plus two renames). An opt-in `rewrap` command would instead
   add a new command, a "partially rewrapped" store state needing its own
   status surface, and an operator-facing explanation of the security
   consequence of not running it.

   Sealed priors are never rewrapped — their seals hash ciphertext — and do
   not need to be: their terms stay in the keyring, so they remain readable
   as rollback targets.

   An interrupted rewrap reports how many files remain on the previous term.
   It is finished by the automatic resume at the next unlock, not by
   re-running `changepass`, which rejects an unchanged passphrase. Expect
   that unlock to take longer than usual while the remainder completes
   before the identity is enabled — long, not hung.

## What phase 1 committed to (implemented)

Kept as the record of what the first implementation PR scoped itself to. It
shipped as described; phase 2 then removed the compatibility seam it left
behind. For what remains, see
[PHASE3_ONBOARDING.md](PHASE3_ONBOARDING.md).

Phase 1 was deliberately the smallest reviewable unit:

1. `keyring.enc` as the self-contained cryptographic root — plaintext KDF
   parameters and salt, AEAD-sealed term set holding a single term 1 that
   wraps what is today the master key. `.keystore` drops to a static
   version/layout marker, and successful AEAD unwrap replaces the separate
   verifier.
2. The envelope gains the term header and the logical object context in its
   AAD, applied at the 18 direct encryption sites. A context-free encrypt
   does not compile.
3. `changepass` keeps today's semantics: generate a fresh term-1 key,
   re-encrypt through the existing swap, rewrap the keyring under the new
   KEK. The two-phase swap and its crash window are retired at phase 3, not
   here.
4. No term append, no rewrap window, no anchors. Everything the transition
   sections describe is phase 3.

Nothing in phase 1 changes observable behavior except the store format,
which under the release policy is a new store rather than a migration.

The four phase-3 blockers — cutover snapshot, historical anchors and the
seal MAC, the divergence baseline, and the AAD phase rule now settled —
should be re-read before phase 3 begins, along with
`docs/formal/rotation_transition.tla`, which checks the transition's
ordering and the laundering defence mechanically.

## Model review against the shipped implementation

`docs/formal/rotation_transition.tla` was written before phase 1 and 2 landed.
Re-reading it against the merged code found six places where the model and the
implementation do not yet meet. None invalidates the model; all are work phase
3 must do, and three change what the transition costs.

1. **The read-authority function has no counterpart.** The model's
   `ReadAuthorized(t)` accepts the current term always and a retiring term
   only while the window is open. `Keyring.Open` looks a term up in
   `kr.terms` and reads it if present. That is vacuous with one term, but it
   means R1 and R2 rest on a check that does not exist: if phase 3 leaves a
   retired term in the keyring after closing the window, it stays readable.
   `Open` is the enforcement point, and it must consult an authority set
   rather than membership.

2. **Five model variables have nowhere durable to live.** The module treats
   `pending`, `retiring`, `snapshot`, `cleanAtCutover`, and `baseline` as
   surviving a crash. The sealed payload holds `schema`, `current_term`, and
   `terms`. Extending it changes the file format, which by the store's own
   rule means bumping `KeyringFileVersion` and the `.keystore` marker version
   together.

3. **The snapshot cannot be as large as the model implies.** It pins one
   entry per object, and the root is read under a 1 MiB limit
   (`maxKeyringBytes`). A store with enough credentials and templates would
   exceed it. Either the snapshot lives outside the root, or it is a digest
   over the inventory rather than the inventory itself. This is a design
   decision phase 3 owes an answer to before it writes the schema.

4. **The snapshot is pinned atomically in the model and cannot be on disk.**
   Enumerating the store races an attacker writing files. The pin must be
   taken where concurrent mutation is excluded — changepass already requires
   generation quiescence and holds the identity mutation lock; term append
   needs the same, and it should be stated rather than inherited by accident.

5. **Term append must not reuse the changepass swap.** The model's root write
   is one atomic file write, which `WriteKeyring` provides. changepass instead
   carries the root through the two-phase `.new`/`.old` swap alongside every
   data file. Reusing that machinery for append would give up the atomicity
   R5 depends on.

6. **`StartRotation`'s guard had no counterpart either.** R5 holds because
   `StartRotation` refuses a root whose rotation descriptor is already
   present. The guarded transition-start slice relaxed the old multi-term
   rejection and installed that real guard in the same change. Tests exercise
   both direct retry and the durable reopened pending root, so resume cannot
   append a third term.

One thing the re-read confirmed rather than found: the object context added in
phase 1 does **not** subsume the cutover snapshot. An attacker holding a
retired term key also controls the filename the context is derived from, so
they can produce a correctly-contexted envelope. The snapshot remains
necessary, and the model's silence about context stays conservative.

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
- **Model the commit protocol.** Done:
  `docs/formal/rotation_transition.tla` checks this design's transition
  invariants R1-R5 against crashes, resume, and a filesystem attacker,
  alongside `generation_commit.tla` for the storage flip. R5 uses a third term
  plus a durable resident-term set. The standard harness also runs
  `rotation_transition_negative.cfg` and requires the unguarded-resume
  mutation to append the third term and violate R5. Both models and the
  negative control run under `make formal-test`.

  Writing it was worth it beyond the checked invariants: TLC rejected the
  first formulation of R1, which demanded that *every* object on disk stay
  readable. An attacker-injected object stranded on a retired term after
  the window closes is the success case, not a violation — the model
  corrected the invariant, not the design.

  What the models do **not** cover, so nobody mistakes green for complete:
  envelope AAD and object context, seal authentication, and historical
  anchors. Those are data-format properties rather than transition ordering,
  and the artifact-class test plus a future anchors module are where they
  get checked.
- **Expect the envelope change to be the risk**, not the keyring type. It
  touches every encrypt/decrypt call site, and a missed one is a file
  written under a term nothing records.
