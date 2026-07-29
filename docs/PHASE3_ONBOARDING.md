# Phase 3 Onboarding: Key-Term Rotation

This is the working brief for the engineer picking up phase 3. It says where
the store is, what phase 3 has to do, and what must be reviewed before any
implementation code is written.

It is deliberately not the design record. That is
[PROPOSAL_KEYTERM_ROTATION.md](PROPOSAL_KEYTERM_ROTATION.md), about 1,170 lines
accumulated across six review rounds by two independent reviewers. Everything
here is derived from it; the reading order at the end says which of its
sections you need and which are archive.

## The one-paragraph version

`apstore changepass` re-encrypts every managed file under a new key using a
two-phase `.new`/`.old` swap. A crash partway through leaves the store with
some files under the old key and some under the new, and there is no recovery
path for managed keys or templates — validation fails closed into a state whose
only exit is restore-from-backup. Phase 3 removes that failure mode by changing
what rotation *is*: instead of re-encrypting everything under one new key,
append a numbered key *term*, record on each file which term sealed it, and
keep old terms readable. Mixed-term content stops being a corrupt state and
becomes the normal one. The root commit is O(1) in the number of store
objects, followed by a resumable rewrap that can be interrupted safely; the
authenticated cutover preparation still performs an O(store) inventory scan
under the identity mutation lock.

## What is already built

Phases 1 and 2 shipped. They are the foundation, not the fix.

| | Where |
|---|---|
| `keyring.enc` — the store's only cryptographic root: plaintext Argon2id parameters and salt over an AEAD-sealed term set; the first phase-3 slice writes strict schema `aplane.keyring.v2` but retains the one-term runtime gate | `internal/crypto/keyring.go`, `keyring_store.go` |
| `.keystore` — a static marker: `{version: 5, layout: "keyring/v2"}` plus a `created` timestamp | `internal/crypto/keyring_store.go` |
| Term envelope (`envelope_version: 3`) — records the term that sealed it, binds term + object identity into the AEAD's authenticated data | `internal/crypto/term_envelope.go` |
| `Keyring.Seal` / `Keyring.Open` — the only way to encrypt or decrypt store data | `internal/crypto/keyring.go` |
| Keyring-confined integrity operations — policy, node-role, and generation-seal callers receive or verify MACs without receiving derived key bytes | `internal/crypto/policy_integrity.go` |
| Generation seal v2 — pins the exact manifest bytes, records the signing term, and authenticates every security-bearing seal field with a domain-separated MAC | `internal/genstore/records.go` |
| Policy and node-role sidecar v2 — records the explicit integrity term and rejects unknown fields, trailing JSON, non-canonical MACs, and unauthorized terms | `internal/policy/integrity.go`, `internal/noderole/integrity.go` |
| K8 inventory foundation — canonical artifact kinds and root-relative paths across generations, recovered batches, deleted archives, integrity documents, and rotation records; exact term envelopes are opened under their logical context before being inventoried | `internal/rotationinventory` |
| Derivation confinement — no code outside `internal/crypto` imports a KDF, holds a raw term key, or wraps raw bytes as a keyring | `test/arch/kdf_confinement_test.go` |

What that gives you: exactly one term (term 1), a single atomic root write, and
every encrypted object already carrying a term number and an identity binding.
The plaintext integrity documents and generation seals now carry the same
explicit current-term authority. Trusted generation operations (rollback,
retained-parent pruning, and flip-away sealing) require an open keyring;
pre-unlock reconciliation only uses seal presence to classify unreachable
attempts and does not treat an unverified seal as a rollback authority. What
this does **not** give you is any of the transition — no append, no window, no
authority split, no historical anchors, and no sealed snapshot or completion
pass. The K8 taxonomy and settled-store scanner are present, but K8 remains a
pre-append gate until that scanner is wired into snapshot construction,
historical opening, and the final exact-path/target-authority check.

The properties that are proven today are K1–K7 in
[FORMAL_TRACEABILITY.md](FORMAL_TRACEABILITY.md), each against a named test.
K8 is listed there as not implemented on purpose; it is yours.

## Read the model early

[`formal/rotation_transition.tla`](formal/rotation_transition.tla) models the
transition you are about to build: append, rewrap, close, with crashes, an
attacker, and resume interleaved. It checks five effective invariants and
carries three negative controls that reproduce real review findings
mechanically.

R5 (no second append) has a third term and a durable resident-term set in the
state space, so it is not implied by `TypeOK`.
[`formal/rotation_transition_negative.cfg`](formal/rotation_transition_negative.cfg)
removes the pending-transition guard on resume; the standard formal harness
requires TLC to reach the third term and report an R5 counterexample. This
negative control is the evidence that the positive model's guard is
load-bearing rather than a vacuous consequence of its types.

Read it before the proposal's prose. It is the most compact statement of what
the transition must do, and its header now states the two places where the
model assumes something the code does not yet provide.

Run it with `python3 scripts/run-formal-tests.py`, which runs all 17 recorded
TLC checks — 13 modules, three additional liveness configurations, and the R5
negative control — against recorded outcomes and metrics in
`formal/metrics.json`. The positive rotation model is 52 distinct states at
depth 9; the expected R5 violation is 21 distinct states at depth 4. **If you
change either shape or the expected outcome, the harness will tell you.**

## What phase 3 must do

Eleven items. They are not equal: three are schema decisions that must be
reviewed before code is written, three are enforcement that must land in the
same change as the thing it guards, four are the original blockers, and one is
a build-order constraint.

### Schema decisions for review

The following three decisions are the phase-3 schema proposal. They are
recorded here for review before implementation; changing one requires
re-checking the transition ordering and the dependent decisions below.

**1. Where the cutover snapshot lives.** The snapshot pins exactly which
objects the rewrap may consume, and it is what stops an attacker holding a
retired term from having their injected file laundered onto the new term. As
modelled it is one entry per object. The root is read under a 1 MiB cap
(`maxKeyringBytes` in `internal/crypto/keyring.go`), so a store with enough
credentials and templates would not fit.

**Decision:** write the snapshot body as
`identities/<identity>/rotation.snapshot.enc`, sealed under the target term
with object class `rotation-snapshot` and the fixed logical selector
`pending`. Its plaintext schema is `aplane.rotation-snapshot.v1`:

- `from_term` and `to_term`;
- a sorted, unique inventory of every input the transition may consume;
- when the current generation is rollback-eligible, its generation ID,
  clean-or-diverged decision, and the effective starting inventory authority
  (its at-mint manifest or the matching prior rotation baseline).

Each inventory entry records a signer-data-root-relative slash-separated
canonical path, one of the artifact kinds defined by K8 below, byte size,
lowercase SHA-256 digest, and, for a term envelope, its logical object class
and selector. Root-relative paths cover both identity-local inputs and the
root `node.yaml` authenticated by the identity's sidecar. Paths are UTF-8,
contain no empty, `.` or `..` component, never begin with `/`, are unique,
and sort by raw UTF-8 byte order. Digests cover the exact bytes read from the
regular file, not a parsed or re-encoded form.

The body is size-limited independently of `keyring.enc`; the implementation
must choose and test an explicit `maxRotationSnapshotBytes` before append is
enabled. The root stores only the SHA-256 digest and byte size of the exact
sealed snapshot file. It never stores the inventory itself.

The identity mutation lock excludes cooperating writers while the snapshot is
built; it does not exclude the direct-filesystem attacker in the threat model.
For that attacker, an edit before an entry is read is pre-cutover, while an
edit after the exact bytes are read must cause a digest or final-inventory
mismatch and fail closed. Rewrap hashes and decrypts the same buffer rather
than validating one read and decrypting another. Before close, a fresh scan
of all in-scope artifact classes must match the snapshot's complete canonical
path set exactly and every output must be on the target term or carry a
target-term integrity sidecar as its artifact kind requires. Added, removed,
substituted, or untransformed in-scope paths leave the transition pending.
Resume reopens the root-pinned snapshot, accepts outputs already authenticated
under the target term, and idempotently retries the remaining pinned inputs.
It must never make progress by blessing the disk's new contents. A persistent
digest or final-inventory mismatch is evidence of tamper or corruption. The
operator must remove an unexpected path or restore the exact missing or
substituted bytes from a trusted copy, or restore the store from backup when
targeted repair is not possible. Resume may close the transition only after
the exact path set and output-authority checks pass.

Commit ordering is:

1. write the sealed snapshot with `WriteFileDurable`;
2. atomically write `keyring.enc` referring to its digest and size;
3. perform and verify the rewrap;
4. write any required divergence baseline durably;
5. atomically clear the pending descriptor from `keyring.enc`;
6. remove the now-unreferenced snapshot durably.

A crash before step 2 leaves an unreferenced orphan that can be removed. A
crash after step 2 must find the exact referenced snapshot or remain in
rotation-pending recovery. Deleting the snapshot before clearing the root is
forbidden.

**2. Where the transition's durable state lives.** The model treats five
variables as surviving a crash: `pending`, `retiring`, `snapshot`,
`cleanAtCutover`, `baseline`. The sealed payload today holds `schema`,
`current_term`, `terms`. Adding them changes the file format.

**Decision:** the v2 sealed keyring payload is the sole authority for whether
a transition is pending and which term has retiring current-state authority:

```json
{
  "schema": "aplane.keyring.v2",
  "current_term": 2,
  "terms": [
    {"term": 1, "key": "<base64>"},
    {"term": 2, "key": "<base64>"}
  ],
  "historical_anchors": [],
  "rotation": {
    "from_term": 1,
    "snapshot_sha256": "<lowercase hex>",
    "snapshot_size": 1234
  }
}
```

`rotation` is optional. Its presence means `pending`; its absence means the
store is settled. While present, the current-state read authority is exactly
`{current_term, rotation.from_term}`. While absent, it is exactly
`{current_term}`. There is no separate `pending` boolean or
`retiring_terms` list that could disagree with this descriptor. The payload
is rejected unless both named terms exist, the terms differ, the snapshot
reference is canonical, and no second transition is started while
`rotation` is present.

Term IDs are JSON integers in `[1, 2^63-1]`. Term records are sorted by
strictly increasing ID and contain no duplicates. `current_term` names the
greatest resident term. Starting a rotation appends exactly
`current_term + 1`, rejects integer overflow, promotes that new term in the
same root write, and records the former current term as `from_term`. A pending
descriptor is valid only when `from_term` is the immediately preceding term.
These are parse-time checks as well as `StartRotation` preconditions.

The single `from_term` is a deliberate narrowing of the proposal, which keeps
`retiring_terms` a set for reserved generality — a future term-GC pass folding
several retirements into one transition. The narrowing is chosen anyway
because a descriptor that cannot disagree with itself is worth more now than
generality no defined path uses yet; if term GC later needs a multi-term
window, that is a payload schema change, reviewed as one.

The large and lifecycle-specific state stays outside the root:

- `snapshot` and `cleanAtCutover` live in the root-pinned sealed snapshot
  described in item 1;
- the completed post-rewrap baseline, when one is required, lives in
  `identities/<identity>/rotation.baseline.enc`, sealed under the current
  term with object class `rotation-baseline` and fixed selector `current`.
  Its plaintext schema is `aplane.rotation-baseline.v1` and contains exactly
  one generation ID, the entry count, and the SHA-256 digest of that
  generation's canonical live inventory;
- historical generation anchors remain in `historical_anchors` in the root,
  one sorted unique `(generation_id, seal_size, seal_sha256)` entry per
  retained sealed generation containing a term that is retiring or has
  retired. `seal_sha256` covers the exact complete `seal.json` v2 bytes,
  including its integrity-term field and MAC.

A baseline file is not a second commit record. For rollback decisions,
missing, malformed, wrong-generation, or wrong-term baseline data falls back
to the immutable at-mint manifest and therefore refuses rollback; it cannot
assert false cleanness. A required baseline must be durable before `rotation`
is cleared. The next successful mint supersedes the baseline; a stale file is
ignored by generation-ID mismatch and removed durably after the `CURRENT`
flip.

Rotation preflight reconciles any existing `rotation.baseline.enc` under the
identity mutation lock before constructing the cutover snapshot. A valid
baseline for the rollback-eligible current generation is pinned as the
effective starting authority and consumed when producing the target-term
completion baseline. A valid baseline naming a superseded generation is stale
and is removed durably before cutover. A malformed baseline, one sealed under
an unauthorized term, or one that otherwise cannot be classified safely
blocks rotation for operator remediation; rotation does not silently delete
possible evidence of tamper or corruption. This preflight also completes
stale-baseline cleanup left by a crash after a mint's `CURRENT` flip.

The baseline inventory uses the same canonical `InventoryEntry` ordering and
field encoding as generation manifests and seals. The baseline digest is over
an explicit domain string plus an unambiguous length-prefixed encoding of
those entries, not over implementation-dependent JSON bytes.

Generation seal v2 embeds `manifest_sha256`, `integrity_term`, and
`integrity_mac`. `manifest_sha256` binds the exact immutable `manifest.json`
bytes; validation hashes the manifest buffer it parsed and compares it before
using lineage or operation metadata. The MAC is computed over a canonical
length-prefixed encoding of all security-bearing seal fields except
`integrity_mac`, under the named term's generation-seal integrity key. An
unanchored seal is accepted only under the current integrity term. Once that
term retires, the exact complete seal bytes must match the root's historical
anchor; the retired-term MAC alone is no longer authority. An unanchored
seal's term-bearing inventory entries must all name the current term.
Historical opening hashes the exact ciphertext buffer it will decrypt and
matches its `(path, size, digest, term)` inventory entry before opening it.

**3. The version bump that follows.** Changing the keyring file format means
bumping `KeyringFileVersion` **and** the `.keystore` marker version together.
Under the release policy a store is readable only by the release that
initialized it, so this is expected — but it must be deliberate, and the
existing `checkKDFParams` comment explains why the two move as a pair.

**Decision:** phase 3 writes and accepts only:

- `KeyringFileVersion = 2`;
- sealed payload schema `aplane.keyring.v2`;
- keyring AAD domain `aplane.keyring-file.v2`;
- `.keystore` marker version `5`;
- `.keystore` layout `keyring/v2`.

There is no v4-to-v5 or keyring-v1-to-v2 in-place migration. Existing stores
cross the release boundary through backup export and restore into a freshly
initialized v5 store. Term envelopes remain at envelope version 3 because
their term-and-object-context wire shape does not change. Generation seals
and policy/node-role integrity sidecars receive their own version bumps when
the seal MAC and explicit integrity term land; those versions are not
overloaded into the keyring version.

#### Schema review outcome

The implementation review approved the three decisions above with these
clarifications:

- durable term IDs use signed 64-bit values, matching the stated
  `[1, 2^63-1]` range independently of the host's native `int` width;
- `terms` and `historical_anchors` are required JSON arrays. A settled fresh
  store writes `historical_anchors: []`; absence or `null` is malformed.
  `rotation` is omitted only when no transition is pending;
- every SHA-256 field is exactly 64 lowercase hexadecimal characters and every
  referenced size is positive. Historical anchors sort strictly by canonical
  generation ID, and terms sort strictly by ID;
- the sealed snapshot file has an independent 16 MiB read/reference cap
  (`maxRotationSnapshotBytes`). This is a cap on the exact encrypted file
  pinned by the root, not part of the 1 MiB `keyring.enc` allowance;
- keyring and marker decoding rejects unknown fields and trailing JSON before
  the data is used. Required-field and canonical-encoding checks then reject
  missing arrays, non-canonical base64 header fields, invalid digests, and
  inconsistent transition state;
- the v2 root and version-5 marker land while the runtime still rejects every
  multi-term, pending, or anchored root. This intentionally does not relax the
  existing safety gate. Multi-term acceptance, `Keyring.Open` authority
  enforcement, and the guarded `StartRotation` operation remain one later
  inseparable change, as items 4 and 5 require.

### Enforcement that must land with the code it guards

**4. `Keyring.Open` must consult an authority set, not term membership.**
Today it looks a term up in `kr.terms` and reads it if present. The model's
rule is that the current term is always readable and a retiring term only while
the window is open. Invariants R1 and R2 both rest on reads being *refused*
outside authority. If retired terms simply stay in the keyring after the window
closes, they stay readable and neither invariant transfers from model to code.

**5. R5's guard must be installed in the same change that relaxes the
multi-term rejection.** `OpenKeyring` still refuses any root with more than
one term even though it now validates the v2 payload shape. The first schema
slice deliberately retained that runtime gate. The model's protection against a second append is
`StartRotation` requiring no rotation already in flight; that guard has to
appear as the rejection disappears, or there is a window with neither. The
formal half of this gate is complete: the positive model checks R5 and the
standard harness requires the unguarded resume mutation to violate it. The
implementation guard remains part of the same code change that relaxes the
multi-term rejection, not follow-up work.

**6. K8 — the cross-artifact term inventory — before append is enabled.**
K8 classifies every durable store artifact rather than incorrectly requiring
every plaintext file to carry an encryption term:

| Classification | Durable classes | Phase-3 rule |
|---|---|---|
| Term-encrypted | active `.key` and `.sen` credentials; installed `.template` files; published recovered batch metadata and entries; deleted key, sentry-credential, and template archives; rotation snapshot and baseline | Envelope carries a term and the class-specific logical context. Mutable and inactive store consumers, including `deleted/`, are snapshot-pinned and rewrapped onto the target term. The snapshot itself is a new target-term record pinned by the root and is not recursively inventoried. A valid matching baseline that exists before cutover is pinned as an input; the baseline written during completion is a target-term output and is not recursively inventoried as another input. |
| Plaintext plus term integrity | `policy.yaml` and root `node.yaml`, through their identity-local HMAC sidecars | Sidecar v2 carries an explicit integrity term. Snapshot pins the exact document input; completion requires a target-term sidecar. |
| Plaintext generation member | key-type state records, witness public metadata, generation manifest, and generation seal | No per-file encryption term is invented. Namespace members are covered by the seal inventory; `manifest.json` is covered by the seal's manifest digest; the seal MAC, historical anchor, and exact-byte historical open provide the term authority described above. |
| Independent or excluded | `keyring.enc` and `.keystore`; standalone-passphrase backups; audit/config/unlock/token/SSH state; plaintext template library; caches; unpublished staging residue | Not opened as a term-encrypted store object. The KEK-sealed root and static marker keep their own versioned contract; other existing independent validation applies. Staging residue is reconciled or rejected before cutover, never promoted by rewrap. |

The `deleted/` choice is deliberate: these paths are durable inactive archives
under the current storage contract, so phase 3 retains and rewraps them. It
does not silently erase them and does not leave them under the retiring term.

The K8 test creates every applicable durable class and proves its
classification. For each term envelope it checks term presence, correct
logical-context opening, wrong-class and wrong-selector refusal, and supported
generation/staging/deleted moves. For integrity documents it checks the
explicit sidecar term and wrong-term refusal. For plaintext generation members
it mutates the member and proves the seal MAC or anchor rejects it. Each gate
must have a mutation-tested negative control. Without K8, a missed writer can
become unreadable only when a term retires, long after the causal write.

#### K8 implementation boundary

`internal/rotationinventory` now defines the canonical artifact kinds and
entry fields (`path`, `kind`, exact byte `size`/`sha256`, and term-envelope
context or integrity term where applicable). Its settled-store scanner:

- inventories current and retained generation members, recovered batches,
  deleted credential/template archives, policy and node-role document pairs,
  and optional rotation records;
- rejects unknown in-scope files and unreconciled generation staging residue;
- opens the exact encrypted buffer it hashes under the context derived from
  the canonical filename or recovered-batch metadata;
- verifies retained namespace buffers against the authenticated seal entry
  before opening them, and parses exact manifest/seal buffers together;
- excludes documented independent state from the inventory.

`TestScanClassifiesEveryK8DurableClass` creates every applicable class,
including generation copies, deleted moves, and recovered staging
publication. Dedicated negative controls cover selector/class substitution,
unauthorized sidecar terms, mutated sealed plaintext members, and unknown
in-scope files.

This is intentionally still a foundation. Before append is enabled, the
rotation snapshot schema must consume this inventory, pending-state scans must
exclude the root-pinned snapshot from recursive input, seal entries must carry
the term of each term-bearing member, historical opening must authorize
anchored retired terms, and completion must compare the fresh canonical path
set and target authority against the pinned snapshot.

### The original blockers

**7. The cutover snapshot** (design in item 1) — an authenticated pin of what
the rewrap may consume. Without it, laundering.

**8. Historical anchors and the seal MAC.** Generation seal v2 now authenticates
the exact manifest digest, explicit integrity term, and canonical inventory
under the current term's generation-seal integrity key. This closes the
pre-rotation unkeyed-seal defect: a filesystem attacker holding no key cannot
alter a plaintext generation member and recompute an accepted seal. Historical
anchors are still required before a term can retire. A holder of that retired
term could otherwise forge a seal under its old MAC key and have
mint-on-rollback bless the result under the current term.

**9. The divergence baseline.** Mandatory rewrap changes every ciphertext
digest, which trips the post-activation rollback guard that compares those
digests against the at-mint manifest. Without a baseline recorded before the
window closes, every later rollback of that generation is refused —
permanently. The model's R3 is exactly this, and its negative control
reproduces it.

**10. Plaintext generation members** — see item 8; listed separately because it
may need its own fix rather than only an anchoring rule.

### Build-order constraints

**11. Two things the code would otherwise lose by accident.** Snapshot
construction must exclude cooperating store and generation mutations.
`changepass` gets that exclusion today from the identity mutation lock plus
generation quiescence — but be careful which half of quiescence you carry
forward. The proposal retires `requireGenerationQuiescence` (in
`internal/storepass/rotate.go`) along with its prune-all-priors prerequisite;
that retention sense of quiescence dissolves in phase 3. The mutual-exclusion
sense — no cooperating generation mutation while the inventory is being
pinned — must survive under the identity mutation lock as a requirement term
append states itself rather than inherits by luck. Direct filesystem writes
are handled by the exact-byte and final-inventory checks in item 1, not by
claiming the lock excludes the attacker. And term append must use the atomic
`WriteKeyring`, **not** the two-phase `.new`/`.old` swap that `changepass`
currently carries the root through — that swap is what phase 3 exists to
retire, and reusing it would give up the atomicity R5 depends on.

## Two things that are easy to get wrong

**Object context does not replace the snapshot.** Phase 1 binds each object's
class and canonical selector into the AEAD. It is tempting to conclude that
laundering is already impossible. It is not: an attacker holding a retired term
key also controls the filename the context is derived from, so they can produce
a correctly-contexted envelope under a retiring term. The snapshot is still
required.

**Decryptable is not authorized.** The proposal has a section under that title
and it is the conceptual heart of the transition. A term key that can decrypt a
file is not thereby entitled to have that file promoted, blessed, or treated as
current state. Most of the review findings that shaped this design were
failures of that distinction.

## What this does not guarantee

Three scoping facts from the proposal that bound what phase 3 delivers:

**The root is authenticated, not fresh.** An attacker who puts back an old
authentic `keyring.enc` erases the pending descriptor, the anchors, and the
promotion, and no in-store mechanism detects it. Every guarantee here is
scoped to a store whose root is the committed one; the proposal scopes root
replay out explicitly, because replacing the root is substituting the store.

**Retained priors stay readable under old terms.** Rotation rewraps the
mutable live store, not sealed prior generations, and a retained prior holds
substantially the same credentials as the current one. The proposal ships
this weaker guarantee deliberately: `changepass` warns the operator that
prior generations remain readable under pre-change terms and points at
`apstore generations prune --all-priors`.

**Terms are appended, never yet deleted.** Term GC is deferred out of the
first implementation, so the keyring grows one entry per rotation, and the
steady state is not one term whenever a prior is retained.

## Reading order

1. This document.
2. `formal/rotation_transition.tla` — the whole file, including the header.
3. `PROPOSAL_KEYTERM_ROTATION.md`, these sections, in order:
   - *Problem* — the defect, stated precisely
   - *Decryptable is not authorized* — the trust model
   - *The rotation transition (durable state machine)* — the steps and ordering
   - *The cutover snapshot* — the laundering defence
   - *Retained sealed generations need an authenticity anchor* — blocker 8
   - *Rewrap versus the rollback divergence guard* — blocker 9
   - *Model review against the shipped implementation* — items 1–5 and 11
     above, with the reasoning (item 6's rationale lives in *Open questions
     (resolved)*, question 3, not here)
4. `FORMAL_TRACEABILITY.md`, Store Cryptography section — what is proven today.

Two sections are archive rather than instruction. *Open questions (resolved)*
is roughly 350 lines of settled debate: read it when you want to know why a
decision went the way it did, not to learn what to build. *Where implementation
starts* describes phase 1, which shipped; it is kept as the record of what that
phase committed to.

## A note on how this work has gone

Every phase so far has had defects found in review that the implementer missed,
including in the gates written to prevent exactly those defects. The habits
that caught them are worth keeping:

- **Verify a reviewer's claim against the code before acting on it.** Several
  turned out to be based on stale reads; several others were sharper than first
  stated.
- **Negative-control every gate.** Break the thing the test guards and confirm
  the test fails. Two tests in this codebase passed while proving nothing, and
  only mutation revealed it.
- **Prefer the compiler to a test where the choice exists.** Phase 2 deleted
  the compatibility seam rather than documenting it, which turned "did every
  site move?" into a build failure.

Phase 3 is the first phase where a mistake is silently unrecoverable. A writer
missing from term stamping produces no error until a term is retired, and by
then the data is unreadable. Budget review accordingly, and get the schema
decisions reviewed as a design before they are implemented.
