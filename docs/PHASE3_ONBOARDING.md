# Phase 3 Onboarding: Key-Term Rotation

This is the working brief for the engineer picking up phase 3. It says where
the store is, what phase 3 has to do, and what must be decided before any code
is written.

It is deliberately not the design record. That is
[PROPOSAL_KEYTERM_ROTATION.md](PROPOSAL_KEYTERM_ROTATION.md), 1,160 lines
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
becomes the normal one. Rotation becomes O(1) metadata plus a background
rewrap that can be interrupted safely.

## What is already built

Phases 1 and 2 shipped. They are the foundation, not the fix.

| | Where |
|---|---|
| `keyring.enc` — the store's only cryptographic root: plaintext Argon2id parameters and salt over an AEAD-sealed term set | `internal/crypto/keyring.go`, `keyring_store.go` |
| `.keystore` — a static `{version: 4, layout: "keyring/v1"}` marker, nothing else | `internal/crypto/keyring_store.go` |
| Term envelope (`envelope_version: 3`) — records the term that sealed it, binds term + object identity into the AEAD's authenticated data | `internal/crypto/term_envelope.go` |
| `Keyring.Seal` / `Keyring.Open` — the only way to encrypt or decrypt store data | `internal/crypto/keyring.go` |
| Derivation confinement — no code outside `internal/crypto` imports a KDF, holds a raw term key, or wraps raw bytes as a keyring | `test/arch/kdf_confinement_test.go` |

What that gives you: exactly one term (term 1), a single atomic root write, and
every object already carrying a term number and an identity binding. What it
does **not** give you is any of the transition — no append, no window, no
authority split, no anchors.

The properties that are proven today are K1–K7 in
[FORMAL_TRACEABILITY.md](FORMAL_TRACEABILITY.md), each against a named test.
K8 is listed there as not implemented on purpose; it is yours.

## Read the model early

[`formal/rotation_transition.tla`](formal/rotation_transition.tla) is 299 lines
and models the transition you are about to build: append, rewrap, close, with
crashes, an attacker, and resume interleaved. It checks five invariants and
carries two negative controls that reproduce real review findings mechanically.

Read it before the proposal's prose. It is the most compact statement of what
the transition must do, and its header now states the two places where the
model assumes something the code does not yet provide.

Run it with `python3 scripts/run-formal-tests.py`, which checks all 16 TLA+
modules against recorded metrics in `formal/metrics.json`. Rotation is 52
distinct states at depth 9. **If you change the model, that number changes and
the harness will tell you.**

## What phase 3 must do

Eleven items. They are not equal: three are decisions owed before the schema
can be written, three are enforcement that must land in the same change as the
thing it guards, four are the original blockers, and one is a build-order
constraint.

### Decide before writing the schema

**1. Where the cutover snapshot lives.** The snapshot pins exactly which
objects the rewrap may consume, and it is what stops an attacker holding a
retired term from having their injected file laundered onto the new term. As
modelled it is one entry per object. The root is read under a 1 MiB cap
(`maxKeyringBytes` in `internal/crypto/keyring.go`), so a store with enough
credentials and templates would not fit. Either the pin lives outside the root
or it becomes a digest over the inventory. This decision constrains everything
after it.

**2. Where the transition's durable state lives.** The model treats five
variables as surviving a crash: `pending`, `retiring`, `snapshot`,
`cleanAtCutover`, `baseline`. The sealed payload today holds `schema`,
`current_term`, `terms`. Adding them changes the file format.

**3. The version bump that follows.** Changing the keyring file format means
bumping `KeyringFileVersion` **and** the `.keystore` marker version together.
Under the release policy a store is readable only by the release that
initialized it, so this is expected — but it must be deliberate, and the
existing `checkKDFParams` comment explains why the two move as a pair.

### Enforcement that must land with the code it guards

**4. `Keyring.Open` must consult an authority set, not term membership.**
Today it looks a term up in `kr.terms` and reads it if present. The model's
rule is that the current term is always readable and a retiring term only while
the window is open. Invariants R1 and R2 both rest on reads being *refused*
outside authority. If retired terms simply stay in the keyring after the window
closes, they stay readable and neither invariant transfers from model to code.

**5. R5's guard must be installed in the same change that relaxes the
multi-term rejection.** `OpenKeyring` currently refuses any root with more than
one term — deliberately, so that a phase-1 binary cannot read a phase-3 store.
Phase 3 relaxes that. The model's protection against a second append is
`StartRotation` requiring no rotation already in flight; that guard has to
appear as the rejection disappears, or there is a window with neither.

**6. K8 — the cross-artifact term inventory — before append is enabled.**
A test that creates every durable class and checks each carries a term, opens
under the right context, and refuses the wrong one. This is the gate that
catches a writer someone forgot to stamp. Without it, a missed writer becomes
unreadable data the first time a term is retired, and nothing surfaces it until
then.

### The original blockers

**7. The cutover snapshot** (design in item 1) — an authenticated pin of what
the rewrap may consume. Without it, laundering.

**8. Historical anchors and the seal MAC.** `seal.json` is unkeyed, so a
retired term can forge a sealed generation and recompute its seal, which
mint-on-rollback would then bless under the current term. Compounding this:
generations contain plaintext members (key-type state, witness public
metadata), so a filesystem attacker holding *no keys at all* can alter a sealed
generation and recompute its seal. That predates rotation, but rotation's
anchoring rules have to account for it.

**9. The divergence baseline.** Mandatory rewrap changes every ciphertext
digest, which trips the post-activation rollback guard that compares those
digests against the at-mint manifest. Without a baseline recorded before the
window closes, every later rollback of that generation is refused —
permanently. The model's R3 is exactly this, and its negative control
reproduces it.

**10. Plaintext generation members** — see item 8; listed separately because it
may need its own fix rather than only an anchoring rule.

### Build-order constraints

**11. Two things the code would otherwise lose by accident.** The snapshot must
be pinned where concurrent mutation is excluded — `changepass` already requires
generation quiescence (`requireGenerationQuiescence` in
`internal/storepass/rotate.go`) and holds the identity mutation lock; term
append needs the same rather than inheriting it by luck. And term append must
use the atomic `WriteKeyring`, **not** the two-phase `.new`/`.old` swap that
`changepass` currently carries the root through — that swap is what phase 3
exists to retire, and reusing it would give up the atomicity R5 depends on.

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
   - *Model review against the shipped implementation* — items 1–6 and 11 above,
     with the reasoning
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
