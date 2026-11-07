# Key Type Specification: Rotating Triple Hybrid

Status: implemented as three separate key types.
`aplane.rotating-triple-xmss.v1` is frozen by its first release (v0.44.0) and
`aplane.rotating-triple-slhdsa.v1` by its first release (v0.45.0); its design
is in section 11. `aplane.rotating-triple-wotsc.v1` isn't frozen; its
design is in section 12. This document specifies all three
for implementers and reviewers: their shared design and the hash-based schemes. It restates, and does not replace, the
authoritative sources:

- `lsig/rotatingtriplexmss/`: XMSS stage template, derivation, signing, tree
  cache, key file codec, generator and registration
- `lsig/rotatingtriplewotsc/`: WOTS+C stage template, derivation, signing, key
  file codec, generator and registration
- `internal/crypto/xmss/` and `internal/crypto/wotsc/`: hash-based primitives
- `internal/crypto/rotatinghybrid/`: shared seed derivation
- `lsig/rotatingfamily/`: what all three rotating key types share:
  registration and the generator, the stage's Ed25519 and Falcon-1024 half,
  stage program salt search and strict parse, and the contract suite
- `internal/rotatingkey/rotatingkey.go`: key type identifiers, frozen sizes
  and resource profiles
- [ARCH_CRYPTO.md](ARCH_CRYPTO.md), [ARCH_SIGNING.md](ARCH_SIGNING.md#rotating-accounts-rotating1)
  and [ARCH_KEYTYPES.md](ARCH_KEYTYPES.md): cryptographic design, signing flow
  and key type contracts

The third implementation, `aplane.rotating-triple-slhdsa.v1`, reuses the
shared `rotating1` account and signing contracts with a stateless hash-based
scheme. Sections 2 through 9 compare the XMSS and WOTS+C variants and keep
their exact layouts. Section 11 specifies where SLH-DSA differs, with the
frozen contract in [ARCH_CRYPTO.md](ARCH_CRYPTO.md#rotating-slh-dsa-triple)
and the qualification record in [SLHDSA_EVALUATION.md](SLHDSA_EVALUATION.md).
Section 12 gives the WOTS+C construction.
Its implementation is `lsig/rotatingtripleslhdsa/`, with the primitive in
`internal/crypto/slhdsa/`. It was first released in v0.45.0.

Where this document and the code disagree, the code and its frozen golden
tests win; report the discrepancy.

## 1. Summary

A rotating triple hybrid is a **rotating** Algorand account. It has one fixed
address, but the LogicSig program that authorizes it (the *stage*) changes on
every confirmed spend. The signer makes every spend rekey the account to the
next stage, so the keys a signature reveals control the account only until that
transaction, or a later rotation, confirms.

Every stage requires **three** signatures over the transaction ID, all of which
must verify:

| Component | Algorithm | Role |
|---|---|---|
| Falcon-1024 | lattice, post-quantum | per-stage key |
| Ed25519 | classical (`ed25519verify_bare`) | per-stage key |
| Hash-based signature | XMSS, WOTS+C or SLH-DSA, SHA-256 | one-time leaf or per-stage few-time key (section 11) |

The hash-based scheme is selected by the key type when the account is created.
Each type has its own stage template, derivation label and addresses, frozen at its
first release except for WOTS+C;
the signing request does not select or switch the scheme.

| Item | XMSS | WOTS+C |
|---|---|---|
| Key type | `aplane.rotating-triple-xmss.v1` | `aplane.rotating-triple-wotsc.v1` |
| Family | `aplane.rotating-triple-xmss` | `aplane.rotating-triple-wotsc` |
| Hash-based key | one leaf of an XMSS tree | one leaf of the stage's own tree |
| One-time keys available per stage | 64 leaves | 64 leaves |
| Stages sharing a tree | 1,024 | none: each stage has its own tree |
| Category and codec | DSA LogicSig, `rotating_lsig` | same |
| Signing flow | `rotating1` | same |
| Creation parameter | `network` (name or base64 genesis hash) | same |
| Client provider | none; signer-side only | same |
| Availability | `Library`: an operator enables it, then generates | same |

## 2. Parameters and sizes (frozen)

The XMSS values are frozen. The WOTS+C values aren't.

| Parameter | XMSS | WOTS+C |
|---|---|---|
| Hash-based construction | `XMSS-SHA2_16_256` | Tree of WOTS+C keys with the FIPS 205 SHA2 tweakable hash |
| Hash and Winternitz parameters | SHA-256, n = 32, w = 16, h = 16 | SHA-256, n = 16, w = 16, h = 6 |
| Chains | 67: 64 message digits + 3 checksum digits | 32 message digits, no checksum digits |
| Steps per chain | 15 | 15 |
| Leaves per tree | 65,536 | 64 |
| Leaves per stage | 64 | 64 |
| Randomizer search limit | 64 counters | 8,192 counters |
| Message checksum cap | 511 | none; the digits must sum to exactly 240 |
| Maximum accepted chain steps | 525 | 240, on every accepted run |
| Validity window cap | 100 rounds (`LastValid - FirstValid`) | same |
| TEAL version | 13 | 13 |
| Stage program bytes, unsalted / salted | 2,661 / 2,664 | 2,483 / 2,486 |
| Stage 0 public record bytes | 1,921 | 1,857 |
| Hash-based signature bytes | 2,692 | 628 |
| Ed25519 signature bytes | 64 | 64 |
| Falcon-1024 signature bytes | at most 1,423, compressed | same |
| Falcon-1024 public key bytes | 1,793 | 1,793 |
| Maximum total argument bytes | 4,179 | 2,115 |
| Maximum opcode cost | 95,857 | 15,721 |
| Group size | 5: one spend + four resource dummies | 3: one spend + two resource dummies |

The stage packages own the templates and cost models. The corresponding
profiles in `internal/rotatingkey` expose their frozen bounds to storage,
inventory and signing orchestration.

## 3. Account and stage model

A stage is indexed by `n >= 0`. Stage 0's program address **is** the account
address. Stage `n` normally signs one transaction, which rekeys the account to
stage `n + 1`'s program address. Releasing a signature does not itself advance
the stage: the chain must confirm a rotation.

The WOTS+C variant derives a fresh tree of 64 WOTS+C keys for every stage. The
XMSS variant assigns stage `n` to tree `n div 1024` and the leaf range
`[64 * (n mod 1024), 64 * (n mod 1024) + 64)` (`stage.RangeFor`). A new tree is needed at every
multiple of 1,024 stages; the worker builds it ahead of need from the midpoint
of the live tree.

### 3.1 Stage program

Every TEAL v13 stage template requires:

1. `RekeyTo` is non-zero and is not the sender.
2. `CloseRemainderTo` is zero.
3. `LastValid - FirstValid <= 100`.
4. `arg 1` is a valid Ed25519 signature of `TxID` under the embedded key.
5. `arg 2` is a valid Falcon-1024 signature of `TxID` under the embedded key.
6. `arg 0` is a valid hash-based signature under the selected scheme.

The XMSS program embeds six constants: the Ed25519 key (32 bytes), Falcon key
(1,793), tree public seed (32), tree root (32), and `Lo` and `Hi` (8-byte
big-endian integers). It requires a 2,692-byte signature, an index within
`[Lo, Hi)`, a message checksum at most 511, and successful WOTS+, L-tree and
authentication-path verification against the root.

The WOTS+C program embeds four constants: the Ed25519 key (32 bytes), Falcon key
(1,793), public seed (16) and tree root (16). It requires a 628-byte signature,
a leaf index below 64, a digest whose digits sum to exactly 240, and successful
chain and authentication-path verification against the root.

The XMSS program verifies everything with `sha256`, `concat`, `extract3`,
`replace3`, `b^`, `itob` and one subroutine (`hnode`). The `toByte(3) || SEED`
prefix of every `PRF` call is hoisted into the per-phase address prefixes, and
a chain step is kept as `step << 32` so a single `itob` yields both trailing
address words. The checksum cap is asserted when the chain loop reaches the
checksum chains. The WOTS+C program runs one loop over its 32 chains and one
over the six path nodes; a chain is unrolled, and `switch` enters its 15 hash
steps at the digit.

No stage program restricts transaction type or constrains `RekeyTo` beyond
condition 1. Anyone holding a valid triple of signatures over a transaction
that satisfies conditions 1 to 3 could spend it. The signer therefore releases
a stage's signatures only for a transaction that rekeys to the account's next
stage. Within an XMSS or WOTS+C stage, each hash-based leaf must authenticate
only one distinct message; the stage provides 64 such leaves. Spending policy
is enforced by the signer's policy layer.

### 3.2 Derivation of the stage address

Each scheme's `stage.Build(keys)` fills its own template and computes
`SHA-512/256("Program" || bytecode)`. If the address is on the Ed25519 curve,
it appends `intcblock 1 <salt>` (bytes `0x20 0x01 <salt>`), choosing the lowest
salt in `[0, 128)` giving an off-curve address, as the TEAL v13 assembler does.
If none exists (probability about 2^-128) the stage is unusable
(`ErrNoOffCurveSalt`).

`stage.Parse` is the strict inverse: it accepts only bytes that `Build` would
produce, including the canonical salt tail when required. No bytecode is
stored in the key file. Stages are derived locally and offline, on requests and
in the background, without trusting a node for addresses. For each scheme a
test compares the local bytes against algod's assembler output for salted and
unsalted stages.

## 4. Key derivation

The only stored private material is a 64-byte BIP-39-style seed. All variants
use HKDF-SHA-512 with their own label as the extraction salt:

| Scheme | Derivation label |
|---|---|
| XMSS | `APLANE_ROTATING_XMSS_V1` |
| WOTS+C | `APLANE_ROTATING_TRIPLE_WOTSC_V1` |

Every expansion includes the network's 32-byte genesis hash `G`. Account-level
info is `tag || G`; stage- or tree-level info is `tag || G || u64be(counter)`.
Thus the same seed derives different material across networks and key types.

| Output | Tag | Counter | Bytes | Scheme |
|---|---|---|---|---|
| Public account tag | `0x10` | none | 32 | XMSS |
| Stage Falcon-1024 seed | `0x01` | stage `n` | 48 | both |
| Stage Ed25519 seed | `0x02` | stage `n` | 32 | both |
| Secret seed (`SK.seed`) | `0x03` | stage `n` | 16 | WOTS+C |
| Randomizer key (`SK.prf`) | `0x04` | stage `n` | 16 | WOTS+C |
| Public seed (`PK.seed`) | `0x05` | stage `n` | 16 | WOTS+C |
| Tree secret seed (`SK_SEED`) | `0x20` | tree number | 32 | XMSS |
| Tree PRF key (`SK_PRF`) | `0x21` | tree number | 32 | XMSS |
| Tree public seed | `0x22` | tree number | 32 | XMSS |

Derivation is random access: a stage does not require deriving its predecessors.
Secrets are derived per call and zeroed before returning.

XMSS additionally builds the public tree (65,536 WOTS+ leaves, about 4 MiB of
nodes). It takes seconds to generate and is cached only in memory, with no
secrets retained. The cache holds at most 3 trees per account (live, next, one
behind) and 16 overall, with least-recently-used eviction. Concurrent requests
for the same tree share one generation. WOTS+C rebuilds its small per-stage tree
in about 5 ms and needs no cache.

## 5. Signing

### 5.1 Message

All three components sign the same raw 32-byte transaction ID. Ed25519 and
Falcon-1024 use their standard signature operations with the stage's keys.

### 5.2 XMSS

The XMSS variant uses the RFC 8391 `XMSS-SHA2_16_256` signature format:

```text
arg 0 = index (4 bytes, big-endian)
     || r (32 bytes)
     || WOTS+ signature (67 * 32 bytes, offset 36)
     || authentication path (16 * 32 bytes, offset 2180)
```

The signed digest is `H_msg(r || root || toByte(index, 32), TxID)`. Verification
uses RFC 8391 hash addresses, masked WOTS+ chains, an L-tree compressing the
67 chain ends, and a 16-level authentication path to the embedded root.

The signer chooses `r` with `xmss.SignBounded`:

1. For counters `c = 0, 1, ..., 63`, compute
   `r = PRF(SK_PRF, toByte(c, 28) || toByte(index, 4))`.
2. Compute the message hash and its WOTS+ checksum.
3. Use the first candidate whose checksum is at most 511, generate one WOTS+
   signature, and attach the authentication path.
4. If no candidate qualifies, return `ErrRandomizerSearchExhausted` without
   generating a signature.

Counter 0 is RFC 8391's own randomizer input, so about four signatures in five
are byte-identical to an RFC signer's. A candidate qualifies with probability
about 0.803, so exhaustion has probability about 2^-150. The search is
deterministic: the same seed, index and message reproduce the same signature,
and no counter is stored. Search counters are not leaf indices and never
consume the stage's leaf budget. Only one WOTS+ signature is ever generated.

The resulting signatures verify under an RFC 8391 verifier, which reads `r`
from the signature. The stage rejects signatures whose checksum exceeds 511,
including otherwise valid RFC signatures. The bounded randomizer procedure and
best-effort leaf management make this **not a conformant stateful XMSS signer**
under RFC 8391 or NIST SP 800-208.

### 5.3 WOTS+C

The WOTS+C variant uses the construction in `internal/crypto/wotsc`: a tree of 64
keys per stage with n = 16, w = 16 and 32 message digits. A fixed digit sum of 240
replaces the checksum chains: the signer searches up to 8,192 deterministic
randomizers until the digest qualifies, and the verifier requires the sum.

```text
arg 0 = leaf (4) || R (16) || chain_element[0] || ... || chain_element[31] || auth[0..5]
```

The signature is 628 bytes. Because the digit sum is fixed, every accepted run
completes exactly 240 chain steps. Each leaf must authenticate only one released
message to retain its one-time security property. Section 12 has the full
construction.

### 5.4 Arguments

| Argument | XMSS variant | WOTS+C variant |
|---|---|---|
| `arg 0` | XMSS signature, 2,692 bytes | WOTS+C signature, 628 bytes |
| `arg 1` | Ed25519 signature, 64 bytes | same |
| `arg 2` | Falcon-1024 signature, at most 1,423 bytes | same |

### 5.5 Signer-side verification

Before releasing anything, `StageOps.SignStage` re-parses the derived program
and verifies all three signatures locally through the scheme's `signerops.Verify`.
XMSS also checks the leaf range and checksum cap. WOTS+C rejects an index outside
0 to 63. Failed signatures are zeroed and refused.

A signature is then released only if the signer hasn't locked since approval, the
request hasn't been cancelled and the key is still present. The sign path is a key
user, so a lock cancels it and waits for the seed to go. The seed goes before the
audit write, so a stalled disk can't hold up a lock, and the checks run again after
the last audit write. A release refused at that point stays on record, which only
makes its leaf look used. Nothing that blocks comes after that check in the signer,
but the response still has to be written, so a lock can arrive while it is on its
way.

## 6. Resource profile and cost

Each group member contributes 20,000 units of pooled LogicSig execution cost
and 1,000 bytes of pooled large-argument allowance.

| Property | XMSS | WOTS+C |
|---|---|---|
| Unsalted verifier cost | `25,507 + 134 * steps` | `5,881 + 41 * 240` |
| Maximum chain steps | 525 | 240 |
| Salt overhead | none; salt follows `return` | same |
| Worst accepting run | 95,857 | 15,721, on every accepted run |
| Maximum argument bytes | 4,179 | 2,115 |
| Group pool | 100,000 cost / 5,000 argument bytes | 60,000 cost / 3,000 argument bytes |
| Resource dummies | 4 | 2 |

For hexadecimal checksum digits `a b d`, the number of verification chain
steps is `45 + 255a + 15b`. XMSS's cap of 511 bounds this at 525; a checksum
of 512 already needs 555. WOTS+C's fixed digit sum makes the count exactly 240.
The generic XMSS primitive's `MaxVerifySteps = 990` remains
unchanged; the 525-step bound belongs to the XMSS stage profile.

## 7. Key file and storage

All variants use a managed `.key` credential with the `rotating_lsig` codec
(`keys.RotatingCodec`), containing the seed, network genesis hash and a
scheme-specific stage 0 public record:

| Scheme | Public record, in order | Bytes |
|---|---|---|
| XMSS | account tag (32), Falcon public key (1,793), tree 0 root (32), tree 0 public seed (32), Ed25519 public key (32) | 1,921 |
| WOTS+C | public seed (16), root (16), Falcon public key (1,793), Ed25519 public key (32) | 1,857 |

The account address is derived from this record. No bytecode is stored; XMSS's
stage 0 leaf range is fixed and is not stored either.

On parsing a WOTS+C key file, `validateSeed` derives stage 0 and compares the
entire public record. For XMSS, it checks the cheap derivations immediately:
account tag, tree public seed, Ed25519 key and Falcon key. It compares the root
when tree 0 is already cached. A wrong root is caught before a spend can be
signed because the derived program would not match the on-chain authorizer.

The public tree cache and per-account stage address table are reconstructible
caches, never signing authority. Backups carry the seed and public record;
restore needs no cached material. See [ARCH_STORE.md](ARCH_STORE.md#stage-address-tables).
Mnemonic export and mnemonic import are refused; recovery material remains in
the signer and its managed backups.

## 8. Signing choreography (`rotating1`)

All variants use only `POST /sign/rotating/prepare` and
`POST /sign/rotating/sign`. `/plan`, `/sign`, `/sign/bounded-admin` and
`/sign/component` refuse them with `rotating_signing_required`. The complete
wire contract lives in [ARCH_SIGNING.md](ARCH_SIGNING.md#rotating-accounts-rotating1).

1. **Prepare.** The client sends one unsigned, ungrouped spend from the account,
   with no `rekey_to`, no close-out, the account's genesis hash and a validity
   window at most 100 rounds. The signer reads the live authorizer from its
   own node, finds stage `n` and confirms it by derivation, sets `rekey_to` to
   stage `n + 1`, adds the profile's resource dummies, sets fees and group ID
   with the ordinary group builder, and returns the exact unsigned group. The
   spend must be canonically encoded. It stores nothing and needs no approval.
2. **Sign.** The group's `rekey_to` fixes `n`. The signer re-derives stage
   `n + 1`, checks the target and canonical group by byte equality, and runs
   ordinary policy gates and operator approval. Under the account lock it
   re-reads the chain and refuses unless stage `n` is still the authorizer
   (`rotating_stage_changed`), `first_valid` is at most 2 rounds ahead of the
   current round, and at least 10 rounds remain before `last_valid`. It proves
   the successor opens (`CheckStageOpens`), signs, verifies, writes a
   `ROTATING_RELEASE` audit entry (account, TxID, stage, `last_valid`, tree and
   leaf index), records the release in memory and responds. It refuses the
   release if the signer locked since approval, the request was cancelled or
   the key was removed.
3. **Open test.** `CheckStageOpens` test-signs the target stage locally before
   any spend signature is released. The leaf variants sign the SHA-256 hash of
   their derivation label followed by ` stage open test`: a fixed label, not a
   TxID, so the test signature authorizes nothing. They test Ed25519 and Falcon
   and check the embedded root and public seed, and XMSS also its leaf range. They
   never sign with a target-stage leaf.

Clients route on `signing_flow`, verify the prepared group preserves the
intended spend except for the rotation, fee, group ID and canonical dummies,
simulate that group, then sign and submit the exact bytes. The signer retains
no prepare session; policy evaluates the spend presented to sign.

### 8.1 One-time key and leaf selection

The signer chooses a leaf under the account lock from release memory:

- An already released transaction keeps its leaf, reproducing its hash-based
  signature on an identical retry.
- Otherwise the first byte of `TxID` picks a position within the stage's range,
  then the first unused leaf upward, wrapping, is selected, so two signers
  sharing a seed and no memory collide one time in 64 rather than always, for
  TxIDs nobody chose.
- If all 64 leaves have been used, the pick is reused and reported.

Release memory chooses the leaf; it does not refuse further releases, with one
exception that isn't about leaves: while the memory is being restored, a sign waits,
and if a reset arrives after that wait, the sign is refused rather than choosing from
an empty memory. The leaf is chosen from a record read together with its restore
state, so a reset can't fall between them. An audit write failure is logged and does
not withhold the signature. The `rotating_leaf_release.tla` model covers any family
with several leaves per stage; see
[FORMAL_TLA_ROTATING_LEAF_RELEASE_MODEL.md](FORMAL_TLA_ROTATING_LEAF_RELEASE_MODEL.md).

### 8.2 Release memory and alerts

The signer keeps the newest release per account and that stage's release
history in process memory, rebuilt at unlock from `ROTATING_RELEASE` audit
entries. It records the stage, TxID, `last_valid` and one-time leaf history
(tree and index; a WOTS+C tree is always 0). Signing waits for audit
restoration, bounded by the request context.

- A release that expires while its stage remains the authorizer raises a
  warning: it cannot confirm and the exposed stage still controls the account.
- Releasing a second distinct transaction on the same leaf marks the stage
  reused and warns until the account moves past it. Multiple releases on distinct leaves show an attempt
  count without a reuse warning.

### 8.3 Stage table worker and recovery

While unlocked, the worker checks each rotating account through the signer's
own node after unlock and about every 30 seconds. It extends the stage table
to `rotating.stage_horizon` past the live stage, prebuilds XMSS trees when
needed and publishes status.

An authorizer is classified as stage 0, a table stage, another credential the
signer holds (`held_key`), or `unknown`. Only an unknown authorizer triggers a
bounded recovery search (`rotating.recovery_max_stages`, default 1,024, and
`rotating.recovery_timeout`). `POST /admin/rotating/recover` lets an operator
grant a separate search budget. A stage is accepted only when its derived
address equals the authorizer read from the chain.

## 9. Security properties and claims

- **All three signatures required.** The stage accepts a transaction only when
  its Falcon-1024, Ed25519 and hash-based signatures all verify over the same
  TxID. A reduction showing that forging the exact WOTS+C construction
  necessarily breaks SHA-256 has not been established. Security claims assume
  the seed remains secret, each hash-based scheme's usage limits are respected,
  and the verifier and surrounding protocol work correctly.
- **Bounded exposure.** A released stage controls the account until a rotation
  confirms. Successor WOTS+C stages embed a new tree; successor XMSS stages embed
  a disjoint leaf range and, at tree boundaries, a new root.
- **Leaf reuse.** A leaf must sign only one message. A stage can use up to 64
  distinct leaves before exhausting its allocation, but rollback, lost audit
  history or independent signers sharing a seed can cause earlier reuse. This
  is capacity, not a guarantee. A repeated leaf forfeits its one-time security
  claim; Falcon-1024 and Ed25519 remain required.
- **XMSS checksum cap.** The cap does not weaken the one-time signature. A
  forger must dominate the released digits on all 67 chains; dominating the 64
  message chains forces the forger's checksum to be at most the released one,
  dominating the three checksum chains forces it to be at least that, so every
  digit is equal. The argument uses only the monotone checksum encoding, not
  the distribution of the released digest. (The same grinding in a stronger
  form is WOTS+C of the SPHINCS+C proposal; the key type does not claim that
  paper's proof covers this construction.) A security proof for the bounded
  randomizer procedure beyond this argument remains an open item.
- **Network binding.** Every derivation includes the genesis hash.

The XMSS variant makes no claim to conformant RFC 8391 or SP 800-208 stateful
signing. The WOTS+C variant isn't a standard; see
section 12. No variant provides on-chain spending limits or an
external-admin recovery path. Policy belongs to the signer; recovery depends
on the backed-up credential.

### 9.1 Failed transactions and leaf reuse

For the leaf variants, a failed transaction doesn't cause reuse by itself. A retry
with a new TxID takes the next unused leaf, so reuse needs a second problem on top of
the failure.

| Failure | Signature released | Leaf used | Reuse risk |
|---|---|---|---|
| Simulation fails | No, caught before signing | No | None |
| Signer refuses (stage moved, window aged) | No | No | None |
| Node rejects the submit | Yes | Yes | None: the retry takes the next leaf |
| Transaction expires without landing | Yes | Yes | None: the repair takes the next leaf |
| Same bytes are resubmitted | Yes | Same leaf | None: the signature is identical |
| Response is lost after signing | Assume yes | Yes | None: the leaf is recorded before the signature leaves |

The signer holds a per-account lock while signing, so concurrent requests can't take
the same leaf.

Each stage allows 64 different signed transactions, which is the first attempt plus
63 retries. The 65th reuses a leaf and is reported. It isn't refused, and a rotation
gives the account 64 fresh leaves. The client's automatic retry covers only refusals
before signing, so it doesn't use leaves.

Reuse needs one of these:

- More than 64 signed transactions on one stage.
- History missing when the retry signs, because:
  - a backup was restored;
  - two signers share a seed;
  - the audit log rotated past the stage's releases;
  - an audit write failed and the signer then restarted; or
  - the audit restore failed for an ordinary reason, since the signer then goes
    ahead rather than refusing. A restore interrupted by a lock, cancellation,
    recovery or refused key use keeps the account held instead.

With history missing, the leaf comes from the TxID alone, and a signer that has lost
that history can't see the reuse, so nothing reports it:

| Different transactions on one stage | Chance two share a leaf |
|---|---|
| 2 | 1.6% |
| 3 | 4.6% |
| 5 | 15% |

These odds assume nobody chose the TxIDs. Whoever controls a transaction's contents can
grind its note to aim it at a leaf in about 64 tries, so with history missing, 1 in 64
is not a bound against an adversary. This doesn't get past an intact history, which
gives every transaction an unused leaf whatever it picks.

A failed transaction also leaves the stage exposed. Its keys are revealed and keep
control of the account until a rotation lands, with no time limit. The hash leg stays
intact while each leaf has signed once, but the fix is a prompt rotate-only spend,
which the signer already warns about.

## 10. Policy and transaction authority

| Property | All variants |
|---|---|
| Admitted transaction types | any, subject to the stage guards |
| Required | non-zero `RekeyTo` different from sender; zero `CloseRemainderTo`; validity window at most 100 rounds |
| Signer-set rotation | always to this account's next stage |
| Group shape | one spend plus the scheme's canonical resource dummies |
| Foreign rekey policy | the next stage counts as the signer's own address |
| Approval | ordinary policy gates; description names signing and target stages |

The protocol rekey itself produces no warning for `always_review_warnings`;
other transaction warnings still apply. A signer invariant refuses rekeying a
different account to a held rotating account. See
[ARCH_POLICY.md](ARCH_POLICY.md#rotating-account-interaction) and
[KEYTYPE_CAPABILITIES.md](KEYTYPE_CAPABILITIES.md).

### 10.1 Group boundary

A rotating spend is the only transaction from its account in a group, and
the only other members are the scheme's resource dummies. This subsection
records why, and what would change it.

**Inherent restrictions.** No group rule changes these. The account's
address is stage 0's program, so nothing can be rekeyed to it and it cannot
act as a cosigner or witness. Every spend carries a rekey, so a contract that
asserts a zero `RekeyTo` on incoming calls rejects every call from the
account. The validity window is at most 100 rounds. A second transaction from
the account in the same group would have to be authorized by stage `n + 1`
and itself rekey to `n + 2`, because the ledger checks each transaction's
authorizer against the group's in-progress state. Several own transactions
per group is therefore a multi-stage release protocol, not a group rule.

**Chosen restriction.** The stage program does not read the group, and the
signature binds the group ID through the TxID, so the chain would accept a
rotating spend grouped with other senders' transactions. The signer refuses
it. With only dummies around the spend, a released signature can fail to
land only through the window expiring or the operator's own concurrent spend
from the same stage. With another sender in the group, that sender decides
whether the rotation lands: it can withhold its signature, or invalidate its
own transaction inside the window after the stage signature is public. The
remedy is a second spend from the same stage, which takes another of its
leaves (section 9). The design tolerates that as a
rare, self-inflicted case with alerts; it does not let a counterparty
trigger it on demand.

**Positioning.** Rotating accounts are designed for single-transaction use:
payments, asset operations, key registration, and application calls that
accept a rekeying sender. Workflows that put more than one user transaction
in an atomic group, whether a second one from the same account or one from
another party, run from an ordinary account instead. The resource dummies
around a spend are signer-manufactured and are not user transactions.
"Single-transaction" describes group composition, not frequency: the account
may act any number of times in sequence, each action one transaction and one
rotation; what is excluded is one atomic outcome needing two user
transactions.

**Deferred, in order of cost.**

1. *Group grammar.* Rotating prepare and sign could accept the ordinary
   sign, passthrough and foreign slots, with the rule that exactly one slot
   is a rotating spend, dummies counted net of the other members' pooled
   budget, and the compare step preserving other slots verbatim. Policy,
   approval and resource planning already handle mixed groups. This admits
   one own transaction plus other senders' transactions. Passthrough-only
   members and signer-side simulation before release bound the race above
   to the submission window; they do not remove it. The narrower step of
   admitting only the user's own ordinary transactions has a complete,
   deferred design in
   [PROPOSAL_ROTATING_INTEGRATION.md](PROPOSAL_ROTATING_INTEGRATION.md).
2. *Multi-stage release.* Several rotating slots in one group, each signed
   by the next stage in the chain. This needs its own design for budget (a
   WOTS+C spend costs 15,721 and an XMSS spend up to 95,857 of a pool
   that grows by 20,000 per member up to 16 members), release memory, audit
   and one-time key accounting.

Reopen this when a product requirement needs the account itself in a
multi-party or multi-transaction group. Neither step touches the stage
program, so the templates stay unpinned on group size at no cost.

## 11. SLH-DSA variant

`aplane.rotating-triple-slhdsa.v1` replaces the one-time leaves of the other
variants with a **stateless few-time** key per stage: an
SLH-DSA key under the SLH-DSA-SHA2-128s construction of FIPS 205, with the
hypertree rescaled to two layers. Everything the earlier sections say about
the account model (§3), the stage program guards (§3.1), the address
derivation (§3.2), the signing choreography (§8) and the policy boundary
(§10) applies unchanged. This section covers what differs: why a stateless
scheme, the parameter set and why it is not the standard one, the signing
and argument layout, the resource profile, the per-stage signing bound that
replaces the one-time rule, and the resulting claims.

### 11.1 Why a stateless scheme

The XMSS and WOTS+C variants rest on a one-time rule: a leaf that signs
two different messages forfeits its hash-based protection for the rest of
the stage. Holding that rule costs machinery. The XMSS variant keeps a leaf
history in release memory, restores it from the audit log at unlock, waits
for that restore before signing, chooses leaves from it, reports reuse, and
caches about 4 MiB of tree nodes per 1,024 stages. Two XMSS signers that
share a seed without sharing memory collide on a leaf with probability 1 in
64 per stage; a restore without the audit log loses the history.

SLH-DSA has no leaf to choose. Each signature picks a hypertree leaf
pseudo-randomly from the message, and the FORS layer tolerates a leaf being
hit more than once. So a stage key can sign, be retried, be restored from an
old backup or be run from several copies without any coordination, and
exceeding the design's usage assumptions costs security margin gradually
rather than at a threshold. The price is a larger signature and a slower
verifier than XMSS. The variant exists for operators who value the absence
of state over one group slot.

### 11.2 Parameter set

| Parameter | SLH-DSA variant |
|---|---|
| Construction | SLH-DSA-SHA2-128s of FIPS 205 (`internal/crypto/slhdsa`), hypertree rescaled |
| Hash and security parameter | SHA-256 throughout, n = 16 |
| Hypertree | h = 22 in d = 2 layers of height h' = 11 (standard set: h = 63, d = 7, h' = 9) |
| FORS | k = 14 trees of height a = 12, as the standard set |
| WOTS+ | w = 16, 35 chains (32 message digits + 3 checksum digits), as the standard set |
| Message digest | 25 bytes: 21 for FORS, 2 for the tree index, 2 for the leaf index (standard set: 30) |
| Signing variant | pure interface, empty context, deterministic `opt_rand = PK.seed` |
| Validity window cap | 100 rounds, as the other variants |
| TEAL version | 13 |
| Stage program bytes, unsalted / salted | 2,834 / 2,837 |
| Stage 0 public record bytes | 1,857 |
| SLH-DSA signature bytes | 4,400 (standard set: 7,856) |
| Ed25519, Falcon-1024 signature bytes | 64; at most 1,423 |
| Maximum total argument bytes | 5,887 |
| Maximum opcode cost | 68,645 |
| Group size | 6: one spend + five resource dummies |
| Go value | `slhdsa.Rescaled128`; `slhdsa.SHA2128s` is the standard set |

**Why the hypertree was rescaled.** Argument bytes, not opcode cost, set a
rotating group's size: each group member contributes 1,000 bytes of pooled
LogicSig argument allowance, and the signature travels as LogicSig arguments.
Under the standard set the three signatures total 9,343 bytes, which needs
ten transactions however cheap the verifier is. The standard set's 63-level
hypertree exists so that one key can sign 2^64 messages while FORS leaves
are rarely reused. A rotating stage key signs a handful of messages (§11.5),
so five of the seven layers paid 3,520 bytes per spend for capacity no stage
uses. Shortening the hypertree to two layers keeps n, w, FORS and every hash
function of the standard set and changes only the number of layers and the
digest split; the signature drops to 4,400 bytes and the group to six
transactions, which is also the floor for any FORS of the standard size.

**What it is not.** FIPS 205 approves only its listed parameter sets. The
rescaled set is the standard construction with a private hypertree shape;
it is not SLH-DSA-SHA2-128s and the key type makes no FIPS 205 conformance
claim. The primitive is parametric so that the standard shape runs through
the same code under the NIST ACVP vectors, which is the evidence that the
construction is implemented correctly; the rescaled shape is pinned by
golden vectors of its own. This places the variant in the same category as
the XMSS variant (§5.2): a standard construction used in a non-conformant
way, with its own written argument.

**Build-time selection.** The height is a constant,
`internal/rotatingkey.RotatingSlhdsaHeight`, with frozen artifacts for both
22 and 63: a verifier source, a template assembled from it, an argument
layout, a measured cost model and golden stage identities each, plus the
matching resource literals in `internal/rotatingkey`. Changing the
constant and rebuilding gives the standard SLH-DSA-SHA2-128s shape at ten
transactions, with every stage address changed, since the shape is
embedded in the stage program. It exists so the standard set stays
reachable for review and measurement; it is not an operator setting.
Released builds use height 22, fixed for the key type's lifetime, and a
height 63 build derives different accounts from the same seed.

**Alternatives considered.**

- *Carry the signature in a companion application call's arguments.* That
  removes the byte floor but leaves the worst-case opcode floor of the
  standard set at ten transactions, so it only pays together with
  per-signature group sizing, and it needs a per-network carrier
  application pinned in the stage template, a custom SLH-DSA signed message
  because the signature can no longer bind the group ID it is part of, and
  a new key type. Shelved.
- *Two layers of height 10 (h = 20).* Same group, 32 fewer signature
  bytes, half the signing and derivation cost, and the bound of §11.5
  crossing 128 bits at about 2^22 messages per stage instead of 2^24.
  Height 11 was chosen so that the margin rests on the tree rather than on
  the operating assumption.
- *A smaller FORS.* Reaching five transactions needs about 2,000 fewer
  signature bytes, which only FORS can give, at the direct expense of the
  128-bit single-use margin. Rejected.

### 11.3 Derivation and stage record

Derivation uses the shared HKDF scheme of §4 under the label
`APLANE_ROTATING_TRIPLE_SLHDSA_V1`, with per-stage tags 1 (Falcon-1024
seed), 2 (Ed25519 seed), 3 (`SK.seed`), 4 (`SK.prf`) and 5 (`PK.seed`),
each expansion including the genesis hash. Stage `n`'s SLH-DSA key is
`KeyGenFromSeeds(SK.seed_n, SK.prf_n, PK.seed_n)` under the rescaled set;
its root is the top of a 2,048-leaf tree, so derivation costs about four
times the standard set's. The stage program embeds, in this order, `PK.seed` (16),
`PK.root` (16), the Falcon-1024 public key (1,793) and the Ed25519 public
key (32), and the stage 0 public record is the same 1,857 bytes. Program
bytes are derived, never stored, as for the other variants.

### 11.4 Signing and arguments

All three components sign the raw 32-byte transaction ID (§5.1). SLH-DSA
signs the pure-interface message `M' = 0x00 || 0x00 || TxID` with
`opt_rand = PK.seed`, so the same stage and transaction always reproduce the
same signature. The signature is `R (16) || FORS (2,912) || layer 0 (736)
|| layer 1 (736)`, and it is split for transport so that every argument
stays under the AVM's 4,096-byte value limit:

| Argument | Content | Bytes |
|---|---|---:|
| `arg 0` | `R` and the FORS signature | 2,928 |
| `arg 1` | both hypertree layers | 1,472 |
| `arg 2` | Ed25519 signature | 64 |
| `arg 3` | Falcon-1024 signature, compressed | at most 1,423 |

The verifier recomputes `H_msg` as one SHA-256 and one MGF1 block, splits
the 25-byte digest into the FORS message, an 11-bit tree index and an 11-bit
leaf index, recovers the 14 FORS roots along their authentication paths,
compresses them, and then walks the two WOTS+ layers: each chain is
unrolled, a `switch` on the digit enters the remaining hash steps, the 35
chain ends are compressed, and an 11-level authentication path yields the
layer's root, which is the next layer's message. The final root must equal
the embedded `PK.root`. There is no randomizer search, leaf range, checksum
cap or signature grinding; every valid signature under the key is accepted.

`StageOps.SignStage` re-parses the derived program and verifies all three
signatures locally before releasing them, as §5.5 describes; the leaf index
the flow passes is ignored.

### 11.5 Per-stage signing bound

The one-time rule of §9 does not apply. In its place the variant assumes a
bound on how many **distinct** messages one stage key signs. FORS security
degrades gradually as leaves are reused; the standard set places up to 2^64
signatures on 2^63 leaves, and the rescaled set with 2^22 leaves is in that
same regime at about **2^22 distinct messages per stage key**. Repeating a
message reproduces the same signature and the same leaf and reveals nothing
new, so retries of one transaction do not count.

Honest use is far inside the bound: the open-test message of §8, which is
never released, and the spends released while the stage is live, normally
one and occasionally a few when a window ages or a client rebuilds the
transaction. The signer does not count signatures per stage and the
protocol does not bound them: a stage stays live until a spend lands, the
signer keeps no limit on releases per stage by design, and copies sharing a
seed sign independently. The bound is a margin statement, and this section
prices it.

**The bound.** It is the few-time analysis of the SPHINCS+ framework
(Bernstein et al., "The SPHINCS+ signature framework", 2019, section 9),
which FIPS 205 inherits. A forger chooses a message and randomizer, and
their digest lands on one of the 2^h leaves pseudo-randomly. With q
distinct messages signed under the stage key, the number γ already signed
on that leaf is binomial(q, 2^-h). The forgery succeeds when the digest's
k FORS indices all fall on values those γ signatures revealed, which
happens with probability (1 - (1 - 2^-a)^γ)^k. Summing over γ gives the
success probability of one digest query, and its reciprocal is the work
this term demands, in hash queries. For a = 12, k = 14 and h = 22:

| Distinct messages per stage key | FORS few-time (ITSR) term, bits |
|---:|---:|
| 3 (honest use) | 188 |
| 100 | 183 |
| 1,000 | 178 |
| 10,000 | 172 |
| 65,536 (2^16) | 165 |
| 2^18 | 159 |
| 2^20 | 151 |
| 2^22 | 140 |
| 2^23 | 134 |
| 2^24 | 126 |
| 2^26 | 106 |

This is one term of the SPHINCS+ bound, not the signature's security. The
bound also carries generic hash terms, for second-preimage, PRF and
multi-target resistance, that scale with n = 16: about 128 bits
classically and the category 1 quantum figure, identical for the rescaled
and the standard set since the hash functions are the same. The hash leg's
security is the smaller of the few-time term and those generic terms, so
it is category 1 for either set while the few-time term stays above them;
the table shows how many distinct messages a stage may sign before the
few-time term becomes the binding one. Under the same bound
SLH-DSA-SHA2-128s (h = 63) has a few-time term of 156 bits at 2^60
messages and 134 bits at its design limit of 2^64. The rescaled set's term
stays above the standard set's design-limit figure to about 2^23 messages
per stage and above the 128-bit generic terms to about 2^24; beyond that
the leg falls below category 1. This prices the hash leg alone; the hybrid
still requires Falcon-1024 and Ed25519 on the same transaction, and the
stage is retired when a spend lands.

**The operating assumption** is the evaluation record's: at most 2^16
distinct messages per stage key across copies and retries. At that count
the few-time term is 165 bits, 37 above the generic terms and 31 above the
standard set's term at its own limit, so the leg's security is the
category 1 figure. That is about nine hours of continuous approved,
unsubmitted signing from one host at two releases per second. The signer's
alerts do not surface that condition: release memory (§8.2) keeps only a
stage's latest release for this variant, so a single expired release warns
but a stream of fresh releases reads as "in flight" indefinitely. A
per-stage count of distinct releases, reported and never enforced, was
considered and not added: reaching the budget takes hours of continuous
approved requests, the assumption holds for the intended deployments by
orders of magnitude, and the hash leg is one of three a forger must break.
The record states what else falls outside the assumption and the two
remedies: a per-stage release rate
limit, which delays rather than refuses and so cannot strand an account, or
a taller tree, each level of which doubles every message count in the
table at twice the signing and derivation cost.

No release cap, counter or used-leaf tracking is added: a cap could strand
an account whose every released spend expired, and tracking leaves to
redraw the randomizer would reintroduce the state this variant exists to
avoid. Independent verification of the bound and of the assumption for the
intended deployments is the review gate (§15).

Release memory (§8.2) keeps only the latest release for this variant:
`StatelessHash` records carry no leaf history, restore nothing from the
audit log beyond the latest release, and never mark reuse. Expired and
in-flight release alerts work as for the other variants.

### 11.6 Resource profile and cost

| Property | SLH-DSA variant |
|---|---|
| Verifier cost | `26,825 + 41 * steps`, salted or not; the salt tail follows `return` |
| Steps per layer | `c + 45 - digitSum16(c)` for checksum `c` in 0..480, at most 510 |
| Maximum chain steps | 1,020 |
| Worst accepting run | 68,645 |
| Typical run | about 48,700 at the mean of 534 steps; LocalNet traces of 450 and 480 steps matched the model exactly |
| Maximum argument bytes | 5,887 |
| Group pool | 120,000 cost / 6,000 argument bytes |
| Resource dummies | 5 |
| Fee at minimum | 6,000 microAlgos, no program surcharge |

Opcode cost fits four transactions; the argument bytes decide the group.
The 41 units per chain step are 6 unit-cost instructions and one SHA-256.

### 11.7 Claims

- **All three signatures required.** As §9, with the hash-based leg a
  few-time rather than one-time key: a forgery needs Falcon-1024, Ed25519
  and SHA-256 broken at once while the stage key has signed well under the
  bound of §11.5.
- **Graceful degradation.** Signing past the bound costs FORS margin per
  additional leaf reuse; nothing fails at a threshold, and the stage still
  requires Falcon-1024 and Ed25519 until rotation confirms.
- **No usage state.** Correctness of signing does not depend on release
  memory, the audit log, backups or replica coordination.
- **Not FIPS 205.** The parameter set is not a listed set; the ACVP
  vectors validate the construction on the standard shape only. Seed
  generation is the shared HKDF derivation, not the standard's key
  generation procedure, as for every rotating variant.
- **Network binding.** Every derivation includes the genesis hash.

### 11.8 Comparison

| Item | XMSS | WOTS+C | SLH-DSA |
|---|---|---|---|
| Hash-based key per stage | 64 one-time leaves of a shared tree | its own tree of 64 one-time leaves | one few-time key |
| Rule on the hash-based key | each leaf signs one message | each leaf signs one message | at most about 2^22 distinct messages |
| State the rule needs | leaf history, audit restore, tree cache | leaf history, audit restore | none |
| Loss of state | possible undetected leaf reuse | same | none |
| Group size | 5 | 3 | 6 |
| Hash-based signature bytes | 2,692 | 628 | 4,400 |
| Worst opcode cost | 95,857 | 15,721 | 68,645 |
| Signing, this host | tree cache amortized | about 9 ms | about 0.2 s |
| Stage derivation, this host | tree cache amortized | about 43 ms | about 100 ms |
| Standing | RFC 8391 format and set, non-conformant signer | Published scheme, private instantiation | FIPS 205 construction, private parameter set |
| Status | released v1 | not frozen | released v1 |

## 12. WOTS+C variant

`aplane.rotating-triple-wotsc.v1` uses a Merkle tree of 64 WOTS+C one-time keys,
built per stage. Everything the earlier sections say about the account model (§3),
the stage program guards (§3.1), the address derivation (§3.2), the signing
choreography (§8), failed transactions (§9.1) and the policy boundary (§10) applies
unchanged. This section covers what differs: why WOTS+C, the parameter set, the
construction, the signing and argument layout, the stage verifier, the resource
profile, and the resulting claims.

### 12.1 Why WOTS+C

The variant is an alternative to XMSS, not a replacement for SLH-DSA, which exists
so a stage key needs no state: it can be retried, restored from an old backup or run
from several copies without coordination. WOTS+C keeps the one-time rule and handles
it the way XMSS does. What it offers is size and cost (§11.8): a fixed digit sum
replaces the checksum chains, and each stage has its own small tree, so there's no
public tree cache.

| Decision | Why |
|---|---|
| A separate key type | v1 stage programs are frozen, and SLH-DSA's value is having no state |
| No leaf counter | After an old backup, or with a second signer, a counter repeats the same leaf every time. The TxID pick collides 1 time in 64 for TxIDs nobody chose (§9.1) |
| Reuse a leaf rather than refuse | Every stage requires this signature and there's no other recovery path, so refusing freezes the funds |
| Keys derived per stage | The signer stores only the seed, so random values couldn't be rebuilt on restore |
| `n`, `w`, `S` and `h` fixed | n=24 needs 48 chains and S=360, and FIPS 205 moves H and T to SHA-512 at that level. The AVM has no plain SHA-512 opcode |
| `S` is 240 | It's the most likely sum, so grinding is shortest. Argument bytes set the group size, so a higher S saves nothing that matters |
| Grinding limit of 8,192 | Keeps signing bounded, and failure is negligible (§12.5) |

### 12.2 Parameter set

| Name | Value | Notes |
|---|---|---|
| n | 16 | Hash output bytes |
| w | 16 | 4 bits per digit |
| len | 32 | Message chains. No checksum chains |
| S | 240 | Required digit sum |
| h | 6 | 64 leaves per stage |
| Grinding limit | 8,192 | Counters tried per signature |

Each stage is its own tree, so `StagesPerTree` is 0 and `Profile.LeafRange` gives
every stage `[0, 64)`. `TreeOf` stays 0, so every stage uses leaf numbers 0 to 63
under tree 0. That's safe because `chooseLeaf` ignores a prior record unless
`prior.Stage == stage`, and each stage has its own keys. Setting `StagesPerTree` to 1
would be wrong: `treeFrontier` would treat the family as shared-tree and limit stage
lookahead to about one stage.

### 12.3 Derivation and stage record

Derivation follows §4 under the label `APLANE_ROTATING_TRIPLE_WOTSC_V1`, with
stage-level info `tag || G || u64be(n)`, as for SLH-DSA. The tags are in §4's table,
and derivation is random access.

The stage 0 public record is `PK.seed` (16), `PK.root` (16), Falcon public key
(1,793) and Ed25519 public key (32), 1,857 bytes in total. Tree generation is cheap
enough that `validateSeed` compares the entire record.

`CheckStageOpens` follows XMSS: it tests Ed25519 and Falcon, and checks the embedded
`PK.seed` and `PK.root` against a rebuilt tree. It never signs with a target-stage
leaf, because a leaf is one-time and that stage hasn't spent yet.

### 12.4 Primitives and tree

The primitives follow the FIPS 205 SHA2 style.

```text
seedblock    = PK.seed || 0^48              # one full SHA-256 block
Th(ADRS, M)  = SHA-256(seedblock || ADRSc || M)[0:16]
```

`ADRSc` is 22 bytes, with integers big-endian:

| Bytes | Field | Value |
|---|---|---|
| 0 | layer | 0 |
| 1-8 | tree | 0 |
| 9 | type | 0 WOTS_HASH, 1 WOTS_PK, 2 TREE, 5 WOTS_PRF |
| 10-13 | keypair | Leaf index. 0 for tree nodes |
| 14-17 | chain or height | |
| 18-21 | hash or index | |

For leaf `i` and chain `j`:

```text
sk[i][j] = Th(ADRS{type=5, keypair=i, chain=j, hash=0}, SK.seed)

chain(x, start, steps, i, j):
    for k in start .. start+steps-1:
        x = Th(ADRS{type=0, keypair=i, chain=j, hash=k}, x)

leaf[i] = Th(ADRS{type=1, keypair=i},
             chain(sk[i][0], 0, 15, i, 0) || ... || chain(sk[i][31], 0, 15, i, 31))
```

A node at height `z+1` and index `t` is
`Th(ADRS{type=2, chain=z+1, hash=t}, left || right)`. The root at height 6 is
`PK.root`.

### 12.5 Signing and arguments

The signing flow chooses the leaf as in §8.1. Then:

```text
digest(R, i, TxID) = SHA-256(PK.seed || PK.root || R || u32be(i) || TxID)[0:16]
digits             = 32 nibbles of digest, high nibble first
```

For `ctr = 0, 1, ..., 8191`:

1. `R = SHA-256(SK.prf || u32be(i) || TxID || u32be(ctr))[0:16]`
2. Use the first `R` whose digits sum to exactly 240.

If no counter qualifies, the signer returns an error without generating a signature.
Each try succeeds with probability about 1/66, so that happens with probability about
2^-181. Search counters aren't leaf indices and don't consume leaves. The search is
deterministic, so the same stage, leaf and TxID reproduce the same signature.

A digest input can't equal a `Th` input, because their lengths differ: the digest
hashes 84 bytes and `Th` hashes at least 102.

```text
arg 0 = u32be(i) || R || sigma_0 .. sigma_31 || auth_0 .. auth_5
        4          16   32 * 16               6 * 16

sigma_j = chain(sk[i][j], 0, d_j, i, j)
auth_z  = sibling at height z on the path from leaf i
```

The signer rebuilds the stage tree to produce the path. That takes about 5 ms on one
core, so no tree cache is needed, and `RotatingTreeOps`, tree rollover and a leaf
range in the program aren't needed either.

### 12.6 Stage verifier

The guards are those of §3.1, then:

1. Assert `arg 0` is exactly 628 bytes and `i < 64`.
2. Compute the digest and its digits.
3. Assert the digits sum to exactly 240. This is mandatory: without it, a digest
   of all high digits forges trivially.
4. For each `j`, compute `chain(sigma_j, d_j, 15 - d_j, i, j)`, reusing the SLH-DSA
   verifier's `switch` fall-through.
5. Compress the 32 chain ends with type 1 to get the leaf.
6. Climb six levels. With `t = i` to start, for `z = 0 .. 5`:
   take `bit = t & 1`, set `t = t >> 1`, then
   `node = Th(ADRS{type=2, chain=z+1, hash=t}, bit ? auth_z || node : node || auth_z)`.
7. Assert `node == PK.root`.

The hash work is exactly 240 chain steps, 1 compression, 6 tree nodes and 1 digest:
248 SHA-256 calls for every accepted signature. Because the step count is fixed, the
cost model is one constant, not `base + step * steps`.

### 12.7 Resource profile and cost

| Property | Value |
|---|---|
| Maximum argument bytes | 2,115 |
| Group size | 3: one spend and two dummies |
| Fee at minimum | 3,000 microAlgos, no program surcharge |
| Group pool | 60,000 opcode units, 3,000 argument bytes |
| Opcode cost | 15,721: 9,840 for chain steps plus 5,881 for everything else |
| Stage program bytes | 2,483, or 2,486 salted |

Arguments decide the group size, because `lsigresource` sizes the group from argument
bytes and opcode cost. Program bytes don't affect it, but they do affect the fee: a
group's programs get 1,000 free bytes per member, and bytes above that carry a
surcharge. A three-member group has 3,000 free bytes and the two dummies use 12, so a
stage program up to 2,988 bytes pays no surcharge.

`Preparation` stays at its zero value: full stage derivation takes about 43 ms, most
of it Falcon-1024 key generation.

### 12.8 Claims

- **All three signatures required.** The stage accepts a transaction only when
  its Falcon-1024, Ed25519 and WOTS+C signatures all verify over the same TxID.
- **Hash output size.** The leg uses 16-byte outputs, compared with XMSS's 32 bytes.
  Output size alone doesn't establish a security level or equivalence to SLH-DSA.
  The expected attacks are a second preimage of the 128-bit digest or a preimage of
  a chain step, but no reduction shows these are the only ones.
- **Fixed sum.** With equal digit sums, one digit vector can only cover another if
  they're identical, so a forger gains nothing from raising digits. Three million
  attempts against a single signature found nothing.
- **Leaf reuse.** A leaf that signs two different messages loses its one-time
  claim. Falcon-1024 and Ed25519 remain required. A signer that holds the stage's
  history reports the reuse until the account moves past it (§9.1).
- **Network binding.** Every derivation includes the genesis hash.
- **Bounded exposure.** A released stage controls the account until a rotation
  confirms, as for every rotating type.

Not claimed:

- Conformance to any standard. WOTS+C isn't in FIPS 205, RFC 8391 or SP 800-208.
- That the SPHINCS+C paper's proof covers this exact construction. No proof has
  been written for it.
- Conformant stateful signing. Leaf management is best-effort, as for XMSS.

### 12.9 Cost of leaf reuse

Measured on the reference implementation. Costs are tries for a forgery on an
attacker-chosen TxID.

| Signatures on one leaf | Median cost | Cheapest of 60 sampled |
|---|---|---|
| 2 | 2^39 | 2^31 |
| 3 | 2^25 | 2^18 |
| 4 | 2^18 | 2^14 |
| 6 | 2^13 | 2^11 |

A forgery from three signatures was carried out and verified, using no secret key,
in 2 seconds on 4 cores. Two reuses are enough to treat the hash leg as lost.

### 12.10 Measurements

Measured on one development host and LocalNet:

| Check | Result |
|---|---|
| Signature size | 628 bytes |
| Verification | 247 `Th` calls plus the digest |
| Grinding | Mean 64 tries over 400 signatures, maximum 313 |
| Exact tries at S=240 | 66 |
| Tamper cases rejected | 44 of 44 |
| Stage tree generation (Go, with midstate) | 4.6 ms |
| Full stage derivation, with Falcon-1024 | 43 ms |
| Full three-part signature | 8.6 ms |
| Hash signature, Go | 40 microseconds |
| On-chain cost | 15,721 in all 60 runs: 6 leaves, salted and not, 5 fresh accounts |
| Go against Python | All 14 vectors identical |
| TEAL against Go | Agrees on all 64 leaves and every flipped byte; 8 of 8 mutated verifiers caught |
| On-chain rejections | 21 of 21 |

The grinding sample comes from one run, and a second 400 gave a mean of 67 and a
maximum of 450. The grinding limit is tested in Go, and the derivation in §12.3 is
what the on-chain runs use.

The Python oracle shares no code with the Go package, but came from the same design
and author, so it catches coding slips, not design mistakes. Falcon-1024 and Ed25519
are stubbed in the offline TEAL runs, and run for real in the on-chain ones.

## 13. Compatibility and versioning

- At its first release, each v1 key type except WOTS+C separately freezes its stage template, embedded constants,
  derivation label and tags, signing procedure, public record and resource
  profile. XMSS also freezes its checksum cap and leaf allocation. Any change
  to the TEAL changes every stage address. Changing these contracts mints a
  new key type version; it does not edit v1.
- WOTS+C isn't frozen, so a change can derive different accounts from the same seed.
- The three schemes have separate identifiers and derivation labels
  (`APLANE_ROTATING_TRIPLE_WOTSC_V1`, `APLANE_ROTATING_XMSS_V1` and
  `APLANE_ROTATING_TRIPLE_SLHDSA_V1`), so their addresses never collide by
  construction. This document groups them under a shared design name; it
  introduces no additional key type, scheme negotiation or conversion of
  existing accounts.
- The SLH-DSA variant is frozen by its first release, v0.45.0. Before that,
  its hypertree rescaling on 2026-10-27 changed its stage template, stage
  identities and resource profile under the same key type identifier, a
  pre-release freeze decision; the same change would now mint a new version.
- Pre-release development templates may derive different addresses and must
  be identified rather than reinterpreted as released v1 templates.
- The shared signing-flow identifier remains `rotating1`. Clients route on
  `signing_flow`, not key type strings.
- The installer floor for upgrades is v0.49.0.

## 14. Evidence (tests)

| Area | Where |
|---|---|
| SLH-DSA construction against the NIST ACVP vectors on the standard shape; rescaled golden vectors; digest split and leaf-index coverage; tampering and cross-shape rejection | `internal/crypto/slhdsa/slhdsa_test.go` |
| SLH-DSA stage build, parse, salt, offsets, argument literals pinned to the parameter set, and cost ceiling | `lsig/rotatingtripleslhdsa/stage/program_test.go`, `template_dump_test.go` |
| SLH-DSA derivation golden vectors, signing, verification and argument layout | `lsig/rotatingtripleslhdsa/signerops/keys_test.go`, `signerreg/register_test.go` |
| SLH-DSA TEAL verifier run offline in a test interpreter against `slhdsa.Verify` on both program shapes: valid signatures (eight messages on the rescaled shape, one on the full-height shape), a bit flipped at the start of every 16-byte node of the first signature on both shapes, other message, other key, wrong lengths, exchanged layers, and the full-width final root comparison | `lsig/rotatingtripleslhdsa/stage/verifier_equiv_test.go`, `lsig/rotatingfamily/avmsim` |
| SLH-DSA on-chain acceptance and rejection, cost model against node traces on both program shapes, six-transaction group | `test/integration/rotating_slhdsa_onchain_test.go` |
| SLH-DSA preparation ceilings, bounded discovery, post-sign chain recheck, restored releases without leaf history; lifecycle benchmark | `internal/signerapp/signing/rotating_slhdsa_test.go`, `rotating_slhdsa_bench_test.go` |
| XMSS stage build, parse, salt, offsets and cost | `lsig/rotatingtriplexmss/stage/program_test.go`, `template_dump_test.go` |
| WOTS+C stage build, parse, salt, offsets and cost | `lsig/rotatingtriplewotsc/stage/program_test.go`, `template_dump_test.go` |
| Algod assembler agreement for salted and unsalted stages, all three schemes | the three `stage` packages' tests (LocalNet) |
| Derivation, signing, verification and tampered fields; XMSS range violations and checksum above cap | `lsig/rotatingtriplexmss/signerops/keys_test.go`, `lsig/rotatingtriplewotsc/signerops/keys_test.go` |
| Codec, generator, seed validation and registration | `lsig/rotatingtriplexmss/signerreg/register_test.go`, `lsig/rotatingtriplewotsc/signerreg/contract_test.go` |
| XMSS vectors from an independent oracle (`tools/xmssoracle`), RFC reference vector, 32 bounded signatures (10 with searched randomizer) | `internal/crypto/xmss/` |
| XMSS checksum boundaries (511/525, 512/555) and exhaustive step counts | `internal/crypto/xmss/`, `lsig/rotatingtriplexmss/stage/` tests |
| WOTS+C vectors from a second implementation (`tools/wotscoracle`), signing, rejection and the grinding limit | `internal/crypto/wotsc/wotsc_test.go` |
| WOTS+C TEAL verifier run offline against the primitive: every leaf, every flipped byte, wrong digit sums and mutated verifiers | `lsig/rotatingtriplewotsc/stage/verifier_equiv_test.go`, `lsig/rotatingfamily/avmsim` |
| Shared HKDF derivation | `internal/crypto/rotatinghybrid/derive_test.go` |
| XMSS on-chain acceptance, cost model at the step ceiling, tree rollover, five-transaction group | `test/integration/rotating_xmss_onchain_test.go` |
| WOTS+C on-chain acceptance, constant cost, three-transaction group | `test/integration/rotating_wotsc_onchain_test.go` |
| Shared signing flow, release gates and recovery | `internal/signerapp/signing/rotating_*_test.go`, `test/integration/rotating_signer_test.go` |
| Every non-payment transaction type through apshell and the signer (asset opt-in, transfer and close-out; app opt-in, call and box reference; online and offline key registration), all three schemes; refusal by a contract that rejects rekeying calls, with nothing signed | `test/integration/rotating_txntypes_test.go` |

Full XMSS tree builds are skipped under the race detector (`internal/racetest`).

## 15. Open items

- WOTS+C needs a second implementation written from section 12 alone.
  `tools/wotscoracle` shares no code with the Go package but came from the same
  design, so it can't catch a design mistake, and WOTS+C has no published vectors.
- Independent review of the SLH-DSA rescaled parameter set and of the
  per-stage signing margin argument (§11.5) is a listed gate in
  [SLHDSA_EVALUATION.md](SLHDSA_EVALUATION.md).
- Per-key-type exit and external-admin paths remain design-only.
- Hinted stage scans and an in-flight release limit remain proposed.
- Grouping with other senders and multi-stage release are deferred by design
  (section 10.1).
- A security proof for XMSS's checksum-bounded randomizer selection beyond the
  monotone-checksum argument has not been written.
