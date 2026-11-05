# Key Type Specification: Rotating Triple WOTS+C

Status: implemented, unreleased, and not independently reviewed. Key type
`aplane.rotating-triple-wotsc.v1`, family `aplane.rotating-triple-wotsc`, signing
flow `rotating1`. It freezes at its first release, so the review in section 12 has
to finish first.

Authoritative sources:

- `lsig/rotatingtriplewotsc/`: stage template, derivation, signing, key file codec
  and registration
- `internal/crypto/wotsc/`: the hash-based primitive
- `internal/rotatingkey/rotatingkey.go`: identifiers, frozen sizes and profile

The shared design of rotating accounts is in
[KEYTYPE_ROTATING_TRIPLE_HYBRID.md](KEYTYPE_ROTATING_TRIPLE_HYBRID.md). This document
covers what differs.

## 1. Summary

Each stage requires Falcon-1024, Ed25519 and a hash-based signature, as every
rotating type does. The hash-based leg is a Merkle tree of 64 WOTS+C one-time
keys, built per stage.

This is an alternative to XMSS and WOTS, not a replacement for SLH-DSA.
SLH-DSA exists so a stage key needs no state: it can be retried, restored from
an old backup or run from several copies without coordination. This design
brings the one-time rule back, and handles it the way XMSS already does.

What it offers over the existing types is size and cost. The last column is
measured on LocalNet (section 11).

| | XMSS | WOTS | SLH-DSA | This |
|---|---|---|---|---|
| Hash signature bytes | 2,692 | 2,144 | 4,400 | 628 |
| Worst opcode cost | 95,857 | 59,772 | 68,645 | 15,721, constant |
| Maximum argument bytes | 4,179 | 3,631 | 5,887 | 2,115 |
| Group size | 5 | 4 | 6 | 3 |
| Attempts per stage without reuse | 64 | 1 | not applicable | 64 |
| Durable usage state | leaf history | reporting only | none | leaf history |
| Public tree cache | about 4 MiB | none | none | none |
| Hash size | n=32 | n=32 | n=16 | n=16 |

## 2. Design decisions

| Decision | Why |
|---|---|
| A separate key type | v1 stage programs are frozen, and SLH-DSA's value is having no state |
| No leaf counter | After an old backup, or with a second signer, a counter repeats the same leaf every time. The TxID pick collides 1 time in 64 for TxIDs nobody chose (section 9.1) |
| Reuse a leaf rather than refuse | Every stage requires this signature and there's no other recovery path, so refusing freezes the funds |
| Keys derived per stage | The signer stores only the seed, so random values couldn't be rebuilt on restore |
| `n`, `w`, `S` and `h` frozen | n=24 needs 48 chains and S=360, and FIPS 205 moves H and T to SHA-512 at that level. The AVM has no plain SHA-512 opcode |
| `S` is 240 | It's the most likely sum, so grinding is shortest. Argument bytes set the group size, so a higher S saves nothing that matters |
| Grinding limit of 8,192 | Keeps signing bounded, and failure is negligible (section 5.3) |

## 3. Parameters (frozen)

| Name | Value | Notes |
|---|---|---|
| n | 16 | Hash output bytes |
| w | 16 | 4 bits per digit |
| len | 32 | Message chains. No checksum chains |
| S | 240 | Required digit sum |
| h | 6 | 64 leaves per stage |
| Grinding limit | 8,192 | Counters tried per signature |
| Validity window cap | 100 rounds | Shared with the other types |
| TEAL version | 13 | Shared with the other types |

## 4. Keys

### 4.1 Derivation

The only stored private material is the 64-byte seed. Derivation uses
HKDF-SHA-512 through `internal/crypto/rotatinghybrid`, with the label
`APLANE_ROTATING_TRIPLE_WOTSC_V1`. Every expansion includes the genesis hash.
Stage-level info is `tag || G || u64be(n)`, as for SLH-DSA.

| Output | Tag | Bytes |
|---|---|---|
| Stage Falcon-1024 seed | `0x01` | 48 |
| Stage Ed25519 seed | `0x02` | 32 |
| `SK.seed` | `0x03` | 16 |
| `SK.prf` | `0x04` | 16 |
| `PK.seed` | `0x05` | 16 |

Derivation is random access, and secrets are zeroed after use.

### 4.2 Primitives

These follow the FIPS 205 SHA2 style.

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

### 4.3 Tree

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

## 5. Signing

### 5.1 Message

All three components sign the raw 32-byte TxID. The TxID covers the group ID, so
any change to the rounds, fee or group needs a new signature.

### 5.2 Leaf selection

The signing flow chooses the leaf with the existing `chooseLeaf`:

- A transaction the stage already released keeps its leaf, which reproduces the
  identical signature.
- Otherwise `TxID[0] mod 64` picks a position, and the first unused leaf upward,
  wrapping, is taken.
- If all 64 are used, the pick is reused and reported.

State chooses the leaf, never whether to sign, with one exception that isn't about
leaves: while the release memory is being restored, a sign waits, and if a reset arrives
after that wait, the sign is refused rather than choosing from an empty memory. The
leaf is chosen from a record read together with its restore state, so a reset can't
fall between them. An audit write failure is logged and doesn't withhold the signature. No leaf counter is stored. The audit entry for a
release is synced durably, as for every rotating type, and it's the only record.

### 5.3 Digest and grinding

```text
digest(R, i, TxID) = SHA-256(PK.seed || PK.root || R || u32be(i) || TxID)[0:16]
digits             = 32 nibbles of digest, high nibble first
```

For `ctr = 0, 1, ..., 8191`:

1. `R = SHA-256(SK.prf || u32be(i) || TxID || u32be(ctr))[0:16]`
2. Use the first `R` whose digits sum to exactly 240.

If no counter qualifies, return an error without generating a signature. Each try
succeeds with probability about 1/66, so that happens with probability about
2^-181. Search counters aren't leaf indices and don't consume leaves. The search
is deterministic, so the same stage, leaf and TxID reproduce the same signature.

A digest input can't equal a `Th` input, because their lengths differ: the digest
hashes 84 bytes and `Th` hashes at least 102.

### 5.4 Arguments

| Argument | Content | Bytes |
|---|---|---|
| `arg 0` | Hash-based signature | 628 |
| `arg 1` | Ed25519 signature | 64 |
| `arg 2` | Falcon-1024 signature, compressed | at most 1,423 |

```text
arg 0 = u32be(i) || R || sigma_0 .. sigma_31 || auth_0 .. auth_5
        4          16   32 * 16               6 * 16

sigma_j = chain(sk[i][j], 0, d_j, i, j)
auth_z  = sibling at height z on the path from leaf i
```

The signer rebuilds the stage tree to produce the path. That takes about 5 ms
on one core, so no tree cache is needed.

### 5.5 Signer-side verification

Before release, `StageOps.SignStage` re-parses the derived program and verifies
all three signatures locally, as the other types do. It rejects an index outside
0 to 63. A failed signature is zeroed and refused.

A signature is then released only if the signer hasn't locked since approval, the
request hasn't been cancelled and the key is still present, as for every rotating type.
The sign path is a key user, so a lock cancels it and waits for the seed to go. The seed
goes before the audit write, so a stalled disk can't hold up a lock, and the checks run
again after the last audit write. A release refused at that point stays on record, which
only makes its leaf look used. Nothing that blocks comes after that check in the signer,
but the response still has to be written, so a lock can arrive while it is on its way.

## 6. Stage program

Frozen TEAL v13 template. It embeds Ed25519 (32 bytes), Falcon-1024 (1,793),
`PK.seed` (16) and `PK.root` (16).

The guards match the other types:

1. `RekeyTo` is non-zero and is not the sender.
2. `CloseRemainderTo` is zero.
3. `LastValid - FirstValid <= 100`.
4. `arg 1` is a valid Ed25519 signature of `TxID`.
5. `arg 2` is a valid Falcon-1024 signature of `TxID`.
6. `arg 0` verifies as follows.

Hash-based verification:

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

The hash work is exactly 240 chain steps, 1 compression, 6 tree nodes and 1
digest: 248 SHA-256 calls for every accepted signature. Because the step count is
fixed, the cost model is one constant, not `base + step * steps`.

Address salting and `stage.Parse` follow section 3.2 of
`docs/KEYTYPE_ROTATING_TRIPLE_HYBRID.md`.

## 7. Integration

### 7.1 Leaf range

Each stage is its own tree, so `StagesPerTree` is 0 and `Profile.LeafRange` gives
every stage `[0, 64)`. `TreeOf` stays 0, so every stage uses leaf numbers 0 to 63
under tree 0. That's safe because `chooseLeaf` ignores a prior record unless
`prior.Stage == stage`, and each stage has its own keys.

Setting `StagesPerTree` to 1 would be wrong: `treeFrontier` would treat the family
as shared-tree and limit stage lookahead to about one stage.

### 7.2 Profile

```go
OneTimeStage:       true,
StatelessHash:      false,
ReusedStageRestsOn: "Falcon-1024 and Ed25519",
LeavesPerStage:     64,
StagesPerTree:      0,
```

`Preparation` stays at its zero value unless benchmarks show otherwise (section
11).

### 7.3 Reused unchanged

- `chooseLeaf`, release memory, audit restore and `AwaitRestored`
- `ROTATING_RELEASE` audit entries, with tree 0
- The stage table worker and lookahead
- `rotating1` prepare and sign, and client routing on `signing_flow`
- Reuse warnings and attempt counts
- `stagesign` for the classical keys

### 7.4 Not needed

`RotatingTreeOps`, a public tree cache, tree rollover and a leaf range in the
program.

### 7.5 Open test

`CheckStageOpens` follows XMSS: it tests Ed25519 and Falcon, and checks the
embedded `PK.seed` and `PK.root` against a rebuilt tree. It never signs with a
target-stage leaf.

### 7.6 Key file

Managed `.key` credential with the `rotating_lsig` codec. The stage 0 public
record is `PK.seed` (16), `PK.root` (16), Falcon public key (1,793), Ed25519 public
key (32), 1,857 bytes in total. Tree generation is cheap enough that
`validateSeed` can compare the entire record.

### 7.7 Code

| Area | Holds |
|---|---|
| `internal/crypto/wotsc` | Primitive: keygen, tree, sign at a chosen leaf, verify |
| `lsig/rotatingtriplewotsc/stage` | Frozen template, verifier source, strict parse, cost |
| `lsig/rotatingtriplewotsc/signerops` | Derivation, stage operations |
| `lsig/rotatingtriplewotsc/signerreg` | Key file record and registration |
| `lsig/rotatingfamily/avmsim` | Offline AVM interpreter used by the verifier tests |
| `tools/wotscoracle` | Second implementation that regenerates the vectors |

### 7.8 Formal model

`rotating_leaf_release.tla` models any family with several leaves per stage, and
this type is a new instance of it with no change to the guard. See
[FORMAL_TLA_ROTATING_LEAF_RELEASE_MODEL.md](FORMAL_TLA_ROTATING_LEAF_RELEASE_MODEL.md).

## 8. Resources

Each group member adds 20,000 opcode units and 1,000 bytes of pooled argument
allowance.

| Property | Value | Status |
|---|---|---|
| Maximum argument bytes | 2,115 | Exact |
| Group size | 3: one spend and two dummies | Measured |
| Fee at minimum | 3,000 microAlgos, no program surcharge | Measured: 2,498 program bytes in the group at most |
| Group pool | 60,000 opcode units, 3,000 argument bytes | Follows from group size |
| Chain step cost | 41 units, as measured for SLH-DSA | Reused figure |
| Opcode cost | 15,721 | Measured: 9,840 for chain steps plus 5,881 for everything else |
| Stage program bytes | 2,483, or 2,486 salted | Measured |

Arguments decide the group size, because `lsigresource` sizes the group from argument
bytes and opcode cost. Program bytes don't affect it, but they do affect the fee:
a group's programs get 1,000 free bytes per member, and bytes above that carry a
surcharge. A three-member group has 3,000 free bytes and the two dummies use 12, so a
stage program up to 2,988 bytes pays no surcharge. The salted program is 2,486 bytes.

## 9. Security claims

- **All three signatures required.** A forgery needs Falcon-1024, Ed25519 and
  SHA-256 broken at once, while no leaf has signed two different messages.
- **Category 1 hash leg.** With n=16, the leg matches the SLH-DSA type and is
  weaker than the n=32 XMSS and WOTS types. Forging needs a second preimage of the
  128-bit digest, or a preimage of a chain step.
- **Fixed sum.** With equal digit sums, one digit vector can only cover another if
  they're identical, so a forger gains nothing from raising digits. Three million
  attempts against a single signature found nothing.
- **Leaf reuse.** A leaf that signs two different messages loses its one-time
  claim. Falcon-1024 and Ed25519 remain required. A signer that holds the stage's
  history reports the reuse until the account moves past it. A signer that has lost
  that history can't see the reuse, so nothing reports it (section 9.1).
- **Network binding.** Every derivation includes the genesis hash.
- **Bounded exposure.** A released stage controls the account until a rotation
  confirms, as for every rotating type.

Not claimed:

- Conformance to any standard. WOTS+C isn't in FIPS 205, RFC 8391 or SP 800-208.
- That the SPHINCS+C paper's proof covers this exact construction. No proof has
  been written for it, so this needs independent review before release.
- Conformant stateful signing. Leaf management is best-effort, as for XMSS.

### 9.1 Failed transactions and leaf reuse

A failed transaction doesn't cause reuse by itself. A retry with a new TxID takes
the next unused leaf, so reuse needs a second problem on top of the failure.

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
  - an audit write failed and the signer then restarted; or
  - the audit restore failed, since the signer then goes ahead rather than refusing.

With history missing, the leaf comes from the TxID alone:

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

### 9.2 Cost of leaf reuse

Measured on the reference implementation. Costs are tries for a forgery on an
attacker-chosen TxID.

| Signatures on one leaf | Median cost | Cheapest of 60 sampled |
|---|---|---|
| 2 | 2^39 | 2^31 |
| 3 | 2^25 | 2^18 |
| 4 | 2^18 | 2^14 |
| 6 | 2^13 | 2^11 |

A forgery from three signatures was carried out and verified, using no secret
key, in 2 seconds on 4 cores. Two reuses are enough to treat the hash leg as lost.

## 10. Compatibility

- The template, constants, derivation label and tags, signing procedure, public
  record and resource profile are frozen on first release. Changing any of them
  mints a new version.
- The label keeps addresses apart from every other type.
- Existing accounts aren't converted.
- `rotating1` doesn't change.

## 11. Evidence and required tests

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
maximum of 450. The grinding limit is tested in Go, and the derivation in section 4.1
is what the on-chain runs use.

The Python oracle shares no code with the Go package, but came from the same design
and author, so it catches coding slips, not design mistakes. A second implementation
from this spec alone is still needed. Falcon-1024 and Ed25519 are stubbed in the
offline TEAL runs, and run for real in the on-chain ones.

Tests live in `internal/crypto/wotsc`, `lsig/rotatingtriplewotsc`,
`internal/signerapp/signing` and `test/integration/rotating_wotsc_onchain_test.go`.

## 12. Open items

- **Independent review.** No proof covers this construction, and nobody outside its
  authors has reviewed it. It has to happen before the first release, because the
  template and derivation freeze then.
- **A second implementation from this document alone.** `tools/wotscoracle` shares
  no code with the Go package but came from the same design, so it can't catch a
  design mistake. WOTS+C has no published vectors.
- **Whether to offer WOTS for new accounts** once this is released. WOTS is the type
  this most clearly improves on, though it has the larger hash size.
