# Key Type Specification: Rotating Triple Hybrid

Status: implemented as two separate key types,
`aplane.rotating-triple-xmss.v1` and `aplane.rotating-triple-wots.v1`; each
v1 is frozen by its first release (v0.44.0). This document specifies both for
implementers and reviewers: their shared design and the two hash-based
schemes. It restates, and does not replace, the authoritative sources:

- `lsig/rotatingtriplexmss/`: XMSS stage template, derivation, signing, tree
  cache, key file codec, generator and registration
- `lsig/rotatingtriplewots/`: WOTS stage template, derivation, signing, key file
  codec, generator and registration
- `internal/crypto/xmss/` and `internal/crypto/wots/`: hash-based primitives
- `internal/crypto/rotatinghybrid/`: shared seed derivation
- `internal/rotatingkey/rotatingkey.go`: key type identifiers, frozen sizes
  and resource profiles
- [ARCH_CRYPTO.md](ARCH_CRYPTO.md), [ARCH_SIGNING.md](ARCH_SIGNING.md#rotating-accounts-rotating1)
  and [ARCH_KEYTYPES.md](ARCH_KEYTYPES.md): cryptographic design, signing flow
  and key type contracts

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
| Hash-based signature | XMSS or WOTS, SHA-256 | one-time leaf or per-stage one-time key |

The hash-based scheme is selected by the key type when the account is created.
Each type has its own frozen stage template, derivation label and addresses;
the signing request does not select or switch the scheme.

| Item | XMSS | WOTS |
|---|---|---|
| Key type | `aplane.rotating-triple-xmss.v1` | `aplane.rotating-triple-wots.v1` |
| Family | `aplane.rotating-triple-xmss` | `aplane.rotating-triple-wots` |
| Hash-based key | one leaf of an XMSS tree | one WOTS key per stage |
| One-time keys available per stage | 64 leaves | 1 key |
| Stages sharing a tree | 1,024 | no shared tree |
| Category and codec | DSA LogicSig, `rotating_lsig` | same |
| Signing flow | `rotating1` | same |
| Creation parameter | `network` (name or base64 genesis hash) | same |
| Client provider | none; signer-side only | same |
| Availability | `Library`: an operator enables it, then generates | same |

## 2. Parameters and sizes (frozen)

| Parameter | XMSS | WOTS |
|---|---|---|
| Hash-based construction | `XMSS-SHA2_16_256` | APlane WOTS-w16 with a simple tweakable chain hash |
| Hash and Winternitz parameters | SHA-256, n = 32, w = 16, h = 16 | SHA-256, n = 32, w = 16 |
| Chains | 67: 64 message digits + 3 checksum digits | same |
| Steps per chain | 15 | 15 |
| Leaves per tree | 65,536 | no tree |
| Leaves per stage | 64 | 1 one-time key |
| Randomizer search limit | 64 counters | none |
| Message checksum cap | 511 | none; checksum can reach 960 |
| Maximum accepted chain steps | 525 | 990 |
| Validity window cap | 100 rounds (`LastValid - FirstValid`) | same |
| TEAL version | 13 | 13 |
| Stage program bytes, unsalted / salted | 2,661 / 2,664 | 2,100 / 2,103 |
| Stage 0 public record bytes | 1,921 | 1,889 |
| Hash-based signature bytes | 2,692 | 2,144 |
| Ed25519 signature bytes | 64 | 64 |
| Falcon-1024 signature bytes | at most 1,423, compressed | same |
| Falcon-1024 public key bytes | 1,793 | 1,793 |
| Maximum total argument bytes | 4,179 | 3,631 |
| Maximum opcode cost | 95,857 | 59,772 |
| Group size | 5: one spend + four resource dummies | 4: one spend + three resource dummies |

The stage packages own the templates and cost models. The corresponding
profiles in `internal/rotatingkey` expose their frozen bounds to storage,
inventory and signing orchestration.

## 3. Account and stage model

A stage is indexed by `n >= 0`. Stage 0's program address **is** the account
address. Stage `n` normally signs one transaction, which rekeys the account to
stage `n + 1`'s program address. Releasing a signature does not itself advance
the stage: the chain must confirm a rotation.

The WOTS variant derives a fresh WOTS key for every stage. The XMSS variant
assigns stage `n` to tree `n div 1024` and the leaf range
`[64 * (n mod 1024), 64 * (n mod 1024) + 64)` (`stage.RangeFor`). A new tree is needed at every
multiple of 1,024 stages; the worker builds it ahead of need from the midpoint
of the live tree.

### 3.1 Stage program

Both frozen TEAL v13 templates require:

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

The WOTS program embeds four constants: the Ed25519 key (32 bytes), Falcon key
(1,793), stage tweak (32) and WOTS public key (32). It requires a 2,144-byte
signature and checks that the hash of its 67 completed chains equals the
embedded WOTS public key.

The XMSS program verifies everything with `sha256`, `concat`, `extract3`,
`replace3`, `b^`, `itob` and one subroutine (`hnode`). The `toByte(3) || SEED`
prefix of every `PRF` call is hoisted into the per-phase address prefixes, and
a chain step is kept as `step << 32` so a single `itob` yields both trailing
address words. The checksum cap is asserted when the chain loop reaches the
checksum chains. The WOTS program runs one loop over its 67 chains, keeping the
TxID, chain index, running checksum, concatenated chain ends, current element,
step, digit and `chain * 256` in scratch slots 0 through 7.

Neither program restricts transaction type or constrains `RekeyTo` beyond
condition 1. Anyone holding a valid triple of signatures over a transaction
that satisfies conditions 1 to 3 could spend it, which is why the keys are
one-time per stage and the signer releases a stage's signatures only for a
transaction that rekeys to the account's next stage. Spending policy is
enforced by the signer's policy layer.

### 3.2 Derivation of the stage address

Each scheme's `stage.Build(keys)` fills its own frozen template and computes
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

The only stored private material is a 64-byte BIP-39-style seed. Both variants
use HKDF-SHA-512 with their own label as the extraction salt:

| Scheme | Derivation label |
|---|---|
| XMSS | `APLANE_ROTATING_XMSS_V1` |
| WOTS | `APLANE_ROTATING_TRIPLE_V1` |

The shared package `internal/crypto/rotatinghybrid` also defines a default
label, `APLANE_ROTATING_HYBRID_V1`; neither v1 key type uses it.

Every expansion includes the network's 32-byte genesis hash `G`. Account-level
info is `tag || G`; stage- or tree-level info is `tag || G || u64be(counter)`.
Thus the same seed derives different material across networks and key types.

| Output | Tag | Counter | Bytes | Scheme |
|---|---|---|---|---|
| Public account tag | `0x10` | none | 32 | both |
| Stage Falcon-1024 seed | `0x01` | stage `n` | 48 | both |
| Stage Ed25519 seed | `0x02` | stage `n` | 32 | both |
| Stage WOTS chain secrets | `0x11` | stage `n` | 2,144 | WOTS |
| Tree secret seed (`SK_SEED`) | `0x20` | tree number | 32 | XMSS |
| Tree PRF key (`SK_PRF`) | `0x21` | tree number | 32 | XMSS |
| Tree public seed | `0x22` | tree number | 32 | XMSS |

Derivation is random access: a stage does not require deriving its predecessors.
Secrets are derived per call and zeroed before returning.

XMSS additionally builds the public tree (65,536 WOTS+ leaves, about 4 MiB of
nodes). It takes seconds to generate and is cached only in memory, with no
secrets retained. The cache holds at most 3 trees per account (live, next, one
behind) and 16 overall, with least-recently-used eviction. Concurrent requests
for the same tree share one generation. WOTS needs no public tree cache.

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

### 5.3 WOTS

The WOTS variant uses the construction in `internal/crypto/wots`: n = 32,
w = 16, 64 message digits and 3 checksum digits. It has 67 SHA-256 chains,
each with 15 steps. This is the per-stage WOTS-w16 scheme, distinct from the
masked WOTS+ construction inside XMSS.

The stage tweak binds the chains to the network, account and stage:

```text
T = SHA-256("APLANE_WOTS_V1" || G || account_tag || u64be(n))
F(T, chain, step, x) = SHA-256(T || u64be(chain * 256 + step) || x)
```

Split `TxID` into 64 hexadecimal digits, high nibble first, then append the
three hexadecimal digits of `sum(15 - message_digit)`. For each chain, signing
advances its secret by that chain's digit value and emits the resulting
32-byte element:

```text
arg 0 = chain_element[0] || ... || chain_element[66]  (2,144 bytes)
```

Verification completes each chain to step 15 and hashes the 67 chain ends
together with SHA-256. The result must equal the embedded 32-byte WOTS public
key. There is no randomizer, leaf index, authentication path or checksum cap.
Each stage has one WOTS key, which must authenticate only one released message
to retain its one-time security property.

### 5.4 Arguments

| Argument | XMSS variant | WOTS variant |
|---|---|---|
| `arg 0` | XMSS signature, 2,692 bytes | WOTS signature, 2,144 bytes |
| `arg 1` | Ed25519 signature, 64 bytes | same |
| `arg 2` | Falcon-1024 signature, at most 1,423 bytes | same |

### 5.5 Signer-side verification

Before releasing anything, `StageOps.SignStage` re-parses the derived program
and verifies all three signatures locally through the scheme's `signerops.Verify`.
XMSS also checks the leaf range and checksum cap. Failed signatures are zeroed
and refused.

## 6. Resource profile and cost

Each group member contributes 20,000 units of pooled LogicSig execution cost
and 1,000 bytes of pooled large-argument allowance.

| Property | XMSS | WOTS |
|---|---|---|
| Unsalted verifier cost | `25,507 + 134 * steps` | `7,301 + 53 * steps` |
| Maximum chain steps | 525 | 990 |
| Salt overhead | none; salt follows `return` | 1 opcode |
| Worst accepting run | 95,857 | 59,772 |
| Maximum argument bytes | 4,179 | 3,631 |
| Group pool | 100,000 cost / 5,000 argument bytes | 80,000 cost / 4,000 argument bytes |
| Resource dummies | 4 | 3 |

For hexadecimal checksum digits `a b d`, the number of verification chain
steps is `45 + 255a + 15b`. XMSS's cap of 511 bounds this at 525; a checksum
of 512 already needs 555. WOTS accepts the full checksum range and may need
990 steps. The generic XMSS primitive's `MaxVerifySteps = 990` remains
unchanged; the 525-step bound belongs to the XMSS stage profile.

## 7. Key file and storage

Both variants use a managed `.key` credential with the `rotating_lsig` codec
(`keys.RotatingCodec`), containing the seed, network genesis hash and a
scheme-specific stage 0 public record:

| Scheme | Public record, in order | Bytes |
|---|---|---|
| XMSS | account tag (32), Falcon public key (1,793), tree 0 root (32), tree 0 public seed (32), Ed25519 public key (32) | 1,921 |
| WOTS | stage 0 tweak (32), Falcon public key (1,793), WOTS public key (32), Ed25519 public key (32) | 1,889 |

The account address is derived from this record. No bytecode is stored; XMSS's
stage 0 leaf range is fixed and is not stored either.

On parsing a WOTS key file, `validateSeed` derives stage 0 and compares the
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

Both variants use only `POST /sign/rotating/prepare` and
`POST /sign/rotating/sign`. `/plan`, `/sign`, `/sign/bounded-admin` and
`/sign/component` refuse them with `rotating_signing_required`. The complete
wire contract lives in [ARCH_SIGNING.md](ARCH_SIGNING.md#rotating-accounts-rotating1).

1. **Prepare.** The client sends one unsigned, ungrouped spend from the account,
   with no `rekey_to`, no close-out, the account's genesis hash and a validity
   window at most 100 rounds. The signer reads the live authorizer from its
   own node, finds stage `n` and confirms it by derivation, sets `rekey_to` to
   stage `n + 1`, adds the profile's resource dummies, sets fees and group ID,
   and returns the exact unsigned group. It stores nothing and needs no approval.
2. **Sign.** The group's `rekey_to` fixes `n`. The signer re-derives stage
   `n + 1`, checks the target and canonical group by byte equality, and runs
   ordinary policy gates and operator approval. Under the account lock it
   re-reads the chain and refuses unless stage `n` is still the authorizer
   (`rotating_stage_changed`), `first_valid` is at most 2 rounds ahead of the
   current round, and at least 10 rounds remain before `last_valid`. It proves
   the successor opens (`CheckStageOpens`), signs, verifies, writes a
   `ROTATING_RELEASE` audit entry (account, TxID, stage, `last_valid`, tree and
   leaf index), records the release in memory and responds.
3. **Open test.** `CheckStageOpens` test-signs the target stage locally before
   any spend signature is released. Both variants sign the SHA-256 hash of
   their derivation label followed by ` stage open test`: a fixed label, not a
   TxID, so the test signature authorizes nothing. WOTS tests all three
   signatures and wipes the test arguments without releasing them. XMSS tests
   Ed25519 and Falcon and checks the embedded root, public seed and leaf range;
   it never signs with a target-stage XMSS leaf.

Clients route on `signing_flow`, verify the prepared group preserves the
intended spend except for the rotation, fee, group ID and canonical dummies,
simulate that group, then sign and submit the exact bytes. The signer retains
no prepare session; policy evaluates the spend presented to sign.

### 8.1 One-time key and leaf selection

WOTS always uses the stage's single one-time key; there is no selectable leaf.
For XMSS, the signer chooses a leaf under the account lock from release memory:

- An already released transaction keeps its leaf, reproducing its hash-based
  signature on an identical retry.
- Otherwise the first byte of `TxID` picks a position within the stage's range,
  then the first unused leaf upward, wrapping, is selected, so two signers
  sharing a seed and no memory collide one time in 64 rather than always.
- If all 64 leaves have been used, the pick is reused and reported.

Release memory chooses the XMSS leaf; it does not refuse further releases.
An audit write failure is logged and does not withhold the signature.

### 8.2 Release memory and alerts

The signer keeps the newest release per account and that stage's release
history in process memory, rebuilt at unlock from `ROTATING_RELEASE` audit
entries. It records the stage, TxID, `last_valid` and one-time leaf history
(WOTS uses leaf 0; XMSS records tree and index). Signing waits for audit
restoration, bounded by the request context.

- A release that expires while its stage remains the authorizer raises a
  warning: it cannot confirm and the exposed stage still controls the account.
- Releasing a second distinct transaction on the same one-time key marks the
  stage reused and warns until the account moves past it (the profile's
  `OneTimeStage` flag). For WOTS this means
  any second distinct transaction; for XMSS it means reusing a leaf. Multiple
  XMSS releases on distinct leaves show an attempt count without a reuse warning.

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

- **All three signatures required.** A forgery needs a break of Falcon-1024,
  of Ed25519 and of SHA-256 at once, so long as the stage's one-time key has
  signed only one message. These properties assume the seed remains secret and
  the verifier and surrounding protocol work correctly.
- **Bounded exposure.** A released stage controls the account until a rotation
  confirms. Successor WOTS stages embed new keys; successor XMSS stages embed
  a disjoint leaf range and, at tree boundaries, a new root.
- **WOTS reuse.** Releasing signatures on two different messages with one stage
  forfeits the one-time security claim for that key. The stage still requires
  Falcon-1024 and Ed25519 until rotation confirms. Repeating the same message
  does not create a second WOTS message signature.
- **XMSS reuse.** A leaf must sign only one message. A stage can use up to 64
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
signing. The WOTS variant is the APlane construction described in §5.3, not
the XMSS WOTS+ format. Neither variant provides on-chain spending limits or an
external-admin recovery path. Policy belongs to the signer; recovery depends
on the backed-up credential.

## 10. Policy and transaction authority

| Property | Both variants |
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

## 11. Compatibility and versioning

- Each v1 key type separately freezes its stage template, embedded constants,
  derivation label and tags, signing procedure, public record and resource
  profile. XMSS also freezes its checksum cap and leaf allocation. Any change
  to the TEAL changes every stage address. Changing these contracts mints a
  new key type version; it does not edit v1.
- The two schemes have separate identifiers and derivation labels
  (`APLANE_ROTATING_TRIPLE_V1` versus `APLANE_ROTATING_XMSS_V1`), so their
  addresses never collide by construction. This document groups them under a shared design name; it introduces no additional
  key type, scheme negotiation or conversion of existing accounts.
- Pre-release development templates may derive different addresses and must
  be identified rather than reinterpreted as released v1 templates.
- The shared signing-flow identifier remains `rotating1`. Clients route on
  `signing_flow`, not key type strings.
- The installer floor for upgrades is v0.44.0.

## 12. Evidence (tests)

| Area | Where |
|---|---|
| XMSS stage build, parse, salt, offsets and cost | `lsig/rotatingtriplexmss/stage/program_test.go`, `template_dump_test.go` |
| WOTS stage build, parse, salt, offsets and cost | `lsig/rotatingtriplewots/stage/program_test.go` |
| Algod assembler agreement for salted and unsalted stages, both schemes | the two `stage` packages' tests (LocalNet) |
| Derivation, signing, verification and tampered fields; XMSS range violations and checksum above cap | `lsig/rotatingtriplexmss/signerops/keys_test.go`, `lsig/rotatingtriplewots/signerops/keys_test.go` |
| Codec, generator, seed validation and registration | `lsig/rotatingtriplexmss/signerreg/register_test.go`, `lsig/rotatingtriplewots/signerreg/register_test.go` |
| XMSS vectors from an independent oracle (`tools/xmssoracle`), RFC reference vector, 32 bounded signatures (10 with searched randomizer) | `internal/crypto/xmss/` |
| XMSS checksum boundaries (511/525, 512/555) and exhaustive step counts | `internal/crypto/xmss/`, `lsig/rotatingtriplexmss/stage/` tests |
| WOTS digits, chains, signatures and step counts | `internal/crypto/wots/wots_test.go` |
| Shared HKDF derivation | `internal/crypto/rotatinghybrid/derive_test.go` |
| XMSS on-chain acceptance, cost model at the step ceiling, tree rollover, five-transaction group | `test/integration/rotating_xmss_onchain_test.go` |
| WOTS on-chain acceptance, resource costs, four-transaction group | `test/integration/rotating_triple_onchain_test.go` |
| Shared signing flow, release gates and recovery | `internal/signerapp/signing/rotating_*_test.go`, `test/integration/rotating_signer_test.go` |
| Every non-payment transaction type through apshell and the signer (asset opt-in, transfer and close-out; app opt-in, call and box reference; online and offline key registration), both schemes; refusal by a contract that rejects rekeying calls, with nothing signed | `test/integration/rotating_txntypes_test.go` |

Full XMSS tree builds are skipped under the race detector (`internal/racetest`).

## 13. Open items

- Per-key-type exit and external-admin paths remain design-only.
- Hinted stage scans and an in-flight release limit remain proposed.
- A security proof for XMSS's checksum-bounded randomizer selection beyond the
  monotone-checksum argument has not been written.
