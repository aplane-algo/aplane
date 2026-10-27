# Key Type Specification: Rotating Triple Hybrid

Status: implemented as three separate key types. `aplane.rotating-triple-xmss.v1`
and `aplane.rotating-triple-wots.v1` are each frozen by their first release
(v0.44.0). `aplane.rotating-triple-slhdsa.v1` is experimental and unreleased;
its design is in section 11. This document specifies all three for
implementers and reviewers: their shared design and the hash-based
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

The third implementation, `aplane.rotating-triple-slhdsa.v1`, reuses the
shared `rotating1` account and signing contracts with a stateless hash-based
scheme. Sections 2 through 9 compare the two released variants and keep
their exact layouts; section 11 specifies where SLH-DSA differs, with the
frozen contract in [ARCH_CRYPTO.md](ARCH_CRYPTO.md#rotating-slh-dsa-triple)
and the qualification record in [SLHDSA_EVALUATION.md](SLHDSA_EVALUATION.md).
Its implementation is `lsig/rotatingtripleslhdsa/`, with the primitive in
`internal/crypto/slhdsa/`. It is not part of the original v0.44.0 release.

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
| Hash-based signature | XMSS, WOTS or SLH-DSA, SHA-256 | one-time leaf, per-stage one-time key, or per-stage few-time key (section 11) |

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
remedy is a second spend from the same stage, which for WOTS is a second
signature on a different message (section 9). The design tolerates that as a
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
   to the submission window; they do not remove it.
2. *Multi-stage release.* Several rotating slots in one group, each signed
   by the next stage in the chain. This needs its own design for budget (a
   WOTS spend costs up to 59,772 and an XMSS spend up to 95,857 of a pool
   that grows by 20,000 per member up to 16 members), release memory, audit
   and one-time key accounting.

Reopen this when a product requirement needs the account itself in a
multi-party or multi-transaction group. Neither step touches the stage
program, so the templates stay unpinned on group size at no cost.

## 11. SLH-DSA variant

`aplane.rotating-triple-slhdsa.v1` replaces the one-time hash-based key of
the two released variants with a **stateless few-time** key per stage: an
SLH-DSA key under the SLH-DSA-SHA2-128s construction of FIPS 205, with the
hypertree rescaled to two layers. Everything the earlier sections say about
the account model (§3), the stage program guards (§3.1), the address
derivation (§3.2), the signing choreography (§8) and the policy boundary
(§10) applies unchanged. This section covers what differs: why a stateless
scheme, the parameter set and why it is not the standard one, the signing
and argument layout, the resource profile, the per-stage signing bound that
replaces the one-time rule, and the resulting claims.

### 11.1 Why a stateless scheme

The WOTS and XMSS variants rest on a one-time rule: a key or leaf that signs
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
| Hypertree | h = 20 in d = 2 layers of height h' = 10 (standard set: h = 63, d = 7, h' = 9) |
| FORS | k = 14 trees of height a = 12, as the standard set |
| WOTS+ | w = 16, 35 chains (32 message digits + 3 checksum digits), as the standard set |
| Message digest | 25 bytes: 21 for FORS, 2 for the tree index, 2 for the leaf index (standard set: 30) |
| Signing variant | pure interface, empty context, deterministic `opt_rand = PK.seed` |
| Validity window cap | 100 rounds, as the other variants |
| TEAL version | 13 |
| Stage program bytes, unsalted / salted | 2,834 / 2,837 |
| Stage 0 public record bytes | 1,857 |
| SLH-DSA signature bytes | 4,368 (standard set: 7,856) |
| Ed25519, Falcon-1024 signature bytes | 64; at most 1,423 |
| Maximum total argument bytes | 5,855 |
| Maximum opcode cost | 68,465 |
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
digest split; the signature drops to 4,368 bytes and the group to six
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
20 and 63: a verifier source, a template assembled from it, an argument
layout, a measured cost model and golden stage identities each, plus the
matching resource literals in `internal/rotatingkey`. Changing the
constant and rebuilding gives the standard SLH-DSA-SHA2-128s shape at ten
transactions, with every stage address changed, since the shape is
embedded in the stage program. It exists so the standard set stays
reachable for review and measurement while the type is experimental; it is
not an operator setting, and a released build fixes one height for the
key type's lifetime.

**Alternatives considered.**

- *Carry the signature in a companion application call's arguments.* That
  removes the byte floor but leaves the worst-case opcode floor of the
  standard set at ten transactions, so it only pays together with
  per-signature group sizing, and it needs a per-network carrier
  application pinned in the stage template, a custom SLH-DSA signed message
  because the signature can no longer bind the group ID it is part of, and
  a new key type. Shelved.
- *Two layers of height 9 (h = 18).* Same signature within 32 bytes, stage
  derivation at the standard set's cost, and a bound in §11.5 four times
  smaller. Height 10 was chosen for margin on a bound the signer does not
  enforce.
- *A smaller FORS.* Reaching five transactions needs about 2,000 fewer
  signature bytes, which only FORS can give, at the direct expense of the
  128-bit single-use margin. Rejected.

### 11.3 Derivation and stage record

Derivation uses the shared HKDF scheme of §4 under the label
`APLANE_ROTATING_TRIPLE_SLHDSA_V1`, with per-stage tags 1 (Falcon-1024
seed), 2 (Ed25519 seed), 3 (`SK.seed`), 4 (`SK.prf`) and 5 (`PK.seed`),
each expansion including the genesis hash. Stage `n`'s SLH-DSA key is
`KeyGenFromSeeds(SK.seed_n, SK.prf_n, PK.seed_n)` under the rescaled set;
its root is the top of a 1,024-leaf tree, so derivation costs about twice
the standard set's. The stage program embeds, in this order, `PK.seed` (16),
`PK.root` (16), the Falcon-1024 public key (1,793) and the Ed25519 public
key (32), and the stage 0 public record is the same 1,857 bytes. Program
bytes are derived, never stored, as for the other variants.

### 11.4 Signing and arguments

All three components sign the raw 32-byte transaction ID (§5.1). SLH-DSA
signs the pure-interface message `M' = 0x00 || 0x00 || TxID` with
`opt_rand = PK.seed`, so the same stage and transaction always reproduce the
same signature. The signature is `R (16) || FORS (2,912) || layer 0 (720)
|| layer 1 (720)`, and it is split for transport so that every argument
stays under the AVM's 4,096-byte value limit:

| Argument | Content | Bytes |
|---|---|---:|
| `arg 0` | `R` and the FORS signature | 2,928 |
| `arg 1` | both hypertree layers | 1,440 |
| `arg 2` | Ed25519 signature | 64 |
| `arg 3` | Falcon-1024 signature, compressed | at most 1,423 |

The verifier recomputes `H_msg` as one SHA-256 and one MGF1 block, splits
the 25-byte digest into the FORS message, a 10-bit tree index and a 10-bit
leaf index, recovers the 14 FORS roots along their authentication paths,
compresses them, and then walks the two WOTS+ layers: each chain is
unrolled, a `switch` on the digit enters the remaining hash steps, the 35
chain ends are compressed, and a 10-level authentication path yields the
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
signatures on 2^63 leaves, and the rescaled set with 2^20 leaves is in that
same regime at about **2^20 distinct messages per stage key**. Repeating a
message reproduces the same signature and the same leaf and reveals nothing
new, so retries of one transaction do not count.

Honest use is far inside the bound: the open-test message of §8, which is
never released, and the spends released while the stage is live, normally
one and occasionally a few when a window ages or a client rebuilds the
transaction. The signer does not count signatures per stage and the
protocol does not bound them: a stage stays live until a spend lands, the
signer keeps no limit on releases per stage by design, and copies sharing a
seed sign independently. The bound is a margin statement, priced by the
SPHINCS+ few-time bound that FIPS 205 inherits: with q distinct messages
under one stage key, a forger's work on the hash leg is about 186 bits at
q = 3, 159 bits at 2^16, 134 bits at 2^21 (the standard set's own margin
at its 2^64 design limit) and 126 bits at 2^22. The evaluation record
tabulates this and adopts an operating assumption of at most 2^16 distinct
messages per stage key across copies and retries, which is two hours of
continuous unsubmitted signing from one host with expired-release warnings
firing throughout. No release cap, rate limit or used-leaf tracking is
added: a cap could strand an account whose every released spend expired,
and tracking leaves to redraw the randomizer would reintroduce the state
this variant exists to avoid. A deployment outside the assumption adds a
per-stage release rate limit, which delays rather than refuses, or a
taller tree.

Release memory (§8.2) keeps only the latest release for this variant:
`StatelessHash` records carry no leaf history, restore nothing from the
audit log beyond the latest release, and never mark reuse. Expired and
in-flight release alerts work as for the other variants.

### 11.6 Resource profile and cost

| Property | SLH-DSA variant |
|---|---|
| Verifier cost | `26,645 + 41 * steps`, salted or not; the salt tail follows `return` |
| Steps per layer | `c + 45 - digitSum16(c)` for checksum `c` in 0..480, at most 510 |
| Maximum chain steps | 1,020 |
| Worst accepting run | 68,465 |
| Typical run | about 48,500 at the mean of 534 steps; LocalNet traces of 480 and 570 steps matched the model exactly |
| Maximum argument bytes | 5,855 |
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

| Item | XMSS | WOTS | SLH-DSA |
|---|---|---|---|
| Hash-based key per stage | 64 one-time leaves of a shared tree | one one-time key | one few-time key |
| Rule on the hash-based key | each leaf signs one message | the key signs one message | at most about 2^20 distinct messages |
| State the rule needs | leaf history, audit restore, tree cache | release memory for reporting only | none |
| Loss of state | leaf reuse, caught and reported | reuse reported | none |
| Group size | 5 | 4 | 6 |
| Hash-based signature bytes | 2,692 | 2,144 | 4,368 |
| Worst opcode cost | 95,857 | 59,772 | 68,465 |
| Signing, this host | tree cache amortized | microseconds | about 0.10 s |
| Stage derivation, this host | tree cache amortized | microseconds | about 50 ms |
| Standing | RFC 8391 format and set, non-conformant signer | APlane construction | FIPS 205 construction, private parameter set |
| Status | released v1 | released v1 | experimental |

## 12. Compatibility and versioning

- Each v1 key type separately freezes its stage template, embedded constants,
  derivation label and tags, signing procedure, public record and resource
  profile. XMSS also freezes its checksum cap and leaf allocation. Any change
  to the TEAL changes every stage address. Changing these contracts mints a
  new key type version; it does not edit v1.
- The three schemes have separate identifiers and derivation labels
  (`APLANE_ROTATING_TRIPLE_V1`, `APLANE_ROTATING_XMSS_V1` and
  `APLANE_ROTATING_TRIPLE_SLHDSA_V1`), so their addresses never collide by
  construction. This document groups them under a shared design name; it
  introduces no additional key type, scheme negotiation or conversion of
  existing accounts.
- The SLH-DSA variant is unreleased. Its hypertree rescaling on 2026-10-27
  changed its stage template, stage identities and resource profile under
  the same key type identifier, a pre-release freeze decision; once it
  ships, the same change would mint a new version.
- Pre-release development templates may derive different addresses and must
  be identified rather than reinterpreted as released v1 templates.
- The shared signing-flow identifier remains `rotating1`. Clients route on
  `signing_flow`, not key type strings.
- The installer floor for upgrades is v0.44.0.

## 13. Evidence (tests)

| Area | Where |
|---|---|
| SLH-DSA construction against the NIST ACVP vectors on the standard shape; rescaled golden vectors; digest split and leaf-index coverage; tampering and cross-shape rejection | `internal/crypto/slhdsa/slhdsa_test.go` |
| SLH-DSA stage build, parse, salt, offsets, argument literals pinned to the parameter set, and cost ceiling | `lsig/rotatingtripleslhdsa/stage/program_test.go`, `template_dump_test.go` |
| SLH-DSA derivation golden vectors, signing, verification and argument layout | `lsig/rotatingtripleslhdsa/signerops/keys_test.go`, `signerreg/register_test.go` |
| SLH-DSA on-chain acceptance and rejection, cost model against node traces on both program shapes, six-transaction group | `test/integration/rotating_slhdsa_onchain_test.go` |
| SLH-DSA preparation ceilings, bounded discovery, post-sign chain recheck, restored releases without leaf history; lifecycle benchmark | `internal/signerapp/signing/rotating_slhdsa_test.go`, `rotating_slhdsa_bench_test.go` |
| XMSS stage build, parse, salt, offsets and cost | `lsig/rotatingtriplexmss/stage/program_test.go`, `template_dump_test.go` |
| WOTS stage build, parse, salt, offsets and cost | `lsig/rotatingtriplewots/stage/program_test.go` |
| Algod assembler agreement for salted and unsalted stages, all three schemes | the three `stage` packages' tests (LocalNet) |
| Derivation, signing, verification and tampered fields; XMSS range violations and checksum above cap | `lsig/rotatingtriplexmss/signerops/keys_test.go`, `lsig/rotatingtriplewots/signerops/keys_test.go` |
| Codec, generator, seed validation and registration | `lsig/rotatingtriplexmss/signerreg/register_test.go`, `lsig/rotatingtriplewots/signerreg/register_test.go` |
| XMSS vectors from an independent oracle (`tools/xmssoracle`), RFC reference vector, 32 bounded signatures (10 with searched randomizer) | `internal/crypto/xmss/` |
| XMSS checksum boundaries (511/525, 512/555) and exhaustive step counts | `internal/crypto/xmss/`, `lsig/rotatingtriplexmss/stage/` tests |
| WOTS digits, chains, signatures and step counts | `internal/crypto/wots/wots_test.go` |
| Shared HKDF derivation | `internal/crypto/rotatinghybrid/derive_test.go` |
| XMSS on-chain acceptance, cost model at the step ceiling, tree rollover, five-transaction group | `test/integration/rotating_xmss_onchain_test.go` |
| WOTS on-chain acceptance, resource costs, four-transaction group | `test/integration/rotating_triple_onchain_test.go` |
| Shared signing flow, release gates and recovery | `internal/signerapp/signing/rotating_*_test.go`, `test/integration/rotating_signer_test.go` |
| Every non-payment transaction type through apshell and the signer (asset opt-in, transfer and close-out; app opt-in, call and box reference; online and offline key registration), all three schemes; refusal by a contract that rejects rekeying calls, with nothing signed | `test/integration/rotating_txntypes_test.go` |

Full XMSS tree builds are skipped under the race detector (`internal/racetest`).

## 14. Open items

- Independent review of the SLH-DSA rescaled parameter set and of the
  per-stage signing margin argument (§11.5) is a listed gate in
  [SLHDSA_EVALUATION.md](SLHDSA_EVALUATION.md).
- Per-key-type exit and external-admin paths remain design-only.
- Hinted stage scans and an in-flight release limit remain proposed.
- Grouping with other senders and multi-stage release are deferred by design
  (section 10.1).
- A security proof for XMSS's checksum-bounded randomizer selection beyond the
  monotone-checksum argument has not been written.
