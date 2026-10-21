# Key Type Specification: `aplane.rotating-triple-xmss.v1`

Status: implemented; v1 is frozen by its first release (v0.44.0). This document
specifies the key type for implementers and reviewers. It restates, and does
not replace, the authoritative sources:

- `lsig/rotatingxmsstriple/stage/program.go`: stage template, constants, parser, cost model
- `lsig/rotatingxmsstriple/signerops/`: key derivation, signing, tree cache
- `lsig/rotatingxmsstriple/signerreg/`: key file codec, generator, registration
- `internal/crypto/xmss/`: RFC 8391 XMSS-SHA2_16_256 and checksum-bounded signing
- `internal/rotatingkey/rotatingkey.go`: frozen sizes and the key type's profile
- `ARCH_CRYPTO.md` (cryptographic design), `ARCH_SIGNING.md` (the `rotating1` flow),
  `ARCH_KEYTYPES.md` (the eight-point key type record)

Where this document and the code disagree, the code and its frozen golden
tests win; report the discrepancy.

## 1. Summary

`aplane.rotating-triple-xmss.v1` is a **rotating** Algorand account. It has one
fixed address, but the LogicSig program that authorizes it (the *stage*) changes
on every spend. Every spend must rekey the account to the next stage, so the keys a
signature reveals control the account only until that transaction confirms.

Every stage requires **three** signatures over the transaction ID, all of which
must verify:

| Component | Algorithm | Role |
|---|---|---|
| Falcon-1024 | lattice, post-quantum | per-stage key |
| Ed25519 | classical (`ed25519verify_bare`) | per-stage key |
| XMSS | RFC 8391 `XMSS-SHA2_16_256`, hash-based | one-time leaf of a tree shared by 1,024 stages |

A forgery needs a break of Falcon-1024, of Ed25519 and of SHA-256 at once, so
long as the leaf has signed only one message.

The type is the XMSS counterpart of `aplane.rotating-triple-wots.v1`. It uses the
same `rotating1` signing flow, the same operation authority, the same policy
gates and the same key file shape. It differs in its hash-based component and
its stage program.

Identifiers:

| Item | Value |
|---|---|
| Key type | `aplane.rotating-triple-xmss.v1` |
| Family | `aplane.rotating-triple-xmss` |
| Category | DSA LogicSig, `rotating_lsig` codec |
| Signing flow | `rotating1` |
| Creation parameter | `network` (name or base64 genesis hash) |
| Client provider | none; signer-side only |
| Availability | `Library` key type: an operator enables it, then generates |

## 2. Parameters and sizes (frozen)

| Parameter | Value |
|---|---|
| XMSS parameter set | `XMSS-SHA2_16_256`: SHA-256, n = 32, w = 16, h = 16 |
| WOTS+ chains | 67 (64 message digits + 3 checksum digits), 15 steps each |
| Leaves per tree | 65,536 |
| Leaves per stage | 64 |
| Stages per tree | 1,024 |
| Randomizer search limit | 64 counters |
| Message checksum cap | 511 (`stage.MaxChecksum`) |
| Maximum accepted chain steps | 525 (`45 + 255*1 + 15*15`) |
| Validity window cap | 100 rounds (`LastValid - FirstValid`) |
| TEAL version | 13 |
| Stage program size | 2,661 bytes unsalted, 2,664 salted (`stage.UnsaltedProgramSize`, `SaltedProgramSize`) |
| Stage 0 key record | 1,921 bytes (`32 + 1793 + 32 + 32 + 32`) |
| XMSS signature | 2,692 bytes (`4 + 32 + 67*32 + 16*32`) |
| Ed25519 signature | 64 bytes |
| Falcon-1024 signature | at most 1,423 bytes (compressed) |
| Falcon-1024 public key | 1,793 bytes |
| Maximum argument bytes | 4,179 |
| Opcode cost | `25,507 + 134 * steps`, at most `95,857` |
| Group size | 5 transactions: one spend plus four resource dummies |

The authoritative program size constants live in `stage/template_bytes.go` and
`rotatingkey.go`; the salted maximum 2,664 is `RotatingXmssMaxProgramBytes`.

## 3. Account and stage model

A stage is indexed by `n >= 0`. Stage 0's program address **is** the account
address. Stage `n` signs exactly one rotation, which rekeys the account to stage
`n + 1`'s program address.

Stage `n` belongs to tree `n div 1024` and owns the leaf indices
`[64 * (n mod 1024), 64 * (n mod 1024) + 64)` of that tree
(`stage.RangeFor`). A new tree is generated when the account crosses a multiple
of 1,024 stages; the stage table worker builds the next tree ahead of need from
the midpoint of the live one.

### 3.1 Stage program

The stage program is a frozen TEAL v13 template with six constants:

1. Ed25519 public key (32 bytes)
2. Falcon-1024 public key (1,793 bytes)
3. XMSS public seed of the stage's tree (32 bytes)
4. XMSS root of the stage's tree (32 bytes)
5. leaf range lower bound `Lo` (8-byte big-endian integer)
6. leaf range upper bound `Hi` (8-byte big-endian integer)

The program accepts a transaction only if all of the following hold:

1. `RekeyTo` is not the zero address and is not the sender.
2. `CloseRemainderTo` is the zero address.
3. `LastValid - FirstValid <= 100`.
4. `arg 1` is a valid Ed25519 signature of `TxID` under the stage's Ed25519 key
   (`ed25519verify_bare`).
5. `arg 2` is a valid Falcon-1024 signature of `TxID` under the stage's
   Falcon key (`falcon_verify`).
6. `arg 0` is exactly 2,692 bytes. Its leading four bytes, the leaf index,
   satisfy `Lo <= index < Hi`.
7. The XMSS message hash `H_msg(r || root || toByte(index, 32), TxID)` has a
   WOTS+ checksum of at most 511. (The program asserts this when its chain loop
   reaches the checksum chains.)
8. The WOTS+ public key recomputed from `arg 0` (67 masked chains, RFC 8391
   addresses), compressed through the L-tree and the 16-level authentication
   path, equals the embedded root.

The program does not restrict the transaction type. It does not constrain
`RekeyTo` beyond condition 1; the signer is what always sets the rekey to the
account's next stage. Anyone holding a valid triple of signatures over a
transaction that satisfies 1 to 3 could spend it, which is why the keys are
one-time per stage and the signer releases a stage's signature only for a
transaction that rekeys to the next stage.

Everything the program verifies uses `sha256`, `concat`, `extract3`, `replace3`,
`b^`, `itob` and one subroutine (`hnode`). The `toByte(3) || SEED` prefix of every
`PRF` call is hoisted into the per-phase address prefixes; a chain step is kept
as `step << 32` so a single `itob` yields both trailing address words.

### 3.2 Derivation of the stage address

`stage.Build(keys)` fills the template, computes the address as
`SHA-512/256("Program" || bytecode)`, and if that address is on the Ed25519
curve, appends `intcblock 1 <salt>` (bytes `0x20 0x01 <salt>`, three bytes)
with the lowest salt in `[0, 128)` giving an off-curve address, exactly as the
TEAL v13 assembler does. If none exists (probability about 2^-128) the stage is
unusable (`ErrNoOffCurveSalt`).

`stage.Parse` is the strict inverse: it accepts only bytes that `Build` would
produce, including a salt tail present exactly when required. No bytecode is
stored in the key file; stages are derived locally and offline, at every request
and in bulk in the background, without trusting a node for addresses. A test
compares the local bytes against algod's assembler output for salted and
unsalted stages.

## 4. Key derivation

The only private material is the 64-byte BIP-39-style seed stored in the key
file. All keys derive from it with HKDF under the label
`APLANE_ROTATING_XMSS_V1`, and the **genesis hash of the account's network is
mixed into every expansion**, so one seed is a different account on every
network.

| Output | Tag | Counter | Size |
|---|---|---|---|
| Public account tag | `0x10` | none | 32 |
| Stage Falcon-1024 seed | `0x01` | stage `n` | per `rotatinghybrid.FalconSeedSize` |
| Stage Ed25519 seed | `0x02` | stage `n` | per `rotatinghybrid.Ed25519SeedSize` |
| Tree XMSS secret seed (`SK_SEED`) | `0x20` | tree number | 32 |
| Tree XMSS PRF key (`SK_PRF`) | `0x21` | tree number | 32 |
| Tree XMSS public seed | `0x22` | tree number | 32 |

Stage derivation is random access: any stage is derivable from the seed and its
tree without deriving its predecessors.

The **public tree** (all nodes, about 4 MiB) takes seconds to build from the
seed (65,536 WOTS+ leaf public keys). It is held in an in-memory cache and is
never persisted; no secret is cached. Secrets are derived per call and zeroed
before returning. The cache holds at most 3 trees per account (live, next,
one behind) and 16 overall, evicting the least recently used. Concurrent
requests for one tree share a single generation.

## 5. Signing

### 5.1 Message

For a spend, the signed message is the raw 32-byte `TxID` of the transaction.
All three signatures cover it.

### 5.2 XMSS signature

The signature is RFC 8391 `XMSS-SHA2_16_256`:

```
arg 0 = index (4 bytes, big-endian)
     || r (32 bytes)                 randomizer
     || WOTS+ signature (67 * 32)    offset 36
     || authentication path (16*32)  offset 2180
```

`H_msg(r || root || toByte(index, 32), TxID)` is the signed message hash.

The signer chooses `r` with `xmss.SignBounded`:

1. for counter `c = 0, 1, ..., 63`, compute
   `r = PRF(SK_PRF, toByte(c, 28) || toByte(index, 4))`;
2. compute the message hash and its WOTS+ checksum;
3. take the first `c` whose checksum is at most 511, sign **once** with that digest
   and attach the authentication path;
4. if none of the 64 candidates qualifies, fail with
   `ErrRandomizerSearchExhausted` and sign nothing.

Counter 0 is RFC 8391's own randomizer input, so about four signatures in five
are byte-identical to an RFC signer's. A candidate qualifies with probability
about 0.803, so exhaustion has probability about 2^-150. The search is
deterministic: the same seed, index and message reproduce the same signature,
and no counter is stored. Search counters are not leaf indices and never consume
the stage's leaf budget. Only one WOTS+ signature is ever generated.

Every signature verifies under any RFC 8391 verifier (which reads `r` from the
signature). The stage, however, **rejects some valid RFC signatures**: those
with a checksum above 511. The signing procedure is therefore not RFC 8391's or
SP 800-208's, and the key type claims no conformance with either (see §9).

### 5.3 Ed25519 and Falcon-1024

Standard signatures over the same 32-byte message with the stage's keys.

### 5.4 Arguments

| Argument | Content | Size |
|---|---|---|
| `arg 0` | XMSS signature | 2,692 |
| `arg 1` | Ed25519 signature | 64 |
| `arg 2` | Falcon-1024 signature | at most 1,423 |

### 5.5 Signer-side verification

Before releasing anything, `StageOps.SignStage` re-parses the stage program and
verifies all three signatures locally (`signerops.Verify`): Ed25519, Falcon, leaf
range, the XMSS signature, and the checksum cap. A signature that does not verify
is zeroed and refused.

## 6. Resource profile and cost

Each group member contributes 20,000 units of pooled LogicSig execution cost
and 1,000 bytes of pooled large-argument allowance.

- Verifier cost: `25,507 + 134 * steps`, where `steps = 45 + 255a + 15b` for a
  message checksum with hexadecimal digits `a b d` (the low digit cancels).
- Under the cap (checksum at most 511: `a <= 1`, `b <= 15`) the worst accepting
  run is `525` steps: `25,507 + 134 * 525 = 95,857`. A checksum of 512 already
  needs 555 steps.
- The salt tail follows the final `return` and never executes, so salted and
  unsalted programs cost the same.
- 4,179 argument bytes plus 95,857 units fit a pool of five group members
  (100,000 units, 5,000 argument bytes): one spend and **four** resource dummies.

The generic RFC package's `xmss.MaxVerifySteps = 990` is unchanged; the capped
bound is the stage's own constraint.

## 7. Key file and storage

The key file is a managed `.key` credential of the `rotating_lsig` codec
(`keys.RotatingCodec`) containing:

- the seed (the only private material),
- the network's genesis hash,
- the **stage 0 public record** (1,921 bytes): public account tag (32),
  Falcon-1024 public key (1,793), tree 0 root (32), tree 0 public seed (32),
  Ed25519 public key (32).

Stage 0's leaf range is fixed and not stored. The account address is derived from
the record (`accountAddress`). No bytecode is stored.

On every key file parse, `validateSeed` checks the cheap derivations: the
account tag, tree 0's public seed, and stage 0's Ed25519 and Falcon-1024
public keys. Tree 0's root takes seconds to recompute, so it is compared only
when tree 0 is already cached; a wrong root is still caught before any signing
because the derived stage program would not match the on-chain authorizer.

Derived caches (reconstructible, not authority): the in-memory public tree cache,
and the per-account stage address table (see `ARCH_STORE.md`, Stage address
tables). Backups carry the seed; restore needs nothing else.

Mnemonic export and mnemonic import are refused: the recovery material never
leaves the signer.

## 8. Signing choreography (`rotating1`)

The type is used only through `POST /sign/rotating/prepare` and
`POST /sign/rotating/sign`. `/plan`, `/sign`, `/sign/bounded-admin` and
`/sign/component` refuse it with `rotating_signing_required`. The full contract is
in `ARCH_SIGNING.md`; the type-specific points are:

1. **Prepare.** The client sends one unsigned, ungrouped spend from the account
   with no `rekey_to`, no close-out, the account's genesis hash and a validity
   window of at most 100 rounds. The signer reads the live authorizer from its own
   node, finds stage `n` (stage address table, confirmed by derivation), sets
   `rekey_to` to stage `n + 1`, adds four resource dummies, sets fees and the group
   ID, and returns the exact unsigned group. It stores nothing and needs no approval.
2. **Sign.** The group's `rekey_to` fixes `n`. The signer re-derives stage `n + 1`
   and refuses unless it matches, rebuilds the group from the presented spend and
   requires byte equality, then runs the ordinary policy gates and operator
   approval (the rotation target counts as the signer's own address). Under the
   account lock it re-reads the chain and refuses unless stage `n` is still the
   authorizer (`rotating_stage_changed`), `first_valid` is at most 2 rounds ahead
   of the current round, and at least 10 rounds remain before `last_valid`. It
   proves stage `n + 1` can sign (`CheckStageOpens`), signs, verifies, writes a
   `ROTATING_RELEASE` audit entry (account, TxID, stage, `last_valid`, tree and
   leaf index), records the release in memory and responds.
3. **Open test.** `CheckStageOpens` test-signs with the target stage's Ed25519
   and Falcon keys over a fixed label hash (`SHA-256("APLANE_ROTATING_XMSS_V1
   stage open test")`, not a TxID, so it authorizes nothing) and checks that the
   program embeds the cached tree's root, seed and range. **It never signs with an
   XMSS leaf**, so a target stage keeps all 64 leaves for spends.

### 8.1 Leaf selection

The signer, not the client, chooses the leaf, under the account lock and from its
release memory:

- a transaction the stage has already released keeps its leaf, so an identical
  retry reproduces the identical signature;
- otherwise the first byte of the TxID picks a leaf inside the stage's range, and
  the first unused leaf upward from it (wrapping) is taken, so two signers sharing
  a seed and no memory collide one time in 64 rather than always;
- if all 64 leaves are used, the pick is reused and **reported**.

State chooses the leaf, never whether to sign. An audit write failure does not
withhold the signature.

### 8.2 Release memory and alerts

The signer keeps the newest release per account in process memory (stage, TxID,
`last_valid`, every leaf released by the stage), rebuilt at unlock from the newest
`ROTATING_RELEASE` audit entry per account. A spend that arrives before the audit
restore finishes waits for it, bounded by its own context. Warnings and notes
(`ARCH_SIGNING.md`, Alerts):

- a release whose `last_valid` has passed while its stage is still the authorizer
  raises a warning: the transaction cannot confirm and the revealed keys still
  control the account;
- a stage that released a second, different transaction over any leaf, or exhausted
  its 64 leaves, is marked **reused**, and warns until the account moves past it
  (the profile's `OneTimeStage` flag).

### 8.3 Stage table worker and recovery

While unlocked, a background worker reads each rotating account's authorizer from
the signer's own node after unlock and about every 30 seconds, extends the stage
address table to `rotating.stage_horizon` stages past the live stage, builds the
next tree ahead of need, and publishes status. An authorizer not in the table is
classified as stage 0, a table stage, a credential this signer holds (`held_key`),
or `unknown`. Only an unknown authorizer triggers a bounded recovery search
(`rotating.recovery_max_stages`, default 1,024, `rotating.recovery_timeout`), and
`POST /admin/rotating/recover` lets an operator grant their own budget. A stage is
accepted only when its derived address equals the chain's authorizer.

## 9. Security properties and claims

What the type claims:

- **Normal operation.** Every stage signs once. A forgery needs a break of
  Falcon-1024, Ed25519 and SHA-256 at once.
- **Bounded exposure.** A stage's keys control the account only until the spend
  that reveals them, or a later rotation, confirms. The successor's program
  embeds a different leaf range (and, at tree boundaries, a different tree), so
  the retired range cannot sign for it.
- **Leaf reuse.** A leaf must sign one message. A stage normally uses one leaf per
  transaction, so it can release up to 64 distinct transactions before any leaf
  repeats. A repeated leaf weakens that leaf's one-time property for the rest of
  that stage; the stage then rests on Falcon-1024 and Ed25519 until the next
  rotation lands. Nothing prevents a second signature; the signer reports it.
  Rollback, lost audit history and independent signers sharing a seed can cause
  reuse before 64 releases. The 64 is stage capacity, not a guarantee.
- **Checksum cap.** The cap does not weaken the one-time signature. A forger must
  dominate the released digits on all 67 chains; dominating the 64 message chains
  forces the forger's checksum to be at most the released one, dominating the three
  checksum chains forces it to be at least that, so every digit is equal. The
  argument uses only the monotone checksum encoding, not the distribution of the
  released digest. (The same grinding in a stronger form is WOTS+C of the SPHINCS+C
  proposal; the key type does not claim that paper's proof covers this construction.)
- **Network binding.** The genesis hash is in every derivation, so a seed gives
  unrelated accounts on different networks.

What the type does **not** claim:

- It is **not** a conformant stateful XMSS signer in the sense of RFC 8391 or
  NIST SP 800-208. Index management is best effort, and randomizer selection is
  checksum-bounded.
- It does not constrain what a stage may spend: any transaction type that rekeys
  to another address, does not close out, and has a window of at most 100 rounds
  is admissible. Spending policy is the signer's policy layer.
- It has no external-admin or recovery path on chain; the escape hatch is the
  seed backup (`ARCH_KEYTYPES.md`: "Design required" for rotating contracts).

## 10. Policy and transaction authority

| Property | Value |
|---|---|
| Admitted transaction types | any, subject to the rules below |
| Required | `RekeyTo` is non-zero and not the sender; no `CloseRemainderTo`; validity window <= 100 rounds |
| Signer-set | the signer always sets the rekey, to the account's next stage |
| Group shape | a single spend with four canonical dummies, signed one transaction at a time |
| Foreign rekey | `reject_foreign_rekey` does not apply to the rotation target |

See `KEYTYPE_CAPABILITIES.md` for the cross-type capability table. In it the type
shares every cell with `aplane.rotating-triple-wots.v1`, apart from the
leaf-range requirement above.

A signed position elsewhere that would rekey an account to a rotating account is
refused by a signer invariant (`ARCH_SIGNING.md`); the rotating account's address is
its stage 0 program address.

## 11. Compatibility and versioning

- v1 freezes the stage template, the six constants and their order, the checksum
  cap (511), the leaf allocation (64 per stage, 1,024 per tree), the signing
  procedure, the derivation label and tags, the key record layout, and the
  resource profile. Any change to the TEAL changes every stage address.
  Changes to those contracts mint a new key type version; they do not edit v1.
- The type is independent of `aplane.rotating-triple-wots.v1`. The two are separate
  key types with separate labels (`APLANE_ROTATING_TRIPLE_V1` versus
  `APLANE_ROTATING_XMSS_V1`) and addresses never collide by construction.
- Accounts created with pre-release development templates have different
  addresses and must be identified, not reinterpreted through v1.
- The signing flow identifier `rotating1` is unchanged; clients route on
  `signing_flow`, not on the key type string.
- The installer floor for upgrades is v0.44.0.

## 12. Evidence (tests)

| Area | Where |
|---|---|
| Stage program build, parse, salt, offsets | `lsig/rotatingxmsstriple/stage/program_test.go`, `template_dump_test.go` |
| Derivation, sign, verify, tampered fields, range violations, checksum above cap | `lsig/rotatingxmsstriple/signerops/keys_test.go` |
| Codec, generator, seed validation, registration | `lsig/rotatingxmsstriple/signerreg/register_test.go` |
| XMSS vectors from an independent oracle (`tools/xmssoracle`), RFC reference vector, 32 bounded signatures (10 with searched randomizer) | `internal/crypto/xmss` |
| Checksum boundaries (511/525, 512/555) and exhaustive step counts | `internal/crypto/xmss`, `stage` tests |
| On-chain acceptance, cost model at the step ceiling, tree rollover, five-transaction group on LocalNet | `test/integration/rotating_xmss_onchain_test.go` |
| Algod assembler agreement for salted and unsalted stages | `stage` tests (LocalNet) |

Full XMSS tree builds are skipped under the race detector
(`internal/racetest`).

## 13. Open items

- Per-key-type exit/external-admin paths for rotating contracts remain design-only.
- Hinted stage scan and an in-flight release limit remain proposed, not implemented.
- A security proof for the checksum-bounded randomizer selection beyond the
  monotone-checksum argument in §9 has not been written.
