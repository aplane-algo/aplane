# Rotating SLH-DSA evaluation record

Status: **experimental; independent security review and production qualification
are pending**. This record covers `aplane.rotating-triple-slhdsa.v1`, which
signs under the SLH-DSA-SHA2-128s construction of FIPS 205 with its hypertree
rescaled to two layers of height 10 (h = 20). That is **not a FIPS 205
parameter set**, and this record is not a FIPS validation claim. The library
display name and description expose both facts to operators.

The cryptographic and wire contract remains in
[ARCH_CRYPTO.md](ARCH_CRYPTO.md#rotating-slh-dsa-triple). The rescaling
changed the stage template, stage identities, signing arguments, resource
profile and fees; the derivation, key file format and transaction
restrictions are unchanged. The primitive stays parametric: the standard
SLH-DSA-SHA2-128s shape runs through the same code under the NIST ACVP
vectors, which is the evidence that the construction is implemented
correctly, and the rescaled shape is pinned by golden vectors of its own.
The height is a build-time constant (`internal/rotatingkey.RotatingSlhdsaHeight`)
with frozen artifacts for 20 and 63, so a build of the standard shape
remains available for review and measurement; it is a different account
for the same seed, not a setting.

## Why the hypertree was rescaled

SLH-DSA-SHA2-128s carries a 63-level hypertree so that one key can sign
2^64 messages while FORS leaves are rarely reused. Its 7,856-byte signature
needs ten transactions of pooled LogicSig argument space on Algorand. A
rotating stage key signs a handful of messages: the open-test message, which
is never released, and the spends released while the stage is live, normally
one and occasionally a few when a window ages or a client rebuilds the
transaction. Five of the seven layers paid for capacity no stage uses.

The rescaled set keeps n, w, FORS and every hash function of the standard
set and shortens only the hypertree. Its signature is 4,368 bytes and the
spend group is six transactions instead of ten. Signing is faster, since two
1,024-leaf layers are fewer WOTS+ key generations than seven 512-leaf layers.
Key generation, and with it every stage address derivation, is slower: the
root is the top of a 1,024-leaf tree instead of a 512-leaf one, about 50 ms
against 22 ms on the hardware below. Stage discovery, lookahead and restore
pay that per stage; signing and the successor self-test gain more than they
lose. A two-layer tree of height 9 (h = 18) would keep derivation at the
old cost and halve the assessed bound below; height 10 was chosen for the
larger margin on a bound the signer does not enforce.

## Per-stage signing bound

The security of a FORS-based few-time scheme degrades with the number of
signatures made under one key, through reuse of FORS leaves. It degrades
gradually: each additional signature on an already-used leaf costs margin,
and nothing fails at a threshold. The standard set places up to 2^64
signatures on 2^63 leaves. The rescaled set has 2^20 leaves, so a stage key
that signs about 2^20 distinct messages is in the standard set's reuse
regime. That figure is a reference point, not a limit the design relies
on: the table below prices every usage level from honest use up to 2^16
messages per stage, and the assessment is that table. Deterministic signing
of the same message reproduces the same signature and the same leaf, which
reveals nothing new; only distinct messages count.

The signer does not count signatures per stage, and the protocol does not
bound them: a stage stays live until a spend lands, the signer deliberately
keeps no limit on releases per stage, and copies sharing a seed sign
independently. The bound is therefore a margin statement, not a rule the
signer holds, and the assessment is the cost of exceeding it, together with
an explicit operating assumption about how far a deployment can exceed it.

**The cost.** It follows the few-time analysis of the SPHINCS+ framework
(Bernstein et al., "The SPHINCS+ signature framework", 2019, section 9),
which FIPS 205 inherits. A forger chooses a message and randomizer; their
digest lands on one of the 2^h leaves pseudo-randomly. With q distinct
messages signed under the key, the number γ already signed on that leaf is
binomial(q, 2^-h), and the forgery succeeds when the digest's k FORS
indices all fall on values those γ signatures revealed, probability
(1 - (1 - 2^-a)^γ)^k. Summing over γ gives the success probability of one
digest query; its reciprocal is the forger's work in hash queries. With
a = 12, k = 14 and h = 20:

| Distinct messages per stage key | Forgery work, bits |
|---:|---:|
| 3 (honest use) | 186 |
| 100 | 180 |
| 1,000 | 175 |
| 10,000 | 167 |
| 65,536 (2^16) | 159 |
| 2^18 | 151 |
| 2^20 | 140 |
| 2^21 | 134 |
| 2^22 | 126 |
| 2^24 | 106 |

For comparison, SLH-DSA-SHA2-128s (h = 63) under the same bound gives 156
bits at 2^60 messages and 134 bits at its design limit of 2^64. So the
rescaled set exceeds the standard set's design-limit margin up to about
2^21 messages per stage, holds the 128-bit category target to about 2^22,
and erodes below it beyond that. This is a bound on the hash leg alone;
the hybrid still requires Falcon-1024 and Ed25519 on the same transaction.

**The operating assumption.** This record assumes **at most 2^16 distinct
messages per stage key**, across every copy, retry and self-test, leaving
159 bits, 25 more than the standard set claims at its own limit. What that
figure means in practice:

- A stage signs one distinct message per release. Reaching 2^16 requires
  65,536 distinct transactions signed from one stage with none landing,
  since the first to land retires the stage. At this host's rate of about
  ten signatures per second that is two hours of continuous requests from
  one signer, or proportionally less across copies sharing the seed, every
  one an approved request through policy and the approval gate.
- Throughout, every status pass reports the stage's expired release as a
  warning (`ARCH_SIGNING.md`, rotating alerts), and a rotate-only spend
  ends the stage.
- A forger who benefits must also forge Falcon-1024 and Ed25519 on the
  same transaction and land it before the legitimate spend rotates the
  stage away.

A deployment where a client could issue signing requests at that rate for
hours without an operator noticing, or where more than a handful of copies
share a seed, falls outside the assumption. The remedies are a per-stage
release rate limit, which delays rather than refuses and so cannot strand
an account, or a taller tree: each extra level of height doubles the
message count at which every row of the table is reached, at twice the
signing and derivation cost. Neither
is added here, because the assumption holds for the intended deployments
by three orders of magnitude and a counter or cap would reintroduce the
state this variant exists to avoid. Review should check the bound and the
assumption, not look for a counter.

The earlier envelope for the standard set, 1,000 signing invocations per
second per copy over 100 years, is far beyond this table and no longer
applies; the rescaled set is explicitly not suited to a key that signs at
that rate.

A successful spend performs a full signing/verification self-test with the
successor key and signs the transaction with the current key. The self-test
signs a fixed domain-specific test digest, erases its signatures and never
releases them; it is one distinct message per stage key. Retain it: it
exercises signing and verification against the embedded public keys, beyond
checking derivation equality.

No new durable counter or leaf allocator is introduced. Release auditing
remains observational: it cannot count discarded computations or activity
in other copies and is not evidence of complete usage. The full stage-zero
public record is still rederived on credential validation.

## Preparation and recovery policy

`internal/rotatingkey.Profile.Preparation` supplies local operational ceilings:

| SLH-DSA operation | Limit |
|---|---:|
| Lookahead past the resolved live stage | `min(rotating.stage_horizon, 2)` |
| Address derivations per account per background fill pass | 4 |
| Address derivations during request-time stage discovery | 4 |
| Parallel address derivations within one chunk | 1 |

Smaller caller budgets still apply. WOTS and XMSS retain their existing settings.
These are work limits, not on-chain resources or lifetime-signature limits, and
can be tuned without changing stage addresses. Concurrent operations do not share
a global CPU quota. Credential validation and required target rederivation and
successor verification add work beyond the address-discovery count.

The existing worker handles live-stage discovery before lookahead. It retains
its pacing, cancellation, unlock-generation checks, recovery allowance and
operator grants. A pass that reaches its limit saves a contiguous prefix and
reports pending work. A request that cannot yet prove the live stage returns
`rotating_stage_unproven`; a later request or recovery continues the search.

Hint probes and prefix growth share one pass budget, including probes that do not
extend the table. A correct hint locates the stage but does not skip earlier
entries: the existing prefix-complete cache contract is preserved. A restore at
stage 64 therefore needs all entries through 64, plus the requested lookahead.
An existing longer cache is retained; the ceiling limits future preparation.
No shared-tree cache is invented for independent per-stage SLH roots.

## Reproducible lifecycle measurements

Run from the repository root, without the race detector:

```sh
go test ./internal/signerapp/signing -run '^$' \
  -bench '^BenchmarkSLHLifecycle$' -benchtime=1x -count=3 -benchmem
```

The benchmark creates real encrypted credentials in an unlocked file store.
Service operations include actual credential reads and full stage-zero validation,
derivation, local verification and durable stage-cache writes. The successor
benchmark isolates full derivation/signing/verification using already-loaded key
material. The credential benchmark isolates a real encrypted read and validation.

Cold means an empty stage-address cache; warm means stages 0 through 2 are cached.
Both states rederive signing secrets. Neither means a cold OS page cache, a fresh
process or a cold passphrase unlock. Restore measurements rebuild a missing cache
to the live stage plus two, using bounded passes and real credential reads; they
exclude backup import/decryption and passphrase unlock.

Chain responses, approval and audit recording use test adapters. These numbers
exclude node/SSH latency, user approval, audit fsync, the daemon's pacing sleeps
and time between passes. They are service-work measurements, not end-to-end
restore latency or production throughput guarantees. Record hardware and ranges;
three iterations are a smoke measurement, not a tail-latency study.

Measured 2026-10-27 on Linux/amd64, AMD Ryzen AI 5 330 (4 cores/8 threads),
14 GiB RAM, Go 1.25.7, default GOMAXPROCS=8, with the command above, under
the rescaled parameter set. This was the development workstation under
ordinary system load, not an isolated or production-qualified host. Each
range is three single-operation samples with fresh randomly generated
fixtures; setup is outside the timer.

| Operation | Median seconds | Observed range, seconds | Fill passes |
|---|---:|---:|---:|
| Encrypted credential read and full validation | 0.073 | 0.063–0.100 | — |
| Successor derivation, signing and verification | 0.180 | 0.174–0.186 | — |
| Prepare, cold stage cache | 0.422 | 0.329–0.422 | — |
| Prepare, warm stage cache | 0.218 | 0.201–0.233 | — |
| Prepare and sign, cold stage cache | 1.037 | 0.986–1.042 | — |
| Prepare and sign, warm stage cache | 0.844 | 0.841–1.005 | — |
| Rebuild cache at stage 0 | 0.496 | 0.494–0.513 | 1 |
| Rebuild cache at stage 8, no hint | 1.729 | 1.696–1.829 | 3 |
| Rebuild cache at stage 8, exact hint | 1.923 | 1.727–2.160 | 3 |
| Rebuild cache at stage 64, no hint | 11.126 | 10.238–12.211 | 17 |
| Rebuild cache at stage 64, exact hint | 12.155 | 10.956–13.109 | 17 |

Against the standard set measured on 2026-10-26 on the same host, the
successor self-test is about 15% faster, prepare and sign end to end is
within noise, and every path that derives stage addresses is slower by
about 30 ms per stage, as the key generation cost above predicts: a
64-stage rebuild went from about 9.8 to about 11 seconds.

The variation does not establish a hint speedup: both paths rebuild the same
prefix, and the hinted path adds a probe. Warm preparation saves address-cache
work but does not eliminate key validation or signing. These measurements support
a small initial preparation budget; they do not qualify slower deployment
hardware or justify changing transaction validity limits. Longer recovery and
complete unlock/restore measurements remain explicit production gates below.

## Remaining production gates

- Independent review of the primitive, TEAL verifier, hybrid composition,
  derivation/domain separation, transaction binding, parsing, resource bounds
  and secret handling. NIST vectors and on-chain tests are supporting evidence,
  not a substitute for review. The rescaled parameter set has no standard
  reference: review must cover the few-time bound argument above, that the
  two-layer shape is the standard construction with no other change, and the
  rescaled golden vectors.
- Review the per-stage signing margin table above: the repeat rate, the
  per-leaf cost of a repeat, and the decision to add no counter or cap.
- Reproduce cold/warm signing and full successor checks on each intended deployment
  class, including slow hardware, competing accounts, concurrent requests and
  cancellation/lock responsiveness. Measure distributions and memory pressure.
- Measure complete daemon unlock, backup restore and long recovery with and without
  hints, including worker pacing, RPC latency and audit restoration. The small
  cache policy trades bounded foreground interference for slower large restores.
- Validate the per-stage envelope across actual backup/replica practices.
  Review any optimization that adds shared state, skips validation or changes
  self-tests before adopting it.
- Decide between deterministic and hedged SLH signing. The signer currently
  sets opt_rand to PK.seed, which FIPS 205 permits; the hedged variant is the
  standard's default and adds a fresh randomizer that gives some resistance to
  fault and side-channel attacks on the signing host. The randomizer R travels
  inside the signature, so switching is a signer-only change that alters no
  stage identity, template, verifier or stored record. Review the threat model
  for the intended signer hosts and record the choice before production.
- Exercise real-network transaction windows and post-sign refusal under slow
  signing and chain movement. Keep the current 100-round span and 10-round
  minimum remaining until deployment measurements justify any protocol change.
- Approve the final compatibility contract for production after resolving review
  findings. Current golden vectors pin implementation behavior; an incompatible
  cryptographic correction requires a new key-type version, never silent changes
  to existing stage identities.
