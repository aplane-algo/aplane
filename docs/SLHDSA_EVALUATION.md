# Rotating SLH-DSA evaluation record

Status: **experimental; independent security review and production qualification
are pending**. This record covers `aplane.rotating-triple-slhdsa.v1`, using the
standard SLH-DSA-SHA2-128s parameter set. It is not a FIPS validation claim.
The library display name and description expose this status to operators.

The cryptographic and wire contract remains in
[ARCH_CRYPTO.md](ARCH_CRYPTO.md#rotating-slh-dsa-triple). This follow-up changes
preparation policy and qualification evidence, not stage identities, derivation,
key files, TEAL, signing arguments, transaction restrictions or fees.

## Lifetime signing envelope

[FIPS 205, section 11](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf)
designs its parameter sets to meet their specified security categories for
up to 2^64 signed messages per key pair. That is a finite bound, not a claim
that arbitrary use of a stateless key is harmless.

For this experimental implementation, assess deployments against this deliberately
conservative envelope **per derived stage key**, across its entire lifetime:

| Assumption | Upper bound used in the assessment |
|---|---:|
| Independent copies sharing the account seed, across all restores and deployments | 1,024 |
| SLH signing invocations per second per copy, across all workers | 1,000 |
| Lifetime of each stage key | 100 years, conservatively 366 days/year |
| Aggregate invocations | 3,238,133,760,000,000, less than 2^52 |

These are assessment assumptions, **not implemented rate limits, measured hardware
ceilings or a guarantee enforced by the signer**. Their product is less than
1/4,096 of 2^64. Before production use, validate that deployment topology,
replication, throughput and lifetime fit the envelope; deployments outside it
need a revised cryptographic assessment. A single key's measured signing speed
does not constrain future implementations, accelerators or additional copies.

Count every invocation conservatively, including retries, cancelled, failed or
discarded signing attempts, and internal successor signing self-tests. Copies
activated from old backups derive the same stage keys and share the aggregate
budget. Signing the same message repeatedly is counted again; rebroadcasting
already-signed bytes does not invoke signing. Address derivation, credential
validation and signature verification alone do not invoke SLH signing.

A successful spend performs a full signing/verification self-test with the
successor key and signs the transaction with the current key. Thus it normally
invokes SLH signing twice, on different stage keys. A stage key's aggregate
includes self-tests performed before it became live and all later attempts to
spend from it. Normal rotation supplies a fresh independent key per stage.

Retain the full successor self-test: it exercises signing and verification
against the embedded public keys, beyond merely checking derivation equality.
It signs a fixed domain-specific test digest, erases its signatures and never
releases them. Deterministic repetition still counts in this conservative
assessment.

No new durable counter or leaf allocator is introduced. Release auditing remains
observational: it cannot count discarded computations or activity in other copies
and is not evidence of complete lifetime usage. The absence of a counter is
justified only within explicit finite deployment assumptions; it is not an
unlimited-use promise. The full stage-zero public record is still rederived on
credential validation.

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

Measured 2026-10-26 on Linux/amd64, AMD Ryzen AI 5 330 (4 cores/8 threads),
14 GiB RAM, Go 1.25.7, default GOMAXPROCS=8, with the command above. This was
the development workstation under ordinary system load, not an isolated or
production-qualified host. Each range is three single-operation samples with
fresh randomly generated fixtures; setup is outside the timer.

| Operation | Median seconds | Observed range, seconds | Fill passes |
|---|---:|---:|---:|
| Encrypted credential read and full validation | 0.042 | 0.041–0.062 | — |
| Successor derivation, signing and verification | 0.213 | 0.211–0.225 | — |
| Prepare, cold stage cache | 0.253 | 0.227–0.406 | — |
| Prepare, warm stage cache | 0.163 | 0.127–0.189 | — |
| Prepare and sign, cold stage cache | 0.938 | 0.806–1.005 | — |
| Prepare and sign, warm stage cache | 0.871 | 0.771–1.003 | — |
| Rebuild cache at stage 0 | 0.412 | 0.390–0.549 | 1 |
| Rebuild cache at stage 8, no hint | 1.277 | 1.247–1.294 | 3 |
| Rebuild cache at stage 8, exact hint | 1.406 | 1.236–2.172 | 3 |
| Rebuild cache at stage 64, no hint | 9.837 | 9.023–11.449 | 17 |
| Rebuild cache at stage 64, exact hint | 7.497 | 7.055–7.654 | 17 |

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
  not a substitute for review.
- Reproduce cold/warm signing and full successor checks on each intended deployment
  class, including slow hardware, competing accounts, concurrent requests and
  cancellation/lock responsiveness. Measure distributions and memory pressure.
- Measure complete daemon unlock, backup restore and long recovery with and without
  hints, including worker pacing, RPC latency and audit restoration. The small
  cache policy trades bounded foreground interference for slower large restores.
- Validate the finite lifetime envelope across actual backup/replica practices.
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
