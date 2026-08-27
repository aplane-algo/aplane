# Bounded Sentry Machine-Checkable Model

> Status: TLC checked over every abstract input combination; the recorded run
> generated 199,168 distinct reachable states at depth 4 and found no
> counterexamples for `Safety`. The normal configuration exhausts the model's
> full finite state space, so no deep configuration exists for this module.

This model checks the first-party client's stage order and the security-bearing
final acceptance boundary of the `bounded-sentry1` choreography. It
complements the legacy guarded assembly model: first-party orchestration
releases an ordinary bounded base signature, requests the sentry only after
signer policy and operator approval, and then uses the shared `/sign/assemble`
route with the distinct `bounded-sentry` target kind to derive and place the
declared arguments. Its external-admin path
deliberately bypasses the sentry.

BS1 is an orchestration property, not a sentry-endpoint authorization claim.
The sentry endpoint does not receive or verify the prior base component, and a
direct client may request a sentry component first. Such a component cannot
produce spend output without the independently verified base authority modeled
by BS3.

The spec lives at [formal/bounded_sentry.tla](formal/bounded_sentry.tla).

## What it covers

| Invariant | Meaning | TLA+ predicate |
|---|---|---|
| BS1 | In the modeled first-party flow, user policy, approval, and base release precede the sentry request | `BS1_UserFirst` |
| BS2 | External-admin completion never requests or consumes a sentry | `BS2_AdminBypassesSentry` |
| BS3 | Spend output requires a valid assembly receipt plus valid base and sentry authorities | `BS3_SpendAuthoritiesVerified` |
| BS4 | Exact target coverage and path-valid argument sources gate output | `BS4_DeclaredArgumentsOnly` |
| BS5 | Passthrough and canonical transaction bytes remain bound | `BS5_CanonicalGroupBound` |
| BS6 | Invalid or signer-gate-rejected paths cannot output | `BS6_InvalidNeverOutputs` |
| BS7 | Failure returns no partial group | `BS7_AtomicOutput` |

## What TLC actually verifies

`Init` enumerates every combination of path (`spend`, `admin`, or invalid),
finalized-plan and classification outcomes, signer policy and approval
decisions, assembly-receipt validity, signature validity, metadata stability,
exact target coverage,
argument-source/path-mask validity, derived-argument success, passthrough
validity, and canonical-byte binding.

TLC then explores the real stage order:

```text
planned -> base_released -> sentry_released -> output
       \-> admin_partial --------------------> output
       \-> rejected
```

The transition predicates transcribe the relevant decision boundaries in
`internal/engine/guarded/submit.go` and
`internal/signerapp/signing/bounded_sentry.go`. Unlike the one-shot assembly
models, the depth-4 state graph checks that the first-party orchestration's
sentry transition is not reachable before a successful base release and that
the admin branch never enters it. It does not model arbitrary direct calls to
the sentry endpoint.

Validation outcomes are intentionally abstract booleans. The model checks that
the implementation consumes each outcome at the correct gate; it does not
prove Falcon cryptography, msgpack canonicalization, Merkle proof construction,
or generated TEAL.

## Mutation expectations

- Allowing `SentryStep` from `planned` violates `BS1_UserFirst`.
- Routing `admin_partial` through `SentryStep` violates
  `BS2_AdminBypassesSentry`.
- Removing the receipt conjunct or either signature conjunct from
  `AssembleStep` violates `BS3_SpendAuthoritiesVerified`.
- Removing source-layout, coverage, or byte-binding conjuncts violates BS4 or
  BS5.
- Setting output on a failed branch violates BS6 or BS7.

The checked model passes its standard exhaustive run.

## Modeling choices and limits

- Validation outcomes are group-wide: a false value means at least one target
  failed. Concrete duplicate, missing-index, and per-target signature cases
  remain in Go tests. The model deliberately has no target-count input because
  it would only duplicate identical abstract states without adding a
  per-target invariant.
- `sourceLayout` abstracts the complete bounded slot contract: base,
  derived/runtime, sentry, and admin sources plus their path masks. The Go
  implementation and compiler tests verify the concrete order and slot sizes.
- The bounded assembly receipt is an abstract boolean. The code mints a
  Falcon-signed receipt during spend signing and verifies it against the
  bounded spending public key during assembly, before accepting the base or
  sentry component; `receipt` abstracts that whole verification, including
  the metadata-hash and runtime-argument binding checked concretely by
  `TestBoundedAssemblyReceiptBindsRuntimeAndMetadata`. The admin path has no
  receipt by contract.
- The admin branch represents `/sign/bounded-admin` plus external completion.
  It requires base and admin signatures but intentionally ignores sentry policy,
  sentry signatures, and spend-only derived arguments.
- Liveness is not claimed. Sentry and approval availability fail closed; the
  model is concerned with what may be released, not eventual completion.

## How to check

```sh
make formal-test
```

For the focused runs:

```sh
java -jar tla2tools.jar -config docs/formal/bounded_sentry.cfg \
  docs/formal/bounded_sentry.tla
```

## Linking back

- Architecture: [ARCH_CORRIDOR.md](ARCH_CORRIDOR.md),
  [ARCH_BOUNDED_DSA.md](ARCH_BOUNDED_DSA.md), and
  [ARCH_SENTRY.md](ARCH_SENTRY.md).
- Legacy guarded assembly: [FORMAL_TLA_GUARDED_ASSEMBLY_MODEL.md](FORMAL_TLA_GUARDED_ASSEMBLY_MODEL.md).
- Traceability: BS1-BS7 in [FORMAL_TRACEABILITY.md](FORMAL_TRACEABILITY.md).
- Concrete tests: `internal/signerapp/signing/bounded_sentry_test.go`,
  `internal/engine/guarded/submit_test.go`, and
  `internal/engine/guarded/simulate_submit_test.go`.
