# Bounded Cosigner Machine-Checkable Model

> Status: TLC checked over every abstract input combination; the recorded run
> generated 531,968 distinct reachable states at depth 4 and found no
> counterexamples for `Safety`. The normal configuration exhausts the model's
> full finite state space, so no deep configuration exists for this module.

This model checks the first-party client's stage order and the security-bearing
final acceptance boundary of the `cosigned1` choreography. It complements the
legacy cosigned assembly model: first-party orchestration releases an ordinary
bounded base signature, requests the cosigner only after signer policy and
operator approval, and then uses the shared `/sign/assemble` route with the
distinct `bounded-cosigner` target kind to derive and place the declared
arguments.

A cosigned account's target takes one of three paths. A spend and a cosigned
rekey (the account's declared spending-key rekey) need the cosigner. A listed
rekey (a rekey to an address on the account's rekey-to list) needs the list's
proof and never the cosigner: the list is the owner's standing statement. The
signer's base component names the path, and the client asks the cosigner only
when that path needs it. The client's choices are inputs here: whether it asks the
cosigner (`askCosigner`) and whether it presents a signature it holds
(`presentCosigner`). A client that asks, skips, or drops wrongly is in the state
space, and assembly, which decides the path again from the canonical
transaction, must catch it. Assembly sees only what is presented: it cannot tell
whether a client asked the cosigner about a listed rekey and dropped the
answer. That the first-party client never asks is a client property, pinned by
`TestBoundedCosignerSimulateUsesUserFirstChoreography`.

BS1 is an orchestration property, not a cosigner-endpoint authorization claim.
The cosigner endpoint does not receive or verify the prior base component, and a
direct client may request a cosigner component first. Such a component cannot
produce spend output without the independently verified base authority modeled
by BS3.

The spec lives at [formal/bounded_cosigner.tla](formal/bounded_cosigner.tla).

## What it covers

| Invariant | Meaning | TLA+ predicate |
|---|---|---|
| BS1 | In the modeled first-party flow, user policy, approval, and base release precede the cosigner request | `BS1_UserFirst` |
| BS2 | A listed rekey outputs with the receipt, the base signature and the list proof, and with no cosigner signature presented | `BS2_ListedRekeyWithoutCosigner` |
| BS3 | Spend and cosigned-rekey output require a valid assembly receipt plus valid base and cosigner authorities | `BS3_CosignedAuthoritiesVerified` |
| BS4 | Exact target coverage and path-valid argument sources gate output | `BS4_DeclaredArgumentsOnly` |
| BS5 | Canonical transaction bytes remain bound | `BS5_CanonicalGroupBound` |
| A8 | Passthrough bytes are kept only with the canonical entry's txid, a signature, and no locally held cosigned signer | `A8_PassthroughTxidBound` |
| BS6 | Invalid or signer-gate-rejected paths cannot output | `BS6_InvalidNeverOutputs` |
| BS7 | Failure returns no partial group | `BS7_AtomicOutput` |

## What TLC actually verifies

`Init` enumerates every combination of path (spend, cosigned rekey, listed
rekey or invalid), finalized-plan and classification outcomes, signer policy
and approval decisions, assembly-receipt validity, signature validity, whether
the client asks the cosigner and presents its signature, the cosigner's policy, metadata stability, exact
target coverage, argument-source/path-mask validity, derived-argument success
(the Merkle proof on a spend, the list proof on a listed rekey), the three
passthrough checks (decoded txid, signature present, no locally held cosigned
signer), and canonical-byte binding. TLC checks 2,127,872 distinct states,
depth 4, with no counterexample (`formal/metrics.json`). The paths are the same
on a bounded host and a plain host: the host decides only which transactions
classify onto which path, which `classified` abstracts.

TLC then explores the real stage order:

```text
planned -> base_released -> cosigner_released -> output
                         \------------------------^   (no cosigner asked)
       \-> rejected
```

The transition predicates transcribe the relevant decision boundaries in
`internal/engine/cosigned/submit.go` and
`internal/signerapp/signing/bounded_cosigner.go`. Unlike the one-shot assembly
models, the state graph checks that the first-party orchestration's cosigner
transition is not reachable before a successful base release. It does not model arbitrary direct calls to
the cosigner endpoint.

The base gate also includes the approval-binding check
(`signing/approval_binding.go::checkApprovalBinding`): after approval and before
any component is produced, the signer refuses a plan that differs
from the one the approval covered. It is one more fail-closed conjunct inside
`BaseGate` and needs no separate state.

Validation outcomes are intentionally abstract booleans. The model checks that
the implementation consumes each outcome at the correct gate; it does not
prove Falcon cryptography, msgpack canonicalization, Merkle proof construction,
or generated TEAL.

## Mutation expectations

- Allowing `CosignerStep` from `planned` violates `BS1_UserFirst`.
- Removing the receipt conjunct or either signature conjunct from
  `AssembleStep` violates `BS3_CosignedAuthoritiesVerified`.
- Removing `AssembleStep`'s refusal of a presented cosigner signature on a
  listed rekey, or its list-proof conjunct, violates
  `BS2_ListedRekeyWithoutCosigner`; removing its cosigner conjunct on a cosigned
  path violates `BS3_CosignedAuthoritiesVerified`. Each of the three was run on
  2026-11-08 and violates `Safety`.
- Removing source-layout, coverage, or byte-binding conjuncts violates BS4 or
  BS5.
- Removing any one of the three passthrough conjuncts (decoded txid, signature
  present, no locally held cosigned signer) violates `A8_PassthroughTxidBound`.
  Each of the three was run on 2026-11-08, when A8 moved here, and violates
  `Safety`.
- Setting output on a failed branch violates BS6 or BS7.

The checked model passes its standard exhaustive run.

## Modeling choices and limits

- Validation outcomes are group-wide: a false value means at least one target
  failed. Concrete duplicate, missing-index, and per-target signature cases
  remain in Go tests. The model deliberately has no target-count input because
  it would only duplicate identical abstract states without adding a
  per-target invariant.
- `sourceLayout` abstracts the complete bounded slot contract: base,
  derived/runtime, and cosigner sources plus their path masks. The Go
  implementation and compiler tests verify the concrete order and slot sizes.
- The bounded assembly receipt is an abstract boolean. The code mints a
  Falcon-signed receipt during spend signing and verifies it against the
  bounded spending public key during assembly, before accepting the base or
  cosigner component; `receipt` abstracts that whole verification, including
  the metadata-hash and runtime-argument binding checked concretely by
  `TestBoundedAssemblyReceiptBindsRuntimeAndMetadata`.
- The external-admin branch (the signer's admin partial plus offline completion)
  was removed with the admin key; BS2 now covers the listed-rekey branch in its
  place. An uncosigned account's listed rekey goes through ordinary `/sign` and
  never reaches this choreography.
- The cosigner node does not know a target's path; it applies its own policy
  (`reject_rekey`, `rekey_policy`) to whatever it is asked. `cosignerPolicy`
  abstracts that verdict for every path.
- Liveness is not claimed. Cosigner and approval availability fail closed; the
  model is concerned with what may be released, not eventual completion.

## Cosigned-flow properties checked in Go

These invariants came from the cosigned signing model, retired with the
dedicated cosigned account in phase 5 of the account overlays; they describe
code the cosigned flow (`cosigned1`) keeps. A8 is now machine-checked above.
A1, A3, A6, A7 and A14 described the dedicated account's user component and
its assembly, and were retired with it; BS3 and BS5 cover what assembly checks
in their place. Anchors are in [FORMAL_TRACEABILITY.md](FORMAL_TRACEABILITY.md).

- **A2, direct signing rejects witness keys and cosigned accounts.** `/sign`
  refuses a witness key, which signs only cosigner components through
  `/sign/component`, and an account with a cosigner, which signs only through the
  cosigned flow.
- **A4, cosigner policy before key load.** Cosigner-role component signing
  resolves and evaluates the requested witness key's policy (its own document,
  else the cosigner default) before loading the private key; with no policy
  snapshot loaded it fails closed.
- **A5, a component selector validates the key class.** A Witness Key ID loads
  only a cosigner key whose stored key type, category, selector and
  public/private pair agree.
- **A8, passthrough bytes stay bound to their group entry.** Assembly keeps
  passthrough signed bytes only when their decoded transaction ID equals the
  canonical entry's, a signature is present, and the effective signer (sender,
  or AuthAddr when rekeyed) is not a cosigned account this signer holds.
- **A9, endpoint mapping is routing, not trust.** `/keys` resolves an
  operation-scoped route only; every required witness key needs exactly one live
  configured endpoint, with no implicit primary-signer fallback. Security still
  comes from assembly (BS3) and the on-chain program.
- **A10, component signatures are opaque to the client.** The client collects
  and forwards component signatures without verifying them, and does not link
  the verification primitives (`cmd/apshell` is pinned off
  `internal/sigconstruction/verify` and the Falcon libraries).
- **A11, the component response shape is exact.** One component per requested
  target, no unexpected or duplicate indices, the expected scheme, and on a
  bounded-base component the path it names.
- **A12, endpoint sync is atomic around hard failures.** Discovery writes no
  persisted routing state; failed endpoints contribute no routes, and usable
  results must still cover every required witness key uniquely.
- **A13, node role gates key classes.** A signer node refuses witness private
  keys; a cosigner node refuses spending keys, cosigned accounts included.
  Conflicting inventory fails closed for the whole node.
- **A15, clients route on versioned signing-flow metadata.** The cosigned
  choreography is `cosigned1`, frozen: a change mints a new label. Clients take
  `""` and `bounded1` down the plain `/sign` path, `cosigned1` through component
  orchestration and `rotating1` through the rotating flow, and refuse any other
  label, `cosigner1` included, before any component request.

## How to check

```sh
make formal-test
```

For the focused runs:

```sh
java -jar tla2tools.jar -config docs/formal/bounded_cosigner.cfg \
  docs/formal/bounded_cosigner.tla
```

## Linking back

- Architecture: [ARCH_COSIGNED.md](ARCH_COSIGNED.md#corridor-v1),
  [ARCH_BOUNDED_DSA.md](ARCH_BOUNDED_DSA.md), and
  [ARCH_COSIGNED.md](ARCH_COSIGNED.md).
- Traceability: BS1-BS7, A2, A4, A5, A8-A13 and A15 in
  [FORMAL_TRACEABILITY.md](FORMAL_TRACEABILITY.md).
- Concrete tests: `internal/signerapp/signing/bounded_cosigner_test.go`,
  `internal/engine/cosigned/submit_test.go`, and
  `internal/engine/cosigned/simulate_submit_test.go`.
