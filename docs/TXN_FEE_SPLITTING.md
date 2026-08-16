# Group Fee Planning for LogicSig and Native-PQ Authorization

## Overview

APlane computes one required fee for the finalized unsigned group. The fee
calculation happens after required resource dummies have been appended and
before the group ID, approval components, or signatures are produced.

The client sets ordinary transaction fees from its algod SuggestedParams. The
signer verifies that ordinary requirement and then accounts for:

- one base fee factor for every transaction;
- transaction byte-pricing factors in the compiled v42 contract;
- the native-PQ scheme contribution for each native Falcon authorization;
- the v42 LogicSig program-byte factor; and
- all caller-supplied fees already present across the group.

The signer does not repair a client-created ordinary fee deficit. It raises
fees only for authorization-induced requirements and never mutates a foreign
or passthrough slot.

## LogicSig Resource Fees

LogicSig program bytes, argument bytes, and opcode cost are distinct resources.

For a final v42 group of size `N`:

```text
free_program_bytes = N * 1000
charged_program_bytes = max(0, sum(program_bytes) - free_program_bytes)
program_fee_factor = charged_program_bytes * PerByteTxnSurcharge
```

Program bytes do not force dummies on v42. Argument or opcode capacity may
still require them:

```text
N >= ceil(sum(max_opcode_cost) / 20000)

if any individual LogicSig has argument_bytes > 1000:
    N >= ceil(sum(argument_bytes) / 1000)
```

The solver finds the smallest fixed point because every added dummy also has a
small LogicSig program and opcode cost. It never adds a dummy merely to reduce
the program surcharge: another transaction costs a full base fee but buys at
most 1,000 free program bytes.

This release has no legacy sizing mode. APlane must be upgraded deliberately
before supporting a consensus contract other than v42.

## Unified Required Fee

Algorand represents fee usage in fixed-point factors where one ordinary
transaction contributes `1_000_000`. APlane sums all applicable factors over
the final group and scales once by the v42 minimum fee:

```text
required_group_fee = ceil(min_txn_fee * total_fee_factor / 1_000_000)
fee_deficit = max(0, required_group_fee - sum(existing transaction fees))
```

`charged_program_bytes * PerByteTxnSurcharge` is a fee-factor contribution,
not a microAlgo value. Native Falcon's scheme contribution is also a factor;
the ordinary transaction base must not be counted twice.

If a deficit remains, APlane distributes it across mutable signer-controlled
transactions. A top-level native-PQ slot outside the LogicSig participant set
is preferred first because that authorization creates its own PQ fee
contribution; this also lets an explicit native-PQ sponsor preserve a
LogicSig's compiled fee ceiling. LogicSig participants identified by resource
planning follow, then any remaining mutable slots. Any remainder is assigned
deterministically. Existing pooled fees count toward the requirement; APlane
does not add a second copy of a fee the caller has already paid.

Foreign unsigned entries with `lsig_resources` contribute to resource and fee
planning but are not mutated. Passthrough entries are immutable signed bytes.
If no signer-controlled transaction can cover a deficit, planning fails.

## Example: Falcon LogicSig on v42

Assume one real transaction has:

```text
program_bytes = 1804
argument_bytes = 1423   # conservative deterministic-compressed maximum
max_opcode_cost = 20000
```

The argument exceeds the individual 1,000-byte allowance, so `N = 2`. The
group contains the real transaction and one resource dummy. The two group
members provide 2,000 free program bytes, so no program surcharge is due in
this example. With a 1,000-microAlgo minimum fee, the group must pay 2,000
microAlgos total.

The actual Falcon signature is variable-length. Planning uses the proven
1,423-byte maximum before signing; signed assembly rejects a signature that
exceeds that declaration.

## Example: Priced Program Bytes

Assume a v42 group is already fixed at `N = 2`, its LogicSig programs total
4,500 bytes, and no additional dummy is required by arguments or opcode cost:

```text
charged_program_bytes = 4500 - 2000 = 2500
program_fee_factor = 2500 * 100 = 250000
```

At a 1,000-microAlgo minimum fee, that factor contributes 250 microAlgos to the
group requirement. Adding three dummies just to eliminate the surcharge would
cost 3,000 microAlgos in new base fees, so APlane pays the surcharge instead.

## Immutable and Multi-Party Groups

Pre-grouped and passthrough-bearing groups are immutable. If their existing
shape or aggregate fees do not satisfy the active consensus rules, the signer
rejects them rather than changing fees, inserting dummies, or recomputing the
group ID.

For an unsigned multi-party group, call `/plan` first. Foreign LogicSig slots
carry the selected path's structured hint:

```json
{
  "txn_bytes_hex": "545800...",
  "lsig_resources": {
    "program_bytes": 1804,
    "argument_bytes": 1423,
    "max_opcode_cost": 20000
  }
}
```

The coordinator must sign and submit the canonical transactions returned by
`/plan`, not its original drafts.

## Implementation Ownership

- `internal/lsigresource` owns closed consensus profiles and the pure resource
  fixed-point solver.
- `internal/signerapp/signing/planner_runtime.go` resolves authorization paths
  and constructs the final group shape.
- `internal/signerapp/signing/native_pq_fee.go` computes and applies the unified
  group fee.
- `internal/signing/dummy_transactions.go` owns deterministic resource-dummy
  construction and signing.

Approval output identifies server-added dummies, aggregate fee changes, native
Falcon contributions, and priced LogicSig program bytes. Policy evaluates the
final transaction bytes and fees that will actually be signed.
