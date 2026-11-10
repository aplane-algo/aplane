# Fee Handling

How APlane divides a group's fees between the client and the signer, and how
the signer plans the fees its LogicSig and native-PQ authorization adds.

## Overview

APlane computes one required fee for the finalized unsigned group. The fee
calculation happens after required resource dummies have been appended and
before the group ID, approval components, or signatures are produced.

The client sets ordinary transaction fees from its algod SuggestedParams.
Those fees pay the client's costs, and the signer adds what its authorization
costs on top (see [Fee Ownership](#fee-ownership)). The requirement accounts
for:

- one base fee factor for every transaction;
- transaction byte-pricing factors in the compiled v42 contract;
- the native-PQ scheme contribution for each native Falcon authorization; and
- the v42 LogicSig program-byte factor.

The signer does not repair a client-created ordinary fee deficit. It raises
fees only by its authorization charge and never mutates a foreign or
passthrough slot.

## Fee Ownership

An Algorand group pays its fees as a pool, and a fee field carries no label
saying what it pays for. APlane divides the pool by who causes each cost:

- The client owns its ordinary requirement: the base and byte-pricing factors
  of the transactions it built. It also owns whatever the group spends when it
  runs, such as inner transactions drawing on the group's fee credit, which the
  signer cannot see before the group executes.
- The signer owns its authorization charge: the base fees of the resource
  dummies it appends, priced LogicSig program bytes, and native-PQ
  contributions, including those of foreign slots whose `lsig_resources` or
  `pq_scheme` hints it plans.

The signer adds its charge on top of the client's fees. A surplus the client
supplied never counts toward the charge, because the signer cannot tell a
spare fee from one reserved for inner transactions: an app call whose extra fee
funds an opcode-budget loop looks the same as an overpayment. A client that
prepays the signer's charge therefore pays it twice. Build transactions with
ordinary suggested fees, plus whatever your own execution needs, and let the
signer add its charge. [An App Call That Pays for Inner
Transactions](#example-an-app-call-that-pays-for-inner-transactions) works
through the numbers.

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

This release accepts v42 and v43, whose fee and resource rules are identical;
the v42 formulas and examples here apply to both. APlane must be upgraded
deliberately before supporting any other consensus contract.

## Unified Required Fee

Algorand represents fee usage in fixed-point factors where one ordinary
transaction contributes `1_000_000`. APlane sums all applicable factors over
the final group and scales once by the v42 minimum fee:

```text
required_group_fee   = ceil(min_txn_fee * total_fee_factor / 1_000_000)
ordinary_requirement = ceil(min_txn_fee * client_fee_factor / 1_000_000)
authorization_charge = required_group_fee - ordinary_requirement
```

`client_fee_factor` sums the base and byte-pricing factors of the client's own
transactions. The signer rejects a group whose fees total less than
`ordinary_requirement`, then adds `authorization_charge`. The group then pays at
least `required_group_fee` and keeps any surplus the client supplied.

`charged_program_bytes * PerByteTxnSurcharge` is a fee-factor contribution,
not a microAlgo value. Native Falcon's scheme contribution is also a factor;
the ordinary transaction base must not be counted twice.

APlane distributes the charge across mutable signer-controlled
transactions. A top-level native-PQ slot outside the LogicSig participant set
is preferred first because that authorization creates its own PQ fee
contribution; this also lets an explicit native-PQ sponsor preserve a
LogicSig's compiled fee ceiling. LogicSig participants identified by resource
planning follow, then any remaining mutable slots. Any remainder is assigned
deterministically. A bounded slot is never raised above its compiled
`max_fee`; a `plain1` account has none.

Foreign unsigned entries with `lsig_resources` contribute to resource and fee
planning but are not mutated. Passthrough entries are immutable signed bytes.
If no signer-controlled transaction can take the charge, or bounded fee
ceilings leave too little room for it, planning fails.

A cosigned group follows the same order. Every position of a cosigned group
is signed by this signer, and the client sends each one as the signer's own,
cosigned or not. So a native Falcon position in the group takes the charge
ahead of the cosigned account, and each position's own `max_fee` is respected.

A bounded account's `max_fee` can be below what its own transaction costs, 0
included. Generation allows that and the apadmin review warns about it.

- Such an account can't pay for its own transaction. Its transaction, an exit
  rekey included, must be in a group where another signer-controlled
  transaction takes the charge.
- The planner still never raises the bounded slot above its `max_fee`. With no
  other signer-controlled transaction that can take the charge, planning fails.
- The same holds in a cosigned group, because the client sends the other
  positions as the signer's own, as described above.

## Planning Twice

The authorization charge depends only on the group's shape (its
transactions and their sizes, the dummies, and the authorizations), never on
its fees, so it is the same however much the client paid. Running the planner
again on fees it already raised would add the charge a second time, so no path
does:

- `/plan` output for a multi-transaction group carries its group ID. Sent back
  to `/sign`, it is pre-grouped and immutable: it is checked against the full
  requirement and not raised. Cosigned and bounded component signing check a
  frozen group the same way.
- The rotating flow's sign step checks a prepared group by rebuilding it. It
  measures the charge on the presented spend, takes it off to recover the
  client's spend, and rebuilds from that.
- A single transaction carries no group ID, so the signer cannot tell a draft
  from its own output. Send the original draft to `/sign`, not the transaction
  `/plan` returned: planning the planned transaction again adds the charge
  again.

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
microAlgos total: the client's transaction pays its own 1,000 and the signer
adds the dummy's 1,000.

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

## Example: An App Call That Pays for Inner Transactions

A native Falcon key calls an app that issues two inner payments with fee 0, so
both draw on the group's fee credit. The client pays its own 1,000-microAlgo
base fee plus 2,000 for the inner payments. The native Falcon contribution adds
2,000 to the outer transaction's cost.

| | Surplus counted toward the charge | Charge added on top |
|---|---|---|
| Client pays (base + inner reserve) | 3,000 | 3,000 |
| Signer adds | 0 (3,000 already covers base + Falcon) | 2,000 |
| Group pays | 3,000 | 5,000 |
| Outer cost (base + Falcon) | 3,000 | 3,000 |
| Fee credit left for the inner payments | 0 | 2,000 |

Counting the surplus leaves no credit, so algod rejects the group at the first
inner submit even though the operator approved it. Adding the charge on top
leaves the client's 2,000 for its inner payments. A larger contract fails the
same way: a Mithras deposit from a native Falcon key lost 4,000 of the inner
fees its opcode-budget loop needed.
`test/integration/inner_fee_reserve_test.go` confirms this group on LocalNet.

## Immutable and Multi-Party Groups

Pre-grouped and passthrough-bearing groups are immutable. Their fees must
already pay the full requirement, authorization charge included. If their
existing shape or aggregate fees do not satisfy the active consensus rules,
the signer rejects them rather than changing fees, inserting dummies, or
recomputing the group ID. A party that pre-groups such a group must therefore
include the charge itself, for example by building it from `/plan` output.

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
