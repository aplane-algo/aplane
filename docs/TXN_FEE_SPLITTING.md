# Fee Splitting for Multi-Sender LogicSig Groups

## Overview

When multiple LogicSig accounts participate in the same atomic group, dummy
transaction fees are **split evenly** across the LogicSig transactions **the
signer actually signs**. Foreign unsigned LogicSig entries that provide an
`lsig_size` hint still contribute to the dummy **budget** calculation (they
raise how many dummies the group needs), but they do **not** carry a fee
share: the signer never rewrites the fee on a transaction it neither signs nor
verifies. If every LogicSig participant is foreign, the pooled fee falls back
to the first transaction the signer signs (never a foreign or passthrough
slot).

> **Why foreign positions are excluded.** Mutating a foreign transaction's fee
> changes bytes another party must sign and shifts the group ID, relying on an
> implicit, unenforced cross-party invariant (that a coordinator forwards the
> fee-adjusted `/plan` output, not the originally submitted bytes). Pooling only
> across signer-signed positions removes that invariant entirely. The cost is
> that the local party pays the full dummy fee in a multi-party group rather
> than splitting it with foreign parties; this is acceptable while no
> multi-party fee-splitting coordinator ships, and would be revisited (with an
> explicit `/plan`-bytes contract and a coordinator-side group-ID check)
> alongside such a feature.

## Why Fee Splitting is Needed

### The Problem

Some LogicSig verification programs are large (~3180 bytes each), requiring dummy transactions for LogicSig budget pooling:

```
Budget available per transaction: 1000 bytes
Large LogicSig size: 3180 bytes (measured: ~3041 + 139 safety margin)
Transactions needed per LogicSig: ceil(3180/1000) = 4 transactions
Dummies needed per signature: 4 - 1 = 3 dummies
```

**With 2 LogicSig senders:**
- 2 LogicSig transactions (2 × 3180 = 6360 bytes LogicSig capacity needed)
- Total capacity needed: ceil(6360/1000) = 7 slots
- Dummies needed: 7 - 2 = **5 dummy transactions**

Each dummy has a minimum fee (typically 1000 microAlgos), so **someone needs to pay for them**.

### The Solution

Instead of making the first sender pay for all dummies (unfair), we **split the cost evenly** across the LogicSig participants the signer signs. Foreign participants raise the budget but are never charged a share (see Overview).

## How It Works

### Fee Calculation Formula

```go
totalDummyFees = dummyCount × minFee
feePerLSig = totalDummyFees ÷ lsigCount
remainder = totalDummyFees % lsigCount

// Each LSig pays their share
for each LogicSig transaction:
    transaction.Fee += feePerLSig

// First LSig gets any remainder (ensures exact total)
firstLSig.Fee += remainder
```

Dummy fees are additive to each LogicSig transaction's existing fee. If a
caller sets a high flat fee for other fee-pooling purposes, APlane preserves
that caller-specified fee and adds the signer-required dummy fee share on top;
the existing fee is not treated as already covering dummy transaction fees.

For example, if a LogicSig transaction starts with a 2,000,000 microAlgo
fee and signer planning requires 4,000 microAlgos of dummy fees for that
participant, the final fee is 2,004,000 microAlgos.

### Example 1: Two LSig Senders (Even Split)

**Setup:**
- 2 LogicSig transactions
- 5 dummies needed
- minFee = 1000 microAlgos

**Calculation:**
```
totalDummyFees = 5 × 1000 = 5000 microAlgos
feePerLSig = 5000 ÷ 2 = 2500 microAlgos
remainder = 5000 % 2 = 0 microAlgos

JUNK2 fee: 1000 (base) + 2500 (dummies) + 0 (remainder) = 3500 microAlgos
JUNK3 fee: 1000 (base) + 2500 (dummies) = 3500 microAlgos

Total fees: 7000 microAlgos (2 × 1000 base + 5 × 1000 dummies)
```

### Example 2: Three LSig Senders (With Remainder)

**Setup:**
- 3 LogicSig transactions
- 7 dummies needed (ceil((3180 × 3) / 1000) - 3 = 7)
- minFee = 1000 microAlgos

**Calculation:**
```
totalDummyFees = 7 × 1000 = 7000 microAlgos
feePerLSig = 7000 ÷ 3 = 2333 microAlgos (integer division)
remainder = 7000 % 3 = 1 microAlgo

LSig 1 fee: 1000 + 2333 + 1 (remainder) = 3334 microAlgos
LSig 2 fee: 1000 + 2333 = 3333 microAlgos
LSig 3 fee: 1000 + 2333 = 3333 microAlgos

Total fees: 10,000 microAlgos (3 × 1000 base + 7 × 1000 dummies)
```

### Example 3: Four LSig Senders

**Setup:**
- 4 LogicSig transactions
- 9 dummies needed (ceil((3180 × 4) / 1000) - 4 = 9)
- minFee = 1000 microAlgos

**Calculation:**
```
totalDummyFees = 9 × 1000 = 9000 microAlgos
feePerLSig = 9000 ÷ 4 = 2250 microAlgos
remainder = 9000 % 4 = 0 microAlgos

Each LSig: 1000 + 2250 = 3250 microAlgos
Total fees: 13,000 microAlgos (4 × 1000 base + 9 × 1000 dummies)
```

## Implementation Details

### Code Location

**File:** `internal/signing/common.go`

**Planner-facing functions:** `CalculateDummyFees()` and `ApplyDummyFees()`

```go
func CalculateDummyFees(
    dummyCount int,
    lsigCount int,
    minFee uint64,
) (DummyFeeInfo, error)

func ApplyDummyFees(
    txns []types.Transaction,
    lsigIndices []int,
    dummyCount int,
    minFee uint64,
) (DummyFeeInfo, error)
```

`ApplyDummyFees()` delegates the actual even split to
`AdjustLSigFeesForDummies()` when LSig indices are present, and falls back to
putting dummy fees on transaction 0 only for internal cases where dummy fees
must be applied but no LSig index was identified.

### Key Features

1. **Even Distribution**
   - Total dummy fees divided by number of LogicSig transactions
   - Integer division ensures whole microAlgos

2. **Remainder Handling**
   - Any remainder from division goes to the first LSig
   - Ensures exact total (no rounding errors)
   - Maximum difference: `lsigCount - 1` microAlgos

3. **Lower-Level Incentive Fee Hook**
   - `AdjustLSigFeesForDummies()` accepts an optional incentive fee for callers
     that need to add extra fee to the first LogicSig
   - The current signer group planner uses `ApplyDummyFees()` and passes no
     incentive fee

4. **Validation**
   - All indices checked before fee adjustment
   - Error if no LogicSig transactions provided
   - Error if any index out of bounds

### When It's Used

**Triggered by:**
- The signer group planner when dummy transactions are needed for LSig budget pooling
- `/sign` and `/plan` flows that build or mutate a transaction group
- Foreign unsigned LogicSig entries with `lsig_size`, which contribute to the
  dummy budget calculation only (they raise the budget but are never charged a
  fee share) and are not signed by this signer

**NOT used for:**
- Pure Ed25519 groups (no dummies needed)
- Passthrough groups, because pre-signed transactions are immutable and the
  planner trusts the pre-formed group structure
- Pre-grouped transactions that would need extra dummies; those are rejected instead of regrouped

## Console Output

When fee splitting occurs, you'll see:

```
[GROUP] Distributed 5000 microAlgos dummy fees across 2 LSig txn(s) (~2500 each)
```

This shows:
- Number of LogicSig transactions sharing the cost
- Approximate fee per LSig (before remainder)
- Total dummy fees being distributed

Client-side verbose signing output may also summarize the mutation report:

```
Fee adjustment: +5000 µAlgos across group
```

## Fee Distribution: First-Sender-Pays vs Even Split

aplane splits the group's dummy-fee budget evenly across the paying senders
rather than letting the first sender absorb all of it.

### First sender pays all (naive)

```
Transaction Group:
  [0] JUNK2 → STAN3: Fee = 6000 microAlgos (86% of total)
  [1] JUNK3 → STAN4: Fee = 1000 microAlgos (14% of total)
  [2-6] 5 Dummies: Fee = 0 each (paid by JUNK2)

Total: 7000 microAlgos
Fairness: JUNK2 pays 6× more for equal participation
```

### Even split (aplane)

```
Transaction Group:
  [0] JUNK2 → STAN3: Fee = 3500 microAlgos (50% of total)
  [1] JUNK3 → STAN4: Fee = 3500 microAlgos (50% of total)
  [2-6] 5 Dummies: Fee = 0 each (split evenly)

Total: 7000 microAlgos
Fairness: Each sender pays a proportional share
```

## Edge Cases

### Case 1: Single LSig Sender

Single LSig groups use the same fee adjustment path. Because there is only one LSig index, that transaction receives the full dummy fee total:

```
3 dummies, 1 LSig sender:
  Total = 3000, Per = 3000, Remainder = 0
  LSig 1: 3000
```

The first-transaction fallback is reserved for internal cases where dummy fees must be applied but no LSig indices were identified.

### Case 2: Odd Number of Dummies

Remainder goes to first LSig:

```
3 dummies, 2 senders:
  Total = 3000, Per = 1500, Remainder = 0
  Sender 1: 1500 + 0 = 1500
  Sender 2: 1500

5 dummies, 3 senders:
  Total = 5000, Per = 1666, Remainder = 2
  Sender 1: 1666 + 2 = 1668 ← Gets remainder
  Sender 2: 1666
  Sender 3: 1666
```

### Case 3: Mixed with Ed25519

Ed25519 transactions pay only their own base fee (no dummy contribution):

```
Group: 2 LSig, 1 Ed25519, 5 dummies

LSig 1: 1000 + 2500 = 3500 microAlgos
LSig 2: 1000 + 2500 = 3500 microAlgos
Ed25519:  1000 = 1000 microAlgos  ← No dummy fees
Dummies:  0 each (5 × 1000 paid by LogicSig accounts)

Total: 8000 microAlgos
```

This is fair because:
- Ed25519 doesn't need dummies (small signature)
- Only LogicSig accounts benefit from LogicSig budget pooling
- Ed25519 just needs group to execute atomically

### Case 4: Variable minFee

If network conditions change minFee (rare):

```
Normal: minFee = 1000, 5 dummies → 5000 total
Congested: minFee = 2000, 5 dummies → 10,000 total

With 2 LogicSig senders:
  Normal: 2500 each
  Congested: 5000 each

The splitting ratio stays the same (50/50), absolute amounts scale.
```

## Verification

When fee splitting occurs, you'll see output like:

```
[GROUP] Distributed 5000 microAlgos dummy fees across 2 LSig txn(s) (~2500 each)
```

To verify fair splitting, check that each LogicSig transaction's fee includes its share of the dummy costs.

## Benefits

1. **Fairness** - Equal participation = equal cost
2. **Transparency** - Clear console output shows split
3. **Scalability** - Works with any number of LogicSig senders
4. **Predictability** - Simple formula: `totalDummyFees ÷ lsigCount`
5. **Accuracy** - Remainder handling ensures exact totals

## Technical Notes

### Atomicity

All fees are adjusted **before** group ID assignment, ensuring:
- Transactions can't be modified after grouping
- Fee adjustments included in group hash
- All-or-nothing execution guaranteed

### Fee Structure in Atomic Groups

Algorand allows flexible fee distribution in groups:
- **Total group fee** must meet minimum requirement
- Individual fees can be 0 as long as group total is sufficient
- We set explicit fees per transaction for clarity

### Alternative Approaches Considered

1. **First sender pays all** - Unfair for multi-party scenarios
2. **Split across ALL transactions** - Ed25519 shouldn't pay for LSig overhead
3. **Split across all LogicSig incl. foreign** - Fair, but mutates foreign bytes
   and relies on an unenforced cross-party invariant (rejected; see Overview)
4. **Split across signer-signed LogicSig only** - Fair among local participants,
   never mutates foreign bytes (current implementation)

---

**Related Documentation:**
- [TXN_MIXED_GROUPS.md](TXN_MIXED_GROUPS.md) - Mixed group signing architecture
- [ARCH_CRYPTO.md](ARCH_CRYPTO.md) - Cryptography layer architecture
- [DEV_TESTING.md](DEV_TESTING.md) - Test suite guide
