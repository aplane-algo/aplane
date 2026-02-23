# Fee Splitting for Multi-Sender Falcon Groups

## Overview

When multiple Falcon accounts participate in the same atomic group, dummy transaction fees are **split evenly** across all Falcon senders. This ensures fair cost distribution when different parties coordinate transactions.

## Why Fee Splitting is Needed

### The Problem

Falcon LogicSig verification programs are large (~3180 bytes each), requiring dummy transactions for LogicSig budget pooling:

```
Budget available per transaction: 1000 bytes
Falcon LogicSig size: 3180 bytes (measured: ~3041 + 139 safety margin)
Transactions needed per LogicSig: ceil(3180/1000) = 4 transactions
Dummies needed per signature: 4 - 1 = 3 dummies
```

**With 2 Falcon senders:**
- 2 Falcon transactions (2 × 3180 = 6360 bytes LogicSig capacity needed)
- Total capacity needed: ceil(6360/1000) = 7 slots
- Dummies needed: 7 - 2 = **5 dummy transactions**

Each dummy has a minimum fee (typically 1000 microAlgos), so **someone needs to pay for them**.

### The Solution

Instead of making the first sender pay for all dummies (unfair), we **split the cost evenly** across all Falcon participants.

## How It Works

### Fee Calculation Formula

```go
totalDummyFees = dummyCount × minFee
feePerFalcon = totalDummyFees ÷ falconCount
remainder = totalDummyFees % falconCount

// Each Falcon pays their share
for each Falcon transaction:
    transaction.Fee += feePerFalcon

// First Falcon gets any remainder (ensures exact total)
firstFalcon.Fee += remainder
```

### Example 1: Two Falcon Senders (Even Split)

**Setup:**
- 2 Falcon transactions
- 5 dummies needed
- minFee = 1000 microAlgos

**Calculation:**
```
totalDummyFees = 5 × 1000 = 5000 microAlgos
feePerFalcon = 5000 ÷ 2 = 2500 microAlgos
remainder = 5000 % 2 = 0 microAlgos

JUNK2 fee: 1000 (base) + 2500 (dummies) + 0 (remainder) = 3500 microAlgos
JUNK3 fee: 1000 (base) + 2500 (dummies) = 3500 microAlgos

Total fees: 7000 microAlgos (2 × 1000 base + 5 × 1000 dummies) ✓
```

### Example 2: Three Falcon Senders (With Remainder)

**Setup:**
- 3 Falcon transactions
- 7 dummies needed (ceil((3180 × 3) / 1000) - 3 = 7)
- minFee = 1000 microAlgos

**Calculation:**
```
totalDummyFees = 7 × 1000 = 7000 microAlgos
feePerFalcon = 7000 ÷ 3 = 2333 microAlgos (integer division)
remainder = 7000 % 3 = 1 microAlgo

Falcon 1 fee: 1000 + 2333 + 1 (remainder) = 3334 microAlgos
Falcon 2 fee: 1000 + 2333 = 3333 microAlgos
Falcon 3 fee: 1000 + 2333 = 3333 microAlgos

Total fees: 10,000 microAlgos (3 × 1000 base + 7 × 1000 dummies) ✓
```

### Example 3: Four Falcon Senders

**Setup:**
- 4 Falcon transactions
- 9 dummies needed (ceil((3180 × 4) / 1000) - 4 = 9)
- minFee = 1000 microAlgos

**Calculation:**
```
totalDummyFees = 9 × 1000 = 9000 microAlgos
feePerFalcon = 9000 ÷ 4 = 2250 microAlgos
remainder = 9000 % 4 = 0 microAlgos

Each Falcon: 1000 + 2250 = 3250 microAlgos
Total fees: 13,000 microAlgos (4 × 1000 base + 9 × 1000 dummies) ✓
```

## Implementation Details

### Code Location

**File:** `internal/signing/common.go`

**Function:** `AdjustLSigFeesForDummies()`

```go
func AdjustLSigFeesForDummies(
    txns []types.Transaction,
    falconIndices []int,
    dummyCount int,
    minFee uint64,
    incentiveFee uint64,
) error
```

### Key Features

1. **Even Distribution**
   - Total dummy fees divided by number of Falcon transactions
   - Integer division ensures whole microAlgos

2. **Remainder Handling**
   - Any remainder from division goes to the first Falcon
   - Ensures exact total (no rounding errors)
   - Maximum difference: `falconCount - 1` microAlgos

3. **Incentive Fee**
   - If specified, added to first Falcon only
   - Used for consensus participation eligibility (2 ALGO)
   - Independent of dummy fee splitting

4. **Validation**
   - All indices checked before fee adjustment
   - Error if no Falcon transactions provided
   - Error if any index out of bounds

### When It's Used

**Triggered by:**
- Server's `/sign` endpoint when processing ungrouped transactions
- Multiple LSig transactions from different senders in same group

**NOT used for:**
- Pure Ed25519 groups (no dummies needed)
- Pre-grouped transactions with sufficient capacity

## Console Output

When fee splitting occurs, you'll see:

```
Split dummy fees across 2 Falcon transaction(s): ~2500 microAlgos each (total: 5000 microAlgos)
```

This shows:
- Number of Falcon transactions sharing the cost
- Approximate fee per Falcon (before remainder)
- Total dummy fees being distributed

## Comparison: Before vs After

### Before (First Sender Pays All)

```
Transaction Group:
  [0] JUNK2 → STAN3: Fee = 6000 microAlgos (86% of total)
  [1] JUNK3 → STAN4: Fee = 1000 microAlgos (14% of total)
  [2-6] 5 Dummies: Fee = 0 each (paid by JUNK2)

Total: 7000 microAlgos
Fairness: ❌ JUNK2 pays 6× more for equal participation
```

### After (Fair Split)

```
Transaction Group:
  [0] JUNK2 → STAN3: Fee = 3500 microAlgos (50% of total)
  [1] JUNK3 → STAN4: Fee = 3500 microAlgos (50% of total)
  [2-6] 5 Dummies: Fee = 0 each (split evenly)

Total: 7000 microAlgos
Fairness: ✅ Each sender pays proportional share
```

## Edge Cases

### Case 1: Single LSig Sender

For single LSig transactions, fee adjustment happens in the server's `/sign` handler. The first transaction's fee is increased to cover all dummies:

```go
// Fee pooling in server handler
dummyFees := types.MicroAlgos(dummyCount) * types.MicroAlgos(sp.MinFee)
txns[0].Fee += dummyFees
```

### Case 2: Odd Number of Dummies

Remainder goes to first Falcon:

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
Group: 2 Falcon, 1 Ed25519, 5 dummies

Falcon 1: 1000 + 2500 = 3500 microAlgos
Falcon 2: 1000 + 2500 = 3500 microAlgos
Ed25519:  1000 = 1000 microAlgos  ← No dummy fees
Dummies:  0 each (5 × 1000 paid by Falcon accounts)

Total: 8000 microAlgos
```

This is fair because:
- Ed25519 doesn't need dummies (small signature)
- Only Falcon accounts benefit from LogicSig budget pooling
- Ed25519 just needs group to execute atomically

### Case 4: Variable minFee

If network conditions change minFee (rare):

```
Normal: minFee = 1000, 5 dummies → 5000 total
Congested: minFee = 2000, 5 dummies → 10,000 total

With 2 Falcon senders:
  Normal: 2500 each
  Congested: 5000 each

The splitting ratio stays the same (50/50), absolute amounts scale.
```

## Verification

When fee splitting occurs, you'll see output like:

```
Split dummy fees across 2 Falcon transaction(s): ~2500 microAlgos each (total: 5000 microAlgos)
```

To verify fair splitting, check that each Falcon transaction's fee includes its share of the dummy costs.

## Benefits

1. **Fairness** - Equal participation = equal cost
2. **Transparency** - Clear console output shows split
3. **Scalability** - Works with any number of Falcon senders
4. **Predictability** - Simple formula: `totalDummies ÷ falconCount`
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

1. ❌ **First sender pays all** - Unfair for multi-party scenarios
2. ❌ **Split across ALL transactions** - Ed25519 shouldn't pay for Falcon overhead
3. ✅ **Split across Falcon only** - Fair and logical (current implementation)

## Future Enhancements

Possible improvements:

1. **User-specified distribution** - Allow custom fee allocation
2. **Weighted splitting** - Based on transaction amounts
3. **Fee estimation** - Preview costs before signing
4. **Optimization** - Minimize total dummy count across multiple groups

---

**Related Documentation:**
- [TXN_MIXED_GROUPS.md](TXN_MIXED_GROUPS.md) - Mixed group signing architecture
- [ARCH_CRYPTO.md](ARCH_CRYPTO.md) - Cryptography layer architecture
- [USER_TESTING.md](USER_TESTING.md) - Comprehensive testing guide
