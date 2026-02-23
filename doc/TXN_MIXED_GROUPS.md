# Mixed Group Signing

> **Version**: 0.38+

This document explains how apshell handles atomic groups containing both Falcon and Ed25519 transactions.

## Overview

Falcon LogicSig verification programs are large (~3180 bytes), requiring "dummy" transactions to provide LogicSig budget capacity. When mixing Falcon with Ed25519 transactions in an atomic group, apshell must decide whether to add dummies and how to handle the group ID.

## The Three Cases

### Case 1: Pre-grouped with Sufficient Capacity

**Condition**: Group ID present AND `total_budget >= required_budget`

**Behavior**: Sign as-is, no modifications, group ID preserved

```
Group: 10 transactions (1 Falcon + 9 others)
Budget: 10 x 1,000 = 10,000 bytes
Required: 1 x 3,180 = 3,180 bytes
Result: 10,000 >= 3,180 -> No dummies needed, sign as-is
```

**Output**:
```
Detected pre-grouped mixed Falcon + non-Falcon atomic group
Signing without modifications, preserving group ID
```

### Case 2: Pre-grouped with Insufficient Capacity

**Condition**: Group ID present AND `total_budget < required_budget`

**Behavior**: Reject with error (cannot add dummies without breaking group ID)

```
Group: 2 transactions (1 Falcon + 1 Ed25519)
Budget: 2 x 1,000 = 2,000 bytes
Required: 1 x 3,180 = 3,180 bytes
Result: 2,000 < 3,180 -> Need dummies, but would break group ID
```

**Error**:
```
Error: cannot sign pre-grouped mixed transactions: insufficient LogicSig capacity.
Group has 2 transactions (2000 bytes budget) but needs 3180 bytes for 1 Falcon LogicSig(s).
Please provide ungrouped transactions or increase group size to at least 4 transactions
```

**Workaround**: Clear group IDs before signing:
```go
emptyGroup := types.Digest{}
for i := range txns {
    txns[i].Group = emptyGroup
}
signing.SignAndSubmitViaGroup(txns, ...)
```

### Case 3: Ungrouped Transactions

**Condition**: No group ID present

**Behavior**: Add dummies as needed, adjust fees, compute group ID, sign

```
Transactions: [Falcon, Ed25519] (no group ID)
Result: Add 3 dummies, compute new group ID, sign all 5
```

**Output**:
```
Detected ungrouped mixed Falcon + non-Falcon transactions
Adding 3 dummy transaction(s) for LogicSig capacity
Mixed atomic group detected:
  Falcon transactions: 1
  Ed25519 transactions: 1
  Dummy transactions needed: 3
  Final group size: 5
```

## LogicSig Capacity Formula

```
Total Budget = Number of Transactions x 1,000 bytes
Required Budget = 3,180 bytes x Number of Falcon Transactions
Dummies Needed = ceil(Required Budget / 1,000) - Falcon Count
```

### Capacity Table

| Txns | Falcon | Budget | Required | Sufficient? | Dummies |
|------|--------|--------|----------|-------------|---------|
| 2 | 1 | 2,000 | 3,180 | No | 2 |
| 4 | 1 | 4,000 | 3,180 | Yes | 0 |
| 7 | 2 | 7,000 | 6,360 | Yes | 0 |
| 6 | 2 | 6,000 | 6,360 | No | 1 |
| 10 | 3 | 10,000 | 9,540 | Yes | 0 |

## Group ID Immutability

### Why Group IDs Cannot Be Modified

```
GroupID = SHA-512/256(concat(encodedTxn1, encodedTxn2, ..., encodedTxnN))
```

Properties:
- **Deterministic**: Same transactions -> same group ID
- **Tamper-proof**: Any change to any transaction -> different group ID
- **Order-dependent**: [txn1, txn2] != [txn2, txn1]

Adding dummies or adjusting fees changes the hash:
```
Original:  hash([txn1, txn2])              = 0xABCD...
Modified:  hash([txn1', txn2, d1, d2, d3]) = 0x1234...
```

### Design Rationale

**Why not auto-clear insufficient pre-grouped transactions?**
- Violates principle of least surprise
- Hides potential bugs (user expected specific group ID)
- Could break other components relying on that group ID

**Why preserve sufficient pre-grouped transactions?**
- DeFi SDK integration (SDKs often pre-group)
- Smart contract compatibility
- Reduced overhead (no dummy creation)
- Predictable group hashes

## Fee Distribution

### Single Falcon Sender

First Falcon transaction pays for all dummies:
```
Falcon fee: base + (dummies x minFee)
```

### Multiple Falcon Senders

Dummy fees are split evenly across all Falcon transactions:

```go
totalDummyFees = dummyCount x minFee
feePerFalcon = totalDummyFees / falconCount
remainder = totalDummyFees % falconCount

// First Falcon gets remainder to ensure exact total
```

**Example** (2 Falcon senders, 5 dummies):
```
Total dummy fees: 5 x 1000 = 5000 microAlgos
Fee per Falcon: 5000 / 2 = 2500 microAlgos

Falcon 1: 1000 (base) + 2500 (dummies) = 3500 microAlgos
Falcon 2: 1000 (base) + 2500 (dummies) = 3500 microAlgos
Total: 7000 microAlgos
```

### Ed25519 in Mixed Groups

Ed25519 transactions pay only their base fee (no dummy contribution):
```
Falcon 1: 1000 + 2500 = 3500 microAlgos (pays dummy share)
Falcon 2: 1000 + 2500 = 3500 microAlgos (pays dummy share)
Ed25519:  1000 = 1000 microAlgos (base only)
```

This is fair because Ed25519 doesn't need LogicSig budget pooling.

## Implementation

### Server-Side Handling (handleSign)

The `/sign` endpoint handles all three cases automatically:

```go
// Server analyzes the group
totalBudget := len(txns) * 1000
requiredBudget := totalLsigBytes  // From key metadata

if isPreGrouped && needsDummies {
    // Case 2: Reject - cannot modify without policy permission
    if !policy.AllowGroupModification {
        return error("insufficient LogicSig capacity")
    }
}

if needsDummies {
    // Case 3: Add dummies, compute group ID
    dummyTxns := CreateDummyTransactions(dummiesNeeded, sp)
    allTxns := append(txns, dummyTxns...)
    AdjustLSigFeesForDummies(allTxns, lsigIndices, dummiesNeeded, minFee)
    AssignGroupID(allTxns)
}
// Sign all transactions
```

### Client Usage (multi.go)

```go
// Send ungrouped transactions - server handles everything
signing.SignAndSubmitViaGroup(txns, authCache, signerClient, algodClient, true, verbose, nil)
```

The server automatically:
- Analyzes LogicSig budget requirements
- Creates dummy transactions if needed
- Adjusts fees across LSig transactions
- Computes group ID for ungrouped transactions

### Shared Functions

| Function | Location | Purpose |
|----------|----------|---------|
| `CreateDummyTransactions()` | `internal/lsig/wrapper.go` | Creates zero-fee dummy transactions |
| `CalculateDummiesNeeded()` | `internal/lsig/wrapper.go` | Calculates required dummy count |
| `SignDummyTransactions()` | `internal/lsig/wrapper.go` | Signs dummies with embedded LogicSig |
| `AdjustLSigFeesForDummies()` | `internal/signing/common.go` | Splits fees across Falcon transactions |
| `AssignGroupID()` | `internal/signing/common.go` | Computes and assigns group ID |

## Usage Patterns

### Best: Large Pre-grouped DeFi Operation

```go
// 10+ transactions have sufficient capacity
txns := defiSdk.PrepareComplexOperation(...)  // 10 transactions
gid, _ := crypto.ComputeGroupID(txns)
for i := range txns {
    txns[i].Group = gid
}
signing.SignAndSubmitViaGroup(txns, ...)
// Works! Group ID preserved
```

### Good: Ungrouped Transactions

```go
// Let apsignerd handle grouping
txns := []types.Transaction{falconTxn, ed25519Txn}
// No group ID assigned
signing.SignAndSubmitViaGroup(txns, ...)
// Works! Signer adds dummies, computes group ID
```

### Fix: Small Pre-grouped (Clear Group IDs)

```go
// SDK returned small pre-grouped set
txns := someSdk.PrepareOperation(...)  // 2 transactions with group ID

// Clear group IDs
emptyGroup := types.Digest{}
for i := range txns {
    txns[i].Group = emptyGroup
}

signing.SignAndSubmitViaGroup(txns, ...)
// Works! Signer adds dummies, computes new group ID
```

## Smart Contract Compatibility

Smart contracts check transaction **positions** and **properties**, not group size:

```teal
gtxn 0 TypeEnum
int pay
==

gtxn 1 Sender
addr ESCROW_ADDRESS
==
```

Adding dummies at the end doesn't affect position-based checks:
```
Original:     [pay, app]              <- positions 0, 1
With dummies: [pay, app, d, d, d]     <- positions 0, 1 still valid
```

## Summary Table

| State | Group ID? | Capacity | Outcome |
|-------|-----------|----------|---------|
| Draft | No | Any | Add dummies if needed, compute group ID |
| Finalized (large) | Yes | Sufficient | Sign as-is, preserve group ID |
| Finalized (small) | Yes | Insufficient | Error: cannot modify |
| Pure Ed25519 | Yes/No | N/A | Sign as-is (no dummies needed) |

## Multi-Party Signing

Two modes support multi-party signing scenarios: **passthrough** and **foreign**.

### Passthrough Mode (Pre-Signed)

For scenarios where one party already has signed transactions, use passthrough mode. This requires a pre-formed group with group ID already set.

```
1. Parties agree on group structure (including dummies):
   [A_falcon, B_falcon, dummy1, dummy2, dummy3]
   Group ID = ComputeGroupID([...])

2. Party B signs their part:
   - B signs B_falcon with their Falcon key
   - B signs dummies with embedded LogicSig
   - Passes complete pre-signed transactions to A

3. Party A submits to apsignerd:
   Request:
   [
     {auth_address: "A_ADDR", txn_bytes_hex: "..."},  // Sign mode
     {signed_txn_hex: "...B's signed txn..."},        // Passthrough
     {signed_txn_hex: "...dummy1 signed..."},         // Passthrough
     {signed_txn_hex: "...dummy2 signed..."},         // Passthrough
     {signed_txn_hex: "...dummy3 signed..."}          // Passthrough
   ]

4. Server signs A's transaction, passes through the rest
   Returns: [A_signed, B_signed, d1_signed, d2_signed, d3_signed]
```

**Key constraints:**
- Group must be pre-formed with group ID set
- No server modifications (no dummy calculation)
- Policy still validates all transactions

### Foreign Mode (Server-Built Groups)

For scenarios where the server should build the group (dummies, fees, group ID) but not sign certain transactions, use foreign mode. This is the preferred approach for multi-party atomic swaps with Falcon keys, because the server correctly computes dummy requirements using `lsig_size` hints.

```
1. Propose: Parties agree on swap terms

2. Plan: One party sends ALL transactions to /plan,
   marking the other party's as foreign with lsig_size hints:
   [
     {auth_address: "ALICE", txn_bytes_hex: "..."},        // Alice's txn
     {txn_bytes_hex: "...", lsig_size: 1700}               // Bob's txn (foreign)
   ]
   Server returns finalized group with dummies, fees, group ID.

3. Sign: Each party sends the finalized group to their own /sign,
   marking the other party's transactions as foreign.
   Each signer signs only its own txns + dummies.
   Foreign slots return "" in the signed array.

4. Assemble: Merge signed outputs and submit.
```

**Key constraints:**
- Cannot mix with passthrough (mutually exclusive)
- All-foreign requests rejected on `/sign` (use `/plan` for preview)
- `lsig_size` is advisory — incorrect hints may cause insufficient budget at submission
- Policy still validates all transactions

### Passthrough vs Foreign

| Aspect | Passthrough | Foreign |
|--------|-------------|---------|
| Group building | Client pre-forms | Server builds |
| Dummy calculation | Client responsibility | Server handles (with `lsig_size` hints) |
| Output for other party's txns | Pre-signed bytes | `""` (empty) |
| Requires group ID? | Yes | No |
| Best for | Simple Ed25519 swaps | Falcon/LSig swaps needing dummies |

See [ARCH_TXNFLOW.md](ARCH_TXNFLOW.md) for full protocol documentation.

## Related Documentation

- [ARCH_CRYPTO.md](ARCH_CRYPTO.md) - Cryptography layer architecture
- [ARCH_TXNFLOW.md](ARCH_TXNFLOW.md) - Transaction signing flow and passthrough mode
- [TXN_FEE_SPLITTING.md](TXN_FEE_SPLITTING.md) - Fee distribution details
- [TXN_BYTES_HEX.md](TXN_BYTES_HEX.md) - Transaction inspection for Falcon
