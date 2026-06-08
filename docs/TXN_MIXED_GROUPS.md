# Mixed Group Signing

This document explains how apshell and apsigner handle atomic groups that mix
LogicSig-signed transactions with Ed25519 or externally signed transactions.

## Overview

Some LogicSig verification programs are large enough to require extra
transactions for LogicSig budget pooling. When a group mixes LogicSig and
Ed25519 participants, the signer planner decides whether to add dummy
transactions, how to distribute dummy fees, and whether the group ID can be
preserved.

## Mixed Guarded/Non-Guarded Groups

`apshell` also supports atomic groups that mix guarded targets with ordinary
signer-managed senders. A guarded target may be a transaction whose sender is a
guarded account, or a transaction whose sender resolves through the auth cache
to a guarded effective signer/AuthAddr. If any original position has a guarded
effective signer, the client uses the guarded orchestration path for the whole
group, builds one canonical group, and signs every participant over those same
frozen bytes.

Guarded positions are signed through `/sign/component` plus `/sign/assemble`.
Ordinary signer-managed originals are signed by an intermediate primary-signer
`/sign` request over the full canonical group: ordinary originals are sign-mode
entries, guarded targets are `foreign` entries with accurate guarded-authorizer
`lsig_size` hints, and client-signed dummies are `foreign` context entries. The
resulting signed ordinary originals and dummies are then passed through to
assembly.

Ordinary `/sign` still rejects guarded account key types. A guarded authorizer
therefore never becomes a one-party `AuthAddress` request: it goes through
component signing and assembly, and assembly verifies `AuthAddr` is the guarded
account when the decoded sender differs.

The remaining limitation is policy scope. Component messages bind role and
target transaction ID; sentry policy is transaction-fact based and does not
receive a separate authorizer field. Per-authorizer allowlists would require a
versioned component message and LogicSig change.

## The Three Cases

### Case 1: Pre-grouped with Sufficient Capacity

**Condition**: Group ID present AND `total_budget >= required_budget`

**Behavior**: Sign as-is, no modifications, group ID preserved

```
Group: 10 transactions (1 large LSig + 9 others)
Budget: 10 x 1,000 = 10,000 bytes
Required: 1 x 3,180 = 3,180 bytes
Result: 10,000 >= 3,180 -> No dummies needed, sign as-is
```

**Output**:
```
[GROUP] Pre-grouped transactions (group ID: ...)
[GROUP] LSig budget: 3180 bytes needed, 10000 bytes available (10 txns x 1000)
```

### Case 2: Pre-grouped with Insufficient Capacity

**Condition**: Group ID present AND `total_budget < required_budget`

**Behavior**: Reject with error (cannot add dummies without breaking group ID)

```
Group: 2 transactions (1 large LSig + 1 Ed25519)
Budget: 2 x 1,000 = 2,000 bytes
Required: 1 x 3,180 = 3,180 bytes
Result: 2,000 < 3,180 -> Need 2 dummies, but would break group ID
```

**Error**:
```
pre-grouped transactions require 2 additional dummies for LogicSig budget but group is immutable - submit ungrouped transactions instead
```

**Workaround**: Clear group IDs before signing:
```go
emptyGroup := types.Digest{}
for i := range txns {
    txns[i].Group = emptyGroup
}
signing.SignAndSubmitViaGroup(txns, ...)
```

Only do this when the application logic can tolerate a newly computed group ID
and any dummy transactions appended by the signer.

### Case 3: Ungrouped Transactions

**Condition**: No group ID present

**Behavior**: Add dummies as needed, adjust fees, compute group ID, sign

```
Transactions: [large LSig, Ed25519] (no group ID)
Result: Add 2 dummies, compute new group ID, sign all 4
```

**Output**:
```
[GROUP] Ungrouped transactions - will compute group ID
[GROUP] LSig budget: 3180 bytes needed, 2000 bytes available (2 txns x 1000)
[GROUP] Need 2 dummy transaction(s) for additional budget
[GROUP] Distributed 2000 microAlgos dummy fees across 1 LSig txn(s) (~2000 each)
```

## LogicSig Capacity Formula

```
Total Budget = Number of Transactions x 1,000 bytes
Required Budget = Sum of signer-known LSig sizes and foreign lsig_size hints
Extra Budget Needed = max(Required Budget - Total Budget, 0)
Dummies Needed = ceil(Extra Budget Needed / 1,000)
```

### Capacity Table

| Txns | Large LSig | Budget | Required | Sufficient? | Dummies |
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

See [TXN_FEE_SPLITTING.md](TXN_FEE_SPLITTING.md) for the fee distribution algorithm and examples. Dummy fees are split across LogicSig participants; Ed25519 entries in a mixed group pay only their base fee.

## Implementation

### Server-Side Handling

The shared planning/signing pipeline handles all three cases automatically.
`/plan` and `/sign` both accept foreign entries for planning and full-group
policy/approval context. Ungrouped foreign requests may be canonicalized by the
signer; pre-grouped foreign requests are preserved when they already have
sufficient LogicSig budget. `/sign` signs only signer-owned entries, preserves
passthrough entries, and returns empty-string placeholders for foreign
positions.

```go
// Planner analyzes the group
currentBudget := len(txns) * lsig.TxLsigBudget
requiredBudget := totalLsigBytes // signer metadata + foreign lsig_size hints

if isPreGrouped && needsDummies {
    // Pre-grouped transactions are immutable: reject if dummies are needed
    return error("pre-grouped transactions require additional dummies for LogicSig budget")
}

if needsDummies {
    // Ungrouped transaction set: add dummies, adjust fees, compute group ID
    dummyTxns := CreateDummyTransactions(dummiesNeeded, sp)
    ApplyDummyFees(txns, lsigIndices, dummiesNeeded, minFee)
    allTxns := append(txns, dummyTxns...)
    gid := crypto.ComputeGroupID(allTxns)
}
// Sign signer-owned transactions and dummies; preserve passthrough slots and
// leave foreign slots unsigned.
```

### Client Usage (multi.go)

```go
// Send ungrouped transactions - server handles everything
txIDs, submittedTxns, err := signing.SignAndSubmitViaGroup(txns, authCache, signerClient, algodClient, signing.SubmitOptions{
    Verbose: true,
})
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
| `SignDummyTransactions()` | `internal/lsig/wrapper.go` | Signs dummies with embedded LogicSig |
| `calculateDummies()` | `internal/signerapp/signing/planner_runtime.go` | Calculates required dummy count from LSig sizes and group budget |
| `CalculateDummyFees()` | `internal/signing/common.go` | Calculates total dummy fees and approximate per-LSig share |
| `ApplyDummyFees()` | `internal/signing/common.go` | Planner-facing dummy fee application helper |
| `AdjustLSigFeesForDummies()` | `internal/signing/common.go` | Lower-level even split helper used by `ApplyDummyFees()` |
| `AssignGroupID()` | `internal/signing/common.go` | Helper for all-local/plugin paths that compute and assign a group ID |

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
// Group ID is preserved
```

### Good: Ungrouped Transactions

```go
// Let apsigner handle grouping
txns := []types.Transaction{lsigTxn, ed25519Txn}
// No group ID assigned
signing.SignAndSubmitViaGroup(txns, ...)
// Signer adds dummies and computes the group ID
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
// Works: signer adds dummies and computes a new group ID
```

## Smart Contract Compatibility

Many smart contracts check transaction **positions** and **properties**:

```teal
gtxn 0 TypeEnum
int pay
==

gtxn 1 Sender
addr ESCROW_ADDRESS
==
```

Adding dummies at the end does not affect checks that only reference the
original positions:
```
Original:     [pay, app]              <- positions 0, 1
With dummies: [pay, app, d, d, d]     <- positions 0, 1 still valid
```

It can break contracts that assert `Global.group_size`, depend on final
positions, or otherwise require an exact group shape. Pre-grouped requests are
preserved when they already have enough LogicSig budget for this reason.

## Summary Table

| State | Group ID? | Capacity | Outcome |
|-------|-----------|----------|---------|
| Draft | No | Any | Add dummies if needed, compute group ID |
| Finalized (large) | Yes | Sufficient | Sign as-is, preserve group ID |
| Finalized (small) | Yes | Insufficient | Error: cannot modify |
| Pure Ed25519 | Yes/No | N/A | No dummies; ungrouped multi-transaction groups may still receive a computed group ID |

## Multi-Party Signing

Two modes support multi-party signing scenarios: **passthrough** and **foreign**.

### Passthrough Mode (Pre-Signed)

For scenarios where one party already has signed transactions, use passthrough mode. This requires a pre-formed group with group ID already set.

```
1. Parties agree on group structure (including dummies):
   [A_lsig, B_lsig, dummy1, dummy2, dummy3]
   Group ID = ComputeGroupID([...])

2. Party B signs their part:
   - B signs B_lsig with their LogicSig key
   - B signs dummies with embedded LogicSig
   - Passes complete pre-signed transactions to A

3. Party A submits to apsigner:
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
- Passthrough transactions are decoded for group consistency, approval context,
  warning analysis, and audit visibility, but transaction-level hard policy is
  applied only to signer-controlled slots

### Foreign Mode (Server-Planned Groups)

For scenarios where unsigned non-local transactions should participate in
planner budget math and approval context, use foreign mode. The common workflow
starts ungrouped and lets the server build dummies, fees, and group ID. An
already pre-grouped foreign request can also be accepted when it already has
sufficient LogicSig budget and no additional dummies are needed.

```
1. Construct the intended group shape.

2. Plan: One party sends all transactions to /plan,
   marking the other party's as foreign with lsig_size hints:
   [
     {auth_address: "ALICE", txn_bytes_hex: "..."},        // Alice's txn
     {txn_bytes_hex: "...", lsig_size: 1700}               // Bob's txn (foreign)
   ]
   Server returns finalized group with dummies, fees, and group ID.

3. Local sign: Each party signs its own finalized transactions locally.

4. Sign: Each party sends the finalized group to their own /sign,
   using sign mode for owned transactions and passthrough for
   transactions already signed by the other party.

5. Assemble: Merge signed outputs if needed and submit.
```

**Key constraints:**
- Cannot mix foreign and passthrough in the same request
- Foreign mode is accepted on both `/plan` and `/sign`
- All-foreign requests are rejected on both `/plan` and `/sign`
- `/sign` returns `""` for foreign positions because those transactions are not
  signed by this signer
- Complete-group SDK convenience helpers may reject these foreign placeholders;
  use `/plan` first, then resubmit finalized foreign slots as passthrough when
  a complete signed group is required
- `lsig_size` is advisory; incorrect hints may cause insufficient budget at submission
- Foreign transactions are included in planning, approval context,
  warning analysis, and audit visibility, but transaction-level hard policy is
  applied only to signer-controlled slots

### Passthrough vs Foreign

| Aspect | Passthrough | Foreign |
|--------|-------------|---------|
| Group building | Client pre-forms signed immutable group | Server usually builds; pre-grouped foreign requests can be preserved when budget is sufficient |
| Dummy calculation | Client responsibility | Server computes for ungrouped requests and validates pre-grouped requests with `lsig_size` hints |
| Output for other party's txns | Pre-signed bytes | Canonical unsigned bytes from `/plan`, or `""` placeholders in `/sign` |
| Requires group ID? | Yes | No for server-built groups; allowed for already sufficient pre-grouped groups |
| Best for | Pre-signed finalized groups | LogicSig swaps needing dummies or unsigned full-group context |

See [ARCH_TXNFLOW.md](ARCH_TXNFLOW.md) for full protocol documentation.

## Related Documentation

- [ARCH_CRYPTO.md](ARCH_CRYPTO.md) - Cryptography layer architecture
- [ARCH_TXNFLOW.md](ARCH_TXNFLOW.md) - Transaction signing flow and passthrough mode
- [TXN_FEE_SPLITTING.md](TXN_FEE_SPLITTING.md) - Fee distribution details
- [TXN_BYTES_HEX.md](TXN_BYTES_HEX.md) - Transaction byte encoding for signer requests
