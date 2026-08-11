# Mixed Group Signing

This document explains how apshell and apsigner handle atomic groups that mix
LogicSig-signed transactions with Ed25519 or externally signed transactions.

## Overview

LogicSig authorization consumes program bytes, argument bytes, and opcode
capacity. Depending on the active consensus profile, a group may require
resource dummies or a program-byte fee surcharge. When a group mixes LogicSig
and native or externally signed participants, the signer planner decides the
final group shape and aggregate fee before any signature is produced.

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
entries, guarded targets are `foreign` entries with accurate selected-path
`lsig_resources` hints, and client-signed dummies are `foreign` context entries. The
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

### Case 1: Pre-grouped with Sufficient Resources

**Condition**: Group ID present and the existing group satisfies its consensus
resource and aggregate-fee requirements.

**Behavior**: Sign as-is, no modifications, group ID preserved

```
Group: 2 transactions (1 Falcon LogicSig + 1 native transaction)
LogicSig args: 1,423-byte declared maximum
Opcode ceiling: <= 40,000 across the group
Result: existing group has sufficient argument/opcode capacity; sign as-is
```

**Output**:
```
[GROUP] Pre-grouped transactions (group ID: ...)
[GROUP] LogicSig resources: program=1810 args=1423 opcode<=20001, group=2 (0 dummy)
```

### Case 2: Pre-grouped with Insufficient Resources

**Condition**: Group ID present, but the immutable group would need another
resource dummy or a fee mutation.

**Behavior**: Reject with error (cannot add dummies without breaking group ID)

```
Group: 1 Falcon LogicSig transaction
Declared args: 1,423 bytes
Result: v42 argument pooling requires N=2, but adding a dummy would break the group ID
```

**Error**:
```
immutable group requires 1 additional dummy transaction for LogicSig arguments/opcode budget; submit an ungrouped unsigned group instead
```

**Workaround**: Clear group IDs before signing:
```go
emptyGroup := types.Digest{}
for i := range txns {
    txns[i].Group = emptyGroup
}
clientsign.SignAndSubmitViaGroup(txns, ...)
```

Only do this when the application logic can tolerate a newly computed group ID
and any dummy transactions appended by the signer.

### Case 3: Ungrouped Transactions

**Condition**: No group ID present

**Behavior**: Add dummies as needed, adjust fees, compute group ID, sign

```
Transactions: [Falcon LogicSig] (no group ID)
Result: Add 1 resource dummy, compute the unified fee and new group ID, sign both
```

**Output**:
```
[GROUP] Ungrouped transactions - will compute group ID
[GROUP] LogicSig resources: program=1810 args=1423 opcode<=20001, group=2 (1 dummy)
[GROUP] Added 1 resource dummy transaction(s); final fee planning follows
```

## LogicSig Capacity Formula

```
N = final number of transactions, including dummies

v41 required N >= ceil(sum(program bytes + argument bytes) / 1,000)

v42 required N >= ceil(sum(max opcode cost) / 20,000)
if any LogicSig has more than 1,000 argument bytes:
    required N >= ceil(sum(argument bytes) / 1,000)

v42 charged program bytes = max(0, sum(program bytes) - N*1,000)
```

### v42 Examples

| Real txns | LogicSig arguments | Total opcode ceiling | Final N | Dummies |
|---:|---|---:|---:|---:|
| 1 | one 900-byte path | 20,000 | 1 | 0 |
| 1 | one 1,423-byte Falcon path | 20,000 | 2 | 1 |
| 2 | two independent 900-byte paths | 40,000 | 2 | 0 |
| 2 | 1,001 bytes and 999 bytes | 40,000 | 2 | 0 |
| 2 | two 1,423-byte paths | 40,000 | 3 | 1 |

Once any individual path exceeds 1,000 argument bytes, v42 checks the sum of
all LogicSig arguments against `N * 1,000`. Program bytes affect the fee but do
not increase `N`.

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

See [TXN_FEE_SPLITTING.md](TXN_FEE_SPLITTING.md) for unified group-fee
planning. Existing fees are pooled, and any remaining deficit is assigned only
to mutable signer-controlled slots.

## Implementation

### Server-Side Handling

The shared planning/signing pipeline handles all three cases automatically.
`/plan` and `/sign` both accept foreign entries for planning and full-group
policy/approval context. Ungrouped foreign requests may be canonicalized by the
signer; pre-grouped foreign requests are preserved when they already have
sufficient LogicSig resources and fees. `/sign` signs only signer-owned entries, preserves
passthrough entries, and returns empty-string placeholders for foreign
positions.

```go
// Planner resolves an explicit consensus profile and the selected path of
// every local or foreign LogicSig.
plan := lsigresource.Solve(profile, lsigresource.PlanInput{
    TransactionCount: uint64(len(txns)),
    LogicSigs:        selectedPathResources,
    Dummy:            dummyResources,
})

if isPreGrouped && plan.DummyCount != 0 {
    // Pre-grouped transactions are immutable: reject if dummies are needed
    return error("immutable group requires additional LogicSig resource dummies")
}

if plan.DummyCount != 0 {
    // Ungrouped transaction set: add dummies before unified fee planning.
    dummyTxns := CreateDummyTransactions(int(plan.DummyCount), sp)
    allTxns := append(txns, dummyTxns...)
}
applyGroupFees(allTxns, resourcePlan)
gid := crypto.ComputeGroupID(allTxns)
// Sign signer-owned transactions and dummies; preserve passthrough slots and
// leave foreign slots unsigned.
```

### Client Usage (multi.go)

```go
// Send ungrouped transactions - server handles everything
txIDs, submittedTxns, err := clientsign.SignAndSubmitViaGroup(txns, authCache, signerClient, algodClient, clientsign.SubmitOptions{
    Verbose: true,
})
```

The server automatically:
- Resolves consensus-specific LogicSig resource requirements
- Creates dummy transactions if needed
- Computes one consensus fee requirement across the final group
- Computes group ID for ungrouped transactions

### Shared Functions

| Function | Location | Purpose |
|----------|----------|---------|
| `CreateDummyTransactions()` | `internal/signing/dummy_transactions.go` | Creates zero-fee dummy transactions |
| `SignDummyTransactions()` | `internal/signing/dummy_transactions.go` | Signs dummies with embedded LogicSig |
| `lsigresource.Solve()` | `internal/lsigresource` | Solves the minimum group from program, argument, and opcode resources |
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
clientsign.SignAndSubmitViaGroup(txns, ...)
// Group ID is preserved
```

### Good: Ungrouped Transactions

```go
// Let apsigner handle grouping
txns := []types.Transaction{lsigTxn, ed25519Txn}
// No group ID assigned
clientsign.SignAndSubmitViaGroup(txns, ...)
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

clientsign.SignAndSubmitViaGroup(txns, ...)
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
preserved when they already have enough LogicSig resources for this reason.

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
sufficient LogicSig resources and no additional dummies are needed.

```
1. Construct the intended group shape.

2. Plan: One party sends all transactions to /plan, marking the other party's
   as foreign with structured `lsig_resources` hints:
   [
     {auth_address: "ALICE", txn_bytes_hex: "..."},
     {txn_bytes_hex: "...", lsig_resources: {
       program_bytes: 1800, argument_bytes: 1423, max_opcode_cost: 20000
     }}
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
- `lsig_resources` is advisory; incorrect hints may cause insufficient
  resources or fees at submission
- Foreign transactions are included in planning, approval context,
  warning analysis, and audit visibility, but transaction-level hard policy is
  applied only to signer-controlled slots

### Passthrough vs Foreign

| Aspect | Passthrough | Foreign |
|--------|-------------|---------|
| Group building | Client pre-forms signed immutable group | Server usually builds; pre-grouped foreign requests can be preserved when resources and fees are sufficient |
| Dummy calculation | Client responsibility | Server computes for ungrouped requests and validates pre-grouped requests with `lsig_resources` hints |
| Output for other party's txns | Pre-signed bytes | Canonical unsigned bytes from `/plan`, or `""` placeholders in `/sign` |
| Requires group ID? | Yes | No for server-built groups; allowed for already sufficient pre-grouped groups |
| Best for | Pre-signed finalized groups | LogicSig swaps needing dummies or unsigned full-group context |

See [ARCH_TXNFLOW.md](ARCH_TXNFLOW.md) for full protocol documentation.

## Related Documentation

- [ARCH_CRYPTO.md](ARCH_CRYPTO.md) - Cryptography layer architecture
- [ARCH_TXNFLOW.md](ARCH_TXNFLOW.md) - Transaction signing flow and passthrough mode
- [TXN_FEE_SPLITTING.md](TXN_FEE_SPLITTING.md) - Fee distribution details
- [TXN_BYTES_HEX.md](TXN_BYTES_HEX.md) - Transaction byte encoding for signer requests
