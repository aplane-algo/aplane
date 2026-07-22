# Balance Verification in Send Command

## Overview

The `send` command verifies that each sender has sufficient balance before
submitting a transaction. This prevents many avoidable submission failures and
provides clear local errors before the signer approval flow begins.

## What Gets Verified

### For ASA (Asset) Transfers

1. **Opt-in Status**: Checks if sender is opted into the ASA
2. **Asset Balance**: Verifies sender has at least the requested amount of the asset
3. **Receiver Opt-in**: Checks if receiver is opted into the ASA (existing check)

Example error messages:
```
Error: sender is not opted into asset 10458941

Error: insufficient balance: have 100.000000, need 150.000000 USDC
```

### For ALGO Transfers

1. **Total Amount**: Checks if sender has enough for: `send_amount + transaction_fee`
2. **Transaction Fee**: Accounts for the transaction fee (default 0.001 ALGO, or custom fee if specified)
3. **New Receiver Minimum**: Blocks sends below 0.1 ALGO to a receiver that appears to be a new account
4. **Minimum Balance Warning**: Warns if the transaction would bring the sender below minimum required

Example error messages:
```
Error: insufficient balance: have 5.000000, need 5.001000 ALGO

Error: recipient is a new account and needs at least 0.1 ALGO minimum balance
```

Example warning:
```
⚠️  Warning: After this transaction, balance will be 0.099000 ALGO, below minimum balance of 0.100000 ALGO
```

## Implementation Details

### Engine Preparation Methods

Balance checking for `send` is part of transaction preparation. The engine
exposes four context-aware entry points the apshell layer drives during send:

- A single-payment preparer that builds the unsigned ALGO payment and runs the
  sender balance check. Implementation: `internal/engine/payment.go` (look for
  `PreparePayment`).
- A single-transfer preparer that builds the unsigned ASA transfer and runs the
  sender opt-in, sender balance, and receiver opt-in checks. Implementation:
  `internal/engine/asa.go` (`PrepareASATransfer`).
- A group validator that statically checks each payment in an atomic group
  against on-chain balances. Implementation: `internal/engine/atomic.go`
  (`ValidateAtomicPayments`).
- A matching group validator for atomic ASA transfers. Implementation:
  `internal/engine/atomic.go` (`ValidateAtomicASATransfers`).

Each preparer returns a prepared transaction plus a `BalanceCheckResult`; the
atomic validators return one `BalanceCheckResult` per entry. `BalanceCheckResult`
is the shared shape consumed by `internal/apshellapp` for send validation and
user-facing warnings. The `balance` command still uses balance-query APIs, but
`send` does not call `Engine.GetBalance()` directly.

### Check Order

1. Resolve addresses (sender, receiver)
2. Resolve asset reference and convert the requested amount to base units
3. Select non-atomic or supported atomic send mode in `internal/apshellapp`
4. Build signing context for each sender, including rekey auth-address handling
5. Query algod account state through the engine preparation method
6. For ASA, verify sender opt-in, sender asset balance, and receiver opt-in
7. For ALGO, verify sender balance, receiver minimum-balance needs, and post-send minimum-balance warning state
8. Validate the prepared `BalanceCheckResult`
9. Sign and submit the transaction or atomic group

### Balance Calculation

For ALGO transfers, the engine fetches the sender's account from algod, derives
the effective transaction fee (default 1000 microAlgos, or the caller-supplied
fee when flat-fee mode is requested), and checks that the sender's amount
covers `send_amount + txn_fee`. Implementation: `internal/engine/payment.go`
(`checkPaymentBalances`).

For ASA transfers, the engine fetches the sender's account from algod, locates
the holding for the requested asset ID, and checks both that the holding exists
(opt-in) and that its balance covers the requested base-unit amount.
Implementation: `internal/engine/asa.go` (`checkASABalances`).

### Minimum Balance Warning

For ALGO transactions, if `(available - required) < minimum_balance`, a warning is displayed but the transaction is not blocked. This is because:
- The account may be intentionally closing out
- The account may be a temporary account
- The user may understand the implications

The warning ensures the user is informed before proceeding.

## Benefits

1. **Early Detection**: Catches insufficient balance before submitting to blockchain
2. **Clear Error Messages**: Explains exactly what's missing and by how much
3. **Fee Awareness**: Explicitly shows transaction fees in error messages
4. **Opt-in Guidance**: Identifies which sender or receiver opt-in is missing
5. **Minimum Balance Awareness**: Warns about minimum balance requirements

## Examples

### Successful ASA Send
```
> send 10 usdc from alice to bob
Sending 10 USDC from ADDR... to ADDR... using Ed25519 key...
Transaction submitted: TXID...
```

### Insufficient ASA Balance
```
> send 150 usdc from alice to bob
Error: insufficient balance: have 100.000000, need 150.000000 USDC
```

### Insufficient ALGO Balance
```
> send 5 algo from alice to bob
Error: insufficient balance: have 4.500000, need 5.001000 ALGO
```

### ALGO Send with Minimum Balance Warning
```
> send 4.9 algo from alice to bob
⚠️  Warning: After this transaction, balance will be 0.099000 ALGO, below minimum balance of 0.100000 ALGO
Sending 4.9 ALGO from ADDR... to ADDR... using Ed25519 key...
Transaction submitted: TXID...
```

## Technical Notes

- The balance check uses algod account lookups during transaction preparation
- This is a small overhead compared to the cost of a failed transaction
- Balance can change between check and actual send (rare, but possible if account receives funds)
- The verification happens locally before involving Signer for approval

## Limitations with Complex Atomic Groups

Balance verification performs **static checks** - each sender's balance is verified against their on-chain balance independently.

### Supported Patterns

The built-in `send` command supports these atomic patterns where static checks work correctly:

1. **Single sender → multiple receivers**: Each prepared payment is statically
   checked, and apshell also checks the aggregate amount for the sender before
   submission
2. **Multiple senders → single receiver**: Each sender's balance is checked independently (no cross-funding)

### Unsupported Pattern: Cross-Funding Within Groups

For complex atomic groups where Transaction A funds Transaction B's sender (e.g., A sends to B, then B sends to C in the same group), static balance checks would incorrectly fail because:

- B's balance is checked against on-chain state
- The pending inflow from A within the same group is not considered

Plugin-generated atomic groups can bypass apshell's balance verification
entirely when the plugin builds and validates its own transaction group.
Simulate mode can check the exact finalized executable group after ordinary
signing, but it does not replace the built-in `send` command's static
pre-checks.
