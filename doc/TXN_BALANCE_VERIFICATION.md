# Balance Verification in Send Command

## Overview

The `send` command now verifies that the sender has sufficient balance before attempting to send a transaction. This prevents failed transactions due to insufficient funds and provides clear error messages.

## What Gets Verified

### For ASA (Asset) Transfers

1. **Opt-in Status**: Checks if sender is opted into the ASA
2. **Asset Balance**: Verifies sender has at least the requested amount of the asset
3. **Receiver Opt-in**: Checks if receiver is opted into the ASA (existing check)

Example error messages:
```
Error: sender ADDR... is not opted into ASA 10458941 (USDC). Opt in first using: optin usdc for alice

Error: insufficient balance: sender has 100.000000 USDC but trying to send 150.000000 USDC
```

### For ALGO Transfers

1. **Total Amount**: Checks if sender has enough for: `send_amount + transaction_fee`
2. **Transaction Fee**: Accounts for the transaction fee (default 0.001 ALGO, or custom fee if specified)
3. **Minimum Balance Warning**: Warns if the transaction would bring balance below minimum required

Example error messages:
```
Error: insufficient balance: sender has 5.000000 ALGO but trying to send 5.000000 ALGO + 0.001000 ALGO fee = 5.001000 ALGO total
```

Example warning:
```
⚠️  Warning: After this transaction, balance will be 0.099000 ALGO, below minimum balance of 0.100000 ALGO
The account may not be able to send more transactions until funded.
Sender has 5.100000 ALGO ✓
```

## Implementation Details

### GetBalance Engine Method

Balance checking is handled by the `Engine.GetBalance()` method in `internal/engine/accounts.go`:

```go
func (e *Engine) GetBalance(addressOrAlias string) (*BalanceResult, error)
```

**Parameters:**
- `addressOrAlias`: The account address or alias to check

**Returns:**
- `BalanceResult` containing balance info for ALGO and opted-in ASAs
- Error if account doesn't exist or network error occurs

### Check Order

1. Resolve addresses (sender, receiver)
2. Build signing context (determines if account is signable)
3. For ASA: Resolve ASA reference and get info
4. **Convert amount to base units**
5. **Check sender balance via `Engine.GetBalance()`** ← NEW
6. **Verify sufficient balance** ← NEW
7. Check receiver opt-in status (ASA only)
8. For ALGO: Get account info for minimum balance check
9. **Display confirmation** ← NEW
10. Send transaction

### Balance Calculation

**For ALGO:**
```go
result, _ := engine.GetBalance(address)
senderBalance := result.AlgoBalance  // Returns microAlgos
required := requestedAmount + txnFee // Both in microAlgos
valid := (senderBalance >= required)
```

**For ASA:**
```go
result, _ := engine.GetBalance(address)
// Find the asset in result.Assets by ID
valid := (assetBalance >= requestedAmount)
```

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
4. **Opt-in Guidance**: Provides exact command to opt in if needed
5. **Minimum Balance Awareness**: Warns about minimum balance requirements

## Examples

### Successful ASA Send
```
> send 10 usdc from alice to bob
Checking sender account balance...
Sender has 100.000000 USDC ✓
Checking if receiver is opted into ASA 10458941...
Receiver is opted into USDC ✓
Sending 10 USDC from ADDR... to ADDR... using Ed25519 key...
```

### Insufficient ASA Balance
```
> send 150 usdc from alice to bob
Checking sender account balance...
Error: insufficient balance: sender has 100.000000 USDC but trying to send 150.000000 USDC
```

### Insufficient ALGO Balance
```
> send 5 algo from alice to bob
Checking sender account balance...
Error: insufficient balance: sender has 4.500000 ALGO but trying to send 5.000000 ALGO + 0.001000 ALGO fee = 5.001000 ALGO total
```

### ALGO Send with Minimum Balance Warning
```
> send 4.9 algo from alice to bob
Checking sender account balance...
⚠️  Warning: After this transaction, balance will be 0.099000 ALGO, below minimum balance of 0.100000 ALGO
The account may not be able to send more transactions until funded.
Sender has 5.000000 ALGO ✓
Sending 4.9 ALGO from ADDR... to ADDR... using Ed25519 key...
```

## Technical Notes

- The balance check adds one additional blockchain API call per transaction
- This is a small overhead compared to the cost of a failed transaction
- Balance can change between check and actual send (rare, but possible if account receives funds)
- The verification happens locally before involving Signer for approval

## Limitations with Complex Atomic Groups

The current balance verification performs **static checks** - each sender's balance is verified against their current on-chain balance independently.

### Supported Patterns

The built-in `send` command supports these atomic patterns where static checks work correctly:

1. **Single sender → multiple receivers**: Total amount is summed and checked against one sender's balance
2. **Multiple senders → single receiver**: Each sender's balance is checked independently (no cross-funding)

### Unsupported Pattern: Cross-Funding Within Groups

For complex atomic groups where Transaction A funds Transaction B's sender (e.g., A sends to B, then B sends to C in the same group), static balance checks would incorrectly fail because:

- B's balance is checked against current on-chain state
- The pending inflow from A within the same group is not considered

**Current Mitigation**: Plugin-generated atomic groups (Tinyman swaps, Reti staking) bypass apshell's balance verification entirely - they build and validate their own transaction groups.

**Future Enhancement**: If apshell adds support for complex atomic patterns, a simulated group balance transition would be needed instead of static per-transaction checks.
