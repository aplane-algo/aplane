# TxnBytesHex Field in SignRequest

## Overview

`TxnBytesHex` is required in every `SignRequest`. It carries the full transaction bytes (`TX` prefix + msgpack) so the signer can both derive the correct signing message for the key type and inspect the transaction for policy/UX.

## Why This Field Exists

Some signing schemes (LogicSig DSA) sign the **transaction ID hash**, while others (Ed25519) sign the **full transaction bytes**. The signer must still inspect the full transaction for policy checks and operator display, so `TxnBytesHex` provides a uniform, always-present source of truth.

## Why This Matters

Signer needs to inspect transaction details to implement security features:

1. **Auto-approve validation transactions**: Automatically approve 0 ALGO self-send transactions (validation checks)
2. **Spending limits**: Reject transactions above certain amounts
3. **Transaction filtering**: Auto-approve or reject based on transaction type, receiver, or other criteria
4. **Accurate display**: Show the operator what they're signing
5. **Audit logging**: Record detailed information about what was signed

Without transaction details, these features only worked for Ed25519 transactions.

## SignRequest (Current)

`TxnBytesHex` is present in both sign mode and foreign mode. In sign mode, `auth_address` identifies the signing key. In foreign mode (multi-party), `txn_bytes_hex` is provided without `auth_address` — the server includes the transaction in group building but does not sign it.

```go
type SignRequest struct {
    AuthAddress string            `json:"auth_address,omitempty"` // Which key to use for signing (omit for foreign mode)
    TxnSender   string            `json:"txn_sender,omitempty"`   // Actual transaction sender (for display)
    TxnBytesHex string            `json:"txn_bytes_hex,omitempty"` // Full transaction bytes (TX + msgpack)
    LsigArgs    map[string]string `json:"lsig_args,omitempty"`    // Runtime args for generic LSigs
    LsigSize    int               `json:"lsig_size,omitempty"`    // LSig size hint for foreign txns
}
```

## How It Works

The signer derives the signing message from `TxnBytesHex` based on key type:

| Key type | Message to sign | Inspection source |
|----------|-----------------|-------------------|
| `ed25519` | Full transaction bytes (`TX` + msgpack) | `TxnBytesHex` |
| LogicSig DSA (Falcon, etc.) | 32-byte transaction ID hash | `TxnBytesHex` |
| Generic LogicSig | N/A (no signature) | `TxnBytesHex` |

### Signer Processing
```go
txnBytes, _ := hex.DecodeString(req.TxnBytesHex)
// Decode txnBytes (after stripping "TX") for policy checks and display.
// The signer derives the signing message from the decoded transaction based on key type.
```

## Why Falcon Signs Hashes Instead of Full Transactions

Falcon/LogicSig transactions must sign the transaction ID (hash) rather than full bytes because:

1. **Atomic Groups**: Falcon transactions are always part of atomic groups (wrapped with dummy transactions)
2. **Group ID Requirement**: The transaction ID includes the group ID in its computation
3. **LogicSig Verification**: The on-chain LogicSig program verifies signatures against transaction IDs
4. **Algorand Protocol**: This is how LogicSig signing works in Algorand

The full transaction bytes are encoded in `TxnBytesHex` as:
```
TX prefix (2 bytes) + msgpack-encoded transaction
```

This is the same format that Ed25519 transactions sign, ensuring consistency.

## Implementation Details

### In apshell (client side)

All signing requests include `TxnBytesHex`:
```go
encodedTxn := msgpack.Encode(txn)
txnBytes := append([]byte("TX"), encodedTxn...)

requestBody := util.SignRequest{
    AuthAddress: signerAddr,
    TxnSender:   senderAddr,
    TxnBytesHex: hex.EncodeToString(txnBytes),
    // LsigArgs (optional)
}
```

### In Signer (server side)

**Validation detection** (`cmd/apsignerd/server.go`):
```go
func isValidationTransaction(messageBytes []byte, txnSender string, authAddr string) bool {
    // Skip "TX" prefix if present
    txnBytes := messageBytes
    if len(messageBytes) > 2 && messageBytes[0] == 'T' && messageBytes[1] == 'X' {
        txnBytes = messageBytes[2:]
    }

    // Decode the transaction
    var txn types.Transaction
    if err := msgpack.Decode(txnBytes, &txn); err != nil {
        return false
    }

    // Check if it's a validation transaction:
    // - Must be a payment transaction
    // - Must be 0 ALGO
    // - Sender and receiver must be the same
    return txn.Type == types.PaymentTx &&
           txn.Amount == 0 &&
           txn.Sender.String() == txn.Receiver.String()
}
```

## Coverage

`TxnBytesHex` provides full transaction visibility in **all scenarios**:

| Scenario | Coverage |
|----------|----------|
| Single standalone transaction | ✅ `TxnBytesHex` |
| Multiple transactions in atomic group | ✅ `TxnBytesHex` |
| Mixed group (Ed25519 + LogicSig) | ✅ `TxnBytesHex` |
| Foreign transaction (multi-party) | ✅ `TxnBytesHex` (no `auth_address`) |

## Benefits

1. **Unified inspection**: Signer can inspect all transactions the same way
2. **Security features**: Auto-approve, spending limits, and filtering work for all signing methods
3. **Minimal overhead**: Adds a small constant payload per request
4. **Clean separation**: What's signed (hash vs full bytes) vs. what's inspected is clearly separated

## Example Use Cases

### Auto-Approve Validation Transactions
```go
// Signer automatically approves 0 ALGO self-send validation transactions
// This works for both Ed25519 and Falcon transactions now
if config.AutoApproveValidation && isValidationTransaction(...) {
    fmt.Println("[AUTO-APPROVE] Validation transaction - automatically approved")
    approved = true
}
```

### Spending Limits (Future Feature)
```go
// Could implement spending limits that work for all transaction types
if txn.Amount > maxAllowedAmount {
    return fmt.Errorf("transaction exceeds spending limit")
}
```

### Transaction Type Filtering (Future Feature)
```go
// Could auto-approve certain transaction types
if txn.Type == types.AssetTransferTx && isWhitelistedAsset(txn.AssetID) {
    approved = true
}
```

## Related Files

- `internal/util/types.go` - SignRequest type definition
- `cmd/apsignerd/server.go` - isValidationTransaction and request handling
- `lsig/falcon1024/signing/provider.go` - Falcon signing provider
- `internal/signing/ed25519.go` - Ed25519 signing implementation
- `internal/signing/mixed.go` - Mixed atomic group signing
- `internal/signing/multi.go` - Multi-transaction signing
