# Anatomy of a Transaction

This document describes the information flow between apshell (client) and apsignerd (server) for transaction signing.

## Overview

aPlane supports three fundamentally different authorization mechanisms:

| Type | Example | Where Signature Goes | Server Handles |
|------|---------|---------------------|----------------|
| **Ed25519** | Native Algorand keys | `SignedTxn.Sig` | Sign with ed25519 |
| **LogicSig DSA** | Falcon-1024 | `LogicSig.Args[0]` | Sign hash, attach bytecode |
| **Generic LogicSig** | Timelock, Hashlock | No signature | Attach bytecode + ordered args |

**Key Feature**: The client sends transactions to `/sign` and receives pre-assembled signed transactions ready for submission. The server handles all complexity: key type detection, message derivation, dummy transactions, fee pooling, and group ID computation.

---

## Message-to-Sign Specification

Each key type has a specific message derivation. This is critical for security—the server and on-chain verification must use the same derivation.

### Derivation by Key Type

| Key Type | Message Derivation | Size | On-Chain Verification |
|----------|-------------------|------|----------------------|
| **Ed25519** | `"TX"` + msgpack(txn) | Variable | SDK-handled |
| **Falcon-1024 DSA** | SHA512/256(`"TX"` + msgpack(txn)) | 32 bytes | `txn TxID` in TEAL |
| **Generic LogicSig** | N/A (no signature) | - | TEAL conditions only |

### Implementation Details

**Ed25519** (standard Algorand keys):
```go
// Server (cmd/apsignerd/server.go)
messageBytes = append([]byte("TX"), msgpack.Encode(txn)...)
signature = ed25519.Sign(privateKey, messageBytes)
```
The SDK handles verification automatically when the transaction is submitted.

**Falcon-1024 DSA** (post-quantum LogicSig):
```go
// Server (cmd/apsignerd/server.go)
txnID := crypto.TransactionID(txn)  // SHA512/256("TX" + msgpack(txn))
messageBytes = txnID[:]             // 32 bytes
signature = falcon.Sign(privateKey, messageBytes)
```

On-chain TEAL verification:
```teal
txn TxID          // Push transaction ID (32 bytes)
arg 0             // Push signature (1280 bytes)
byte 0x<pubkey>   // Push public key (1793 bytes)
falcon_verify     // Verify: returns 1 if valid
```

**Key invariant**: `crypto.TransactionID(txn)` in Go produces the same value as `txn TxID` in TEAL. Both compute SHA512/256 of `"TX"` prefix + msgpack-encoded transaction.

### Why Different Derivations?

- **Ed25519**: Signs full message for SDK compatibility. The Algorand SDK expects signatures over `"TX"` + msgpack.
- **Falcon-1024**: Signs transaction ID (32 bytes) because:
  1. Falcon signatures are large (1280 bytes)—signing a hash is more efficient
  2. TEAL provides `txn TxID` opcode for verification
  3. Transaction ID uniquely identifies the transaction

### Test Vectors

The following test verifies message derivation consistency:

```go
// lsig/falcon1024/timelock/derive_test.go:TestFalconTimelockSignatureRoundTrip
txn := transaction.MakePaymentTxn(sender, receiver, amount, nil, "", sp)
txid := crypto.TransactionID(txn)        // Server-side derivation
sig, _ := kp.Sign(txid)                  // Sign the 32-byte ID
// ... wrap in LogicSig ...
_, _, err = crypto.SignLogicSigTransaction(lsig, txn)  // On-chain verification
```

---

### Group Signing Flow

The `/sign` endpoint accepts a `GroupSignRequest` containing one or more transactions:

```
┌─────────┐                                         ┌──────────┐
│ apshell │                                         │ apsignerd│
└────┬────┘                                         └────┬─────┘
     │                                                   │
     │  POST /sign                                       │
     │  ┌────────────────────────────────────────┐      │
     │  │ GroupSignRequest {                     │      │
     │  │   requests: [                          │      │
     │  │     { auth_address, txn_bytes_hex },   │      │
     │  │     { auth_address, txn_bytes_hex },   │      │
     │  │     ...                                │      │
     │  │   ]                                    │      │
     │  │ }                                      │      │
     │  └────────────────────────────────────────┘      │
     │──────────────────────────────────────────────────>│
     │                                                   │
     │                         ┌─────────────────────────┐
     │                         │ Server processing:      │
     │                         │ 1. Decode transactions  │
     │                         │ 2. Validate group       │
     │                         │ 3. Add dummies if needed│
     │                         │ 4. Compute group ID     │
     │                         │ 5. Pool fees            │
     │                         │ 6. Request approval     │
     │                         │ 7. Sign each by type    │
     │                         │ 8. Return signed bytes  │
     │                         └─────────────────────────┘
     │                                                   │
     │  200 OK                                           │
     │  ┌────────────────────────────────────────┐      │
     │  │ GroupSignResponse {                    │      │
     │  │   signed: [                            │      │
     │  │     "<signed_txn_1_hex>",              │      │
     │  │     "<signed_txn_2_hex>",              │      │
     │  │     "<dummy_txn_hex>",  // if needed   │      │
     │  │     ...                                │      │
     │  │   ]                                    │      │
     │  │ }                                      │      │
     │  └────────────────────────────────────────┘      │
     │<──────────────────────────────────────────────────│
     │                                                   │
     │  Submit all signed bytes to algod                 │
     │                                                   │
```

### Request Format

```go
type GroupSignRequest struct {
    Requests []SignRequest `json:"requests"`
}

// SignRequest supports three mutually exclusive modes:
// - Sign mode: auth_address + txn_bytes_hex (server signs with its key)
// - Passthrough mode: signed_txn_hex (already signed, included as-is)
// - Foreign mode: txn_bytes_hex without auth_address (another signer owns this txn)
type SignRequest struct {
    // Sign mode fields
    AuthAddress  string            `json:"auth_address,omitempty"`  // Which key to use for signing
    TxnSender    string            `json:"txn_sender,omitempty"`    // Transaction sender (for display)
    TxnBytesHex  string            `json:"txn_bytes_hex,omitempty"` // TX + msgpack(txn)
    LsigArgs     map[string]string `json:"lsig_args,omitempty"`     // Runtime args for generic LSigs
    LsigSize     int               `json:"lsig_size,omitempty"`     // LSig size hint for foreign txns

    // Passthrough mode field
    SignedTxnHex string `json:"signed_txn_hex,omitempty"` // Already-signed txn (msgpack, hex)
}
```

**Mode Selection:**
- If `signed_txn_hex` is provided → Passthrough mode (include as-is)
- If `auth_address` + `txn_bytes_hex` provided → Sign mode (server signs)
- If `txn_bytes_hex` without `auth_address` → Foreign mode (not signed by this signer)
- Both or neither → Error

### Response Format

```go
type GroupSignResponse struct {
    Signed    []string        `json:"signed,omitempty"`    // Signed transactions (msgpack, hex)
    Mutations *MutationReport `json:"mutations,omitempty"` // Server modifications (nil if none)
    Error     string          `json:"error,omitempty"`
}

type MutationReport struct {
    DummiesAdded     int    `json:"dummies_added,omitempty"`     // Dummy txns added for LSig budget
    GroupIDChanged   bool   `json:"group_id_changed,omitempty"`  // Group ID was computed/recomputed
    FeesModified     []int  `json:"fees_modified,omitempty"`     // Indices of fee-modified txns (0-based)
    TotalFeesDelta   int    `json:"total_fees_delta,omitempty"`  // Total fee increase (microAlgos)
    OriginalCount    int    `json:"original_count,omitempty"`    // Txns in original request
    FinalCount       int    `json:"final_count,omitempty"`       // Txns in signed response
    PassthroughCount int    `json:"passthrough_count,omitempty"` // Pre-signed txns included as-is
    ForeignCount     int    `json:"foreign_count,omitempty"`     // Foreign txns (not signed by this signer)
    Reason           string `json:"reason,omitempty"`            // e.g., "lsig_budget", "passthrough"
}
```

The `Signed` array contains pre-assembled signed transactions ready for submission. If the server added dummy transactions for LogicSig budget, they are included in the array.

The `Mutations` field provides observability into server modifications:
- **Dummies**: If `dummies_added > 0`, the server added dummy transactions to meet LogicSig byte budget requirements
- **Fees**: The `fees_modified` array lists which transactions had their fees increased to cover dummy transaction costs
- **Group ID**: If `group_id_changed` is true, the server computed a new group ID (for ungrouped transactions or when dummies were added to pre-grouped transactions)
- **Passthrough**: If `passthrough_count > 0`, some transactions were pre-signed and included as-is
- **Foreign**: If `foreign_count > 0`, some transactions belong to another signer and were not signed

---

## The `/plan` Endpoint

The `/plan` endpoint provides a **preview** of group building without signing. It performs all the same processing as `/sign` (decoding, dummy calculation, fee pooling, group ID computation) but stops before approval and signing.

**Use cases:**
- Preview how the server will modify a group (dummies, fees) before committing
- Build finalized groups for multi-party signing workflows
- Validate group structure without requiring the signer to be unlocked

**Request/Response:** Same `GroupSignRequest` / `GroupSignResponse` format as `/sign`, but the `signed` array contains the **unsigned, finalized** transaction bytes (with dummies, fees, and group ID applied). The signer does not need to be unlocked.

---

## Passthrough Mode (Multi-Party Signing)

Passthrough mode enables multi-party signing scenarios where some transactions in a group are signed by external parties.

### Use Case: Atomic Swap

```
1. Parties agree on group structure:
   [A's Falcon txn, B's Falcon txn, dummy1, dummy2, ...]
   Group ID computed and set on all transactions

2. Party B signs their Falcon transaction + dummies
   Passes to Party A: [A_unsigned, B_signed, dummies_signed]

3. Party A submits to apsignerd:
   - A's transaction: Sign mode (auth_address + txn_bytes_hex)
   - B's transaction: Passthrough mode (signed_txn_hex)
   - Dummies: Passthrough mode (signed_txn_hex)

4. apsignerd signs A's part, includes B's and dummies as-is
   Returns complete signed group

5. Party A submits to algod
```

### Request Example

```json
{
  "requests": [
    {
      "auth_address": "A_FALCON_ADDR...",
      "txn_bytes_hex": "545800..."
    },
    {
      "signed_txn_hex": "82a3736967..."
    },
    {
      "signed_txn_hex": "82a3736967..."
    }
  ]
}
```

### Constraints

1. **Pre-grouped required**: Passthrough transactions require a pre-set group ID. The server cannot add dummies or modify the group without invalidating existing signatures.

2. **Group structure is fixed**: When passthrough is used, the server trusts the pre-formed group is complete and does not calculate dummy requirements.

3. **Policy still applies**: All transactions (including passthrough) are validated against policy linters before approval.

---

## Foreign Mode (Multi-Party Group Building)

Foreign mode enables multi-party signing workflows where the server builds the complete group (dummies, fees, group ID) but does not sign transactions owned by another party.

### Use Case: Multi-Party Atomic Swap

```
1. Propose: Parties agree on swap terms

2. Plan: One party builds ALL transactions, sends to their signer's /plan
   with lsig_size hints for the other party's transactions.
   Gets back finalized group (with dummies, fees, group ID).

3. Sign: Each party sends the finalized group to their own /sign,
   marking the other party's transactions as foreign.
   Each signer signs only its own transactions + dummies,
   returns "" for foreign slots.

4. Assemble: Merge signed outputs (one non-empty entry per slot) and submit.
```

### Request Example

```json
{
  "requests": [
    {
      "auth_address": "ALICE_ADDR...",
      "txn_bytes_hex": "545800..."
    },
    {
      "txn_bytes_hex": "545800...",
      "lsig_size": 1700
    }
  ]
}
```

The second entry has `txn_bytes_hex` but no `auth_address` — this is a foreign transaction. The optional `lsig_size` hint (in bytes) tells the server how much LogicSig budget to reserve for the foreign party's key type, enabling correct dummy calculation.

### Response

Foreign entries return `""` (empty string) in the `signed` array:

```json
{
  "signed": ["82a3736967...", ""],
  "mutations": {
    "foreign_count": 1,
    "dummies_added": 2,
    "group_id_changed": true
  }
}
```

### Constraints

1. **Cannot mix with passthrough**: Passthrough requires pre-grouped transactions; foreign implies the server computes the group ID. These are mutually exclusive.

2. **All-foreign is rejected on `/sign`**: If every entry is foreign (nothing to sign), the server returns 400 with a suggestion to use `/plan` instead.

3. **Policy still applies**: All transactions (including foreign) go through policy linting.

4. **`lsig_size` is advisory**: The server trusts the hint for dummy calculation. An incorrect hint may result in insufficient LogicSig budget at submission time.

### Foreign vs Passthrough

| Aspect | Passthrough | Foreign |
|--------|-------------|---------|
| Input field | `signed_txn_hex` | `txn_bytes_hex` (no `auth_address`) |
| Pre-grouped? | Required | Not required (server computes group ID) |
| Server modifications | None (group is fixed) | Full (dummies, fees, group ID) |
| Output | Pre-signed bytes (included as-is) | `""` (not signed by this signer) |
| Use case | Include already-signed txns | Build group for multi-party signing |

---

## Server Control Flow Trace

The `/sign` endpoint (`handleSign`) has a single entry point and single success path. This trace shows all branches and error paths from request receipt to response:

```
handleSign()
│
├─► Method check
│   └─► ERROR: "Method not allowed" (not POST)
│
├─► Extract identity from context (injected by requireAuth)
│   └─► ERROR: "no authenticated identity" (401)
│
├─► JSON decode
│   └─► ERROR: "Invalid JSON"
│
├─► Empty requests check
│   └─► ERROR: "requests array is empty"
│
├─► Request mode validation (sign vs passthrough vs foreign)
│   ├─► ERROR: "cannot specify both sign fields and passthrough field"
│   ├─► ERROR: "must specify either sign fields or passthrough field"
│   ├─► ERROR: "cannot mix passthrough and foreign transactions"
│   └─► ERROR: "txn_bytes_hex is required for sign mode"
│
├─► Decode transactions loop
│   ├─► For sign mode: decode TxnBytesHex
│   │   └─► ERROR: "invalid hex encoding" / "invalid msgpack"
│   └─► For passthrough: decode SignedTxnHex, extract Transaction
│       └─► ERROR: "invalid signed transaction msgpack"
│
├─► Group consistency check
│   ├─► ERROR: "different group ID"
│   └─► ERROR: "inconsistent grouping"
│
├─► Passthrough requires pre-grouped check
│   └─► ERROR: "passthrough transactions require pre-set group ID"
│
├─► Network params validation (if multi-txn)
│   ├─► ERROR: "different genesis hash"
│   ├─► ERROR: "different genesis ID"
│   └─► ERROR: "validity windows do not overlap"
│
├─► All-foreign check (nothing to sign)
│   └─► ERROR: "no signable transactions; use /plan for preview"
│
├─► Auth addresses signable check (identity-scoped, skip passthrough + foreign)
│   └─► ERROR: key not found (for sign mode transactions only)
│
├─► Dummy calculation (skip if passthrough mode)
│   ├─► Group size limit check
│   │   └─► ERROR: "group would be X transactions (max 16)"
│   └─► Pre-grouped modification check
│       └─► ERROR: "enable allow_group_modification"
│
├─► Create dummies if needed (not in passthrough mode)
│   ├─► ERROR: "failed to create dummy transactions"
│   └─► ERROR: "failed to adjust fees"
│
├─► Recompute group ID if needed
│   └─► ERROR: "failed to compute group ID"
│
├─► Signer locked check
│   └─► ERROR: "Signer is locked"
│
├─► Policy linter (Layer 1 - hard reject, no human override)
│   ├─► ERROR: "policy linter rejected group"
│   └─► ERROR: "policy linter rejected transaction X"
│
├─► Human approval (Layer 2)
│   │
│   ├─► GROUP PATH (len(requests) > 1)
│   │   ├─► group_auto_approve: true → APPROVED
│   │   ├─► no apadmin connected → ERROR
│   │   ├─► hub.RequestSigningApproval()
│   │   │   ├─► ERROR: "group approval error"
│   │   │   └─► ERROR: "Group request rejected by operator"
│   │   └─► APPROVED
│   │
│   └─► SINGLE TXN PATH (len(requests) == 1)
│       ├─► validation txn (0 ALGO self-send) → APPROVED
│       ├─► txn_auto_approve: true → APPROVED
│       ├─► no apadmin connected → ERROR
│       ├─► hub.RequestSigningApproval()
│       │   ├─► ERROR: "txn approval error"
│       │   └─► ERROR: "Transaction rejected by operator"
│       └─► APPROVED
│
├─► Sign transactions loop (skip passthrough + foreign entries)
│   │
│   ├─► Get key material
│   │   └─► ERROR: "failed to load key"
│   │
│   ├─► BRANCH: Generic LSig (no crypto signature)
│   │   ├─► ERROR: "template not found"
│   │   ├─► ERROR: "invalid hex in arg"
│   │   ├─► ERROR: "missing required lsig arg"
│   │   └─► ERROR: "failed to sign"
│   │
│   └─► BRANCH: Ed25519 or DSA-based LogicSig
│       ├─► ERROR: "unsupported key type" (no provider)
│       ├─► BRANCH: DSA LogicSig → sign txn ID (32 bytes)
│       ├─► BRANCH: Ed25519 → sign TX+msgpack
│       ├─► ERROR: "failed to sign"
│       ├─► BRANCH: DSA → assemble LogicSig
│       │   └─► ERROR: "failed to assemble lsig txn"
│       └─► BRANCH: Ed25519 → set Sig + AuthAddr
│
├─► Sign dummy transactions (if any)
│   └─► ERROR: "failed to sign dummy transactions"
│
└─► SUCCESS: Return GroupSignResponse{Signed: [...], Mutations: {...}}
```

### Branch Summary

| Category | Branches | Description |
|----------|----------|-------------|
| Input validation | 11 error paths | Identity, decode, format, consistency, foreign checks |
| Policy linter | 2 error paths | Hard constraints, no override |
| Human approval | 2 main paths | Group vs single txn, 6 sub-branches each |
| Signing | 3 key types | Generic LSig, DSA LSig, Ed25519 |
| **Total error paths** | ~27 | All return `GroupSignResponse{Error: "..."}` |
| **Success path** | 1 | Returns `GroupSignResponse{Signed: [...], Mutations: {...}}` |

---

## Server-Side Processing by Key Type

When the server processes each transaction, it determines the signing method based on the key type for `auth_address`. Key lookups are scoped by the authenticated identity extracted from the request context (currently always `"default"`).

### 1. Ed25519 Signing

Native Algorand signing where the 64-byte signature goes in `SignedTxn.Sig`.

```
Server receives: { auth_address, txn_bytes_hex }
                          │
                          ▼
              ┌───────────────────────┐
              │ 1. Load private key   │
              │ 2. Key type: ed25519  │
              │ 3. Sign full txn bytes│
              │    (TX + msgpack)     │
              │ 4. Build SignedTxn {  │
              │      Txn: <txn>       │
              │      Sig: <64 bytes>  │
              │    }                  │
              │ 5. Return msgpack     │
              └───────────────────────┘
                          │
                          ▼
              Returns: msgpack(SignedTxn)
```

| Aspect | Value |
|--------|-------|
| Message signed | Full transaction bytes (`TX` + msgpack) |
| Signature size | 64 bytes |
| Signature location | `SignedTxn.Sig` |

### 2. LogicSig DSA Signing (e.g., Falcon-1024)

Post-quantum signatures implemented via TEAL programs. The cryptographic signature goes in `LogicSig.Args[0]`.

```
Server receives: { auth_address, txn_bytes_hex }
                          │
                          ▼
              ┌───────────────────────┐
              │ 1. Load private key   │
              │ 2. Key type: falcon   │
              │ 3. Compute txn ID hash│
              │    (32 bytes)         │
              │ 4. Sign hash with     │
              │    Falcon-1024        │
              │ 5. Load TEAL bytecode │
              │ 6. Build SignedTxn {  │
              │      Txn: <txn>       │
              │      Lsig: {          │
              │        Logic: <teal>  │
              │        Args: [<sig>]  │
              │      }                │
              │    }                  │
              │ 7. Return msgpack     │
              └───────────────────────┘
                          │
                          ▼
              Returns: msgpack(SignedTxn)
```

| Aspect | Value |
|--------|-------|
| Message signed | 32-byte transaction ID hash |
| Signature size | ~1280 bytes (Falcon-1024) |
| Signature location | `LogicSig.Args[0]` |
| TEAL verifier | Embedded in `LogicSig.Logic` |

The TEAL verifier program:
1. Extracts signature from `Args[0]`
2. Computes transaction ID
3. Verifies signature against embedded public key
4. Returns 1 (approve) or 0 (reject)

### 3. Generic LogicSig (e.g., Timelock, Hashlock)

TEAL programs that authorize transactions without cryptographic signatures. Authorization is purely through TEAL evaluation.

```
Server receives: { auth_address, txn_bytes_hex, lsig_args }
                          │
                          ▼
              ┌───────────────────────┐
              │ 1. Load key file      │
              │ 2. Key type: timelock │
              │ 3. NO CRYPTOGRAPHIC   │
              │    SIGNING            │
              │ 4. Load TEAL bytecode │
              │ 5. Order runtime args │
              │    per template def   │
              │ 6. Build SignedTxn {  │
              │      Txn: <txn>       │
              │      Lsig: {          │
              │        Logic: <teal>  │
              │        Args: [<args>] │
              │      }                │
              │    }                  │
              │ 7. Return msgpack     │
              └───────────────────────┘
                          │
                          ▼
              Returns: msgpack(SignedTxn)
```

| Aspect | Value |
|--------|-------|
| Message signed | N/A (no signing) |
| Authorization | TEAL program logic only |
| Runtime args | Client sends by name, server orders |

#### Runtime Args

Generic LogicSigs may require runtime arguments (e.g., a preimage for hashlock). The client sends args **by name**, and the server orders them according to the template definition:

**Client sends:**
```json
{
  "auth_address": "ABC123...",
  "txn_bytes_hex": "...",
  "lsig_args": {
    "preimage": "48656c6c6f"
  }
}
```

**Server looks up template and orders args for `LogicSig.Args`.**

---

## Dummy Transactions and Fee Pooling

Post-quantum signatures (e.g., Falcon ~1280 bytes) exceed Algorand's 1000-byte LogicSig budget per transaction. The server automatically adds dummy transactions to provide additional budget.

### How It Works

1. Server analyzes transactions to identify LogicSig DSA signers
2. Calculates total LogicSig budget needed
3. Creates dummy self-payment transactions to provide extra budget
4. Pools all fees onto the first transaction (dummies have fee=0)
5. Computes group ID across all transactions (main + dummies)
6. Signs and returns the complete group

### Example

For 1 Falcon transaction (1280-byte signature):
- Budget needed: 1280 bytes
- Budget per txn: 1000 bytes
- Dummies needed: `ceil(1280/1000) - 1 = 1`

The server returns 2 signed transactions: the main transaction + 1 dummy.

### Server Modification Behavior

The server may modify transactions (add dummies, adjust fees, compute group ID) depending on the input format and whether large LogicSigs are involved:

| Input | Large LSig? | Dummies Added | Fees Modified | Group ID Modified |
|-------|-------------|---------------|---------------|-------------------|
| Single ungrouped txn | No | No | No | No (stays empty) |
| Single ungrouped txn | Yes | Yes | Yes | Yes (new group ID) |
| Single pre-grouped txn | No | No | No | No (preserved) |
| Single pre-grouped txn | Yes | Policy check* | Policy check* | Policy check* |
| Multiple ungrouped txns | No | No | No | Yes (computed) |
| Multiple ungrouped txns | Yes | Yes | Yes | Yes (computed) |
| Multiple pre-grouped txns | No | No | No | No (preserved) |
| Multiple pre-grouped txns | Yes | Policy check* | Policy check* | Policy check* |

**\*Policy check:** If `allow_group_modification: true` in policy, modifications proceed. Otherwise, request is **rejected** with an error explaining insufficient LogicSig budget.

**Key insight:** Pre-grouped transactions are protected from modification by default. Ungrouped transactions are always eligible for server-side dummification and grouping.

### Modified Transaction Consistency

When transactions are modified (fees adjusted, group ID computed), the **modified transaction data** is used consistently throughout the approval flow:

- **Approval UI**: Displays the actual fees and group ID that will be signed
- **Validation checks**: Validation transactions (0 ALGO self-send) always auto-approved
- **Policy violations**: Fee thresholds checked against actual (adjusted) fees

This ensures operators approve exactly what will be signed, and policy rules evaluate the actual transaction data rather than the original request.

When modifications occur, the approval UI displays an explicit banner:
```
[MODIFIED BY SERVER]
  • Added 1 dummy transaction(s) for LSig budget
  • Fee adjustment: +1000 microAlgos across 1 LSig txn(s)
  • Group ID recomputed
```

### Relevant Policy Parameters

The following `config.yaml` policy settings affect server behavior:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `allow_group_modification` | `false` | Allow server to modify pre-grouped transactions (add dummies, change group ID). Required for large LSig with pre-grouped input. |
| `group_auto_approve` | `false` | Auto-approve all group-level requests (2+ txns) without TUI confirmation. **When true, transaction-level approval is skipped entirely.** |
| `txn_auto_approve` | `false` | Auto-approve all individual transaction signing requests. Only evaluated for single transactions. |

**Note**: Validation transactions (0 ALGO self-send) are always auto-approved.

Example `config.yaml` (policy-relevant settings):
```yaml
# Allow server to add dummies to pre-grouped transactions
allow_group_modification: true

# Auto-approve all single transactions (use with caution)
txn_auto_approve: true
```

See [`ARCH_POLICY.md`](ARCH_POLICY.md) for full policy configuration documentation.

---

## Policy and Approval

Before signing, transactions must pass through the two-layer approval system:

1. **Policy Linter**: Hard constraints - if failed, transaction is rejected (no human override)
2. **Human Approval**: Auto-approve rules or TUI approval

| Request Type | Policy Linter | Human Approval |
|--------------|---------------|----------------|
| Single txn | Txn policy linter | Txn-level: auto-approve rules or TUI |
| Group (2+ txns in client request) | Group + all txn policy linters | Group-level only: `group_auto_approve` or TUI |

**Key points**:
- "Group" means 2+ transactions in client request (server-added dummies don't change this)
- Groups never undergo per-transaction human approval
- Policy linter rejection cannot be overridden by humans

See [`ARCH_POLICY.md`](ARCH_POLICY.md) for complete details on policy linting, warnings, and auto-approve rules.

---

## Client Usage

### Simple Flow (Recommended)

```go
// Build transactions with suggested params
txns := []types.Transaction{txn1, txn2, ...}

// Sign and submit via /sign endpoint
// Server handles dummies, fees, grouping, and signing
txIDs, err := signing.SignAndSubmitViaGroup(
    txns,
    authCache,
    signerClient,
    algodClient,
    waitForConfirmation,
    verbose,
    lsigArgsMap, // nil if no generic lsigs
)
```

### Manual Flow

```go
// Build requests
requests := []util.SignRequest{
    {
        AuthAddress: "ABC123...",
        TxnSender:   "ABC123...",
        TxnBytesHex: hex.EncodeToString(append([]byte("TX"), msgpack.Encode(txn)...)),
    },
}

// Send to server
resp, err := signerClient.RequestGroupSign(requests)

// Decode and submit
for _, hexStr := range resp.Signed {
    signedBytes, _ := hex.DecodeString(hexStr)
    algodClient.SendRawTransaction(signedBytes)
}
```

---

## How the Server Derives What to Sign

The server looks up the key type for `auth_address` and derives the message to sign:

| Key Type | Message to Sign | Rationale |
|----------|-----------------|-----------|
| `ed25519` | Full transaction bytes (`TX` + msgpack) | Standard Algorand Ed25519 signing |
| `falcon1024-v1` (or other DSA) | 32-byte transaction ID hash | LogicSig DSA schemes sign the hash |
| `timelock-v1` (or other generic) | N/A (no signing) | Generic LogicSigs don't need signatures |

This design achieves **true client key-type agnosticism**: clients never need to know what type of key they're using or how to format messages for signing.

---

## Summary Table

| Aspect | Ed25519 | LogicSig DSA | Generic LogicSig |
|--------|---------|--------------|------------------|
| **What server signs** | Full txn bytes | 32-byte txn ID hash | N/A |
| **Signature size** | 64 bytes | ~1280 bytes (Falcon) | N/A |
| **Needs dummies** | No | Yes (if sig > 1000 bytes) | No |
| **Runtime args** | No | No | Optional |
| **Authorization** | Signature verification | TEAL verifies sig | TEAL logic only |

---

## Related Documents

- [`ARCH_CRYPTO.md`](ARCH_CRYPTO.md) - Cryptographic subsystem architecture
- [`TXN_BYTES_HEX.md`](TXN_BYTES_HEX.md) - Why we send full transaction bytes
- [`TXN_MIXED_GROUPS.md`](TXN_MIXED_GROUPS.md) - Mixed transaction groups with multiple key types
- [`DEV_New_DSA_LSig.md`](DEV_New_DSA_LSig.md) - Adding new DSA LogicSig schemes
- [`DEV_New_GenericLSig.md`](DEV_New_GenericLSig.md) - Adding new generic LogicSig templates
