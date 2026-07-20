# Anatomy of a Transaction

This document describes the information flow between apshell (client) and apsigner (server) for transaction signing.

## Overview

APlane separates group construction from cryptographic authorization. The server first canonicalizes the group shape (group ID, fees, dummy budget), then authorizes each entry according to its key type: native signature, DSA-backed LogicSig, or pure-TEAL LogicSig assembly.

APlane supports three fundamentally different authorization mechanisms:

| Type | Example | Where Signature Goes | Server Handles |
|------|---------|---------------------|----------------|
| **Ed25519** | Native Algorand keys | `SignedTxn.Sig` | Derive standard signing bytes and produce native Ed25519 signature |
| **LogicSig DSA** | Falcon-1024 | `LogicSig.Args[0]` | Derive DSA message (transaction ID), sign it, assemble LogicSig |
| **Generic LogicSig** | Timelock, Hashlock | No signature | Assemble LogicSig bytecode and canonical runtime args |

For standard transactions, the client sends transactions to `/sign` and receives a finalized group representation. Each request entry uses one of three modes — **sign**, **passthrough**, or **foreign**; `/plan` uses the same request grammar but stops before approval and signing. See [Mode Selection](#mode-selection) below for the trichotomy.

**Plugin transactions**: external plugins can participate in transaction flow
through the default unsigned-intent path or one of the explicit group modes.
`groupMode:"presign-plan"` uses `/plan` with plugin-owned slots as foreign
entries, then calls the plugin back with canonical bytes through
`signTransactions` before `/sign` signs the managed slots.
`groupMode:"pregrouped-signed"` is fully plugin-signed and bypasses apsigner
entirely after local client review. Top-level `localSigners` is unsupported and
rejected. See [Plugin Group Modes](#plugin-group-modes) below and
[ARCH_PLUGINS.md](ARCH_PLUGINS.md) for the plugin protocol.

**Group immutability rule**: Pre-grouped transactions (group ID already set) are always immutable. The server will not add dummies, adjust fees, or recompute the group ID. If a pre-grouped group has insufficient LogicSig budget, the request is rejected. Clients that need server-side canonicalization must submit ungrouped transactions.

> **Approval semantics**: "Group" means 2+ client-requested transactions. Server-added dummies do not convert a single-transaction request into group approval mode.

---

## Message-to-Sign Specification

Each key type has a specific message derivation. This is critical for security—the server and on-chain verification must use the same derivation.

### Byte Domains

Three distinct byte representations appear in the signing flow:

| Domain | Content | Used For |
|--------|---------|----------|
| **Unsigned transaction encoding** | msgpack(txn) | Internal transaction representation |
| **Signing preimage** | `"TX"` + msgpack(txn) | Ed25519 signs this directly; Falcon hashes it to derive the transaction ID |
| **Transport field** (`txn_bytes_hex`) | Hex encoding of the signing preimage | Wire format in `/sign` and `/plan` requests. Server strips the `TX` prefix before msgpack decoding. |

### Derivation by Key Type

| Key Type | Message Derivation | Size | On-Chain Verification |
|----------|-------------------|------|----------------------|
| **Ed25519** | `"TX"` + msgpack(txn) | Variable | Standard Algorand native signature verification |
| **Falcon-1024 DSA** | SHA512/256(`"TX"` + msgpack(txn)) = transaction ID | 32 bytes | `txn TxID` in TEAL |
| **Generic LogicSig** | N/A (no signature) | - | TEAL conditions only |

### Implementation Details

**Ed25519** (standard Algorand keys):
```go
// Server signing path (internal/signerapp/signing/execution.go)
messageBytes = append([]byte("TX"), msgpack.Encode(txn)...)
signature = ed25519.Sign(privateKey, messageBytes)
```
The standard Algorand transaction path verifies this signature using the normal native signature rules.

**Falcon-1024 DSA** (post-quantum LogicSig):
```go
// Server signing path (internal/signerapp/signing/execution.go)
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
- **Falcon-1024**: Signs the transaction ID (32 bytes) because:
  1. Falcon signatures are large (1280 bytes)—signing a 32-byte transaction ID is more efficient than signing the full preimage
  2. TEAL provides `txn TxID` opcode for verification
  3. Because the transaction ID is itself derived from the canonical Algorand transaction encoding, signing the txid still commits to the full transaction contents

### Test Vectors

Representative tests verify message derivation and provider consistency:

```go
// internal/logicsigdsa/dsa_test.go:TestFalcon1024V1Sign
sig, err := dsa.Sign(priv, message)

// lsig/falcon1024_ed25519/provider_test.go verifies that generated TEAL uses
// txn TxID, falcon_verify, and ed25519verify_bare in the expected order.
```

---

### Group Signing Flow

The `/sign` endpoint accepts a `GroupSignRequest` containing one or more transactions:

```
┌─────────┐                                         ┌──────────┐
│ apshell │                                         │ apsigner│
└────┬────┘                                         └────┬─────┘
     │                                                   │
     │  POST /sign                                       │
     │  ┌────────────────────────────────────────┐       │
     │  │ GroupSignRequest {                     │       │
     │  │   request_id: "cli-...",               │       │
     │  │   requests: [                          │       │
     │  │     { auth_address, txn_bytes_hex },   │       │
     │  │     { auth_address, txn_bytes_hex },   │       │
     │  │     ...                                │       │
     │  │   ]                                    │       │
     │  │ }                                      │       │
     │  └────────────────────────────────────────┘       │
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
     │  ┌────────────────────────────────────────┐       │
     │  │ GroupSignResponse {                    │       │
     │  │   signed: [                            │       │
     │  │     "<signed_txn_1_hex>",              │       │
     │  │     "<signed_txn_2_hex>",              │       │
     │  │     "<dummy_txn_hex>",  // if needed   │       │
     │  │     ...                                │       │
     │  │   ]                                    │       │
     │  │ }                                      │       │
     │  └────────────────────────────────────────┘       │
     │<──────────────────────────────────────────────────│
     │                                                   │
     │  Submit all signed bytes to algod                 │
     │                                                   │
```

See [ARCH_HTTP_API.md](ARCH_HTTP_API.md) for the `/sign` request lifecycle, identity routing, and cancellation semantics. This document focuses on the *flow* of transaction data through the endpoint.

### Request Format

```go
type GroupSignRequest struct {
    RequestID string        `json:"request_id,omitempty"` // Optional signer request lifecycle ID
    Requests []SignRequest `json:"requests"`
}

// SignRequest supports three mutually exclusive modes:
// - Sign mode: auth_address + txn_bytes_hex (server signs with its key)
// - Passthrough mode: signed_txn_hex (already signed, included as-is)
// - Foreign mode: txn_bytes_hex without auth_address (context-only; another signer owns this txn)
type SignRequest struct {
    // Sign mode fields
    AuthAddress  string            `json:"auth_address,omitempty"`  // Which key to use for signing
    TxnSender    string            `json:"txn_sender,omitempty"`    // Transaction sender (for display)
    TxnBytesHex  string            `json:"txn_bytes_hex,omitempty"` // TX + msgpack(txn)
    LsigArgs     map[string]string `json:"lsig_args,omitempty"`     // Runtime args for generic LSigs
    LsigSize     int               `json:"lsig_size,omitempty"`     // LSig size hint for foreign txns
    AppCallInfo  *AppCallInfo      `json:"app_call_info,omitempty"` // Optional approval metadata

    // Passthrough mode field
    SignedTxnHex string `json:"signed_txn_hex,omitempty"` // Already-signed txn (msgpack, hex)
}

type AppCallInfo struct {
    Mode   string `json:"mode,omitempty"`   // "raw" or "abi"
    Method string `json:"method,omitempty"` // ABI method signature when available
}
```

### Mode Selection

`/plan` and `/sign` accept three mutually exclusive per-entry modes:

- **Sign** — `auth_address` + `txn_bytes_hex`. The server signs the entry with its key.
- **Passthrough** — `signed_txn_hex`. The entry is already signed elsewhere and is preserved byte-for-byte. Requires a pre-formed group ID.
- **Foreign** — `txn_bytes_hex` without `auth_address`. The entry is part of the group for canonicalization, policy context, and approval rendering, but is never signed by this signer. The optional `lsig_size` hint reserves LogicSig budget for the foreign party's key type.

Both or neither → error. Passthrough and foreign are mutually exclusive within
one request. Passthrough supplies already-signed bytes and preserves them
byte-for-byte; foreign entries are unsigned context and still participate in
decoding, group consistency, approval rendering, and LogicSig-budget math
through `lsig_size` hints. Foreign mode can be used with ungrouped requests the
server canonicalizes, or with already pre-grouped requests that have sufficient
budget.

Aligning the grammar across `/plan` and `/sign` lets clients send one canonical full-group shape to the signer, have the signer evaluate the entire group for approval and policy context, and still receive signatures only for signer-owned entries. `/plan` returns canonical unsigned transactions; `/sign` signs only signer-owned entries, preserves passthrough entries, and returns `""` for foreign slots.

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

The `Signed` array maps 1:1 to the finalized group positions. Signable and passthrough entries contain pre-assembled signed transaction bytes. Foreign entries are returned as empty strings `""` because they contributed to canonicalization but were not signed by this signer. Server-added dummy transactions are appended to the array.

The `Mutations` field provides observability into server modifications:
- **Dummies**: If `dummies_added > 0`, the server added dummy transactions to meet LogicSig byte budget requirements
- **Fees**: The `fees_modified` array lists which transactions had their fees increased to cover dummy transaction costs
- **Group ID**: If `group_id_changed` is true, the server computed a new group ID for an ungrouped request. Pre-grouped transactions remain immutable; requests that would require dummy insertion into a pre-grouped group are rejected.
- **Passthrough**: If `passthrough_count > 0`, some transactions were pre-signed and included as-is
- **Foreign**: This count is useful on both `/plan` and `/sign`. On `/sign`, foreign entries remain in the request as context-only slots and return `""` in the aligned `signed[]` response.

### `/sign` Processing Pipeline

When apsigner receives a grouped `/sign` request, it processes the group in this order:

1. Validate each request entry by mode.
   - `signed_txn_hex` means passthrough.
   - `auth_address` + `txn_bytes_hex` means sign mode.
   - `txn_bytes_hex` without `auth_address` means foreign mode.
   - Invalid field combinations are rejected before planning starts.

2. Decode all supplied transaction material.
   - Sign and foreign entries decode from `txn_bytes_hex`.
   - Passthrough entries decode from `signed_txn_hex`.
   - Decode failures, malformed hex, and invalid msgpack fail the request.

3. Classify the group and enforce shape rules.
   - All-foreign groups are rejected because the signer has no signer-managed work to perform.
   - Pre-grouped passthrough groups must already have a stable group shape.
   - Requests that mix incompatible grouping assumptions are rejected.

4. Build the canonical group.
   - The server determines the finalized transaction order and group ID.
   - If the input is already pre-grouped and immutable, the server preserves that shape.
   - If the input is ungrouped, the server computes the canonical grouped form.

5. Calculate LogicSig budget and append dummies if required.
   - This applies to sign-mode entries and to foreign entries that provide `lsig_size`.
   - If dummy insertion would exceed Algorand's maximum group size, the request is rejected.

6. Pool or adjust fees if required by the finalized group.
   - Fee edits happen on the canonical unsigned transactions before signing.
   - These changes are reported back in `mutations`.

7. Run approval and policy evaluation on the finalized group.
   - The signer evaluates the whole group, including foreign context and passthrough entries.
   - Only sign-mode entries are candidates for actual signing by this signer.
   - Approval mode is based on the number of client-requested transactions, not the expanded finalized group length after dummy insertion.
   - Server-added dummies affect disclosure, fee impact, and final artifact construction, but they are not rendered as separate approval items.

8. Sign signer-owned entries by key type.
   - Native keys produce standard signed transactions.
   - DSA-backed LogicSigs derive their signing message and assemble the final authorized transaction.
   - Generic LogicSigs assemble bytecode and runtime args without a cryptographic signature.

9. Preserve passthrough entries exactly as provided.
   - Already-signed bytes are carried through unchanged.
   - Passthrough is how externally signed slots remain part of the final output.

10. Return aligned output for the full finalized group.
    - Sign-mode slots contain signed transaction bytes.
    - Passthrough slots contain the original signed bytes.
    - Foreign slots contain `""`.
    - Any appended dummy slots appear at the end of the response.

---

## The `/plan` Endpoint

The `/plan` endpoint provides group building without signing. It performs all the same processing as `/sign` (decoding, dummy calculation, fee pooling, group ID computation) but stops before approval and signing. The signer must be unlocked (key metadata is needed for dummy calculation).

**Use cases:**
- Build finalized canonical groups for plugin `presign-plan` and multi-party signing workflows
- Preview how the server will modify a group (dummies, fees) before committing
- Build finalized groups for multi-party signing workflows

**Request:** `GroupSignRequest`, using the same sign, passthrough, and foreign
modes as `/sign`. Passthrough and foreign remain mutually exclusive because
passthrough short-circuits dummy calculation while foreign participates in
planner budget math. Foreign requests may be ungrouped, in which case the
server canonicalizes them, or pre-grouped, in which case the server preserves
the shape if no extra dummies are needed.

**Response:** `GroupPlanResponse` — a dedicated type with a `transactions` field containing the finalized unsigned transaction bytes (with dummies, fees, and group ID applied):

```go
type GroupPlanResponse struct {
    Transactions []string        `json:"transactions,omitempty"` // TX-prefixed hex-encoded unsigned txns
    Mutations    *MutationReport `json:"mutations,omitempty"`
    Error        string          `json:"error,omitempty"`
}
```

The `Transactions` array maps 1:1 to the finalized group positions. Each entry is a hex-encoded unsigned transaction with the `TX` prefix, ready for signing.

The `/simulate` endpoint accepts the same request shape as `/sign`. It
canonicalizes and signs inside apsigner, resolves algod from the transaction
group's genesis/network, calls algod simulate with real signatures, and returns
`GroupSimulateResponse` containing txids, final unsigned `transactions`,
mutation metadata, diagnostic output, and a `failed` flag when algod reports an
execution failure. It never returns signed transaction bytes.

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

3. Party A submits to apsigner:
   - A's transaction: Sign mode (auth_address + txn_bytes_hex)
   - B's transaction: Passthrough mode (signed_txn_hex)
   - Dummies: Passthrough mode (signed_txn_hex)

4. apsigner signs A's part, includes B's and dummies as-is
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

3. **Approval context still applies**: All transactions (including passthrough) still contribute to approval context, warning analysis, and audit visibility. Even though passthrough bytes are not modified, their decoded transaction contents are still part of the reviewed group.

---

## Foreign Mode (Multi-Party Group Building)

Foreign mode enables multi-party signing workflows where the server builds the complete group (dummies, fees, group ID) but does not sign transactions owned by another party.

This same foreign-mode shape is also valid on `/sign`. The distinction between the endpoints is not the request grammar but the side effects:

- `/plan` returns canonical unsigned transactions only
- `/sign` runs approval/signing, signs only local slots, preserves passthrough slots, and returns `""` for foreign slots

That allows clients to move from planning to signing without rewriting the request model.

### Example: Two-Party Foreign-Mode Signing

```
1. Construct the intended multi-party group shape.

2. Plan: One party sends all intended transactions to /plan with any needed
   `lsig_size` hints for foreign slots.
   The signer returns the finalized canonical group with dummies, fees, and
   group ID.

3. Local sign: Each party signs its own finalized transactions outside the
   server-owned signer.

4. Sign: Each party sends the finalized group to their own /sign,
   using sign mode for owned transactions, foreign mode for unsigned
   transactions owned by the other party, and passthrough only for
   transactions that are already signed.

5. Assemble: Merge outputs if needed and submit the final group.
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

`/plan` returns canonical unsigned transactions, not signed placeholders:

```json
{
  "transactions": ["545800...", "545800..."],
  "mutations": {
    "foreign_count": 1,
    "dummies_added": 2,
    "group_id_changed": true
  }
}
```

### Constraints

1. **Cannot mix with passthrough**: Passthrough is already-signed byte
   preservation; foreign is unsigned context that participates in budget math.
   The combined shape is rejected.

2. **All-foreign is rejected by apsigner**: If every entry is foreign (nothing to sign), both `/sign` and `/plan` return 400 because apsigner has no managed signing work to perform.

3. **Policy applies to signer-controlled slots**: Hard policy linting runs only on signer-controlled transactions. Foreign slots are part of planning and approval context, but are not hard-rejected by the signer's policy engine.

4. **`lsig_size` is advisory for generic foreign entries**: An estimated final
   LogicSig serialized size in bytes, used only for dummy-budget planning. The
   server trusts the hint. Guarded mixed-group clients provide accurate hints
   for guarded foreign entries so client and server budget calculations stay in
   parity; incorrect hints can cause early pre-grouped rejection or later algod
   failure.

5. **Dummies are returned by this signer unless already supplied**: Dummy
   transactions created during foreign-mode group construction are assembled
   with APlane's embedded dummy LogicSig and returned in the signer's own
   output, not as foreign placeholders. In guarded mixed groups, dummies may be
   client-created and signed locally, then sent as foreign context to the
   intermediate `/sign` and passthrough to `/sign/assemble`.

See [Mode Selection](#mode-selection) for the full trichotomy. The key
operational difference: passthrough requires a pre-formed group and is
preserved byte-for-byte, while foreign leaves an entry unsigned but visible and
budgeted.

---

## Plugin Group Modes

Top-level `localSigners` is not a supported plugin signing mechanism. If a
plugin returns it, apshell rejects the result before planning, approval, or
submission. APlane never signs with plugin-supplied secret keys.

`groupMode:"presign-plan"` generalizes the mixed-signing shape for plugin-owned
signers whose key material cannot be exported. The plugin emits an unsigned
draft plus `pluginSigners`; apshell sends plugin-owned slots to `/plan` as
foreign entries with optional `lsig_size` hints, verifies `/plan` preserved all
original fields except `Group` and `Fee`, calls the plugin's `signTransactions`
callback over the canonical bytes, then submits a `/sign` request with
plugin-signed slots as passthrough and managed slots in sign mode. This is the
path used when plugin LogicSigs need pooled opcode/byte budget.

`groupMode:"pregrouped-signed"` is the all-plugin signed case. The plugin
returns already-signed, already-grouped bytes; apshell validates the embedded
group ID is self-consistent and submits the exact bytes verbatim. apsigner does
not plan, approve, or sign that group, so local client review is the human gate.

See [ARCH_PLUGINS.md](ARCH_PLUGINS.md) for the plugin group-mode wire contract.

---

## Server Control Flow Trace

The `/sign` endpoint has a single entry point and a single success path. Method
enforcement, identity extraction, JSON decoding, runtime availability, and
empty-requests checks gate the request before any planning starts. The
`SignRequest` entries are then validated per mode (sign, passthrough, foreign)
and decoded — sign and foreign entries from `txn_bytes_hex`, passthrough
entries from `signed_txn_hex`. Decoded transactions are checked for group
consistency, recognized genesis network, overlapping validity windows,
passthrough's pre-grouped requirement, and the presence of at least one
signable entry under the authenticated identity. Dummy calculation runs next
(skipped for passthrough groups) and enforces the maximum group size and
pre-grouped immutability; if dummies are needed, the planner creates them,
adjusts fees, and recomputes the group ID. The finalized group passes through
hard policy linting, forced-review policy, explicit auto-approval, and then
either group-mode or single-transaction operator approval (or the
`user_auto_approve:true` operator-default shortcut).
Signing dispatches by key type — generic LogicSig, DSA LogicSig (signing the
32-byte transaction ID), or Ed25519 (signing the `TX`-prefixed msgpack) — then
signs any dummies. The successful response is a `GroupSignResponse` carrying
the aligned `signed` slots plus a `mutations` report; any failure short-circuits
to a `GroupSignResponse` with a populated `error`.

See `internal/signerapp/daemon/http_handlers_signing.go`'s `handleSign` for the dispatch
implementation, and `internal/signerapp/signing/planner.go` and
`internal/signerapp/signing/execution.go` for the planning and per-key
signing logic it drives.

### Branch Summary

| Category | Description |
|----------|-------------|
| Input validation | Identity, runtime availability, decode, format, network, consistency, passthrough/foreign checks |
| Policy and reviewability | Hard constraints, forced review, and explicit auto-approval before operator default; unsupported approval surfaces fail closed |
| Human approval | Group vs single txn, each using apadmin approval unless policy/`user_auto_approve:true` bypasses it |
| Signing | Generic LSig, DSA LSig, Ed25519 |
| Failure shape | `GroupSignResponse{Error: "..."}` for every error path |
| Success shape | `GroupSignResponse{Signed: [...], Mutations: {...}}` |

---

## Server-Side Processing by Key Type

When the server processes each transaction, it determines the signing method based on the key type for `auth_address`. Key lookups are scoped by the authenticated identity extracted from the request context and resolved through the bound identity runtime. The normal operational path targets the product identity; `auth.CurrentProductIdentityID()` is a process-boundary/defaulting helper rather than the primary runtime lookup mechanism inside request handling.

### 1. Ed25519 Signing

Native single-signature Algorand signing places the Ed25519 signature in `SignedTxn.Sig`.

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
              │ 3. Compute txn ID     │
              │    (32 bytes)         │
              │ 4. Sign txn ID with   │
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
| Message signed | 32-byte transaction ID |
| Signature size | ~1280 bytes (Falcon-1024) |
| Signature location | `LogicSig.Args[0]` |
| TEAL verifier | Embedded in `LogicSig.Logic` |

The TEAL verifier program:
1. Extracts signature from `Args[0]`
2. Computes transaction ID
3. Verifies signature against embedded public key
4. Returns 1 (approve) or 0 (reject)

### 3. Generic LogicSig (e.g., Timed Allowlist, Hashlock)

TEAL programs that authorize transactions without cryptographic signatures. Authorization is purely through TEAL evaluation.

```
Server receives: { auth_address, txn_bytes_hex, lsig_args }
                          │
                          ▼
              ┌───────────────────────┐
              │ 1. Load key file      │
              │ 2. Key type: timed-   │
              │    allowlist          │
              │ 3. NO CRYPTOGRAPHIC   │
              │    SIGNING            │
              │ 4. Load TEAL bytecode │
              │ 5. Order runtime args │
              │    per stored schema  │
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

Generic LogicSigs may require runtime arguments, such as a preimage for a
Hashed TimeLock Contract (HTLC). The client sends args **by name**, and the
server orders them according to the runtime-arg schema stored in the key file
at generation time:

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

**Server uses the stored key-file schema to order args for `LogicSig.Args`.**
The live template is not consulted at sign time.

---

## Dummy Transactions and Fee Pooling

Post-quantum signatures (e.g., Falcon ~1280 bytes) exceed Algorand's 1000-byte LogicSig budget per transaction. The server automatically adds dummy transactions to provide additional budget.

### How It Works

1. Server analyzes transactions to identify LogicSig DSA signers
2. Calculates total LogicSig budget needed
3. Creates dummy self-payment transactions to provide extra budget
4. Adds dummy fees to the LogicSig transaction fees, split across identified LogicSig participants when possible (dummies have fee=0)
   These fees are added to existing transaction fees and are not netted
   against any caller-supplied fee pool.
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
| Single pre-grouped txn | Yes | **Rejected** | **Rejected** | **Rejected** |
| Multiple ungrouped txns | No | No | No | Yes (computed) |
| Multiple ungrouped txns | Yes | Yes | Yes | Yes (computed) |
| Multiple pre-grouped txns | No | No | No | No (preserved) |
| Multiple pre-grouped txns | Yes | **Rejected** | **Rejected** | **Rejected** |

**Pre-grouped transactions are immutable.** If they require additional dummies for LogicSig budget, the request is rejected — the client must submit ungrouped transactions instead so the server can canonicalize the group. Pre-grouped groups are only accepted if they already have sufficient LogicSig budget.

### Modified Transaction Consistency

When transactions are modified (fees adjusted, group ID computed), the **modified transaction data** is used consistently throughout the approval flow:

- **Approval UI**: Displays the actual fees and group ID that will be signed
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

The following runtime and policy settings affect server behavior:

| Setting | Location | Default | Description |
|---------|----------|---------|-------------|
| `user_auto_approve` | `identities/<identity>/config.yaml` | `false` | Sign requests that are not auto-rejected, forced to review, or explicitly auto-approved without TUI confirmation. |
| `reject_foreign_rekey` | `identities/<identity>/policy.yaml` | `true` | Reject txns whose non-zero `RekeyTo` target is not held by the current signer before approval. |
| `reject_close_remainder` | `identities/<identity>/policy.yaml` | `false` | Reject txns with non-zero `CloseRemainderTo` before approval. |
| `reject_asset_close` | `identities/<identity>/policy.yaml` | `false` | Reject txns with non-zero `AssetCloseTo` before approval. |
| `reject_clawback` | `identities/<identity>/policy.yaml` | `false` | Reject ASA clawback txns using `AssetSender` before approval. |
| `always_review_warnings` | `identities/<identity>/policy.yaml` | `false` | Force operator review for warning-level findings before auto-approval or `user_auto_approve:true` can sign. |
| `auto_approve_self_noop_transfer` | `identities/<identity>/policy.yaml` | `false` | Auto-approve a single 0 ALGO payment to self or 0-unit ASA transfer to self only when it has no caller-provided group, no passthrough/foreign slots, no rekey, no close remainder, no asset close, no clawback sender, no note, no lease, and normalized fee is at most 1000 microAlgos. Signer-generated LogicSig-budget dummies are allowed only when they exactly match APlane's dummy transaction shape and fee adjustment. |
| `max_fee_microalgos` | `identities/<identity>/policy.yaml` | unset | Reject txns whose fee exceeds the raw microAlgo ceiling. |
| `review_algo_payments` | `identities/<identity>/policy.yaml` | unset | Force review for payment txns whose raw microAlgo amount exceeds the configured per-network threshold. Admin UI/IPC input and review messages use ALGO display units. |
| `max_algo_payments` | `identities/<identity>/policy.yaml` | unset | Reject payment txns whose raw microAlgo amount exceeds the configured per-network ceiling. Admin UI/IPC input and rejection messages use ALGO display units. |
| `review_asa_amounts` | `identities/<identity>/policy.yaml` | unset | Force review for ASA transfers whose stored raw asset amount exceeds the configured per-network, per-asset threshold. In the admin UI, any ASA ref that resolves on the selected network is entered in display units and converted to raw before persistence. |
| `max_asa_amounts` | `identities/<identity>/policy.yaml` | unset | Reject ASA transfers whose stored raw asset amount exceeds the configured per-network, per-asset ceiling. In the admin UI, any ASA ref that resolves on the selected network is entered in display units and converted to raw before persistence. |
| `key_overrides` | `identities/<identity>/policy.yaml` | unset | YAML-only sparse policy overrides. Signer-domain overrides are keyed by signing auth address; sentry-domain overrides are keyed by Sentry Key ID. Unset fields inherit identity-wide policy, and nested overrides are rejected. |

**Pre-grouped immutability**: Pre-grouped transactions are always immutable. If they require additional dummies for LogicSig budget, the request is rejected. Clients should submit ungrouped transactions to let the server canonicalize the group.

Signing behavior is governed by hard-reject safety policy, warnings, and approval.

---

## Policy and Approval

For the canonical current policy verdict model, see
[ARCH_POLICY.md](ARCH_POLICY.md). This section focuses on transaction-flow
consequences.

Signing uses:

- hard-reject signer safety policy before approval,
- forced-review policy before auto-approval,
- explicit auto-approval policy for narrow low-risk requests,
- warning analysis for operator-visible risk surfacing,
- human approval or `user_auto_approve:true` for requests that are not auto-rejected, forced to review, or explicitly auto-approved.

| Request Type | Warning / Review Surface | Human Approval |
|--------------|--------------------------|----------------|
| Single txn | Transaction warnings | Txn-level: `user_auto_approve:true` or TUI |
| Group (2+ txns in client request) | Group context and aggregated warnings | Group-level only: `user_auto_approve:true` or TUI |

**Key points**:
- "Group" means 2+ transactions in client request (server-added dummies don't change this)
- Groups never undergo per-transaction human approval
- hard-reject safety policy can block a request before approval
- forced-review policy can require human approval even when `user_auto_approve:true`
- explicit auto-approval policy never bypasses hard-reject safety policy
- warning analysis informs approval, but remains separate from the hard-reject layer

---

## Client Usage

### Simple Flow (Recommended)

```go
// Build transactions with suggested params
txns := []types.Transaction{txn1, txn2, ...}

// Sign and submit via /sign endpoint
// Server handles dummies, fees, grouping, and signing
txIDs, submittedTxns, err := clientsign.SignAndSubmitViaGroup(
    txns,
    authCache,
    signerClient,
    algodClient,
    clientsign.SubmitOptions{
        WaitForConfirmation: waitForConfirmation,
        Verbose:             verbose,
        LsigArgsMap:         lsigArgsMap, // nil if no generic lsigs
    },
)
```

### Manual Flow

```go
// Build requests
requests := []signerapi.SignRequest{
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
| `aplane.falcon1024.v1` (or other DSA) | 32-byte transaction ID | LogicSig DSA schemes sign the transaction ID |
| `aplane.timed-allowlist.v1` (or other generic) | N/A (no signing) | Generic LogicSigs don't need signatures |

This design achieves **true client key-type agnosticism**: clients never need to know what type of key they're using or how to format messages for signing.

---

## Bounded Contract-Admin Rekey Flow

An admin-key bounded profile keeps pure spending on `/sign`, but routes a pure
rekey through a typed partial flow:

1. The client constructs a pure zero-amount self-payment rekey.
2. `POST /sign/bounded-admin` performs canonical planning, policy, forced review,
   approval, dummy/fee/group finalization, and Falcon spending signing.
3. Apsigner verifies the spending signature and returns finalized unsigned
   transactions plus one aligned partial LogicSig. It never returns the partial
   in `signed[]` and never handles contract-admin private material.
4. `apbounded-admin sign` independently decodes the finalized group, verifies
   the pure rekey shape, bounded profile, program binding, Contract Admin Key ID,
   transaction ID, and spending signature, then confirms and adds the external
   Falcon signature.
5. Completion verifies both signatures, preserves every unsigned byte and group
   ID, rechecks authorization/network/validity state, and submits directly to
   Algod without replanning.

Online `apbounded-admin rekey` performs these stages directly. The separated
ceremony path splits them across `prepare-rekey`/`prepare-unrekey`, offline
`sign`, and `complete` using `.apbounded-admin-request` and
`.apbounded-admin-signature` files.

## Summary Table

| Aspect | Ed25519 | LogicSig DSA | Generic LogicSig |
|--------|---------|--------------|------------------|
| **What server signs** | Full txn bytes | 32-byte transaction ID | N/A |
| **Signature size** | 64 bytes | ~1280 bytes (Falcon) | N/A |
| **Needs dummies** | No | Yes (if sig > 1000 bytes) | No |
| **Runtime args** | No | Optional for composed DSA | Optional |
| **Authorization** | Signature verification | TEAL verifies sig | TEAL logic only |

Bounded LogicSig DSA is the transaction-aware case: pure spends and
spending-key rekeys use their declared base, derived, and runtime argument
slots, while an admin-key rekey uses a signer partial plus an externally
completed Falcon contract-admin slot.

---

## Related Documents

- [`ARCH_CRYPTO.md`](ARCH_CRYPTO.md) - Cryptographic subsystem architecture
- [`TXN_BYTES_HEX.md`](TXN_BYTES_HEX.md) - Why we send full transaction bytes
- [`TXN_MIXED_GROUPS.md`](TXN_MIXED_GROUPS.md) - Mixed transaction groups with multiple key types
- [`DEV_KEYTYPES.md`](DEV_KEYTYPES.md) - Adding new key types and LogicSig templates
