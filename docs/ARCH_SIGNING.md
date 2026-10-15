# Transaction Signing

> How a transaction travels from apshell or an SDK client through apsigner to a
> signed group, and the compatibility-bearing apsigner HTTP wire contract that
> carries it: endpoints, request/response shapes, status codes, `/sign/cancel`,
> the error model, and SDK contracts.

This document describes the information flow between apshell (client) and apsigner (server) for transaction signing.
The first part explains the flow. The [HTTP API Contract](#http-api-contract)
part is the compatibility-bearing wire contract; its sections are marked as
such, and a change to them is a protocol change. For overall compatibility
scope, see [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md).

## Contents

- [Overview](#overview)
- [Message-to-Sign Specification](#message-to-sign-specification)
- [Group Signing Flow](#group-signing-flow)
- [The `/plan` Endpoint](#the-plan-endpoint)
- [Passthrough Mode (Multi-Party Signing)](#passthrough-mode-multi-party-signing)
- [Foreign Mode (Multi-Party Group Building)](#foreign-mode-multi-party-group-building)
- [Plugin Group Modes](#plugin-group-modes)
- [Server Control Flow Trace](#server-control-flow-trace)
- [Server-Side Processing by Key Type](#server-side-processing-by-key-type)
- [Dummy Transactions and Fee Pooling](#dummy-transactions-and-fee-pooling)
- [Policy and Approval](#policy-and-approval)
- [Client Usage](#client-usage)
- [How the Server Derives What to Sign](#how-the-server-derives-what-to-sign)
- [Bounded-Cosigner Spend Flow](#bounded-cosigner-spend-flow)
- [Bounded Contract-Admin Rekey Flow](#bounded-contract-admin-rekey-flow)
- [Summary Table](#summary-table)
- [HTTP API Contract](#http-api-contract) (compatibility-bearing)
  - [Endpoints](#endpoints)
  - [Request/Response Shapes](#requestresponse-shapes)
  - [Sign Cancellation Semantics](#sign-cancellation-semantics)
  - [HTTP Status Mapping](#http-status-mapping)
  - [Error Model](#error-model)
  - [SDK Contracts](#sdk-contracts)
- [Related Documents](#related-documents)

## Overview

APlane separates group construction from cryptographic authorization. The server first canonicalizes the group shape (group ID, fees, dummy budget), then authorizes each entry according to its key type: native Ed25519 signature, native Falcon-1024 authorization, DSA-backed LogicSig, or pure-TEAL LogicSig assembly.

APlane supports four fundamentally different authorization mechanisms:

| Type | Example | Where Signature Goes | Server Handles |
|------|---------|---------------------|----------------|
| **Ed25519** | Native Algorand keys | `SignedTxn.Sig` | Derive standard signing bytes and produce native Ed25519 signature |
| **Native Falcon-1024** | `falcon1024` (`authorization_kind:"native_pq"`) | `SignedTxn.PQsig` | Authorize the structured transaction with Falcon over the standard signing bytes; no LogicSig |
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

**Group immutability rule**: Pre-grouped transactions (group ID already set)
are always immutable. The server will not add dummies, adjust fees, or
recompute the group ID. If a pre-grouped group has insufficient LogicSig
resources or aggregate fee, the request is rejected. Clients that need
server-side canonicalization must submit ungrouped transactions.

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
| **Native Falcon-1024** (`falcon1024`) | `"TX"` + msgpack(txn) | Variable | Protocol-native `PQsig` verification |
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
arg 0             // Push signature (variable, at most 1,423 bytes)
pushbytes 0x<pubkey> // Push public key (1793 bytes)
falcon_verify     // Verify: returns 1 if valid
```

**Key invariant**: `crypto.TransactionID(txn)` in Go produces the same value as `txn TxID` in TEAL. Both compute SHA512/256 of `"TX"` prefix + msgpack-encoded transaction.

### Why Different Derivations?

- **Ed25519**: Signs full message for SDK compatibility. The Algorand SDK expects signatures over `"TX"` + msgpack.
- **Falcon-1024**: Signs the transaction ID (32 bytes) because:
  1. Falcon signatures are large (up to 1,423 bytes)—signing a 32-byte transaction ID is more efficient than signing the full preimage
  2. TEAL provides `txn TxID` opcode for verification
  3. Because the transaction ID is itself derived from the canonical Algorand transaction encoding, signing the txid still commits to the full transaction contents

### Test Vectors

Representative tests verify message derivation and provider consistency:

```go
// internal/logicsigdsa/dsa_test.go:TestFalcon1024V1Sign
sig, err := dsa.Sign(priv, message)

// lsig/falcon1024/v1 tests verify that generated TEAL uses txn TxID and
// falcon_verify in the expected order.
```

## Group Signing Flow

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

See [HTTP API Contract](#http-api-contract) for the `/sign` request lifecycle, fixed runtime binding, and cancellation semantics.

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
    LsigArgs      map[string]string       `json:"lsig_args,omitempty"`      // Runtime args for generic LSigs
    LsigResources *LogicSigResourceUsage `json:"lsig_resources,omitempty"` // Foreign/passthrough selected-path resources
    PQScheme      string                 `json:"pq_scheme,omitempty"`      // Foreign-only native-PQ scheme hint ("f1"); exclusive with lsig_resources
    AppCallInfo   *AppCallInfo            `json:"app_call_info,omitempty"`  // Optional approval metadata

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
- **Passthrough** — `signed_txn_hex`. The entry is already signed elsewhere
  and is preserved byte-for-byte. It requires a pre-formed group ID. A
  passthrough LogicSig also requires `lsig_resources`; the signer checks its
  declared program/argument bytes against the envelope and uses the reviewed
  opcode ceiling for planning.
- **Foreign** — `txn_bytes_hex` without `auth_address`. The entry is part of
  the group for canonicalization, policy context, and approval rendering, but
  is never signed by this signer. Optional `lsig_resources` declares
  `program_bytes`, `argument_bytes`, and `max_opcode_cost` for the foreign
  party's selected LogicSig authorization path.

Both or neither → error. Passthrough and foreign are mutually exclusive within
one request. Passthrough supplies already-signed bytes and preserves them
byte-for-byte; foreign entries are unsigned context and still participate in
decoding, group consistency, approval rendering, and LogicSig-resource math
through `lsig_resources` hints. Foreign mode can be used with ungrouped requests the
server canonicalizes, or with already pre-grouped requests that have sufficient
budget.

Aligning the grammar across `/plan` and `/sign` lets clients send one canonical full-group shape to the signer, have the signer evaluate the entire group for approval and policy context, and still receive signatures only for signer-owned entries. `/plan` returns canonical unsigned transactions; `/sign` signs only signer-owned entries, preserves passthrough entries, and returns `""` for foreign slots.

### Response Format

```go
type GroupSignResponse struct {
    Signed    []string        `json:"signed,omitempty"`    // Signed transactions (msgpack, hex)
    Mutations *MutationReport `json:"mutations,omitempty"` // Server modifications (nil if none)
    Error     string          `json:"error,omitempty"`     // Legacy; never set (failures use ErrorResponse)
}

type MutationReport struct {
    DummiesAdded     int    `json:"dummies_added,omitempty"`     // Dummy txns added for LSig resources
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

The `signed[]` slot rules are part of the wire contract; see [Request/Response Shapes](#requestresponse-shapes).

The `Mutations` field provides observability into server modifications:
- **Dummies**: If `dummies_added > 0`, the server added dummy transactions to
  meet LogicSig argument or opcode requirements.
- **Fees**: The `fees_modified` array lists transactions whose fees increased
  to meet the final group's aggregate consensus fee, including transaction
  bases, priced LogicSig program bytes, and native-PQ contributions.
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

4. Resolve the active consensus profile, calculate LogicSig resources, and
   append dummies if required.
   - This applies to sign-mode entries, foreign entries that provide
     `lsig_resources`, and passthrough LogicSigs whose declaration is required.
   - On v42, only pooled arguments and opcode capacity can require dummies;
     excess program bytes contribute to the group fee instead.
   - If dummy insertion would exceed Algorand's maximum group size, the request is rejected.

5. Pool or adjust fees if required by the finalized group.
   - Fee edits happen on the canonical unsigned transactions before signing.
   - These changes are reported back in `mutations`.

6. Build the canonical group.
   - The server determines the finalized transaction order and computes the
     group ID last, over the dummy-extended, fee-finalized transactions.
   - If the input is already pre-grouped and immutable, the server preserves that shape.
   - If the input is ungrouped, the server computes the canonical grouped form.

7. Run approval and policy evaluation on the finalized group.
   - The signer evaluates the whole group, including foreign context and passthrough entries.
   - Only sign-mode entries are candidates for actual signing by this signer.
   - Approval mode is based on the number of client-requested transactions, not the expanded finalized group length after dummy insertion.
   - Server-added dummies affect disclosure, fee impact, and final artifact construction, but they are not rendered as separate approval items.

8. Sign signer-owned entries by key type.
   - Native Ed25519 keys produce standard signed transactions; native
     Falcon-1024 keys produce a `SignedTxn` with top-level `PQsig`.
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
modes as `/sign`. Passthrough and foreign remain mutually exclusive (request
validation rejects mixing them) because passthrough requires an immutable
pre-grouped group. Passthrough entries still take part in LogicSig resource and
fee calculation; an immutable group that would need more dummies is rejected.
Foreign requests may be ungrouped, in which case the
server canonicalizes them, or pre-grouped, in which case the server preserves
the shape if no extra dummies are needed.

**Response:** `GroupPlanResponse` — a dedicated type with a `transactions` field containing the finalized unsigned transaction bytes (with dummies, fees, and group ID applied):

```go
type GroupPlanResponse struct {
    Transactions []string        `json:"transactions,omitempty"` // TX-prefixed hex-encoded unsigned txns
    Mutations    *MutationReport `json:"mutations,omitempty"`
    Error        string          `json:"error,omitempty"` // Legacy; never set (failures use ErrorResponse)
}
```

The `Transactions` array maps 1:1 to the finalized group positions. Each entry is a hex-encoded unsigned transaction with the `TX` prefix, ready for signing.

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

2. **Group structure is fixed**: The server calculates the complete resource
   requirement for a passthrough group but cannot change it. If the declared
   LogicSig resource demand requires more dummies than the immutable group
   already contains, planning rejects before additional signatures are released.

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
   `lsig_resources` hints for foreign slots.
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
      "lsig_resources": {
        "program_bytes": 1800,
        "argument_bytes": 1423,
        "max_opcode_cost": 20000
      }
    }
  ]
}
```

The second entry has `txn_bytes_hex` but no `auth_address` — this is a foreign
transaction. Its optional `lsig_resources` object tells the server the exact
final-program length and reviewed argument/opcode ceilings for the selected
authorization path, enabling consensus-correct dummy and fee calculation.

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

4. **`lsig_resources` is advisory for generic foreign entries**: It is a
   structured selected-path declaration used for dummy and program-fee
   planning. The server trusts the hint. Guarded mixed-group clients provide
   signer-advertised values so client and server resource calculations stay in
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
foreign entries with `lsig_resources` for LogicSig slots or `pq_scheme` for
native-PQ slots, verifies `/plan` preserved all
original fields except `Group` and `Fee`, calls the plugin's `signTransactions`
callback over the canonical bytes, then submits a `/sign` request with
plugin-signed slots as passthrough and managed slots in sign mode. Apshell
verifies the returned authorization class and observable LogicSig sizes match
the declaration, then retains the declaration on the final passthrough request.
This is the path used when plugin LogicSigs need pooled opcode/byte budget.

`groupMode:"pregrouped-signed"` is the all-plugin signed case. The plugin
returns already-signed, already-grouped bytes; apshell validates the embedded
group ID is self-consistent and submits the exact bytes verbatim. apsigner does
not plan, approve, or sign that group, so local client review is the human gate.

See [ARCH_PLUGINS.md](ARCH_PLUGINS.md) for the plugin group-mode wire contract.

---

## Server Control Flow Trace

The `/sign` endpoint has a single entry point and a single success path.
Product authentication and authorization, method enforcement, runtime
availability, JSON decoding, and empty-requests checks gate the request before any planning starts. The
`SignRequest` entries are then validated per mode (sign, passthrough, foreign)
and decoded — sign and foreign entries from `txn_bytes_hex`, passthrough
entries from `signed_txn_hex`. Decoded transactions are checked for group
consistency, recognized genesis network, overlapping validity windows,
passthrough's pre-grouped requirement, and the presence of at least one
signable entry in the bound product runtime. Dummy calculation runs next
and enforces the maximum group size and pre-grouped immutability; if dummies are
needed for an immutable passthrough/pre-grouped group, it rejects. Otherwise
the planner creates them, adjusts fees, and recomputes the group ID. The finalized group passes through
hard policy linting, forced-review policy, explicit auto-approval, and then
either group-mode or single-transaction operator approval (or the
`user_auto_approve:true` operator-default shortcut).
Signing dispatches by key type — generic LogicSig, DSA LogicSig (signing the
32-byte transaction ID), native Falcon-1024 (structured authorization into
`SignedTxn.PQsig`), or Ed25519 (signing the `TX`-prefixed msgpack) — then
signs any dummies. The successful response is a `GroupSignResponse` carrying
the aligned `signed` slots plus a `mutations` report. Any failure short-circuits
to a non-2xx `signerapi.ErrorResponse` with `error` and a stable `code`;
`GroupSignResponse` is the success shape only.

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
| Signing | Generic LSig, DSA LSig, native Falcon-1024, Ed25519 |
| Failure shape | non-2xx `ErrorResponse{error, code}` |
| Success shape | `GroupSignResponse{Signed: [...], Mutations: {...}}` |

---

## Server-Side Processing by Key Type

When the server processes each transaction, it determines the signing method
based on the key type for `auth_address`. Product authentication binds the
request to the one `default` runtime; it does not select a runtime from caller
input. Key lookups then use that bound runtime.

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

#### Native Falcon-1024 Authorization

A `falcon1024` key (`authorization_kind:"native_pq"`) has no LogicSig
bytecode. The signer calls the provider's structured transaction authorizer,
which signs the `TX`-prefixed msgpack with Falcon-1024 and returns a
`SignedTxn` whose top-level `PQsig` carries the scheme (`f1`), address salt,
public key, and signature. The signer independently validates that envelope
before returning it.

| Aspect | Value |
|--------|-------|
| Message signed | Full transaction bytes (`TX` + msgpack) |
| Signature size | variable, at most 1,538 bytes |
| Signature location | `SignedTxn.PQsig` |
| Dummies | None; contributes native-PQ fee units (see [Native Falcon Authorization And Consensus Resources](#native-falcon-authorization-and-consensus-resources)) |

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
| Signature size | variable, at most 1,423 bytes (Falcon-1024) |
| Signature location | `LogicSig.Args[0]` |
| TEAL verifier | Embedded in `LogicSig.Logic` |

The TEAL verifier program:
1. Extracts signature from `Args[0]`
2. Computes transaction ID
3. Verifies signature against embedded public key
4. Returns 1 (approve) or 0 (reject)

### 3. Generic LogicSig (e.g., HTLC)

TEAL programs that authorize transactions without cryptographic signatures. Authorization is purely through TEAL evaluation.

```
Server receives: { auth_address, txn_bytes_hex, lsig_args }
                          │
                          ▼
              ┌───────────────────────┐
              │ 1. Load key file      │
              │ 2. Key type: htlc     │
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

Post-quantum signatures (e.g., Falcon up to 1,423 bytes) exceed Algorand's 1,000-byte LogicSig argument allowance per transaction. The server automatically adds dummy transactions when the active consensus resource rules require them.

### How It Works

1. Server analyzes transactions to identify LogicSig DSA signers
2. Resolves the selected path's program, argument, and opcode resources.
3. Solves the smallest consensus-valid group and creates required resource
   dummy self-payments.
4. Computes one aggregate fee requirement across the final group, crediting
   caller-supplied fees and assigning any deficit only to mutable signer slots.
5. Computes the group ID across the fee-finalized transactions.
6. Approves, signs, and returns the complete group.

### Example

For one Falcon transaction planned at the 1,423-byte signature ceiling under
v42:

- the individual argument allowance is 1,000 bytes;
- argument pooling therefore applies;
- the group must contain at least two transactions;
- program bytes are priced only if the final group's free program pool is
  insufficient; and
- the opcode ceiling must also fit `2 * 20,000`.

The server returns 2 signed transactions: the main transaction + 1 dummy.

### Native Falcon Authorization And Consensus Resources

Native Falcon authorization occupies top-level `SignedTxn.PQsig`, never
`SignedTxn.Sig` or `SignedTxn.Lsig`, and contributes `2e6` fixed-point fee
units in addition to the transaction's ordinary `1e6` base factor. This
APlane release implements the v42 authorization contract; clients reject an
algod that reports another contract before constructing transactions and
refresh the check before executable signing or submission workflows.
The signer derives this authorization budget from local key metadata or a
passthrough `PQsig`. An unsigned foreign native-PQ slot in `/plan` or `/sign`
declares `pq_scheme: "f1"`, and a passthrough LogicSig declares
`lsig_resources`; [Request/Response Shapes](#requestresponse-shapes) specifies
both hints and how the signer checks them.

LogicSig program sizing and native-PQ contributions are consensus-defined.
This release compiles exactly one reviewed contract, v42, into the signer.
`internal/lsigresource` owns that closed consensus profile and the pure
fixed-point group/resource solver. `internal/signerapp/signing` selects and
validates per-slot authorization usages, invokes the solver, and applies its
resource result to canonical group and fee planning.

`/plan` and `/sign` never query a per-network algod. The client owns ordinary
transaction fee selection through its algod SuggestedParams response and
validates that response as v42-compatible.
First-party planning and executable workflows refresh this check before asking
apsigner to plan, releasing signatures, or submitting, including JavaScript
`plan()`, prebuilt transaction signing, plugin pre-sign callbacks, guarded
signing, bounded-admin partial signing, and verbatim pregrouped
submission/simulation. The apsigner `/plan` endpoint itself remains independent
of a client algod.
The signer rejects an ordinary fee deficit, then adds only authorization-
induced requirements: resource-dummy base fees, priced LogicSig program bytes,
and native-PQ contributions. The signer's separately configured compile algod
remains responsible only for template compilation/simulation workflows.

### Server Modification Behavior

The server may modify transactions (add dummies, adjust fees, compute group ID) depending on the input format and whether large LogicSigs are involved:

| Input | Needs more resources/fees? | Dummies Added | Fees Modified | Group ID Modified |
|-------|-------------|---------------|---------------|-------------------|
| Single ungrouped txn | No | No | No | No (stays empty) |
| Single ungrouped txn | Yes | Yes | Yes | Yes (new group ID) |
| Single pre-grouped txn | No | No | No | No (preserved) |
| Single pre-grouped txn | Yes | **Rejected** | **Rejected** | **Rejected** |
| Multiple ungrouped txns | No | No | No | Yes (computed) |
| Multiple ungrouped txns | Yes | Yes | Yes | Yes (computed) |
| Multiple pre-grouped txns | No | No | No | No (preserved) |
| Multiple pre-grouped txns | Yes | **Rejected** | **Rejected** | **Rejected** |

**Pre-grouped transactions are immutable.** If they require additional dummies
or fees, the request is rejected — the client must submit ungrouped transactions
instead so the server can canonicalize the group. Pre-grouped groups are only
accepted if they already have sufficient LogicSig resources and aggregate fee.

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

The following runtime and policy settings affect server behavior. Policy
settings live in the selected generation's policy documents, in the v1 format
specified in [ARCH_POLICY.md](ARCH_POLICY.md#the-boundary): the node default
(`default.json`) or the signing key's own document
(`policies/<selector>.json`), whichever governs the key. Every policy field
below is required in each document; the "Shipped default" column is the value
in the embedded signer default a fresh store starts from.

| Setting | Source | Shipped default | Description |
|---------|--------|-----------------|-------------|
| `user_auto_approve` | `identities/default/config.yaml` | `false` | Sign requests that are not auto-rejected, forced to review, or explicitly auto-approved without TUI confirmation. |
| `transaction_types` | policy document (default or the key's own file) | `{"*": "allow"}` | Per-type verdict evaluated before every other rule: `reject` is a hard rejection, `review` forces operator review, `allow` continues to the rules below; `*` covers every type not named. |
| `reject_foreign_rekey` | policy document (default or the key's own file) | `true` | Reject txns whose non-zero `RekeyTo` target is not held by the current signer before approval. |
| `reject_close_remainder` | policy document (default or the key's own file) | `false` | Reject txns with non-zero `CloseRemainderTo` before approval. |
| `reject_asset_close` | policy document (default or the key's own file) | `false` | Reject txns with non-zero `AssetCloseTo` before approval. |
| `reject_clawback` | policy document (default or the key's own file) | `false` | Reject ASA clawback txns using `AssetSender` before approval. |
| `always_review_warnings` | policy document (default or the key's own file) | `true` | Force operator review for warning-level findings before auto-approval or `user_auto_approve:true` can sign. |
| `auto_approve_self_noop_transfer` | policy document (default or the key's own file) | `false` | Auto-approve a single 0 ALGO payment to self or 0-unit ASA transfer to self only when it has no caller-provided group, no passthrough/foreign slots, no rekey, no close remainder, no asset close, no clawback sender, no note, no lease, and normalized fee is at most 1000 microAlgos. Signer-generated LogicSig-budget dummies are allowed only when they exactly match APlane's dummy transaction shape and fee adjustment. |
| `max_fee_microalgos` | policy document (default or the key's own file) | `"0"` (no cap) | Reject txns whose fee exceeds the raw microAlgo ceiling. |
| `limits` | policy document (default or the key's own file) | none | Optional per-network, per-asset `review_above` (force review) and `reject_above` (reject) thresholds for ALGO payments (microAlgos) and ASA transfers (base units), as decimal strings keyed by `algo` or `asa:<id>`. |
| `transfer_policy` | policy document (default or the key's own file) | one `self-transfer` route; `on_no_route`, `close_on_no_route`, and `clawback_on_no_route` all `operator_default` | Route table for direct `pay` and `axfer` movements and the verdict for a movement no route covers. |

Signing behavior is governed by hard-reject safety policy, warnings, and approval.

---

## Policy and Approval

For the canonical current policy verdict model, see
[ARCH_POLICY.md](ARCH_POLICY.md). This section focuses on transaction-flow
consequences.

Signing resolves the policy per signing key (the key's own document, or the
node default) from one snapshot captured when the request's signing service
is built, then uses:

- the transaction-type verdict (`transaction_types`) first: `reject` is a
  hard rejection and `review` forces review, both as `transaction_type:<type>`,
- hard-reject signer safety policy before approval,
- forced-review policy before auto-approval,
- explicit auto-approval policy for narrow low-risk requests,
- warning analysis for operator-visible risk surfacing: rekey, close-out,
  asset close, clawback, application delete, clear-state, or update, asset
  reconfigure or destroy, asset freeze or unfreeze, and unusually high fees;
  under `always_review_warnings` these force review on the signer's own legs,
  and a warning on a passthrough or foreign leg forces review regardless,
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

### Approval Waits and Cancellation

Signing approval timeout is the product-runtime `approval_wait` value,
defaulting to 60 seconds.

For HTTP `/sign`, request context cancellation cancels queued or pending manual
approval waits when the cancellation reaches apsigner. Clients that need
reliable prompt dismissal across tunnels or other transports should also send
`POST /sign/cancel` with the same `request_id` from a fresh request context.
Canceled approval requests are removed from the coordinator and must not be
delivered later as stale prompts. If the request was already sent to an admin
client, apsigner sends a best-effort `sign_request_canceled` notification with
reason `client_canceled` so the client can dismiss the prompt. Approval timeout
also removes the request and sends `sign_request_canceled` with reason
`timeout`. Both are distinct from operator rejection; the current HTTP mapping
is service unavailable. An unknown or no-longer-live `request_id` returns
`not_found`. Request IDs are not scoped per principal: the lookup is global
across authenticated clients. `/sign/cancel` request and
response shapes and the `canceled`/`not_found` states are in
[Sign Cancellation Semantics](#sign-cancellation-semantics).

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

// After checking the response, decode every nonempty slot and submit the group once.
var groupBytes []byte
for _, hexStr := range resp.Signed {
    signedBytes, err := hex.DecodeString(hexStr)
    if err != nil || len(signedBytes) == 0 { /* abort incomplete/invalid group */ }
    groupBytes = append(groupBytes, signedBytes...)
}
_, err = algodClient.SendRawTransaction(groupBytes).Do(ctx)
```

---

## How the Server Derives What to Sign

The server looks up the key type for `auth_address` and derives the message to sign:

| Key Type | Message to Sign | Rationale |
|----------|-----------------|-----------|
| `ed25519` | Full transaction bytes (`TX` + msgpack) | Standard Algorand Ed25519 signing |
| `falcon1024` | Full transaction bytes (`TX` + msgpack) | Native Falcon-1024 authorization into `SignedTxn.PQsig` |
| `aplane.falcon1024.v1` (or other DSA) | 32-byte transaction ID | LogicSig DSA schemes sign the transaction ID |
| `aplane.htlc.v1` (or other generic) | N/A (no signing) | Generic LogicSigs don't need signatures |

This design achieves **true client key-type agnosticism**: clients send transaction bytes rather than cryptographic signing preimages.
They still route on advertised signing flows and resource metadata.

---

## Bounded-Cosigner Spend Flow

For inventory rows with `signing_flow: bounded-cosigner1`, the client must:

1. call `POST /plan` to freeze canonical bytes, dummies, fees, and group ID;
2. call `POST /sign/component` with `kind:"bounded-base"` on the user signer, which validates the
   group and applies signer policy/operator approval before returning base args
   and the assembly receipt;
3. finish any ordinary signer slots through `/sign`, then request the
   cosigner-role signature over those exact finalized bytes with
   `POST /sign/component`;
4. call `POST /sign/assemble` on the user signer with both components;
5. submit or simulate the exact returned signed group.

Ordinary `/sign` rejects these spends. Contract-admin rekey remains a separate
flow and never contacts the cosigner.

## Bounded Contract-Admin Rekey Flow

An admin-key bounded profile keeps pure spending on `/sign`, but routes a pure
rekey through a typed partial flow:

1. The client constructs a pure zero-amount self-payment rekey.
2. The separate `aprekey` administrative client calls
   `POST /sign/bounded-admin`, which performs canonical planning, policy,
   forced review, approval, dummy/fee/group finalization, and Falcon spending
   signing.
3. Apsigner verifies the spending signature and returns finalized unsigned
   transactions plus one aligned partial LogicSig. It never returns the partial
   in `signed[]` and never handles contract-admin private material.
4. `aprekey sign` independently decodes the finalized group, verifies
   the pure rekey shape, bounded profile, program binding, Contract Admin Key ID,
   transaction ID, and spending signature, then confirms and adds the external
   Falcon signature.
5. Completion verifies both signatures, preserves every unsigned byte and group
   ID, rechecks authorization/network/validity state, and submits directly to
   Algod without replanning.

Online `aprekey rekey` performs these stages directly. The separated
ceremony path splits them across `prepare-rekey`/`prepare-unrekey`, offline
`sign`, and `complete` using `.apbounded-admin-request` and
`.apbounded-admin-signature` files.

## Summary Table

| Aspect | Ed25519 | Native Falcon-1024 | LogicSig DSA | Generic LogicSig |
|--------|---------|--------------------|--------------|------------------|
| **What server signs** | Full txn bytes | Full txn bytes | 32-byte transaction ID | N/A |
| **Signature size** | 64 bytes | variable, at most 1,538 bytes | variable, at most 1,423 bytes (Falcon) | N/A |
| **Needs dummies** | No | No (adds native-PQ fee units) | According to pooled argument/opcode resources | According to pooled argument/opcode resources |
| **Runtime args** | No | No | Optional for composed DSA | Optional |
| **Authorization** | Signature verification | Protocol verifies `PQsig` | TEAL verifies sig | TEAL logic only |

Bounded LogicSig DSA is the transaction-aware case: pure spends and
spending-key rekeys use their declared base, derived, and runtime argument
slots, while an admin-key rekey uses a signer partial plus an externally
completed Falcon contract-admin slot. A cosigner-enabled bounded spend inserts
the cosigner source between Layer-3 and admin slots and uses the user-first
bounded component choreography above.

---

## HTTP API Contract

> **Compatibility-bearing.** Everything under this heading is wire contract:
> request/response shapes, status codes, fixed runtime binding, the
> `/sign/cancel` lifecycle, the error model, and SDK contracts.

This contract is consumed by `apshell`, the in-tree `internal/signerclient`, and external SDK clients in the `aplane-algo/aplanesdk` repo (Go, TypeScript, Python). It documents the request/response wire format, status codes, fixed runtime binding, the `/sign/cancel` lifecycle, the error model, and the SDK contracts.
The DTO and error-code source of truth is `pkg/signerapi`, which in-repo
callers import directly.

The current signer HTTP protocol is `2.0`. Version 2 removes the signer-owned
ordinary and guarded simulation endpoints and their DTOs. Simulation-capable
clients must use ordinary signing followed by client-side algod simulation.
This is a coordinated breaking change: clients that call the removed routes
receive `404` and must be upgraded with apsigner.

The product-facing HTTP API is a single-signer API. A request is authenticated
by the SSH connection it arrived on: the enrolled client key that authenticated
that connection becomes the request's `client:<fingerprint>` principal, and
every authenticated handler uses the process-owned product runtime. HTTP requests and authorization
resources carry no runtime or store selector. Status and audit fields identify
request state and principals without a runtime ID.

### Endpoints

| Method | Path | Auth | Requires Unlock |
|--------|------|------|-----------------|
| `GET` | `/health` | no | no |
| `GET` | `/status` | yes | no |
| `GET` | `/keys` | yes | yes |
| `GET` | `/keytypes` | yes | no (but template-backed types appear only after unlock) |
| `POST` | `/sign` | yes | yes |
| `POST` | `/sign/bounded-admin` | yes | yes |
| `POST` | `/sign/component` | yes | yes |
| `POST` | `/sign/assemble` | yes | yes |
| `POST` | `/sign/rotating/prepare` | yes | yes |
| `POST` | `/sign/rotating/sign` | yes | yes |
| `POST` | `/sign/cancel` | yes | no |
| `POST` | `/plan` | yes | yes |
| `POST` | `/admin/generate` | yes | yes |
| `DELETE` | `/admin/keys` | yes | yes |

Method enforcement:

- `/sign`, `/sign/bounded-admin`, `/sign/component`, `/sign/assemble`,
  `/sign/rotating/prepare`, `/sign/rotating/sign`, `/sign/cancel`, `/plan`,
  `/status`, `/admin/generate`, and `/admin/keys` enforce their HTTP method.
- `/keys`, `/keytypes`, and `/health` are operationally `GET` endpoints and accept wrong methods for compatibility.

Transport behavior:

- all responses are `Content-Type: application/json`,
- non-2xx responses use `signerapi.ErrorResponse` with top-level `error` plus
  a stable machine-readable `code` (see `pkg/signerapi/error_codes.go`);
  clients branch on `code`, never on `error` message text; endpoint-specific
  success DTOs are not the error envelope,
- request `Content-Type` is not enforced,
- malformed JSON returns `400`,
- oversized bodies return `413`,
- request body limit is 5 MB for POST endpoints.

Error codes:

The stable wire-contract `code` values that SDK clients branch on are defined in
`pkg/signerapi/error_codes.go`; their HTTP status mapping is owned by
`internal/signerapp/svcerr` (`Kind.HTTPStatus()`):

| Code | Meaning | HTTP status |
|------|---------|-------------|
| `bad_request` | malformed or invalid request input | `400` |
| `unauthorized` | missing or invalid authentication | `401` |
| `forbidden` | authenticated request the signer refuses (policy or role) | `403` |
| `locked` | signer keystore is locked | `403` |
| `not_found` | unknown key or resource | `404` |
| `invalid_passphrase` | passphrase verification failure | `403` |
| `unavailable` | temporary inability to serve the request | `503` |
| `cache_refresh` | store mutated but the signer key cache failed to refresh | `500` |
| `internal` | unexpected server-side failure | `500` |
| `bounded_admin_required` | admin-key bounded operation sent to ordinary `/sign` | `400` |
| `bounded_cosigner_required` | cosigner-gated bounded spend sent to ordinary `/sign` | `400` |
| `rotating_signing_required` | rotating account sent to `/plan`, `/sign`, `/sign/bounded-admin` or `/sign/component` | `400` |
| `rotating_stage_unproven` | the signer has not yet found the rotating account's live stage; its background scan continues and a retry usually succeeds | `409` |
| `rotating_stage_changed` | the account's authorizer moved between prepare and sign; nothing was signed, rebuild and prepare again | `409` |

An empty `code` means the server predates code support or the failure had no
specific classification. New codes may be added; existing values must not change
meaning.

Timeout behavior:

- `apsigner` sets HTTP `ReadHeaderTimeout` to 5 seconds, `ReadTimeout` to 30
  seconds, `IdleTimeout` to 120 seconds, and `WriteTimeout` to
  `MaxApprovalWait + 2m` so a valid manual approval wait can complete before
  the server write deadline.
- The REST listener accepts at most 64 concurrent connections; further
  connections wait in the kernel accept queue until one closes. Request
  headers are limited to 64 KiB (`431 Request Header Fields Too Large`
  beyond that). Both bound what unauthenticated loopback clients can make the
  signer allocate; `mlockall` keeps that memory resident.
- Only authenticated requests keep their connection alive. Every response to
  an unauthenticated request (`/health`, authentication failures, unknown
  routes) carries `Connection: close`, so an unauthenticated client holds a
  connection slot for at most one request and its header timeout and cannot
  keep every slot busy with keep-alive requests.
- the repo-owned `internal/signerclient` uses per-request default deadlines:
  `/health` 3 seconds, `/status` 5 seconds, inventory requests 30 seconds,
  mutations 60 seconds, `/plan` 60 seconds,
  `/sign/rotating/prepare` 60 seconds, `/sign/cancel` 5 seconds,
  `/sign/component` 2 minutes for cosigner targets, `/sign/assemble` 2 minutes,
  and `/sign`, `/sign/bounded-admin`, `/sign/rotating/sign`, or
  approval-bearing `/sign/component` based on approval wait.
  User and bounded-base `/sign/component` requests can
  block on operator approval and use the same approval-aware deadline as
  `/sign`.
- caller-provided contexts with earlier deadlines are preserved.
- before `/sign`, `internal/signerclient` attempts `/status` discovery; when
  `approval_wait_seconds` is known and valid, the `/sign` deadline is
  `approval_wait + 30s`, otherwise it falls back to 6 minutes.
- external SDK clients should mirror the same effective behavior for `/sign`.
  A fixed SDK default shorter than the product-runtime approval wait is a
  compatibility bug because it can cancel a valid manual approval flow before
  apsigner's approval timeout expires.

Fixed runtime binding:

- HTTP auth resolves the enrolled client key of the request's SSH connection
  to a `client:<fingerprint>` principal; requests carry no credential, and the
  loopback listener answers only `/health`.
- authenticated handlers use the process-owned product runtime; requests carry
  no runtime or store selector.
- missing or invalid credentials return `401`; authorization failures return
  `403`.

### Request/Response Shapes

`/sign` and `/plan` share request type `signerapi.GroupSignRequest`
from `pkg/signerapi/types.go`:

- top-level fields: optional `request_id`, `requests[]`
- each entry is one of:
  - sign: `auth_address`, optional `txn_sender`, `txn_bytes_hex`, optional `lsig_args`, optional `app_call_info`
  - passthrough: `signed_txn_hex`; if the signed envelope uses LogicSig,
    `lsig_resources` is required
  - foreign: `txn_bytes_hex` without `auth_address`, with at most one
    authorization-resource hint: optional `lsig_resources` or native-PQ
    `pq_scheme` (`f1`)

The signer derives authorization shape for locally held keys. An unsigned
foreign native-PQ slot must declare `pq_scheme:"f1"` so pooled protocol fees
are correct. A foreign LogicSig slot declares `lsig_resources` with
`program_bytes`, `argument_bytes`, and `max_opcode_cost`.

A passthrough LogicSig also requires `lsig_resources`. The signer verifies
`program_bytes` and `argument_bytes` against the signed envelope and uses the
declared reviewed `max_opcode_cost`; it never substitutes a guessed minimum for
immutable foreign bytecode. Supplying `lsig_resources` for a non-LogicSig
passthrough is rejected. The retired combined `lsig_size` field is rejected
explicitly rather than ignored, because silently dropping it would understate
LogicSig resources.

`txn_sender` is an advisory display hint for clients. Signer authority,
policy, and audit decisions use the sender decoded from `txn_bytes_hex`.

`app_call_info` is approval-rendering metadata on the shared request DTO:

- `mode`: `raw` or `abi`
- `method`: ABI method signature when `mode:"abi"`

`/sign` uses `app_call_info` to render application-call approval prompts.
`/plan` accepts the same request DTO but does not perform approval or signing.

`request_id` is optional and is used by `/sign` to correlate a live synchronous
sign request with a later `/sign/cancel` request. If absent, apsigner generates
an internal request ID for approval display as before, but external clients
cannot cancel it by ID. Clients that need explicit cancellation should set
`request_id` to an opaque ASCII identifier of at most 128 characters using
letters, digits, `-`, `_`, `.`, or `:`.

See [Mode Selection](#mode-selection) for the foreign/passthrough/sign distinction. The contract surface:

- Both endpoints accept the same per-entry modes; mixing passthrough and foreign in one request is invalid, and all-foreign requests are rejected on both endpoints.
- `/plan` performs canonical group building only. It never touches keys and returns canonical unsigned transactions in `transactions[]`.
- `/sign` performs canonical group building plus approval/signing.
  Signer-controlled guarded account keys are rejected before approval because
  they require the guarded component/assembly endpoints; `/plan` may admit
  them to freeze those guarded workflows. Transaction-level hard policy is
  applied only to signer-controlled slots; passthrough and foreign entries
  contribute to group consistency, approval context, warning analysis, and
  audit visibility.
- `/sign/bounded-admin` performs the same planning, policy, forced review, group
  finalization, and spending-key signing for one admin-key-authorized pure
  rekey, then returns a typed partial for external contract-admin completion.
  It never loads a contract-admin private key and never returns the partial
  through `signed[]`.
- Apsigner has no simulation endpoint or simulation request mode. Full
  simulation obtains an executable group through ordinary `/sign`; guarded
  and bounded-cosigner groups both use `/plan`, `/sign/component`, and
  `/sign/assemble`, and the client verifies the assembled group against the
  frozen canonical bytes. The client then sends the exact returned group to its configured algod simulate
  endpoint. Apsigner cannot distinguish this from a request whose result will
  be submitted, so policy, review, approval, signing, and audit semantics are
  identical.
- Client simulation fails before requesting signatures when no client algod is
  configured. Once signatures are returned, the client holds reusable,
  network-submittable bytes until their validity window expires.
- Plugin-generated simulation follows the same rule: canonicalize as needed,
  obtain every managed signature through ordinary signing, preserve plugin
  passthrough signatures, and send the exact final group from the client to
  algod simulation.
- First-party client workflows validate the live algod consensus identifier
  before asking apsigner to plan, requesting or releasing signatures, invoking
  plugin signers, or broadcasting/simulating a pregrouped signed group. This is
  an apshell/engine boundary; apsigner's `/plan` endpoint remains
  network-independent and uses its compiled v42 contract without querying
  algod.

`/sign` response (`signerapi.GroupSignResponse`):

- `signed`
- optional `mutations`
- optional `error`: legacy DTO field the current server never populates;
  errors arrive as a non-2xx `ErrorResponse`

`/sign` response semantics:

- `signed[]` always aligns 1:1 with the finalized group positions.
- sign-mode entries contain hex-encoded signed transaction msgpack blobs.
- passthrough entries contain the original signed transaction bytes, returned unchanged.
- foreign entries contain the empty string `""`.
- server-added dummy slots appear as appended signed dummy transactions.
- The ordinary client `/sign` path treats `mutations` as an authorization to
  transform transaction bodies, not merely as display metadata. Before
  simulation or submission it verifies the report counts and fee delta,
  permits only reported fee increases and group-ID assignment on original
  positions, recomputes the canonical final group ID, and reconstructs every
  appended dummy transaction and its embedded LogicSig authorization. Any
  unreported field change, malformed report, or non-canonical dummy fails
  closed on the client.
- Admin-key bounded operations are rejected with `code:"bounded_admin_required"`;
  pure spends and explicitly spending-key-authorized rekeys return complete
  base-argument LogicSigs from `/sign` only when no cosigner is required.
- Cosigner-enabled bounded spends are rejected with
  `code:"bounded_cosigner_required"`; they must use the `bounded-cosigner1`
  choreography below.
- Rotating accounts (`signing_flow: rotating1`) are rejected before approval
  with `code:"rotating_signing_required"` on `/plan`, `/sign`,
  `/sign/bounded-admin` and `/sign/component`.

`/plan` response (`signerapi.GroupPlanResponse`):

- `transactions`
- optional `mutations`
- optional `error`: legacy DTO field the current server never populates;
  errors arrive as a non-2xx `ErrorResponse`

`MutationReport` fields:

- `dummies_added`
- `group_id_changed`
- `fees_modified`
- `total_fees_delta`
- `original_count`
- `final_count`
- `passthrough_count`
- `foreign_count`
- `reason`

`/sign/bounded-admin` request (`signerapi.BoundedAdminRequest`) carries optional
`request_id`, `operation:"rekey"`, and shared `requests[]`. V1 requires exactly
one sign-mode pure rekey, no caller LogicSig arguments, and no passthrough,
foreign, or unrelated signable entries. The signer may append budget dummies.

`/sign/bounded-admin` response (`signerapi.BoundedAdminPartialResponse`) contains:

- `schema:"aplane.bounded-admin-partial.v1"` and `operation:"rekey"`
- finalized TX-prefixed unsigned `transactions[]`
- aligned `partial_signed[]`, with a spending-only LogicSig at `target_index`
  and empty strings in every other slot
- `authorization` with Contract Admin Key ID, public and spending public keys,
  program binding, finalized transaction ID, diagnostic message, base argument
  count, spend effects, and maximum fee
- optional `mutations`

The response is not submission-ready. `message_hex` and every other derived
authorization field must be recomputed by the completing helper from the
finalized transaction, durable metadata, and program contract.

`/sign/component` accepts `signerapi.ComponentRequest`: optional `request_id`,
frozen TX-prefixed `group_bytes_hex[]`, discriminated `targets[]`, foreign-only
`contextual_positions[]`, and a contiguous `dummy_positions[]` suffix. The
three position sets form a closed partition. Target `kind` is `user`, `cosigner`,
or `bounded-base`; kind-specific fields are rejected on other kinds.
Dummy classification is semantic in both directions: every declared dummy must
match the canonical signer-added suffix form, and a canonical dummy suffix may
not be relabeled as caller-supplied original positions.

The endpoint never plans or mutates a group. User and bounded-base targets are
policy- and operator-gated and use the live `/sign/cancel` lifecycle. Cosigner
targets use deterministic cosigner policy without operator approval. Bounded-base
authorization is reconstructed from frozen bytes and signer-held metadata,
including resources, fees, runtime arguments, and the canonical dummy suffix.
The response is `signerapi.ComponentResponse`, with `request_id` and
kind-tagged `components[]`. User/cosigner components carry `signature`; bounded
components carry `auth_address`, `base_signatures[]`, canonical `runtime_args`,
and `assembly_receipt`. Every component carries `target_index`, `kind`, and
`signature_scheme`.

The Falcon-signed bounded assembly receipt commits to the account, target TxID,
normalized durable metadata, and sorted runtime arguments under
`APLANE_BOUNDED_COSIGNER_ASSEMBLY_V1`. It prevents transplanting released base
material into another account, metadata instance, or runtime-argument set.

`/sign/assemble` accepts `signerapi.AssemblyRequest`: optional `request_id`,
the frozen group, discriminated `targets[]`, and optional `passthrough[]`.
Guarded targets carry user and cosigner signatures; bounded-cosigner targets carry
base signatures, runtime arguments, an assembly receipt, and a cosigner
signature. Every position is covered exactly once. The response is
`signerapi.AssemblyResponse` with `request_id` and aligned `signed_group[]`.

Assembly keeps the authorization models distinct. Guarded targets are verified
against their local guarded account key and both component signatures. Bounded
targets reload durable metadata, verify receipt and both authorities against
the frozen TxID, derive only declared signer-generated arguments, and check the
LogicSig address and authorizer. Contract-admin paths never use this endpoint
or contact a cosigner. Assembly request IDs are correlation-only and are not
cancelable through `/sign/cancel`.

#### Rotating accounts (`rotating1`)

A rotating account keeps one address while its authorizing stage program
changes on every spend. Stage `n` is a program over the Falcon-1024 and
Ed25519 keys derived for `n` from the account's seed; stage 0's program
address is the account. Both endpoints use the `sign_request` action,
resolve the key by the account address, refuse any account that is not
rotating, and read the account's authorizer and the round from the signer's
own node (see `ARCH_NETWORKS.md`). The signer keeps no durable state for the
account between requests: the chain says which stage is live, the seed says
which stage comes next.

The invariant every release upholds: a signature from stage `n` is released
only while `n` is the authorizer, and its transaction rekeys the account to
stage `n + 1`. So every landed rotation installs a stage that has never
signed, and the keys a signature reveals control the account only until that
transaction, or a later rotation, confirms.

`/sign/rotating/prepare` request (`signerapi.RotatingPrepareRequest`):

- `account`: the rotating account address
- `txn_bytes_hex`: one unsigned, ungrouped, TX-prefixed transaction from the
  account, with no `rekey_to`, no close-out, the account's genesis hash, and a
  validity window of at most 100 rounds
- optional `request_id`

The signer reads the authorizer, finds its stage `n` (through the stage
address table, confirmed by derivation), sets `rekey_to` to stage `n + 1`'s
address derived from the seed, adds the resource dummies the key type's
profile needs (one for the Falcon hybrid, two for the WOTS hybrid), sets fees
and the group ID, and returns the exact unsigned group. It stores nothing.
Preparation needs no approval and reveals nothing secret. An account whose
live stage the signer has not found yet is refused with
`rotating_stage_unproven` after a bounded foreground search (30 s); the
background scan continues and a retry succeeds once it has caught up.

`/sign/rotating/prepare` response (`signerapi.RotatingPrepareResponse`):

- `account`, `rekey_to`
- `stage`: the live stage, which will sign; `target`: always `stage + 1`
- `transactions`: the final unsigned group, TX-prefixed hex
- `mutations`: the ordinary mutation report (dummies, fees, group ID)

Clients simulate exactly these bytes and send them back unchanged.

`/sign/rotating/sign` request (`signerapi.RotatingSignRequest`):

- `account`
- `transactions`: the prepared group
- optional `request_id`, cancelable through `/sign/cancel` while live

The group's `rekey_to` names stage `n + 1`, which fixes `n`; the request
carries no stage of its own and nothing is carried over from prepare. The
signer finds `n + 1` in the table, re-derives stage `n + 1` from the seed
and refuses unless it matches `rekey_to`, and rebuilds the group from the
presented spend: the result must be byte-identical to what was presented,
so the group can only be that spend plus the rotation's own `rekey_to`,
fee, group ID and canonical dummies. The signer keeps nothing from prepare,
so it does not and cannot check that the presented spend is the one the
client prepared: a client may change the spend between the two calls, and
what the signer binds is the presented transaction, which is what policy
evaluates and the operator sees. Preserving the user's intent across
prepare and sign is the client's job (first-party clients verify the
prepared group against the transaction they sent, below). It then runs the
ordinary policy gates and operator approval; the rotation target counts as
the signer's own address, so `reject_foreign_rekey` does not apply to it. After approval, under the
account's lock, it reads the chain again and refuses unless the authorizer
is still stage `n` (`rotating_stage_changed` otherwise: nothing was signed),
`first_valid` is at most 2 rounds ahead of the round read, and at least 10
rounds remain before `last_valid`. It proves stage `n + 1` can sign, signs
the TxID with stage `n`'s two keys (Falcon-1024 and Ed25519, or WOTS and
Ed25519), verifies both,
writes a `ROTATING_RELEASE` audit entry (account, TxID, stage, `last_valid`)
with a durable sync, records the release in memory, and responds. An audit
write failure is logged as a warning and does not withhold the signature:
the entry only feeds the alerts below, so a release missing from the log is
one whose alert cannot be restored after a restart, never a safety gap.

There is no limit on releases per stage. Two spends prepared from the same
stage both rekey to the same `n + 1`; whichever lands second is rejected by
the ledger ("should have been authorized by"), and nothing the signer could
store would change that outcome.

`/sign/rotating/sign` response (`signerapi.RotatingSignResponse`):

- `signed`: the signed group, hex msgpack; the spend carries the stage program
  as its LogicSig and an `auth_address` for stages above 0
- `stage`: the stage whose keys the signature revealed; `target`: `stage + 1`
- `txid`, `group_id`: the identifiers clients use to track the outcome

Creating and using rotating accounts:

- `aplane.rotating-hybrid.v1` (Falcon-1024 + Ed25519 stages) and
  `aplane.rotating-wots-hybrid.v1` (hash-based WOTS + Ed25519 stages) are
  `Library` key types: an operator enables one, then generates with the
  single creation parameter `network`: any network the signer knows
  (built-in or configured, which `/keytypes` lists as the parameter's
  `options`), or a base64 genesis hash. Both use this flow unchanged; they
  differ only in the stage program and its resource profile. Like every key
  type, their recovery material never leaves the signer: neither the admin
  protocol nor HTTP returns the mnemonic, and backups carry the seed.
  Mnemonic import is refused.
- First-party clients route on the sender's own `signing_flow: rotating1`,
  not on its on-chain authorizer, which is a stage address the signer never
  lists. A rotating spend is sent alone; the client caps its validity window
  at 100 rounds and rebuilds it when it has aged, prepares, verifies that the
  prepared group changed only `rekey_to`, the spend's fee, the group ID and
  canonical dummies and that `target` is `stage + 1`, simulates the unsigned
  group, and only then signs and submits exactly the returned bytes. A
  `rotating_stage_changed` or window-timing refusal means nothing was signed,
  and the client rebuilds and prepares again a bounded number of times.
  Simulate-only requests stop before signing, so they reveal no keys.

Restore: a rotating key restored from a backup, rebuilt or re-imported has
everything it needs. The signer reads the live stage from the chain and
rebuilds the stage address table
([ARCH_STORE.md](ARCH_STORE.md#stage-address-tables)) in the background; until the table reaches the live stage,
requests are refused with `rotating_stage_unproven` and `/status` carries a
note ("stage not yet found, N stages scanned"). No operator recovery step
exists or is needed.

Alerts: the signer remembers the newest release per account (stage, TxID,
`last_valid`) in process memory, rebuilt at unlock from the newest
`ROTATING_RELEASE` audit entry per account (read from the audit log and its
two rotated predecessors; entries the log has rotated past are simply
absent), and checks every rotating account's authorizer on its own node right
after unlock and then about every 30 seconds while unlocked (a nominal
interval: chain reads and paced derivation can stretch it). A release whose
`last_valid` has passed while its stage is still the authorizer raises a
warning: that transaction can never confirm and the revealed keys still
control the account. A release still within its window is a note. A read
that shows the account past the release clears it; a stale read never
erases a newer release. Only the newest release is kept, but a release
that replaces one from the same stage over a different TxID marks the
record as reused (a retry that re-records the same TxID does not), and the
mark survives until the account moves past the stage; the audit reader
applies the same rule across the entries it can see, so a reuse older than
the retained log goes unreported. An earlier release from the same stage
that expired while a newer one is still within its window is reported
through the newer one: the stage is the same, and the newer transaction
either lands and moves the account or expires and raises the warning, which
then also says the stage has signed more than one transaction. For a key
type whose stage signature is one-time (`aplane.rotating-wots-hybrid.v1`),
a reused stage that is still live raises a warning even while the newest
release is within its window: the stage is Ed25519-only until the account
moves. For other types the reuse is harmless and only appears in the
in-flight note. Warnings appear in the daemon log once when they
appear and once when they clear, in authenticated `/status` `warnings`, in
apadmin's status bar, and in apshell's `rotate status`; notes appear in
`/status` `notes`. The remedy for an expired release is a rotate-only spend
through the endpoints above. Alerts are observational: safety does not
depend on them, on the table, or on the audit log.

`/keys` response:

- `count`
- `keys[]` with `address`, `public_key_hex`, `key_type`
- optional `authorization_kind` with closed account-authorization values
  `ed25519`, `native_pq`, or `logic_sig`. It is derived from the durable key
  category and is authoritative for choosing the transaction authorization
  envelope. Witness rows omit it because they are not spending accounts.
- optional `signing_flow`: explicit signing choreography label. `cosigner1`
  selects legacy guarded component signing, `bounded1` selects bounded routing
  without an online cosigner, `bounded-cosigner1` selects the user-first bounded
  component/cosigner/assembly flow, `rotating1` selects the rotating account
  prepare and sign flow, and empty means ordinary `/sign`. Clients
  dispatch these cases explicitly and fail closed on labels they do not
  implement.
- optional `cosigner_component_key_type`: the cosigner component key type used by
  this key's `signing_flow` (for `cosigner1` or `bounded-cosigner1`)
- optional `bounded_authorization`: present for `signing_flow: bounded1` and
  `bounded-cosigner1`.
  It contains `contract`, `base_signature_arg_layout`,
  `spend_effects`, `max_fee`, `admin_operations` (including each operation's
  `policy_gate`), `runtime_args`, `derived_args`, the path-specific
  `argument_layout`, and `layer3_policy`. `/keys` also includes instance-only
  `admin_key_id` and `program_binding` when
  applicable. This is routing and assembly metadata, not permission; signer
  classification and stored bytecode remain authoritative.
- optional `logic_sig_resources`, containing final compiled program bytes and
  path-specific argument-byte and maximum-opcode-cost ceilings
- optional `is_generic_lsig`
- optional `is_witness_key` and `is_spending_account`: cosigner-key rows use
  `address` as the Witness Key ID, not as an Algorand spending address.
  Witness Key IDs are always 52-character uppercase base32
  SHA-512/256 digests over the domain-separated key-type/public-key tuple;
  `public_key_hex` carries the full component public key.
- optional `signing_args`: the key file's stored signing schema captured at
  generation time, not the live template/provider schema; this is what the
  signer enforces at sign time for that specific key. SDK consumers must treat
  an absent field the same as an empty list.
- optional `parameters`: non-secret key creation parameters needed by clients
  to orchestrate key-type-specific workflows. For guarded account rows this
  includes `cosigner_public_key`, the cosigner public key embedded in the
  account LogicSig bytecode. Its key family and size are determined by the
  guarded account `key_type`. SDK consumers must treat this as signer-owned
  metadata, not as proof of remote cosigner endpoint ownership.
  Bounded rows expose only the reviewed public parameter projection used by
  the bundled profiles (`recipients`, asset/amount limits, `unlock_round`, and
  framework cosigner/admin public keys). Newly stored bounded parameters are
  omitted until explicitly classified as public; `/keys` never defaults to
  exposing the complete stored creation-parameter map.
- optional `template_provenance_status`, `template_provenance_note`; these are
  informational, version-aware comparisons between stored key template
  provenance and the registered local definition, not signing gates. The
  fingerprint is behavior-only and versioned (`<n>:` prefix), so renaming a
  `key_type`, family, or base key type does not by itself produce a conflict

`template_provenance_status` values:

- `conflict`: the stored `template_fingerprint` and the registered local
  provider/template fingerprint for `key_type` are the **same fingerprint
  version** but differ — a genuine behavior difference
- `unavailable`: no provider/template fingerprint can be resolved for
  `key_type`, **or** the stored and registered fingerprints are a different
  version or malformed (not comparable). A different-version or malformed
  comparison is benign and is never reported as a `conflict`

Absence of `template_provenance_status` means no provenance note is known or no
stored provenance was available. These fields do not change `/sign` behavior.

`/status` response:

- `node_role`: optional signer node role (`signer` or `cosigner`); omitted when unset
- `protocol_version`: signer HTTP API protocol version `{major, minor}`; this
  is diagnostic surfacing, not capability negotiation
- `build_version`: apsigner build string for skew diagnosis
- `state`: runtime state (`locked`, `unlocked`, `recovery`, or `unknown`)
- `signer_locked`
- `ready_for_signing`
- `key_count`: number of loaded keys
- `keyset_revision`: process-local unsigned revision counter for the published
  key snapshot. It starts at `0` on process start and increments after each
  successful key reload/snapshot publish. Clients may compare this value across
  status polls to decide whether to refresh `/keys`; it is not a durable
  storage version and must not be compared across apsigner restarts.
- `approval_wait_seconds`: effective manual signing approval wait, in seconds,
  for the product runtime. Clients may use this value to size `/sign`
  request deadlines. Clients must tolerate this field being omitted.
- `warnings`: optional persistent operator-facing health warnings. Clients
  should display non-empty warnings and must tolerate this field being omitted.
  They include rotating account alerts (see Rotating accounts); those name
  accounts and never appear on `/health`.
- `notes`: optional informational lines that need no action, such as a
  rotating account's release still in flight or a live stage the signer is
  still scanning for. Clients must tolerate this field being omitted.

`/keytypes` response:

- `key_types[]` with `key_type`, `family`, `display_name`, `description`, optional `authorization_kind` (`ed25519`, `native_pq`, or `logic_sig`), compatibility field `requires_logicsig`, `mnemonic_word_count`, `mnemonic_import`, `mnemonic_scheme`, optional `signing_flow`, optional `cosigner_component_key_type`, optional definition-level `bounded_authorization`, `creation_params[]`, `runtime_args[]`
- each `creation_params` entry includes `name`, `label`, `description`, `type`, `required`, and optional `max_length`, `input_modes[]`, `options[]`, `min_items`, `max_items`, `min`, `max`, `example`, `placeholder`, `default`
- each `input_modes` entry includes `name` and optional `label`, `transform`, `byte_length`, and `input_type`
- each `runtime_args` entry includes `name`, `type`, and optional `label`, `description`, `required`, `byte_length`, and `max_size`

The older `requires_logicsig` boolean remains
present on key-type inventory for compatibility and is true only for
`logic_sig` entries. Clients must not infer that every false value means
Ed25519; native Falcon-1024 also has `requires_logicsig:false`.

`/keytypes` is a metadata contract. It describes enabled key types and their
creation/runtime argument shapes for new key generation. The
`runtime_args` here come from the live template/provider schema and are
distinct from the per-key snapshot returned by `/keys`, which is the source of
truth for signing an existing key. `mnemonic_import` is the explicit user-facing
mnemonic import capability; clients must not infer importability from
`mnemonic_word_count`. It does not otherwise expose whether the binary
has populated signer-side signing, keygen, mnemonic, or key-processor registries.
Client/signer provider-boundary refactors must preserve this schema and field
meaning. The `family` field carries the middle segment of the canonical
`publisher.family.vN` identifier and is intended for display and grouping;
the canonical `key_type` is what clients send back on subsequent requests.
Clients route signing by the advertised `signing_flow`; server registries and
stored metadata resolve the provider and any composed template's base primitive.
For a bounded profile with `authorization: admin_key`, creation metadata includes
the framework-injected scalar `bounded_admin_public_key` (`type:"bytes"`). It
accepts the 1,793-byte Falcon-1024 public key from an external
`.wit.json` reference. The signer derives the Contract Admin Key
ID, which is the enrolled witness's Witness Key ID, and the program binding;
neither is accepted as a separate creation input.

`/admin/generate`:

- request has `key_type`, optional `parameters`
- no `name` field
- response has `address`, optional `public_key_hex`, `key_type`, optional
  `is_witness_key`, optional `is_spending_account`, and optional `parameters`
- no mnemonic in REST response

`/admin/keys`:

- `DELETE` with query param `address`
- success response is `success: true`; non-2xx failures use `ErrorResponse`

`/health`:

- `status` (`healthy` or `degraded`)
- `service`
- `protocol_version`: signer HTTP API protocol version `{major, minor}`; this
  is diagnostic surfacing, not capability negotiation
- `build_version`: apsigner build string for skew diagnosis
- `signer_locked`
- `ready_for_signing`
- `ssh_enabled`
- `ipc_enabled`
- `warnings`: optional persistent operator-facing health warnings. `/health`
  is unauthenticated, so its warnings omit error detail such as store paths
  (the authenticated `/status` warnings keep it), and the store inspection
  behind them is reused for 5 seconds.

### Sign Cancellation Semantics

`/sign` is a synchronous HTTP API. While a request is live,
apsigner tracks its optional `request_id` in memory so `/sign/cancel` can cancel
the request context and withdraw any pending manual approval prompt. This
tracking is not a durable request table, not a polling API, and not an exposed
async signing state machine.

Cancelable: live `/sign`, `/sign/bounded-admin`, `/sign/rotating/sign`, and
approval-bearing user or bounded-base `/sign/component`. Cosigner-only
`/sign/component` and `/sign/assemble` request IDs are correlation-only. Once a cancelable request
is no longer live, later `/sign/cancel` calls return `state:"not_found"`.

`/sign/cancel` request (`signerapi.CancelSignRequest`):

- `request_id`

`/sign/cancel` response (`signerapi.CancelSignResponse`):

- `success`
- `state`
- optional `error`

`/sign/cancel` withdraws a live `/sign`, `/sign/bounded-admin`,
`/sign/rotating/sign`, or approval-bearing user or bounded-base
`/sign/component` request. It is idempotent
for client behavior. A valid, authenticated cancel request returns `200` with
`success:true`; cancellation miss is represented in `state`, not as an HTTP
error. Cosigner-only `/sign/component` and `/sign/assemble` request IDs are
correlation fields rather than live cancel handles and return `not_found` if
supplied to `/sign/cancel`.

Cancel response states:

- `canceled`: apsigner accepted cancellation for a matching live request,
  canceled a pending approval prompt, or accepted a duplicate cancel while that
  live request was unwinding.
- `not_found`: no live cancelable request matched the supplied `request_id`.

Invalid `request_id` syntax returns `400`.

### HTTP Status Mapping

| Condition | Status |
|-----------|--------|
| Malformed JSON | 400 |
| Oversized body | 413 |
| Wrong method | 405 |
| Missing/invalid credentials | 401 |
| Product runtime unavailable / node failure | 503 |
| Authorization denied by `auth.Authorizer` | 403 |
| Locked signer (handler entry) | 403 (`code:"locked"`) |
| Operator/policy rejection | 403 |
| Signer locked after planning | 403 (`code:"locked"`) |
| No approval client connected | 503 |
| Approval timeout | 503 |
| Approval wait canceled by request context or deadline | 503 |
| Invalid request shape, hex, msgpack, groups, params | 400 |
| Unknown address / missing key | 400 |
| Missing key on delete | 404 |
| LogicSig key file missing `signing_metadata_version` when used for signing | 500 |
| LogicSig key file has a missing or inconsistent derivation record (`lsig_derivation`, plus `salt_counter` only for compatible manual-counter keys) | Rejected during scan/restore; may surface as unknown address or restore failure |
| LogicSig key file bytecode derives an on-curve address | Rejected during scan/restore; may surface as unknown address or restore failure; if detected during signing, 500 |
| Internal provider failure | 500 |

Additional compatibility-sensitive request failures:

- missing `txn_bytes_hex` for sign mode: `400`
- passthrough entries without an existing group ID: `400`
- passthrough LogicSig entries without `lsig_resources`, with declarations
  whose program/argument sizes differ from the signed envelope, or with
  `lsig_resources` on a non-LogicSig passthrough: `400`
- immutable pre-grouped transactions that would require extra dummies: `400`
- requests whose required dummies would push the group above 16 transactions: `400`
- invalid runtime args or generic LogicSig arg decoding: `400`
- missing TEAL compile algod configuration for generic LogicSig generation: `500`
- missing `address` query parameter on delete: `400`
- all-foreign `/sign` or `/plan` requests: `400` because apsigner has no signer-managed work to perform

### Error Model

Internal sentinel errors include, for example, in `internal/keystore`:

- `ErrKeyNotFound`
- `ErrInvalidPassphrase`
- `ErrStoreLocked`

Errors are wrapped with contextual `%w`. Signer services classify them with
`errors.Is` into typed `ServiceError` kinds (`internal/signerapp/svcerr`), and
only the resulting `code` and HTTP status reach clients; sentinel identity and
message text are not part of the wire contract.

SDK-facing typed errors in Go include:

- `ErrAuthentication`
- `ErrNotEnrolled`
- `ErrEnrollment`
- `ErrSigningRejected`
- `ErrSignerUnavailable`
- `ErrKeyNotFound`
- `ErrSignerLocked`
- `ErrKeyDeletion`
- `ErrLogicSigRejected`
- `ErrInsufficientFunds`
- `ErrInvalidTransaction`
- `ErrTransactionRejected`
- `ErrConfigNotFound`

`TransactionError` wraps rejection details with optional TxID.

### SDK Contracts

The companion SDK source communicates via the same HTTP REST API as `apshell`,
through an SSH tunnel authenticated with the client's enrolled SSH key;
requests carry no auth header. SDK implementation and release publication are
owned by the separate `aplane-algo/aplanesdk` repository.

Cross-SDK compatibility-bearing behavior:

- concatenated-group and list-per-slot signing APIs are distinct supported shapes
- passthrough semantics are first-class for final signing; passthrough
  LogicSigs require selected-path `lsig_resources`, with observable sizes
  checked against the signed envelope
- high-level signing helpers return base64 payloads converted from server hex
- `FromEnv` and connection helper path resolution are part of the product contract
- Enrollment helpers return the authenticating key's SHA256 fingerprint and
  pending/already-enrolled state, validating the reply against the local key.
  Pending means the request was queued for later admin approval; it does not
  authorize API connections. Go exposes `RequestEnrollment`, TypeScript
  `requestEnrollment`, and Python `request_enrollment`, with endpoint-selecting
  from-env variants. Go uses `ErrNotEnrolled` for refused client authentication
  and `ErrEnrollment` for enrollment failures; TypeScript and Python expose
  `AuthenticationError` and `EnrollmentError` for those respective failures.
- SDK-native prepared transaction models carry unsigned transaction bytes plus
  signer metadata such as effective auth address, optional LogicSig args,
  optional selected-path LogicSig resource hints, optional app-call display metadata, and
  SDK-side preflight checks. Prepared groups preserve caller/apshell-equivalent
  transaction ordering before handoff to `/plan`, `/sign`, or the
  guarded component flow.
- For equivalent normalized typed transaction intents, SDK prep should converge
  with apshell's core prep behavior for transaction fields, suggested params,
  flat-fee handling, auth-address semantics, LogicSig runtime args, app-call
  metadata, and group ordering. SDKs do not need to copy shell grammar,
  aliases, prompts, or rendering.
- For ordinary APlane-managed signing, SDK prep must not take ownership of
  final group ID assignment, signer-managed dummy insertion, fee pooling,
  policy, approval, or signing. Those remain apsigner-owned behavior behind
  `/plan` and `/sign`.
- The SDKs do not expose `/sign/bounded-admin` and do not build or complete
  contract-admin rekeys (the Go SDK contract test forbids it). Ordinary SDK
  signing surfaces `bounded_admin_required`; contract-admin rekeys go through
  `aprekey`, which uses the in-tree `internal/signerclient`.
- Guarded prepared signing requires frozen canonical bytes before component
  signatures are requested. The normative SDK sequence is: classify guarded
  targets; construct intended original transactions; send those originals plus
  signer-advertised structured LogicSig resource hints to `/plan`; validate the
  returned canonical group and mutation report; derive the
  target/context/dummy position partition; locally sign only the canonical
  dummy suffix returned by `/plan`; obtain the required user, cosigner, or
  bounded-base components; call ordinary `/sign` for any non-guarded original
  positions; and call `/sign/assemble` with the frozen group and signed
  passthrough positions. Resource hints are planning inputs, not locally
  inserted transactions. Final guarded assembly remains signer-owned, and
  submission or simulation uses the exact assembled group. User-role
  `/sign/component` requests run the signer-domain approval gates and can block
  on operator approval, so SDK deadlines for them follow the same
  approval-aware rule as `/sign`, not the short cosigner-role component deadline.
- SDKs expose the authenticated `/status` DTO, including
  `protocol_version`, `build_version`, `keyset_revision`, and
  `approval_wait_seconds`, plus optional persistent operator-facing `warnings`,
  and include the matching signer API fixture in their contract suites.
- SDK `/sign` calls should include an opaque `request_id` when the client may
  need cancellation. SDKs should expose `/sign/cancel` and use it for
  best-effort cleanup when a local timeout, caller cancellation, or transport
  disconnect ends a live synchronous signing request. Go supports
  caller-initiated cancellation through `context.Context`; Python high-level
  signing accepts a caller-owned `request_id` so applications can cancel from
  another thread; TypeScript high-level signing accepts a caller-owned
  `requestId` and `AbortSignal`.

Go SDK specifics:

- `ConnectSSH(host, sshKeyPath, opts)` establishes the SSH tunnel with the client key, then HTTP
- `FromEnv(opts)` resolves the client SSH identity and signer endpoint routing from the client data dir
- `NewSignerClient(baseURL)` supports caller-owned transport and direct client construction
- `SetHTTPClient(client)` overrides the HTTP transport for advanced callers.
  If caller-owned transport sets a global timeout shorter than the effective
  signing approval wait, the SDK cannot extend that deadline.
- `GetKeysResponseWithContext(ctx)` returns `*KeysResult`, which embeds the
  `/keys` DTO (`KeysResponse`) and adds a client-side `Locked` flag; locked
  state is not part of the HTTP DTO.
- `GetStatusWithContext(ctx)` returns the raw `/status` DTO for keyset
  revision and approval-wait discovery
- `PlanRequestsWithContext(ctx, requests)` and `SignRequestsWithContext(ctx, requests)` expose server-shaped `/plan` and `/sign` request flows directly
- raw request methods operate on SDK DTOs (`SignRequest`, `KeysResponse`,
  `PlanGroupResponse`, `GroupSignResponse`) rather
  than the base64-returning convenience layer. The `/sign` response is
  `GroupSignResponse`.
- `Config.NewAlgodClient(network)` is part of the supported Go SDK config surface
- `SigningArg` is the `/keys` name for `RuntimeArg`
- input uses `go-algorand-sdk` `types.Transaction`

TypeScript and Python SDKs preserve the same broad behaviors:

- high-level convenience signing APIs return base64 payloads and may reject
  unresolved foreign placeholders when they cannot project empty foreign slots
  into single-payload returns
- list-returning and raw request APIs preserve per-slot outputs, including
  native `/sign` foreign slots returned as empty strings
- signer status helpers expose `/status` and are used to size signing
  request deadlines when callers do not provide an earlier explicit timeout
- raw `signRequests` / `sign_requests` APIs accept one or more `/sign` request
  entries and expose the native `/sign` response for adapters that already own
  transaction encoding
- simulation helpers use ordinary raw signing APIs and then call the SDK's
  client-configured algod simulation endpoint with the returned executable group
- AlgoKit Utils adapters are optional client-side projections over the native
  SDK client. They provide the AlgoKit `addr` plus transaction-signer shape and
  call raw `/sign` for the indexes AlgoKit asks them to sign. They do not
  mutate or re-plan groups or run the SDK-native typed prep layer.

Primary SDK sources live in the separate MIT-licensed
`aplane-algo/aplanesdk` repository. When `APLANE_SDKS_REPO` points at a local
SDK checkout, this repo's `make integration-test` and `make integration-test-reuse`
targets also run the SDK live signer integration suites through
`test/run-sdk-integration.sh`; when unset, that bridge is skipped, and when set
to a non-directory path, the make target fails before running SDK tests.

Committed JSON golden fixtures for signer API contract tests live under
`test/contracts/signerapi/` and round-trip through the public DTO structs in
`pkg/signerapi`. These fixtures are compatibility source material for this
repository and the external SDK repository: update them intentionally with any
wire-contract change, not as generated test runtime state.
With an SDK checkout available,
`make contract-sync-check APLANESDK_DIR=/path/to/aplanesdk` verifies that the
copied fixture trees match. The normal in-repo `contract-test` target does not
perform that cross-repository comparison.
Cross-language SDK prep parity fixtures are owned in the external SDK
repository because they exercise SDK transaction builders rather than signer
HTTP DTOs; update them when SDK prep request-shape behavior intentionally
changes.

Known-answer key derivation fixtures live in
`test/integration/key_derivation_regression_test.go`. They pin deterministic
addresses for supported DSA and template-backed LogicSig derivation paths.
Update those expected addresses intentionally, in the same change as the
behavior change, when a versioned derivation path, salt style, TEAL template
body, seed derivation, or generator changes.

## Related Documents

- [`ARCH_CRYPTO.md`](ARCH_CRYPTO.md) - Cryptographic subsystem architecture
- [`TXN_BYTES_HEX.md`](TXN_BYTES_HEX.md) - Why we send full transaction bytes
- [`TXN_MIXED_GROUPS.md`](TXN_MIXED_GROUPS.md) - Mixed transaction groups with multiple key types
- [`DEV_KEYTYPES.md`](DEV_KEYTYPES.md) - Adding new key types and LogicSig templates
