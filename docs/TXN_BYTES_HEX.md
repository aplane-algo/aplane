# TxnBytesHex Field in SignRequest

## Overview

`txn_bytes_hex` is required for sign-mode and foreign-mode `SignRequest`
entries. It carries the full unsigned transaction bytes (`TX` prefix + msgpack)
so the signer can inspect the transaction for group planning, policy, approval
rendering, and audit. The final signing message is derived from the planned
transaction after any group-ID, dummy, or fee canonicalization.

Passthrough-mode entries use `signed_txn_hex` instead because they already
contain an externally signed transaction that must be returned unchanged.

## Why This Field Exists

Some signing schemes (LogicSig DSA) sign the **transaction ID hash**, while others (Ed25519) sign the **full transaction bytes**. The signer must still inspect the full transaction for policy checks and operator display, so `TxnBytesHex` provides a uniform, always-present source of truth.

## Why This Matters

Signer needs to inspect transaction details to implement security features:

1. **Signer policy**: Reject transactions that violate configured fee, ALGO/ASA
   amount, rekey, close-out, foreign rekey, or clawback rules
2. **Approval warnings**: Surface transaction type, receiver, amount, rekey,
   close-out, app-call, and group context to the operator
3. **Accurate display**: Show the operator what they're signing
4. **Audit logging**: Record detailed information about what was signed

## SignRequest

`TxnBytesHex` is present in sign mode and in foreign mode. In sign mode, `auth_address` identifies the signing key. In foreign mode (multi-party context), `txn_bytes_hex` is provided without `auth_address` so `/plan` or `/sign` can include the transaction in group building without signing it.

The canonical `SignRequest` and `AppCallInfo` definitions live in
`pkg/signerapi/types.go`. The wire-relevant fields are:

- `auth_address` — which signer-managed key to use for signing (sign mode).
- `txn_sender` — transaction sender, used for approval display.
- `txn_bytes_hex` — TX-prefixed msgpack-encoded unsigned transaction, hex
  encoded. Required for sign mode and foreign mode.
- `lsig_args` — name-keyed runtime arguments for generic LogicSigs.
- `lsig_size` — optional LogicSig size hint in bytes, used in foreign mode so
  the server can reserve LogicSig budget for the foreign party's key type.
- `app_call_info` — optional approval metadata for app-call transactions; the
  `mode` is `"raw"` or `"abi"` and `method` carries the ABI method signature
  when available.
- `signed_txn_hex` — already-signed transaction bytes (msgpack, hex) for
  passthrough mode; mutually exclusive with the sign-mode fields.

Foreign-mode semantics:

- on `/plan`, the transaction participates in planning and is returned in the planned unsigned group
- on `/sign`, the transaction still participates in planning and approval context, but it is not signed and its position in `signed[]` is returned as `""`
- foreign mode is for unsigned non-local transactions
- optional `lsig_size` reserves LogicSig budget for a foreign party's key type
- already-signed non-local transactions must use passthrough mode (`signed_txn_hex`) instead
- passthrough and foreign entries cannot appear in the same request because
  passthrough supplies already-signed bytes whose group shape is accepted as
  immutable, while foreign entries remain unsigned context that participates in
  planner budget math

Foreign requests may be ungrouped, in which case the server canonicalizes the
group, or already pre-grouped, in which case the server preserves the shape
when no additional dummies are required.

Plan response semantics:

- `/plan` returns `GroupPlanResponse.transactions`
- each entry is a TX-prefixed hex-encoded unsigned transaction in final group order
- server-added dummy transactions, fee pooling, and group-ID assignment are reflected in the returned transactions
- clients that need local/cooperative signing or simulate-without-signing should consume `/plan` output instead of `/sign` output

## How It Works

The signer decodes `TxnBytesHex` into a transaction, builds the final planned
group, and then derives the signing message from the planned transaction based
on key type:

| Key type | Message to sign | Inspection source |
|----------|-----------------|-------------------|
| `ed25519` | Full transaction bytes (`TX` + msgpack) | `TxnBytesHex` |
| LogicSig DSA (Falcon, etc.) | 32-byte transaction ID hash | `TxnBytesHex` |
| Generic LogicSig | N/A (no signature) | `TxnBytesHex` |

### Signer Processing

The signer hex-decodes `TxnBytesHex`, strips the leading `TX` prefix if present,
and msgpack-decodes the remaining bytes into a `types.Transaction`. The decoded
form drives policy checks and approval rendering. The actual signing message is
derived from the *final planned* transaction (after group ID, dummy, and fee
canonicalization), not from the raw inbound bytes. Implementation:
`internal/signerapp/signing/planner.go`.

## Why LogicSig DSA Signs Hashes Instead of Full Transactions

LogicSig DSA transactions sign the transaction ID (hash) rather than full bytes
because on-chain TEAL verification uses the transaction ID:

1. **LogicSig verification**: DSA-backed LogicSig programs verify signatures against `txn TxID`
2. **Canonical commitment**: transaction ID is SHA512/256 over `TX` + msgpack transaction bytes
3. **Group ID commitment**: for grouped transactions, the transaction ID includes the final group ID
4. **Dummy/fee canonicalization**: server planning may change group shape before the final transaction ID is known

The full transaction bytes are encoded in `TxnBytesHex` as:
```
TX prefix (2 bytes) + msgpack-encoded transaction
```

This is the same format that Ed25519 transactions sign, ensuring consistency.

## Implementation Details

### In apshell (client side)

Sign-mode request construction encodes the unsigned transaction with the `TX`
prefix via `txnutil.EncodeWithPrefix`, hex-encodes the result into
`TxnBytesHex`, and attaches `AuthAddress`, `TxnSender`, and any generic
LogicSig args. See `internal/signing/multi.go` and
`internal/engine/plugin_signing.go` for the call sites.

### In Signer (server side)

Request decoding lives in `internal/signerapp/signing/planner.go`: the planner
hex-decodes `TxnBytesHex`, strips a leading `TX` prefix when present, and
msgpack-decodes the remainder into a transaction; malformed hex or msgpack
fails the request.

Message selection lives in `internal/signerapp/signing/execution.go`. For
LogicSig DSA keys (those backed by TEAL bytecode), the signing message is the
32-byte transaction ID. For Ed25519 keys, the signing message is the
`TX`-prefixed msgpack encoding of the final planned transaction, produced via
`txnutil.EncodeWithPrefix`.

The strict client-side helpers — `txnutil.EncodeWithPrefixHex` and
`txnutil.DecodePrefixedHex` in `internal/txnutil/txn.go` — round-trip the
canonical TX-prefixed hex form. `DecodePrefixedHex` rejects input without the
`TX` prefix and is used by clients consuming planned unsigned transactions.
The server request decoder remains backward-tolerant of unprefixed msgpack for
inbound requests, but clients should send and expect the TX-prefixed form.

## Coverage

`TxnBytesHex` provides full transaction visibility in **all scenarios**:

| Scenario | Coverage |
|----------|----------|
| Single standalone transaction | `TxnBytesHex` |
| Multiple transactions in atomic group | `TxnBytesHex` |
| Mixed group (Ed25519 + LogicSig) | `TxnBytesHex` |
| Foreign transaction (multi-party) | `TxnBytesHex` (no `auth_address`) |
| Passthrough transaction | `signed_txn_hex` (already signed; returned unchanged) |
| Planned unsigned group | `/plan` `transactions[]` (`TX` + msgpack, hex) |
| Signer-managed simulation | `/simulate` response with txids, diagnostics, and final unsigned `transactions[]`; signed bytes stay in apsigner |
| Unsigned planning simulation | `/plan` output + algod simulate with empty signatures enabled |

## Benefits

1. **Unified inspection**: Signer can inspect all transactions the same way
2. **Security features**: Auto-approve, spending limits, and filtering work for all signing methods
3. **Minimal overhead**: Adds a small constant payload per request
4. **Clean separation**: What's signed (hash vs full bytes) vs. what's inspected is clearly separated

## Example Use Cases

### Signer Policy Enforcement

`TxnBytesHex` lets the signer apply the same hard-reject policy to Ed25519,
LogicSig DSA, and generic LogicSig transactions:

- maximum fee ceilings
- network-scoped ALGO payment ceilings
- network-scoped ASA transfer ceilings
- reject foreign rekey
- reject close remainder / asset close
- reject clawback

Policy runs before human approval. If policy rejects a request, no approval
prompt is shown and no signing occurs.

### Approval and Audit Rendering

The signer uses decoded transaction content to render approval prompts and audit
records from the final planned transaction shape, not from opaque bytes alone.
This includes server-side changes such as dummy insertion, fee pooling, and
group-ID assignment.

## Related Files

- `pkg/signerapi/types.go` - SignRequest type definition
- `internal/signing/multi.go` - client-side request construction
- `internal/engine/plugin_signing.go` - plugin/mixed-party request construction
- `internal/txnutil/txn.go` - TX-prefixed transaction encoding helpers
- `internal/signerapp/signing/planner.go` - request categorization and transaction decoding
- `internal/signerapp/signing/execution.go` - key-type-specific message selection and assembly
- `internal/signerapp/signing/approval.go` - policy and approval description flow
- `lsig/falcon1024/signing/provider.go` - Falcon signing provider
- `internal/signing/ed25519/provider.go` - Ed25519 signing provider
