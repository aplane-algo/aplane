# Cooperative Signing Protocol

## 1. Problem Statement

The `localSigners` mechanism allows plugins to return ephemeral Ed25519 secret keys so that apshell signs certain transactions locally, bypassing apsigner entirely. This creates three blind spots:

- **Policy visibility bypass**: Signer policy and warning analysis cannot see locally-signed transactions unless the full group is routed through signer-visible planning and approval. apsigner therefore cannot make a complete policy decision about participation by its managed keys when part of the group bypasses the server.
- **Approval visibility bypass**: The operator approval workflow in the apadmin TUI only covers server-signed transactions. The operator is not shown the full group context before approving participation by managed keys.
- **Audit gap**: The audit log (`internal/signerapp/audit/audit.go`) records only transactions that flow through apsigner. Locally-signed transactions leave no trace, so the final submitted group is only partially visible in signer-side audit records.

This gap cannot be fixed incrementally. Client-side signing fundamentally bypasses the server. When that happens, apsigner loses visibility into part of the atomic group, so it cannot make an informed policy or approval decision about whether its own managed keys should participate.

The cooperative signing protocol restores full-group visibility while preserving signer boundaries. apsigner does **not** claim authority over plugin-controlled or otherwise foreign accounts. Instead, it inspects the full group as execution context, applies policy and approval to the participation of the accounts it manages, and records signer-side request/planning context for audit. The plugin retains custody of its ephemeral keys and signs only its own subset.

## 2. Protocol Overview

The protocol uses three steps — all existing endpoints, no new server-side state:

```
┌──────────┐          ┌──────────┐         ┌──────────┐
│  Plugin  │          │  apshell │         │apsigner │
└────┬─────┘          └────┬─────┘         └────┬─────┘
     │   execute result    │                    │
     │   (top-level        │                    │
     │    localSigners)    │                    │
     │────────────────────>│                    │
     │                     │  POST /plan        │
     │                     │  (sign + foreign)  │
     │                     │───────────────────>│
     │                     │                    │ build group:
     │                     │                    │ dummies, fees,
     │                     │                    │ group ID
     │                     │  canonical txns    │
     │                     │<───────────────────│
     │                     │                    │
     │                     │ (local signing:    │
     │                     │  plugin-owned +    │
     │                     │  dummies)          │
     │                     │                    │
     │                     │  POST /sign        │
     │                     │  (sign + passthru) │
     │                     │───────────────────>│
     │                     │                    │ policy lint,
     │                     │                    │ approval workflow,
     │                     │                    │ sign server subset,
     │                     │                    │ audit log
     │                     │  signed group      │
     │                     │<───────────────────│
     │                     │                    │
     │                     │  submit to network │
```

### Step 1 — `POST /plan` (group building)

apshell sends transactions to `/plan`:

| Original transaction owner | Mode in /plan request | Fields |
|---|---|---|
| Server-managed (apsigner has the key) | **Sign** | `auth_address` + `txn_bytes_hex` + optional `lsig_args` |
| Plugin-owned (local signer key) | **Foreign** | `txn_bytes_hex` only |

The server builds the canonical group: adds dummies for LSig budget, pools fees, computes group ID. Returns TX-prefixed hex-encoded unsigned transactions and a `MutationReport`. No keys are touched, no approval flow is triggered.

### Step 2 — Local signing (no HTTP call)

apshell signs two subsets of the canonical group locally:

1. **Plugin-owned transactions** (indices `0..len(originals)-1` where sender is in `localSignerKeys`): signed with `signing.SignWithRawKey(canonicalTxn, secretKey, address)`
2. **Dummy transactions** (indices `len(originals)..len(canonical)-1`): signed with `signing.SignDummyTransaction(canonicalTxn)`

### Step 3 — `POST /sign` (approval + server signing)

apshell sends the full canonical group to `/sign`:

| Transaction | Mode in /sign request | Fields |
|---|---|---|
| Server-managed originals | **Sign** | `auth_address` + canonical `txn_bytes_hex` + optional `lsig_args` |
| Plugin-signed originals | **Passthrough** | `signed_txn_hex` |
| Dummies | **Passthrough** | `signed_txn_hex` |

The `/sign` request contains one entry per canonical group position, in order. The server's `planGroup()` sees pre-grouped transactions with passthrough entries, skips group mutations, and proceeds to signer-controlled policy checks, full-context warning/approval rendering, and signing. The operator sees the complete group, including plugin-owned and dummy transactions, before approving participation by managed keys.

The server signs its subset (sign-mode entries), includes passthrough entries as-is, and returns the fully signed group.

Transaction-level hard policy applies only to signer-controlled slots. Foreign
and passthrough entries still participate in group consistency, group-level
policy context, warning analysis, approval rendering, and audit visibility.

**Constraint**: The `/sign` request uses passthrough + sign-mode only — no foreign entries. The shared signer API validation allows each request mode independently, but the signer planner rejects mixing passthrough and foreign entries in one group because passthrough requires an already grouped transaction and foreign mode requires server-computed grouping.

## 3. Edge Case: All-Plugin Group

If every transaction sender is in `localSignerKeys`, the `/plan` call would be
all-foreign and rejected by the server because apsigner has no signer-managed
work to perform. The planner error is:

> `no signable transactions: all entries are foreign. Build and submit this group locally instead of using apsigner`

This is handled by falling back to local group-building:

1. Assign group ID locally via `signing.AssignGroupID()`
2. Sign everything locally (plugin-owned transactions are Ed25519, no LSig budget needed)
3. Submit directly to the network

apsigner has nothing to govern in an all-plugin group; no managed keys participate.

In simulate mode, the all-plugin fallback assigns the group ID locally, signs
locally, and calls algod simulate with real signatures. It does not return or
persist submission-capable signed bytes.

## 3.1 Simulate Mode

Simulate mode follows the same visibility boundary but does not return reusable
signed transaction bytes.

- Mixed plugin/server-managed groups call `/plan`, decode the canonical
  unsigned transactions, sign plugin-owned and dummy transactions locally, then
  call `/simulate` with those passthrough signatures. apsigner signs
  signer-managed slots internally, calls algod simulate, and does not return
  signed bytes.
- All-plugin groups assign the group ID locally, sign locally, and call algod
  simulate without a signer request.
- Simulate mode does not call `/sign`.

## 4. Security Properties

| Property | How it's achieved |
|----------|------------------|
| **Full group visibility** | apsigner sees the entire group for operator approval and warning context before managed keys are used |
| **Full approval context** | Operator sees and approves the entire group in one prompt before signer-managed keys are used |
| **Audit coverage** | `/sign` audit logging records the request/planning context for the full group, but `SIGN_APPROVED` is emitted only for transactions the signer actually signs |
| **No key escrow** | Plugin secret keys stay in apshell; only unsigned transactions and signed blobs cross the boundary |
| **Canonical binding** | Plugin signs the exact canonical bytes computed by `/plan`; these bytes are sent to `/sign` as passthrough |
| **Stateless server** | No plan store, no TTL, no state machine. Each step is a standalone HTTP call. |
| **No plan state** | Submit mode uses `/plan` and `/sign`; simulate mode uses `/plan` and `/simulate`. No server-side plan store or multi-step state is required. |

## 5. Trust Boundary

apsigner governs its own managed keys. It does not claim authority over plugin-controlled accounts. The cooperative protocol gives apsigner what it needs — full group context — to make informed decisions about its own keys' participation.

- **apsigner decides**: Whether to sign with managed keys, given the full group context (policy + operator approval)
- **Plugin decides**: How to use its ephemeral keys; signs its own subset independently
- **apshell orchestrates**: Bridges the two signers via `/plan` → local sign → `/sign`

The trust boundary is at the key level, not the transaction level. apsigner trusts its own key operations; it treats plugin-signed transactions as opaque context for policy and approval decisions.

## 6. Comparison with Direct `/sign`

| Aspect | Direct `/sign` (no local signers) | Cooperative `/plan` then `/sign` |
|--------|----------------------------------|-------------------------------|
| Group building | Server does it in `/sign` | Server does it in `/plan` |
| Plugin signing | N/A | Client signs after `/plan` |
| Policy + approval | Transaction-level hard policy on sign-mode slots; foreign entries are full-group context | Transaction-level hard policy on sign-mode slots; passthrough entries are full-group context |
| Server state | Stateless | Stateless |
| Round trips | 1 (`/sign`) | 2 (`/plan` + `/sign`) |

## 7. Request Ordering

The `/sign` request must include one entry per canonical group position, in group-position order. `handleSign()` iterates entries in order — signing sign-mode entries and including passthrough entries as-is. The `Signed[]` response array maps 1:1 to the request entries.

## Key Files

- `internal/engine/plugin_signing.go` — `SignAndSubmitWithLocalSigners()` orchestrates the 3-step flow and `SignAndSubmitAllLocal()` handles the all-plugin fallback
- `internal/apshellapp/submission.go` — parses plugin `localSigners` from execute results and hands mixed-signing requests to the engine
- `pkg/signerapi/types.go` — public `/plan` and `/sign` request/response payloads, including sign, foreign, and passthrough modes
- `internal/signerclient/client.go` — `RequestGroupPlan()` / `RequestGroupPlanWithContext()` and `RequestGroupSign()` / `RequestGroupSignWithContext()` client methods
- `internal/signerapp/daemon/http_handlers_signing.go` and `internal/signerapp/signing/` — `/plan` and `/sign` handler/service/planner path
- `internal/signing/lsig_helpers.go` — `SignWithRawKey()`, `SignDummyTransaction()`
- `internal/signing/common.go` — `AssignGroupID()` (used in all-plugin fallback)
