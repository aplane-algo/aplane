# Transaction Policy System

The signer uses a two-layer approval model. Both layers must pass for a transaction to be signed.

## Two-Layer Model

| Layer | Purpose | On Failure |
|-------|---------|------------|
| **Policy Linter** | Hard constraints that MUST be satisfied | Rejected (no human override) |
| **Human Approval** | Determines if operator intervention needed | Warnings shown, auto-approve rules checked |

```
Request arrives
      │
      ▼
┌─────────────────────────┐
│ LAYER 1: Policy Linter  │
│                         │
│ - Group policy linter   │──FAIL──▶ REJECTED (no override)
│ - Txn policy linter     │
└────────┬────────────────┘
         │ PASS
         ▼
┌─────────────────────────┐
│ LAYER 2: Human Approval │
│                         │
│ - Warnings (TUI display)│
│ - Auto-approve rules    │
│ - TUI approval if needed│
└────────┬────────────────┘
         │ APPROVED
         ▼
       SIGN
```

## Layer 1: Policy Linter

Policy linting enforces hard constraints. If any check fails, the transaction is rejected immediately with no human override possible.

### Group Policy Linter

Validates the group as a whole before any transaction is processed.

```go
CheckGroupPolicyLinter(txns []types.Transaction) error
```

Potential checks (to be implemented):
- Maximum group size limits
- Mixed sender restrictions
- Group-level spending limits

### Transaction Policy Linter

Validates each transaction individually.

```go
CheckTxnPolicyLinter(txn types.Transaction, sender string) error
```

Potential checks (to be implemented):
- Sender doesn't overspend (balance verification)
- Transaction amount within configured limits
- Recipient not on blocklist

### Execution Order

| Request Type | Policy Linter Checks |
|--------------|----------------------|
| Single transaction | Transaction policy linter only |
| Group (2+ txns in client request) | Group policy linter, then transaction policy linter for each |

**Note**: "Group" for human approval purposes means 2+ transactions in the client request. However, policy linting runs on the final signed output (including server-added dummies and adjusted fees) to ensure what's actually signed meets policy constraints.

## Layer 2: Human Approval

After passing policy linting, the human approval layer determines whether operator intervention is required.

### 2a: Warnings (Single Transactions Only)

Warnings are displayed to the operator in the TUI but can be overridden. These alert to potentially dangerous operations.

**Note**: Warnings are only shown for single-transaction approvals. Groups undergo group-level approval without per-transaction warning display (consistent with "no per-txn human approval for groups").

```go
CheckTxnWarnings(txnBytesHex string) []protocol.PolicyViolation
```

#### Critical Warnings

| Field | Risk | Description |
|-------|------|-------------|
| `RekeyTo` | Loss of control | Transfers signing authority to another address permanently |
| `CloseRemainderTo` | Loss of funds | Closes account and sends ALL remaining ALGO |

#### Standard Warnings

| Field | Risk | Description |
|-------|------|-------------|
| `AssetCloseTo` | Asset loss | Sends entire ASA balance to another address |
| `AssetSender` | Clawback | Moves funds from another account using clawback authority |
| High Fee | Fee drain | Fee exceeds 1 ALGO (normal is ~0.001 ALGO) |

#### TUI Display

```
┌──────────────────────────────────────────────────────────┐
│ Signing Request                                          │
│                                                          │
│ ⚠ CRITICAL: RekeyTo                                     │
│    This transaction will PERMANENTLY transfer signing    │
│    authority to another address.                         │
│    Value: NEWAUTH...ADDRESS                              │
│                                                          │
│        ┌─────────┐  ┌────────┐                          │
│        │ APPROVE │  │ REJECT │                          │
│        └─────────┘  └────────┘                          │
└──────────────────────────────────────────────────────────┘
```

### 2b: Auto-Approve Rules

Auto-approve rules bypass human intervention when conditions are met. These are configured in `config.yaml`.

#### Group Auto-Approve

| Setting | Effect |
|---------|--------|
| `group_auto_approve: true` | Groups auto-approved without TUI |
| `group_auto_approve: false` | Groups require TUI approval |

#### Transaction Auto-Approve

Only applies to single transactions (groups use group-level approval only).

| Setting | Effect |
|---------|--------|
| `txn_auto_approve: true` | All single transactions auto-approved |

### Approval Flow by Request Type

| Request Type | Group Approval | Transaction Approval |
|--------------|----------------|----------------------|
| Single transaction | Skipped | Auto-approve rules or TUI |
| Group (2+ txns in client request) | `group_auto_approve` or TUI | Skipped |

**Key insight**: Groups never undergo per-transaction human approval. Once a group passes policy linting and group-level approval, all transactions are signed.

**Note**: For human approval, request type is determined by client request (server-added dummies don't change a single-txn request into a group). For policy linting, the final output is checked.

## Configuration

### config.yaml Policy Settings

```yaml
# Layer 2: Human approval auto-approve rules
# Note: Validation transactions (0 ALGO self-send) are always auto-approved
group_auto_approve: false          # Require TUI for groups
txn_auto_approve: false            # Require TUI for single txns

# Group modification (not approval-related)
allow_group_modification: false    # Protect pre-grouped transactions
```

### Default Thresholds

| Setting | Default | Description |
|---------|---------|-------------|
| Max fee warning | 1 ALGO | Fees above this trigger a warning |

## Implementation

All policy checking is consolidated in:

- `internal/util/policy.go` - Policy linting and human approval functions
- `internal/protocol/messages.go` - `PolicyViolation` type definition

### Function Reference

```go
// Layer 1: Policy Linting
CheckGroupPolicyLinter(txns []types.Transaction) error
CheckTxnPolicyLinter(txn types.Transaction, sender string) error

// Layer 2a: Warnings
CheckTxnWarnings(txnBytesHex string) []protocol.PolicyViolation

// Layer 2b: Auto-approve rules
(*ServerConfig) EffectiveTxnAutoApprove() bool

// Helpers
DecodeTxnFromHex(txnBytesHex string) (types.Transaction, error)
```

## Related Documents

- [`ARCH_TXNFLOW.md`](ARCH_TXNFLOW.md) - Transaction signing flow with approval checkpoints
- [`USER_CONFIG.md`](USER_CONFIG.md) - Configuration guide
