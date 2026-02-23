# Box Storage Contract

`swap_box.teal` is a TEAL v10 contract that provides per-box access-controlled storage on Algorand. It is designed as a public-goods contract: anyone can deploy or use an existing instance, each user funds their own boxes, and the contract is immutable once deployed.

## Box Layout

Every box has a 160-byte prefix followed by the application data:

```
┌──────────────┬──────────────┬──────────────┬──────────────┬──────────────┬──────────┐
│ creator (32B)│  slot1 (32B) │  slot2 (32B) │  slot3 (32B) │  slot4 (32B) │ data (N) │
└──────────────┴──────────────┴──────────────┴──────────────┴──────────────┴──────────┘
  offset 0        offset 32      offset 64      offset 96      offset 128    offset 160
```

- **Creator**: The account that created the box and paid the MBR deposit. Receives the refund on delete.
- **Slots 1-4**: Up to 4 accounts authorized to write to and delete the box (ACL). Unused slots are zero-filled and ignored by the ACL check.

The prefix is written atomically during box creation and cannot be modified afterward.

## Methods

Three operations, routed by `app_args[0]`:

### `create`

Creates a new box and writes the 160-byte prefix.

| Field | Value |
|-------|-------|
| `app_args[0]` | `"create"` |
| `app_args[1]` | Box name (arbitrary bytes) |
| `app_args[2]` | Box size in bytes (big-endian uint64, includes 160-byte prefix) |
| `Accounts[1..N]` | 1-4 authorized accounts |
| Group requirement | Previous transaction must be a payment to the app address for at least the box MBR |

The contract verifies the MBR payment amount: `2500 + 400 * (name_len + box_size)` microAlgo.

The creator is recorded as `Txn.Sender`. Only the accounts actually passed are written; remaining slots stay zero-filled.

### `write`

Writes data to the box. The caller provides a logical offset; the contract adds 160 to skip the prefix.

| Field | Value |
|-------|-------|
| `app_args[0]` | `"write"` |
| `app_args[1]` | Box name |
| `app_args[2]` | Logical offset (big-endian uint64, 0-based relative to data region) |
| `app_args[3]` | Chunk data |

Only accounts in non-zero ACL slots may call this method.

### `delete`

Deletes the box and refunds the MBR to the original creator via inner transaction.

| Field | Value |
|-------|-------|
| `app_args[0]` | `"delete"` |
| `app_args[1]` | Box name |

Only accounts in non-zero ACL slots may call this method. The caller pays the outer transaction fee plus the inner refund transaction fee (set outer fee to `2 * min_fee` with fee pooling).

The refund always goes to the creator (bytes 0-31 of the prefix), regardless of which authorized account calls delete.

## ACL Check

The `check_acl` subroutine extracts all 4 ACL slots (bytes 32-159, 128 bytes) and compares `Txn.Sender` against each 32-byte address. Zero-filled slots never match a real Algorand address, so unused slots are effectively ignored. If no slot matches, the transaction is rejected.

## MBR Economics

| Event | Who pays | Who receives |
|-------|----------|--------------|
| Box create | Caller (grouped payment) | Contract account (holds MBR) |
| Box delete | Caller (2x fee for inner txn) | Creator (MBR refund via inner txn) |

This ensures:
- Each user funds their own boxes — no shared pool to drain.
- The creator has a financial incentive to clean up (they get their deposit back).
- Any authorized account can trigger cleanup, but the refund always goes to the creator.

For a typical swap exchange (~5KB compressed data, 16-byte box name):
- Box size: 5000 + 160 = 5160 bytes
- MBR: 2500 + 400 * (16 + 5160) = 2,072,900 microAlgo (~2.07 ALGO)
- Fully reclaimable on delete.

## Immutability

The approval program only accepts `OnCompletion == NoOp`. Both `UpdateApplication` and `DeleteApplication` are rejected, making the contract immutable once deployed. The contract cannot be modified or deleted by anyone, including the deployer.

The app account's minimum balance (0.1 ALGO) is the permanent cost of deployment.

## Public-Goods Suitability

The contract is designed to be deployed once and shared by any number of users:

- **No shared funding pool**: Each box creator pays their own MBR. The contract account only needs its 0.1 ALGO minimum balance.
- **No state bloat risk**: Algorand loads only the boxes referenced in a transaction, so a contract with thousands of boxes performs identically to one with ten.
- **Self-cleaning incentives**: The MBR refund motivates creators to delete boxes when done.
- **Immutable logic**: Users can verify the TEAL source and trust it won't change.
- **No admin keys**: No privileged accounts, no upgrade path, no kill switch.

## Deployment

```bash
python deploy_contract.py
```

Compiles `swap_box.teal`, creates the application, and funds it with 0.1 ALGO. The app ID is written to `swap_app_id.txt`.

## Python API

`box_exchange.py` provides the client-side interface:

```python
from box_exchange import write_box, read_box, delete_box

# Write: compresses data, sends MBR payment + create + write chunks as atomic group
# acl_addrs: 1-4 addresses authorized to write/delete this box
write_box(algod_client, signer, app_id, sender, box_name, data,
          acl_addrs=[addr1, addr2])

# Read: REST query, skips 160-byte prefix, decompresses
data = read_box(algod_client, app_id, box_name)

# Delete: triggers MBR refund to creator via inner transaction
delete_box(algod_client, signer, app_id, sender, box_name)
```
