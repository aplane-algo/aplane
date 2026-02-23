# LLM-Orchestrated Atomic Swap Demo

This demo shows two independent LLM agents (Claude Sonnet) negotiating and executing an atomic swap on Algorand testnet. Either side of the swap can be native ALGO or an ASA. Each agent runs its own apsignerd instance and communicates with the other party entirely on-chain via transaction notes.

The demo exercises aPlane's multi-party signing stack: the `/plan` endpoint, foreign mode, `sign_transactions_list`, and `assemble_group` from the Python SDK. Exchange data (planned transactions + partial signatures) is stored in an Algorand on-chain box, eliminating any shared filesystem requirement.

## What It Does

Two parties — a **buyer** and a **seller** — each offer something the other wants. Either side can be ALGO or an ASA (e.g., 1 ALGO for 1 USDC, or 1 USDC for 1 BOB). The buyer proposes a swap, and the seller accepts by building an atomic transaction group, signing its half, and writing the exchange data to an on-chain box. The buyer reads the box, verifies and completes the group, then submits the atomic swap to the network. Either both transfers happen or neither does.

The LLM agents follow a structured protocol but make their own tool calls. The tools enforce all security invariants — address validation, amount matching, proposal hash binding — so the LLM cannot deviate from the agreed terms.

## Architecture

```
┌─────────────────────┐                    ┌─────────────────────┐
│   run_buyer.py      │                    │   run_seller.py     │
│                     │                    │                     │
│   orchestrator.py   │                    │   orchestrator.py   │
│   ┌───────────────┐ │   on-chain notes   │ ┌───────────────┐  │
│   │ Claude Sonnet │◄├────────────────────►┤ │ Claude Sonnet │  │
│   │  (Anthropic)  │ │   (0-ALGO txns     │ │  (Anthropic)  │  │
│   └──────┬────────┘ │    with JSON note)  │ └──────┬────────┘  │
│          │          │                    │          │          │
│   ┌──────▼────────┐ │   on-chain box     │ ┌──────▼────────┐  │
│   │   tools.py    │ │   (planned txns    │ │   tools.py    │  │
│   │  (9 tools)    │◄├── + partial sigs)──►┤ │  (9 tools)    │  │
│   └──────┬────────┘ │                    │ └──────┬────────┘  │
│          │          │                    │          │          │
│   ┌──────▼────────┐ │                    │ ┌──────▼────────┐  │
│   │  apsignerd A  │ │                    │ │  apsignerd B  │  │
│   │  (Falcon-1024)│ │                    │ │  (Ed25519)    │  │
│   └───────────────┘ │                    │ └───────────────┘  │
└─────────────────────┘                    └─────────────────────┘
```

## Protocol

### Step-by-step

| Step | Who | Action | On-chain? |
|------|-----|--------|-----------|
| 1 | Buyer | `get_my_key_info` — learn key type and `lsig_size` | No |
| 2 | Buyer | `opt_in_asa` — ensure opted in to receive what the seller offers (no-op if ALGO) | Yes |
| 3 | Buyer | `send_note` — send `swap_propose` with offer terms, `lsig_size`, and `app_id` | Yes |
| 4 | Seller | Receives `swap_propose` via Indexer polling | — |
| 5 | Seller | `check_asa_balance` — verify buyer holds enough of what they're offering | No |
| 6 | Seller | `opt_in_asa` — ensure opted in to receive what the buyer offers (no-op if ALGO) | Yes |
| 7 | Seller | `build_and_sign_swap` — build group via `/plan` with foreign mode, sign own half, write exchange data to on-chain box | Yes (box create + write) |
| 8 | Seller | `send_note` — send `swap_partial` signal (with `app_id`) to buyer | Yes |
| 9 | Buyer | Receives `swap_partial` via Indexer polling | — |
| 10 | Buyer | `verify_and_submit_swap` — read on-chain box, verify proposal hash + both txn legs, sign own half, assemble, submit | Yes |
| 11 | Seller | Detects incoming transfer (the atomic group confirmed) | — |
| 12 | Both | `complete_swap` — mark complete + delete box (reclaim MBR) | Yes (box delete) |

### On-chain message format

Communication uses 0-ALGO payment transactions with JSON-encoded notes:

```json
{"type": "swap_propose", "offer_asa": 0, "offer_amount": 1000000,
 "want_asa": 10458941, "want_amount": 1000000, "lsig_size": 3085,
 "app_id": 755635046}
```

An `offer_asa` or `want_asa` of `0` means native ALGO.

```json
{"type": "swap_partial", "app_id": 12345678}
```

The `swap_partial` note includes the `app_id` so the buyer knows which application holds the exchange box. The actual transaction data (planned group + partial signatures) is stored in the on-chain box because signed Falcon-1024 LogicSig transactions are far too large for the 1KB note limit.

### On-chain box exchange

The proposal hash (SHA-256 of canonical swap terms, truncated to 16 hex chars) serves as the box name, providing natural session binding. The box contains the following JSON structure (before compression):

```json
{
  "proposal_hash": "a3f8b2c1e9d04567",
  "planned_txns_hex": ["5458...", "5458...", ...],
  "signed":          ["",        "gqNzaW...", ...]
}
```

- `planned_txns_hex`: The finalized transactions from `/plan`, with group ID already assigned. The buyer decodes these to verify every field before signing.
- `signed`: The seller's partial signatures. Non-empty for the transactions the seller controls (TxnB + its dummies), `""` for foreign slots (the buyer's TxnA + buyer's dummies).

The seller compresses this (~9KB JSON → ~5KB via zlib) and writes it using an atomic group of app calls (MBR payment + create + N write chunks of 2KB each). The buyer reads the box via a REST query (no transaction needed). On completion, either party can delete the box; the MBR is refunded to the original creator (the seller).

The box storage contract (`swap_box.teal`) provides per-box ACL, caller-funded MBR, and creator-tracked refunds. See [README_box_app.md](README_box_app.md) for the full contract design.

## Multi-Party Signing

This demo showcases the full multi-party signing flow using foreign mode.

### Why foreign mode?

The group ID and fee pooling depend on *every* transaction in the group, including ones the seller can't sign. The seller builds both TxnA (buyer sends ALGO or ASA) and TxnB (seller sends ALGO or ASA), but it can't compute the group ID alone — it doesn't know how many dummy padding transactions the buyer's Falcon key will require. Foreign mode (`auth_addresses=[None, seller_addr]`) tells apsignerd: "include TxnA in planning but skip signing it." The server sees the full picture, adds dummies, computes fees, assigns the group ID, and returns partial signatures — filled for the seller's transactions, `""` for the buyer's.

### Signing flow

1. **Seller plans the group**: The seller submits both transactions to `/plan` with TxnA marked as foreign and `lsig_sizes={0: 3085}` hinting at the buyer's Falcon key size. The server adds 5 dummy padding transactions for the buyer's LogicSig, computes fee pooling, and assigns the group ID. 2 real transactions become a 7-transaction group.

2. **Seller signs its half**: `sign_transactions_list` returns 7 entries — a full signature for TxnB (index 1), `""` for TxnA (index 0, foreign), and `""` for the 5 buyer dummies (indices 2-6, belonging to the buyer).

3. **Exchange via box**: The seller writes the planned transactions and its partial signatures to an on-chain box. The buyer reads the box via REST.

4. **Buyer verifies**: The buyer decodes all 7 planned transactions and checks every field of TxnA and TxnB (sender, receiver, ASA ID, amount) against the agreed swap terms. It also verifies the proposal hash matches.

5. **Buyer signs its half**: The buyer calls `sign_transactions_list` with all 7 finalized transactions, marking index 0 as its own (`auth_addresses=[my_address, None, None, ...]`). The server signs TxnA + the buyer's 5 Falcon dummies, returns `""` for TxnB.

6. **Assembly**: `assemble_group` merges the two partial arrays, taking the non-empty entry from each position:

```
seller:   [ ""   , sig_B, ""   , ""   , ""   , ""   , ""    ]
buyer:    [ sig_A, ""   , sig_2, sig_3, sig_4, sig_5, sig_6 ]
combined: [ sig_A, sig_B, sig_2, sig_3, sig_4, sig_5, sig_6 ]
```

The buyer submits the combined group. Either both transfers execute atomically or neither does.

### Why 7 transactions?

The buyer uses a Falcon-1024 post-quantum key. Its LogicSig program is 3085 bytes, which exceeds Algorand's per-transaction LogicSig size limit. aPlane automatically splits the signature across multiple "dummy" self-payment transactions (each carrying a fragment in its note field), then the real transaction references the assembled LogicSig. This is transparent to both the seller's code and the LLM agents.

### With two Ed25519 keys

If both parties use Ed25519 keys, the same flow works identically — foreign mode, `/plan`, `sign_transactions_list`, `assemble_group` — but `/plan` has nothing extra to do. No dummies, no fee rebalancing. The group stays at 2 transactions, the box data is much smaller (~1-2KB compressed), and the box write needs fewer chunks. The code path is the same regardless of key type.

### Generality

The multi-party signing stack is not swap-specific. `/plan`, foreign mode, `sign_transactions_list`, and `assemble_group` work with any transaction type — fee delegation, multi-party contract interactions, coordinated opt-ins, escrow releases. The atomic swap is just the most intuitive demonstration. The hard part (Falcon dummies, fee pooling, group ID computation across heterogeneous key types) is handled once in the infrastructure; the application layer just describes what transactions it wants.

## Security Design

The tools enforce invariants that prevent the LLM from making dangerous mistakes:

- **Address pinning**: `send_note` rejects any sender != `my_address` or receiver != `peer_address`. `build_and_sign_swap` rejects mismatched addresses.
- **Amount validation**: `build_and_sign_swap` cross-checks all ASA IDs and amounts against the swap state. The LLM cannot alter the terms.
- **Proposal hash**: A SHA-256 hash of the canonical swap terms (both addresses, both ASA IDs, both amounts) is used as the box name. The buyer verifies this hash before signing — binding the on-chain box to the specific negotiated swap.
- **Transaction verification**: `verify_and_submit_swap` decodes and inspects every field of TxnA and TxnB (sender, receiver, ASA ID, amount) against the state before signing. Takes zero LLM-provided parameters.
- **No blind signing**: The buyer never signs transactions it hasn't independently verified.

## Files

| File | Description |
|------|-------------|
| `config.py` | Swap configuration: addresses, ASA IDs, amounts (edit this for your environment) |
| `orchestrator.py` | Main loop: Indexer polling, LLM invocation, tool-use loop, state machine |
| `tools.py` | 9 tool implementations + Anthropic tool schemas + dispatch |
| `prompts.py` | System prompts defining each agent's protocol steps and rules |
| `state.py` | `SwapState` dataclass with JSON persistence |
| `box_exchange.py` | Box read/write/delete via Algorand box storage |
| `swap_box.teal` | TEAL v10 box storage contract with ACL and MBR refund (see [README_box_app.md](README_box_app.md)) |
| `deploy_contract.py` | One-time deployment script for swap_box.teal |
| `swap_log.py` | Shared append-only log with timestamps |
| `run_buyer.py` | Buyer entry point (imports config) |
| `run_seller.py` | Seller entry point (imports config) |

### Generated at runtime

| File | Description |
|------|-------------|
| `state_buyer.json` | Buyer's persisted swap state |
| `state_seller.json` | Seller's persisted swap state |
| `swap_log.log` | Unified timeline of both agents' actions |

## Prerequisites

- Python 3.10+
- `algosdk`, `requests`, `anthropic` packages
- aPlane Python SDK (`sdk/python/` in this repo)
- Two running apsignerd instances, each with a funded testnet account holding the ASA to swap
- `ANTHROPIC_API_KEY` environment variable
- `APLANE_SIGNER_URL` and `APLANE_TOKEN` environment variables (or configured per-instance)

## Deployment (one-time)

Deploy the box storage contract before running the swap:

```bash
python deploy_contract.py
```

This compiles `swap_box.teal`, creates the application, and funds the app account with 0.1 ALGO (minimum balance). Each box creator pays their own MBR via a grouped payment transaction. The app ID is persisted to `swap_app_id.txt` and loaded automatically. `run_buyer.py` also calls this automatically if the contract hasn't been deployed yet.

## Configuration

Edit `config.py` to set your addresses and swap terms:

```python
BUYER = "YOUR_BUYER_ADDRESS"
SELLER = "YOUR_SELLER_ADDRESS"

ASA_A = 0           # what the buyer offers (0 = ALGO)
ASA_B = 10458941    # what the seller offers (testnet USDC)

ASA_A_AMOUNT = 1000000  # 1 ALGO (6 decimals)
ASA_B_AMOUNT = 1000000  # 1 USDC (6 decimals)
```

## Running

Start in two separate terminals (can be on different machines):

```bash
# Terminal 1: Start the buyer (sends the proposal)
python run_buyer.py

# Terminal 2: Start the seller (waits for proposal, then responds)
python run_seller.py
```

The buyer starts immediately by sending a `swap_propose` note. The seller polls the Indexer until it sees the proposal, then proceeds autonomously. Both agents print their LLM reasoning and tool calls to stdout.

A typical run completes in under a minute. The unified log (`swap_log.log`) shows the interleaved timeline.

## Example Run

From `swap_log.log` of a successful swap (1 ALGO for 1 USDC):

```
23:37:54 JHXB: Started buyer — offering ALGO (amount 1000000)
23:37:56 JHXB: Key info: type=falcon1024-v1, lsig_size=3085
23:38:00 M75L: Started seller — offering ASA 10458941 (amount 1000000)
23:38:04 JHXB: Sent note (swap_propose) txid: ZXWV5PVX7RL7H7FFYXFNOB37LNYDN66KIFHRPCXQRSKFIUQ2WHEQ
23:38:05 M75L: Received swap_propose (round 60580752)
23:38:09 M75L: Checked ALGO balance of JHXB...YNHPA: 20631741
23:38:14 M75L: Built planned group (7 txns) and signed own half; wrote on-chain box
23:38:23 M75L: Sent note (swap_partial) txid: HQUZKTVPGPGCIZQCGXLXNNDOSUW6F476MV5HL7VBISD5Y4KHNNEQ
23:38:26 JHXB: Received swap_partial (round 60580759)
23:38:31 JHXB: Verified TxnA and TxnB fields match proposal
23:38:36 JHXB: Submitted atomic group (txid: N2Y7GJC4HVHXHO6HDPGZL6H647WG7AO2V4XPJLVZ6IG6UT4IBX6Q)
23:38:38 M75L: Detected incoming ALGO transfer
23:38:40 JHXB: Swap complete
23:38:42 M75L: Swap complete
```

Total time: ~48 seconds (dominated by on-chain confirmation latency).

## Design Notes

### Why `/plan` matters

`/plan` earns its keep by handling group mutations — adding Falcon dummy transactions, rebalancing fees across the group, and recomputing the group ID after those changes. The caller can't compute the group ID alone because it doesn't know the final group structure until the server adds dummies. In this demo, the seller builds 2 transactions but the server expands them to 7. The group ID is a hash of all 7, not the original 2.

### Passthrough vs foreign mode

aPlane supports two approaches for multi-party signing:

- **Foreign mode**: The server sees the transaction, includes it in group planning (group ID, fees, dummies), but doesn't sign it. Returns `""` for that slot. Works for any key type because the server handles all mutations before signing. This is what the demo uses.

- **Passthrough**: A pre-signed transaction is included in the group as-is, byte-identical. The server doesn't modify it. Requires the group ID to already be set (since the signature covers the group ID). Works only when no group mutations are needed — today that means Ed25519-only groups.

Foreign mode is the general solution; passthrough is a fast lane for the simple case.

### Future: no-dummies world

If Algorand increases the LogicSig budget (e.g., from 1KB to 16KB), Falcon-1024 signatures would fit in a single transaction without dummies. Group mutations disappear entirely — `/plan` still works but has nothing to add. Any party can compute the group ID locally with `algosdk.transaction.assign_group_id()` since the group structure is final from the start.

In that world, passthrough becomes the primary multi-party signing mechanism. A seller could compute the group ID, sign its transaction locally, and hand the pre-signed bytes to the buyer. The buyer submits with passthrough for the seller's transaction and sign mode for its own — one apsignerd call, no assembly step. The current foreign mode flow still works but becomes heavier than necessary.

## Limitations and Notes

- **Single swap**: The demo runs one swap and exits. There's no retry logic or timeout-based cancellation.
- **Testnet only**: Hardcoded to Algorand testnet via Algonode public endpoints.
- **LLM cost**: Each run makes ~4-8 Claude Sonnet API calls total across both agents.
- **Box MBR**: For ~5KB compressed data: ~2.07 ALGO (reclaimable on box delete). Each box creator pays their own MBR; the refund goes to the creator on delete. See [README_box_app.md](README_box_app.md).
