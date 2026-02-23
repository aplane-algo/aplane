"""Tool implementations, Anthropic tool schemas, and dispatch table."""

import base64
import hashlib
import json
import os
import time

import requests
from algosdk import encoding, transaction
from algosdk.v2client import algod

import aplane
from box_exchange import write_box, read_box, delete_box
from swap_log import log

# ---------------------------------------------------------------------------
# Clients
# ---------------------------------------------------------------------------

ALGOD_ADDRESS = "https://testnet-api.algonode.cloud"
ALGOD_TOKEN = ""
INDEXER_URL = "https://testnet-idx.algonode.cloud"
POLL_INTERVAL = 4  # seconds between polls

# App ID for the swap box storage contract (written by deploy_contract.py)
_APP_ID_PATH = os.path.join(os.path.dirname(__file__), "swap_app_id.txt")


def load_swap_app_id() -> int:
    """Load the swap app ID from the deployment output file.

    Always reads from disk (not cached) so that a freshly deployed
    contract is picked up even if the file was created after import.
    """
    if not os.path.exists(_APP_ID_PATH):
        return 0
    with open(_APP_ID_PATH) as f:
        return int(f.read().strip())


def get_algod():
    return algod.AlgodClient(ALGOD_TOKEN, ALGOD_ADDRESS)


def get_signer():
    return aplane.SignerClient.from_env()


def record(state, message):
    """Append to state actions and shared log."""
    state.actions.append(message)
    log(state.my_address[:4], message)


def _is_algo(asa_id):
    """Return True if asa_id represents native ALGO (0)."""
    return int(asa_id) == 0


def _proposal_hash(buyer_addr, seller_addr, offer_asa, offer_amount,
                   want_asa, want_amount):
    """Deterministic hash of swap terms for session binding."""
    canonical = json.dumps({
        "buyer": buyer_addr,
        "seller": seller_addr,
        "offer_asa": int(offer_asa),
        "offer_amount": int(offer_amount),
        "want_asa": int(want_asa),
        "want_amount": int(want_amount),
    }, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Polling helpers (private)
# ---------------------------------------------------------------------------


def _poll_messages(address: str, last_round: int, seen_txids: set) -> list:
    """Poll Indexer for incoming swap notes addressed to us."""
    prefix = base64.b64encode(b'{"type":"swap_').decode()
    params = {
        "address-role": "receiver",
        "address": address,
        "tx-type": "pay",
        "note-prefix": prefix,
    }
    if last_round > 0:
        params["min-round"] = last_round

    try:
        resp = requests.get(
            f"{INDEXER_URL}/v2/transactions", params=params, timeout=10
        )
        if resp.status_code != 200:
            return []

        txns = resp.json().get("transactions", [])
        messages = []
        for txn in txns:
            txid = txn.get("id", "")
            if txid in seen_txids:
                continue
            note_b64 = txn.get("note", "")
            if not note_b64:
                continue
            try:
                note_bytes = base64.b64decode(note_b64)
                note_json = json.loads(note_bytes)
                if isinstance(note_json, dict) and note_json.get("type", "").startswith("swap_"):
                    messages.append({
                        "txid": txid,
                        "round": txn.get("confirmed-round", 0),
                        "note": note_json,
                        "sender": txn.get("sender", ""),
                    })
            except (json.JSONDecodeError, Exception):
                continue

        return messages
    except Exception as e:
        print(f"  Poll error: {e}")
        return []


def _poll_incoming_asa(address: str, asa_id: int, min_round: int,
                       seen_txids: set) -> dict | None:
    """Poll Indexer for an incoming ASA transfer (or ALGO payment if asa_id==0)."""
    if _is_algo(asa_id):
        params = {
            "address": address,
            "address-role": "receiver",
            "tx-type": "pay",
        }
    else:
        params = {
            "address": address,
            "address-role": "receiver",
            "tx-type": "axfer",
            "asset-id": asa_id,
        }
    if min_round > 0:
        params["min-round"] = min_round

    try:
        resp = requests.get(
            f"{INDEXER_URL}/v2/transactions", params=params, timeout=10
        )
        if resp.status_code != 200:
            return None
        for txn in resp.json().get("transactions", []):
            txid = txn.get("id", "")
            if txid in seen_txids:
                continue
            # For ALGO payments, skip 0-amount notes (coordination messages)
            if _is_algo(asa_id):
                pay_info = txn.get("payment-transaction", {})
                if pay_info.get("amount", 0) == 0:
                    continue
            return {
                "txid": txid,
                "round": txn.get("confirmed-round", 0),
                "sender": txn.get("sender", ""),
            }
    except Exception as e:
        print(f"  Poll incoming transfer error: {e}")
    return None


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------


def tool_wait_for_message(state, timeout=120):
    """Block until an incoming swap_* note arrives. Updates state from the note."""
    seen = set(state.seen_txids)
    deadline = time.time() + timeout

    print(f"  [wait_for_message] Polling for incoming swap note (timeout={timeout}s)...")
    while time.time() < deadline:
        msgs = _poll_messages(state.my_address, state.last_seen_round, seen)
        if msgs:
            msg = msgs[0]  # process first new message
            note = msg["note"]
            msg_type = note.get("type", "")

            # Dedup
            state.seen_txids.append(msg["txid"])
            seen.add(msg["txid"])
            state.last_seen_round = max(state.last_seen_round, msg["round"])

            # Update state from received note
            if msg_type == "swap_propose":
                state.peer_asa_id = note.get("offer_asa", state.peer_asa_id)
                state.peer_asa_amount = note.get("offer_amount", state.peer_asa_amount)
                if note.get("app_id"):
                    state.swap_app_id = int(note["app_id"])
                state.status = "propose_received"
            elif msg_type == "swap_partial":
                if note.get("app_id"):
                    state.swap_app_id = int(note["app_id"])
                state.status = "partial_received"

            record(state, f"Received {msg_type} (round {msg['round']})")
            print(f"  [wait_for_message] Received {msg_type} (round {msg['round']})")
            return {"type": msg_type, "note": note, "round": msg["round"],
                    "sender": msg["sender"]}

        time.sleep(POLL_INTERVAL)

    record(state, "wait_for_message timed out")
    return {"error": f"No incoming swap message within {timeout}s"}


def tool_wait_for_asa_transfer(state, asa_id, timeout=120):
    """Block until an incoming ASA transfer is detected. Sets state.group_txid."""
    seen = set(state.seen_txids)
    asa_id = int(asa_id)
    deadline = time.time() + timeout

    print(f"  [wait_for_asa_transfer] Polling for incoming ASA {asa_id} (timeout={timeout}s)...")
    while time.time() < deadline:
        incoming = _poll_incoming_asa(
            state.my_address, asa_id, state.last_seen_round, seen)
        if incoming:
            state.group_txid = incoming["txid"]
            state.seen_txids.append(incoming["txid"])
            record(state, f"Detected incoming ASA {asa_id} (txid: {incoming['txid']})")
            print(f"  [wait_for_asa_transfer] Detected ASA {asa_id} "
                  f"transfer (round {incoming['round']})")
            return {"txid": incoming["txid"], "round": incoming["round"],
                    "sender": incoming["sender"], "asa_id": asa_id}

        time.sleep(POLL_INTERVAL)

    record(state, f"wait_for_asa_transfer timed out for ASA {asa_id}")
    return {"error": f"No incoming ASA {asa_id} transfer within {timeout}s"}


def tool_send_note(state, sender, receiver, note_json):
    """Send a 0-ALGO transaction with a JSON note."""
    # Enforce: sender must be our address
    if sender != state.my_address:
        return {"error": f"sender must be your address ({state.my_address}), got {sender}"}
    # Enforce: receiver must be peer address
    if receiver != state.peer_address:
        return {"error": f"receiver must be peer address ({state.peer_address}), got {receiver}"}
    algod_client = get_algod()
    signer = get_signer()
    try:
        sp = algod_client.suggested_params()
        note_bytes = json.dumps(note_json, separators=(",", ":")).encode("utf-8")
        if len(note_bytes) > 1024:
            return {"error": f"Note exceeds 1024 bytes ({len(note_bytes)})"}
        txn = transaction.PaymentTxn(
            sender=sender,
            sp=sp,
            receiver=receiver,
            amt=0,
            note=note_bytes,
        )
        signed = signer.sign_transaction(txn)
        txid = aplane.send_raw_transaction(algod_client, signed)
        transaction.wait_for_confirmation(algod_client, txid, 4)
        msg_type = note_json.get("type", "?") if isinstance(note_json, dict) else "?"
        record(state, f"Sent note ({msg_type}) txid: {txid}")
        if msg_type == "swap_propose":
            state.status = "propose_sent"
        elif msg_type == "swap_partial":
            state.status = "partial_sent"
        return {"txid": txid}
    finally:
        signer.close()


def tool_opt_in_asa(state, asa_id):
    """Opt in to an ASA by sending a 0-amount transfer to self. No-op for ALGO (asa_id=0)."""
    asa_id = int(asa_id)
    if _is_algo(asa_id):
        record(state, "No opt-in needed for ALGO")
        return {"asa_id": 0, "status": "not_needed"}

    algod_client = get_algod()
    signer = get_signer()
    try:
        # Check if already opted in
        info = algod_client.account_info(state.my_address)
        for asset in info.get("assets", []):
            if asset.get("asset-id") == asa_id:
                record(state, f"Already opted in to ASA {asa_id}")
                return {"asa_id": asa_id, "status": "already_opted_in"}

        sp = algod_client.suggested_params()
        txn = transaction.AssetTransferTxn(
            sender=state.my_address,
            sp=sp,
            receiver=state.my_address,
            amt=0,
            index=asa_id,
        )
        signed = signer.sign_transaction(txn)
        txid = aplane.send_raw_transaction(algod_client, signed)
        transaction.wait_for_confirmation(algod_client, txid, 4)
        record(state, f"Opted in to ASA {asa_id} (txid: {txid})")
        return {"asa_id": asa_id, "status": "opted_in", "txid": txid}
    finally:
        signer.close()


def tool_check_asa_balance(state, address, asa_id):
    """Check the ASA (or ALGO if asa_id=0) balance of an address."""
    algod_client = get_algod()
    info = algod_client.account_info(address)
    asa_id = int(asa_id)
    if _is_algo(asa_id):
        amount = info.get("amount", 0)
        record(state, f"Checked ALGO balance of {address}: {amount}")
        return {"address": address, "asa_id": 0, "amount": amount}
    for asset in info.get("assets", []):
        if asset.get("asset-id") == asa_id:
            amount = asset.get("amount", 0)
            record(state, f"Checked ASA {asa_id} balance of {address}: {amount}")
            return {"address": address, "asa_id": asa_id, "amount": amount}
    record(state, f"Checked ASA {asa_id} balance of {address}: not opted in")
    return {"address": address, "asa_id": asa_id, "amount": 0, "note": "not opted in"}


def tool_get_my_key_info(state):
    """Get key info (key_type, lsig_size) for own address."""
    signer = get_signer()
    try:
        info = signer.get_key_info(state.my_address)
        if info is None:
            return {"error": f"No key found for {state.my_address}"}
        result = {
            "address": info.address,
            "key_type": info.key_type,
            "lsig_size": info.lsig_size,
        }
        record(state, f"Key info: type={info.key_type}, lsig_size={info.lsig_size}")
        return result
    finally:
        signer.close()


def tool_build_and_sign_swap(state, buyer_addr, seller_addr, offer_asa,
                             offer_amount, want_asa, want_amount,
                             buyer_lsig_size=0):
    """Build swap group using /plan, sign seller's half with foreign mode.

    Uses plan_group to get the finalized group (with dummies if needed),
    then sign_transactions_list to sign seller's txn + dummies.
    Writes the planned group and partial signatures to an on-chain box.

    Returns summary of the planned group.
    """
    # Enforce: seller_addr must be our address, buyer_addr must be peer
    if seller_addr != state.my_address:
        return {"error": f"seller_addr must be your address ({state.my_address}), got {seller_addr}"}
    if buyer_addr != state.peer_address:
        return {"error": f"buyer_addr must be peer address ({state.peer_address}), got {buyer_addr}"}
    # Enforce: swap terms must match state
    # offer_asa/offer_amount = what buyer sends = state.peer_asa_id/peer_asa_amount
    # want_asa/want_amount = what seller sends = state.my_asa_id/my_asa_amount
    if int(offer_asa) != state.peer_asa_id:
        return {"error": f"offer_asa mismatch: {offer_asa} != state.peer_asa_id {state.peer_asa_id}"}
    if int(offer_amount) != state.peer_asa_amount:
        return {"error": f"offer_amount mismatch: {offer_amount} != state.peer_asa_amount {state.peer_asa_amount}"}
    if int(want_asa) != state.my_asa_id:
        return {"error": f"want_asa mismatch: {want_asa} != state.my_asa_id {state.my_asa_id}"}
    if int(want_amount) != state.my_asa_amount:
        return {"error": f"want_amount mismatch: {want_amount} != state.my_asa_amount {state.my_asa_amount}"}

    algod_client = get_algod()
    signer = get_signer()
    try:
        sp = algod_client.suggested_params()

        # TxnA: buyer → seller (ALGO or ASA the buyer is paying with)
        if _is_algo(offer_asa):
            txn_a = transaction.PaymentTxn(
                sender=buyer_addr,
                sp=sp,
                receiver=seller_addr,
                amt=int(offer_amount),
            )
        else:
            txn_a = transaction.AssetTransferTxn(
                sender=buyer_addr,
                sp=sp,
                receiver=seller_addr,
                amt=int(offer_amount),
                index=int(offer_asa),
            )

        # TxnB: seller → buyer (ALGO or ASA the seller provides in return)
        if _is_algo(want_asa):
            txn_b = transaction.PaymentTxn(
                sender=seller_addr,
                sp=sp,
                receiver=buyer_addr,
                amt=int(want_amount),
            )
        else:
            txn_b = transaction.AssetTransferTxn(
                sender=seller_addr,
                sp=sp,
                receiver=buyer_addr,
                amt=int(want_amount),
                index=int(want_asa),
            )

        # Do NOT assign group ID — let the server handle it.
        # auth_addresses: None for buyer (foreign), seller_addr for seller's txn
        auth_addresses = [None, seller_addr]

        # lsig_sizes hint for foreign txn at index 0
        lsig_sizes = None
        buyer_lsig_size = int(buyer_lsig_size)
        if buyer_lsig_size > 0:
            lsig_sizes = {0: buyer_lsig_size}

        # Plan the group to get finalized txns (with dummies, fees, group ID)
        plan_result = signer.plan_group(
            txns=[txn_a, txn_b],
            auth_addresses=auth_addresses,
            lsig_sizes=lsig_sizes,
        )
        planned_txns_hex = plan_result["transactions"]

        # Sign: server adds same dummies, signs seller's txn + all dummies
        # Foreign index 0 comes back as ""
        signed_list = signer.sign_transactions_list(
            txns=[txn_a, txn_b],
            auth_addresses=auth_addresses,
            lsig_sizes=lsig_sizes,
        )

        # Compute proposal hash for session binding
        prop_hash = _proposal_hash(
            buyer_addr, seller_addr,
            offer_asa, offer_amount, want_asa, want_amount,
        )

        # Write exchange data to on-chain box
        exchange_data = {
            "proposal_hash": prop_hash,
            "planned_txns_hex": planned_txns_hex,
            "signed": signed_list,
        }
        exchange_json = json.dumps(exchange_data, separators=(",", ":")).encode()
        box_name = prop_hash.encode()
        app_id = state.swap_app_id or load_swap_app_id()
        if not app_id:
            return {"error": "No swap app_id — deploy the box contract first (run_buyer.py does this automatically)"}

        write_box(algod_client, signer, app_id, seller_addr, box_name,
                  exchange_json, acl_addrs=[seller_addr, buyer_addr])

        # Store box coordinates in state for later cleanup
        state.swap_app_id = app_id
        state.swap_box_name = prop_hash

        record(state, f"Built planned group ({len(planned_txns_hex)} txns) "
               f"and signed own half; wrote on-chain box {prop_hash}")
        return {
            "group_size": len(planned_txns_hex),
            "proposal_hash": prop_hash,
            "box_name": prop_hash,
            "app_id": app_id,
        }
    finally:
        signer.close()


def tool_verify_and_submit_swap(state):
    """Read exchange data from on-chain box, verify both legs, sign buyer's half, assemble, submit.

    All expected values are taken from state — no LLM-provided params.
    Verifies: proposal hash binding, TxnA (our send), TxnB (peer's send).
    """
    algod_client = get_algod()
    signer = get_signer()
    try:
        # Compute box name from proposal hash
        expected_hash = _proposal_hash(
            state.my_address, state.peer_address,
            state.my_asa_id, state.my_asa_amount,
            state.peer_asa_id, state.peer_asa_amount,
        )
        box_name = expected_hash.encode()
        app_id = state.swap_app_id

        # Read exchange data from on-chain box
        raw = read_box(algod_client, app_id, box_name)
        exchange_data = json.loads(raw)

        planned_txns_hex = exchange_data["planned_txns_hex"]
        seller_signed = exchange_data["signed"]

        # Verify proposal hash matches our swap terms (session binding)
        file_hash = exchange_data.get("proposal_hash", "")
        if file_hash != expected_hash:
            msg = f"Proposal hash mismatch: box={file_hash}, expected={expected_hash}"
            record(state, msg)
            return {"error": msg}

        # Decode planned txns to Transaction objects
        finalized_txns = []
        for hex_str in planned_txns_hex:
            txn_bytes = bytes.fromhex(hex_str)
            txn_msgpack = txn_bytes[2:]  # Strip "TX" prefix
            txn_b64 = base64.b64encode(txn_msgpack).decode()
            txn = encoding.msgpack_decode(txn_b64)
            finalized_txns.append(txn)

        errors = []

        # Verify TxnA (index 0): our outgoing transfer (ALGO or ASA)
        txn_a = finalized_txns[0]
        if txn_a.sender != state.my_address:
            errors.append(f"TxnA sender mismatch: {txn_a.sender} != {state.my_address}")
        if txn_a.receiver != state.peer_address:
            errors.append(f"TxnA receiver mismatch: {txn_a.receiver} != {state.peer_address}")
        if _is_algo(state.my_asa_id):
            if not isinstance(txn_a, transaction.PaymentTxn):
                errors.append(f"TxnA expected PaymentTxn, got {type(txn_a).__name__}")
            elif txn_a.amt != state.my_asa_amount:
                errors.append(f"TxnA amount mismatch: {txn_a.amt} != {state.my_asa_amount}")
        else:
            if not isinstance(txn_a, transaction.AssetTransferTxn):
                errors.append(f"TxnA expected AssetTransferTxn, got {type(txn_a).__name__}")
            else:
                if txn_a.index != state.my_asa_id:
                    errors.append(f"TxnA ASA mismatch: {txn_a.index} != {state.my_asa_id}")
                if txn_a.amount != state.my_asa_amount:
                    errors.append(f"TxnA amount mismatch: {txn_a.amount} != {state.my_asa_amount}")

        # Verify TxnB (index 1): peer's incoming transfer to us (ALGO or ASA)
        if len(finalized_txns) < 2:
            errors.append("Group has fewer than 2 transactions")
        else:
            txn_b = finalized_txns[1]
            if txn_b.sender != state.peer_address:
                errors.append(f"TxnB sender mismatch: {txn_b.sender} != {state.peer_address}")
            if txn_b.receiver != state.my_address:
                errors.append(f"TxnB receiver mismatch: {txn_b.receiver} != {state.my_address}")
            if _is_algo(state.peer_asa_id):
                if not isinstance(txn_b, transaction.PaymentTxn):
                    errors.append(f"TxnB expected PaymentTxn, got {type(txn_b).__name__}")
                elif txn_b.amt != state.peer_asa_amount:
                    errors.append(f"TxnB amount mismatch: {txn_b.amt} != {state.peer_asa_amount}")
            else:
                if not isinstance(txn_b, transaction.AssetTransferTxn):
                    errors.append(f"TxnB expected AssetTransferTxn, got {type(txn_b).__name__}")
                else:
                    if txn_b.index != state.peer_asa_id:
                        errors.append(f"TxnB ASA mismatch: {txn_b.index} != {state.peer_asa_id}")
                    if txn_b.amount != state.peer_asa_amount:
                        errors.append(f"TxnB amount mismatch: {txn_b.amount} != {state.peer_asa_amount}")

        if errors:
            msg = "Transaction verification failed: " + "; ".join(errors)
            record(state, msg)
            return {"error": msg}

        record(state, "Verified TxnA and TxnB fields match proposal")

        # Sign buyer's txn: auth only for index 0, None for the rest
        auth_addresses = [state.my_address] + [None] * (len(finalized_txns) - 1)
        buyer_signed = signer.sign_transactions_list(
            txns=finalized_txns,
            auth_addresses=auth_addresses,
        )

        # Assemble full group from both partial signatures
        combined = aplane.assemble_group([seller_signed, buyer_signed])

        # Submit atomic group
        txid = aplane.send_raw_transaction(algod_client, combined)
        transaction.wait_for_confirmation(algod_client, txid, 4)

        state.group_txid = txid
        state.status = "submitted"
        record(state, f"Submitted atomic group (txid: {txid})")
        return {"txid": txid}
    finally:
        signer.close()


def tool_complete_swap(state):
    """Mark the swap as complete and clean up the on-chain box."""
    state.status = "complete"

    # Delete the exchange box to reclaim MBR (tolerate failure —
    # the other party may have already deleted it)
    if state.swap_app_id and state.swap_box_name:
        try:
            algod_client = get_algod()
            signer = get_signer()
            try:
                delete_box(algod_client, signer, state.swap_app_id,
                           state.my_address, state.swap_box_name.encode())
                record(state, "Deleted exchange box")
            finally:
                signer.close()
        except Exception as e:
            record(state, f"Box cleanup skipped ({e})")

    record(state, "Swap marked complete")
    return {"status": "complete"}


# ---------------------------------------------------------------------------
# Anthropic tool schemas
# ---------------------------------------------------------------------------

TOOL_SCHEMAS = [
    {
        "name": "wait_for_message",
        "description": (
            "Block and poll the Indexer until an incoming swap_* note arrives "
            "from the peer. Updates state with received info (peer ASA details, "
            "app_id, status). Returns the note JSON. Use this instead of waiting "
            "passively — it handles all polling and state updates internally."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "timeout": {
                    "type": "integer",
                    "description": "Max seconds to wait (default 120)",
                    "default": 120,
                },
            },
            "required": [],
        },
    },
    {
        "name": "wait_for_asa_transfer",
        "description": (
            "Block and poll the Indexer until an incoming ASA transfer (or "
            "ALGO payment if asa_id=0) is detected. Used by the seller to "
            "confirm the atomic group was submitted by the buyer. Sets "
            "state.group_txid. Returns transfer info."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "asa_id": {
                    "type": "integer",
                    "description": "ASA ID to watch for incoming transfers (0 for ALGO)",
                },
                "timeout": {
                    "type": "integer",
                    "description": "Max seconds to wait (default 120)",
                    "default": 120,
                },
            },
            "required": ["asa_id"],
        },
    },
    {
        "name": "send_note",
        "description": (
            "Send a 0-ALGO payment transaction with a JSON note to communicate "
            "with the other party on-chain. Max note size 1024 bytes."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "sender": {
                    "type": "string",
                    "description": "Sender Algorand address",
                },
                "receiver": {
                    "type": "string",
                    "description": "Receiver Algorand address",
                },
                "note_json": {
                    "type": "object",
                    "description": "JSON object to include as transaction note",
                },
            },
            "required": ["sender", "receiver", "note_json"],
        },
    },
    {
        "name": "opt_in_asa",
        "description": (
            "Opt in to an ASA so your address can receive it. "
            "Sends a 0-amount asset transfer to yourself. "
            "No-op if already opted in. No-op for ALGO (asa_id=0)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "asa_id": {
                    "type": "integer",
                    "description": "ASA ID to opt in to (0 for ALGO, which is a no-op)",
                },
            },
            "required": ["asa_id"],
        },
    },
    {
        "name": "check_asa_balance",
        "description": "Check the ASA (or ALGO if asa_id=0) balance of an Algorand address.",
        "input_schema": {
            "type": "object",
            "properties": {
                "address": {
                    "type": "string",
                    "description": "Algorand address to check",
                },
                "asa_id": {
                    "type": "integer",
                    "description": "ASA ID to check balance for (0 for ALGO)",
                },
            },
            "required": ["address", "asa_id"],
        },
    },
    {
        "name": "get_my_key_info",
        "description": (
            "Get signing key info for your own address. Returns key_type "
            "(e.g. 'ed25519', 'falcon-1024') and lsig_size (0 for ed25519, "
            ">0 for LogicSig keys). Include lsig_size in proposals so the "
            "other party can build the group correctly."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
    {
        "name": "build_and_sign_swap",
        "description": (
            "Build a swap transaction group using the /plan endpoint and sign "
            "the seller's half. Uses foreign mode for the buyer's txn so "
            "the server adds dummies and computes fees correctly for any key "
            "type. Writes the planned group and partial signatures to an "
            "on-chain box for the buyer to read. Seller only."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "buyer_addr": {
                    "type": "string",
                    "description": "Buyer's Algorand address (sender of TxnA)",
                },
                "seller_addr": {
                    "type": "string",
                    "description": "Seller's Algorand address (sender of TxnB)",
                },
                "offer_asa": {
                    "type": "integer",
                    "description": "ASA ID the buyer is offering (sent in TxnA). Use 0 for ALGO.",
                },
                "offer_amount": {
                    "type": "integer",
                    "description": "Amount of offer_asa in base units (microAlgos if ALGO) in TxnA",
                },
                "want_asa": {
                    "type": "integer",
                    "description": "ASA ID the seller sends in return (sent in TxnB). Use 0 for ALGO.",
                },
                "want_amount": {
                    "type": "integer",
                    "description": "Amount of want_asa in base units (microAlgos if ALGO) in TxnB",
                },
                "buyer_lsig_size": {
                    "type": "integer",
                    "description": (
                        "LSig size of the buyer's key (from swap_propose). "
                        "0 for ed25519 keys, >0 for LogicSig keys (e.g. falcon-1024). "
                        "Needed so the server can add correct dummies."
                    ),
                    "default": 0,
                },
            },
            "required": [
                "buyer_addr", "seller_addr",
                "offer_asa", "offer_amount",
                "want_asa", "want_amount",
                "buyer_lsig_size",
            ],
        },
    },
    {
        "name": "verify_and_submit_swap",
        "description": (
            "Read the planned group and seller's partial signatures from "
            "the on-chain box. Verify the proposal hash matches this swap, "
            "verify both TxnA (your send) and TxnB (peer's send) match the "
            "agreed terms, sign your half, assemble the full group, and submit. "
            "All expected values come from state — no parameters needed. "
            "Buyer only."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
    {
        "name": "complete_swap",
        "description": (
            "Mark the atomic swap as complete, clean up the on-chain box, "
            "and stop the orchestrator. Call this after the swap is confirmed "
            "on-chain."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
]

# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

_DISPATCH = {
    "wait_for_message": lambda state, inp: tool_wait_for_message(state, **inp),
    "wait_for_asa_transfer": lambda state, inp: tool_wait_for_asa_transfer(state, **inp),
    "send_note": lambda state, inp: tool_send_note(state, **inp),
    "opt_in_asa": lambda state, inp: tool_opt_in_asa(state, **inp),
    "check_asa_balance": lambda state, inp: tool_check_asa_balance(state, **inp),
    "get_my_key_info": lambda state, inp: tool_get_my_key_info(state),
    "build_and_sign_swap": lambda state, inp: tool_build_and_sign_swap(state, **inp),
    "verify_and_submit_swap": lambda state, inp: tool_verify_and_submit_swap(state),
    "complete_swap": lambda state, inp: tool_complete_swap(state),
}


def dispatch_tool(tool_name, tool_input, state):
    fn = _DISPATCH.get(tool_name)
    if fn is None:
        return {"error": f"Unknown tool: {tool_name}"}
    return fn(state, tool_input)
