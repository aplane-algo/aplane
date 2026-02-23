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
from htlc_log import log

# ---------------------------------------------------------------------------
# Clients
# ---------------------------------------------------------------------------

ALGOD_ADDRESS = "https://testnet-api.algonode.cloud"
ALGOD_TOKEN = ""
INDEXER_URL = "https://testnet-idx.algonode.cloud"
POLL_INTERVAL = 4  # seconds between polls


def get_algod():
    return algod.AlgodClient(ALGOD_TOKEN, ALGOD_ADDRESS)


def get_signer():
    return aplane.SignerClient.from_env()


def record(state, message):
    """Append to state actions and shared log."""
    state.actions.append(message)
    log(state.my_address[:4], message)


def _is_valid_address(addr: str) -> bool:
    """Return True if addr is a syntactically valid Algorand address."""
    try:
        return bool(addr) and encoding.is_valid_address(addr)
    except Exception:
        return False


def _is_algo(asa_id):
    """Return True if asa_id represents native ALGO (0)."""
    return int(asa_id) == 0


# ---------------------------------------------------------------------------
# Polling helpers (private)
# ---------------------------------------------------------------------------


def _poll_messages(address: str, last_round: int, seen_txids: set) -> list:
    """Poll Indexer for incoming HTLC notes addressed to us."""
    prefix = base64.b64encode(b'{"type":"htlc_').decode()
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
                if isinstance(note_json, dict) and note_json.get("type", "").startswith("htlc_"):
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


def _poll_hashlock_claim(hashlock_address: str, min_round: int) -> dict | None:
    """Poll Indexer for a claim transaction on a hashlock address.

    Looks for transactions FROM the hashlock that have LogicSig args,
    indicating someone claimed by providing the preimage.  Returns
    {"preimage": hex, "txid": ..., "round": ...} or None.
    """
    params = {
        "address": hashlock_address,
        "address-role": "sender",
        "min-round": min_round,
    }
    try:
        resp = requests.get(
            f"{INDEXER_URL}/v2/transactions", params=params, timeout=10
        )
        if resp.status_code != 200:
            return None
        for txn in resp.json().get("transactions", []):
            sig = txn.get("signature", {})
            lsig = sig.get("logicsig", {})
            args = lsig.get("args", [])
            if args:
                preimage_bytes = base64.b64decode(args[0])
                return {
                    "preimage": preimage_bytes.hex(),
                    "txid": txn.get("id", ""),
                    "round": txn.get("confirmed-round", 0),
                }
    except Exception as e:
        print(f"  Poll hashlock claim error: {e}")
    return None


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------


def tool_get_current_round(state):
    """Fetch the latest confirmed round from algod."""
    client = algod.AlgodClient(ALGOD_TOKEN, ALGOD_ADDRESS)
    current_round = client.status().get("last-round", 0)
    record(state, f"Current round: {current_round}")
    return {"round": current_round}


def tool_generate_preimage(state):
    """Generate random 32-byte preimage + SHA256 hash."""
    preimage = os.urandom(32)
    h = hashlib.sha256(preimage).digest()
    state.preimage = preimage.hex()
    state.hash = h.hex()
    record(state, f"Generated preimage (hash: {state.hash})")
    return {"preimage": state.preimage, "hash": state.hash}


def tool_create_hashlock(state, hash_hex, recipient, refund_address, timeout_round):
    """Create a hashlock-v1 key on the signer."""
    if recipient != state.peer_address:
        return {"error": f"recipient must be peer address ({state.peer_address}), got {recipient}"}
    if refund_address != state.my_address:
        return {"error": f"refund_address must be your address ({state.my_address}), got {refund_address}"}
    if not isinstance(hash_hex, str) or len(hash_hex) != 64:
        return {"error": "hash_hex must be a 64-character hex string"}
    try:
        bytes.fromhex(hash_hex)
    except ValueError:
        return {"error": "hash_hex must be valid hex"}

    timeout_round = int(timeout_round)
    if timeout_round <= 0:
        return {"error": f"timeout_round must be > 0, got {timeout_round}"}
    if state.role == "seller" and state.peer_timeout and timeout_round >= int(state.peer_timeout):
        return {
            "error": (
                f"seller timeout must be shorter than buyer timeout: "
                f"{timeout_round} >= {state.peer_timeout}"
            )
        }

    signer = get_signer()
    try:
        result = signer.generate_key(
            key_type="hashlock-v1",
            parameters={
                "hash": hash_hex,
                "recipient": recipient,
                "refund_address": refund_address,
                "timeout_round": str(timeout_round),
            },
        )
        # Track in state
        state.my_hashlock = result.address
        state.my_timeout = timeout_round
        state.hash = hash_hex
        record(state, f"Created hashlock: {result.address}")
        return {"address": result.address}
    finally:
        signer.close()


def tool_fund_hashlock(state, from_address, hashlock_address, amount_microalgos):
    """Fund a hashlock address with ALGO."""
    if from_address != state.my_address:
        return {"error": f"from_address must be your address ({state.my_address}), got {from_address}"}
    if not state.my_hashlock:
        return {"error": "No my_hashlock in state — create_hashlock must run first"}
    if hashlock_address != state.my_hashlock:
        return {"error": f"hashlock_address must be your hashlock ({state.my_hashlock}), got {hashlock_address}"}
    if int(amount_microalgos) < int(state.fund_algo_amount):
        return {
            "error": (
                f"amount_microalgos too low: {amount_microalgos} < required "
                f"{state.fund_algo_amount}"
            )
        }

    algod_client = get_algod()
    signer = get_signer()
    try:
        sp = algod_client.suggested_params()
        txn = transaction.PaymentTxn(
            sender=from_address,
            sp=sp,
            receiver=hashlock_address,
            amt=int(amount_microalgos),
        )
        signed = signer.sign_transaction(txn)
        txid = aplane.send_raw_transaction(algod_client, signed)
        transaction.wait_for_confirmation(algod_client, txid, 4)
        record(state, f"Funded {hashlock_address} with {amount_microalgos} microAlgos (txid: {txid})")
        return {"txid": txid}
    finally:
        signer.close()


def tool_send_note(state, sender, receiver, note_json):
    """Send a 0-ALGO transaction with a JSON note."""
    if sender != state.my_address:
        return {"error": f"sender must be your address ({state.my_address}), got {sender}"}
    if receiver != state.peer_address:
        return {"error": f"receiver must be peer address ({state.peer_address}), got {receiver}"}
    if not isinstance(note_json, dict):
        return {"error": "note_json must be an object"}

    # Canonicalize note shape so "type" is first; this keeps indexer
    # note-prefix filtering effective and independent of LLM key order.
    if "type" in note_json:
        canonical = {"type": note_json["type"]}
        for k, v in note_json.items():
            if k != "type":
                canonical[k] = v
        note_json = canonical

    algod_client = get_algod()
    signer = get_signer()
    try:
        sp = algod_client.suggested_params()
        note_bytes = json.dumps(note_json, separators=(",", ":")).encode("utf-8")
        if len(note_bytes) > 1024:
            return {"error": "Note exceeds 1024 bytes"}
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
        # Update status based on note type
        if msg_type == "htlc_offer":
            state.status = "offer_sent"
        elif msg_type == "htlc_accept":
            state.status = "accept_sent"
        return {"txid": txid}
    finally:
        signer.close()


def tool_optin_asa(state, hashlock_address, asa_id):
    """Opt a hashlock address into an ASA (0-amount axfer to self). No-op for ALGO."""
    if _is_algo(asa_id):
        record(state, "No opt-in needed for ALGO")
        return {"asa_id": 0, "status": "not_needed"}
    if not state.my_hashlock:
        return {"error": "No my_hashlock in state — create_hashlock must run first"}
    if hashlock_address != state.my_hashlock:
        return {"error": f"hashlock_address must be your hashlock ({state.my_hashlock}), got {hashlock_address}"}
    if int(asa_id) != int(state.my_asa_id):
        return {"error": f"asa_id mismatch: {asa_id} != state.my_asa_id {state.my_asa_id}"}

    algod_client = get_algod()
    signer = get_signer()
    try:
        sp = algod_client.suggested_params()
        txn = transaction.AssetTransferTxn(
            sender=hashlock_address,
            sp=sp,
            receiver=hashlock_address,
            amt=0,
            index=int(asa_id),
        )
        signed = signer.sign_transaction(
            txn,
            auth_address=hashlock_address,
        )
        txid = aplane.send_raw_transaction(algod_client, signed)
        transaction.wait_for_confirmation(algod_client, txid, 4)
        record(state, f"Opted {hashlock_address} into ASA {asa_id} (txid: {txid})")
        return {"txid": txid}
    finally:
        signer.close()


def tool_fund_hashlock_asa(state, from_address, hashlock_address, asa_id, asa_amount):
    """Fund a hashlock address with an ASA (or ALGO if asa_id=0)."""
    if from_address != state.my_address:
        return {"error": f"from_address must be your address ({state.my_address}), got {from_address}"}
    if not state.my_hashlock:
        return {"error": "No my_hashlock in state — create_hashlock must run first"}
    if hashlock_address != state.my_hashlock:
        return {"error": f"hashlock_address must be your hashlock ({state.my_hashlock}), got {hashlock_address}"}
    if not _is_algo(asa_id) and int(asa_id) != int(state.my_asa_id):
        return {"error": f"asa_id mismatch: {asa_id} != state.my_asa_id {state.my_asa_id}"}
    if int(asa_amount) != int(state.my_asa_amount):
        return {"error": f"asa_amount mismatch: {asa_amount} != state.my_asa_amount {state.my_asa_amount}"}

    algod_client = get_algod()
    signer = get_signer()
    try:
        sp = algod_client.suggested_params()
        if _is_algo(asa_id):
            txn = transaction.PaymentTxn(
                sender=from_address,
                sp=sp,
                receiver=hashlock_address,
                amt=int(asa_amount),
            )
        else:
            txn = transaction.AssetTransferTxn(
                sender=from_address,
                sp=sp,
                receiver=hashlock_address,
                amt=int(asa_amount),
                index=int(asa_id),
            )
        signed = signer.sign_transaction(txn)
        txid = aplane.send_raw_transaction(algod_client, signed)
        transaction.wait_for_confirmation(algod_client, txid, 4)
        label = "ALGO" if _is_algo(asa_id) else f"ASA {asa_id}"
        record(state, f"Funded {hashlock_address} with {asa_amount} of {label} (txid: {txid})")
        return {"txid": txid}
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


def tool_claim_hashlock(state, hashlock_address, recipient, preimage_hex):
    """Claim ALGO from a hashlock using the preimage (pay with close_remainder_to)."""
    if not state.peer_hashlock:
        return {"error": "No peer_hashlock in state — cannot claim"}
    if hashlock_address != state.peer_hashlock:
        return {"error": f"hashlock_address must be peer_hashlock ({state.peer_hashlock}), got {hashlock_address}"}
    if recipient != state.my_address:
        return {"error": f"recipient must be your address ({state.my_address}), got {recipient}"}
    if not isinstance(preimage_hex, str) or len(preimage_hex) != 64:
        return {"error": "preimage_hex must be a 64-character hex string"}
    try:
        preimage_bytes = bytes.fromhex(preimage_hex)
    except ValueError:
        return {"error": "preimage_hex must be valid hex"}
    if state.hash and hashlib.sha256(preimage_bytes).hexdigest() != state.hash:
        return {"error": "preimage_hex does not match expected hash in state"}

    algod_client = get_algod()
    signer = get_signer()
    try:
        sp = algod_client.suggested_params()
        txn = transaction.PaymentTxn(
            sender=hashlock_address,
            sp=sp,
            receiver=recipient,
            amt=0,
            close_remainder_to=recipient,
        )
        signed = signer.sign_transaction(
            txn,
            auth_address=hashlock_address,
            lsig_args={"preimage": preimage_bytes},
        )
        txid = aplane.send_raw_transaction(algod_client, signed)
        transaction.wait_for_confirmation(algod_client, txid, 4)
        state.claim_txid = txid
        record(state, f"Claimed ALGO from {hashlock_address} (txid: {txid})")
        return {"txid": txid}
    finally:
        signer.close()


def tool_claim_hashlock_asa(state, hashlock_address, recipient, preimage_hex, asa_id):
    """Claim an ASA (or ALGO if asa_id=0) from a hashlock using the preimage."""
    if not state.peer_hashlock:
        return {"error": "No peer_hashlock in state — cannot claim"}
    if hashlock_address != state.peer_hashlock:
        return {"error": f"hashlock_address must be peer_hashlock ({state.peer_hashlock}), got {hashlock_address}"}
    if recipient != state.my_address:
        return {"error": f"recipient must be your address ({state.my_address}), got {recipient}"}
    if not _is_algo(asa_id) and int(asa_id) != int(state.peer_asa_id):
        return {"error": f"asa_id mismatch: {asa_id} != state.peer_asa_id {state.peer_asa_id}"}
    if not isinstance(preimage_hex, str) or len(preimage_hex) != 64:
        return {"error": "preimage_hex must be a 64-character hex string"}
    try:
        preimage_bytes = bytes.fromhex(preimage_hex)
    except ValueError:
        return {"error": "preimage_hex must be valid hex"}
    if state.hash and hashlib.sha256(preimage_bytes).hexdigest() != state.hash:
        return {"error": "preimage_hex does not match expected hash in state"}

    algod_client = get_algod()
    signer = get_signer()
    try:
        sp = algod_client.suggested_params()
        if _is_algo(asa_id):
            txn = transaction.PaymentTxn(
                sender=hashlock_address,
                sp=sp,
                receiver=recipient,
                amt=0,
                close_remainder_to=recipient,
            )
        else:
            txn = transaction.AssetTransferTxn(
                sender=hashlock_address,
                sp=sp,
                receiver=recipient,
                amt=0,
                index=int(asa_id),
                close_assets_to=recipient,
            )
        signed = signer.sign_transaction(
            txn,
            auth_address=hashlock_address,
            lsig_args={"preimage": preimage_bytes},
        )
        txid = aplane.send_raw_transaction(algod_client, signed)
        transaction.wait_for_confirmation(algod_client, txid, 4)
        state.claim_txid = txid
        label = "ALGO" if _is_algo(asa_id) else f"ASA {asa_id}"
        record(state, f"Claimed {label} from {hashlock_address} (txid: {txid})")
        return {"txid": txid}
    finally:
        signer.close()


def tool_wait_for_message(state, timeout=120):
    """Block until an incoming htlc_offer or htlc_accept note arrives.

    Updates state from the received note:
    - htlc_offer: sets hash, peer_hashlock, peer_timeout, peer_asa_id,
      peer_asa_amount, status="offer_received"
    - htlc_accept: sets peer_hashlock, peer_timeout, peer_asa_id,
      peer_asa_amount, status="accept_received"
    """
    seen = set(state.seen_txids)
    deadline = time.time() + timeout

    print(f"  [wait_for_message] Polling for incoming htlc note (timeout={timeout}s)...")
    while time.time() < deadline:
        msgs = _poll_messages(state.my_address, state.last_seen_round, seen)
        if msgs:
            msg = msgs[0]  # process first new message
            note = msg["note"]
            msg_type = note.get("type", "")
            sender = msg.get("sender", "")

            if sender != state.peer_address:
                record(state, f"Ignored {msg_type or 'unknown'} note from non-peer sender {sender}")
                state.seen_txids.append(msg["txid"])
                seen.add(msg["txid"])
                state.last_seen_round = max(state.last_seen_round, msg["round"])
                continue

            # Dedup
            state.seen_txids.append(msg["txid"])
            seen.add(msg["txid"])
            state.last_seen_round = max(state.last_seen_round, msg["round"])

            # Update state from received note
            if msg_type == "htlc_offer":
                note_hash = note.get("hash", "")
                note_hashlock = note.get("hashlock_addr", "")
                note_timeout = int(note.get("timeout_round", 0))
                note_asa_id = int(note.get("asa_id", -1))
                note_asa_amount = int(note.get("asa_amount", -1))

                if len(note_hash) != 64:
                    return {"error": "Invalid htlc_offer: hash must be 64 hex chars"}
                try:
                    bytes.fromhex(note_hash)
                except ValueError:
                    return {"error": "Invalid htlc_offer: hash must be valid hex"}
                if not _is_valid_address(note_hashlock):
                    return {"error": "Invalid htlc_offer: hashlock_addr is not a valid Algorand address"}
                if note_timeout <= 0:
                    return {"error": "Invalid htlc_offer: timeout_round must be > 0"}
                if note_asa_id != int(state.peer_asa_id):
                    return {
                        "error": (
                            f"Invalid htlc_offer: asa_id mismatch {note_asa_id} "
                            f"!= expected {state.peer_asa_id}"
                        )
                    }
                if note_asa_amount != int(state.peer_asa_amount):
                    return {
                        "error": (
                            f"Invalid htlc_offer: asa_amount mismatch {note_asa_amount} "
                            f"!= expected {state.peer_asa_amount}"
                        )
                    }

                state.hash = note_hash
                state.peer_hashlock = note_hashlock
                state.peer_timeout = note_timeout
                state.peer_asa_id = note_asa_id
                state.peer_asa_amount = note_asa_amount
                state.status = "offer_received"
            elif msg_type == "htlc_accept":
                note_hashlock = note.get("hashlock_addr", "")
                note_timeout = int(note.get("timeout_round", 0))
                note_asa_id = int(note.get("asa_id", -1))
                note_asa_amount = int(note.get("asa_amount", -1))

                if not _is_valid_address(note_hashlock):
                    return {"error": "Invalid htlc_accept: hashlock_addr is not a valid Algorand address"}
                if note_timeout <= 0:
                    return {"error": "Invalid htlc_accept: timeout_round must be > 0"}
                if state.my_timeout and note_timeout >= int(state.my_timeout):
                    return {
                        "error": (
                            f"Unsafe htlc_accept: peer timeout must be shorter than ours "
                            f"({note_timeout} >= {state.my_timeout})"
                        )
                    }
                if note_asa_id != int(state.peer_asa_id):
                    return {
                        "error": (
                            f"Invalid htlc_accept: asa_id mismatch {note_asa_id} "
                            f"!= expected {state.peer_asa_id}"
                        )
                    }
                if note_asa_amount != int(state.peer_asa_amount):
                    return {
                        "error": (
                            f"Invalid htlc_accept: asa_amount mismatch {note_asa_amount} "
                            f"!= expected {state.peer_asa_amount}"
                        )
                    }

                state.peer_hashlock = note_hashlock
                state.peer_timeout = note_timeout
                state.peer_asa_id = note_asa_id
                state.peer_asa_amount = note_asa_amount
                state.status = "accept_received"
            else:
                return {"error": f"Unknown note type: {msg_type}"}

            record(state, f"Received {msg_type} (round {msg['round']})")
            print(f"  [wait_for_message] Received {msg_type} (round {msg['round']})")
            return {"type": msg_type, "note": note, "round": msg["round"],
                    "sender": msg["sender"]}

        time.sleep(POLL_INTERVAL)

    record(state, "wait_for_message timed out")
    return {"error": f"No incoming htlc message within {timeout}s"}


def tool_wait_for_preimage(state, timeout=300):
    """Block until the buyer claims from our hashlock, revealing the preimage.

    Polls for claim transactions FROM state.my_hashlock (no LLM-provided
    address). Sets state.preimage and status="preimage_discovered".
    """
    if not state.my_hashlock:
        return {"error": "No my_hashlock in state — cannot poll for preimage"}

    deadline = time.time() + timeout

    print(f"  [wait_for_preimage] Polling {state.my_hashlock[:8]}... for claim (timeout={timeout}s)...")
    while time.time() < deadline:
        claim = _poll_hashlock_claim(state.my_hashlock, state.last_seen_round)
        if claim:
            claim_round = int(claim.get("round", 0))
            state.last_seen_round = max(state.last_seen_round, claim_round)
            state.preimage = claim["preimage"]
            state.status = "preimage_discovered"
            record(state, f"Discovered preimage on-chain (txid: {claim['txid']})")
            print(f"  [wait_for_preimage] Preimage discovered (round {claim['round']})")
            return {
                "preimage": claim["preimage"],
                "claim_txid": claim["txid"],
                "round": claim["round"],
            }

        time.sleep(POLL_INTERVAL)

    record(state, "wait_for_preimage timed out")
    return {"error": f"No preimage discovered within {timeout}s"}


def tool_complete_swap(state):
    """Mark the swap as complete."""
    state.status = "complete"
    record(state, "Swap marked complete")
    return {"status": "complete"}


# ---------------------------------------------------------------------------
# Anthropic tool schemas
# ---------------------------------------------------------------------------

TOOL_SCHEMAS = [
    {
        "name": "get_current_round",
        "description": (
            "Get the latest confirmed round number from the Algorand network. "
            "Use this to compute hashlock timeout rounds (round + 500 for "
            "buyer, round + 200 for seller)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
    {
        "name": "generate_preimage",
        "description": (
            "Generate a random 32-byte preimage and its SHA256 hash. "
            "Returns {preimage, hash} both as hex strings. Buyer only."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
    {
        "name": "create_hashlock",
        "description": (
            "Create a hashlock-v1 key on the signer. Returns the hashlock address. "
            "Parameters: hash (64 hex chars SHA256), recipient (Algorand address that "
            "can claim by providing the preimage), refund_address (Algorand address "
            "that can reclaim after timeout), timeout_round (block round after which "
            "refund is possible)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "hash_hex": {
                    "type": "string",
                    "description": "SHA256 hash in hex (64 characters)",
                },
                "recipient": {
                    "type": "string",
                    "description": "Algorand address that can claim with preimage",
                },
                "refund_address": {
                    "type": "string",
                    "description": "Algorand address that can refund after timeout",
                },
                "timeout_round": {
                    "type": "integer",
                    "description": "Block round after which refund is possible",
                },
            },
            "required": ["hash_hex", "recipient", "refund_address", "timeout_round"],
        },
    },
    {
        "name": "fund_hashlock",
        "description": (
            "Fund a hashlock address with ALGO via a payment transaction. "
            "The transaction is signed by from_address and sends amount_microalgos "
            "to the hashlock."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "from_address": {
                    "type": "string",
                    "description": "Sender Algorand address",
                },
                "hashlock_address": {
                    "type": "string",
                    "description": "Hashlock address to fund",
                },
                "amount_microalgos": {
                    "type": "integer",
                    "description": "Amount in microAlgos to send",
                },
            },
            "required": ["from_address", "hashlock_address", "amount_microalgos"],
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
        "name": "optin_asa",
        "description": (
            "Opt a hashlock address into an ASA so it can receive that asset "
            "(no-op for ALGO, i.e. asa_id=0). "
            "This sends a 0-amount asset transfer from the hashlock to itself. "
            "The hashlock must already be funded with ALGO for minimum balance."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "hashlock_address": {
                    "type": "string",
                    "description": "Hashlock address to opt in",
                },
                "asa_id": {
                    "type": "integer",
                    "description": "ASA ID to opt into",
                },
            },
            "required": ["hashlock_address", "asa_id"],
        },
    },
    {
        "name": "fund_hashlock_asa",
        "description": (
            "Fund a hashlock address with an ASA (uses ALGO payment if asa_id=0). "
            "The hashlock must already be opted into the ASA (not needed for ALGO). "
            "The transaction is signed by from_address."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "from_address": {
                    "type": "string",
                    "description": "Sender Algorand address",
                },
                "hashlock_address": {
                    "type": "string",
                    "description": "Hashlock address to fund",
                },
                "asa_id": {
                    "type": "integer",
                    "description": "ASA ID to send",
                },
                "asa_amount": {
                    "type": "integer",
                    "description": "Amount in base units to send",
                },
            },
            "required": ["from_address", "hashlock_address", "asa_id", "asa_amount"],
        },
    },
    {
        "name": "check_asa_balance",
        "description": "Check the ASA balance of an Algorand address (or ALGO balance if asa_id=0).",
        "input_schema": {
            "type": "object",
            "properties": {
                "address": {
                    "type": "string",
                    "description": "Algorand address to check",
                },
                "asa_id": {
                    "type": "integer",
                    "description": "ASA ID to check balance for",
                },
            },
            "required": ["address", "asa_id"],
        },
    },
    {
        "name": "claim_hashlock",
        "description": (
            "Claim ALGO from a hashlock by providing the preimage. Sends a payment "
            "from the hashlock address with close_remainder_to set to the recipient, "
            "sweeping all ALGO out."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "hashlock_address": {
                    "type": "string",
                    "description": "Hashlock address to claim from",
                },
                "recipient": {
                    "type": "string",
                    "description": "Address to receive the ALGO (must match hashlock recipient)",
                },
                "preimage_hex": {
                    "type": "string",
                    "description": "Preimage in hex (64 characters / 32 bytes)",
                },
            },
            "required": ["hashlock_address", "recipient", "preimage_hex"],
        },
    },
    {
        "name": "claim_hashlock_asa",
        "description": (
            "Claim an ASA from a hashlock by providing the preimage (uses ALGO "
            "payment if asa_id=0). Sends an asset transfer from the hashlock with "
            "close_assets_to set to the recipient, sweeping the entire balance out."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "hashlock_address": {
                    "type": "string",
                    "description": "Hashlock address to claim from",
                },
                "recipient": {
                    "type": "string",
                    "description": "Address to receive the ASA (must match hashlock recipient)",
                },
                "preimage_hex": {
                    "type": "string",
                    "description": "Preimage in hex (64 characters / 32 bytes)",
                },
                "asa_id": {
                    "type": "integer",
                    "description": "ASA ID to claim",
                },
            },
            "required": ["hashlock_address", "recipient", "preimage_hex", "asa_id"],
        },
    },
    {
        "name": "wait_for_message",
        "description": (
            "Block and poll the Indexer until an incoming htlc_offer or htlc_accept "
            "note arrives from the peer. Updates state with received info (hash, "
            "peer_hashlock, peer_timeout, peer ASA details, status). Returns the "
            "note JSON. Use this instead of waiting passively — it handles all "
            "polling and state updates internally."
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
        "name": "wait_for_preimage",
        "description": (
            "Block and poll the Indexer until the buyer claims from your "
            "hashlock, revealing the preimage on-chain via LogicSig args. "
            "Uses the hashlock address from state (no parameters needed except "
            "optional timeout). Sets state.preimage and status='preimage_discovered'. "
            "Seller only."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "timeout": {
                    "type": "integer",
                    "description": "Max seconds to wait (default 300)",
                    "default": 300,
                },
            },
            "required": [],
        },
    },
    {
        "name": "complete_swap",
        "description": (
            "Mark the atomic swap as complete and stop the orchestrator. "
            "Call this after all claims are done."
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
    "get_current_round": lambda state, inp: tool_get_current_round(state),
    "generate_preimage": lambda state, inp: tool_generate_preimage(state),
    "create_hashlock": lambda state, inp: tool_create_hashlock(state, **inp),
    "fund_hashlock": lambda state, inp: tool_fund_hashlock(state, **inp),
    "optin_asa": lambda state, inp: tool_optin_asa(state, **inp),
    "fund_hashlock_asa": lambda state, inp: tool_fund_hashlock_asa(state, **inp),
    "send_note": lambda state, inp: tool_send_note(state, **inp),
    "check_asa_balance": lambda state, inp: tool_check_asa_balance(state, **inp),
    "claim_hashlock": lambda state, inp: tool_claim_hashlock(state, **inp),
    "claim_hashlock_asa": lambda state, inp: tool_claim_hashlock_asa(state, **inp),
    "wait_for_message": lambda state, inp: tool_wait_for_message(state, **inp),
    "wait_for_preimage": lambda state, inp: tool_wait_for_preimage(state, **inp),
    "complete_swap": lambda state, inp: tool_complete_swap(state),
}


def dispatch_tool(tool_name, tool_input, state):
    fn = _DISPATCH.get(tool_name)
    if fn is None:
        return {"error": f"Unknown tool: {tool_name}"}
    return fn(state, tool_input)
