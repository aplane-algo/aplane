"""Box read/write/delete for swap exchange data via Algorand box storage."""

import zlib

from algosdk import transaction
from algosdk.v2client import algod

import aplane

CHUNK_SIZE = 2000  # bytes per box_replace call
PREFIX_SIZE = 160  # creator (32B) + 4 ACL slots (4 × 32B), zero-filled if unused
BOX_MBR_BASE = 2500       # microAlgo base cost per box
BOX_MBR_PER_BYTE = 400    # microAlgo per byte of (name + value)


def _box_mbr(name_len: int, value_len: int) -> int:
    """Compute the minimum balance requirement for a box."""
    return BOX_MBR_BASE + BOX_MBR_PER_BYTE * (name_len + value_len)


def _delete_stale_box(algod_client, signer, app_id, sender, box_name):
    """Delete an existing box (cleanup from a previous failed run)."""
    sp = algod_client.suggested_params()
    sp.fee = 2 * sp.min_fee   # cover inner MBR refund txn
    sp.flat_fee = True
    box_refs = [[app_id, box_name]] * 7
    delete_txn = transaction.ApplicationCallTxn(
        sender=sender,
        sp=sp,
        index=app_id,
        on_complete=transaction.OnComplete.NoOpOC,
        app_args=[b"delete", box_name],
        boxes=box_refs,
    )
    signed = signer.sign_transaction(delete_txn)
    txid = aplane.send_raw_transaction(algod_client, signed)
    transaction.wait_for_confirmation(algod_client, txid, 4)


def write_box(algod_client: algod.AlgodClient, signer: aplane.SignerClient,
              app_id: int, sender: str, box_name: bytes, data: bytes,
              acl_addrs: list[str] | None = None):
    """Compress data and write to an on-chain box via atomic group.

    Builds an atomic group: MBR payment + create + N write-chunk calls.
    All signed by the same sender.

    acl_addrs is a list of 1-4 Algorand addresses authorized to write/delete
    this box.  They are stored in the 160-byte prefix by the TEAL contract.
    """
    compressed = zlib.compress(data)
    size = len(compressed)

    # Delete any stale box from a previous failed run
    try:
        algod_client.application_box_by_name(app_id, box_name)
        # Box exists — delete it first
        _delete_stale_box(algod_client, signer, app_id, sender, box_name)
    except Exception:
        pass  # Box doesn't exist, proceed normally

    sp = algod_client.suggested_params()
    box_size = size + PREFIX_SIZE
    mbr = _box_mbr(len(box_name), box_size)
    app_addr = transaction.logic.get_application_address(app_id)

    # Build transaction group: MBR payment + create + write chunks
    txns = []

    # MBR payment to contract (must precede the create app call)
    pay_txn = transaction.PaymentTxn(
        sender=sender,
        sp=sp,
        receiver=app_addr,
        amt=mbr,
    )
    txns.append(pay_txn)

    # Create box — size includes prefix; pass ACL accounts
    create_txn = transaction.ApplicationCallTxn(
        sender=sender,
        sp=sp,
        index=app_id,
        on_complete=transaction.OnComplete.NoOpOC,
        app_args=[b"create", box_name, box_size.to_bytes(8, "big")],
        accounts=acl_addrs or [],
        boxes=[[app_id, box_name]],
    )
    txns.append(create_txn)

    # Write chunks — TEAL adds PREFIX_SIZE to caller's offset automatically
    for offset in range(0, size, CHUNK_SIZE):
        chunk = compressed[offset:offset + CHUNK_SIZE]
        write_txn = transaction.ApplicationCallTxn(
            sender=sender,
            sp=sp,
            index=app_id,
            on_complete=transaction.OnComplete.NoOpOC,
            app_args=[b"write", box_name, offset.to_bytes(8, "big"), chunk],
            boxes=[[app_id, box_name]],
        )
        txns.append(write_txn)

    # All same signer — use sign_transactions (no foreign entries)
    auth_addresses = [sender] * len(txns)
    signed = signer.sign_transactions(txns, auth_addresses=auth_addresses)
    txid = aplane.send_raw_transaction(algod_client, signed)
    transaction.wait_for_confirmation(algod_client, txid, 4)
    return txid


def read_box(algod_client: algod.AlgodClient, app_id: int,
             box_name: bytes) -> bytes:
    """Read and decompress box data (REST query, no transaction needed)."""
    import base64
    result = algod_client.application_box_by_name(app_id, box_name)
    raw = base64.b64decode(result["value"])
    return zlib.decompress(raw[PREFIX_SIZE:])


def delete_box(algod_client: algod.AlgodClient, signer: aplane.SignerClient,
               app_id: int, sender: str, box_name: bytes):
    """Delete a box to reclaim MBR. Tolerates failure."""
    sp = algod_client.suggested_params()
    sp.fee = 2 * sp.min_fee   # cover inner MBR refund txn
    sp.flat_fee = True
    # Each box reference adds 1024 bytes of I/O budget.
    # For a ~5KB box, we need ~7 references (1 base + 6 extra) to cover it.
    box_refs = [[app_id, box_name]] * 7
    delete_txn = transaction.ApplicationCallTxn(
        sender=sender,
        sp=sp,
        index=app_id,
        on_complete=transaction.OnComplete.NoOpOC,
        app_args=[b"delete", box_name],
        boxes=box_refs,
    )
    signed = signer.sign_transaction(delete_txn)
    txid = aplane.send_raw_transaction(algod_client, signed)
    transaction.wait_for_confirmation(algod_client, txid, 4)
    return txid
