#!/usr/bin/env python3
"""Launch the HTLC swap seller agent."""

import os
import sys

# Ensure aplane SDK is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "sdk", "python"))

from config import BUYER, SELLER, ASA_A, ASA_A_AMOUNT, ASA_B, ASA_B_AMOUNT
from orchestrator import run

STATE_FILE = os.path.join(os.path.dirname(__file__), "state_seller.json")

if __name__ == "__main__":
    # Clean slate: remove previous state file
    if os.path.exists(STATE_FILE):
        os.remove(STATE_FILE)

    run(
        role="seller",
        my_address=SELLER,
        peer_address=BUYER,
        state_path=STATE_FILE,
        my_asa_id=ASA_B,
        my_asa_amount=ASA_B_AMOUNT,
        peer_asa_id=ASA_A,
        peer_asa_amount=ASA_A_AMOUNT,
    )
