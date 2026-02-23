#!/usr/bin/env python3
"""Launch the HTLC swap buyer agent."""

import os
import sys

# Ensure aplane SDK is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "sdk", "python"))

from config import BUYER, SELLER, ASA_A, ASA_A_AMOUNT, ASA_B, ASA_B_AMOUNT
from htlc_log import LOG_PATH
from orchestrator import run

STATE_FILE = os.path.join(os.path.dirname(__file__), "state_buyer.json")

if __name__ == "__main__":
    # Clean slate: remove previous state and log
    if os.path.exists(STATE_FILE):
        os.remove(STATE_FILE)
    if os.path.exists(LOG_PATH):
        os.remove(LOG_PATH)

    run(
        role="buyer",
        my_address=BUYER,
        peer_address=SELLER,
        state_path=STATE_FILE,
        my_asa_id=ASA_A,
        my_asa_amount=ASA_A_AMOUNT,
        peer_asa_id=ASA_B,
        peer_asa_amount=ASA_B_AMOUNT,
    )
