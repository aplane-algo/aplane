"""Shared append-only log for unified HTLC swap timeline."""

import os
import time

LOG_PATH = os.path.join(os.path.dirname(__file__), "htlc_swap.log")


def log(tag: str, message: str):
    """Append a timestamped entry to the shared log file.

    Args:
        tag: Short identifier, e.g. first 4 chars of the address.
        message: Action description.
    """
    ts = time.strftime("%H:%M:%S")
    line = f"{ts} {tag}: {message}\n"
    with open(LOG_PATH, "a") as f:
        f.write(line)
