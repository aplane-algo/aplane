"""Swap state dataclass with JSON persistence."""

import json
import os
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class SwapState:
    role: str  # "buyer" or "seller"
    status: str = "pending"
    my_address: str = ""
    peer_address: str = ""

    # Preimage/hash
    preimage: str = ""   # hex, buyer only until revealed
    hash: str = ""       # hex, both parties know

    # Hashlock addresses
    my_hashlock: str = ""    # the hashlock I created
    peer_hashlock: str = ""  # the hashlock they created

    # Timeouts
    my_timeout: int = 0
    peer_timeout: int = 0

    # ASA swap details (each side offers a different ASA)
    my_asa_id: int = 0          # ASA ID I'm offering
    my_asa_amount: int = 0      # base units of my ASA
    peer_asa_id: int = 0        # ASA ID peer is offering
    peer_asa_amount: int = 0    # base units of peer's ASA

    # ALGO for hashlock minimum balance (covers account + 1 ASA opt-in)
    fund_algo_amount: int = 300000  # 0.3 ALGO

    # Transaction tracking
    claim_txid: str = ""

    # Dedup
    seen_txids: List[str] = field(default_factory=list)
    last_seen_round: int = 0

    # Action history
    actions: List[str] = field(default_factory=list)


def save_state(state: SwapState, path: str):
    with open(path, "w") as f:
        json.dump(state.__dict__, f, indent=2)


def load_state(path: str) -> Optional[SwapState]:
    if not os.path.exists(path):
        return None
    with open(path, "r") as f:
        data = json.load(f)
    state = SwapState(role=data["role"])
    for k, v in data.items():
        setattr(state, k, v)
    return state


def state_summary(state: SwapState) -> str:
    """Format state as a concise string for LLM context."""
    lines = [
        f"Role: {state.role}",
        f"Status: {state.status}",
        f"My address: {state.my_address}",
        f"Peer address: {state.peer_address}",
        f"My ASA: {state.my_asa_id} amount={state.my_asa_amount}",
        f"Peer ASA: {state.peer_asa_id} amount={state.peer_asa_amount}",
    ]
    if state.hash:
        lines.append(f"Hash (SHA256): {state.hash}")
    if state.preimage:
        lines.append(f"Preimage (hex): {state.preimage}")
    if state.my_hashlock:
        lines.append(f"My hashlock address: {state.my_hashlock}")
    if state.peer_hashlock:
        lines.append(f"Peer hashlock address: {state.peer_hashlock}")
    if state.my_timeout:
        lines.append(f"My hashlock timeout: round {state.my_timeout}")
    if state.peer_timeout:
        lines.append(f"Peer hashlock timeout: round {state.peer_timeout}")
    if state.claim_txid:
        lines.append(f"Claim txid: {state.claim_txid}")
    if state.actions:
        lines.append("\nAction history:")
        for a in state.actions:
            lines.append(f"  - {a}")
    return "\n".join(lines)
