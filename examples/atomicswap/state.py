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

    # ASA swap details (each side offers a different ASA)
    my_asa_id: int = 0          # ASA ID I'm offering
    my_asa_amount: int = 0      # base units of my ASA
    peer_asa_id: int = 0        # ASA ID peer is offering
    peer_asa_amount: int = 0    # base units of peer's ASA

    # Atomic group tracking
    group_txid: str = ""

    # Box storage for exchange data
    swap_app_id: int = 0
    swap_box_name: str = ""

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
    my_label = "ALGO" if state.my_asa_id == 0 else f"ASA {state.my_asa_id}"
    peer_label = "ALGO" if state.peer_asa_id == 0 else f"ASA {state.peer_asa_id}"
    lines = [
        f"Role: {state.role}",
        f"Status: {state.status}",
        f"My address: {state.my_address}",
        f"Peer address: {state.peer_address}",
        f"I offer: {my_label} amount={state.my_asa_amount}",
        f"Peer offers: {peer_label} amount={state.peer_asa_amount}",
    ]
    if state.group_txid:
        lines.append(f"Group txid: {state.group_txid}")
    if state.actions:
        lines.append("\nAction history:")
        for a in state.actions:
            lines.append(f"  - {a}")
    return "\n".join(lines)
