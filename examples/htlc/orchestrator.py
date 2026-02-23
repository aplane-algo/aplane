"""Generic tool-use orchestrator: no protocol knowledge, just an LLM loop."""

import json
import time

from algosdk.v2client import algod

from anthropic import Anthropic, RateLimitError

from prompts import BUYER_PROMPT, SELLER_PROMPT
from state import SwapState, load_state, save_state, state_summary
from htlc_log import log
from tools import TOOL_SCHEMAS, dispatch_tool

ALGOD_URL = "https://testnet-api.algonode.cloud"
MODEL = "claude-haiku-4-5-20251001"
MAX_TOOL_ROUNDS = 15


def _get_current_round() -> int:
    client = algod.AlgodClient("", ALGOD_URL)
    return client.status().get("last-round", 0)


def run(role: str, my_address: str, peer_address: str, state_path: str,
        my_asa_id: int = 0, my_asa_amount: int = 0,
        peer_asa_id: int = 0, peer_asa_amount: int = 0):
    """Run the orchestrator for the given role."""
    anthropic = Anthropic()

    # Load or create state
    state = load_state(state_path)
    if state is None:
        state = SwapState(
            role=role,
            my_address=my_address,
            peer_address=peer_address,
            my_asa_id=my_asa_id,
            my_asa_amount=my_asa_amount,
            peer_asa_id=peer_asa_id,
            peer_asa_amount=peer_asa_amount,
            fund_algo_amount=300000,
            last_seen_round=_get_current_round(),
        )
        save_state(state, state_path)

    print(f"=== HTLC Swap Orchestrator ({role}) ===")
    print(f"  My address:   {my_address}")
    print(f"  Peer address: {peer_address}")
    print(f"  I offer:      ASA {state.my_asa_id} amount {state.my_asa_amount}")
    print(f"  Peer offers:  ASA {state.peer_asa_id} amount {state.peer_asa_amount}")
    print()
    tag = my_address[:4]
    log(tag, f"Started {role} — offering ASA {state.my_asa_id} (amount {state.my_asa_amount})")

    # Select system prompt (only role-aware line)
    fmt = dict(
        my_address=state.my_address,
        peer_address=state.peer_address,
        my_asa_id=state.my_asa_id,
        my_asa_amount=state.my_asa_amount,
        peer_asa_id=state.peer_asa_id,
        peer_asa_amount=state.peer_asa_amount,
    )
    if role == "buyer":
        system = BUYER_PROMPT.format(**fmt)
    else:
        system = SELLER_PROMPT.format(**fmt)

    # Initial user message
    messages = [{"role": "user", "content": (
        f"Current swap state:\n{state_summary(state)}\n\n"
        "Begin the swap protocol."
    )}]

    # Generic tool-use loop
    for round_num in range(MAX_TOOL_ROUNDS):
        print(f"  LLM call {round_num + 1}...")
        for attempt in range(5):
            try:
                response = anthropic.messages.create(
                    model=MODEL,
                    max_tokens=2048,
                    system=system,
                    tools=TOOL_SCHEMAS,
                    messages=messages,
                )
                break
            except RateLimitError:
                wait = 2 ** attempt * 10  # 10, 20, 40, 80, 160s
                print(f"    Rate limited, retrying in {wait}s...")
                time.sleep(wait)
        else:
            print("  Rate limit exceeded after retries — stopping.")
            break

        assistant_content = response.content
        messages.append({"role": "assistant", "content": assistant_content})

        for block in assistant_content:
            if hasattr(block, "text") and block.text:
                print(f"  LLM: {block.text}")

        tool_uses = [b for b in assistant_content if b.type == "tool_use"]
        if not tool_uses:
            break

        tool_results = []
        for tu in tool_uses:
            print(f"    Tool: {tu.name}({json.dumps(tu.input)})")
            try:
                result = dispatch_tool(tu.name, tu.input, state)
                result_str = json.dumps(result)
                print(f"    Result: {result_str}")
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": tu.id,
                    "content": result_str,
                })
            except Exception as e:
                print(f"    Error: {e}")
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": tu.id,
                    "content": json.dumps({"error": str(e)}),
                    "is_error": True,
                })
            save_state(state, state_path)

        messages.append({"role": "user", "content": tool_results})

        if state.status == "complete":
            break

    if state.status == "complete":
        print("\nSwap complete!")
        log(tag, "Swap complete")
    else:
        print(f"\nStopped (status={state.status})")
        log(tag, f"Stopped (status={state.status})")

