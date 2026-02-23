#!/usr/bin/env bash
# Launch buyer and seller side-by-side in a tmux split.
# Usage: ./run_swap.sh
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SESSION="atomicswap"

# Kill any existing session with the same name
tmux kill-session -t "$SESSION" 2>/dev/null || true

# Left pane: buyer
tmux new-session -d -s "$SESSION" \
    "export PS1='aplane\$ '; printf '\\033]0;aplane swap\\007'; cd '$DIR' && python3 run_buyer.py; exec bash --norc --noprofile"

# Set terminal title (must come after new-session so tmux server exists)
tmux set-option -t "$SESSION" set-titles on
tmux set-option -t "$SESSION" set-titles-string "aplane swap"

# Right pane: seller
tmux split-window -v -t "$SESSION" \
    "export PS1='aplane\$ '; printf '\\033]0;aplane swap\\007'; cd '$DIR' && python3 run_seller.py; exec bash --norc --noprofile"

tmux select-pane -t "$SESSION":0.0
tmux attach -t "$SESSION"
