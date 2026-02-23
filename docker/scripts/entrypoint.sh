#!/bin/bash
set -e

# Set terminal type and locale for TUI apps and Unicode support
export TERM=xterm-256color
export LANG=C.UTF-8
export LC_ALL=C.UTF-8
export CHARSET=UTF-8

# Start apsignerd in background (uses APSIGNER_DATA=/root/apsigner from Dockerfile ENV)
apsignerd > /tmp/apsignerd.log 2>&1 &
sleep 2

# Launch tmux with UTF-8 support (-u flag)
# apshell and apadmin use APCLIENT_DATA and APSIGNER_DATA env vars from Dockerfile
exec tmux -u new-session -s playground \; \
    send-keys '/usr/local/bin/welcome.sh && cd /root/apshell && apshell' Enter \; \
    split-window -h -p 50 \; \
    send-keys 'tail -f /tmp/apsignerd.log' Enter \; \
    split-window -v -p 75 \; \
    send-keys 'apadmin' Enter \; \
    select-pane -t 2
