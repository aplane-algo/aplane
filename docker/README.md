# aPlane Docker Playground

A containerized demo environment for aPlane.

## Quick Start

```bash
# Pull from Docker Hub
docker run -it makman568/ap-play

# Or build locally
docker build -t ap-play -f docker/Dockerfile .
docker run -it ap-play
```

## What You'll See

A tmux session with three panes:
- **Left**: apshell client shell
- **Top-right**: apsignerd server logs
- **Bottom-right**: apadmin TUI for approving transactions

## Navigation

- `Ctrl+B` then arrow keys to switch panes
- `Ctrl+B` then `d` to detach
- Type `exit` or `Ctrl+D` to quit

## Demo Flow

1. Generate a key: `generate falcon`
2. View your keys: `keys`
3. Fund your key via testnet dispenser (external)
4. Send a transaction: `send 1 to <address>`
5. Switch to apadmin pane and approve

## Notes

- Uses Algorand TestNet
- Keys are ephemeral (lost when container stops)
- Passphrase is pre-set to "playground" for demo purposes
