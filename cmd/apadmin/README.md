# ApAdmin

ApAdmin is a Terminal User Interface (TUI) tool for administering Signer servers. It provides a visual interface for managing cryptographic keys, unlocking the signer, and approving signing requests.

## Security Model

**🔒 ApAdmin is the ONLY tool for key lifecycle management and signer unlocking.**

### Architecture

```
apadmin (TUI tool)
    ↓ WebSocket connection
Signer (daemon)
    ↓ file watching (fsnotify)
users/ directory
    ↓ SSH tunnel / HTTPS
apshell (remote signing client)
```

ApAdmin connects to Signer via WebSocket to:
- Unlock the signer with passphrase
- Approve signing requests
- Generate, import, export, and delete keys
- Monitor signer status

The `apshell` client can only:
- List available keys (read-only via Signer)
- Request signatures for transactions
- Manage local aliases and caches

## Building

```bash
go build -o apadmin ./cmd/apadmin
```

## Usage

Start the TUI (connects to Signer automatically):

```bash
./apadmin
```

With custom server address:

```bash
./apadmin --server localhost:11270
```

With custom config file:

```bash
./apadmin --config /path/to/config.yaml
```

## TUI Features

### Main Screen
- View all keys loaded in Signer
- See signer lock/unlock status
- Navigate with arrow keys, Enter to select

### Key Management
- **Generate**: Create new Falcon or Ed25519 keys
- **Import**: Import keys from mnemonic phrases
- **Export**: Export mnemonic from existing keys
- **Delete**: Remove keys (moves to deletedkeys/)

### Signer Operations
- **Unlock**: Enter passphrase to unlock the signer 
- **Lock**: Lock the signer (clears passphrase from memory)

### Signing Approvals
When Signer receives a signing request:
1. ApAdmin displays the transaction details
2. User reviews and approves/rejects
3. Response sent back to Signer

## Key Commands

| Key | Action              |
|-----|---------------------|
| `↑/↓` | Navigate list       |
| `Enter` | Select/Confirm      |
| `g` | Generate new key    |
| `i` | Import key          |
| `e` | Export key mnemonic |
| `d` | Delete key          |
| `u` | Unlock signer       |
| `l` | Lock signer         |
| `q` | Quit                |

## Configuration

ApAdmin reads the same `config.yaml` as Signer for the default port:

```json
{
  "signer_port": 11270
}
```

## Backup and Restore

For backup and restore operations, use the standalone `apstore` CLI tool:

```bash
# Backup all keys
./apstore backup all /mnt/usb/backup

# Restore all keys
./apstore restore all /mnt/usb/backup

# Verify backup integrity
./apstore verify /mnt/usb/backup --deep
```

See `apstore --help` for more options.

## See Also

- [Signer](../apsignerd/) - The key management daemon
- [apshell](../apshell/) - Algorand shell tool for transaction operations
- [apstore](../apstore/) - Backup and restore CLI tool
