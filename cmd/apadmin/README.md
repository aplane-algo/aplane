# apadmin

apadmin is the interactive admin and approval TUI for `apsigner`. It connects
over local IPC only, independently of apshell client configuration.

## Scope

apadmin is the primary interactive surface for:
- unlock and approval operations
- key generation, import, and deletion
- runtime/admin settings and online guided policy editing
- signer status monitoring

Adjacent tools:
- `appass` manages passphrase auto-unlock configuration offline
- `apstore` handles stopped-daemon bootstrap, rescue, verification, permission
  migration, and generation pruning
- `apapprover` is the minimal approval-only CLI

## Architecture

```text
apadmin (TUI)
    ↓ line-delimited JSON admin protocol over local IPC
apsigner (daemon)
    ↓ product runtime, approval, key management
signer data directory
```

## Building

```bash
go build -o apadmin ./cmd/apadmin
```

## Usage

Local IPC mode:

```bash
./apadmin -d /path/to/signer-data
```

For remote administration, log in to the signer machine:

```bash
ssh -t user@signer 'apadmin -d /path/to/signer-data'
```

Batch commands use the same local IPC transport as the TUI:

```bash
./apadmin policy edit
./apadmin policy check
./apadmin policy export > policy.yaml
./apadmin policy apply - < policy.yaml
./apadmin -d /path/to/signer-data policy rescue edit
./apadmin backup create all
./apadmin backup export aplane-backup-YYYYMMDD-HHMMSS.tar.gz /mnt/usb
./apadmin restore preview aplane-backup-YYYYMMDD-HHMMSS.tar.gz
./apadmin restore apply aplane-backup-YYYYMMDD-HHMMSS.tar.gz
./apadmin changepass
./apadmin template list
./apadmin keytype enable aplane.falcon1024-sentry1024.v1
./apadmin sentry list
./apadmin endpoint export --out endpoint.json
./apadmin generations list
```

Online policy commands use the same local IPC transport as the main TUI.
They authenticate and unlock before policy access. The explicit `policy rescue`
namespace accesses a stopped signer's store directly and never falls back from
a failed online connection. Run `apadmin policy --help` for verbs and stream behavior.

`APSIGNER_DATA` can be used instead of `-d`; `--ipc-path` selects a socket
explicitly. apadmin does not use `APCLIENT_DATA`, client tokens, or endpoint files.

## TUI Features

### Main Screen
- View keys currently available in the signer
- See signer lock/unlock status
- Review pending approvals and admin state

### Key Management
- **Generate**: Create native keys and template-backed LogicSig types
- **Import**: Import keys from mnemonic phrases
- **Backup**: Create encrypted signer-managed backup archives for recovery
- **Delete**: Remove keys

### Signer Operations
- **Unlock**: Enter passphrase to unlock the signer
- **Approve/Reject**: Review pending requests
- **Settings**: Inspect admin settings, edit the active node-role policy, create signer-managed backups, and restore from managed backup archives for the bound identity

### Signing Approvals
When `apsigner` receives a signing request:
1. apadmin displays the transaction details.
2. The operator reviews and approves or rejects.
3. The response is sent back to `apsigner`.

## Key Commands

| Key | Action |
|-----|--------|
| `↑/↓` | Navigate |
| `Enter` | Select / confirm |
| `g` | Generate new key |
| `i` | Import key |
| `d` | Delete key |
| `u` | Unlock signer |
| `b` | Open backup flow from the settings/admin panel |
| `o` | Open restore flow from the settings/admin panel |
| `p` | Open the policy editor |
| `l` (key list/settings) | Lock signer after confirmation, keeping apadmin open |
| `q` | Quit |

## Configuration

Local mode reads the signer data directory configured by `-d` or
`APSIGNER_DATA`.

## Backup and Restore

For live managed backup and restore operations, use `apadmin` on the signer machine:

```bash
./apadmin -d /path/to/signer-data backup create all
./apadmin -d /path/to/signer-data backup list
./apadmin -d /path/to/signer-data backup export aplane-backup-YYYYMMDD-HHMMSS.tar.gz /mnt/usb
./apadmin -d /path/to/signer-data backup import /mnt/usb/aplane-backup.tar.gz
./apadmin -d /path/to/signer-data restore preview aplane-backup.tar.gz
./apadmin -d /path/to/signer-data restore apply aplane-backup.tar.gz
./apadmin -d /path/to/signer-data restore rollback
./apadmin -d /path/to/signer-data restore reconcile
```

For a live signer-managed backup, unlock the signer, open the admin/settings
panel, choose `Create backup`, and enter an export passphrase. `apsigner`
writes the resulting archive on the signer host under
`backups/default/aplane-backup-YYYYMMDD-HHMMSS.tar.gz` beneath the signer
data root.

For a live signer-managed restore, unlock the signer, open the admin/settings
panel, choose `Restore backup` or press `o`, select a managed archive, enter
the archive export passphrase, preview the contained keys, select keys to
restore, then confirm the direct restore. Enable replacement only for listed
destination conflicts you intend to replace. The complete archive is
authenticated and validated before one generation commits the credentials;
there is no recovered-batch or source-policy review step. Restored credentials
use the destination's current policy and configuration.

`apadmin` imports external archives into the daemon-owned backup locker before
restoring them. It does not perform offline recovery. With the daemon stopped,
use `apstore verify` to inspect an external archive or `apstore rebuild` to
recover an absent product store.

See `docs/USER_STORE_MGMT.md` for the complete live and offline command split.

## See Also

- `docs/USER_INSTALL.md` for local and systemd install flows
- `docs/USER_CONFIG.md` for client and signer configuration formats
- `appass` for auto-unlock configuration
- `apstore` for offline bootstrap, verification, and rescue
