# APSigner

APSigner is the interactive admin and approval TUI for `apsigner`. It connects
over local IPC by default and can also connect over the SSH admin subsystem in
remote mode.

## Scope

APSigner is the primary interactive surface for:
- unlock and approval operations
- key generation, import, and deletion
- runtime/admin settings and online guided policy editing
- signer status monitoring

Adjacent tools:
- `appass` manages passphrase auto-unlock configuration offline
- `apstore` handles offline keystore init, backup, restore, verify, and template management
- `apapprover` is the minimal approval-only CLI

## Architecture

```text
apadmin (TUI)
    ↓ line-delimited JSON admin protocol over IPC or SSH admin transport
apsigner (daemon)
    ↓ identity-scoped runtime, approval, key management
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

Remote SSH admin mode:

```bash
./apadmin --remote --client-data /path/to/apclient
```

Policy batch and standalone editor commands:

```bash
./apadmin policy edit
./apadmin policy check
./apadmin policy export > policy.yaml
./apadmin policy apply - < policy.yaml
./apadmin -d /path/to/signer-data policy rescue edit
```

Online policy commands use the same local IPC or `--remote` SSH transport as
the main TUI. They authenticate and unlock before policy access. The explicit
`policy rescue` namespace accesses a stopped signer's store directly and never
falls back from a failed online connection. Run `apadmin policy --help` for all
verbs and stream behavior.

`APSIGNER_DATA` and `APCLIENT_DATA` can be used instead of passing `-d` or
`--client-data`.

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
1. APSigner displays the transaction details.
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

Remote mode reads the client endpoint registry and token from `--client-data`
or `APCLIENT_DATA`. The client must already be enrolled: the endpoint token file
must exist and the signer host must already be trusted in `known_hosts`. Use
standalone `apshell request-token` or `apshell connect` before remote `apadmin`
when setting up a client.

Example remote client endpoint registry:

```yaml
schema_version: 1
default: primary
endpoints:
  primary:
    role: signer
    url: ssh://signer.example.com:1127
    signer_port: 11270
    identity_file: .ssh/id_ed25519
    known_hosts_path: .ssh/known_hosts
    token_file: aplane.token
```

## Backup and Restore

For local managed backup, restore, export, and verification operations, use the
standalone `apstore` CLI tool on the signer host:

```bash
./apstore -d /path/to/signer-data backup create all
./apstore -d /path/to/signer-data backup list
./apstore -d /path/to/signer-data backup export aplane-backup-YYYYMMDD-HHMMSS.tar.gz /mnt/usb
./apstore -d /path/to/signer-data backup import /mnt/usb/aplane-backup.tar.gz
./apstore -d /path/to/signer-data restore preview aplane-backup.tar.gz
./apstore -d /path/to/signer-data restore apply aplane-backup.tar.gz
./apstore -d /path/to/signer-data restore rollback
./apstore -d /path/to/signer-data restore reconcile
./apstore -d /path/to/signer-data verify /mnt/usb/aplane-backup.tar.gz
```

For a live signer-managed backup, unlock the signer, open the admin/settings
panel, choose `Create backup`, and enter an export passphrase. `apsigner`
writes the resulting archive on the signer host under
`backups/<identity>/aplane-backup-YYYYMMDD-HHMMSS.tar.gz` beneath the signer
data root.

For a live signer-managed restore, unlock the signer, open the admin/settings
panel, choose `Restore backup` or press `o`, select a managed archive, enter
the archive export passphrase, preview the contained keys, select keys to
restore, then confirm the direct restore. Enable replacement only for listed
destination conflicts you intend to replace. The complete archive is
authenticated and validated before one generation commits the credentials;
there is no recovered-batch or source-policy review step. Restored credentials
use the destination's current policy and configuration.

`apadmin` does not verify backups or restore arbitrary external paths. Use
`apstore` for verification, direct restore/rollback/reconciliation, and the
separate absent-store `rebuild` rescue path.

See `apstore --help` for more options.

## See Also

- `docs/USER_INSTALL.md` for local and systemd install flows
- `docs/USER_CONFIG.md` for client and signer configuration formats
- `appass` for auto-unlock configuration
- `apstore` for offline keystore and template management
