# Linux Production Installation

This guide covers installing apsignerd as a systemd service on Linux. It uses `systemd-creds` (TPM2/host key) to encrypt the keystore passphrase at rest, and systemd's `LoadCredentialEncrypted` to inject it at service start.

**Requirements:** Linux with systemd 250+ (Ubuntu 24.04+, Debian 12+, RHEL/Rocky 9+, Fedora 36+). macOS users should run apsignerd directly.

## Table of Contents

- [Install from Release Tarball](#install-from-release-tarball)
- [Quick Start](#quick-start)
- [Prerequisites](#prerequisites)
- [Step 1: Build](#step-1-build)
- [Step 2: Install Binaries](#step-2-install-binaries)
- [Step 3: Create Service User](#step-3-create-service-user)
- [Step 4: Install the systemd Service](#step-4-install-the-systemd-service)
- [Step 5: Initialize the Keystore](#step-5-initialize-the-keystore)
- [Step 6: Enable and Start](#step-6-enable-and-start)
- [Managing the Service](#managing-the-service)
- [Multiple Instances](#multiple-instances)
- [Installer Files Reference](#installer-files-reference)
- [How Passphrase Encryption Works](#how-passphrase-encryption-works)
- [Changing the Passphrase](#changing-the-passphrase)
- [Migrating to a New Machine](#migrating-to-a-new-machine)
- [Uninstalling](#uninstalling)
- [Troubleshooting](#troubleshooting)

---

## Install from Release Tarball

The easiest way to install — no build tools required. Download a release tarball from GitHub:

```bash
# Download and extract
tar xzf aplane_*_linux_amd64.tar.gz
cd aplane

# Install (creates user, copies binaries, sets up systemd, writes config, initializes keystore if needed)
sudo ./install.sh aplane aplane

# Enable and start
sudo systemctl enable aplane@$(systemd-escape /var/lib/aplane)
sudo systemctl start aplane@$(systemd-escape /var/lib/aplane)
```

The tarball contains:

```
aplane/
├── bin/            # All binaries (apsignerd, apshell, apadmin, etc.)
├── installer/      # systemd unit files and sudoers template
├── scripts/        # systemd-setup.sh and init-signer.sh
└── install.sh      # Convenience wrapper (copies binaries, runs systemd setup, writes config, initializes keystore)
```

`install.sh` accepts an optional third argument for the install directory (default: `/usr/local/bin`):

```bash
sudo ./install.sh aplane aplane /opt/aplane/bin
```

Re-running `install.sh` is safe:

- Existing `config.yaml` is left unchanged
- A canonical template is written to `config.yaml.aplane-installer.new`
- Keystore init is skipped if `.keystore` already exists

---

## Quick Start

For the impatient — build from source and install at `/var/lib/aplane` as the `aplane` user:

```bash
# Build
make all

# Install binaries
sudo cp bin/apsignerd bin/pass-systemd-creds bin/apstore bin/apadmin /usr/local/bin/
sudo chmod 755 /usr/local/bin/pass-systemd-creds

# Create service user
sudo useradd -r -m -d /var/lib/aplane -s /usr/sbin/nologin aplane

# Install systemd service and sudoers
sudo ./scripts/systemd-setup.sh aplane aplane /usr/local/bin

# Write signer config (required before keystore init)
sudo -u aplane tee /var/lib/aplane/config.yaml <<'EOF'
store: /var/lib/aplane/store
passphrase_command_argv: ["/usr/local/bin/pass-systemd-creds", "passphrase.cred"]
passphrase_timeout: "0"
lock_on_disconnect: false
EOF

# Initialize keystore with TPM2-encrypted passphrase
sudo ./scripts/init-signer.sh /var/lib/aplane aplane:aplane

# Enable and start
sudo systemctl enable aplane@$(systemd-escape /var/lib/aplane)
sudo systemctl start aplane@$(systemd-escape /var/lib/aplane)
```

The rest of this guide explains each step in detail.

---

## Prerequisites

1. **systemd 250+** — verify with:
   ```bash
   systemctl --version
   ```

2. **TPM2 support** (recommended but optional — systemd-creds falls back to the host key):
   ```bash
   systemd-creds has-tpm2
   # "yes" means TPM2 is available; "no" means host-key-only fallback
   ```

3. **Build tools** — Go 1.22+ and musl-tools. See [DEV_BUILD.md](DEV_BUILD.md) for full build prerequisites.

---

## Step 1: Build

```bash
make all
```

This produces statically linked binaries in `bin/`:

| Binary | Purpose |
|--------|---------|
| `apsignerd` | Signing server |
| `pass-systemd-creds` | Passphrase encryption helper (TPM2/host key) |
| `apstore` | Keystore init, backup, restore, passphrase change |
| `apadmin` | Key generation and management (TUI and batch) |
| `apapprover` | Signing approval interface |
| `apshell` | Transaction shell (client) |

---

## Step 2: Install Binaries

Copy the server-side binaries to a system path:

```bash
sudo cp bin/apsignerd bin/pass-systemd-creds bin/apstore bin/apadmin /usr/local/bin/
sudo chmod 755 /usr/local/bin/pass-systemd-creds
```

Or keep them in a custom directory — `systemd-setup.sh` accepts a `bindir` argument (see Step 4).

---

## Step 3: Create Service User

Create a dedicated system user with no login shell:

```bash
sudo useradd -r -m -d /var/lib/aplane -s /usr/sbin/nologin aplane
```

This creates the `aplane` user and group with home directory `/var/lib/aplane`.

To use an existing user instead, skip this step and substitute your username in the following steps.

---

## Step 4: Install the systemd Service

The setup script installs a systemd **template** service (`aplane@.service`) that can manage instances for different data directories using systemd's `%I` specifier.

```bash
sudo ./scripts/systemd-setup.sh <username> <group> [bindir]
```

**Arguments:**

| Argument | Description | Default |
|----------|-------------|---------|
| `username` | User to run apsignerd as | (required) |
| `group` | Group to run apsignerd as | (required) |
| `bindir` | Directory containing the apsignerd binary | `../bin` relative to the script |

**Example with default bindir** (binaries in `./bin/`):

```bash
sudo ./scripts/systemd-setup.sh aplane aplane
```

**Example with custom bindir** (binaries in `/usr/local/bin/`):

```bash
sudo ./scripts/systemd-setup.sh aplane aplane /usr/local/bin
```

This installs:

- `/lib/systemd/system/aplane@.service` — the template unit file
- `/etc/sudoers.d/99-aplane-systemctl` — allows the service user to start/stop/restart without a password

---

## Step 5: Initialize the Keystore

Before initializing, create `/var/lib/aplane/config.yaml`:

```yaml
store: /var/lib/aplane/store

# Passphrase helper: reads from systemd credential directory at runtime
passphrase_command_argv: ["/usr/local/bin/pass-systemd-creds", "passphrase.cred"]

# Headless mode requires no auto-lock timeout
passphrase_timeout: "0"
lock_on_disconnect: false
```

If you installed binaries in a custom bindir, set that absolute path in `passphrase_command_argv[0]`.

Then run the init script:

```bash
sudo ./scripts/init-signer.sh /var/lib/aplane aplane:aplane
```

This creates:
- `/var/lib/aplane/store/` — keystore directory (owned by `aplane:aplane`)
- `/var/lib/aplane/passphrase.cred` — TPM2-encrypted passphrase (owned by `root`)

The `passphrase.cred` file is root-owned because `systemd-creds encrypt` requires root. systemd decrypts it at service start via `LoadCredentialEncrypted` — apsignerd itself never needs root access.

See [USER_CONFIG.md](USER_CONFIG.md#headless-operation) for additional configuration options (auto-approve policies, network settings, etc.).

---

## Step 6: Enable and Start

systemd template instances use `systemd-escape` to encode the data directory path:

```bash
# Enable on boot
sudo systemctl enable aplane@$(systemd-escape /var/lib/aplane)

# Start now
sudo systemctl start aplane@$(systemd-escape /var/lib/aplane)
```

Check status:

```bash
systemctl status aplane@$(systemd-escape /var/lib/aplane)
```

View logs:

```bash
journalctl -u aplane@$(systemd-escape /var/lib/aplane) -f
```

---

## Managing the Service

With the sudoers rules installed, the `aplane` user can manage the service without `sudo`:

```bash
# As the aplane user (or via sudo -u aplane)
systemctl status aplane@$(systemd-escape /var/lib/aplane)
sudo systemctl restart aplane@$(systemd-escape /var/lib/aplane)
sudo systemctl stop aplane@$(systemd-escape /var/lib/aplane)
```

### Generate Keys

Use `apadmin` to generate signing keys:

```bash
# TUI mode
sudo -u aplane apadmin -d /var/lib/aplane

# Batch mode
sudo -u aplane apadmin -d /var/lib/aplane --batch generate falcon1024-v1
```

apsignerd auto-detects new keys via file watching — no restart needed.

### Backup Keys

```bash
sudo -u aplane apstore -d /var/lib/aplane backup all /mnt/usb/backup
```

See [USER_STORE_MGMT.md](USER_STORE_MGMT.md) for full backup/restore documentation.

---

## Multiple Instances

The template service supports multiple apsignerd instances on the same machine, each with a different data directory:

```bash
# Create a second data directory
sudo mkdir -p /var/lib/aplane-staging
sudo chown aplane:aplane /var/lib/aplane-staging

# Initialize it
sudo ./scripts/init-signer.sh /var/lib/aplane-staging aplane:aplane

# Configure it (copy and edit config.yaml)
sudo -u aplane cp /var/lib/aplane/config.yaml /var/lib/aplane-staging/config.yaml

# Enable and start
sudo systemctl enable aplane@$(systemd-escape /var/lib/aplane-staging)
sudo systemctl start aplane@$(systemd-escape /var/lib/aplane-staging)
```

Each instance runs independently with its own keystore, configuration, and IPC socket.

---

## Installer Files Reference

The `installer/` directory contains service files for different deployment scenarios:

| File | Use Case |
|------|----------|
| `installer/aplane.service` | Static single-instance service. Hardcoded for `/var/lib/aplane` as `aplane:aplane`. Copy directly to `/etc/systemd/system/` for the simplest possible setup. |
| `installer/aplane@.service` | Template multi-instance service. Uses `%I` for the data directory path. Hardcoded for `aplane:aplane` with binaries in `/usr/local/bin/`. Copy directly to `/lib/systemd/system/` if defaults match your setup. |
| `installer/aplane@.service.template` | Template with `@@BINDIR@@`, `@@USER@@`, `@@GROUP@@` placeholders. Used by `scripts/systemd-setup.sh` for customizable installs. |
| `installer/sudoers.template` | sudoers rules with `@@USER@@` placeholder. Allows the service user to manage `aplane@*` services without a password. Covers both `/bin/systemctl` (Ubuntu) and `/usr/bin/systemctl` (RHEL/CentOS) paths. |

### Manual Installation (Without the Setup Script)

If you prefer not to use `systemd-setup.sh`, you can install the pre-built files directly:

**Option A: Static service** (single instance at `/var/lib/aplane`):

```bash
sudo cp installer/aplane.service /etc/systemd/system/aplane.service
sudo systemctl daemon-reload
sudo systemctl enable aplane
sudo systemctl start aplane
```

**Option B: Template service** (multi-instance, default user/bindir):

```bash
sudo cp installer/aplane@.service /lib/systemd/system/aplane@.service
sudo systemctl daemon-reload
sudo systemctl enable aplane@$(systemd-escape /var/lib/aplane)
sudo systemctl start aplane@$(systemd-escape /var/lib/aplane)
```

---

## How Passphrase Encryption Works

The passphrase flow uses three components working together:

```
┌──────────────────────────────────────────────────────────────────────────┐
│                          One-Time Setup                                  │
│                                                                          │
│  apstore init --random                                                   │
│       │                                                                  │
│       ├─► generates random passphrase                                    │
│       ├─► creates keystore (Argon2id-derived master key)                 │
│       └─► calls pass-systemd-creds write passphrase.cred                │
│                  │                                                        │
│                  └─► systemd-creds encrypt ──► passphrase.cred (on disk) │
│                      (TPM2 / host key)                                   │
└──────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────┐
│                        Every Service Start                               │
│                                                                          │
│  systemd reads unit file:                                                │
│    LoadCredentialEncrypted=aplane-passphrase:passphrase.cred             │
│       │                                                                  │
│       └─► decrypts passphrase.cred ──► tmpfs: $CREDENTIALS_DIRECTORY/    │
│           (TPM2 / host key)                   aplane-passphrase          │
│                                                                          │
│  apsignerd starts:                                                       │
│    passphrase_command_argv: ["/usr/local/bin/pass-systemd-creds",         │
│                               "passphrase.cred"]                           │
│       │                                                                  │
│       └─► pass-systemd-creds read                                        │
│              │                                                           │
│              └─► reads $CREDENTIALS_DIRECTORY/aplane-passphrase          │
│                  (plaintext in tmpfs, no root needed)                     │
│                                                                          │
│  apsignerd unlocks keystore with passphrase ──► ready to sign            │
└──────────────────────────────────────────────────────────────────────────┘
```

**Key security properties:**

- The passphrase is encrypted at rest on disk (bound to this machine's TPM2/host key)
- systemd decrypts it into a tmpfs that only the service process can read
- apsignerd runs as an unprivileged user — never needs root
- The `passphrase.cred` file is useless on any other machine

---

## Changing the Passphrase

To rotate the keystore passphrase:

```bash
sudo apstore -d /var/lib/aplane changepass --random
```

This atomically re-encrypts all keys with a new random passphrase and updates `passphrase.cred`. Restart the service afterward:

```bash
sudo systemctl restart aplane@$(systemd-escape /var/lib/aplane)
```

---

## Migrating to a New Machine

The TPM2-encrypted `passphrase.cred` is bound to the original machine and cannot be decrypted elsewhere. To migrate:

1. **On the old machine** — create a backup:
   ```bash
   sudo -u aplane apstore -d /var/lib/aplane backup all /mnt/usb/backup
   ```

2. **On the new machine** — install apsignerd (Steps 1–4 above), then restore:
   ```bash
   sudo -u aplane apstore -d /var/lib/aplane restore all /mnt/usb/backup
   ```

3. **On the new machine** — initialize a new passphrase credential:
   ```bash
   sudo ./scripts/init-signer.sh /var/lib/aplane aplane:aplane
   ```

4. Enable and start the service (Step 6).

---

## Uninstalling

```bash
# Stop and disable
sudo systemctl stop aplane@$(systemd-escape /var/lib/aplane)
sudo systemctl disable aplane@$(systemd-escape /var/lib/aplane)

# Remove service and sudoers
sudo rm /lib/systemd/system/aplane@.service
sudo rm /etc/sudoers.d/99-aplane-systemctl
sudo systemctl daemon-reload

# Remove binaries
sudo rm /usr/local/bin/apsignerd /usr/local/bin/pass-systemd-creds \
       /usr/local/bin/apstore /usr/local/bin/apadmin

# Remove data (CAUTION: this deletes all keys!)
# sudo userdel -r aplane
```

---

## Troubleshooting

### Service fails to start

Check the journal:

```bash
journalctl -u aplane@$(systemd-escape /var/lib/aplane) --no-pager -n 50
```

### "LoadCredentialEncrypted failed"

The `passphrase.cred` file may be missing or corrupted:

```bash
ls -la /var/lib/aplane/passphrase.cred
```

Re-initialize if needed:

```bash
sudo ./scripts/init-signer.sh /var/lib/aplane aplane:aplane
```

### "AssertPathExists failed"

The data directory doesn't exist. Create it:

```bash
sudo mkdir -p /var/lib/aplane
sudo chown aplane:aplane /var/lib/aplane
```

### Permission denied on IPC socket

The IPC socket is created in the data directory. Ensure the directory is owned by the service user:

```bash
sudo chown aplane:aplane /var/lib/aplane
```

### systemd-creds not found

Your systemd version is too old. Check with `systemctl --version`. You need systemd 250+.

### No TPM2

`systemd-creds` will fall back to the host key automatically. The passphrase is still encrypted at rest, but the protection is weaker — anyone who can read the host key and the credential file can decrypt the passphrase. For stronger protection, use a machine with a TPM2 chip.

---

## Related Documentation

- [DEV_BUILD.md](DEV_BUILD.md) — Build instructions and prerequisites
- [USER_CONFIG.md](USER_CONFIG.md) — Full configuration reference (headless mode, approval policies)
- [USER_STORE_MGMT.md](USER_STORE_MGMT.md) — Key backup, restore, and passphrase management
- [ARCH_SECURITY.md](ARCH_SECURITY.md) — Security architecture (pass-systemd-creds protocol details)
