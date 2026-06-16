# Installation Guide

APlane supports three install modes:

| Mode | Command | Use Case |
|------|---------|----------|
| **Local** (default) | `./install.sh [--role signer\|sentry] [path]` | Development, demos, multi-instance. Rootless by default, no systemd. |
| **Client-only** | `./install.sh --client` | apshell only, connects to a remote signer. |
| **Systemd** | `sudo ./install.sh --systemd [--role signer\|sentry] [operator-root] [--bindir <path>] [--no-enable] [--no-start]` | systemd service for production servers. |

**Requirements:** Linux with systemd for `--systemd` mode. Auto-unlock requires systemd 250+ (Ubuntu 24.04+, Debian 12+, RHEL/Rocky 9+, Fedora 36+). Local and `--client` modes work on both Linux and macOS.

**Optional `--systemd` flags:**

| Flag | Description |
|------|-------------|
| `--bindir <path>` | Install binaries into `<path>` instead of `/usr/local/bin`. |
| `--no-enable` | Skip `systemctl enable apsigner` so the service does not start on boot. |
| `--no-start` | Skip `systemctl start apsigner` so the service is installed but not started. |

**Node role:** local and systemd installs default to `--role signer`. Use
`--role sentry` only for a dedicated sentry data root. Node roles are
immutable; create separate top-level roots for signer and sentry nodes.

**Environment defaults:** `APLANE_INSTALL_ROOT` supplies the optional
`[path]` / `[operator-root]` argument when it is omitted. `APLANE_BINDIR`
supplies the default `--systemd --bindir` value when `--bindir` is omitted.
Command-line arguments take precedence over environment variables, and
environment variables take precedence over prompts/defaults.
Installer-generated `apenv.sh` files export `APLANE_INSTALL_ROOT`; systemd
operator `apenv.sh` also exports `APLANE_BINDIR`.
The bootstrap wrapper also accepts `APLANE_VERSION`,
`APLANE_ENABLE_SERVICE`, `APLANE_START_SERVICE`, and
`APLANE_REQUIRE_MINISIGN`; older `APSIGNER_*` names remain accepted as
compatibility aliases.

## Table of Contents

- [Local Install (Default)](#local-install-default)
- [Install via curl Bootstrap](#install-via-curl-bootstrap)
- [Upgrading](#upgrading)
- [Client-Only Install (apshell)](#client-only-install-apshell)
- [Install from Release Tarball](#install-from-release-tarball)
- [Systemd Install](#systemd-install)
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
- [Identity Runtime Layout](#identity-runtime-layout)
- [Installer Files Reference](#installer-files-reference)
- [How Passphrase Encryption Works](#how-passphrase-encryption-works)
- [Changing the Passphrase](#changing-the-passphrase)
- [Migrating to a New Machine](#migrating-to-a-new-machine)
- [Uninstalling](#uninstalling)
- [Troubleshooting](#troubleshooting)

---

## Local Install (Default)

Local mode installs both the signer and client into a single directory under the current user — no systemd, no system users, and no root unless you opt into Linux memory locking. This is the default when running `install.sh` without flags.

```bash
# Install to ~/aplane (default)
./install.sh

# Install to a custom path
./install.sh /path/to/my/aplane

# Install a dedicated local sentry node
./install.sh --role sentry ~/aplane-sentry

# Equivalent custom path via environment
APLANE_INSTALL_ROOT=/path/to/my/aplane ./install.sh
```

### What gets created

```
<install-path>/
├── apsigner/             # Signer data directory ($APSIGNER_DATA)
│   ├── bin/               # apsigner, apadmin, apapprover, apstore, appolicy, appass, approbe, and other signer-side tools
│   ├── config.yaml        # Signer config (ports, SSH, algod)
│   ├── library/           # KeyType Library install sources
│   │   └── templates/     # Template YAML files for defaults and apstore imports
│   ├── .ssh/              # SSH host key and legacy/global authorized_keys
│   └── identities/default/ # Keystore (created during install)
│       ├── .keystore
│       └── .ssh/          # Identity-scoped authorized_keys after token enrollment
├── apclient/              # Client data directory ($APCLIENT_DATA)
│   ├── bin/               # apshell
│   ├── config.yaml        # Client config (network and UI defaults)
│   ├── endpoints.yaml     # Client endpoint registry
│   ├── .mcp.json          # MCP client config for apshell --mcp
│   ├── .codex/config.toml # Codex project MCP config for apshell --mcp
│   ├── plugins.yaml       # Enabled plugin names
│   ├── plugins.available/  # Installed plugin catalog entries
│   └── scripts/           # Saved JavaScript/MCP snippets
├── apconsole.yaml         # Console profile (mode and relative data paths)
├── apenv.sh               # Environment file (PATH, APLANE_INSTALL_ROOT, APSIGNER_DATA, APCLIENT_DATA)
└── start.sh               # Unified console launcher (apconsole)
```

### Ports

Each local install selects **random available ports** in the dynamic range (49152–65535) for both the signer REST API and the SSH tunnel. This allows multiple independent APlane instances on the same machine without port conflicts. The selected ports are written into `apsigner/config.yaml` and the primary signer record in `apclient/endpoints.yaml`.

For `--role sentry`, the selected ports are written into `apsigner/config.yaml`
and an `apclient/endpoints.yaml` `local-sentry` endpoint. The generated
endpoint registry intentionally has no default signer endpoint.

### Confirmation prompt

Before creating any files, the installer displays a summary and asks for confirmation:

```
=== apsigner installer (local mode) ===

  Mode:        fresh install
  Node role:   signer
  Install to:  /home/user/aplane
  Signer:      /home/user/aplane/apsigner
  Client:      /home/user/aplane/apclient
  Signer port: 52847
  SSH port:    61203

Proceed with installation? [Y/n]
```

On Linux local installs, the installer also asks whether to enable enforced
memory locking for `apsigner`. If you accept, it uses `sudo setcap
cap_ipc_lock+ep` on the installed `apsigner` binary and writes
`require_memory_protection: true` so startup fails if memory locking is not
available. macOS does not use Linux capabilities, so this prompt is skipped.

### Keystore initialization

The installer runs `apstore initialize --role <role>` locally before first node
startup to create the keystore. You'll be prompted to set a passphrase. This
passphrase is needed each time you unlock the signer or sentry via `apadmin`.

### Environment setup

The installer creates `apenv.sh` and optionally adds it to your shell rc file (`.bashrc` or `.zshrc`). Source it to set up your environment:

```bash
source /path/to/aplane/apenv.sh
```

This adds the binary directories to `PATH` and exports
`APLANE_INSTALL_ROOT`, `APSIGNER_DATA`, and `APCLIENT_DATA`.

### Starting the system

The installer-generated launcher loads the environment for this install and
starts the unified console:

```bash
cd /path/to/aplane
./start.sh
```

For local signer nodes, this opens shell, signer admin, and daemon panes in one
Bubble Tea console while preserving the same apshell, apadmin, and apsigner
transport interfaces. Unlock the signer pane, then run `request-token` in the
shell pane. Local `apconsole` probes the live loopback SSH endpoint before
pinning the local signer's SSH host key into the client `known_hosts` file.
Approve the request in the signer pane; that first enrollment writes
`aplane.token` into the client data directory and the shell immediately attempts
to connect.

For local sentry nodes, `apconsole` shows the sentry admin pane and daemon pane
only. Unlock the sentry in that console, then open another terminal, source the
install's `apenv.sh`, start `apshell`, and run
`request-token --endpoint local-sentry`. Approve the request in the sentry admin
pane; enrollment writes `tokens/local-sentry.token` under the client data
directory.

Or start components individually:

```bash
source apenv.sh
apsigner              # Start the signer
apadmin               # Unlock and manage keys (in another terminal)
apshell                # Transaction shell (in another terminal)
```

### After installing

For a signer node:

1. Run `./start.sh` from the install root
2. Unlock the signer pane with the keystore passphrase
3. Generate a signing key in the signer pane (press `g`)
4. In the shell pane, run `request-token` to obtain an API token via SSH provisioning
5. Approve the request in the signer pane

For a sentry node:

1. Run `./start.sh` from the install root
2. Unlock the sentry admin pane with the keystore passphrase
3. In another terminal, source the install's `apenv.sh`
4. Run `apshell`, then `request-token --endpoint local-sentry`
5. Approve the request in the sentry admin pane

`request-token` creates the client SSH key if it is missing, then waits for an
operator to approve enrollment in `apadmin` or `apapprover`.
After approval, the shell saves the token for the selected endpoint and
immediately attempts to connect.

### Multiple local instances

Simply install to different paths:

```bash
./install.sh ~/demo-buyer
./install.sh ~/demo-seller
./install.sh --role sentry ~/demo-sentry
```

Each instance gets its own random ports, keystore, and `start.sh` launcher. They can run simultaneously without interference.

### Existing install paths

In-place upgrades are supported only from APlane `v0.24.0` or newer. Older
installs, or installs without `install/release.json`, must use a fresh install
root and fresh `apclient`/`apsigner` data directories.

The installer is still conservative when pointed at an existing path:
- Existing `config.yaml` files are left unchanged
- `apconsole.yaml` is refreshed with the local console profile
- Bundled plugin catalog payloads, currently
  `plugins.available/algokit-localnet`, are refreshed under
  `apclient/plugins.available/`
- Repo-checkout installs verify bundled plugin payloads before replacing
  binaries. If only plugin source files are present, rootless `install.sh`
  builds the host `algokit-localnet` payload; sudo installs stop with a
  remediation command instead of leaving stale bundled plugins in place.
- Plugin activation is controlled by `apclient/plugins.yaml`. On first install
  the installer creates an empty activation list; existing activation choices
  are preserved when the installer is re-run.
- If local signer/client ports disagree, the installer warns. Client signer
  routing is edited in `apclient/endpoints.yaml`.
- A canonical template is written to `config.yaml.aplane-installer.new` for review
- If an initialized signer keystore already exists, the installer stops and
  asks you to use a fresh install root

To inspect an environment without changing it, run:

```bash
./installer/scripts/aplane-env-audit.sh
```

The audit script checks resolved data directories, config presence, signer/client
port consistency, listeners, IPC socket state, token and SSH key permissions,
and common partial-install states.

### Uninstalling a local install

```bash
./uninstall.sh [path]
./uninstall.sh --local
```

This removes installer-managed local artifacts: binaries under `apsigner/bin/`
and `apclient/bin/`, generated `apenv.sh`, `apconsole.yaml`, `start.sh`, the
copied `uninstall.sh`, and the shell rc source block for this install. It
preserves `apsigner/` and `apclient/` state by default, including signer keys,
configuration, audit logs, client token, SSH trust, plugins, scripts, caches,
and swap state. Use `--local` to force local uninstall mode; when no path is
provided, it prompts for the local APlane directory. If you run the copied
`<install-path>/uninstall.sh`, the prompt defaults to that install path.

At the end, the uninstaller prints the retained paths and explicit `rm -rf`
commands for irreversible state destruction. Only run those commands after
backing up any keys, tokens, audit logs, or client state you still need.

---

## Install via curl Bootstrap

Use the bootstrap installer to download and install in one step:

```bash
# Default: local install (rootless, no systemd)
curl -fsSL https://raw.githubusercontent.com/aplane-algo/aplane/main/bootstrap-install.sh | bash

# Local install to a custom root
curl -fsSL https://raw.githubusercontent.com/aplane-algo/aplane/main/bootstrap-install.sh | \
  bash -s -- /path/to/aplane
```

For Systemd:

```bash
curl -fsSL https://raw.githubusercontent.com/aplane-algo/aplane/main/bootstrap-install.sh | \
  bash -s -- --systemd
```

This bootstrap script:
- Detects architecture (`amd64`/`arm64`)
- Downloads the matching GitHub release tarball
- Verifies checksums (and minisign signature if `minisign` is installed)
- Runs the bundled `install.sh`
- In `--systemd` mode, enables and starts the `apsigner` systemd service

Useful options:

```bash
# Client-only (apshell, no signer — see next section; works on macOS too)
curl -fsSL https://raw.githubusercontent.com/aplane-algo/aplane/main/bootstrap-install.sh | \
  bash -s -- --client

# Systemd mode (systemd service)
curl -fsSL https://raw.githubusercontent.com/aplane-algo/aplane/main/bootstrap-install.sh | \
  bash -s -- --systemd

# Pin a specific release
curl -fsSL https://raw.githubusercontent.com/aplane-algo/aplane/main/bootstrap-install.sh | \
  bash -s -- --version v1.2.3

# Require minisign verification (fails if minisign is unavailable)
curl -fsSL https://raw.githubusercontent.com/aplane-algo/aplane/main/bootstrap-install.sh | \
  APLANE_REQUIRE_MINISIGN=1 bash

# Systemd mode with a custom binary directory
curl -fsSL https://raw.githubusercontent.com/aplane-algo/aplane/main/bootstrap-install.sh | \
  bash -s -- --systemd --bindir /usr/local/bin

# Equivalent systemd defaults via environment
curl -fsSL https://raw.githubusercontent.com/aplane-algo/aplane/main/bootstrap-install.sh | \
  APLANE_INSTALL_ROOT=/srv/operator/aplane APLANE_BINDIR=/opt/aplane/bin \
  bash -s -- --systemd
```

---

## Upgrade Compatibility

This release supports in-place upgrades only from APlane `v0.24.0` or newer.
If the existing install is older, or if the installer cannot read
`install/release.json`, install into a fresh root and initialize fresh
`apclient` and `apsigner` data directories. Preserve old install directories
separately until you have confirmed the fresh environment has the keys, policy,
endpoint routing, tokens, and network configuration you intend to use.

---

## Client-Only Install (apshell)

If you only need the transaction shell (apshell) and will connect to a remote signer, use `--client`. This installs apshell under `~/aplane/apclient/` by default — no root, no systemd, no signer binaries.

**Works on both Linux and macOS.** The bootstrap script auto-detects the OS and downloads the correct tarball.

```bash
curl -fsSL https://raw.githubusercontent.com/aplane-algo/aplane/main/bootstrap-install.sh | \
  bash -s -- --client
```

Or from an extracted release tarball:

```bash
./install.sh --client
```

This installs:
- `~/aplane/apclient/bin/apshell` — the transaction shell binary
- `~/aplane/apclient/config.yaml` — client configuration (network and UI defaults)
- `~/aplane/apclient/endpoints.yaml` — client endpoint registry; new installs start with a `primary` signer endpoint
- `~/aplane/apclient/.mcp.json` — MCP client configuration for `apshell --mcp`
- `~/aplane/apclient/.codex/config.toml` — Codex project MCP configuration for `apshell --mcp`; Codex loads it when started from this trusted client directory
- `~/aplane/apclient/.ssh/id_ed25519` — SSH key for signer tunnel, generated during install if `ssh-keygen` is available or by `apshell request-token` when first needed
- `~/aplane/apclient/plugins.yaml` — enabled plugin names; new installs start with an empty activation list
- `~/aplane/apclient/plugins.available/algokit-localnet/` — bundled LocalNet operations plugin, loaded only when `algokit-localnet` is listed in `plugins.yaml`
- `~/aplane/apclient/scripts/` — saved JavaScript/MCP snippets

**After installing:**

1. Ensure `~/aplane/apclient/bin` is on your `PATH`, or invoke `apshell` by full path
2. Edit `~/aplane/apclient/endpoints.yaml` to set your remote signer host
3. Run `apshell`, then use `request-token` to generate or reuse your SSH key and request an API token
4. Ask the signer operator to approve the token enrollment in `apadmin` or `apapprover`

Manual public-key exchange is only needed for custom provisioning workflows. The normal `request-token` flow handles key enrollment and token delivery together.
After approval, interactive `apshell` saves the token and immediately attempts
to connect to the signer.

**Constraints:** `--client` cannot be combined with `--systemd` or `--bindir`. It must not be run as root.

**Uninstalling:**

```bash
./uninstall.sh --client
```

This removes installer-created client assets under `~/aplane/apclient/` by
default, or `[path]/apclient/` if you passed a custom root. User-edited
`config.yaml` files are kept, generated SSH keys and installer MCP templates
are removed, bundled and external plugins are left in place, and the directory
is removed only if it becomes empty.

---

## Install from Release Tarball

No build tools required. Download a release tarball from GitHub:

```bash
# Download and extract
tar xzf aplane_*_linux_amd64.tar.gz
cd aplane

# Local install (default — rootless, no systemd)
./install.sh

# Or to a custom path:
./install.sh ~/my-aplane

# Systemd (systemd service):
sudo ./install.sh --systemd
```

The tarball contains:

```
aplane/
├── bin/            # All binaries (apsigner, apshell, apadmin, etc.)
├── installer/      # systemd files, sudoers template, and installer helper scripts
│   └── scripts/    # systemd, environment-audit, and MCP config helpers
├── library/
│   └── templates/  # Template library copied into $APSIGNER_DATA/library/templates
├── plugins.available/ # Bundled plugin catalog
├── install.sh      # Installer
└── uninstall.sh    # State-preserving uninstaller
```

`install.sh --systemd` accepts an optional operator root path plus `--bindir`
for a custom binary directory (default: `/usr/local/bin`):

```bash
sudo ./install.sh --systemd --bindir /opt/aplane/bin
sudo ./install.sh --systemd /srv/operator/aplane --bindir /opt/aplane/bin
sudo ./install.sh --systemd --role sentry /srv/operator/aplane-sentry
sudo APLANE_INSTALL_ROOT=/srv/operator/aplane APLANE_BINDIR=/opt/aplane/bin ./install.sh --systemd
```

If you sourced `<operator-root>/apenv.sh`, preserve the installer variables
across `sudo` explicitly:

```bash
sudo APLANE_INSTALL_ROOT="$APLANE_INSTALL_ROOT" APLANE_BINDIR="$APLANE_BINDIR" ./install.sh --systemd
```

In-place upgrades are supported only from APlane `v0.24.0` or newer. For older
installs, run `install.sh` against a new local root or use `--systemd` with a
fresh signer data directory.

- Existing `config.yaml` is left unchanged
- A canonical template is written to `config.yaml.aplane-installer.new`
- If an initialized signer keystore is from an unsupported install, the installer stops and
  asks you to use a fresh install root

If `config.yaml.aplane-installer.new` is created, review and merge intentionally:

```bash
sudo -u aplane diff -u "$DATA_DIR/config.yaml" "$DATA_DIR/config.yaml.aplane-installer.new" || true
```

---

## Systemd Install

This section covers installing apsigner as a systemd service on Linux.

By default, the systemd installer initializes the keystore, starts the
service in **locked state**, and expects you to unlock via `apadmin`.

Systemd installs always enable enforced memory locking for `apsigner`.
The systemd unit grants `CAP_IPC_LOCK`, sets `LimitMEMLOCK=infinity`, and writes
`require_memory_protection: true` in the signer config so startup fails if
memory locking cannot be enabled.

Systemd installs are marked as systemd-managed. Start and stop them with `systemctl`, not by running `apsigner` directly. Manual startup is blocked for systemd-managed data directories unless explicitly overridden for diagnostics.

### What gets created

Systemd mode installs binaries into `/usr/local/bin` by default, or the
directory passed with `--bindir`. The signer data directory is the `aplane`
service user's home directory, normally `/var/lib/apsigner`.

Key systemd paths:

| Path | Purpose |
|------|---------|
| `/var/lib/apsigner/` | Signer data directory, owned by `aplane:aplane`, mode `2770` |
| `/var/lib/apsigner/config.yaml` | Signer configuration, owned by `aplane:aplane`, mode `0640` |
| `/var/lib/apsigner/identities/default/` | Default identity keystore, keys, policy, and unlock settings |
| `/var/lib/apsigner/install/uninstall.sh` | Bundled systemd uninstaller |
| `/etc/systemd/system/apsigner.service` | systemd service unit |
| `/etc/sudoers.d/99-apsigner-systemctl` | sudoers rule allowing the service user to manage the service |
| `<operator-root>/` | Operator workspace for the user who ran `sudo install.sh --systemd`; defaults to `~<installing-user>/aplane/` |
| `<operator-root>/apclient/` | apshell client config, scripts, plugin activation config, and bundled plugin catalog |
| `<operator-root>/apenv.sh` | Environment file for `APLANE_INSTALL_ROOT`, `APLANE_BINDIR`, `APSIGNER_DATA`, `APCLIENT_DATA`, and `PATH` |
| `<operator-root>/apconsole.yaml` | apconsole profile pointing at `./apclient` and `/var/lib/apsigner` |

The service starts locked unless you later configure a passphrase helper.
Users who run `apadmin` against `/var/lib/apsigner` must be members of the
`aplane` group. `appass` changes systemd passphrase handling and should be
run with `sudo appass -d /var/lib/apsigner` while `apsigner` is stopped.
Systemd `apstore` commands also run with `sudo`; local data directories do
not. Both tools refuse the wrong mode before prompting or touching the store.

For unattended operation, install normally first, stop the service, then use
`sudo appass -d /var/lib/apsigner` to configure a passphrase helper such as
`systemd-creds`.

### Existing systemd installs

Systemd in-place upgrades are supported only from APlane `v0.24.0` or newer.
Use a fresh signer data directory instead of installing over an older existing
one.

The installer still refuses to continue while `apsigner.service` is active,
activating, reloading, or deactivating so it does not replace binaries under a
live daemon.

```bash
sudo systemctl stop apsigner
sudo ./install.sh --systemd
```

When pointed at an existing systemd install after the service is stopped, the
installer checks `install/release.json` before upgrading an initialized signer
store. Treat that behavior as a safety guard, not a migration guarantee.

If a previous install left `identities/<id>/passphrase.cred` in place, the
installer re-adds the matching `LoadCredentialEncrypted=` directive to the
new unit so the daemon can auto-unlock without rerunning
`appass set systemd-creds`.

---

## Quick Start

For the impatient — build from source and install at `/var/lib/apsigner` as the `aplane` user.

### Locked-start mode (default)

```bash
# Build runtime binaries plus applugin-checksum
make all applugin-checksum

# Install binaries
sudo cp bin/apsigner bin/apadmin bin/apconsole bin/apapprover bin/apstore bin/appolicy bin/appass bin/aplocalnet \
        bin/appass-file bin/appass-systemd-creds bin/approbe bin/applugin-checksum /usr/local/bin/
sudo chmod 755 /usr/local/bin/appass-systemd-creds

# Create service user
sudo useradd -r -m -d /var/lib/apsigner -s /usr/sbin/nologin aplane
sudo chown aplane:aplane /var/lib/apsigner
sudo chmod 2770 /var/lib/apsigner

# Install systemd service and sudoers
sudo ./installer/scripts/systemd-setup.sh aplane aplane /usr/local/bin --data-dir /var/lib/apsigner

# Write signer config
sudo -u aplane tee /var/lib/apsigner/config.yaml <<'EOF'
passphrase_timeout: "15m"
lock_on_disconnect: true
user_auto_approve: false
EOF
sudo chmod 640 /var/lib/apsigner/config.yaml

# Initialize keystore, then enable and start
sudo apstore -d /var/lib/apsigner initialize
sudo systemctl enable apsigner
sudo systemctl start apsigner

# Unlock via apadmin, or use apconsole for the unified secure-machine console
sudo -u aplane apadmin -d /var/lib/apsigner
```

### Auto-unlock setup after install (requires systemd 250+)

```bash
# Install and initialize first
sudo ./install.sh --systemd

# Stop the daemon before changing passphrase auto-handling
sudo systemctl stop apsigner

# Configure the helper in the offline TUI, then start again
sudo appass -d /var/lib/apsigner
sudo systemctl start apsigner
```

The rest of this guide explains each step in detail.

---

## Prerequisites

1. **systemd** — verify with:
   ```bash
   systemctl --version
   ```
   For auto-unlock mode, systemd 250+ is required.

2. **TPM2 support** (auto-unlock only, recommended but optional — systemd-creds falls back to the host key):
   ```bash
   systemd-creds has-tpm2
   # "yes" means TPM2 is available; "no" means host-key-only fallback
   ```

3. **Build tools** — Go 1.25+ and musl-tools. See [DEV_BUILD.md](DEV_BUILD.md) for full build prerequisites.

---

## Step 1: Build

```bash
make all
```

This produces statically linked binaries in `bin/`:

| Binary | Purpose |
|--------|---------|
| `apsigner` | Signing server |
| `appass-systemd-creds` | Passphrase encryption helper (TPM2/host key) |
| `apstore` | Keystore init, backup, restore, passphrase change |
| `apadmin` | Key generation and management (TUI) |
| `apconsole` | Unified secure-machine console for shell, signer TUI, and daemon status |
| `apapprover` | Signing and token provisioning approval interface |
| `appass` | Offline passphrase auto-unlock configuration TUI |
| `appolicy` | Offline policy checker/editor TUI |
| `aplocalnet` | LocalNet setup TUI/CLI for apshell default network, signer config, plugin activation, and KMD override persistence |
| `appass-file` | Development-only plaintext passphrase helper |
| `approbe` | Installer/helper liveness probe for signer IPC reachability |
| `apshell` | Transaction shell (client) |

`applugin-checksum` is built by `make applugin-checksum` and is included in release
tarballs. Build it explicitly if you are following the manual copy commands
below.

---

## Step 2: Install Binaries

Copy the server-side binaries to a system path:

```bash
sudo cp bin/apsigner bin/apadmin bin/apconsole bin/apapprover bin/apstore bin/appolicy bin/appass bin/aplocalnet \
        bin/appass-file bin/appass-systemd-creds bin/approbe bin/applugin-checksum /usr/local/bin/
sudo chmod 755 /usr/local/bin/appass-systemd-creds
```

Or keep them in a custom directory — `systemd-setup.sh` accepts a `bindir` argument (see Step 4).

---

## Step 3: Create Service User

Create a dedicated system user with no login shell:

```bash
sudo useradd -r -m -d /var/lib/apsigner -s /usr/sbin/nologin aplane
sudo chown aplane:aplane /var/lib/apsigner
sudo chmod 2770 /var/lib/apsigner
```

This creates the `aplane` user and group with home directory `/var/lib/apsigner`.
The `2770` mode keeps the directory private to the service user and `aplane`
group while preserving group ownership for new files.

To use an existing user instead, skip this step and substitute your username in the following steps.

---

## Step 4: Install the systemd Service

The setup script installs a systemd service (`apsigner.service`) configured for a specific data directory.

```bash
sudo ./installer/scripts/systemd-setup.sh <username> <group> [bindir] [--data-dir <path>] [--memory-lock]
```

**Arguments:**

| Argument | Description | Default |
|----------|-------------|---------|
| `username` | User to run apsigner as | (required) |
| `group` | Group to run apsigner as | (required) |
| `bindir` | Directory containing the apsigner binary | `../../bin` relative to the script |
| `--data-dir` | Data directory for apsigner | `/var/lib/apsigner` |
| `--memory-lock` | Grant `CAP_IPC_LOCK` and `LimitMEMLOCK=infinity` in the systemd unit | disabled |

**Example — locked-start (default):**

```bash
sudo ./installer/scripts/systemd-setup.sh aplane aplane /usr/local/bin --data-dir /var/lib/apsigner
```

This installs:

- `/etc/systemd/system/apsigner.service` — the service unit file
- `/etc/sudoers.d/99-apsigner-systemctl` — allows the service user to start/stop/restart without a password

---

## Step 5: Initialize the Keystore

Initialize the keystore before first use. The systemd installer does this
for you; for a manual systemd setup, run `sudo apstore -d /var/lib/apsigner initialize`.

### Auto-unlock setup

Initialize the keystore first:

```bash
sudo apstore -d /var/lib/apsigner initialize
```

This creates:
- `/var/lib/apsigner/identities/default/` — identity directory with keystore, group-accessible to `aplane`

Then configure auto-unlock offline:

```bash
sudo systemctl stop apsigner
sudo appass -d /var/lib/apsigner
sudo systemctl start apsigner
```

For `systemd-creds` mode, `appass` writes identity-scoped unlock settings,
creates `identities/default/passphrase.cred`, adds the matching
`LoadCredentialEncrypted` line to the systemd unit, and reloads systemd.
The resulting unit gains a line of the form:

```ini
LoadCredentialEncrypted=aplane-passphrase:/var/lib/apsigner/identities/default/passphrase.cred
```

At service start, systemd decrypts `passphrase.cred` and places the
plaintext in a tmpfs at `$CREDENTIALS_DIRECTORY/aplane-passphrase`. apsigner
invokes `appass-systemd-creds read`, which reads directly from that path —
no root access required, no shell wrapper. The credential name
`aplane-passphrase` is constant and must match between
`LoadCredentialEncrypted=` and `appass-systemd-creds`; `appass` keeps the
two in sync. Encrypting the credential the first time requires root because
`systemd-creds encrypt` accesses the TPM2 or host key directly, which is why
`appass` is run with `sudo`.

`appass-systemd-creds` helper configurations refuse non-root
`apstore changepass` before prompting because rewriting the encrypted
systemd credential requires root. See [Changing the Passphrase](#changing-the-passphrase)
below.

### Locked-start setup

Create `/var/lib/apsigner/config.yaml`:

```yaml
lock_on_disconnect: true
user_auto_approve: false
```

Ensure systemd ownership and permissions:

```bash
sudo chown aplane:aplane /var/lib/apsigner/config.yaml
sudo chmod 640 /var/lib/apsigner/config.yaml
```

Then initialize the keystore and start the service:

```bash
sudo apstore -d /var/lib/apsigner initialize
# For a dedicated sentry node:
sudo apstore -d /var/lib/apsigner initialize --role sentry
sudo systemctl start apsigner
sudo -u aplane apadmin -d /var/lib/apsigner
```

For auto-unlock, stop the daemon after initialization and run `sudo appass -d /var/lib/apsigner`.

See [USER_CONFIG.md](USER_CONFIG.md#headless-operation) for additional configuration options (`user_auto_approve:true`, network settings, etc.).

---

## Step 6: Enable and Start

```bash
# Enable on boot
sudo systemctl enable apsigner

# Start now
sudo systemctl start apsigner
```

If you skipped Step 5, initialize the keystore before unlocking:

```bash
sudo apstore -d /var/lib/apsigner initialize
# For a dedicated sentry node:
sudo apstore -d /var/lib/apsigner initialize --role sentry
sudo -u aplane apadmin -d /var/lib/apsigner
```

Check status:

```bash
systemctl status apsigner
```

View logs:

```bash
journalctl -u apsigner -f
```

---

## Managing the Service

With the sudoers rules installed, the `aplane` user can manage the service with passwordless `sudo systemctl`:

```bash
# As the service user (or via sudo -u aplane)
sudo systemctl status apsigner
sudo systemctl restart apsigner
sudo systemctl stop apsigner
```

### Granting apadmin Access

Users who need to run `apadmin` (to unlock, generate keys, approve requests, etc.) must be members of the `aplane` group:

```bash
sudo usermod -aG aplane <username>
```

Log out and back in for the group change to take effect. Group members can then run `apadmin` directly:

```bash
apadmin -d /var/lib/apsigner
```

### Generate Keys

Use the apadmin TUI to generate signing keys:

```bash
apadmin -d /var/lib/apsigner
```

Press `g` and select a key type to generate. apsigner auto-detects new keys via file watching — no restart needed.

### Backup Keys

```bash
sudo apstore -d /var/lib/apsigner backup create all
sudo apstore -d /var/lib/apsigner backup export aplane-backup-YYYYMMDD-HHMMSS.tar.gz /mnt/usb
```

See [USER_STORE_MGMT.md](USER_STORE_MGMT.md) for full backup/restore documentation.

---

## Multiple Instances

To run multiple apsigner instances on the same machine, create a separate service unit for each data directory. Copy the installed service file and adjust the `Environment=APSIGNER_DATA=` line:

```bash
# Create a second data directory
sudo mkdir -p /var/lib/apsigner-staging
sudo chown aplane:aplane /var/lib/apsigner-staging

# Initialize it
sudo /usr/local/bin/apstore -d /var/lib/apsigner-staging initialize

# Configure it (copy and edit config.yaml)
sudo -u aplane cp /var/lib/apsigner/config.yaml /var/lib/apsigner-staging/config.yaml

# Create a second service unit
sudo cp /etc/systemd/system/apsigner.service /etc/systemd/system/apsigner-staging.service
sudo sed -i 's|/var/lib/apsigner|/var/lib/apsigner-staging|g' /etc/systemd/system/apsigner-staging.service
sudo systemctl daemon-reload

# Enable and start
sudo systemctl enable apsigner-staging
sudo systemctl start apsigner-staging
```

Each instance runs independently with its own keystore, configuration, and IPC socket.

---

## Identity Runtime Layout

The installer creates `identities/default/` with the keystore. As the signer runs, it populates that identity directory with additional runtime files:

```
$APSIGNER_DATA/identities/default/
├── .keystore         # Keystore metadata (master salt and passphrase verifier)
├── config.yaml       # Identity-scoped runtime setting overrides
├── policy.yaml       # Identity-scoped node-role policy
├── policy.yaml.hmac  # Integrity sidecar for policy.yaml
├── unlock.yaml       # Identity-scoped passphrase helper settings
├── .ssh/
│   └── authorized_keys  # Identity-scoped enrolled client public keys
├── keytypes/
│   ├── *.json        # Plaintext key type state records
│   └── *.template    # Encrypted installed template YAML
├── keys/             # Encrypted key files
│   └── *.key
├── deleted/          # Identity-local deletion archive
│   ├── keys/
│   └── keytypes/
├── aplane.token      # Identity API token created by apstore initialize
└── passphrase.cred   # systemd-creds-encrypted passphrase (auto-unlock only)
```

`policy.yaml` and `policy.yaml.hmac` are created by `apstore initialize`.
`config.yaml` and `unlock.yaml` are created on first edit through `apadmin` or
`appass`. The signer-side `aplane.token` is created during initialization;
client-side token files are written when a client is enrolled via
`request-token`. `passphrase.cred` exists only when `appass` configures
auto-unlock with `systemd-creds`.

The client data directory grows over time as well:

```
$APCLIENT_DATA/
├── config.yaml           # Network and UI defaults
├── endpoints.yaml        # Signer endpoint routing
├── aplane.token          # API token (created after request-token approval)
├── tokens/               # Optional endpoint-specific API tokens
├── .mcp.json             # Installer-written MCP client config for apshell --mcp
├── .codex/config.toml    # Installer-written Codex project MCP config
├── .ssh/
│   ├── id_ed25519        # SSH private key for authentication
│   ├── id_ed25519.pub    # SSH public key
│   └── known_hosts       # Trusted server host keys
├── plugins.yaml          # Enabled plugin names
├── plugins.available/    # Installed plugin catalog entries
└── scripts/              # Saved JavaScript/MCP snippets
```

---

## Installer Files Reference

The `installer/` directory contains service files and installer helper scripts for different deployment scenarios:

| File | Use Case |
|------|----------|
| `installer/apsigner.service` | Pre-built service unit. Hardcoded for `/var/lib/apsigner` as user `aplane` with binaries in `/usr/local/bin/`. Copy directly to `/etc/systemd/system/` for the simplest possible setup. |
| `installer/apsigner.service.template` | Service template with `@@BINDIR@@`, `@@USER@@`, `@@GROUP@@`, `@@DATA_DIR@@`, and `@@MEMORY_LOCK_SERVICE_LINES@@` placeholders. Used by `installer/scripts/systemd-setup.sh` for customizable installs. |
| `installer/sudoers.template` | sudoers rules with `@@USER@@` placeholder. Allows the service user to manage the `apsigner` service without a password. Covers both `/bin/systemctl` (Ubuntu) and `/usr/bin/systemctl` (RHEL/CentOS) paths. |
| `installer/scripts/aplane-env-audit.sh` | Read-only environment audit for local configuration, ports, listeners, IPC socket state, token/key permissions, and partial installs. |
| `installer/scripts/config-mcp.sh` | Helper that writes `$APCLIENT_DATA/.mcp.json` and `$APCLIENT_DATA/.codex/config.toml` for `apshell --mcp`. Installers call the same configuration logic automatically. |

### Manual Installation (Without the Setup Script)

If you prefer not to use `systemd-setup.sh`, you can install the pre-built service file directly:

```bash
sudo cp installer/apsigner.service /etc/systemd/system/apsigner.service
sudo systemctl daemon-reload
sudo systemctl enable apsigner
sudo systemctl start apsigner
```

---

## How Passphrase Encryption Works

This section applies to **auto-unlock mode** only.

The passphrase flow uses three components working together:

```
One-time setup:
  appass systemd-creds setup
    -> prompts for passphrase
    -> writes identities/default/unlock.yaml
    -> runs appass-systemd-creds write identities/default/passphrase.cred
    -> adds LoadCredentialEncrypted to the systemd unit

Every service start:
  systemd decrypts identities/default/passphrase.cred
    -> plaintext appears in $CREDENTIALS_DIRECTORY/aplane-passphrase
  apsigner invokes appass-systemd-creds read
    -> helper reads the systemd credential directory
  apsigner unlocks the keystore and is ready to sign
```

**Key security properties:**

- The passphrase is encrypted at rest on disk (bound to this machine's TPM2/host key)
- systemd decrypts it into a tmpfs that only the service process can read
- apsigner runs as an unprivileged user — never needs root
- The `passphrase.cred` file is useless on any other machine

---

## Changing the Passphrase

To rotate the keystore passphrase (auto-unlock mode):

```bash
sudo apstore -d /var/lib/apsigner changepass
```

This asks you to manually enter the current passphrase, atomically re-encrypts
all keys with a new passphrase, re-signs the policy and node-role integrity
sidecars, and updates `passphrase.cred`. Restart the service afterward:

Systemd data directories contain a `.prod` marker. For those directories,
all `apstore` commands require root and exit before prompting if they are not
run with `sudo`. Local data directories reject root instead.
When running against systemd data, `apstore` returns managed store files to
the signer data directory owner/group after successful mutations and keeps
`passphrase.cred` root-owned.

```bash
sudo systemctl restart apsigner
```

---

## Migrating to a New Machine

The TPM2-encrypted `passphrase.cred` is bound to the original machine and cannot be decrypted elsewhere. To migrate:

1. **On the old machine** — create a backup:
   ```bash
   sudo apstore -d /var/lib/apsigner backup create all
   sudo apstore -d /var/lib/apsigner backup export aplane-backup-YYYYMMDD-HHMMSS.tar.gz /mnt/usb
   ```

2. **On the new machine** — install apsigner (Steps 1–4 above), then restore:
   ```bash
   sudo apstore -d /var/lib/apsigner backup import /mnt/usb/aplane-backup.tar.gz
   sudo apstore -d /var/lib/apsigner restore preview aplane-backup.tar.gz
   sudo apstore -d /var/lib/apsigner restore apply aplane-backup.tar.gz
   ```

3. **On the new machine** — if using auto-unlock, create a new machine-bound credential:
   ```bash
   sudo appass -d /var/lib/apsigner
   ```

4. Enable and start the service (Step 6).

---

## Uninstalling

```bash
sudo /var/lib/apsigner/install/uninstall.sh
sudo /var/lib/apsigner/install/uninstall.sh --systemd /srv/operator/aplane
```

On Linux, when no mode flag is provided, `uninstall.sh` prompts for `local` or
`systemd`. Systemd data discovery still selects the signer data directory
after you choose `systemd`; it does not select the mode for you.
`--systemd` remains available as an explicit mode flag on Linux. On non-Linux
platforms, local uninstall is the default and `--systemd` is rejected.
Systemd uninstall stops and disables `apsigner`, removes the systemd unit,
sudoers file, installed binaries, and the invoking user's operator workspace
under the install-recorded operator root. Pass `[operator-root]` to override
that recorded value. If no operator root is recorded and no `[operator-root]`
is provided, systemd uninstall leaves user client directories untouched
instead of guessing at `$SUDO_USER_HOME/aplane`. It preserves
`/var/lib/apsigner` and the `aplane:aplane` account so the signer keystore,
configuration, audit log, and ownership remain available for backup.

Local uninstall follows the same preservation principle: it removes generated
local binaries and launcher/env files, but keeps `apsigner/` and `apclient/`
state unless you manually run the printed destructive cleanup commands.

### What is preserved and why it matters

The "Left behind" output at the end of `uninstall.sh --systemd` enumerates
every retained path with a one-line label. Security-relevant entries:

- **`identities/<id>/keys/`** -- encrypted private keys. Treat as sensitive at
  rest; back up before disposing of the host.
- **`identities/<id>/passphrase.cred`** -- the keystore passphrase encrypted
  to this host's TPM2 and/or host key by `systemd-creds`. **Bound to this
  physical machine.** It is unreadable on a different host, and unreadable on
  this host if the TPM is reset, the disk is moved, or the host key changes.
  See "Migrating to a New Machine" for the safe relocation path.
- **`identities/<id>/.keystore`** -- master salt and passphrase verifier.
- **`identities/<id>/aplane.token`** -- HTTP API token; treat as a credential.
- **`audit.log`** -- the signer's audit trail. Retain for compliance and
  forensics unless you have already exported it.
- **`backups/`** -- encrypted backup tarballs (same protections as keys).
- **`config.yaml`** -- operator-edited configuration (algod endpoints, ports,
  policy). Preserved so uninstall does not silently discard operator state.

What `uninstall.sh` *removes*: the `apsigner` systemd unit, the
`/etc/sudoers.d/99-apsigner-systemctl` rule, the installed APlane binaries
under the configured binary directory, and the operator workspace under the
operator root.

The systemd `LoadCredentialEncrypted=` binding lives in the unit file and is
removed along with it, but the underlying `passphrase.cred` is preserved. On a
fresh systemd install, use `sudo appass -d /var/lib/apsigner` to configure
auto-unlock explicitly.

To delete everything manually, `uninstall.sh` prints the exact command
sequence at the end of its output. **`sudo rm -rf /var/lib/apsigner` is
irreversible and destroys keys.** Only run it after exporting any backups or
audit trails you need.

---

## Troubleshooting

### Service fails to start

Check the journal:

```bash
journalctl -u apsigner --no-pager -n 50
```

### "LoadCredentialEncrypted failed"

This only applies to auto-unlock mode. Common causes:

- The identity-scoped `passphrase.cred` file is missing or corrupted:

  ```bash
  ls -la /var/lib/apsigner/identities/default/passphrase.cred
  ```

- The unit file is missing the `LoadCredentialEncrypted=` directive, for
  example after a hand-edited unit:

  ```bash
  grep LoadCredentialEncrypted /etc/systemd/system/apsigner.service
  ```

  Re-running `sudo ./install.sh --systemd` re-adds the directive
  automatically when `passphrase.cred` is present. See
  "Re-running systemd install" and "What is preserved and why it matters".

Reconfigure auto-unlock if needed:

```bash
sudo systemctl stop apsigner
sudo appass -d /var/lib/apsigner
sudo systemctl start apsigner
```

### "AssertPathExists failed"

The data directory doesn't exist. Create it:

```bash
sudo mkdir -p /var/lib/apsigner
sudo chown aplane:aplane /var/lib/apsigner
```

### Permission denied on IPC socket

The IPC socket is created in the data directory. Ensure the directory is owned by the service user:

```bash
sudo chown aplane:aplane /var/lib/apsigner
```

### systemd-creds not found

This is only needed for auto-unlock mode. Check with `systemctl --version`. You need systemd 250+ for auto-unlock. Without auto-unlock, the service starts in locked state and can be unlocked via `apadmin`.

### No TPM2

`systemd-creds` will fall back to the host key automatically. The passphrase is still encrypted at rest, but the protection is weaker — anyone who can read the host key and the credential file can decrypt the passphrase. For stronger protection, use a machine with a TPM2 chip.

---

## Related Documentation

- [DEV_BUILD.md](DEV_BUILD.md) — Build instructions and prerequisites
- [USER_CONFIG.md](USER_CONFIG.md) — Full configuration reference (headless mode, approval policies)
- [USER_STORE_MGMT.md](USER_STORE_MGMT.md) — Key backup, restore, and passphrase management
- [ARCH_SECURITY.md](ARCH_SECURITY.md) — Security architecture (appass-systemd-creds protocol details)
