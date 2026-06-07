# Build Instructions

This project builds several first-party commands and developer helpers:

1. **apshell** - client shell, JavaScript runner, MCP server, and plugin host
2. **apsigner** - signing daemon, HTTP API, admin protocol, approval coordinator, and SSH tunnel server
3. **apadmin** - TUI admin client over local IPC or the SSH admin subsystem
4. **apconsole** - secure-machine unified console for apshell, apadmin, and apsigner panes
5. **apapprover** - minimal approval-only CLI over local IPC
6. **apstore** - keystore management client for signer-owned admin flows plus local verify/rebuild rescue
7. **appolicy** - offline policy checker/editor TUI
8. **appass** - passphrase auto-unlock setup TUI
9. **aplocalnet** - LocalNet setup TUI/CLI
10. **appass-file** - dev-only plaintext passphrase helper
11. **appass-systemd-creds** - Linux/systemd production passphrase helper using systemd credentials
12. **approbe** - installer-facing signer liveness probe
13. **applugin-checksum** - plugin checksum generator
14. **compile_teal** - TEAL-to-Go bytecode generator used by development workflows
15. **configdoc** - configuration reference generator

## Project Structure

```text
aplane/
├── cmd/
│   ├── apshell/              # Shell, scripting, MCP, and plugin host
│   ├── apsigner/            # Signing daemon and admin/HTTP/SSH runtime
│   ├── apadmin/             # Admin TUI
│   ├── apconsole/            # Secure-machine unified console
│   ├── apapprover/           # Approval-only CLI
│   ├── apstore/              # Keystore management, local flows, IPC-admin flows
│   ├── appolicy/             # Offline policy checker/editor TUI
│   ├── appass/               # Passphrase auto-unlock TUI
│   ├── aplocalnet/           # LocalNet setup TUI/CLI
│   ├── appass-file/            # Dev passphrase helper
│   ├── appass-systemd-creds/   # Linux systemd-creds passphrase helper
│   ├── approbe/                # Installer liveness probe
│   ├── applugin-checksum/      # Plugin integrity helper
│   ├── compile_teal/         # TEAL-to-Go bytecode generator
│   └── configdoc/            # Config reference generator
├── internal/
│   ├── apshellapp/           # Shell command workflows and result APIs
│   ├── engine/               # Client-side business logic and signer connection state
│   ├── clientstate/          # APCLIENT_DATA-scoped caches and local state
│   ├── signerapp/            # Signer runtime, identity, approval, and key/template lifecycle
│   ├── signing/              # Native signing and signer-facing helpers
│   ├── lsigprovider/         # LogicSig provider interfaces and registry
│   ├── keytypecatalog/       # Compiled key type availability
│   ├── keytypestate/         # Identity-scoped key type state records
│   ├── keys/                 # Key file scanning and persistence helpers
│   ├── keystore/             # Keystore metadata and encrypted key storage
│   ├── templatestore/        # Encrypted identity template store
│   ├── templatelibrary/      # Plaintext KeyType Library parsing and install prep
│   ├── transport/            # Admin transport clients
│   ├── sshtunnel/            # SSH tunnel server/client
│   ├── plugin/               # External plugin discovery and JSON-RPC runtime
│   ├── scripting/            # JavaScript runtime orchestration
│   ├── jsapi/                # JavaScript bindings
│   └── config/               # Client and server config loading/validation
├── lsig/
│   ├── falcon1024/           # Falcon-1024 DSA provider
│   ├── falcon1024_ed25519/   # Dual Falcon-1024 / Ed25519 DSA provider
│   ├── ecdsak1/              # ECDSA k=1 LogicSig provider
│   ├── generictemplate/      # YAML-backed generic LogicSig providers
│   └── composeddsa/          # DSA + TEAL-suffix composition helpers
├── library/templates/        # Optional KeyType Library YAML source
├── test/integration/         # End-to-end integration tests
├── examples/                 # Example scripts and external plugins
├── analysis/                 # Security analyzers
├── Makefile                  # Build automation
└── docs/                     # Documentation
```

## Building

Linux CGO binaries are built with **musl-based static linking** by default for
portability. Pure Go helpers are built with `CGO_ENABLED=0`. macOS builds are
dynamically linked because Apple does not support fully static binaries.

### Prerequisites

- Go 1.25+
- Node.js 20+ and npm only when explicitly building TypeScript example plugins

#### For macOS builds:

```bash
# Install Xcode Command Line Tools (required for CGO)
xcode-select --install

# Verify Go sees a working C toolchain
go env CGO_ENABLED
clang --version
```

#### For x86_64 Linux builds:

```bash
# Install musl compiler (Debian/Ubuntu)
sudo apt-get install musl-tools

# Or download from https://musl.cc/
curl -O https://musl.cc/x86_64-linux-musl-cross.tgz
tar -xzf x86_64-linux-musl-cross.tgz
export PATH="$PWD/x86_64-linux-musl-cross/bin:$PATH"
```

#### For ARM64 Linux builds:

```bash
# The default ARM64 cross-compiler is Zig.
# Install Zig from https://ziglang.org/download/ and verify:
zig version

# Optional: override the compiler if you have a musl cross toolchain.
make bin-arm64 ARM64_CC=aarch64-linux-musl-gcc
```

### Option 1: Using Makefile (recommended)

```bash
# Build the default runtime binaries
make all

# Build individual binaries
make apshell
make apsigner
make apadmin
make apconsole
make apapprover
make apstore
make appass
make aplocalnet
make appass-file
make appass-systemd-creds
make approbe
make applugin-checksum

# Generate development artifacts
make config-docs

# Build release-layout binaries
make bin-amd64
make bin-arm64
make bin-darwin-amd64
make bin-darwin-arm64

# Build bundled external plugin payloads
make bundled-plugins
make bundled-plugins-linux
make bundled-plugins-darwin

# Build local release archives
make release-local

# Run the canonical full verification gate
make integrity-check

# Clean binaries
make clean
```

`make all` builds the default runtime binaries and runs `compile-teal` first.
Precompiled token files are committed, but if `resources/dummy.teal` is newer
than the token files then `goal` must be available to recompile them.
Most developer helpers, such as `compile_teal` and `configdoc`, are built or
run separately when needed. `applugin-checksum` is built by `make all` because
the bundled plugin checksum target depends on it.

`make bundled-plugins` builds installable bundled plugin payloads from
`plugins/` (currently the host `algokit-localnet` binary) for local installs
from a checkout. `make bundled-plugins-linux` and `make bundled-plugins-darwin`
build target-specific `algokit-localnet` release payloads under
`dist/bundled-plugins/<os>-<arch>/algokit-localnet`. GitHub release packaging
consumes those target payloads so archives ship ready-to-install bundled
plugins. Production bundled plugin builds do not require Node.js or npm.

### Option 2: Manual build commands

```bash
mkdir -p bin

# Build apshell with musl static linking
CGO_ENABLED=1 CC=musl-gcc go build -ldflags '-extldflags "-static"' \
  -o bin/apshell ./cmd/apshell

# Build apsigner with musl static linking
CGO_ENABLED=1 CC=musl-gcc go build -ldflags '-extldflags "-static"' \
  -o bin/apsigner ./cmd/apsigner

# Build apsigner ARM64 cross-compile with Zig/musl
CGO_ENABLED=1 GOOS=linux GOARCH=arm64 CC='zig cc -target aarch64-linux-musl' \
  go build -ldflags '-extldflags "-static"' -o bin/apsigner-arm64 ./cmd/apsigner

# Build admin, keystore-management, and helper tools
CGO_ENABLED=1 CC=musl-gcc go build -ldflags '-extldflags "-static"' \
  -o bin/apadmin ./cmd/apadmin
CGO_ENABLED=1 CC=musl-gcc go build -ldflags '-extldflags "-static"' \
  -o bin/apconsole ./cmd/apconsole
CGO_ENABLED=0 go build -o bin/apapprover ./cmd/apapprover
CGO_ENABLED=1 CC=musl-gcc go build -ldflags '-extldflags "-static"' \
  -o bin/apstore ./cmd/apstore
CGO_ENABLED=0 go build -o bin/appass ./cmd/appass
CGO_ENABLED=0 go build -o bin/aplocalnet ./cmd/aplocalnet
CGO_ENABLED=0 go build -o bin/appass-file ./cmd/appass-file
CGO_ENABLED=0 go build -o bin/appass-systemd-creds ./cmd/appass-systemd-creds
CGO_ENABLED=0 go build -o bin/approbe ./cmd/approbe
CGO_ENABLED=0 go build -o bin/applugin-checksum ./cmd/applugin-checksum
CGO_ENABLED=0 go build -o bin/compile_teal ./cmd/compile_teal
CGO_ENABLED=0 go build -o bin/configdoc ./cmd/configdoc

# Regenerate config reference docs
go run ./cmd/configdoc > docs/USER_CONFIG_REFERENCE.md

# Verify static linking on Linux CGO binaries
ldd bin/apshell
ldd bin/apsigner

# Clean
make clean
```

## Running

### apshell CLI

```bash
# Set data directory (or use -d flag)
export APCLIENT_DATA=~/aplane/apclient

# Start interactive REPL
bin/apshell

# Or with explicit data directory
bin/apshell -d ~/aplane/apclient

# Connect to the configured signer, then list available signing keys
apshell> request-token
apshell> connect
apshell> keys

# Send transactions
apshell> send 10 algo from mykey to RECEIVER...
```

`connect` reads the default signer endpoint from
`$APCLIENT_DATA/endpoints.yaml`. Passing an endpoint alias connects to that
named profile. This release does not support top-level `ssh:` signer routing in
client `config.yaml`.

### Signer Server

```bash
# Set data directory (or use -d flag)
export APSIGNER_DATA=~/aplane/apsigner

# Start the signer server
bin/apsigner

# Or with explicit data directory
bin/apsigner -d ~/aplane/apsigner
```

### apadmin (Admin TUI)

```bash
# Set data directory (uses same as apsigner)
export APSIGNER_DATA=~/aplane/apsigner

# Interactive TUI mode over local IPC
bin/apadmin

# Or with explicit data directory
bin/apadmin -d ~/aplane/apsigner

# Remote SSH admin mode uses APCLIENT_DATA/client config and token
bin/apadmin --remote --client-data ~/aplane/apclient
```

### apconsole (Unified Secure-Machine Console)

```bash
# Set both signer and shell data directories
export APSIGNER_DATA=~/aplane/apsigner
export APCLIENT_DATA=~/aplane/apclient

# Local secure-machine wrapper; attaches to an existing apsigner IPC socket
# or starts apsigner as an owned child when no socket exists.
bin/apconsole

# Or with explicit data directories
bin/apconsole -d ~/aplane/apsigner -client-data ~/aplane/apclient

# Or with an install-root profile
bin/apconsole -config ~/aplane/apconsole.yaml

# Remote admin mode uses the SSH admin subsystem for the signer pane.
bin/apconsole -remote -client-data ~/aplane/apclient
```

### apapprover (Signing Approval)

```bash
# Set data directory
export APSIGNER_DATA=~/aplane/apsigner

# Start approver (connects via IPC, prompts for passphrase)
bin/apapprover
```

### apstore (Local And IPC Keystore Management)

```bash
# Set data directory
export APSIGNER_DATA=~/aplane/apsigner

# Initialize a store
bin/apstore initialize

# Backup all keys into signer-managed backup storage
bin/apstore backup create all

# Export a managed backup to an external directory
bin/apstore backup export aplane-backup-YYYYMMDD-HHMMSS.tar.gz /path/to/backups

# Backup specific key
bin/apstore backup create address ABC123...

# Import and restore keys
# Import prompts for the export passphrase and validates encrypted key payloads.
# Bundled template validation may require the TEAL compile algod endpoint.
bin/apstore backup import /path/to/aplane-backup.tar.gz
bin/apstore restore preview aplane-backup.tar.gz
bin/apstore restore apply aplane-backup.tar.gz

# Verify backup (accepts an external archive path or backup directory)
bin/apstore verify /path/to/aplane-backup.tar.gz

# Change passphrase
bin/apstore changepass

# List, show, or install encrypted identity templates
bin/apstore template list
bin/apstore template show aplane.whitelist.v1 --show-sensitive-template
bin/apstore template import library/templates/aplane.whitelist.v1.yaml
```

### appass (Auto-Unlock Setup)

```bash
export APSIGNER_DATA=~/aplane/apsigner

# apsigner must be stopped for offline auto-unlock edits
bin/appass
bin/appass -d ~/aplane/apsigner -identity default
```

## Plugin System

APlane Shell supports **external plugins**: standalone executables that run as
separate processes and communicate via JSON-RPC over stdin/stdout. Plugins can
be written in any language.

Included example plugins:

- `echo-plugin`: development-only protocol illustration; not bundled or
  installed
- `reti`: TypeScript/Node.js Réti staking-protocol example, built into a
  standalone executable with Node SEA. Source lives under
  `examples/external_plugins/reti/`; it is source-only and not included in
  production release archives

Production bundled plugins live under `plugins/`:

- `algokit-localnet`: bundled LocalNet operations plugin, installed to
  `plugins.available` but not enabled by default

Plugins are installed under `$APCLIENT_DATA/plugins.available` and loaded only
when their directory names are listed in `$APCLIENT_DATA/plugins.yaml`.

Build and validate bundled and example plugins with:

```bash
make bundled-plugins
make bundled-plugins-linux
make bundled-plugins-darwin
make install-example-plugins
make build-example-plugins
make check-example-plugins
make applugin-checksums
```

`make bundled-plugins` builds host payloads for plugins under `plugins/`
(currently `algokit-localnet`). `make bundled-plugins-linux` and
`make bundled-plugins-darwin` build target-specific `algokit-localnet` payloads
for release packaging.
For a one-shot dev install of every example plugin, run `make example-plugins`
from the repo root. It builds every example, copies each one with a complete
payload (including `echo-plugin`) into `$APCLIENT_DATA/plugins.available/`,
and writes `plugins.yaml` enabling all of them. The target is destructive on
those two paths and is intended for dev client data directories only.
`make build-example-plugins` only builds and does not touch `$APCLIENT_DATA`.

For `reti`, Node.js and npm are build-time requirements for the explicit
example workflow only. Production release builds do not install npm packages or
ship `reti` runtime payloads.

The installer copies runtime plugin catalog entries into
`$APCLIENT_DATA/plugins.available` when they are present in the archive.
Payloads are staged as
`plugins.available/algokit-localnet/{manifest.json,checksums.sha256,algokit-localnet}`.
When installing from a repo checkout, `install.sh` verifies each payload
before replacing binaries. If the checkout only has `algokit-localnet`
source files, rootless installs build the host payload; sudo installs stop
with a remediation command so the checkout is not rewritten with root-owned
plugin build outputs. Activation is preserved in `plugins.yaml`; first-install
creates an empty activation list.

Plugin discovery requires a valid `checksums.sha256`; regenerate it with
`bin/applugin-checksum <plugin-directory>` or `make applugin-checksums`.

See
[examples/external_plugins/README.md](../examples/external_plugins/README.md#installing-in-a-dev-environment)
for the `make example-plugins` dev-install workflow, and
[ARCH_PLUGINS.md](ARCH_PLUGINS.md) for plugin architecture details.

## Verification

```bash
# Unit tests excluding integration tests
make test

# Go signer API contract fixtures
make contract-test

# Integration tests; regenerates .env.test and the shared fixture first
make integration-test

# Full stack gate: formatting, vet, module tidy, lint, deadcode, security
# analyzers, race tests, cross-builds, smoke tests, contracts, integration,
# and a clean-tree check
make integrity-check
```

## Security Setup

Enable memory locking to prevent key material from being swapped to disk:

```bash
# For apsigner, which owns unlocked key material
sudo setcap cap_ipc_lock+ep bin/apsigner
```

Set `require_memory_protection: true` in signer `config.yaml` when startup
should fail if memory locking is unavailable. `apadmin`, `apconsole`,
`apstore`, `appolicy`, `appass`, `aplocalnet`, and `approbe` perform admin, setup, rescue, policy-editing, or liveness-probe
workflows and do not need this capability.

## Notes

- **apshell** does not hold signer-managed private keys; signing is delegated to `apsigner`
- **apsigner** stores all private keys encrypted at rest
- **apadmin** provides TUI admin, approval, key, and KeyType Library workflows
- **apconsole** composes shell, signer-admin, and daemon panes on the secure signer machine
- **apapprover** handles approval-only workflows over local IPC
- **apstore** performs local initialize, policy integrity, endpoint export, public sentry reference, backup import admission, verification, and rebuild rescue flows; signer-owned backup, restore, passphrase, key type, and template mutations use the local admin protocol
- **appolicy** verifies and edits the node-role policy document offline, can
  convert deterministic signing policy into sentry-domain `policy.yaml`, and can
  save/sign either policy document while holding the store mutation lock
- **appass** edits identity-scoped auto-unlock configuration while `apsigner` is stopped
- **aplocalnet** configures a running AlgoKit LocalNet as apshell's default network, updates apsigner genesis mapping, enables the LocalNet plugin, and can persist a KMD URL override for plugin processes
- **appass-systemd-creds** is built for Linux/systemd releases; Darwin release archives omit it
- **approbe** checks local signer IPC liveness for installer live-daemon gating
- Signature operations require admin approval unless the identity has `user_auto_approve:true`
- Plugin system uses external processes communicating via JSON-RPC
- Cross-compilation targets Linux ARM64/AMD64 and Darwin ARM64/AMD64
- Linux CGO binaries use musl static linking; macOS binaries are dynamically linked
- Optional KeyType Library YAML lives under `library/templates/` in the repo or `<APSIGNER_DATA>/library/templates/`; installed optional templates are encrypted under `identities/<identity>/keytypes/` with adjacent state records, and removed keys/templates are archived under `identities/<identity>/deleted/`
- See [USER_CONFIG.md](USER_CONFIG.md) for configuration reference
