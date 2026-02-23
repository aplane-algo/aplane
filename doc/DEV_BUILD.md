# Build Instructions

This project contains five applications:
1. **apshell** - Main CLI tool for aPlane Shell post-quantum transactions
2. **apsignerd** - Remote key management and signing server
3. **apadmin** - TUI/batch admin tool for key generation and management
4. **apapprover** - CLI tool for approving signing requests
5. **apstore** - Keystore management (init, backup, restore, passfile, verify, changepass, inspect, list)

## Project Structure

```
aplane/
├── cmd/
│   ├── apshell/              # CLI application
│   ├── apsignerd/            # Key signer server
│   ├── apadmin/          # Admin TUI and batch mode
│   ├── apapprover/       # Signing approval CLI
│   └── apstore/          # Keystore management utility
├── internal/
│   ├── signing/             # Signature provider registry
│   ├── lsig/                # LogicSig provider registry
│   ├── transaction/         # Transaction building and submission
│   ├── keys/                # Key management utilities
│   ├── keygen/              # Key generation registry
│   ├── mnemonic/            # Mnemonic handlers
│   ├── algorithm/           # Algorithm metadata
│   ├── tui/                 # Terminal UI components
│   ├── transport/           # IPC client transport
│   └── util/                # Shared utilities
├── lsig/
│   └── falcon1024/          # Falcon-1024 post-quantum implementation
│       ├── signing/         # Signing provider
│       ├── derivation/      # LogicSig derivation
│       └── keys/            # Key generation
├── coreplugins/             # Enabled core plugins (symlinks)
├── coreplugins_repository/  # Available core plugins
├── Makefile                 # Build automation
└── doc/                     # Documentation
```

## Building

All builds use **musl-based static linking** by default for maximum portability and to avoid glibc runtime dependencies.

### Prerequisites

#### For x86_64 builds:
```bash
# Install musl compiler (Debian/Ubuntu)
sudo apt-get install musl-tools

# Or download from https://musl.cc/
curl -O https://musl.cc/x86_64-linux-musl-cross.tgz
tar -xzf x86_64-linux-musl-cross.tgz
export PATH="$PWD/x86_64-linux-musl-cross/bin:$PATH"
```

#### For ARM64 builds:
```bash
# Download ARM64 musl cross-compiler from https://musl.cc/
curl -O https://musl.cc/aarch64-linux-musl-cross.tgz
tar -xzf aarch64-linux-musl-cross.tgz
sudo mv aarch64-linux-musl-cross /opt/
export PATH="/opt/aarch64-linux-musl-cross/bin:$PATH"

# Verify installation
aarch64-linux-musl-gcc --version
```

### Option 1: Using Makefile (recommended)

```bash
# Build all applications (uses musl static linking)
make all

# Build only apshell (core, no plugins)
make apshell-core

# Build apshell with all enabled plugins
make apshell

# Build only apsignerd
make apsignerd

# Build admin tools
make apadmin
make apapprover
make apstore

# Clean binaries
make clean
```

### Option 2: Manual build commands

```bash
# Build apshell CLI (core, no plugins) with musl static linking
CGO_ENABLED=1 CC=musl-gcc go build -ldflags '-extldflags "-static"' \
  -o apshell ./cmd/apshell

# Build apshell with specific core plugins
CGO_ENABLED=1 CC=musl-gcc go build -ldflags '-extldflags "-static"' \
  -tags "selfping" -o apshell ./cmd/apshell

# Build apsignerd with musl static linking
CGO_ENABLED=1 CC=musl-gcc go build -ldflags '-extldflags "-static"' \
  -o apsignerd ./cmd/apsignerd

# Build apsignerd ARM64 cross-compile with musl
CGO_ENABLED=1 GOOS=linux GOARCH=arm64 CC=aarch64-linux-musl-gcc \
  go build -ldflags '-extldflags "-static"' -o apsignerd-arm64 ./cmd/apsignerd

# Build admin tools
CGO_ENABLED=1 CC=musl-gcc go build -ldflags '-extldflags "-static"' \
  -o apadmin ./cmd/apadmin
CGO_ENABLED=1 CC=musl-gcc go build -ldflags '-extldflags "-static"' \
  -o apapprover ./cmd/apapprover
CGO_ENABLED=1 CC=musl-gcc go build -ldflags '-extldflags "-static"' \
  -o apstore ./cmd/apstore

# Verify static linking (should output: "not a dynamic executable")
ldd apshell
ldd apsignerd

# Clean
rm -f apshell apsignerd apsignerd-arm64 apadmin apapprover apstore
```

## Running

### apshell CLI
```bash
# Set data directory (or use -d flag)
export APCLIENT_DATA=~/.apshell

# Start interactive REPL
./apshell

# Or with explicit data directory
./apshell -d ~/.apshell

# List available signing keys (auto-connects to local signer)
apshell> keys

# Send transactions
apshell> send 10 algo from mykey to RECEIVER...

# Connect to remote signer via SSH tunnel
apshell> connect remotehost
```

### Signer Server
```bash
# Set data directory (or use -d flag)
export APSIGNER_DATA=~/.apsigner

# Start the signer server
./apsignerd

# Or with explicit data directory
./apsignerd -d ~/.apsigner
```

### SignerAdmin (Key Management)
```bash
# Set data directory (uses same as apsignerd)
export APSIGNER_DATA=~/.apsigner

# Interactive TUI mode
./apadmin

# Or with explicit data directory
./apadmin -d ~/.apsigner

# Batch mode for scripting
./apadmin -d ~/.apsigner --batch list
./apadmin -d ~/.apsigner --batch generate falcon1024-v1
```

### ApApprover (Signing Approval)
```bash
# Set data directory
export APSIGNER_DATA=~/.apsigner

# Start approver (connects via IPC, prompts for passphrase)
./apapprover
```

### SignerStore (Key Backup and Passphrase Management)
```bash
# Set data directory
export APSIGNER_DATA=~/.apsigner

# Backup all keys
./apstore backup all /path/to/backup

# Or with explicit data directory
./apstore -d ~/.apsigner backup all /path/to/backup

# Backup specific key
./apstore backup ABC123... /path/to/backup

# Restore keys
./apstore restore all /path/to/backup

# Verify backup
./apstore verify /path/to/backup --deep

# Change passphrase
./apstore changepass
```

## Plugin System

aPlane Shell supports optional plugins via build tags:

```bash
# Build with core plugins (currently only selfping)
go build -tags "selfping" -o apshell ./cmd/apshell
```

**Core plugins** (compiled-in via build tags):
- `selfping`: Demo self-payment plugin

**External plugins** (runtime subprocess, any language):
- `tinymanswap`: Tinyman DEX swap integration
- `reti`: Reti staking pool operations
- `echo-plugin`: Demo plugin for testing

External plugins are discovered from:
1. `$APCLIENT_DATA/plugins`
2. `./plugins`
3. `/usr/local/lib/apshell/plugins`

See [ARCH_PLUGINS.md](ARCH_PLUGINS.md) for details on both core and external plugins.

## Security Setup

Enable memory locking to prevent key material from being swapped to disk:

```bash
# For apsignerd (stores keys)
sudo setcap cap_ipc_lock+ep ./apsignerd

# For apadmin (generates keys)
sudo setcap cap_ipc_lock+ep ./apadmin
```

## Notes

- **apshell** never touches private keys - LogicSig bytecode is fetched from Signer on-demand and cached in memory
- **apsignerd** stores all private keys encrypted at rest
- **apadmin** provides TUI and batch mode for key management
- **apapprover** handles signing approval via IPC
- **apstore** creates encrypted backups of the keystore and manages passphrases
- Signature operations require manual approval via apapprover (unless txn_auto_approve/group_auto_approve is enabled)
- Plugin system uses Go build tags for conditional compilation
- Cross-compilation supported ARM64 platforms
- **All builds use musl static linking** for maximum portability - binaries have no runtime dependencies
- Static binaries can be copied to any Linux system (including older distributions) without library conflicts
- No `lsig/` directory is created at runtime - all LogicSig bytecode is session-cached in memory
- See [CONFIG.md](CONFIG.md) for configuration reference
