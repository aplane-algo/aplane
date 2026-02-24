# System Architecture

This document provides a high-level overview of the aPlane Shell system architecture.

## System Layering

```
┌─────────────────────────────────────────────────────────────┐
│                      UI Layer                               │
│  REPL, TUI (apadmin), CLI modes                          │
│  Command parsing, user interaction, display formatting      │
│                                                             │
│  See: ARCH_UI.md                                            │
├─────────────────────────────────────────────────────────────┤
│                    Engine Layer                             │
│  Business logic, transaction preparation, state management  │
│  UI-agnostic operations, command execution                  │
│                                                             │
│  See: ARCH_ENGINE.md                                        │
├─────────────────────────────────────────────────────────────┤
│                   Provider Layer                            │
│  Signing providers, LSig providers, metadata, mnemonic,     │
│  key generation - modular DSA algorithm support             │
│                                                             │
│  See: ARCH_CRYPTO.md                                 │
├─────────────────────────────────────────────────────────────┤
│              Algorand SDK / Network                         │
│  Transaction encoding, node communication, crypto primitives│
└─────────────────────────────────────────────────────────────┘
```

## Applications

| Application | Purpose | Key Layers Used |
|-------------|---------|-----------------|
| **apshell** | Transaction shell | UI (REPL) + Engine + Providers (LSig) |
| **apsignerd** | Signing server | Providers (Signing, KeyGen, Mnemonic) |
| **apadmin** | Key management TUI | UI (TUI) + Providers |
| **apapprover** | Signing approval daemon | Providers (Signing) |
| **apstore** | Keystore management (init, backup, restore) | Providers (KeyGen) + Crypto |

## Security Boundary

The system enforces a strict security boundary between aPlane Shell (client) and Signer (server):

```
┌──────────────────────┐          ┌──────────────────────┐
│      apshell          │          │    Signer        │
│                      │          │                      │
│  • Builds txns       │  ──────► │  • Stores keys       │
│  • NO private keys   │  SignReq │  • Signs messages    │
│  • LSig construction │  ◄────── │  • Zeros key memory  │
│                      │  Sig     │                      │
└──────────────────────┘          └──────────────────────┘
     Internet-connected              Network-isolated
```

**Key principle**: Private keys never leave the signing device.

## Layer Responsibilities

### UI Layer
- Parse user commands
- Resolve aliases and addresses
- Format output with colors
- Handle interactive prompts
- Delegate to Engine for business logic

### Engine Layer
- Prepare transactions (fee calculation, balance checks)
- Manage caches (aliases, signers, LSig bytecode)
- Coordinate signing operations (client-side assembly optional)
- Submit transactions to network
- Provide UI-agnostic API

### Provider Layer
- Abstract signature algorithms (Falcon, Ed25519, future PQ)
- Handle key loading, signing, zeroing
- Construct LogicSig transactions
- Generate and recover keys from mnemonics
- Auto-register via `init()` pattern

## Directory Structure

```
aplane/
├── cmd/                           # Application entry points
│   ├── apshell/                   # Transaction shell
│   │   └── internal/
│   │       └── repl/              # REPL parser & autocomplete (UI-specific)
│   ├── apsignerd/                 # Signing server
│   ├── apadmin/               # Key management TUI
│   │   └── internal/
│   │       └── tui/               # Bubble Tea TUI (UI-specific)
│   ├── apapprover/            # Signing approval daemon
│   └── apstore/               # Keystore management utility
│
├── internal/                      # Shared library packages
│   ├── ai/                        # AI prompt generation
│   ├── algo/                      # Algorand SDK wrappers
│   ├── algorithm/                 # Algorithm metadata interface
│   ├── auth/                      # Authentication interfaces
│   ├── backup/                    # Key backup utilities
│   ├── cmdspec/                   # Shared ArgSpec types (for command, ai, plugins)
│   ├── command/                   # Command registry, Handler, Context
│   ├── crypto/                    # Cryptographic utilities (AES-GCM, Argon2id)
│   ├── engine/                    # Business logic (Engine layer)
│   ├── genericlsig/               # Generic LogicSig template interface
│   ├── jsapi/                     # JavaScript API bindings
│   ├── keygen/                    # Key generator interface
│   ├── keymgmt/                   # Key management
│   ├── keys/                      # Key file operations
│   ├── keystore/                  # Key storage interface
│   ├── logicsigdsa/               # LogicSig DSA interface
│   ├── lsig/                      # LSig utilities (wrapper, dummy txns)
│   ├── lsigprovider/              # Unified LSig provider registry (single source of truth)
│   ├── tealsubst/                 # Shared TEAL @variable substitution utilities
│   ├── templatestore/             # Encrypted template file storage
│   ├── manifest/                  # Binary manifest utilities
│   ├── mnemonic/                  # Mnemonic handler interface
│   ├── plugin/                    # Plugin system (discovery, manifest, RPC)
│   ├── protocol/                  # IPC protocol definitions
│   ├── scripting/                 # Goja JavaScript runtime
│   ├── security/                  # Security utilities
│   ├── signing/                   # Signing provider interface
│   ├── sshtunnel/                 # SSH tunnel support
│   ├── testutil/                  # Test utilities and mocks
│   ├── transport/                 # IPC transport layer
│   ├── util/                      # Shared utilities, config
│   └── version/                   # Version info injection
│
├── lsig/                          # LogicSig implementations
│   ├── falcon1024/                # Falcon-1024 post-quantum DSA
│   │   ├── derivation/            # Version-specific derivation (v1/)
│   │   ├── family/                # Algorithm constants
│   │   ├── keygen/                # Key generator
│   │   ├── keys/                  # Key processing
│   │   ├── mnemonic/              # Mnemonic handler
│   │   ├── signing/               # Signing provider
│   │   ├── timelock/              # Hybrid timelock TEAL template
│   │   ├── composer.go            # ComposedDSA (DSA + TEAL suffix)
│   │   └── hashlock_v1.go         # Falcon + hashlock composition
│   ├── falcon1024template/        # YAML-based Falcon compositions
│   ├── hashlock/                  # Hashlock LogicSig template (generic)
│   ├── timelock/                  # Timelock LogicSig template (generic)
│   └── multitemplate/             # YAML-based generic templates
│
├── coreplugins/                   # Active core plugins (symlinks)
├── coreplugins_repository/        # Available core plugins
│   └── selfping/                  # Diagnostic self-payment plugin
│
└── examples/
    └── external_plugins/          # External plugin examples (TypeScript)
```

### Package Location Principles

| Package Type | Location | Rationale |
|--------------|----------|-----------|
| **UI-specific** | `cmd/<app>/internal/` | Only used by that application (repl, tui) |
| **Shared library** | `internal/` | Used by multiple apps or coreplugins |
| **Algorithm impl** | `lsig/` | DSA family implementations |
| **Core plugins** | `coreplugins_repository/` | Extend apshell, compiled in with build tags |

The `internal/` packages are shared infrastructure usable by any client (CLI, GUI, web). UI-specific code lives under its respective `cmd/<app>/internal/` directory.

## Configuration

Applications read from `config.yaml` in their data directory:
- apshell: `$APCLIENT_DATA/config.yaml` or `-d <path>`
- apsignerd: `$APSIGNER_DATA/config.yaml` or `-d <path>`

See [USER_CONFIG.md](USER_CONFIG.md) for full reference.

## Transaction Signing Flow (Summary)

Clients send `TxnBytesHex` to the signer and the server derives what to sign based on key type:
- **Ed25519**: sign full transaction bytes (`TX` + msgpack)
- **LogicSig DSA**: sign 32-byte transaction ID hash
- **Generic LogicSig**: no signature

The signer can return both component fields (`Signature`, `LsigBytecode`, `LsigArgsOrdered`) and a pre-assembled `SignedTxn`. Clients may either submit `SignedTxn` directly or assemble locally when they need full control (fee pooling, grouped transactions).

**Endpoints:**
- `POST /sign` — Sign transactions (supports sign, passthrough, and foreign modes)
- `POST /plan` — Preview group building (dummies, fees, group ID) without signing

**Multi-party signing:** Transactions can be marked as **foreign** (`txn_bytes_hex` without `auth_address`) to include them in group building without signing. An optional `lsig_size` hint enables correct dummy calculation for the other party's key type. See [`ARCH_TXNFLOW.md`](ARCH_TXNFLOW.md) for details.

## apsignerd Startup Modes

apsignerd supports two startup modes that share a unified initialization path:

```
┌─────────────────────────────────────────────────────────────────┐
│                     apsignerd Startup                            │
│                                                                  │
│   ┌─────────────────┐         ┌─────────────────┐               │
│   │  Headless Mode  │         │   Locked Mode   │               │
│   │                 │         │                 │               │
│   │  passphrase from│         │  passphrase via │               │
│   │  file or env    │         │  apadmin    │               │
│   └────────┬────────┘         └────────┬────────┘               │
│            │                           │                         │
│            │    ┌──────────────────┐   │                         │
│            └───►│  reloadKeys()    │◄──┘                         │
│                 │                  │                              │
│                 │  1. Load runtime │                              │
│                 │     templates    │                              │
│                 │  2. Scan keys/   │                              │
│                 │  3. Build identity│                             │
│                 │     -scoped maps │                              │
│                 │  4. Initialize   │                              │
│                 │     key session  │                              │
│                 └──────────────────┘                              │
└─────────────────────────────────────────────────────────────────┘
```

| Mode | Passphrase Source | Starts | Use Case |
|------|-------------------|--------|----------|
| **Headless** | `unseal_command_argv` config or `TEST_PASSPHRASE` env | Unlocked | Automation, CI/CD, systemd services |
| **Locked** | apadmin IPC connection | Locked | Interactive operation, manual approval |

**Why unified initialization matters:**
- Both modes use the same `reloadKeys()` function
- Ensures runtime templates are loaded before key scanning
- Guarantees consistent `keyTypes` map population
- Prevents divergent behavior between headless and interactive modes

**Identity-scoped key caches:**

The in-memory key caches are two-level maps indexed by identity then address:
```
keys:         map[identity]map[address]keyfilePath
keyTypes:     map[identity]map[address]keyType
keyLsigSizes: map[identity]map[address]lsigSize
```

Today all keys are loaded under `DefaultIdentityID` (`"default"`) since the flat `users/` directory has no identity partitioning. HTTP handlers extract the authenticated identity from request context; IPC handlers use the connection's identity. This plumbing is ready for multi-tenant key isolation when needed — the disk layout and `FileKeyStore` are unchanged.

See [USER_USER_CONFIG.md](USER_USER_CONFIG.md#headless-operation) for headless configuration details.

## Adding New Features

| To Add | Layer | Documentation |
|--------|-------|---------------|
| New command | UI | ARCH_UI.md |
| New operation | Engine | ARCH_ENGINE.md |
| New algorithm | Provider | ARCH_CRYPTO.md |
| New config option | Config | USER_CONFIG.md |

## Related Documentation

- [ARCH_UI.md](ARCH_UI.md) - UI layer details (REPL, TUI, CLI)
- [ARCH_ENGINE.md](ARCH_ENGINE.md) - Engine layer details
- [ARCH_TXNFLOW.md](ARCH_TXNFLOW.md) - Transaction signing flow details
- [ARCH_CRYPTO.md](ARCH_CRYPTO.md) - Provider layer details (DSA algorithms)
- [USER_CONFIG.md](USER_CONFIG.md) - Configuration reference
- [README.md](../README.md) - User-facing documentation
