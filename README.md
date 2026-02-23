# aPlane - Secure Signing Infrastructure for Algorand

aPlane is a suite of CLI tools for secure key management and transaction signing in the Algorand ecosystem. It supports standard Ed25519 keys, Falcon-1024 post-quantum signatures, and custom logic signatures (eg. timelock, hashlock, etc).

Designed for security-first operations where private keys are isolated on dedicated REST-based signing devices with restricted network exposure.

## Key Features

- **Post-Quantum Ready**: Falcon-1024 signatures via LogicSig, protecting against future quantum threats
- **Agent Friendly**: Enables agents to sign transactions securely 
- **Network hardened**: Signing server can run on machines with restrictive firewalls and single-port exposure
- **Flexible approval engine**: Supports both manual transaction-by-transaction approval and policy-driven auto-approval
- **JavaScript Scripting**: Automate complex operations with a sandboxed JS runtime
- **AI Code Generation**: Describe operations in natural language, get executable JavaScript
- **Plugin Architecture**: Extend with DeFi integrations (Reti staking, Tinyman swaps)
- **Mixed Transaction Groups**: Combine Ed25519 and Falcon signatures in atomic transactions

## Components

| Component | Description |
|-----------|-------------|
| **apshell** | Interactive shell for building and submitting transactions (no private keys) |
| **apsignerd** | Signing server with REST API and IPC interface |
| **apadmin** | TUI for key management and transaction approval |
| **apstore** | Keystore management (init, backup, restore, passphrase management) |

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Signer (Secure Zone)                     │
│                                                             │
│  apsignerd           apadmin                                │
│  ┌────────────┐      ┌────────────┐                         │
│  │ REST API   │◄────►│ TUI        │                         │
│  │ IPC Socket │      │ Approval   │                         │
│  └────────────┘      └────────────┘                         │
│        │                                                    │
│        │  • Encrypted key storage (AES-256-GCM)             │
│        │  • Memory locked (never swapped)                   │
│        │  • Keys zeroed after use                           │
│        │  • Manual approval by default                      │
└────────┼────────────────────────────────────────────────────┘
         │
         │ SSH Tunnel or localhost
         │ (signatures only, never keys)
         │
┌────────▼────────────────────────────────────────────────────┐
│                 apshell (Client Zone)                       │
│                                                             │
│  • Transaction building            • JavaScript scripting   │
│  • Network communication           • AI code generation     │
│  • Plugin execution                • NO private keys        │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Security Model

### Zero Private Key Exposure

| Component | Has Private Keys | Purpose |
|-----------|------------------|---------|
| **apsignerd** | Yes (encrypted) | Signs transactions, requires approval |
| **apshell** | No | Builds transactions, submits to network |

### Defense in Depth

| Protection | Implementation |
|------------|----------------|
| Keys encrypted at rest | AES-256-GCM with master key (Argon2id, memory-hard) |
| Memory protection | `mlockall()` prevents swap, core dumps disabled |
| Key material zeroing | Private keys wiped immediately after signing |
| Transaction policy | Linter warns on rekey, close-to, high fees |
| Manual approval | Every signature requires explicit approval by default |

### Threat Model

| Attack Vector | Protected | How |
|---------------|-----------|-----|
| Client machine compromised | Yes | Keys never on client |
| Network traffic intercepted | Yes | Only signatures transmitted |
| Malicious transaction | Yes | Policy linter + manual approval |
| Memory dump on signer | Yes | Memory locked, keys zeroed |
| Brute force (SSH) | Yes | Token + public key 2FA, rate limiting |

## Supported Operations

### Transaction Types
- ALGO and ASA transfers (single, batch, atomic groups)
- ASA opt-in/opt-out with balance handling
- Account rekeying and unrekeying
- Participation key registration (online/offline)
- Mixed atomic groups (Falcon + Ed25519 in same group)

### Key Types
- **ed25519**: Native Algorand keys
- **falcon1024-v1**: Post-quantum signatures via LogicSig
- **timelock-v1**: Time-locked escrow (generic LogicSig)
- **hashlock-v1**: Hash-locked payments (generic LogicSig)

### Automation
- JavaScript scripting with full transaction API
- AI-assisted code generation (Claude/GPT)
- Line-based command scripts (.apshell files)

## Quick Start

### Build

```bash
make all                 # Build all components
make apshell apsignerd apadmin  # Build specific components
```

### Initialize Keystore

```bash
# Create a new keystore with passphrase
./apstore init -d /path/to/signer-data

# Start the signing server
./apsignerd -d /path/to/signer-data

# In another terminal, manage keys via TUI
./apadmin -d /path/to/signer-data
```

### Connect apshell

```bash
# Local connection
./apshell -d /path/to/shell-data
> connect localhost:11270

# Remote connection via SSH tunnel
> connect user@remote-signer:2222
```

### Basic Operations

```bash
# In apshell REPL
> alias alice AAAA...
> alias bob BBBB...
> send 10 algo from alice to bob
> balance alice
```

### JavaScript Scripting

```bash
# Run a script file
> js scripts/distribute.js

# Inline JavaScript
> js { send("alice", "bob", algo(10)) }

# AI-generated code
> ai send 5 algo from alice to bob and check the balance
```

## Plugin System

aPlane supports two types of plugins:

### Core Plugins (Compile-time)
Built into the binary via Go build tags. Enable/disable with:
```bash
make enable-selfping    # Enable plugin
make disable-selfping   # Disable plugin
make apshell            # Rebuild with enabled plugins
```

### External Plugins (Runtime)
Separate executables communicating via JSON-RPC. Install to `$APCLIENT_DATA/plugins/`:
```bash
cp -r examples/external_plugins/reti ./plugins/
```

Available integrations:
- **Reti**: Staking pool deposits/withdrawals
- **Tinyman**: Token swaps

## Documentation

All documentation is in the [`doc/`](doc/) directory.

### Architecture
- [ARCH_OVERVIEW.md](doc/ARCH_OVERVIEW.md) - System architecture and layering
- [ARCH_SECURITY.md](doc/ARCH_SECURITY.md) - Authentication and security model
- [ARCH_CRYPTO.md](doc/ARCH_CRYPTO.md) - Signing providers and key types
- [ARCH_ENGINE.md](doc/ARCH_ENGINE.md) - Business logic layer
- [ARCH_UI.md](doc/ARCH_UI.md) - User interface architecture
- [ARCH_PLUGINS.md](doc/ARCH_PLUGINS.md) - Plugin system (core and external)
- [ARCH_POLICY.md](doc/ARCH_POLICY.md) - Transaction policy linter
- [ARCH_AI_SCRIPTING.md](doc/ARCH_AI_SCRIPTING.md) - JavaScript API and AI integration
- [ARCH_TXNFLOW.md](doc/ARCH_TXNFLOW.md) - Transaction signing flow details

### User Guides
- [USER_CONFIG.md](doc/USER_CONFIG.md) - Configuration guide
- [USER_CONFIG_REFERENCE.md](doc/USER_CONFIG_REFERENCE.md) - Configuration reference
- [USER_STORE_MGMT.md](doc/USER_STORE_MGMT.md) - Keystore management, backup, and recovery

### Developer Guides
- [DEV_BUILD.md](doc/DEV_BUILD.md) - Build instructions
- [DEV_TESTING.md](doc/DEV_TESTING.md) - Testing guide
- [DEV_New_DSA_LSig.md](doc/DEV_New_DSA_LSig.md) - Adding new DSA LogicSig schemes
- [DEV_New_GenericLSig.md](doc/DEV_New_GenericLSig.md) - Adding new generic LogicSig templates

### Transaction Details
- [TXN_MIXED_GROUPS.md](doc/TXN_MIXED_GROUPS.md) - Mixed signature atomic groups
- [TXN_FEE_SPLITTING.md](doc/TXN_FEE_SPLITTING.md) - Fee distribution
- [TXN_BALANCE_VERIFICATION.md](doc/TXN_BALANCE_VERIFICATION.md) - Balance checks
- [TXN_BYTES_HEX.md](doc/TXN_BYTES_HEX.md) - Transaction encoding

## Requirements

- Go 1.25+
- CGO enabled (for Falcon-1024 cryptography)
- Linux recommended for memory protection features

## License

AGPL-3.0-or-later

## Support

- Issues: [GitHub Issues](https://github.com/aplane-algo/aplane/issues)
