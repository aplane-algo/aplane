<p align="center">
  <img src="https://raw.githubusercontent.com/aplane-algo/aplane.io/main/img/aplane.png" alt="APlane" width="400">
</p>

<sub><a href="docs/USER_QUICKSTART.md">APlane QuickStart</a></sub>&nbsp;&nbsp;<sub><a href="https://github.com/aplane-algo/aplanesdk">SDK Repo</a></sub>
# APlane - A Signing System for Algorand 

APlane is a flexible command-line signing system for Algorand. In addition to standard Ed25519 keys, it supports Falcon post-quantum signatures, generic LogicSig templates (e.g. allowlists, timelocks, hashlocks, and custom templates), and composed signature + LogicSig authorization schemes (e.g. allowlist-constrained Falcon, Falcon+ed25519 hybrid, etc.)

It is designed for security-focused operations where private keys can be isolated on dedicated signing machines with restricted network exposure.

## EXPERIMENTAL Status

APlane is currently in alpha and should be considered experimental.  The Algorand Foundation has released its <a href="https://algorand.co/blog/algorand-post-quantum-cryptography-roadmap">2026 post-quantum roadmap</a>, which introduces new key types and LogicSig templates that APlane will adopt and evolve with. After those standards are in place, APlane will move toward a production-oriented footing.

- Release-to-release compatibility should be considered best-effort but is not currently guaranteed.
- Breaking changes may still occur, especially across CLI, SDK, config, and plugin surfaces.
- The project is security-conscious, but it has not undergone a full external security audit.

## Key Features

- **Post-Quantum Ready**: Supports Falcon-1024 signatures via Algorand Logic Sigs, protecting against future quantum threats
- **General LogicSig Capability**: Supports general LogicSig signing; built-in timelock, hashed timelock, 
combo Falcon-hashlock; supports user-defined custom LogicSigs
- **Enables key isolation**: Signing operations (and private keys) can be kept on dedicated purpose-built machines with restrictive firewalls and single-port exposure
- **Supports App Interaction Primitives**: Read Algorand app state, call contracts via raw or ARC-4/ABI methods, 
deploy apps from TEAL source or compiled AVM bytecode, execute grouped flows such as companion-payment app calls
- **Agent Friendly**: SDKs enable agents to send transactions securely without ever seeing private key material. MCP enables LLMs to generate transactions and interact with the system
- **Flexible approval engine**: Supports both manual human transaction approval and policy-driven auto-approval
- **Extensible Plugin Architecture**: For more complex flows, external sandboxed plugins are supported via a documented JSON-RPC plugin interface
- **JavaScript Scripting**: Complex operations can be automated with a sandboxed JS runtime

## Components

| Component | Description |
|-----------|-------------|
| **apshell** | Interactive shell for building and submitting transactions (no private keys) |
| **apconsole** | Unified TUI console combining apshell, signer admin, and local daemon status |
| **apsigner** | Signing daemon with HTTP API, admin protocol, and SSH tunnel server |
| **apadmin** | TUI admin client over IPC or SSH admin transport |
| **apapprover** | Optional approval-only admin client over IPC or SSH admin transport |
| **apstore** | Keystore management (init, backup, restore, passphrase management) |
| **appolicy** | Offline policy checker/editor TUI |
| **appass** | Passphrase auto-unlock setup TUI |

### SDKs

Go, TypeScript, and Python SDKs live in the separate [https://github.com/aplane-algo/aplanesdk](https://github.com/aplane-algo/aplanesdk) repository for integrating with the signing server programmatically. Python and TypeScript packages are also available on PyPI and npmjs:

```bash
pip install aplanesdk
npm install aplanesdk
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                 Signer Host (Secure Zone)                   │
│                                                             │
│  apsigner: signer daemon                                    │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ HTTP signing API    • Admin protocol                  │  │
│  │ SSH tunnel server   • SSH admin subsystem             │  │
│  │ Identity runtime    • Approval + audit                │  │
│  │ Encrypted keys      • Locked memory • Key zeroing     │  │
│  └───────────────────────────────────────────────────────┘  │
│                                                             │
│  Local signer-host tools: apstore, appass, optional         │
│  apadmin over IPC                                           │
└───────────────┬──────────────────────────────┬──────────────┘
                │ SSH tunnel + HTTP            │ SSH admin     
                │ transaction planning/sign    │ or local IPC  
                │                              │               
┌───────────────▼──────────────────────────────▼──────────────┐
│                   Client / Operator Zone                    │
│                                                             │
│   apshell                         apadmin / apapprover      │
│  ┌──────────────────────┐         ┌──────────────────────┐  │
│  │ REPL, JS, MCP,       │         │ Remote admin client  │  │
│  │ plugins, network ops │         │ approval + key mgmt  │  │
│  └──────────────────────┘         └──────────────────────┘  │
│                                                             │
│  Plugins run as separate processes. No signer-managed keys. │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Security Model

### Signer-Isolated Private Keys

| Component | Has Private Keys | Purpose |
|-----------|------------------|---------|
| **apsigner** | Yes (encrypted) | Signs transactions, requires approval |
| **apshell / sdk / mcp** | No | Builds transactions, submits to network |

### Safety

| Protection | Implementation |
|------------|----------------|
| Keys encrypted at rest | AES-256-GCM with master key (Argon2id, memory-hard) |
| Memory protection | `mlockall()` prevents swap, core dumps disabled |
| Key material zeroing | Private keys wiped immediately after signing |
| Transaction policy | Linter warns on rekey, close-to, etc |
| Manual approval | Every signature requires explicit approval by default |

### Approval Workflow

By default, every signing request requires explicit approval. An operator uses **apadmin** or **apapprover** (over IPC locally, or over SSH remotely) to review pending requests and approve or reject them. Policy-driven auto-approval can be configured per-identity to allow certain transaction patterns without manual intervention. See [ARCH_SECURITY.md](docs/ARCH_SECURITY.md) for details.

### SSH Tunnel

apshell and apadmin can connect to apsigner over an SSH tunnel, allowing the signer host to expose only a single SSH port. The tunnel carries both the HTTP signing API and the admin transport. Connection parameters (host, SSH port, signer port) are configured in `config.yaml`. See [USER_CONFIG.md](docs/USER_CONFIG.md) for setup details.

## Supported Operations

### Transaction Types
- ALGO and ASA transfers (single, batch, atomic groups)
- ASA opt-in/opt-out with balance handling
- Account rekeying and unrekeying
- Participation key registration (online/offline)
- Mixed atomic groups (Falcon + Ed25519 in same group)

### Key Types
- **ed25519**: Native Algorand keys
- **falcon1024**: Protocol-native post-quantum signatures on consensus v42+
- **aplane.falcon1024.v1**: Falcon-1024 signatures via LogicSig
- **general LogicSigs**: timelock, hashlock, user-loaded custom TEAL
- **hybrid DSA+LogicSig**: falcon1024-hashlock, falcon1024-timelock

### Automation & Integration
- JavaScript scripting with full transaction API
- Line-based command scripts (.apshell files)
- MCP (Model Context Protocol) surface in apshell for LLM tool-use integration

## Quick Start

For installation and a first testnet transaction flow, see
[USER_QUICKSTART.md](docs/USER_QUICKSTART.md). For the offline AlgoKit LocalNet
flow, see [USER_QUICKSTART_LOCALNET.md](docs/USER_QUICKSTART_LOCALNET.md).

## Plugin System

APlane supports external plugins — standalone executables that communicate via JSON-RPC over stdin/stdout. Plugins can be written in any language and are discovered at runtime.

Install plugins to one of the discovery paths (`$APCLIENT_DATA/plugins/`, `./plugins/`, or `/usr/local/lib/aplane/plugins/`):
```bash
cp -r examples/external_plugins/echo-plugin $APCLIENT_DATA/plugins/
cp -r examples/external_plugins/reti $APCLIENT_DATA/plugins/
```

This repo includes both a minimal reference plugin (`echo-plugin`) and a more
concrete protocol integration example (`reti`). Use `echo-plugin` to
understand the minimal JSON-RPC shape; use `reti` as the better reference for
real networked transaction-building plugins.

## Documentation

All documentation is in the [`docs/`](docs/) directory.

### Architecture
- [ARCH_OVERVIEW.md](docs/ARCH_OVERVIEW.md) - System architecture and layering
- [ARCH_DATA_MODEL.md](docs/ARCH_DATA_MODEL.md) - System-wide durable, runtime, wire, and cache data model
- [ARCH_SECURITY.md](docs/ARCH_SECURITY.md) - Authentication and security model
- [ARCH_CRYPTO.md](docs/ARCH_CRYPTO.md) - Signing providers and key types
- [ARCH_ENGINE.md](docs/ARCH_ENGINE.md) - Business logic layer
- [ARCH_REPL.md](docs/ARCH_REPL.md) - apshell REPL architecture
- [ARCH_MCP.md](docs/ARCH_MCP.md) - apshell MCP server and tool surface
- [ARCH_TUI.md](docs/ARCH_TUI.md) - signer admin TUI (apadmin)
- [ARCH_PLUGINS.md](docs/ARCH_PLUGINS.md) - External plugin system
- [ARCH_APP_INTERACTION.md](docs/ARCH_APP_INTERACTION.md) - Application interaction (read state, call contracts, deploy)
- [ARCH_SENTRY.md](docs/ARCH_SENTRY.md) - Guarded signing and sentry node architecture
- [ARCH_BOUNDED_DSA.md](docs/ARCH_BOUNDED_DSA.md) - Bounded DSA contracts, effect model, and external contract-admin ceremonies
- [ARCH_TXNFLOW.md](docs/ARCH_TXNFLOW.md) - Transaction signing flow details

### Specification
- [ARCH_SPEC.md](docs/ARCH_SPEC.md) - Cross-cutting implementation map and subsystem ownership
- [ARCH_CONTRACTS.md](docs/ARCH_CONTRACTS.md) - Compatibility contracts (on-disk, config, SDK, plugin, MCP) with TOC into extracted docs
- [ARCH_HTTP_API.md](docs/ARCH_HTTP_API.md) - HTTP wire shapes, status codes, identity routing, and sign cancellation
- [ARCH_ADMIN_PROTOCOL.md](docs/ARCH_ADMIN_PROTOCOL.md) - apsigner admin RPC catalog, payload shapes, writable-settings rules
- [FORMALIZATION_ROADMAP.md](docs/FORMALIZATION_ROADMAP.md) - Formal-assurance roadmap and scope
- [FORMAL_TXN_PLANNING_MODEL.md](docs/FORMAL_TXN_PLANNING_MODEL.md) - Precise transaction-planning model and invariants
- [FORMAL_POLICY_MODEL.md](docs/FORMAL_POLICY_MODEL.md) - Precise policy precedence model and invariants
- [FORMAL_SIGNING_AUTHORITY_MODEL.md](docs/FORMAL_SIGNING_AUTHORITY_MODEL.md) - Precise existing-key signing authority model
- [FORMAL_APPROVAL_COORDINATOR_MODEL.md](docs/FORMAL_APPROVAL_COORDINATOR_MODEL.md) - Approval delivery, cancellation, fail-all, and progress model
- [FORMAL_TRACEABILITY.md](docs/FORMAL_TRACEABILITY.md) - Invariant status, code anchors, test coverage, and open gaps
- [FORMAL_TEST_GAPS.md](docs/FORMAL_TEST_GAPS.md) - Concrete sketches for each missing test, in recommended write order
- [FORMAL_TLA_SIGN_BOUNDARY_MODEL.md](docs/FORMAL_TLA_SIGN_BOUNDARY_MODEL.md) - First machine-checkable TLA+ artifact (sign boundary)
- [FORMAL_TLA_POLICY_PRECEDENCE_MODEL.md](docs/FORMAL_TLA_POLICY_PRECEDENCE_MODEL.md) - Second machine-checkable TLA+ artifact (policy precedence, including real I9)
- [FORMAL_TLA_COMPOSITION_MODEL.md](docs/FORMAL_TLA_COMPOSITION_MODEL.md) - Third machine-checkable TLA+ artifact (joins sign boundary + policy precedence)
- [FORMAL_TLA_SESSION_OWNERSHIP_MODEL.md](docs/FORMAL_TLA_SESSION_OWNERSHIP_MODEL.md) - Machine-checked single-admin ownership and displacement model

### User Guides
- [USER_INSTALL.md](docs/USER_INSTALL.md) - Installation guide
- [USER_CONFIG.md](docs/USER_CONFIG.md) - Configuration guide
- [USER_CONFIG_REFERENCE.md](docs/USER_CONFIG_REFERENCE.md) - Configuration reference
- [USER_POLICY.md](docs/USER_POLICY.md) - Signer policy guide
- [USER_TRANSFER_ROUTING.md](docs/USER_TRANSFER_ROUTING.md) - Transfer routing deep dive
- [USER_COMMANDS.md](docs/USER_COMMANDS.md) - Command reference
- [USER_JSAPI.md](docs/USER_JSAPI.md) - JavaScript API reference for `apshell`
- [USER_STORE_MGMT.md](docs/USER_STORE_MGMT.md) - Keystore management, backup, and recovery
- [USER_KEYTYPES.md](docs/USER_KEYTYPES.md) - Key type and template management
- [USER_LOGGING.md](docs/USER_LOGGING.md) - Logging configuration

### Developer Guides
- [DEV_BUILD.md](docs/DEV_BUILD.md) - Build instructions
- [DEV_TESTING.md](docs/DEV_TESTING.md) - Testing guide
- [DEV_KEYTYPES.md](docs/DEV_KEYTYPES.md) - Adding new key types and LogicSig templates

### Transaction Details
- [TXN_MIXED_GROUPS.md](docs/TXN_MIXED_GROUPS.md) - Mixed signature atomic groups
- [TXN_FEE_SPLITTING.md](docs/TXN_FEE_SPLITTING.md) - Fee distribution
- [TXN_BALANCE_VERIFICATION.md](docs/TXN_BALANCE_VERIFICATION.md) - Balance checks
- [TXN_BYTES_HEX.md](docs/TXN_BYTES_HEX.md) - Transaction encoding

## Requirements

- Go 1.25+
- CGO enabled (for Falcon-1024 cryptography)
- Linux or macOS

## Project Governance

APlane is an open-source project stewarded by the APlane Project.

See [DISCLAIMER.md](DISCLAIMER.md) for important information regarding risk, liability, and usage.

## License

This project is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later).
