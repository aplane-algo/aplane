# Repository Guidelines

Guidelines for AI agents and contributors working on the aPlane codebase.

## Project Structure & Module Organization
aPlane is the overarching Project name. Its goal is to provide an ops substrate that puts safety first.
Signer is one of the two major components; it holds keys and signs transactions.
Apshell is the other major component; it provides a shell-like interface to generate and submit transactions to the network.

### Binaries (`cmd/`)
- `cmd/apshell/`: Interactive shell and scripting environment for Algorand transactions
- `cmd/apsignerd/`: Signing server with approval workflow and key management
- `cmd/apadmin/`: TUI-based admin tool for key management and apsignerd control
- `cmd/apapprover/`: Standalone approval interface
- `cmd/apstore/`: Keystore management (init, backup, restore, verify, changepass, inspect, list)
- `cmd/pass-file/`: Dev-only plaintext passphrase helper (insecure)
- `cmd/pass-systemd/`: Production passphrase helper using systemd-creds (TPM2/host key)
- `cmd/configdoc/`: Documentation generator for configuration
- `cmd/plugin-checksum/`: Checksum generator for plugins

### Internal Packages (`internal/`)
- `internal/ai/`: AI integration for code generation
- `internal/algo/`: Algorand SDK wrappers and client utilities
- `internal/algorithm/`: Algorithm utilities
- `internal/auth/`: Authentication interfaces (`Authenticator`, `TokenAuthenticator`)
- `internal/backup/`: Backup and restore functionality
- `internal/cmdspec/`: Command specification definitions
- `internal/command/`: Command registry and plugin system
- `internal/crypto/`: Encryption (AES-256-GCM), secure memory, passphrase handling
- `internal/engine/`: Core business logic shared by apshell commands
- `internal/genericlsig/`: Generic LogicSig registry (timelock, hashlock, etc.)
- `internal/jsapi/`: JavaScript API bindings for scripting
- `internal/keygen/`: Key generation (Ed25519, Falcon-1024)
- `internal/keymgmt/`: Key management operations
- `internal/keys/`: Key file operations, scanning, type detection
- `internal/keystore/`: Key storage interfaces (`KeyStore`, `FileKeyStore`)
- `internal/logicsigdsa/`: LogicSig-based DSA registry
- `internal/lsig/`: LogicSig utilities
- `internal/manifest/`: Manifest handling
- `internal/mnemonic/`: Mnemonic handling (BIP-39)
- `internal/plugin/`: Plugin discovery, manifest, JSON-RPC protocol
- `internal/protocol/`: IPC message types
- `internal/scripting/`: Goja JavaScript runtime integration
- `internal/security/`: Security utilities (memory protection, core dump prevention)
- `internal/signing/`: Signature provider interface and registry (Ed25519, Falcon-1024)
- `internal/sshtunnel/`: SSH tunnel server/client for remote access
- `internal/tealsubst/`: Shared TEAL @variable substitution utilities
- `internal/testutil/`: Test utilities and mocks
- `internal/transport/`: IPC client for Unix socket communication
- `internal/util/`: Shared utilities (config, tokens, formatting, caching)
- `internal/version/`: Version information

### Cryptographic Modules (`lsig/`)
- `lsig/falcon1024/`: Falcon-1024 post-quantum signature implementation
  - `family/`: Family registration and metadata
  - `signing/`: Signing provider implementation
  - `keys/`: Key derivation and processing
  - `keygen/`: Key generation
  - `mnemonic/`: Mnemonic handling
  - `derivation/`: Version-specific derivation logic
- `lsig/timelock/`: Timelock LogicSig template
- `lsig/hashlock/`: Hashlock LogicSig template
- `lsig/multitemplate/`: Multi-template provider for generic LogicSigs

### Other Directories
- `doc/`: Architecture and usage documentation
- `sdk/python/`: Python SDK for signer integration
- `test/integration/`: Integration tests with test harness
- `examples/`: JavaScript scripts and external plugin examples
- `coreplugins/`: Active core plugins (symlinks to `coreplugins_repository/`)
- `coreplugins_repository/`: Available core plugins
- `analysis/`: Security analysis tools (keyzero, keylog, insecurerand)
- `docker/`: Docker playground configuration
- `resources/`: TEAL programs and other resources
- `temp/`: Untracked directory for temporary files

## Build, Test, and Development Commands

### Building
```bash
make all              # Build everything
make apshell           # Build apshell with enabled plugins
make apshell-core      # Build apshell without plugins (minimal)
make apsignerd         # Build signing server
make apadmin       # Build admin TUI
make apstore       # Build backup/restore tool
```

### Cross-Compilation (ARM64)
```bash
make bin-arm64        # Build all binaries for ARM64
make bin-amd64        # Build all binaries for AMD64
```

### Testing
```bash
make test             # Run all tests
make unit-test        # Run unit tests only
make integration-test # Run integration tests (requires .env.test)
go test ./...         # Direct test invocation
go test -race ./...   # With race detector
```

### Security Analysis
```bash
make security-analysis    # Run all security analyzers
make analyze-keyzero      # Check key material zeroing
make analyze-keylog       # Check for keys in logs
make analyze-insecurerand # Check for insecure random
```

### Static Analysis
```bash
go vet ./...              # Go vet
staticcheck ./...         # Staticcheck
golangci-lint run ./...   # Golangci-lint
~/go/bin/gosec ./...      # Security scanner
```

### Plugin Management
```bash
make list-plugins         # List available/active plugins
make enable-selfping      # Enable a plugin
make disable-selfping     # Disable a plugin
make disable-all          # Disable all plugins
```

## CLI Conventions

### apshell Commands
- Interactive REPL with command history
- Requires data directory: `-d <path>` or `APCLIENT_DATA` env var
- Config file: `<data_dir>/config.yaml`
- Commands: `connect`, `network`, `balance`, `send`, `keyreg`, `sign`, `run`, `help`
- JavaScript scripting via `js script.js`
- Tab completion for addresses, commands, assets

### apsignerd
- Starts signing server with HTTP REST API and IPC interface
- Requires data directory: `-d <path>` or `APSIGNER_DATA` env var
- Config file: `<data_dir>/config.yaml`
- Endpoints: `POST /sign`, `GET /keys`, `GET /health`
- Authentication: `Authorization: aplane <token>` header

### apadmin
- TUI for key management and apsignerd control
- Commands: `generate`, `import`, `export`, `delete`, `list`, `unlock`
- IPC authentication via passphrase

### Exit Codes
- `0`: Success
- `1`: Operation failed / signature invalid
- `2`: Usage error / configuration error

## Coding Style & Naming Conventions

### Formatting
- Use `gofmt -s -w .` (required)
- Tabs for indentation (Go default)
- Line length: ~100-120 chars preferred

### Naming
- Exported: `PascalCase` (e.g., `SigningProvider`, `KeyStore`)
- Unexported: `camelCase` (e.g., `loadKey`, `validateToken`)
- Interfaces: noun or noun phrase (e.g., `Authenticator`, `KeyStore`)
- Test files: `*_test.go`

### Error Handling
- Return `error`; avoid `panic` in library code
- Wrap errors with context: `fmt.Errorf("failed to load key: %w", err)`
- Use sentinel errors for expected conditions: `ErrKeyNotFound`, `ErrInvalidPassphrase`
- Cryptographic failures (e.g., `crypto/rand` failure) may panic as they indicate system issues

### Package Separation
- CLI concerns: `cmd/*/`
- Business logic: `internal/engine/`
- Cryptographic primitives: `internal/crypto/`, `lsig/`
- Interfaces: `internal/auth/`, `internal/keystore/`, `internal/signing/`
- Utilities: `internal/util/`

### Interface Design
- Keep interfaces small and focused
- Define interfaces where they're used, not where implemented
- Use compile-time checks: `var _ Interface = (*Implementation)(nil)`

## Testing Guidelines

### Framework
- Go `testing` package
- Table-driven tests where appropriate
- Test files: `*_test.go` alongside source

### Test Types
- Unit tests: Test individual functions/methods
- Integration tests: In `test/integration/`, require `.env.test` with credentials
- Run integration tests: `INTEGRATION=1 go test ./test/integration/...`

### Coverage
- Focus on critical paths: crypto, signing, authentication
- Include negative cases and error conditions
- Use `go test -cover ./...` to check coverage

### Mocking
- Use interfaces for dependencies to enable mocking
- Example: `Authenticator` interface allows mock auth in tests

## Security Guidelines

### Key Material
- Zero sensitive data after use: `crypto.ZeroBytes(data)`
- Use `crypto.SecureString` for passphrases
- Never log key material or passphrases
- Lock memory to prevent swap: `mlockall()`

### Authentication
- HTTP: Bearer token with constant-time comparison
- IPC: Passphrase verified against Argon2id-derived master key
- See `doc/ARCH_SECURITY.md` for full architecture

### Cryptography
- Use `crypto/rand` for random bytes (never `math/rand`)
- AES-256-GCM for encryption
- Argon2id for key derivation (memory-hard, GPU-resistant)
- Falcon-1024 for post-quantum signatures

### Key File Format
Key files (`.key`) use two-layer versioning:
- `envelope_version`: Encryption envelope format (AES-GCM parameters, salt/nonce encoding)
- `format_version`: Decrypted payload schema (key fields, structure)

This allows independent evolution of encryption and key schema.

### Input Validation
- Validate all user input
- Use hex decoding with error checking
- Verify transaction bytes match claimed transaction ID (anti-blind-signing)

## Commit & Pull Request Guidelines

### Commits
- Concise, imperative subject lines (e.g., "Add KeyStore interface")
- Keep changes focused and atomic
- Do not include AI attribution in commit messages

### Pull Requests
- Clear description of changes and rationale
- Include tests for new functionality
- Update documentation if behavior changes
- Ensure all tests pass: `make test`
- Run static analysis before submitting

### Before Committing
```bash
go build ./...        # Ensure it compiles
go test ./...         # Run tests
go vet ./...          # Check for issues
gofmt -s -w .         # Format code
```

## Configuration Files

### Key Files
- `aplane.token`: API token for HTTP authentication (mode 0600)
- `keys/*.key`: Encrypted private keys (mode 0600)
- `keys/.keystore`: Keystore metadata (master salt, passphrase verification)
- `config.yaml`: Server configuration including approval policy (relative paths resolved to data directory)

### Environment Variables
- `APCLIENT_DATA`: Data directory for apshell (config, plugins)
- `APSIGNER_DATA`: Data directory for apsignerd (config, keys, IPC socket)
- `TEST_PASSPHRASE`: Passphrase for testing (auto-unlocks apsignerd)
- `TEST_FUNDING_MNEMONIC`: Funding account for integration tests
- `DISABLE_MEMORY_LOCK`: Skip memory locking (for testing)
- `INTEGRATION`: Enable integration tests

## Documentation

### Architecture Docs (`doc/`)
- `ARCH_OVERVIEW.md`: System architecture overview
- `ARCH_SECURITY.md`: Authentication and security architecture
- `ARCH_PLUGINS.md`: Plugin system architecture
- `ARCH_CRYPTO.md`: Cryptographic design
- `ARCH_ENGINE.md`: Engine and business logic
- `ARCH_UI.md`: User interface architecture
- `ARCH_TXNFLOW.md`: Transaction signing flow details
- `ARCH_AI_SCRIPTING.md`: AI code generation and JavaScript scripting guide
- `ARCH_POLICY.md`: Policy configuration guide

### User Docs
- `USER_CONFIG.md`: Configuration guide
- `USER_CONFIG_REFERENCE.md`: Generated configuration reference
- `USER_STORE_MGMT.md`: Keystore management, backup, and restore guide
- `USER_COMMANDS.md`: Command reference

### Developer Docs
- `DEV_BUILD.md`: Build instructions
- `DEV_TESTING.md`: Test suite documentation
- `DEV_New_DSA_LSig.md`: Guide for adding new DSA LogicSig schemes
- `DEV_New_GenericLSig.md`: Guide for adding new generic LogicSig templates
- `DEV_MULTITEMPLATE_LSIG.md`: Multi-template LogicSig development

### Transaction Docs
- `TXN_BALANCE_VERIFICATION.md`: Balance verification transactions
- `TXN_BYTES_HEX.md`: Transaction bytes hex format
- `TXN_FEE_SPLITTING.md`: Fee splitting in transaction groups
- `TXN_MIXED_GROUPS.md`: Mixed transaction groups

## Plugin Development

### Core Plugins
- Located in `coreplugins_repository/`
- Enabled via symlink to `coreplugins/`
- Built into binary with build tags

### External Plugins
- Separate executables communicating via JSON-RPC
- See `examples/external_plugins/` for TypeScript examples
- Must implement plugin manifest and command handlers

### Network Handling
- Plugins must use execution context network, not initialization network
- See `doc/ARCH_PLUGINS.md` for best practices
