# Repository Guidelines

Guidelines for AI agents and contributors working on the APlane codebase.

## Read First

Before making architectural, protocol, storage, or refactor-sensitive changes, read:

- `docs/ARCH_SPEC.md`: repo orientation, subsystem ownership, runtime model, architectural seams, and source-of-truth files
- `docs/ARCH_CONTRACTS.md`: compatibility-bearing HTTP/IPC behavior, on-disk formats, config contracts, SDK/plugin/MCP contracts
- `docs/ARCH_AUTHORIZATION.md`: principal/group/grant authorization model, stable actions, bootstrap product authorization, and enforcement points
- `docs/ARCH_POLICY.md`: current signer policy verdict model, phase ordering, and rule inventory
- `docs/ARCH_NETWORKS.md`: network context tokens, genesis-hash mapping, and network-scoped policy behavior

Before generating or modifying key types or LogicSig templates, also read:

- `docs/AGENTS_KEYTYPES.md`: agent-specific checklist for safe key type and LogicSig template work
- `docs/DEV_KEYTYPES.md`: canonical developer guide for key type categories, registries, YAML schema, and tests
- `docs/USER_LOGICSIG_GUIDELINES.md`: security and design guide for LogicSig TEAL policies, with a review checklist and bundled-template inventory

Use `AGENTS.md` as the short operational guide and the engineering docs as the authoritative detailed reference.

## Project Structure & Module Organization
APlane is the overarching Project name. Its goal is to provide an ops substrate that puts safety first.
Signer is one of the two major components; it holds keys and signs transactions.
Apshell is the other major component; it provides a shell-like interface to generate and submit transactions to the network.

### Binaries (`cmd/`)
- `cmd/apshell/`: Interactive shell, scripting environment, plugin host, and MCP surface
- `cmd/apsigner/`: Signing server, approval coordinator, HTTP API, IPC admin surface, and SSH tunnel server
- `cmd/apadmin/`: TUI and batch admin client over IPC
- `cmd/apconsole/`: Secure-machine console wrapper for apshell/apadmin/apsigner panes
- `cmd/apapprover/`: Approval-only admin client over IPC
- `cmd/apstore/`: Keystore management (initialize, backup, restore, rebuild, verify, changepass, template, keytype)
- `cmd/appolicy/`: Offline policy checker/editor TUI for identity `policy.yaml`
- `cmd/appass/`: Passphrase auto-unlock setup TUI
- `cmd/appass-file/`: Dev-only plaintext passphrase helper (insecure)
- `cmd/appass-systemd-creds/`: Production passphrase helper using systemd-creds (TPM2/host key)
- `cmd/approbe/`: Installer/helper liveness probe for signer IPC reachability
- `cmd/compile_teal/`: Dev/build helper that compiles TEAL source to generated Go bytecode
- `cmd/configdoc/`: Documentation generator for configuration
- `cmd/applugin-checksum/`: Checksum generator for plugins

### Core Internal Areas
- `internal/engine/`: Client-side business logic and transaction orchestration
- `internal/clientstate/`: Cache-backed client mutation and display state
- `internal/engine/connect/`: Signer connection state, tunnel lifecycle, and signer-facing HTTP
- `internal/appresult/`: Shared structured results and MCP projection
- `internal/signerapp/`: Signer runtime, approval, identity, signing, and template lifecycle
- `internal/keystore/`, `internal/keys/`, `internal/crypto/`: Keystore storage, key scanning, encryption, passphrase handling
- `internal/signing/`, `internal/lsigprovider/`, `lsig/`: Native signing and LogicSig provider registries/families
- `internal/adminproto/`, `internal/protocol/`, `internal/transport/`: IPC protocol, session/dispatch layer, and client transport
- `internal/plugin/`: Plugin discovery, manifest, lifecycle, and JSON-RPC protocol
- `internal/scripting/`, `internal/jsapi/`: Goja runtime and JavaScript bindings
- `internal/sshtunnel/`: SSH tunnel server/client
- `internal/config/`: Client and server configuration loading/validation

For a current ownership map and source-of-truth files, prefer `docs/ARCH_SPEC.md` over this summary.

### Cryptographic Modules (`lsig/`)
- `lsig/falcon1024/`: Falcon-1024 post-quantum signature implementation
  - `family/`: Family registration and metadata
  - `signing/`: Signing provider implementation
  - `keys/`: Key derivation and processing
  - `keygen/`: Key generation
  - `mnemonic/`: Mnemonic handling
  - `derivation/`: Version-specific derivation logic
- `lsig/generictemplate/`: YAML-backed provider for generic LogicSigs

### Other Directories
- `docs/`: Architecture and usage documentation
- SDKs live in the separate [`aplane-algo/aplanesdk`](https://github.com/aplane-algo/aplanesdk) repo (Go, TypeScript, Python). This repo owns the HTTP DTOs in `pkg/signerapi/` and the contract fixtures in `test/contracts/signerapi/` that the SDK repo consumes.
- `test/integration/`: Integration tests with test harness
- `examples/`: JavaScript scripts and external plugin examples
- `analysis/`: Security analysis tools (keyzero, keylog, insecurerand, seedphrase)
- `docker/`: Docker playground configuration
- `resources/`: TEAL programs and other resources
- `temp/`: Untracked directory for temporary files

## Build, Test, and Development Commands

### Building
```bash
make all              # Build everything
make apshell           # Build apshell
make apsigner         # Build signing server
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
make test             # Run unit tests (excludes integration)
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
make analyze-seedphrase   # Check for BIP-39 seed phrases in files
```

### Static Analysis
```bash
go vet ./...              # Go vet
staticcheck ./...         # Staticcheck
golangci-lint run ./...   # Golangci-lint
~/go/bin/gosec ./...      # Security scanner
```

### Example Plugins
```bash
make install-example-plugins  # Install npm dependencies for example plugins
make build-example-plugins    # Rebuild example plugins that have TS build outputs
make check-example-plugins    # Check if example plugin build outputs are stale
make applugin-checksums         # Generate checksums.sha256 for all example plugins
```

## CLI Conventions

### apshell Commands
- Interactive REPL with command history
- Requires data directory: `-d <path>` or `APCLIENT_DATA` env var
- Config file: `<data_dir>/config.yaml`
- Commands: `connect`, `network`, `balance`, `send`, `keyreg`, `sign`, `run`, `help`
- JavaScript scripting via `js script.js`
- Tab completion for addresses, commands, assets
- For the broader command and MCP surface, prefer `docs/ARCH_SPEC.md` and `docs/ARCH_CONTRACTS.md`

### apsigner
- Starts signing server with HTTP REST API and IPC interface
- Requires data directory: `-d <path>` or `APSIGNER_DATA` env var
- Config file: `<data_dir>/config.yaml`
- Endpoints: see `docs/ARCH_HTTP_API.md` for the current HTTP surface
- Authentication: `Authorization: aplane <token>` header

### apadmin
- TUI for key management and apsigner control
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
- Shell application workflows: `internal/apshellapp/`
- Business logic: `internal/engine/`
- Cryptographic primitives: `internal/crypto/`, `lsig/`
- Interfaces: `internal/auth/`, `internal/keystore/`, `internal/signing/`
- Avoid catch-all utility packages; keep helpers in owning packages or focused packages such as `internal/fsutil/` and `internal/storepaths/`

### Apshell Boundary Rule
- `cmd/apshell` is adapter-only: parse input, handle REPL/UI prompts, manage MCP/plugin/runtime wiring, and render results.
- Do not add new shell business logic or command workflow decisions to `cmd/apshell`.
- `internal/apshellapp` owns shell command workflows and shell-facing use-cases.
- New shell features should land in `internal/apshellapp` with typed request/result APIs and behavior tests in `internal/apshellapp`.
- `internal/engine` owns reusable client/runtime mechanics and lower-level transaction operations, not shell command semantics.
- `cmd/apshell` should call `internal/apshellapp` for command behavior rather than reaching into behavior-owning `internal/engine` APIs directly.

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
- See `docs/ARCH_SECURITY.md` for authentication/security architecture and `docs/ARCH_AUTHORIZATION.md` for authorization architecture

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
- `identities/<identity>/keys/*.key`: Encrypted private keys (mode 0600)
- `identities/<identity>/.keystore`: Keystore metadata (master salt, passphrase verification)
- `config.yaml`: Process-global server configuration
- `identities/<identity>/config.yaml`: Identity-scoped runtime settings
- `identities/<identity>/unlock.yaml`: Identity-scoped passphrase-helper configuration

See `docs/ARCH_CONTRACTS.md` for the full on-disk layout and compatibility details.

### Environment Variables
- `APCLIENT_DATA`: Data directory for apshell (config, plugins)
- `APSIGNER_DATA`: Data directory for apsigner (config, keys, IPC socket)
- `TEST_PASSPHRASE`: Passphrase for testing (auto-unlocks apsigner)
- `TEST_FUNDING_MNEMONIC`: Funding account for integration tests
- `DISABLE_MEMORY_LOCK`: Skip memory locking (for testing)
- `INTEGRATION`: Enable integration tests

## Documentation

### Engineering Docs
- `ARCH_SPEC.md`: Cross-cutting implementation map, ownership model, runtime model, architectural seams, source-of-truth files
- `ARCH_CONTRACTS.md`: Compatibility-bearing on-disk/config/SDK/plugin/MCP contracts and TOC pointing at extracted contract docs
- `ARCH_HTTP_API.md`: HTTP request/response wire shapes, status codes, identity routing, and `/sign/cancel` lifecycle
- `ARCH_ADMIN_PROTOCOL.md`: apsigner admin RPC message catalog, payload shapes, and writable-settings rules

### Architecture Docs (`docs/`)
- `ARCH_OVERVIEW.md`: System architecture overview
- `ARCH_SECURITY.md`: Authentication and security architecture
- `ARCH_AUTHORIZATION.md`: Principal/group/grant authorization architecture
- `ARCH_POLICY.md`: Current signer policy verdict model and rule inventory
- `ARCH_NETWORKS.md`: Network context token and genesis-hash mapping architecture
- `ARCH_APP_INTERACTION.md`: App interaction, app-local vs signer-managed action boundaries, and token/caller model
- `ARCH_COOPERATIVE_SIGNING.md`: Cooperative signing and split-authorization architecture
- `ARCH_LSIG_PROVIDER.md`: LogicSig provider, template, salting, and registration architecture
- `ARCH_PLUGINS.md`: Plugin system architecture
- `ARCH_CRYPTO.md`: Cryptographic design
- `ARCH_ENGINE.md`: Engine and business logic
- `ARCH_REPL.md`: apshell REPL architecture (parsing, dispatch, rendering)
- `ARCH_MCP.md`: apshell MCP server and tool surface
- `ARCH_TUI.md`: signer admin TUI (apadmin) architecture
- `ARCH_TXNFLOW.md`: Transaction signing flow details

### User Docs
- `USER_INSTALL.md`: Installation and upgrade guide
- `USER_QUICKSTART.md`: Quickstart guide
- `USER_CONFIG.md`: Configuration guide
- `USER_CONFIG_REFERENCE.md`: Generated configuration reference
- `USER_POLICY.md`: Signer policy guide
- `USER_TRANSFER_ROUTING.md`: Transfer routing deep dive
- `USER_STORE_MGMT.md`: Keystore management, backup, and restore guide
- `USER_COMMANDS.md`: Command reference
- `USER_KEYTYPES.md`: Key type and template management guide
- `USER_JSAPI.md`: JavaScript scripting API guide
- `USER_LOGGING.md`: Logging behavior and configuration
- `USER_LOGICSIG_GUIDELINES.md`: LogicSig security and design guide, review checklist, and bundled-template inventory

### Developer Docs
- `DEV_BUILD.md`: Build instructions
- `DEV_TESTING.md`: Test suite documentation
- `AGENTS_KEYTYPES.md`: Agent checklist for safe key type and LogicSig template work
- `DEV_KEYTYPES.md`: Unified guide for adding key types and LogicSig templates
- `DEV_GUIDELINES.md`: General development guidelines

### Transaction Docs
- `TXN_BALANCE_VERIFICATION.md`: Balance verification transactions
- `TXN_BYTES_HEX.md`: Transaction bytes hex format
- `TXN_FEE_SPLITTING.md`: Fee splitting in transaction groups
- `TXN_MIXED_GROUPS.md`: Mixed transaction groups

## Plugin Development

### Plugins
- Standalone executables communicating via JSON-RPC over stdin/stdout
- Can be written in any language
- See `examples/external_plugins/` for the in-tree reference plugin (`echo-plugin`)
- Must implement plugin manifest and command handlers

### Network Handling
- Plugins must use execution context network, not initialization network
- See `docs/ARCH_PLUGINS.md` for best practices
