# Testing Guide

This document describes the testing strategy and practices for the APlane project.

## Table of Contents

- [Overview](#overview)
- [Unit Testing](#unit-testing)
- [Integration Testing](#integration-testing)
- [API Contract Tests](#api-contract-tests)
- [Docker Install Smoke Tests](#docker-install-smoke-tests)
- [REPL Testing](#repl-testing)
- [Running Tests](#running-tests)
- [Writing Integration Tests](#writing-integration-tests)
- [Coverage](#coverage)
- [Continuous Integration](#continuous-integration)
- [Troubleshooting](#troubleshooting)
- [Test Suite Overview](#test-suite-overview)
- [Quick Reference](#quick-reference)

## Overview

The project uses a layered testing approach:

1. **Unit Tests**: Fast, isolated tests for individual components (Go test framework)
2. **API Contract Tests**: Golden fixture compatibility tests for signer API wire surfaces
3. **Integration Tests**: End-to-end tests against an explicitly selected Algorand network profile, either public testnet or a running AlgoKit LocalNet (Go test framework)
4. **Docker Install Smoke Tests**: Local and Systemd installer/uninstaller checks
5. **REPL Tests**: Interactive command-line testing for user workflows (manual)

This combination ensures code correctness, API compatibility, installer behavior, real-world
network compatibility, and user experience validation.

## Unit Testing

### What We Test

Unit tests cover:
- Key generation (Ed25519, Falcon-1024)
- Transaction signing (single, multi-sig, atomic groups)
- LogicSig derivation and validation
- Cache behavior (LSig cache, signer cache, auth address cache)
- Transaction group analysis
- Fee calculation and splitting
- Cryptographic operations
- Audit logging

### Unit Test Structure

Selected key test files (run `rg --files | rg '_test\.go$' | wc -l` for full count):

```
aplane/
├── cmd/
│   ├── apshell/
│   │   └── main.go                    # Thin entrypoint; behavior lives in internal packages
│   ├── apsigner/
│   │   ├── audit_test.go              # Signer audit logging tests
│   │   ├── server_test.go             # HTTP server tests
│   │   ├── hub_test.go                # Hub state tests
│   │   ├── admin_test.go              # Admin endpoint tests
│   │   └── plan_sign_parity_test.go   # Plan/sign parity and group-shaping tests
│   ├── apstore/
│   │   ├── ipc_backup_test.go         # Backup IPC command tests
│   │   ├── ipc_template_keytype_test.go # Template and key type command tests
│   │   └── store_commands_test.go     # Local store command tests
│   ├── appass/
│   │   ├── actions_test.go            # Passphrase helper setup tests
│   │   └── policy_test.go             # Passphrase helper policy tests
│   └── apadmin/
│       └── audit_test.go              # Admin audit logging tests
├── lsig/
│   └── falcon1024/
│       ├── keygen/generator_test.go   # Falcon key generation tests
│       ├── signing/provider_test.go   # Falcon signing provider tests
│       ├── metadata_test.go           # Algorithm metadata tests
│       └── v1/
│           ├── composer_test.go       # ComposedDSA tests
│           └── v1_test.go             # Falcon v1 provider tests
├── internal/
│   ├── algo/
│   │   ├── client_test.go            # Algorand client tests
│   │   └── parser_test.go            # Transaction parser tests
│   ├── cache/
│   │   ├── auth_cache_test.go        # Auth address cache tests
│   │   ├── alias_test.go             # Address alias cache tests
│   │   ├── asa_test.go               # ASA metadata cache tests
│   │   ├── set_test.go               # Address set cache tests
│   │   └── signer_test.go            # Signer cache tests
│   ├── command/
│   │   ├── command_test.go           # Command structure tests
│   │   └── registry_test.go          # Command registry tests
│   ├── crypto/
│   │   ├── encryption_test.go        # AES-GCM encryption tests
│   │   └── encryption_bytes_test.go  # Byte-level encryption tests
│   ├── engine/
│   │   ├── engine_test.go            # Core engine tests
│   │   ├── accounts_test.go          # Account management tests
│   │   ├── app_call_test.go          # Application call tests
│   │   ├── cache_test.go             # Engine cache tests
│   │   └── payment_test.go           # Payment transaction tests
│   ├── apshellapp/
│   │   ├── connect_test.go           # Shell connection workflow tests
│   │   ├── send_test.go              # Shell send workflow tests
│   │   └── txcmds_validate_test.go   # Shell transaction validation tests
│   ├── apshellcli/
│   │   ├── commands_info_test.go     # Shell command adapter tests
│   │   ├── mcp_test.go               # MCP rendering and command behavior tests
│   │   └── plugin_parity_test.go     # Plugin command registration parity tests
│   ├── shellrepl/
│   │   ├── autocomplete_test.go      # REPL completion tests
│   │   └── parser_test.go            # Command parsing tests
│   ├── signing/
│   │   ├── common_test.go            # Common signing tests
│   │   ├── lsig_helpers_test.go      # LogicSig helper tests
│   │   └── registry_test.go          # Signing provider registry tests
│   ├── keystore/
│   │   ├── file_test.go              # File keystore tests
│   │   └── session_test.go           # Key session tests
│   ├── mnemonic/
│   │   ├── bip39_test.go             # BIP-39 mnemonic tests
│   │   ├── ed25519_test.go           # Ed25519 mnemonic tests
│   │   └── handler_test.go           # Mnemonic handler registry tests
│   ├── plugin/
│   │   ├── integrity/integrity_test.go   # Plugin integrity tests
│   │   ├── jsonrpc/protocol_test.go      # JSON-RPC protocol tests
│   │   ├── manifest/manifest_test.go     # Plugin manifest tests
│   │   └── sandbox/sandbox_test.go       # Plugin sandbox tests
│   ├── tokenfile/
│   │   └── tokenfile_test.go         # Token file permission and IO tests
│   └── transport/
│       ├── client_test.go            # IPC transport tests
│       ├── protocol_flow_test.go     # Admin protocol flow tests
│       └── ssh_test.go               # SSH transport tests
```

### Example Unit Test

```go
func TestGenerateFromSeed(t *testing.T) {
    paths := storepaths.NewPaths(t.TempDir())
    generator := &keygen.Ed25519Generator{}
    seed := make([]byte, ed25519.SeedSize)
    masterKey := bytes.Repeat([]byte{0x11}, 32)

    result, err := generator.GenerateFromSeed(paths, "default", seed, masterKey, "ed25519", nil)
    if err != nil {
        t.Fatalf("GenerateFromSeed() error = %v", err)
    }

    if result.Address == "" {
        t.Fatal("Address is empty")
    }
    if result.KeyType != "ed25519" {
        t.Fatalf("KeyType = %q, want ed25519", result.KeyType)
    }
}
```

### Unit Test Best Practices

- Prefer in-process transport fakes (`http.RoundTripper`, injected dial/listen seams, SDK transport hooks) over real local listeners for unit tests.
- Reserve `net.Listen`, `httptest.NewServer`, and similar listener-binding helpers for tests that are explicitly about transport behavior rather than application logic.
- Treat `cmd/apsigner/ssh_admin_shape_test.go` as a self-contained loopback transport-shape suite, not a pure unit test. It intentionally exercises real localhost TCP, SSH framing, and admin subsystem wiring to pin the SSH admin contract, and skips when the environment forbids loopback listener binds.
- When adding new signer tests, keep business logic under in-process tests in owner packages and add listener-based tests only when the transport contract itself is the thing being verified.

1. **Isolation**: Use `t.TempDir()` for file operations
2. **Determinism**: Use fixed seeds/inputs for reproducible results
3. **Fast Execution**: Mock external dependencies (network, `apsigner`)
4. **Clear Naming**: Test names should describe what they test
5. **Table-Driven Tests**: Use table-driven tests for multiple scenarios

### Selecting test packages

Most ad-hoc `go test` commands below exclude integration tests, vendored
JavaScript, scratch packages, and the unbuildable `apshell` shim. Build the
`PKGS` list once:

```bash
PKGS=$(go list ./... | grep -v '/test/integration' | grep -v '/node_modules/' | grep -v '^github.com/aplane-algo/aplane/temp/' | grep -v '^apshell$')
```

Other sections refer to this as the canonical `$PKGS` definition.

### Running Unit Tests

```bash
# Run all unit tests
make unit-test

# Run with verbose output (uses $PKGS from "Selecting test packages")
go test -v $PKGS

# Run specific package
go test ./internal/signing

# Run with coverage
go test -cover $PKGS

# Run with race detection
make race-test

# Run specific test
go test -v -run TestGenerate ./lsig/falcon1024/keygen
```

### Current Unit Test Coverage

Coverage changes frequently. Generate current numbers locally instead of relying on a checked-in table (uses `$PKGS` from [Selecting test packages](#selecting-test-packages)):

```bash
go test -cover $PKGS
go test -coverprofile=coverage.out $PKGS
go tool cover -func=coverage.out | sort -k3
```

## Integration Testing

### What We Test

Integration tests validate:
- Full transaction flow from key generation to network submission
- Signer process lifecycle management (start, stop, restart)
- SSH tunnel connectivity and host key verification
- apshell CLI interaction patterns
- Real network transaction confirmation
- Falcon signature validation by Algorand nodes
- Passthrough (pre-signed) and mixed-party transaction groups
- Key persistence across signer restarts
- Account close-out and fund recovery

### Integration Test Structure

```
test/
├── setup-test-env.sh              # Creates self-contained test environment
├── integration/
│   ├── harness/
│   │   ├── apshell.go             # apshell CLI test interface
│   │   ├── apadmin.go            # apadmin CLI (key management, unlock)
│   │   ├── fund.go                # Algorand SDK-based funding helper
│   │   ├── funding.go             # Funding account validation
│   │   ├── signer.go              # Signer process management
│   │   ├── testnet.go             # Selected integration network utilities
│   │   └── util.go                # Shared test utilities
│   ├── basic_falcon_test.go       # Core Falcon tests (sign, group, restart)
│   ├── generic_template_test.go   # YAML template install and spend flows
│   ├── js_test.go                 # Live JavaScript helper flows
│   ├── key_derivation_regression_test.go # Deterministic derivation pins
│   ├── multitenant_test.go        # Multi-identity signer routing tests
│   ├── signer_test.go             # Signer policy, lock, approval, restart tests
│   ├── app_test.go                # Application deploy/read/call flow tests
│   ├── apstore_initialize_test.go # apstore initialize bootstrap tests
│   ├── backup_portability_test.go # Backup/restore portability tests
│   ├── ssh_token_test.go          # SSH enrollment and token provisioning tests
│   ├── apstore_changepass_test.go # Passphrase rotation restart regression
│   └── passthrough_test.go        # Passthrough/multi-party signing tests
```

### Test Environment Setup

The integration tests require a fully isolated signer environment and an
explicit network profile. `make integration-test` is the normal entry point and
invokes `test/setup-test-env.sh` before running Go tests. The setup script
creates everything from scratch.

Testnet mode requires a funded testnet mnemonic:

```bash
export APLANE_INTEGRATION_NETWORK=testnet
export TEST_FUNDING_MNEMONIC="your twenty five word algorand testnet mnemonic here"

# Regenerate the test environment and run integration tests
make integration-test

# Or run only the setup script when you need to inspect the generated fixture
./test/setup-test-env.sh
```

LocalNet mode requires an already running AlgoKit LocalNet with algod and KMD
reachable. It does not require a user-provided funding mnemonic; setup exports a
funded KMD account as `TEST_FUNDING_MNEMONIC` and `TEST_FUNDING_ACCOUNT` in the
generated `.env.test`:

```bash
APLANE_INTEGRATION_NETWORK=localnet make integration-test

# Or run only setup
APLANE_INTEGRATION_NETWORK=localnet ./test/setup-test-env.sh
```

This creates `/tmp/aplane-test-env/` containing:

```
/tmp/aplane-test-env/
├── apsigner/                     # Signer data directory (APSIGNER_DATA)
│   ├── config.yaml                # Signer config (random ports, user_auto_approve:true)
│   ├── passphrase                 # Test passphrase file
│   ├── .ssh/
│   │   ├── ssh_host_key           # Generated SSH host key
│   │   ├── ssh_host_key.pub
│   │   └── authorized_keys        # Client public key
│   └── identities/default/
│       ├── .ssh/
│       │   └── authorized_keys        # Identity-scoped SSH client key authorization
│       ├── .keystore              # Initialized keystore metadata
│       ├── aplane.token           # Generated API token
│       ├── policy.yaml            # Permissive integration-test policy
│       ├── policy.yaml.hmac       # Integrity sidecar for policy.yaml
│       ├── attestation.yaml       # Permissive integration-test attestor policy
│       ├── attestation.yaml.hmac  # Integrity sidecar for attestation.yaml
│       └── keys/                  # Empty key directory (tests generate keys)
├── library/templates/              # Plaintext KeyType Library copied from repo
└── apclient/                      # Client data directory (APCLIENT_DATA)
    ├── config.yaml                # Client config (network and algod settings)
    ├── endpoints.yaml             # Client endpoint registry (SSH signer route)
    ├── aplane.token               # Copy of API token
    └── .ssh/
        ├── id_ed25519             # Generated client SSH key
        ├── id_ed25519.pub
        └── known_hosts            # Pre-populated with signer host key
```

The script also writes `.env.test` in the project root, which the Makefile sources automatically.

#### What the setup script does

1. Generates ed25519 SSH host key for the signer
2. Generates ed25519 SSH client key and authorizes it on the signer
3. Picks random available ports for REST API and SSH (avoids collisions with running services)
4. Writes signer `config.yaml` (random ports, `user_auto_approve:true`, no admin idle timeout)
5. Writes client `config.yaml` for network/algod settings and `endpoints.yaml`
   for the SSH signer route, token file, and `known_hosts_path`
6. Writes passphrase file for the signer
7. Initializes the keystore non-interactively by piping the generated test passphrase to `apstore initialize`
8. Copies the generated API token to the client data directory
9. Pre-populates client `known_hosts` with the signer's SSH host key (avoids TOFU prompts)
10. Writes identity-scoped authorized keys and permissive test policy
11. Copies the top-level `library/templates/` YAML files into the signer data library
12. In localnet mode, exports a funded KMD account as `TEST_FUNDING_MNEMONIC`, writes the current localnet genesis hash into signer config, and seeds the integration burn address
13. Writes `.env.test` with all required environment variables

#### Test environment ports

The setup script picks random available ports at creation time to avoid
collisions with running services or other test runs. The signer REST and SSH
ports are written to signer `config.yaml`; the client-facing signer route is
written to `apclient/endpoints.yaml`. Production defaults are 11270 (REST) and
1127 (SSH).

#### Teardown

The setup script removes any previous test environment (`rm -rf /tmp/aplane-test-env`) before creating a new one. The OS also cleans `/tmp` on reboot. No separate teardown script is needed.

All per-test temp directories (binary builds, apshell work dirs) use Go's `t.TempDir()` and are cleaned up automatically after each test.

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `APLANE_INTEGRATION_NETWORK` | Integration profile: `testnet` or `localnet` | Always, before setup |
| `TEST_FUNDING_MNEMONIC` | 25-word funding mnemonic. In testnet mode, provide a funded testnet account. In localnet mode, setup exports one from KMD. | Testnet input; localnet auto |
| `TEST_FUNDING_ACCOUNT` | Funding account address. Optional in testnet mode; setup writes the exported KMD account in localnet mode. | Optional before setup |
| `ALGOD_URL` | Algod endpoint. Defaults by profile. | Optional |
| `ALGOD_TOKEN` | Algod token. Defaults empty for testnet and the AlgoKit token for localnet. | Optional |
| `APLANE_LOCALNET_ALGOD_URL` | LocalNet algod endpoint fallback when `ALGOD_URL` is unset. | Optional localnet |
| `APLANE_LOCALNET_KMD_URL` | LocalNet KMD endpoint. | Optional localnet |
| `APLANE_LOCALNET_TOKEN` | LocalNet algod/KMD token fallback when `ALGOD_TOKEN` is unset. | Optional localnet |
| `APLANE_LOCALNET_WALLET` | KMD wallet used to select/export the funding account. | Optional localnet |
| `APLANE_LOCALNET_WALLET_PASSWORD` | Password for the selected KMD wallet. | Optional localnet |
| `TEST_PASSPHRASE` | Keystore passphrase (set by setup script) | Auto |
| `APSIGNER_DATA` | Signer data directory (set by setup script) | Auto |
| `APCLIENT_DATA` | Client data directory (set by setup script) | Auto |
| `DISABLE_MEMORY_LOCK` | Skip mlock for testing (set by setup script) | Auto |

For testnet, the only required user-provided variables are
`APLANE_INTEGRATION_NETWORK=testnet` and `TEST_FUNDING_MNEMONIC`. For localnet,
the only required user-provided variable is
`APLANE_INTEGRATION_NETWORK=localnet`, assuming standard AlgoKit LocalNet
defaults and a funded account in the default KMD wallet. Override the secondary
localnet variables only when your LocalNet uses nonstandard endpoints, token, or
wallet settings.

`APSIGNER_PASSPHRASE` is a general-purpose environment variable for non-interactive `apstore` usage (not test-specific). When set, all `apstore` passphrase prompts are answered with its value. The setup script does not export it; instead, it pipes the generated test passphrase into `apstore initialize`. It is not written to `.env.test` and is not needed at test runtime.

### Running Integration Tests

```bash
# Testnet prerequisite
export APLANE_INTEGRATION_NETWORK=testnet
export TEST_FUNDING_MNEMONIC="your twenty five word mnemonic here"

# Run via Makefile. This regenerates the fixture and sources .env.test.
make integration-test

# LocalNet prerequisite: AlgoKit LocalNet already running
APLANE_INTEGRATION_NETWORK=localnet make integration-test

# Show live test progress during a full run
APLANE_INTEGRATION_NETWORK=testnet make integration-test INTEGRATION_GO_ARGS='-count=1 -timeout 25m -v'

# Run a specific test with a fresh regenerated fixture
APLANE_INTEGRATION_NETWORK=localnet make integration-test INTEGRATION_GO_ARGS='-count=1 -timeout 25m -v -run TestBasicFalconTransaction'

# Run the LocalNet-only transaction soak test
make soak-test-localnet

# Run broad LocalNet apshell command coverage separately
make apshell-command-coverage-localnet

# Run a short LocalNet soak for smoke-checking the soak harness itself
make soak-test-localnet APLANE_SOAK_DURATION=2m SOAK_GO_ARGS='-count=1 -timeout 10m -v'

# Also run the external SDK integration suites against the regenerated fixture
APLANE_INTEGRATION_NETWORK=testnet APLANE_SDKS_REPO=~/aplanesdk make integration-test

# Reuse the existing fixture and .env.test without regenerating
make integration-test-reuse

# Clean up leaked test apps from previous failed runs
make integration-test-cleanup

# Dry-run cleanup for leftover LocalNet signer keys in /tmp/aplane-test-env
set -a && . .env.test && set +a
go run ./test/integration/cmd/localnet-clean-test-keys

# Delete those LocalNet signer test keys
go run ./test/integration/cmd/localnet-clean-test-keys -yes
```

`make integration-test` is the canonical path because integration tests require a coherent generated fixture: signer/client data dirs, randomized ports, SSH keys, token files, and initialized keystore state. Focused runs should still go through `make integration-test` with `INTEGRATION_GO_ARGS` so the fixture is regenerated before `go test`.

When `APLANE_SDKS_REPO` points at a local `aplanesdk` checkout, the Makefile
also runs the SDK repo's live signer integration tests after the in-repo Go
integration suite. The SDK bridge reuses `.env.test`, starts a temporary
`apsigner` from the generated fixture, runs `make integration-test` in the SDK
repo, and stops the signer afterward. If `APLANE_SDKS_REPO` is unset, SDK
integration is skipped and the ordinary APlane integration flow is unchanged.

Full testnet integration runs take about 1000 seconds. This is driven
largely by Algorand block inclusion time: each confirmed transaction group waits
for real testnet finality, which is approximately 3 seconds per block. LocalNet
runs are usually much faster, but still exercise live algod/KMD behavior.

Manual `go test` is only a reuse path after a fixture exists:

```bash
set -a && . .env.test && set +a
INTEGRATION=1 go test -v -count=1 -timeout 25m ./test/integration
```

The integration package exits immediately unless `INTEGRATION=1` is set, so
plain `go test ./...` does not accidentally run live integration tests.

### LocalNet Soak Tests

`make soak-test-localnet` regenerates the integration fixture with
`APLANE_INTEGRATION_NETWORK=localnet`, sources `.env.test`, and runs only the
opt-in endurance loop with `APLANE_SOAK=1`. The loop starts `apsigner` once,
repeatedly generates signer keys, funds them from the LocalNet KMD funding
account, sends a small payment to the integration burn address, closes the
account back to the funder, and deletes the generated key. It keeps `apsigner`
running for the duration unless `APLANE_SOAK_RESTART_EVERY` is set to a
positive value.

`make apshell-command-coverage-localnet` is a separate breadth check. It runs
one LocalNet command-coverage pass under `APLANE_COMMAND_COVERAGE=1`, exercising
the safe apshell command surface: connection/config/status, aliases/sets,
balance and participation reads, write/verbose/simulate modes, script and
JavaScript helpers, app read commands, ASA cache/info/opt-in/opt-out,
generate/delete, validate, offline keyreg, rekey/unrekey, send, sweep, and
close. It intentionally skips plugins, token provisioning, and keyreg-online.

The target is intentionally separate from `make integration-test` and
`make integrity-check`; it is for capacity and endurance testing against a
running LocalNet, not for every pre-commit run.

If an older soak run left generated signer keys behind, source the generated
`.env.test` and run `go run ./test/integration/cmd/localnet-clean-test-keys`
for a dry run. Add `-yes` to delete the keys from the LocalNet integration
signer fixture. The cleanup helper refuses to run unless
`APLANE_INTEGRATION_NETWORK=localnet` and the signer data directory is under
`/tmp/aplane-test-env`.

| Variable | Default | Description |
|----------|---------|-------------|
| `APLANE_SOAK_DURATION` | `30m` | Wall-clock duration for `make soak-test-localnet` |
| `APLANE_SOAK_MAX_ITERATIONS` | `0` | Optional cap on ed25519 iterations; `0` means duration-bound only |
| `APLANE_SOAK_RESTART_EVERY` | `0` | Restart `apsigner` after this many ed25519 iterations; `0` disables restarts |
| `APLANE_SOAK_FALCON_EVERY` | `5` | Add one Falcon-1024 LogicSig account cycle every N ed25519 iterations; `0` disables Falcon cycles |
| `SOAK_GO_ARGS` | `-count=1 -timeout 2h` | Go test flags for the soak package |

Examples:

```bash
# One quick iteration for harness validation
make soak-test-localnet APLANE_SOAK_DURATION=0s APLANE_SOAK_MAX_ITERATIONS=1 SOAK_GO_ARGS='-count=1 -timeout 5m -v'

# Longer endurance run
make soak-test-localnet APLANE_SOAK_DURATION=4h SOAK_GO_ARGS='-count=1 -timeout 5h -v'
```

### Representative Integration Tests

| Test | What it validates |
|------|-------------------|
| `TestBasicFalconTransaction` | Full lifecycle: import ed25519 funding key, generate Falcon key, fund it, send Falcon-signed payment, confirm on the selected network, close account back to funder |
| `TestFalconGroupTransaction` | Generate two Falcon keys, fund them, sign an atomic payment group, and close accounts back to the funder |
| `TestFalconPassphraseSigning` | Verify passphrase-protected Falcon signing flow |
| `TestSignerRestartPreservesUsableKeys` | Generate key, stop signer, restart, verify key remains usable |
| `TestApstoreChangepassUpdatesIdentityUnlockHelperAndSignerRestarts` | Rotate passphrase through `apstore changepass`, require manual current passphrase entry, update identity unlock helper, and restart via that helper |
| `TestBackupPortabilityFirstMilestone` | Backup and restore key/template variants across signer stores |
| `TestAppDeployAndExercise` | Deploy and exercise the test application fixture |
| `TestPreparedGroupDepositFlow` | Build, sign, and submit prepared payment/app-call groups |
| `TestJavaScriptTransactionFlows` | Exercise JavaScript transaction helpers against the signer |
| `TestGenericWhitelistTemplateAllowsSendAndCloseToFundingAccount` | Install and spend with a generic template-backed LogicSig |
| `TestSignerManagedBackupRoundTripViaApstoreRestore` | Create a signer-managed backup, restore through `apstore`, and verify restored keys remain usable |
| `TestKeyDerivationRegression` | Pin known-answer addresses for supported Ed25519, DSA LogicSig, and template-backed LogicSig derivation paths |
| `TestPassthroughMixedGroup` | Sign + passthrough in one group: server signs txn A, pre-signed txn B passes through unchanged |
| `TestPassthroughResign` | Sign full group, strip one signature, resubmit with mix of sign + passthrough |
| `TestPassthroughRequiresPreGrouped` | Verify passthrough rejects transactions without pre-set group ID |
| `TestRequestTokenHappyPathEnrollsKeyAndConnectWorks` | Exercise SSH token provisioning, enrollment, and reconnect |

`TestKeyDerivationRegression` is a compatibility golden, not a generated test
artifact. If a derivation path intentionally changes, such as a LogicSig salt
style, TEAL template body, seed derivation, or provider generator, update the
expected address in the same change that changes the behavior.

#### Fund recovery

Tests that move real ALGO close out test accounts back to the funding account using Algorand's `CloseRemainderTo` field. This returns the full balance minus fee, preventing fund leakage into inaccessible accounts.

#### Leaked app cleanup

If integration tests fail mid-run, they may leave test apps on testnet that can't be deleted normally (e.g. apps with outstanding boxes). Run `make integration-test-cleanup` to find and delete these. It identifies test apps by their schema signature (2 global uint, 2 global bytes, 2 local uint, 0 local bytes), updates each with the current approval program (which has `delete_box` support), removes all boxes, and then deletes the app. Refuses to run on non-testnet networks.

### Integration Test Harness

The test harness (`test/integration/harness/`) provides utilities for managing test infrastructure:

#### **SignerHarness** (`harness/signer.go`)
Manages apsigner process lifecycle:
- Reads `APSIGNER_DATA` and `TEST_PASSPHRASE` from environment
- Builds apsigner binary from project root
- Reads signer port from `config.yaml`
- Starts process with `DISABLE_MEMORY_LOCK=1`
- Auto-unlocks via `TEST_PASSPHRASE` by default; tests can opt out to exercise configured passphrase helpers
- HTTP health check polls `/health` for readiness
- Captures stdout/stderr to log file
- Graceful shutdown with 5-second kill timeout

```go
signerd := harness.NewSignerHarness(t)
if err := signerd.Start(); err != nil {
    t.Fatalf("Failed to start: %v", err)
}
defer func() { _ = signerd.Stop() }()

url := signerd.GetURL()             // "http://localhost:<port>"
dir := signerd.GetWorkDir()         // APSIGNER_DATA path
token := signerd.GetTokenPath()     // Path to aplane.token
logs, _ := signerd.GetLogs()        // Captured log output
```

#### **ApAdminHarness** (`harness/apadmin.go`)
Manages apadmin CLI for key management:
- Builds apadmin binary with `-tags testmode` (test mode is test-only, not available in production builds)
- Runs commands in `--test` mode (non-interactive)
- Uses IPC socket for signer communication
- Tracks generated keys for cleanup

> **Note:** The `--test` flag is gated behind the `testmode` build tag. Production builds of apadmin do not include test mode. The test harness automatically builds with `-tags testmode` to enable it. To build a test-capable binary manually: `go build -tags testmode -o apadmin-test ./cmd/apadmin`

```go
apadmin := harness.NewApAdminHarness(t, signerd.GetWorkDir())
defer apadmin.Cleanup()  // Deletes all generated keys

// Key management
addr, err := apadmin.GenerateKey("seed")                    // Falcon key; seed is ignored
addr, err := apadmin.GenerateKeyWithType("ed25519")         // Specific native type
addr, err := apadmin.GenerateKeyWithType("aplane.falcon1024.v1")   // Specific LogicSig DSA type
addr, err := apadmin.ImportKey(mnemonic)               // From mnemonic
err := apadmin.DeleteKey(addr)                         // Delete one
err := apadmin.ActivateKeyType("aplane.falcon1024_ed25519.v1") // Enable library-visible compiled key type
_, err := apadmin.CreateBackup("export-passphrase")    // Signer-managed backup

// Unlock management
err := apadmin.UnlockSigner()                          // One-shot unlock
err := apadmin.StartUnlockBackground()                 // Keep unlocked
defer apadmin.StopUnlockBackground()
```

#### **ApshellHarness** (`harness/apshell.go`)
Provides programmatic interface to apshell CLI:
- Builds apshell binary from project root
- Requires `APCLIENT_DATA` to be set; signer routing is loaded from
  `endpoints.yaml`
- Parses transaction IDs from command output

```go
apshell := harness.NewApshellHarness(t, signerd.GetURL())
if err := apshell.CopyTokenFrom(signerd.GetWorkDir()); err != nil {
    t.Fatal(err)
}

// Transactions
txid, err := apshell.SendTransaction(from, to, 0.1)     // Payment
txid, err := apshell.CloseAccount(account, destination)  // Close-out

// Custom commands
output, err := apshell.RunWithInput("accounts\nquit\n")
```

#### **FundTestAccount** (`harness/fund.go`)
SDK-based funding (signs directly, no signer needed):
- Reads `TEST_FUNDING_MNEMONIC` from environment. Testnet users provide this
  mnemonic; localnet setup exports it from KMD.
- Creates and signs transactions with go-algorand-sdk
- Submits directly to algod

```go
network, err := harness.NewTestnetConfig()
funder, err := harness.NewFundTestAccount(network.Client)
err := funder.FundMicroAlgosAndWait(address, 1_000_000)  // Fund and wait
addr := funder.GetAddress()                              // Funding account address
```

#### **TestnetConfig** (`harness/testnet.go`)
Selected integration network connection and utilities:
- Requires `APLANE_INTEGRATION_NETWORK=testnet` or `localnet`
- Testnet algod default: `https://testnet-api.4160.nodely.dev`
- LocalNet algod default: `http://localhost:4001`
- Suggested params, account info queries
- Transaction confirmation waiting with round-based polling

```go
network, err := harness.NewTestnetConfig()
sp, err := network.GetSuggestedParams()
balance, err := network.GetAccountInfo(address)
confirmed, err := network.WaitForConfirmation(txid, 10)  // max 10 rounds
```

### How Tests Use the Environment

Each integration test follows this pattern:

1. **Start signer** — `NewSignerHarness(t)` reads from `APSIGNER_DATA`, builds and starts apsigner
2. **Manage keys** — `NewApAdminHarness(t, ...)` generates/imports keys via IPC
3. **Unlock** — Background unlock process or `TEST_PASSPHRASE` auto-unlock
4. **Transact** — Use apshell harness (SSH tunnel) or direct HTTP
5. **Verify** — Check responses, confirm on the selected integration network
6. **Clean up** — `apadmin.Cleanup()` deletes generated keys, `signerd.Stop()` kills the process, `CloseAccount` returns funds

The signer auto-unlocks on startup when `TEST_PASSPHRASE` is set. The SSH tunnel uses the pre-populated `known_hosts` from the test environment, so no TOFU prompts occur.

The Go, TypeScript, and Python SDKs live in the separate MIT-licensed
`aplane-algo/aplanesdk` repository. SDK unit tests, SDK contract checks, and
SDK package integration coverage are owned there.

## API Contract Tests

`make contract-test` runs the offline signer API compatibility suite. This is separate from both ordinary Go unit tests and integration tests.

What it verifies:

- the committed signer API JSON fixtures decode and re-encode through `pkg/signerapi` without dropping or renaming fields,
- every committed contract fixture is accounted for by the signer API fixture manifest.

The contract fixtures live under:

```text
test/contracts/signerapi/
```

These files are committed golden fixtures, not generated test state. Update them intentionally in the same change as any compatibility-bearing wire contract change.

Run the suite with:

```bash
make contract-test
```

The target prints a section header before each leg:

```text
== Go signer API ==
```

Under the hood, it runs:

```bash
go test -v -run 'TestSignerAPIContract(FixturesRoundTrip|FixtureManifest)' ./pkg/signerapi
```

Environment requirements:

- Go toolchain.

What it does **not** require:

- no `.env.test`,
- no `/tmp/aplane-test-env`,
- no funded integration account,
- no algod, KMD, or indexer,
- no running `apsigner`,
- no keystore, signer unlock, SSH tunnel, or IPC connection.

Do not wire this suite to `test/setup-test-env.sh`. Integration setup can be useful when manually collecting candidate live responses, but the committed contract fixtures are the source of truth for these tests.

`make contract-test` is not folded into `make test` because it is a compatibility
gate with a narrower fixture focus. Use `make contract-test` directly or via
`make check`.

For full non-integration validation, use:

```bash
make check
```

`make check` runs the Go unit suite (`make test`) and then the signer API
contract suite (`make contract-test`). It is the recommended local pre-PR target
for non-integration validation.

Contract decoding policy:

- API decoders should be permissive about unknown response fields so additive signer API fields remain forward-compatible.
- Required-field and wrong-type validation may be added where there is a real validation boundary, but the contract suite should not introduce strict unknown-field rejection without an explicit API policy change.
- Do not add shadow raw DTO layers in TypeScript or Python just to mimic Go-style round trips; test the real request builders and public response mappings instead.

## Docker Install Smoke Tests

The installer smoke tests build or consume a release tarball and run it inside Ubuntu containers. They validate packaging, install layouts, uninstall behavior, and the live-daemon gates that prevent replacing files while a signer is running.

```bash
# Local, rootless install mode in a non-systemd container
make docker-local-test

# Systemd install mode in a systemd container
make docker-systemd-test
```

`make docker-local-test` uses `scripts/docker-local-smoke.sh`. It verifies the rootless layout, bundled binaries including `approbe`, `appass --check`, token request approval through `apapprover`, `apshell status`, the live-signer install gate, stopped in-place reinstall rejection for this new-install-only release, installed-uninstaller behavior, and uninstall state preservation.

`make docker-systemd-test` uses `scripts/docker-systemd-smoke.sh`. It verifies `/usr/local/bin` and `/var/lib/apsigner` layout, systemd service status, memory-locking unit settings, `appass --check`, token request approval, the active-service install gate, stopped in-place systemd reinstall rejection for this new-install-only release, and uninstall signer-state preservation.

## REPL Testing

### What is REPL Testing?

REPL (Read-Eval-Print-Loop) testing validates the interactive command-line user experience. These tests run actual commands in the apshell shell to verify:

- Command syntax and parsing
- User workflow completeness
- Transaction routing logic
- Group formation behavior
- Error messages and guidance

### Manual REPL Testing

REPL testing is performed manually by running commands in the apshell shell:

```bash
# Start apshell and connect to signer (connection target from endpoints.yaml)
bin/apshell -d /path/to/apclient
apshell> connect
apshell> network <testnet|localnet>

# Test key generation
apshell> generate aplane.falcon1024.v1

# Test transaction commands
apshell> send 0.1 algo from <from> to <to>
apshell> status

# Test help and info
apshell> help
apshell> accounts
```

### REPL vs Integration Tests

| Aspect | REPL Tests | Integration Tests |
|--------|-----------|-------------------|
| **Format** | Manual shell commands | Go test files |
| **Execution** | Manual in apshell shell | Automated via `go test` |
| **Focus** | User experience | Code correctness |
| **Coverage** | Command workflows | Component behavior |
| **Duration** | 5-10 minutes | ~1000 seconds for a full run |
| **Setup** | Requires configured signer/client data | Fixture plus per-test funding helpers |

## Running Tests

This section is the canonical command catalog. The "Quick Reference" at the bottom of the doc cross-references back here.

### Quick Commands

Uses `$PKGS` from [Selecting test packages](#selecting-test-packages) where shown.

```bash
# Unit tests only (exclude integration)
make unit-test

# Integration tests only (regenerates fixture and sources .env.test)
APLANE_INTEGRATION_NETWORK=localnet make integration-test

# Signer API contract tests
make contract-test

# Full non-integration validation
make check

# Full local/release gate
make integrity-check

# With coverage
go test -cover $PKGS

# With race detection
make race-test

# Verbose mode
go test -v $PKGS

# Specific package
go test ./internal/signing

# Specific test
go test -v -run TestGenerate ./lsig/falcon1024/keygen
```

### Test Flags

| Flag | Description |
|------|-------------|
| `-v` | Verbose output (show all test names) |
| `-cover` | Show coverage percentages |
| `-race` | Enable race detector |
| `-run PATTERN` | Run only tests matching pattern |
| `-timeout DURATION` | Set test timeout (default 10m) |
| `-count N` | Run tests N times |
| `-parallel N` | Run N tests in parallel |

### Getting Test Coverage

Uses `$PKGS` from [Selecting test packages](#selecting-test-packages).

```bash
# Generate coverage report
go test -coverprofile=coverage.out $PKGS

# View coverage in browser
go tool cover -html=coverage.out

# Show coverage by function
go tool cover -func=coverage.out

# Get total coverage percentage
go test -cover $PKGS | grep coverage
```

## Writing Integration Tests

Project-specific conventions for new integration tests. Generic Go testing
patterns (table-driven, `t.Run`, `t.TempDir`, testify) are not repeated here.

1. **Gate on the network env var**. Integration tests must require
   `APLANE_INTEGRATION_NETWORK`:

   ```go
   if os.Getenv("APLANE_INTEGRATION_NETWORK") == "" {
       t.Fatal("APLANE_INTEGRATION_NETWORK must be set to testnet or localnet")
   }
   ```

   The integration package as a whole also gates on `INTEGRATION=1`; see
   [Running Integration Tests](#running-integration-tests).

2. **Use the harnesses, not raw process spawning**. New tests start the signer
   via `harness.NewSignerHarness(t)`, manage keys via
   `harness.NewApAdminHarness(t, ...)`, and drive apshell via
   `harness.NewApshellHarness(t, ...)`. See
   [Integration Test Harness](#integration-test-harness).

3. **Always defer cleanup** so a failing test still releases the signer process
   and removes generated keys:

   ```go
   defer func() { _ = signerd.Stop() }()
   defer apadmin.Cleanup()
   ```

4. **Recover funds with `CloseAccount`**, not `SendTransaction`. `CloseAccount`
   uses `CloseRemainderTo` to return the entire balance minus fee, preventing
   dust leakage on testnet. See [Fund recovery](#fund-recovery).

5. **Pick timeouts that match block inclusion time**. Full testnet runs take
   ~1000s because each confirmed group waits ~3s per block. Per-test
   `context.WithTimeout` values must accommodate real finality; do not copy
   short unit-test timeouts. The Go-level `-timeout` for the whole suite is
   typically `25m` (see `INTEGRATION_GO_ARGS` in
   [Running Integration Tests](#running-integration-tests)).

## Coverage

### Coverage Goals

| Category | Target |
|----------|--------|
| Core signing logic | >90% |
| Key generation | >75% |
| Cache mechanisms | >85% |
| CLI workflows | >70% |
| Overall | >75% |

Use the commands below for current coverage numbers; checked-in percentages drift quickly as packages move.

### Measuring Coverage

Uses `$PKGS` from [Selecting test packages](#selecting-test-packages).

```bash
# Per-package coverage
go test -cover $PKGS

# Detailed coverage report
go test -coverprofile=coverage.out $PKGS
go tool cover -html=coverage.out

# Coverage by function
go tool cover -func=coverage.out | grep -v 100.0%
```

### Coverage Exclusions

Some code is intentionally excluded from coverage targets:
- Generated code (protobuf, mocks)
- Main functions (entry points)
- Debug/development utilities
- Third-party integrations (tested via integration tests)

## Continuous Integration

### Current CI Pipeline

CI runs automatically on all pushes and PRs to master/main branches via GitHub Actions (`.github/workflows/ci.yml`).

#### What Runs in CI

| Job | Checks | Runs On |
|-----|--------|---------|
| **Lint** | gofmt, go vet, staticcheck, golangci-lint | Every push/PR |
| **Test** | Unit tests with race detector and coverage | After lint passes |
| **Contract** | Signer API contract fixtures | After lint passes |
| **Build** | Compile all packages | After lint passes |
| **Security** | keyzero, keylog, insecurerand, seedphrase analyzers | After lint passes |

#### What Does NOT Run in CI

**Integration tests** are excluded from CI for these reasons:

1. **Funding / service requirement**: Testnet runs need a funded testnet
   mnemonic; localnet runs need an algod/KMD service with exportable funded keys.
2. **Network dependency**: Tests require stable live algod behavior.
3. **Cost**: Testnet runs consume testnet ALGO.
4. **Flakiness**: Live network tests can fail due to congestion, rate limits, or
   local service availability.

Run integration tests locally before submitting changes that affect transaction flows:

```bash
export APLANE_INTEGRATION_NETWORK=testnet
export TEST_FUNDING_MNEMONIC="your twenty five word mnemonic..."
make integration-test

# Or, with AlgoKit LocalNet already running:
APLANE_INTEGRATION_NETWORK=localnet make integration-test
```

### CI Guardrails

The CI workflow enforces these quality gates:

```yaml
# Lint job (must pass first)
- gofmt check (formatting)
- go vet (static analysis)
- staticcheck 2025.1.1 (extended checks)
- golangci-lint v2.8.0 (comprehensive linting)

# Test job (depends on lint)
- go test -race -coverprofile=coverage.out -covermode=atomic (race detector and coverage enabled)
- Coverage uploaded to Codecov
- Integration tests EXCLUDED: grep -v '/test/integration'

# Contract job (depends on lint)
- make contract-test

# Security job (depends on lint)
- keyzero: verifies key material is zeroed
- keylog: detects potential key logging
- insecurerand: ensures crypto/rand usage
- seedphrase: detects committed seed phrases
```

### Running CI Checks Locally

Before pushing, run the same checks CI performs:

```bash
# Formatting
gofmt -l . | head

# Static analysis
go vet ./...
staticcheck ./...
golangci-lint run --timeout=5m

# Tests with race detector (excluding integration)
go test -race $(go list ./... | grep -v '/test/integration')

# API / SDK contracts
make contract-test

# Security analyzers
go run ./analysis/keyzero .
go run ./analysis/keylog .
go run ./analysis/insecurerand .
go run ./analysis/seedphrase -git .
```

Or use the Makefile targets:

```bash
make test              # Unit tests
make security-analysis # All local security analyzers, including seed phrase detection
```

### CI/CD Strategy

**Unit Tests**:
- Run on every commit
- Fast feedback (<2 minutes)
- Must pass before merge

**Integration Tests**:
- Run locally by developers
- Run before releases
- Require `APLANE_INTEGRATION_NETWORK`
- Testnet profile requires `TEST_FUNDING_MNEMONIC`
- LocalNet profile requires running algod/KMD; setup exports the funding mnemonic from KMD

**REPL Tests**:
- Manual execution before releases
- Regression testing for user workflows

## Troubleshooting

### Common Issues

**Unit Tests**

1. **Test caching**: Tests not running
   ```bash
   go clean -testcache
   make unit-test
   ```

2. **File permission errors**: Use proper umask
   ```go
   os.WriteFile(path, data, 0600)  // Not 0644
   ```

3. **Working directory issues**: Always use absolute paths or t.TempDir()

**Integration Tests**

1. **"APLANE_INTEGRATION_NETWORK must be set"**
   - Set `APLANE_INTEGRATION_NETWORK=testnet` or `APLANE_INTEGRATION_NETWORK=localnet`
   - The setup script intentionally has no implicit default.

2. **"TEST_FUNDING_MNEMONIC not set"**
   - For testnet, set the environment variable with your funded testnet account mnemonic
   - Get testnet ALGO from: https://dispenser.testnet.aws.algodev.network/
   - For localnet, do not set this manually; run setup with `APLANE_INTEGRATION_NETWORK=localnet` so KMD export populates it.

3. **"Keystore not initialized"**
   - Run `APLANE_INTEGRATION_NETWORK=<testnet|localnet> make integration-test` to regenerate the test environment and run the suite
   - The script initializes the keystore by piping the generated test passphrase to `apstore initialize`

4. **"failed to connect to algod"**
   - In testnet mode, check internet connection and `ALGOD_URL` / `ALGOD_TOKEN`.
   - In localnet mode, verify AlgoKit LocalNet is running and `ALGOD_URL` or `APLANE_LOCALNET_ALGOD_URL` points at its algod endpoint.

5. **"KMD wallet ... not found" or "no funded KMD wallet account found"**
   - Localnet setup needs KMD reachable at `APLANE_LOCALNET_KMD_URL` and a funded account in `APLANE_LOCALNET_WALLET`.
   - For standard AlgoKit LocalNet, the defaults are `http://localhost:4002` and `unencrypted-default-wallet`.
   - If your wallet has a password, set `APLANE_LOCALNET_WALLET_PASSWORD`.

6. **"apsigner failed to start"**
   - Check if the assigned ports are already in use (re-run setup to pick new ports)
   - Review logs: Tests print log file path with `-v`

7. **"host key rejected by user"**
   - The test environment pre-populates `known_hosts`, but if keys were regenerated
     without re-running setup, delete `/tmp/aplane-test-env` and re-run `APLANE_INTEGRATION_NETWORK=<testnet|localnet> make integration-test`

8. **"transaction not confirmed"**
   - Testnet may be congested, or localnet may have stopped.
   - For testnet, check the transaction in an explorer.
   - Increase timeout in test

**SDK Tests**

SDK tests are owned by the external `aplane-algo/aplanesdk` repository.

**REPL Tests**

- Check that Signer is running and connected
- Verify test accounts are funded
- Run `rekey` to check rekeyed account states

### Debug Mode

Enable debug logging:
```bash
export APSHELL_DEBUG=1
APLANE_INTEGRATION_NETWORK=localnet make integration-test INTEGRATION_GO_ARGS='-count=1 -timeout 25m -v'
```

View full test output:
```bash
go test -v $(go list ./... | grep -v '/test/integration') 2>&1 | tee test.log
```

## Test Suite Overview

| Test Type | Duration | Frequency | Prerequisites |
|-----------|----------|-----------|---------------|
| **Unit** | 10-30s | Every commit | None |
| **API Contract** | <1s | Every signer API contract change | Go |
| **Integration** | profile-dependent | On-demand | `APLANE_INTEGRATION_NETWORK` plus profile-specific funding/service inputs |
| **REPL** | 5-10min | Before releases | Funded accounts |

## Quick Reference

The canonical command catalog lives in [Running Tests](#running-tests).
Day-to-day shortcuts:

| Goal | Command |
|------|---------|
| Local pre-commit | `make check` (unit + contract) |
| Race detector pass | `make race-test` |
| Integration on testnet | `APLANE_INTEGRATION_NETWORK=testnet TEST_FUNDING_MNEMONIC=... make integration-test` |
| Integration on LocalNet | `APLANE_INTEGRATION_NETWORK=localnet make integration-test` |
| Focused integration run | add `INTEGRATION_GO_ARGS='-count=1 -timeout 25m -v -run TestX'` |
| Reuse existing fixture | `make integration-test-reuse` |
| Coverage HTML | `go test -coverprofile=coverage.out $PKGS && go tool cover -html=coverage.out` |
