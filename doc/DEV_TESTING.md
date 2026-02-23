# Testing Guide

This document describes the testing strategy and practices for the aPlane Shell project.

## Table of Contents

- [Overview](#overview)
- [Unit Testing](#unit-testing)
- [Integration Testing](#integration-testing)
- [REPL Testing](#repl-testing)
- [Running Tests](#running-tests)
- [Writing Tests](#writing-tests)
- [Coverage](#coverage)
- [Continuous Integration](#continuous-integration)

## Overview

The project uses a three-tier testing approach:

1. **Unit Tests**: Fast, isolated tests for individual components (Go test framework)
2. **Integration Tests**: End-to-end tests against real Algorand testnet (Go test framework)
3. **REPL Tests**: Interactive command-line testing for user workflows (manual)

This combination ensures code correctness, real-world compatibility, and user experience validation.

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

```
aplane/
├── cmd/
│   ├── apshell/
│   │   ├── audit_test.go          # Command audit logging tests
│   │   ├── commands_test.go       # Command handler tests
│   │   └── transactions_test.go   # Transaction building tests
│   ├── apsignerd/
│   │   ├── audit_test.go          # Signer audit logging tests
│   │   ├── server_test.go         # HTTP server tests
│   │   └── hub_test.go            # Hub state tests
│   └── apadmin/
│       └── audit_test.go          # Admin audit logging tests
├── lsig/
│   └── falcon1024/
│       ├── keygen/
│       │   └── generator_test.go  # Falcon key generation tests
│       ├── signing/
│       │   └── provider_test.go   # Falcon signing provider tests
│       ├── mnemonic/
│       │   └── handler_test.go    # Falcon mnemonic tests
│       └── metadata_test.go       # Algorithm metadata tests
├── internal/
│   ├── algo/
│   │   ├── client_test.go         # Algorand client tests
│   │   └── parser_test.go         # Transaction parser tests
│   ├── command/
│   │   ├── command_test.go        # Command structure tests
│   │   ├── context_test.go        # Execution context tests
│   │   └── registry_test.go       # Command registry tests
│   ├── crypto/
│   │   └── encryption_test.go     # Encryption tests
│   ├── engine/
│   │   ├── engine_test.go         # Core engine tests
│   │   ├── accounts_test.go       # Account management tests
│   │   └── cache_test.go          # Engine cache tests
│   ├── keygen/
│   │   └── ed25519_test.go        # Ed25519 key generation tests
│   ├── logicsigdsa/
│   │   └── dsa_test.go            # LogicSig DSA registry tests
│   ├── lsig/
│   │   └── wrapper_test.go        # LogicSig wrapper tests
│   ├── mnemonic/
│   │   ├── ed25519_test.go        # Ed25519 mnemonic tests
│   │   └── handler_test.go        # Mnemonic handler tests
│   ├── repl/
│   │   └── parser_test.go         # Command parsing tests
│   ├── signing/
│   │   ├── common_test.go         # Common signing tests
│   │   ├── ed25519_test.go        # Ed25519 signing tests
│   │   ├── mixed_test.go          # Mixed signing group tests
│   │   └── registry_test.go       # Signing provider registry tests
│   ├── transaction/
│   │   └── keyreg_test.go         # Key registration tests
│   ├── transport/
│   │   └── client_test.go         # IPC transport tests
│   └── util/
│       ├── auth_cache_test.go     # Auth address cache tests
│       ├── format_test.go         # Formatting tests
│       └── lsig_test.go           # LogicSig utility tests
```

### Example Unit Test

```go
func TestFalconKeyGeneration(t *testing.T) {
    // Use t.TempDir() for isolation
    tmpDir := t.TempDir()
    oldDir, _ := os.Getwd()
    defer os.Chdir(oldDir)
    os.Chdir(tmpDir)

    generator := &FalconGenerator{}
    seed := make([]byte, 64)

    // Generate key
    result, err := generator.GenerateFromSeed(seed, "")
    if err != nil {
        t.Fatalf("Failed to generate key: %v", err)
    }

    // Verify result
    if result.Address == "" {
        t.Error("Expected address to be set")
    }
    if result.PublicKeyHex == "" {
        t.Error("Expected public key to be set")
    }
}
```

### Unit Test Best Practices

1. **Isolation**: Use `t.TempDir()` for file operations
2. **Determinism**: Use fixed seeds/inputs for reproducible results
3. **Fast Execution**: Mock external dependencies (network, Signer server)
4. **Clear Naming**: Test names should describe what they test
5. **Table-Driven Tests**: Use table-driven tests for multiple scenarios

### Running Unit Tests

```bash
# Run all unit tests
go test ./...

# Run with verbose output
go test -v ./...

# Run specific package
go test ./internal/signing

# Run with coverage
go test -cover ./...

# Run with race detection
go test -race ./...

# Run specific test
go test -v -run TestFalconKeyGeneration ./lsig/falcon1024/keygen
```

### Current Unit Test Coverage

| Package | Coverage | Key Test Files |
|---------|----------|----------------|
| `internal/engine` | 80%+ | `engine_test.go`, `accounts_test.go`, `cache_test.go` |
| `internal/repl` | 80%+ | `parser_test.go` |
| `lsig/falcon1024` | 75%+ | `keygen/generator_test.go`, `signing/provider_test.go` |
| `internal/signing` | 67%+ | `ed25519_test.go`, `mixed_test.go`, `registry_test.go` |
| `internal/logicsigdsa` | 90%+ | `dsa_test.go` |
| `internal/util` | 85%+ | `auth_cache_test.go`, `encryption_test.go`, `lsig_test.go` |
| `cmd/*/` | 90%+ | `audit_test.go`, `server_test.go`, `commands_test.go` |

## Integration Testing

### What We Test

Integration tests validate:
- Full transaction flow from key generation to testnet submission
- Signer process lifecycle management
- Apshell CLI interaction patterns
- Real network transaction confirmation
- Falcon signature validation by Algorand nodes
- Atomic group transactions
- Key persistence across restarts

### Integration Test Structure

```
test/
├── integration/
│   ├── harness/
│   │   ├── apshell.go       # Apshell CLI test interface
│   │   ├── fund.go          # SDK-based funding helper
│   │   ├── funding.go       # Funding account validation
│   │   ├── signer.go        # Signer process management
│   │   ├── apadmin.go   # SignerAdmin process management
│   │   ├── testnet.go       # Testnet utilities
│   │   └── util.go          # Shared test utilities
│   ├── basic_falcon_test.go # Core Falcon integration tests
│   └── README.md            # Integration testing guide
```

### Prerequisites

Integration tests require:

1. **Funded Testnet Account**: Either address for balance checking or mnemonic for funding
2. **Network Access**: Connection to Algorand testnet
3. **Build Environment**: Ability to compile Signer and Apshell

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `TEST_FUNDING_ACCOUNT` | Testnet address for balance checking | Optional* |
| `TEST_FUNDING_MNEMONIC` | 25-word mnemonic for funding test accounts | Optional* |
| `ALGOD_URL` | Algod API endpoint | No (default: Algonode) |
| `ALGOD_TOKEN` | Algod API token | No |

\* At least one of `TEST_FUNDING_ACCOUNT` or `TEST_FUNDING_MNEMONIC` must be set

### Example Integration Test

```go
func TestBasicFalconTransaction(t *testing.T) {
    // Skip if no funding configured
    if os.Getenv("TEST_FUNDING_MNEMONIC") == "" {
        t.Skip("TEST_FUNDING_MNEMONIC not set")
    }

    // Connect to testnet
    testnet, err := harness.NewTestnetConfig()
    if err != nil {
        t.Fatalf("Failed to connect to testnet: %v", err)
    }

    // Start Signer
    apsignerd := harness.NewSignerHarness(t)
    if err := apsignerd.Start(); err != nil {
        t.Fatalf("Failed to start Signer: %v", err)
    }
    defer apsignerd.Stop()

    // Create apshell harness
    apshell := harness.NewApshellHarness(t, apsignerd.GetURL())

    // Generate Falcon key
    address, err := apshell.GenerateKey("test seed")
    if err != nil {
        t.Fatalf("Failed to generate key: %v", err)
    }

    // Fund the account
    funder, _ := harness.NewFundTestAccount(testnet.Client)
    if err := funder.FundAndWait(address, 1.0); err != nil {
        t.Fatalf("Failed to fund: %v", err)
    }

    // Send transaction
    txid, err := apshell.SendTransaction(address, recipient, 0.1)
    if err != nil {
        t.Fatalf("Failed to send: %v", err)
    }

    // Wait for confirmation
    if err := funder.WaitForConfirmation(txid); err != nil {
        t.Fatalf("Transaction not confirmed: %v", err)
    }

    t.Logf("Transaction confirmed: %s", txid)
}
```

### Running Integration Tests

```bash
# Set up environment
export TEST_FUNDING_MNEMONIC="your twenty five word mnemonic here..."

# Run all integration tests
go test ./test/integration/...

# Run with verbose output
go test -v ./test/integration/...

# Run specific test
go test -v -run TestBasicFalconTransaction ./test/integration/...
```

### Integration Test Harness

The test harness provides utilities for managing test infrastructure:

#### **SignerHarness** (`harness/signer.go`)
Manages Signer process lifecycle:
- Builds Signer binary from project root
- Starts process in isolated directory
- Allocates free port dynamically (no port conflicts)
- Captures logs for debugging
- Handles stdin for passphrase prompt
- HTTP health check for readiness
- Handles graceful shutdown

```go
apsignerd := harness.NewSignerHarness(t)
if err := apsignerd.Start(); err != nil {
    t.Fatalf("Failed to start: %v", err)
}
defer apsignerd.Stop()

url := apsignerd.GetURL()           // Get connection URL
logs, _ := apsignerd.GetLogs()      // Get captured logs
```

#### **ApshellHarness** (`harness/apshell.go`)
Provides programmatic interface to apshell CLI:
- Builds apshell binary from project root
- Manages working directory and keys
- Auto-connects to Signer using `connect` command
- Handles stdin/stdout for interactive commands

```go
apshell := harness.NewApshellHarness(t, apsignerd.GetURL())

// Generate key
address, err := apshell.GenerateKey("seed phrase")

// Send transaction
txid, err := apshell.SendTransaction(from, to, amount)

// Run custom command
output, err := apshell.RunWithInput("status\nquit\n")
```

#### **FundTestAccount** (`harness/fund.go`)
SDK-based funding for test accounts:
- Uses mnemonic from environment
- Direct transaction submission
- Confirmation waiting

```go
funder, err := harness.NewFundTestAccount(client)
if err := funder.FundAndWait(address, 1.0); err != nil {
    t.Fatalf("Funding failed: %v", err)
}
```

#### **TestnetConfig** (`harness/testnet.go`)
Testnet connection and utilities:
- Algod client management (default: Algonode)
- Transaction submission
- Account queries
- Retry logic with exponential backoff

```go
testnet, err := harness.NewTestnetConfig()
sp, err := testnet.GetSuggestedParams()
acct, err := testnet.GetAccountInfo(address)
```

### Integration Test Phases

**Phase 1 (Current)**
- ✅ Basic Falcon transaction signing
- ✅ Key generation and persistence
- ✅ Passphrase protection
- ✅ Process restart handling
- ✅ Harness infrastructure

**Phase 2 (Planned)**
- [ ] Atomic group transactions
- [ ] Mixed Ed25519/Falcon groups
- [ ] Rekeyed account handling
- [ ] Cache eviction and reload
- [ ] SSH tunnel operation

**Phase 3 (Future)**
- [ ] Concurrent operations
- [ ] Error recovery scenarios
- [ ] Performance benchmarks
- [ ] Load testing

## REPL Testing

### What is REPL Testing?

REPL (Read-Eval-Print-Loop) testing validates the interactive command-line user experience. These tests run actual commands in the apshell shell to verify:

- Command syntax and parsing
- User workflow completeness
- Transaction routing logic
- Group formation behavior
- Error messages and guidance

### Manual REPL Testing

REPL testing is currently performed manually by running commands in the apshell shell:

```bash
# Start apshell and connect to signer
./apshell
apshell> connect localhost:11270
apshell> network testnet

# Test key generation
apshell> generate falcon

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
| **Duration** | 5-10 minutes | 1-5 minutes |
| **Setup** | Requires pre-funded accounts | Auto-funds test accounts |

## Running Tests

### Quick Commands

```bash
# Run everything (unit tests only)
go test ./...

# Unit tests only (exclude integration)
go test $(go list ./... | grep -v test/integration)

# Integration tests only
go test ./test/integration/...

# With coverage
go test -cover ./...

# With race detection
go test -race ./...

# Verbose mode
go test -v ./...

# Specific package
go test ./internal/signing

# Specific test
go test -v -run TestFalconKeyGeneration ./lsig/falcon1024/keygen
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

```bash
# Generate coverage report
go test -coverprofile=coverage.out ./...

# View coverage in browser
go tool cover -html=coverage.out

# Show coverage by function
go tool cover -func=coverage.out

# Get total coverage percentage
go test -cover ./... | grep coverage
```

## Writing Tests

### Unit Test Guidelines

1. **Test Structure**: Arrange-Act-Assert pattern
```go
func TestFeature(t *testing.T) {
    // Arrange: Set up test data
    input := "test"

    // Act: Execute the code
    result := ProcessInput(input)

    // Assert: Verify the result
    if result != expected {
        t.Errorf("got %v, want %v", result, expected)
    }
}
```

2. **Table-Driven Tests**: For multiple scenarios
```go
func TestValidation(t *testing.T) {
    tests := []struct {
        name    string
        input   string
        wantErr bool
    }{
        {"valid input", "abc", false},
        {"empty input", "", true},
        {"invalid chars", "!@#", true},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            err := Validate(tt.input)
            if (err != nil) != tt.wantErr {
                t.Errorf("wantErr %v, got %v", tt.wantErr, err)
            }
        })
    }
}
```

3. **Subtests**: Group related tests
```go
func TestKeyGeneration(t *testing.T) {
    t.Run("from seed", func(t *testing.T) {
        // Test seed generation
    })

    t.Run("from mnemonic", func(t *testing.T) {
        // Test mnemonic generation
    })

    t.Run("random", func(t *testing.T) {
        // Test random generation
    })
}
```

4. **Test Helpers**: Extract common setup
```go
func setupTestDir(t *testing.T) string {
    tmpDir := t.TempDir()
    oldDir, _ := os.Getwd()
    t.Cleanup(func() { os.Chdir(oldDir) })
    os.Chdir(tmpDir)
    return tmpDir
}

func TestFeature(t *testing.T) {
    dir := setupTestDir(t)
    // Test continues...
}
```

5. **Cleanup**: Use `defer` and `t.Cleanup()`
```go
func TestWithResources(t *testing.T) {
    file, _ := os.Create("test.txt")
    t.Cleanup(func() { os.Remove("test.txt") })

    // Or use defer for immediate cleanup
    defer file.Close()
}
```

### Integration Test Guidelines

1. **Skip Gracefully**: Check prerequisites
```go
func TestIntegration(t *testing.T) {
    if os.Getenv("TEST_FUNDING_MNEMONIC") == "" {
        t.Skip("Skipping integration test: no funding configured")
    }
    // Test continues...
}
```

2. **Resource Management**: Always clean up
```go
apsignerd := harness.NewSignerHarness(t)
if err := apsignerd.Start(); err != nil {
    t.Fatalf("Failed to start: %v", err)
}
defer apsignerd.Stop() // Always defer cleanup
```

3. **Logging**: Use `t.Log()` for progress
```go
t.Log("Starting Signer...")
apsignerd.Start()
t.Log("Generating key...")
address, _ := apshell.GenerateKey("seed")
t.Logf("Generated address: %s", address)
```

4. **Retries**: Handle flaky network operations
```go
config := harness.DefaultRetryConfig()
err := harness.RetryOperation(config, func() error {
    return submitTransaction(txn)
})
```

5. **Timeouts**: Set reasonable limits
```go
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()
```

## Coverage

### Coverage Goals

| Category | Target | Current |
|----------|--------|---------|
| Core signing logic | >90% | 67-90% |
| Key generation | >75% | 75-80% |
| Cache mechanisms | >85% | 85-90% |
| CLI commands | >70% | 90%+ |
| Overall | >75% | ~80% |

### Measuring Coverage

```bash
# Per-package coverage
go test -cover ./...

# Detailed coverage report
go test -coverprofile=coverage.out ./...
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
| **Build** | Compile all packages | After lint passes |
| **Security** | keyzero, keylog, insecurerand analyzers | After lint passes |

#### What Does NOT Run in CI

**Integration tests** are excluded from CI for these reasons:

1. **Funding requirement**: Tests need a funded Algorand testnet account
2. **Network dependency**: Tests require stable testnet connectivity
3. **Cost**: Each test run consumes testnet ALGO
4. **Flakiness**: Network tests can fail due to congestion or rate limits

Run integration tests locally before submitting changes that affect transaction flows:

```bash
export TEST_FUNDING_MNEMONIC="your twenty five word mnemonic..."
make integration-test
```

### CI Guardrails

The CI workflow enforces these quality gates:

```yaml
# Lint job (must pass first)
- gofmt check (formatting)
- go vet (static analysis)
- staticcheck 2025.1.1 (extended checks)
- golangci-lint v1.61.0 (comprehensive linting)

# Test job (depends on lint)
- go test -race (race detector enabled)
- Coverage uploaded to Codecov
- Integration tests EXCLUDED: grep -v '/test/integration'

# Security job (depends on lint)
- keyzero: verifies key material is zeroed
- keylog: detects potential key logging
- insecurerand: ensures crypto/rand usage
```

### Running CI Checks Locally

Before pushing, run the same checks CI performs:

```bash
# Formatting
gofmt -l . | head

# Static analysis
go vet ./...
staticcheck ./...

# Tests with race detector (excluding integration)
go test -race $(go list ./... | grep -v '/test/integration')

# Security analyzers
go run ./analysis/keyzero .
go run ./analysis/keylog .
go run ./analysis/insecurerand .
```

Or use the Makefile targets:

```bash
make test              # Unit tests
make security-analysis # All security analyzers
```

### CI/CD Strategy

**Unit Tests**:
- Run on every commit
- Fast feedback (<2 minutes)
- Must pass before merge

**Integration Tests**:
- Run locally by developers
- Run before releases
- Require `TEST_FUNDING_MNEMONIC` environment variable

**REPL Tests**:
- Manual execution before releases
- Regression testing for user workflows

## Troubleshooting

### Common Issues

**Unit Tests**

1. **Test caching**: Tests not running
   ```bash
   go clean -testcache
   go test ./...
   ```

2. **File permission errors**: Use proper umask
   ```go
   os.WriteFile(path, data, 0600)  // Not 0644
   ```

3. **Working directory issues**: Always use absolute paths or t.TempDir()

**Integration Tests**

1. **"TEST_FUNDING_MNEMONIC not set"**
   - Set the environment variable with your funded testnet account mnemonic
   - Get testnet ALGO from: https://dispenser.testnet.aws.algodev.network/

2. **"failed to connect to algod"**
   - Check internet connection
   - Verify ALGOD_URL if using custom node
   - Try default: `unset ALGOD_URL`

3. **"apsignerd failed to start"**
   - Check build errors: `go build ./cmd/apsignerd`
   - Review logs: Tests print log file path with `-v`
   - Check port availability: Dynamic port allocation should prevent this

4. **"transaction not confirmed"**
   - Testnet may be congested
   - Check transaction on AlgoExplorer
   - Increase timeout in test

**REPL Tests**

- Check that Signer is running and connected
- Verify test accounts are funded
- Run `rekey` to check rekeyed account states

### Debug Mode

Enable debug logging:
```bash
export APSHELL_DEBUG=1
go test -v ./test/integration/...
```

View full test output:
```bash
go test -v ./... 2>&1 | tee test.log
```

## Best Practices Summary

### Unit Tests
✅ Use `t.TempDir()` for isolation
✅ Test deterministically with fixed inputs
✅ Mock external dependencies
✅ Use table-driven tests for scenarios
✅ Keep tests fast (<100ms each)

### Integration Tests
✅ Skip gracefully when prerequisites missing
✅ Always defer cleanup (apsignerd.Stop, etc.)
✅ Use `t.Log()` for progress tracking
✅ Handle network flakiness with retries
✅ Set reasonable timeouts
✅ Dynamic port allocation prevents conflicts

### REPL Tests
✅ Maintain funded test accounts
✅ Run before major releases
✅ Test new commands manually
✅ Document expected outcomes

### General
✅ Write tests before fixing bugs
✅ Maintain >75% coverage
✅ Run tests before committing
✅ Review coverage reports regularly
✅ Document test-specific requirements

## Test Suite Overview

| Test Type | Duration | Frequency | Prerequisites |
|-----------|----------|-----------|---------------|
| **Unit** | 10-30s | Every commit | None |
| **Integration** | 1-5min | Nightly / on-demand | Testnet mnemonic |
| **REPL** | 5-10min | Before releases | Funded accounts |

## Resources

- [Go Testing Package](https://pkg.go.dev/testing)
- [Table Driven Tests](https://github.com/golang/go/wiki/TableDrivenTests)
- [Integration Testing README](../test/integration/README.md)
- [Algorand Testnet Dispenser](https://dispenser.testnet.aws.algodev.network/)

## Contributing

When adding new code:

1. **Write unit tests first** (TDD when possible)
2. **Maintain coverage** (don't decrease overall %)
3. **Add integration tests** for user-facing features
4. **Update REPL tests** if command syntax changes
5. **Update this document** if adding new test patterns
6. **Run all tests** before submitting PR

```bash
# Pre-commit checklist
go test ./...                    # All tests pass
go test -race ./...              # No race conditions
go test -cover ./... | grep coverage  # Coverage maintained
```

## Quick Reference

```bash
# Daily development
go test ./...                                    # Run unit tests

# Before PR
go test -race -cover ./...                       # Full unit test suite

# Integration testing
export TEST_FUNDING_MNEMONIC="..."
go test -v ./test/integration/...                # Run integration tests

# REPL testing (manual)
./apshell
apshell> connect localhost:11270
apshell> network testnet
apshell> help                                     # Verify commands available

# Coverage analysis
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out                 # View in browser
```
