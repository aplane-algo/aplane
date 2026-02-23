# Integration Testing

This directory contains integration tests for Signer and Algosh that validate end-to-end functionality against Algorand testnet.

## Prerequisites

### 1. Funded Test Account

Integration tests require a funded Algorand testnet account. You have two options:

#### Option A: Provide Account Address Only (for balance checking)
```bash
export TEST_FUNDING_ACCOUNT="YOUR_TESTNET_ADDRESS_HERE"
```

#### Option B: Provide Mnemonic (for actual funding)
```bash
export TEST_FUNDING_MNEMONIC="your twenty five word mnemonic phrase here..."
```

The account should have:
- At least 10 ALGO for test transactions
- If using mnemonic, the tests will automatically fund test accounts

### 2. Testnet Connection

By default, tests connect to Algonode's public testnet API. To use a different node:

```bash
export ALGOD_URL="https://your-algod-node:port"
export ALGOD_TOKEN="your-api-token"  # If required
```

## Running Tests

### Run All Integration Tests
```bash
go test ./test/integration/...
```

### Run with Verbose Output
```bash
go test -v ./test/integration/...
```

### Run Specific Test
```bash
go test -v -run TestBasicFalconTransaction ./test/integration/...
```

### Skip Integration Tests
If `TEST_FUNDING_ACCOUNT` is not set, integration tests will be skipped automatically.

## Test Structure

### Harness Components

The test harness provides utilities for managing test infrastructure:

#### `harness/funding.go`
- Validates funding account balance before tests
- Ensures sufficient ALGO/assets for test operations
- Prevents tests from running without proper funding

#### `harness/signer.go`
- Manages Signer process lifecycle
- Builds and starts Signer in isolated environment
- Captures logs for debugging
- Handles graceful shutdown

#### `harness/algosh.go`
- Provides programmatic interface to algosh CLI
- Manages key generation and transactions
- Handles input/output for interactive commands

#### `harness/testnet.go`
- Testnet connection management
- Transaction submission and confirmation
- Account information queries
- Retry logic for network operations

### Test Files

#### `basic_falcon_test.go`
Contains fundamental Falcon signing tests:
- `TestBasicFalconTransaction`: Simple payment with Falcon signature
- `TestFalconGroupTransaction`: Atomic group with Falcon signatures
- `TestFalconWithPassphrase`: Encrypted key usage
- `TestSignerRestart`: Key persistence across restarts

## Writing New Tests

### Basic Test Template

```go
func TestMyFeature(t *testing.T) {
    // Skip if no funding account
    if os.Getenv("TEST_FUNDING_ACCOUNT") == "" {
        t.Skip("TEST_FUNDING_ACCOUNT not set")
    }

    // Start Signer
    apsignerd := harness.NewSignerHarness(t)
    if err := apsignerd.Start(); err != nil {
        t.Fatalf("Failed to start Signer: %v", err)
    }
    defer apsignerd.Stop()

    // Create algosh harness
    algosh := harness.NewAlgoshHarness(t, apsignerd.GetURL())

    // Your test logic here...
}
```

### Best Practices

1. **Always check funding**: Use `TestMain` to verify funding account
2. **Clean up resources**: Use `defer` for cleanup operations
3. **Isolate tests**: Each test gets its own temp directory
4. **Log important steps**: Use `t.Log()` for test progress
5. **Handle retries**: Network operations may be flaky
6. **Check logs**: Verify operations in Signer logs when possible

## Test Scenarios

### Phase 1 (Current)
- ✅ Basic Falcon transaction signing
- ✅ Key generation and persistence
- ✅ Passphrase protection
- ✅ Process restart handling

### Phase 2 (Planned)
- [ ] Atomic group transactions
- [ ] Mixed Ed25519/Falcon groups
- [ ] Rekeyed account handling
- [ ] Cache eviction and reload
- [ ] SSH tunnel operation

### Phase 3 (Future)
- [ ] Concurrent operations
- [ ] Error recovery scenarios
- [ ] Performance benchmarks
- [ ] Load testing

## Debugging

### View Test Logs
Run tests with `-v` flag to see detailed output:
```bash
go test -v ./test/integration/...
```

### Check Signer Logs
Logs are saved in the test's temp directory. The path is printed when tests run with `-v`.

### Common Issues

1. **"TEST_FUNDING_ACCOUNT not set"**
   - Set the environment variable with your funded testnet address

2. **"insufficient ALGO in funding account"**
   - Fund your test account with at least 10 ALGO from the [testnet dispenser](https://dispenser.testnet.aws.algodev.network/)

3. **"failed to connect to algod"**
   - Check your internet connection
   - Verify ALGOD_URL if using custom node

4. **"apsignerd failed to start"**
   - Check that the project builds successfully
   - Review Signer logs for startup errors

## Continuous Integration

To run integration tests in CI/CD:

1. Set up secrets for `TEST_FUNDING_ACCOUNT` private key
2. Fund the account periodically (testnet resets monthly)
3. Consider running integration tests on a schedule rather than every commit
4. Use test result caching for faster feedback

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `TEST_FUNDING_ACCOUNT` | Funded testnet address for balance checking | (optional) |
| `TEST_FUNDING_MNEMONIC` | Mnemonic for funding test accounts | (optional) |
| `ALGOD_URL` | Algod API endpoint | `https://testnet-api.algonode.cloud` |
| `ALGOD_TOKEN` | Algod API token | (empty) |
| `TEST_VERBOSE` | Enable verbose logging | `false` |

Note: At least one of `TEST_FUNDING_ACCOUNT` or `TEST_FUNDING_MNEMONIC` must be set for tests to run.

## Contributing

When adding new integration tests:

1. Follow the existing test structure
2. Add documentation for new test scenarios
3. Ensure tests are idempotent
4. Clean up all resources
5. Update this README with new test descriptions
