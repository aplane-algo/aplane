# Integration Testing

Integration tests for APlane that validate end-to-end functionality against
Algorand TestNet or an explicitly selected AlgoKit LocalNet. Tests spin up
their own apsigner process — no manual process management required.

## Prerequisites

### 1. Test Environment Setup

The `make integration-test` path regenerates an isolated fixture at
`/tmp/aplane-test-env/` on every run by invoking `test/setup-test-env.sh`
first. Select the integration network explicitly. For testnet:

```bash
export APLANE_INTEGRATION_NETWORK=testnet
export TEST_FUNDING_MNEMONIC="your twenty five word mnemonic phrase here..."
./test/setup-test-env.sh
```

To run against an already running v42-capable AlgoKit LocalNet instead, do not
provide a mnemonic. Setup funds a new disposable native Falcon account from
KMD, then exports that account under the same `TEST_FUNDING_MNEMONIC` contract:

```bash
APLANE_INTEGRATION_NETWORK=localnet ./test/setup-test-env.sh
```

`TEST_FUNDING_MNEMONIC` always identifies a protocol-native `falcon1024`
account. It is never interpreted as Ed25519. Public-network runs therefore
require a network that has activated native Falcon authorization (v42).

Corridor/ALock asset vectors reuse the oldest clean `Corridor Test Asset`
created by the funding account for which the account still holds the complete
10-unit supply. If the account has no such fixture, the test creates one on the
selected network. If a matching fixture exists but is depleted, the test fails
instead of creating a replacement, preventing repeated runs from accumulating
assets when cleanup is incomplete.

This creates configs, SSH keys, token, and keystore, then writes `.env.test`
in the project root with all required environment variables.

### 2. Running Tests

```bash
# Recommended: rebuild fixture, rewrite .env.test, then run tests quietly
APLANE_INTEGRATION_NETWORK=testnet make integration-test

# LocalNet run against an already running AlgoKit LocalNet
APLANE_INTEGRATION_NETWORK=localnet make integration-test

# Faster reuse path: keep the existing fixture and .env.test as-is
make integration-test-reuse

# Focused run with a fresh regenerated fixture
APLANE_INTEGRATION_NETWORK=localnet make integration-test INTEGRATION_GO_ARGS='-count=1 -timeout 25m -v -run TestBasicFalconTransaction'

# LocalNet transaction soak test
make soak-test-localnet

# Broad LocalNet apshell command coverage
make apshell-command-coverage-localnet

# Dry-run cleanup for leftover LocalNet signer keys
set -a && . .env.test && set +a
go run ./test/integration/cmd/localnet-clean-test-keys

# Full run with live progress output
make integration-test INTEGRATION_GO_ARGS='-count=1 -timeout 25m -v'

# Manual reuse path: load env vars and opt in to live integration tests
set -a && . .env.test && set +a && INTEGRATION=1 go test ./test/integration -v -count=1

# Run app fixture tests only
make integration-test INTEGRATION_GO_ARGS='-count=1 -timeout 25m -v -run TestAppDeployAndExercise'
```

Plain `go test ./...` does not run the live integration package. Set
`INTEGRATION=1` explicitly, or use `make integration-test`, to opt in. If
`TEST_FUNDING_MNEMONIC` is not set, funding-backed tests skip automatically
even when opted in.

### 3. Network Selection

With `APLANE_INTEGRATION_NETWORK=testnet`, tests connect to Nodely's public
testnet API by default. Override with:

```bash
export ALGOD_URL="https://your-algod-node:port"
export ALGOD_TOKEN="your-api-token"
```

Set `APLANE_INTEGRATION_NETWORK=localnet` to run against LocalNet. LocalNet mode
defaults to:

- algod: `http://localhost:4001`
- KMD: `http://localhost:4002`
- token: the standard AlgoKit LocalNet `aaaaaaaa...` token
- wallet: `unencrypted-default-wallet`

The localnet setup path creates and funds a disposable native Falcon account,
exports its mnemonic as `TEST_FUNDING_MNEMONIC`, writes
`networks.localnet.genesis_hash` into signer config, and seeds the integration
burn address so tests that send small payments to it behave like testnet. Tests
derive the funding address from the mnemonic.

If an interrupted LocalNet soak leaves generated signer keys in the test
fixture, run `go run ./test/integration/cmd/localnet-clean-test-keys` after
sourcing `.env.test`. It is dry-run by default; add `-yes` to delete. The helper
only operates on the APlane signer fixture and does not delete KMD wallet keys
or algod accounts.

For capacity and endurance checks, run `make soak-test-localnet`. It is
LocalNet-only and opt-in; the target regenerates the fixture, starts `apsigner`
once, generates and funds short-lived signer accounts, sends and closes
transactions, and deletes each generated key. It keeps `apsigner` running unless
`APLANE_SOAK_RESTART_EVERY` is set to a positive value. Tune it with
`APLANE_SOAK_DURATION`,
`APLANE_SOAK_MAX_ITERATIONS`, `APLANE_SOAK_RESTART_EVERY`,
`APLANE_SOAK_FALCON_EVERY`, and `SOAK_GO_ARGS`.

For breadth checks, run `make apshell-command-coverage-localnet`. It exercises
the broad LocalNet apshell command surface separately from the endurance soak,
and intentionally skips plugins, token provisioning, and keyreg-online.

## Harness Components

### Process Management

| File | Purpose |
|------|---------|
| `harness/signer.go` | Start/stop apsigner, health checks, log capture |
| `harness/apadmin.go` | Key generation, import, delete, background unlock via apadmin CLI |
| `harness/apshell.go` | Send transactions, close accounts via apshell CLI |

### Network & Funding

| File | Purpose |
|------|---------|
| `harness/testnet.go` | Selected integration network algod client, suggested params, submit, wait for confirmation |
| `harness/funding.go` | Pre-flight funding account balance check |
| `harness/fund.go` | Derive and directly sign with the native Falcon `TEST_FUNDING_MNEMONIC` |
| `cmd/localnet-funding` | Bootstrap a disposable native Falcon funder from LocalNet KMD and export genesis metadata |

### App Fixture

| File | Purpose |
|------|---------|
| `harness/testapp.go` | Deploy test app, call methods, read state, grouped txns |

See `test/fixtures/testapp/README.md` for contract details and usage patterns.

### Utilities

| File | Purpose |
|------|---------|
| `harness/util.go` | `findProjectRoot()` for resolving fixture paths |

## Test Files

### `basic_falcon_test.go`

Falcon happy-path signing:

- `TestBasicFalconTransaction` — simple Falcon-signed payment
- `TestFalconGroupTransaction` — atomic group with Falcon signatures

### `signer_test.go`

Signer boundary, lifecycle, rekey, and LSig coverage:

- `TestSignerRejectsWhenLocked` — locked signer rejection
- `TestSignerRejectsUnauthorizedRequest` — `/sign` auth failures
- `TestPolicyApprovalRejection` — manual approval required without operator
- `TestRekeyedAccountSignsViaAuthAddress` — rekey success path
- `TestRekeyedAccountRejectsMissingAuthAddress` — rekey failure when auth key is unavailable
- `TestFalconPassphraseSigning` — lock/unlock/sign flow for Falcon
- `TestSignerRejectsUnknownSigningAddress` — missing key rejection
- `TestSignerRestartPreservesUsableKeys` — signing still works after restart
- `TestPolicyValidationRejectsInvalidTxn` — malformed request rejection
- `TestLSigSigningFlow` — generic LSig end-to-end path
- `TestLSigRuntimeArgValidation` — LSig arg validation
- `TestApprovalTimeoutOrClientDisconnect` — approval disconnect handling

### `native_falcon_test.go`

Protocol-native Falcon-1024 live acceptance on any selected v42 network:

- `TestNativeFalconProfile` — validates network genesis/consensus and the funded native Falcon root
- `TestNativeFalconPayment` — backup/restore, pure and mixed native Falcon groups, apshell rekey/unrekey through a Falcon authorizer, spend, and close

### `passthrough_test.go`

Pre-signed (passthrough) transaction handling:

- `TestPassthroughMixedGroup` — mixed sign/passthrough in one group
- `TestPassthroughResign` — re-signing passthrough transactions
- `TestPassthroughRequiresPreGrouped` — validation of pre-grouped requirement

### `app_test.go`

App interaction fixture smoke test:

- `TestAppDeployAndExercise` — deploys test contract and validates all harness
  operations: increment (global state), additive increment, opt-in (local state),
  set_box (box storage), grouped deposit (atomic payment + app call)

## Writing New Tests

### Basic Pattern

```go
func TestMyFeature(t *testing.T) {
    if os.Getenv("TEST_FUNDING_MNEMONIC") == "" {
        t.Skip("TEST_FUNDING_MNEMONIC not set")
    }

    network, err := harness.NewTestnetConfig()
    // ...

    signerd := harness.NewSignerHarness(t)
    signerd.Start()
    defer func() { _ = signerd.Stop() }()

    apadmin := harness.NewApAdminHarness(t, signerd.GetWorkDir())
    apadmin.StartUnlockBackground()
    defer apadmin.StopUnlockBackground()

    apshell := harness.NewApshellHarness(t, signerd.GetURL())
    apshell.CopyTokenFrom(signerd.GetWorkDir())

    // Your test logic...
}
```

### App Fixture Pattern

```go
func TestMyAppFeature(t *testing.T) {
    network, _ := harness.NewTestnetConfig()
    funder, _ := harness.NewFundTestAccount(network.Client)

    app, _ := harness.DeployTestApp(t, network.Client, funder)
    defer app.DestroyTestApp(funder)

    // Set up known state, then test APlane features against it
}
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `APLANE_INTEGRATION_NETWORK` | Integration network profile: `testnet` or `localnet` | required |
| `APSIGNER_DATA` | Signer data directory | (from setup-test-env.sh) |
| `APCLIENT_DATA` | Client data directory | (from setup-test-env.sh) |
| `TEST_PASSPHRASE` | Keystore passphrase | (from setup-test-env.sh) |
| `TEST_FUNDING_MNEMONIC` | Native Falcon-1024 funding mnemonic; operator-supplied for TestNet and generated/funded from KMD on LocalNet | required for TestNet setup |
| `ALGOD_URL` | Algod API endpoint | testnet Nodely URL or `http://localhost:4001` |
| `ALGOD_TOKEN` | Algod API token | empty for testnet, AlgoKit token for localnet |
| `APLANE_LOCALNET_KMD_URL` | LocalNet KMD endpoint | `http://localhost:4002` |
| `APLANE_LOCALNET_WALLET` | LocalNet KMD wallet used to bootstrap the native Falcon funder | `unencrypted-default-wallet` |

## Debugging

Run with `-v` for detailed output. Signer logs are captured and printed on
test failure. Check `t.Log` output for transaction IDs and round numbers.
