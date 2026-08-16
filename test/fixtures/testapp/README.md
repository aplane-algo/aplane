# APlane App-Interaction Integration Fixture

A minimal ARC-4 smart contract and deployment harness for testing APlane's
application call, state read, and grouped execution capabilities.

## What This Is

A purpose-built integration fixture for validating APlane features:

- App deployment via direct SDK signing
- Global state, local state, and box reads
- Raw app calls (manual selector + encoded args)
- ABI-backed app calls (method name + typed args)
- Grouped atomic transactions (payment + app call)
- Simulation against a known contract
- Signer approval rendering for app call transactions

## What This Is Not

- Not a general-purpose smart contract testing framework
- Not a contract development environment
- Not a localnet/sandbox fixture (requires testnet + funded account)
- Not comprehensive ARC-4 coverage (no return values, no complex types)

## Contract Design

Hand-written TEAL v10 with a manual ARC-4 method router. No Python toolchain
(PyTeal, Beaker, algopy) is involved.

### Global State (2 keys)

| Key       | Type   | Description                    |
|-----------|--------|--------------------------------|
| `counter` | uint64 | Incrementing counter           |
| `admin`   | bytes  | Creator address, set at deploy |

### Local State (1 key)

| Key       | Type   | Description        |
|-----------|--------|--------------------|
| `balance` | uint64 | Per-account balance |

### ARC-4 Methods

| Method                       | Selector     | Description                                    |
|------------------------------|--------------|------------------------------------------------|
| `increment(uint64)void`     | `0x8296da2e` | Add amount to global counter                   |
| `set_box(byte[],byte[])void`| `0x6eb66b06` | Create or overwrite a box                      |
| `optin()void`               | `0xdc0de7eb` | Opt in, initialize local balance to 0          |
| `deposit()void`             | `0x92e03b1c` | Add companion payment amount to local balance  |

`deposit()` requires a preceding payment to the app address in the same atomic
group. All other methods can be called standalone.

### On-Completion Handling

| OnCompletion       | Behavior                        |
|--------------------|---------------------------------|
| NoOp               | Dispatch by method selector     |
| OptIn              | `optin()` method or bare opt-in |
| CloseOut           | Allowed unconditionally         |
| ClearState         | Handled by clear program        |
| Update / Delete    | Creator only                    |

## Files

```
test/fixtures/testapp/
  approval.teal         Hand-written TEAL v10 approval program
  clear.teal            Minimal clear program (int 1; return)
  aplane_test.json      ARC-4 ABI JSON matching the TEAL
  README.md             This file
```

## Maintenance

The TEAL and ABI JSON are hand-maintained. There is no build step or code
generation.

If you modify the contract:

1. Edit `approval.teal` directly
2. Update `aplane_test.json` to match any method signature changes
3. Update method selectors in `test/integration/harness/testapp.go`
   (`IncrementSelector()`, etc.) — selectors are the first 4 bytes of
   `sha512_256("method_signature")`
4. Run `TestAppDeployAndExercise` to verify everything still works

## Deployment Harness

`test/integration/harness/testapp.go` provides:

- `DeployTestApp()` — compile TEAL via algod, deploy, return handle
- `FundApp()` — fund app address for box MBR
- `OptIn()` — opt in an account (direct SDK signing)
- `CallMethod()` — call an ARC-4 method (direct SDK signing)
- `ReadGlobalState()` / `ReadLocalState()` — read state via algod
- `SubmitGroupedPaymentAndAppCall()` — atomic payment + app call
- `DestroyTestApp()` — delete the application (cleanup)

All fixture operations use the harness's direct native Falcon authorizer. This
avoids circular dependencies — the fixture sets up state for the features being
tested, it is not the thing being tested.

## Usage From Tests

```go
func TestMyAppFeature(t *testing.T) {
    testnet, _ := harness.NewTestnetConfig()
    funder, _ := harness.NewFundTestAccount(testnet.Client)

    app, _ := harness.DeployTestApp(t, testnet.Client, funder)
    defer app.DestroyTestApp(funder)

    // Set up state via harness (direct SDK signing)
    app.CallMethod(
        [][]byte{harness.IncrementSelector(), harness.EncodeUint64(5)},
        funder, nil,
    )

    // Now test your APlane feature against the known state...
}
```

Each test deploys its own app instance for full isolation.
