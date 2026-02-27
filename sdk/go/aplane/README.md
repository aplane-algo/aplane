# aPlane Go SDK

Go SDK for signing Algorand transactions via apsignerd.

## Installation

```bash
go get github.com/aplane-algo/aplane/sdk/go/aplane
```

## Quick Start

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/aplane-algo/aplane/sdk/go/aplane"
)

func main() {
	// Connect to signer
	client, err := aplane.FromEnv(nil)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// Build transaction with go-algorand-sdk
	algodClient, _ := algod.MakeClient("https://testnet-api.4160.nodely.dev", "")
	params, _ := algodClient.SuggestedParams().Do(context.Background())

	txn, _ := transaction.MakePaymentTxn(
		"SENDER_ADDRESS",
		"RECEIVER_ADDRESS",
		1000000, // 1 ALGO
		nil, "", params,
	)

	// Sign via apsignerd (waits for operator approval)
	signed, err := client.SignTransaction(txn, "", nil)
	if err != nil {
		log.Fatal(err)
	}

	// Submit using standard go-algorand-sdk (signed is base64)
	signedBytes, _ := aplane.Base64ToBytes(signed)
	txid, _ := algodClient.SendRawTransaction(signedBytes).Do(context.Background())
	fmt.Printf("Submitted: %s\n", txid)
}
```

## Connection Methods

### Local Connection

Connect to apsignerd running on the same machine:

```go
client := aplane.ConnectLocal("your-token", &aplane.ConnectOptions{
	Host:    "localhost", // default
	Port:    11270,       // default
	Timeout: 90,          // seconds, default
})
```

### Remote Connection via SSH

Connect to apsignerd on a remote machine through an SSH tunnel with 2FA:

```go
client, err := aplane.ConnectSSH(
	"signer.example.com",
	"your-token",           // used for both SSH auth and HTTP API
	"~/.ssh/id_ed25519",
	&aplane.SSHConnectOptions{
		SSHPort:    1127,   // default
		SignerPort: 11270,  // default
		Timeout:    90,     // seconds, default
	},
)
if err != nil {
	log.Fatal(err)
}
defer client.Close()
```

**Note**: SSH uses 2FA (token + public key). The token is passed as the SSH username.

### Environment-Based Connection

Load configuration from a data directory:

```go
// Uses APCLIENT_DATA env var or ~/.apclient
client, err := aplane.FromEnv(nil)

// Or specify data directory
client, err := aplane.FromEnv(&aplane.FromEnvOptions{
	DataDir: "~/.apclient",
})
```

Data directory structure:
```
~/.apclient/
  config.yaml          # Connection settings
  aplane.token         # Authentication token
  .ssh/id_ed25519      # SSH key (if using SSH tunnel)
```

Example `config.yaml`:
```yaml
signer_port: 11270
ssh:
  host: signer.example.com
  port: 1127
  identity_file: .ssh/id_ed25519
```

## API Reference

### SignerClient

#### `Health() (bool, error)`

Check if signer is reachable.

```go
healthy, err := client.Health()
```

#### `ListKeys(refresh bool) ([]KeyInfo, error)`

List available signing keys.

```go
keys, err := client.ListKeys(false)
for _, key := range keys {
	fmt.Printf("%s [%s]\n", key.Address, key.KeyType)
}
```

#### `SignTransaction(txn, authAddress, lsigArgs) (string, error)`

Sign a single transaction. Returns base64-encoded signed transaction.

```go
// Basic signing
signed, err := client.SignTransaction(txn, "", nil)

// Rekeyed account
signed, err := client.SignTransaction(txn, "AUTH_KEY_ADDRESS", nil)

// Generic LogicSig with runtime args
signed, err := client.SignTransaction(
	txn,
	hashlockAddress,
	aplane.LsigArgs{"preimage": preimageBytes},
)
```

#### `SignTransactions(txns, authAddresses, lsigArgsMap) (string, error)`

Sign multiple transactions as a group. Returns concatenated base64.

**Important**: Do NOT pre-assign group IDs. The server computes the group ID.

```go
signed, err := client.SignTransactions(
	[]types.Transaction{txn1, txn2},
	[]string{authAddr1, authAddr2},
	nil,
)
```

## Supported Key Types

| Key Type | Description | Notes |
|----------|-------------|-------|
| `ed25519` | Native Algorand keys | Standard signing |
| `falcon1024-v*` | Post-quantum LogicSig | Large signature (~3KB) |
| `timelock-v*` | Time-locked funds | No signature, TEAL-only |
| `hashlock-v*` | Hash-locked funds | Requires `preimage` arg |

## Error Handling

```go
import "errors"

signed, err := client.SignTransaction(txn, "", nil)
if err != nil {
	if errors.Is(err, aplane.ErrAuthentication) {
		log.Println("Invalid token")
	} else if errors.Is(err, aplane.ErrSigningRejected) {
		log.Println("Operator rejected")
	} else if errors.Is(err, aplane.ErrSignerUnavailable) {
		log.Println("Signer not reachable")
	} else if errors.Is(err, aplane.ErrKeyNotFound) {
		log.Println("Key not in signer")
	} else {
		log.Printf("Error: %v", err)
	}
}
```

## Fee Pooling (Large LogicSigs)

Algorand limits LogicSig size to 1000 bytes per transaction. Large signatures like Falcon-1024 (~3000 bytes) exceed this limit.

The server automatically creates dummy transactions to expand the LogicSig budget pool:

```go
// Falcon-1024 has lsigSize ~3035 bytes, needs 3 dummies
// Server automatically handles this - just sign and submit
signed, err := client.SignTransaction(txn, "", nil)
signedBytes, _ := aplane.Base64ToBytes(signed)
txid, _ := algodClient.SendRawTransaction(signedBytes).Do(ctx)
```

| Key Type | LogicSig Size | Dummies Needed | Extra Fee |
|----------|---------------|----------------|-----------|
| Ed25519 | 0 | 0 | 0 |
| Falcon-1024 | ~3035 | 3 | ~3000 uA |

## License

AGPL-3.0-or-later
