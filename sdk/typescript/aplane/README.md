# aPlane TypeScript SDK

TypeScript SDK for signing Algorand transactions via apsignerd.

## Installation

```bash
npm install @aplane/signer algosdk
```

Or with yarn/pnpm:

```bash
yarn add @aplane/signer algosdk
pnpm add @aplane/signer algosdk
```

### Installing from Local Tarball

When installing from a local `.tgz` file, ensure your project has a `package.json`:

```bash
# Initialize package.json if needed
npm init -y

# Install from tarball
npm install ./aplane-signer-0.1.0.tgz algosdk
```

### Troubleshooting

**Peer dependency conflicts**: If you see peer dependency errors, try:

```bash
npm install @aplane/signer algosdk --legacy-peer-deps
```

## Quick Start

```typescript
import { SignerClient, sendRawTransaction } from "@aplane/signer";
import algosdk from "algosdk";

// Connect to signer
const client = SignerClient.connectLocal("your-token-here");

// Build transaction with algosdk
const algodClient = new algosdk.Algodv2("", "https://testnet-api.4160.nodely.dev", "");
const params = await algodClient.getTransactionParams().do();

const txn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
  sender: "SENDER_ADDRESS",
  receiver: "RECEIVER_ADDRESS",
  amount: 1000000, // 1 ALGO
  suggestedParams: params,
});

// Sign via apsignerd (waits for operator approval)
const signed = await client.signTransaction(txn);

// Submit to network (signed is ready to use, no processing needed)
const txid = await sendRawTransaction(algodClient, signed);
console.log(`Submitted: ${txid}`);
```

## Connection Methods

### Local Connection

Connect to apsignerd running on the same machine:

```typescript
const client = SignerClient.connectLocal("your-token", {
  host: "localhost",     // default
  port: 11270,           // default
  timeout: 90000,        // milliseconds, default
});
```

### Remote Connection via SSH

Connect to apsignerd on a remote machine through an SSH tunnel with 2FA:

```typescript
const client = await SignerClient.connectSsh(
  "signer.example.com",
  "your-token",              // used for both SSH auth and HTTP API
  "~/.ssh/id_ed25519",
  {
    sshPort: 1127,           // default: 1127
    signerPort: 11270,       // default: 11270
    timeout: 90000,          // milliseconds, default
  }
);
```

**Note**: SSH uses 2FA (token + public key). The token is passed as the SSH
username. Remember to close when done:

```typescript
client.close();
```

### Environment-Based Connection

Load configuration from a data directory:

```typescript
// Set environment variable
// export APCLIENT_DATA=~/.aplane

const client = await SignerClient.fromEnv();

// Or pass directly
const client = await SignerClient.fromEnv({ dataDir: "~/.aplane" });
```

Data directory structure:
```
~/.aplane/
  config.yaml          # Connection settings
  aplane.token         # Authentication token
  .ssh/id_ed25519      # SSH key (if using SSH tunnel)
```

Example `config.yaml` (local):
```yaml
signer_port: 11270
```

Example `config.yaml` (remote via SSH):
```yaml
signer_port: 11270
ssh:
  host: signer.example.com
  port: 1127
  identity_file: .ssh/id_ed25519
```

## Authentication

The token is the contents of the `aplane.token` file from your apsignerd data directory.

```typescript
import { loadToken } from "@aplane/signer";

// Load from file
const token = loadToken("~/.aplane/aplane.token");

// Or from environment
const token = process.env.APSIGNER_TOKEN;
```

## API Reference

### SignerClient

#### `health(): Promise<boolean>`

Check if signer is reachable.

```typescript
if (await client.health()) {
  console.log("Signer is online");
}
```

#### `listKeys(refresh?: boolean): Promise<KeyInfo[]>`

List available signing keys.

```typescript
const keys = await client.listKeys();
for (const key of keys) {
  console.log(`${key.address} [${key.keyType}]`);
}
```

Returns list of `KeyInfo`:
- `address`: Algorand address
- `keyType`: "ed25519", "falcon1024-v1", "timelock-v1", etc.
- `lsigSize`: LogicSig size (for budget calculation)
- `isGenericLsig`: True if no cryptographic signature needed
- `runtimeArgs`: List of `RuntimeArg` for generic LogicSigs

**Discovering required arguments for generic LogicSigs:**

```typescript
const keyInfo = await client.getKeyInfo(hashlockAddress);
if (keyInfo?.runtimeArgs) {
  for (const arg of keyInfo.runtimeArgs) {
    console.log(`${arg.name}: ${arg.type} - ${arg.description}`);
  }
}
```

#### `signTransaction(txn, authAddress?, lsigArgs?): Promise<string>`

Sign a single transaction. Returns a base64-encoded string ready for submission.

The server automatically handles fee pooling for large LogicSigs (e.g., Falcon-1024) by adding dummy transactions as needed.

```typescript
// Basic signing (uses txn.sender as authAddress)
const signed = await client.signTransaction(txn);

// Rekeyed account (different auth key)
const signed = await client.signTransaction(txn, "SIGNER_KEY_ADDRESS");

// Generic LogicSig with runtime args (e.g., hashlock)
const signed = await client.signTransaction(
  txn,
  "HASHLOCK_ADDRESS",
  { preimage: new Uint8Array([/* secret value */]) }
);

// Submit directly (no processing needed)
const txid = await sendRawTransaction(algodClient, signed);
```

#### `signTransactions(txns, authAddresses?, lsigArgsMap?): Promise<string>`

Sign multiple transactions as a group. Returns a base64-encoded string of concatenated signed transactions, ready for submission.

**Important**: Do NOT pre-assign group IDs. The server computes the group ID after adding any required dummy transactions for large LogicSigs.

```typescript
// Build transactions (do NOT call assignGroupId)
const txn1 = algosdk.makePaymentTxnWithSuggestedParamsFromObject({...});
const txn2 = algosdk.makePaymentTxnWithSuggestedParamsFromObject({...});

// Sign group (server handles grouping and dummies)
const signed = await client.signTransactions([txn1, txn2]);

// Submit directly (no processing needed)
const response = await algodClient.sendRawTransaction(Buffer.from(signed, "base64")).do();
```

#### `signTransactionsList(txns, authAddresses?, lsigArgsMap?): Promise<string[]>`

Like `signTransactions()` but returns individual base64-encoded transactions instead of concatenated. Useful when you need to inspect transactions individually.

```typescript
const signedList = await client.signTransactionsList([txn1, txn2]);
// signedList is string[], each element is a base64-encoded signed transaction
```

## Supported Key Types

| Key Type | Description | Notes |
|----------|-------------|-------|
| `ed25519` | Native Algorand keys | Standard signing |
| `falcon1024-v*` | Post-quantum LogicSig | Signature in LogicSig.Args[0] |
| `timelock-v*` | Time-locked funds | No signature, TEAL-only |
| `hashlock-v*` | Hash-locked funds | Requires `preimage` arg (check `runtimeArgs`) |

The server assembles the complete signed transaction - the SDK returns a base64 string ready for submission.

## Error Handling

### Signing Exceptions

```typescript
import {
  SignerError,
  AuthenticationError,
  SigningRejectedError,
  SignerUnavailableError,
  KeyNotFoundError,
} from "@aplane/signer";

try {
  const signed = await client.signTransaction(txn);
} catch (error) {
  if (error instanceof AuthenticationError) {
    console.log("Invalid token");
  } else if (error instanceof SigningRejectedError) {
    console.log("Operator rejected the request");
  } else if (error instanceof SignerUnavailableError) {
    console.log("Signer not reachable or locked");
  } else if (error instanceof KeyNotFoundError) {
    console.log("Key not found in signer");
  } else if (error instanceof SignerError) {
    console.log(`Signing failed: ${error.message}`);
  }
}
```

### Submission Exceptions

`sendRawTransaction()` wraps verbose algod errors into clean exceptions:

```typescript
import {
  sendRawTransaction,
  TransactionRejectedError,
  LogicSigRejectedError,
  InsufficientFundsError,
  InvalidTransactionError,
} from "@aplane/signer";

try {
  const txid = await sendRawTransaction(algodClient, signed);
} catch (error) {
  if (error instanceof LogicSigRejectedError) {
    console.log(`LogicSig failed: ${error.reason}`); // error.txid also available
  } else if (error instanceof InsufficientFundsError) {
    console.log(`Not enough funds: ${error.reason}`);
  } else if (error instanceof InvalidTransactionError) {
    console.log(`Invalid transaction: ${error.reason}`);
  } else if (error instanceof TransactionRejectedError) {
    console.log(`Rejected: ${error.reason}`);
  }
}
```

## Example: Complete Workflow

```typescript
import { SignerClient, loadToken, SignerError, sendRawTransaction } from "@aplane/signer";
import algosdk from "algosdk";

async function main() {
  // Load token
  const token = loadToken("~/.aplane/aplane.token");

  // Connect to local signer
  const client = SignerClient.connectLocal(token);

  // List keys
  const keys = await client.listKeys();
  const sender = keys[0].address;
  console.log(`Using: ${sender}`);

  // Build transaction
  const algodClient = new algosdk.Algodv2("", "https://testnet-api.4160.nodely.dev", "");
  const params = await algodClient.getTransactionParams().do();

  const txn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
    sender: sender,
    receiver: sender,
    amount: 0,
    suggestedParams: params,
  });

  // Sign (will wait for operator approval)
  try {
    const signed = await client.signTransaction(txn);
    console.log("Signed!");

    // Submit directly (no processing needed)
    const txid = await sendRawTransaction(algodClient, signed);
    console.log(`TxID: ${txid}`);

    // Wait for confirmation
    const result = await algosdk.waitForConfirmation(algodClient, txid, 4);
    console.log(`Confirmed in round ${result["confirmed-round"]}`);
  } catch (error) {
    if (error instanceof SignerError) {
      console.log(`Failed: ${error.message}`);
    } else {
      throw error;
    }
  }
}

main().catch(console.error);
```

## Fee Pooling (Large LogicSigs)

Algorand limits LogicSig size to 1000 bytes per transaction. Large signatures like Falcon-1024 (~3000 bytes) exceed this limit.

**Solution**: The server automatically creates dummy transactions to expand the LogicSig budget pool. Each transaction in a group contributes 1000 bytes to the shared pool.

### How It Works (Server-Side)

1. Server detects key's `lsigSize` exceeds available budget
2. Server calculates dummies needed: `ceil(total_lsig_bytes / 1000) - num_txns`
3. Server creates dummy self-payment transactions (0 amount, min fee)
4. Server distributes dummy fees across LogicSig transactions in the group
5. Server computes group ID and signs all transactions
6. SDK returns concatenated signed group ready for submission

### Example: Falcon-1024 Key

```typescript
// Falcon-1024 has lsigSize ~3035 bytes, needs 3 dummies
// Total group: 1 main + 3 dummies = 4 transactions
// Pool budget: 4 x 1000 = 4000 bytes (enough for 3035)

const params = await algodClient.getTransactionParams().do();
const txn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
  sender: falconAddr,
  receiver: receiverAddr,
  amount: 1000000,
  suggestedParams: params,
});

// Server automatically adds dummies - just sign and submit
const signed = await client.signTransaction(txn);
const txid = await sendRawTransaction(algodClient, signed);
```

### Fee Impact

| Key Type | LogicSig Size | Dummies Needed | Extra Fee |
|----------|---------------|----------------|-----------|
| Ed25519 | 0 | 0 | 0 |
| Falcon-1024 | ~3035 | 3 | ~3000 uA |

The extra fee covers the dummy transactions required for post-quantum security.

## License

AGPL-3.0-or-later
