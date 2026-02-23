# Engine Architecture

> **Version**: 0.38+
> **Status**: Core subsystem documentation

## Overview

The Engine subsystem (`internal/engine/`) is the core business logic layer for aPlane Shell. It provides a clean separation between business operations and user interface concerns, enabling multiple UI implementations (REPL, TUI, CLI one-shot) to share a single source of truth for transaction logic, cache management, and state.

## Design Philosophy

### Principle: Engine is Alias-Agnostic, Set-Agnostic, and Amount-Format-Agnostic

The Engine operates exclusively on:
- **Pre-resolved 58-character Algorand addresses** (not aliases like "alice")
- **Pre-resolved asset IDs** (uint64, not names like "USDC")
- **Amounts in base units** (uint64 microAlgos or base asset units)

The REPL/UI layer is responsible for:
- Parsing user input
- Resolving aliases ("alice" -> "ABC123...")
- Expanding sets ("@validators" -> ["ADDR1", "ADDR2", ...])
- Converting amounts ("1.5" ALGO -> 1500000 microAlgos)
- Formatting output for display
- Providing command history, tab completion, etc.

This separation ensures:
1. **Testability**: Engine logic can be unit tested without UI dependencies
2. **Reusability**: Same Engine powers REPL, TUI, and CLI modes
3. **Consistency**: All UIs behave identically for the same inputs
4. **Clarity**: Clear boundaries prevent mixing concerns

## Architecture Diagram

```
+-----------------------------------------------------------------------------+
|                              UI Layer                                        |
|                                                                             |
|   +--------------+    +--------------+    +--------------+                 |
|   |   CLI Mode   |    |  REPL Mode   |    |   TUI Mode   |                 |
|   |  (one-shot)  |    | (interactive)|    | (bubbletea)  |                 |
|   +------+-------+    +------+-------+    +------+-------+                 |
|          |                   |                   |                          |
|          |    +--------------+--------------+    |                          |
|          |    |      internal/repl/         |    |                          |
|          |    |   - ParseSendCommand()      |    |                          |
|          |    |   - ParseOptinCommand()     |    |                          |
|          |    |   - ParseRekeyCommand()     |    |                          |
|          |    |   - etc.                    |    |                          |
|          |    +--------------+--------------+    |                          |
|          |                   |                   |                          |
|          |    +--------------+--------------+    |                          |
|          |    |    Resolution Layer         |    |                          |
|          |    |  - Alias -> Address         |    |                          |
|          |    |  - @set -> [Addresses]      |    |                          |
|          |    |  - "1.5" -> 1500000         |    |                          |
|          |    |  - "USDC" -> 31566704       |    |                          |
|          |    +--------------+--------------+    |                          |
+----------------------------+-------------------------------------------------+
                             |
                   +---------v---------+
                   |                   |
                   |  internal/engine  |
                   |                   |
                   |  Business Logic   |
                   |  - Transactions   |
                   |  - Balances       |
                   |  - Signing        |
                   |  - Connections    |
                   |  - Caches         |
                   |                   |
                   +---------+---------+
                             |
+----------------------------+-------------------------------------------------+
|                            |      Foundation Layer                          |
|                            |                                                 |
|   +-----------+    +-------v-------+    +-------------+                     |
|   |signing/   |    |    algo/      |    |    util/    |                     |
|   |           |    |               |    |             |                     |
|   |Providers  |    | AlgodClient   |    |  Caches     |                     |
|   |KeyMaterial|    | Transactions  |    |  Resolvers  |                     |
|   +-----------+    +---------------+    +-------------+                     |
|                                                                             |
+-----------------------------------------------------------------------------+
```

## File Organization

```
internal/engine/
├── engine.go       # Engine struct, NewEngine(), configuration options
├── errors.go       # Sentinel errors (ErrNoAlgodClient, ErrNotConnected, etc.)
├── results.go      # Result types (StatusResult, BalanceResult, etc.)
├── accounts.go     # Account queries, balance checks, participation status
├── assets.go       # ASA info, opt-in status
├── cache.go        # Alias and set management
├── connection.go   # Signer connection (direct and SSH tunnel)
├── signing.go      # SigningContext, LSig management, auth address handling
├── transaction.go  # Transaction preparation and submission
├── script.go       # Script execution engine
├── init.go         # Package initialization
└── *_test.go       # Unit tests
```

## Engine Structure

### Core Type

```go
// Engine contains all business logic and state, independent of any UI.
type Engine struct {
    // Network Configuration
    Network     string
    AlgodClient *algod.Client

    // Caches
    AsaCache    util.ASACache
    AliasCache  util.AliasCache
    LsigCache   *util.LSigCache
    SignerCache util.SignerCache
    AuthCache   util.AuthAddressCache
    SetCache    util.SetCache

    // Remote Signing
    SignerClient *util.SignerClient

    // Configuration
    WriteMode bool
    ConfigDir string
    Verbose   bool // Controls detailed signing output (default: false)

    // Connection State (thread-safe)
    connMu           sync.Mutex
    sshTunnelClient  *sshtunnel.Client
    sshPort          int
    tunnelConnected  bool
    tunnelCtx        context.Context
    tunnelCancel     context.CancelFunc
    connectionTarget string
}
```

### Functional Options Pattern

The Engine uses functional options for configuration:

```go
eng, err := engine.NewEngine("testnet",
    engine.WithAlgodClient(client),
    engine.WithASACache(asaCache),
    engine.WithAliasCache(aliasCache),
    engine.WithSignerCache(signerCache),
    engine.WithLSigCache(lsigCache),
    engine.WithAuthCache(authCache),
    engine.WithSetCache(setCache),
    engine.WithSignerClient(signerClient),
    engine.WithConfigDir(configDir),
    engine.WithWriteMode(false),
)
```

## Error Types

The Engine defines sentinel errors for common conditions:

```go
var (
    ErrNotConnected     = errors.New("not connected to Signer")
    ErrInvalidAddress   = errors.New("invalid address or alias")
    ErrInvalidAmount    = errors.New("invalid amount")
    ErrInvalidAssetID   = errors.New("invalid asset ID")
    ErrNoSigningKey     = errors.New("no signing key available for address")
    ErrTransactionFailed = errors.New("transaction failed")
    ErrScriptError      = errors.New("script execution error")
    ErrAlreadyConnected = errors.New("already connected")
    ErrConnectionFailed = errors.New("connection failed")
    ErrInvalidNetwork   = errors.New("invalid network")
    ErrNoAlgodClient    = errors.New("algod client not configured")
    ErrAliasNotFound    = errors.New("alias not found")
    ErrSetNotFound      = errors.New("set not found")
)
```

These allow callers to handle specific error conditions:

```go
result, err := engine.SignAndSubmit(prep, true)
if errors.Is(err, engine.ErrNotConnected) {
    fmt.Println("Please connect to Signer first")
    return
}
```

## Result Types

The Engine returns structured result types rather than printing directly:

```go
// StatusResult holds data for the status command
type StatusResult struct {
    Network          string
    IsConnected      bool
    ConnectionTarget string
    SigningMode      string // "local", "remote", "disconnected"
    WriteMode        bool
    ASACacheCount    int
    AliasCacheCount  int
    SetCacheCount    int
    SignerCacheCount int
    LsigCacheCount   int
}

// BalanceResult holds account balance information
type BalanceResult struct {
    Address     string
    Alias       string // empty if no alias
    AlgoBalance uint64 // microAlgos
    Assets      []AssetBalance
    AuthAddr    string // if rekeyed
    MinBalance  uint64
}

// AssetBalance represents a single ASA holding
type AssetBalance struct {
    AssetID   uint64
    Amount    uint64
    UnitName  string
    Decimals  uint64
    IsFrozen  bool
    IsOptedIn bool
}

// TransactionResult holds the outcome of a single transaction
type TransactionResult struct {
    TxID           string
    GroupID        string // for atomic groups
    ConfirmedRound uint64
    Fee            uint64
    Sender         string
    Receiver       string
    Amount         uint64
    AssetID        uint64 // 0 for ALGO
    Note           string
    WroteToFile    string // file path if write mode enabled
}

// ConnectionResult holds connection attempt outcome
type ConnectionResult struct {
    Connected    bool
    Target       string
    Port         int
    KeyCount     int
    ErrorMessage string
}

// ParticipationResult holds consensus participation status
type ParticipationResult struct {
    Address           string
    IsOnline          bool
    VoteKey           string
    SelectionKey      string
    StateProofKey     string
    VoteFirstValid    uint64
    VoteLastValid     uint64
    VoteKeyDilution   uint64
    IncentiveEligible bool
}
```

## Transaction API

### Parameter Types

All transaction methods receive strongly-typed parameter structs with pre-resolved addresses:

```go
// SendPaymentParams for ALGO payments
type SendPaymentParams struct {
    From       string // Resolved sender address (58-char)
    To         string // Resolved receiver address (58-char)
    Amount     uint64 // Amount in microAlgos
    Note       string
    Fee        uint64
    UseFlatFee bool
}

// SendASAParams for ASA transfers
type SendASAParams struct {
    From       string // Resolved sender address (58-char)
    To         string // Resolved receiver address (58-char)
    AssetID    uint64 // Resolved asset ID
    Amount     uint64 // Amount in base units
    Note       string
    Fee        uint64
    UseFlatFee bool
}

// OptInParams for ASA opt-in
type OptInParams struct {
    Account    string // Resolved address (58-char)
    AssetID    uint64
    Fee        uint64
    UseFlatFee bool
}

// KeyRegParams for key registration (online/offline)
type KeyRegParams struct {
    Account           string
    Mode              string // "online" or "offline"
    VoteKey           string
    SelectionKey      string
    StateProofKey     string
    VoteFirst         uint64
    VoteLast          uint64
    KeyDilution       uint64
    IncentiveEligible bool
}

// RekeyParams for rekeying accounts
type RekeyParams struct {
    From       string // Account to rekey
    To         string // New auth address
    Fee        uint64
    UseFlatFee bool
}

// CloseAccountParams for closing accounts
type CloseAccountParams struct {
    From       string // Account to close
    CloseTo    string // Recipient of remaining ALGO
    Fee        uint64
    UseFlatFee bool
}

// OptOutParams for ASA opt-out
type OptOutParams struct {
    Account    string
    AssetID    uint64
    CloseTo    string // Recipient of remaining balance
    Fee        uint64
    UseFlatFee bool
}

// AtomicPaymentParams for atomic group payments
type AtomicPaymentParams struct {
    From   string
    To     string
    Amount uint64
    Note   string
}

// AtomicASAParams for atomic group ASA transfers
type AtomicASAParams struct {
    From    string
    To      string
    AssetID uint64
    Amount  uint64
    Note    string
}
```

### Prepare-Then-Submit Pattern

Transaction operations follow a two-phase pattern:

```go
// Phase 1: Prepare transaction (validate, build, check balances)
prep, balanceCheck, err := engine.PreparePayment(SendPaymentParams{
    From:   "ABC123...",  // Pre-resolved address
    To:     "DEF456...",  // Pre-resolved address
    Amount: 1000000,      // 1 ALGO in microAlgos
})

// UI can display balance warnings from balanceCheck
if !balanceCheck.SufficientFunds {
    fmt.Printf("Warning: Insufficient funds\n")
}

// Phase 2: Sign and submit
result, err := engine.SignAndSubmit(prep, true) // wait for confirmation
```

### Available Transaction Methods

| Method | Description |
|--------|-------------|
| `PreparePayment` | Prepare ALGO payment |
| `PrepareASATransfer` | Prepare ASA transfer |
| `PrepareOptIn` | Prepare ASA opt-in |
| `PrepareOptOut` | Prepare ASA opt-out with balance handling |
| `PrepareKeyReg` | Prepare key registration (online/offline) |
| `PrepareRekey` | Prepare rekey transaction |
| `PrepareClose` | Prepare account close (with validation) |
| `PrepareAtomicPayments` | Prepare atomic ALGO group |
| `PrepareAtomicASATransfers` | Prepare atomic ASA group |
| `SignAndSubmit` | Sign and submit single transaction |
| `SignAndSubmitAtomic` | Sign and submit atomic group |
| `SignAndSubmitTransactionsFromFile` | Sign pre-built transactions |
| `ValidateAtomicPayments` | Validate atomic ALGO payments |
| `ValidateAtomicASATransfers` | Validate atomic ASA transfers |
| `WaitForConfirmation` | Wait for transaction confirmation |

## Signing API

### SigningContext

The Engine builds signing contexts that encapsulate all information needed to sign:

```go
type SigningContext struct {
    Address     string           // Resolved address (the account)
    LSig        *util.LSigConfig // nil for Ed25519, non-nil for LSig schemes
    SigningAddr string           // Auth address (may differ if rekeyed)
    KeyType     string           // e.g., "ed25519", "falcon1024"
    SigSize     int              // Signature size (for fee calculation)
}

// BuildSigningContext handles:
// 1. Alias resolution
// 2. Auth address lookup (for rekeyed accounts)
// 3. LSig retrieval (for post-quantum schemes)
ctx, err := engine.BuildSigningContext("ABC123...")
```

### LSig Management

```go
// GetOrFetchLSig gets LSig from cache or auto-fetches from Signer
lsigConfig, err := engine.GetOrFetchLSig(address)

// RefreshAuthCache refreshes auth addresses from blockchain
err := engine.RefreshAuthCache()

// IsRekeyed checks if address is rekeyed
isRekeyed, authAddr := engine.IsRekeyed(address)

// CanSignForAddress checks signing capability
canSign, isLsig := engine.CanSignForAddress(address)
```

## Connection API

### Direct Connection (localhost)

```go
result, err := engine.ConnectDirect("localhost:11270", apiToken)
if result.Connected {
    fmt.Printf("Connected, %d keys available\n", result.KeyCount)
}
```

### SSH Tunnel Connection (remote)

```go
result, err := engine.ConnectWithTunnel(
    target,      // "user@host"
    userPart,    // "user"
    host,        // "host.example.com"
    sshPort,     // 1127
    localPort,   // 11270
    signerPort,  // 11270
    token,       // API token (HTTP auth)
    identityFile,    // SSH private key path (optional, uses agent if empty)
    knownHostsPath,  // known_hosts file for SSH verification
)
```

### Connection Management

```go
// Check connection status
if engine.IsConnected() { ... }
if engine.IsTunnelConnected() { ... }

// Get connection info
target := engine.GetConnectionTarget()

// Disconnect
err := engine.Disconnect()

// Quick connection check (for localhost)
if !engine.CheckLocalhostConnection() {
    fmt.Println("Connection lost")
}
```

## Cache Management API

### Aliases

```go
// List all aliases
aliases := engine.ListAliases()

// Get specific alias
alias := engine.GetAlias("alice")

// Add/update alias
result, err := engine.AddAlias("alice", "ABC123...")

// Remove alias
addr, err := engine.RemoveAlias("alice")
```

### Sets

```go
// List all sets
sets := engine.ListSets()

// Get specific set
set := engine.GetSet("validators")

// Add set
result, err := engine.AddSet("team", []string{"alice", "bob"})

// Modify set
result, err := engine.AddToSet("team", []string{"charlie"})
result, err := engine.RemoveFromSet("team", []string{"alice"})

// Remove set
count, err := engine.RemoveSet("team")
```

## Account API

```go
// Get balance
result, err := engine.GetBalance(address)

// Get account info (all known accounts)
accounts := engine.GetAccounts()

// Get participation status
result, err := engine.GetParticipation(address)

// Check incentive eligibility
eligible, err := engine.GetIncentiveEligibility(address)
```

## Thread Safety

Connection state is protected by a mutex:

```go
type Engine struct {
    connMu           sync.Mutex
    sshTunnelClient  *sshtunnel.Client
    // ...
}

func (e *Engine) IsConnected() bool {
    e.connMu.Lock()
    defer e.connMu.Unlock()
    return e.SignerClient != nil
}
```

## Commands Using Engine

| Command | Engine Methods Used |
|---------|---------------------|
| send | PreparePayment, PrepareASATransfer, SignAndSubmit |
| optin | PrepareOptIn, SignAndSubmit |
| optout | PrepareOptOut, SignAndSubmit |
| rekey/unrekey | PrepareRekey, SignAndSubmit |
| close | PrepareClose, SignAndSubmit |
| sweep | PreparePayment, PrepareASATransfer, SignAndSubmit |
| sign | SignAndSubmitTransactionsFromFile |
| keyreg | PrepareKeyReg, SignAndSubmit |
| alias | ListAliases, GetAlias, AddAlias, RemoveAlias |
| sets | ListSets, GetSet, AddSet, RemoveSet, AddToSet, RemoveFromSet |
| balances | GetBalance, GetASAInfo |
| accounts | GetAccounts |
| participation | GetParticipation |
| status | GetStatus |
| connect | ConnectDirect, ConnectWithTunnel |
| refresh | RefreshAuthCache |

## Benefits of the Engine Pattern

1. **Single Source of Truth** - All business logic lives in one place
2. **Testability** - Engine methods can be unit tested independently
3. **Consistency** - Identical behavior across REPL, TUI, and CLI
4. **Maintainability** - Clear separation of concerns
5. **Extensibility** - New UIs can be added with thin adapters
6. **Documentation** - Parameter types serve as contracts

## Related Documentation

- [ARCH_OVERVIEW.md](ARCH_OVERVIEW.md) - Overall system architecture
- [ARCH_CRYPTO.md](ARCH_CRYPTO.md) - Cryptography layer (signing, key generation)
- [ARCH_UI.md](ARCH_UI.md) - UI layer architecture
- [CONFIG.md](CONFIG.md) - Configuration reference
