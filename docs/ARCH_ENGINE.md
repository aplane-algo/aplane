# Engine Architecture

## Overview

The Engine subsystem (`internal/engine/`) is the core business-operations layer
for APlane Shell. It sits beneath the shell application layer in
`internal/apshellapp`, which owns shell-facing command semantics and workflow
orchestration. The engine provides reusable transaction logic, cache-backed
runtime state, signer connectivity, and network operations that can be shared
across `apshell` REPL, MCP, scripting, and CLI one-shot flows. It is not the
backend for `apadmin` or `apapprover`, which talk to `apsigner` over the admin
protocol (`apadmin` over local IPC or SSH admin transport; `apapprover` over
local IPC).

## Design Philosophy

### Principle: Engine Separation from UI Concerns

Transaction preparation methods operate on:
- **Pre-resolved 58-character Algorand addresses** (not aliases like "alice")
- **Pre-resolved asset IDs** (uint64, not names like "USDC")
- **Amounts in base units** (uint64 microAlgos or base asset units)

The REPL/UI layer and `internal/apshellapp` are responsible for:
- Parsing user input
- Expanding sets ("@validators" -> ["ADDR1", "ADDR2", ...])
- Converting amounts ("1.5" ALGO -> 1500000 microAlgos)
- Formatting output for display
- Providing command history, tab completion, etc.

Shell ownership is layered:
- `internal/apshellcli` owns command registry, command adapters, REPL/session
  mechanics, MCP mode, plugin argument normalization, and shell rendering
- `internal/shellrepl` owns shell command tokenization and top-level
  transaction command grammar
- `internal/cmdspec` owns shared parsing and resolution helpers used by those
  command parsers

However, some convenience methods in the Engine do accept aliases and resolve them internally (e.g., `GetBalance()`, `BuildSigningContext()`). The Engine also owns alias, set, and signer caches. The boundary is partially clean: transaction preparation is alias-agnostic, but query and signing-context methods are not.

This separation ensures:
1. **Testability**: Engine logic can be unit tested without UI dependencies
2. **Reusability**: The same Engine powers `internal/apshellapp` across REPL, MCP, scripting, and CLI modes
3. **Consistency**: All `apshell` entrypoints behave identically for the same inputs
4. **Clarity**: Clear boundaries prevent mixing concerns

## Architecture Diagram

```
+-----------------------------------------------------------------------------+
|                              UI Layer                                       |
|                                                                             |
|   +--------------+    +--------------+    +--------------+                  |
|   |   CLI Mode   |    |  REPL Mode   |    |  JS / MCP    |                  |
|   |  (one-shot)  |    | (interactive)|    |  surfaces    |                  |
|   +------+-------+    +------+-------+    +------+-------+                  |
|          |                   |                   |                          |
|          |    +--------------+--------------+    |                          |
|          |    | internal/shellrepl/         |    |                          |
|          |    | + internal/cmdspec          |    |                          |
|          |    |   - ParseSendCommand()      |    |                          |
|          |    |   - ParseOptinCommand()     |    |                          |
|          |    |   - ParseRekeyCommand()     |    |                          |
|          |    |   - shared token/byte/addr  |    |                          |
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
+----------------------------+------------------------------------------------+
                             |
                   +---------v---------+
                   |                   |
                   | internal/         |
                   | apshellapp        |
                   |                   |
                   | Shell command     |
                   | semantics         |
                   | orchestration     |
                   | result shaping    |
                   |                   |
                   +---------+---------+
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
+----------------------------+------------------------------------------------+
|                            |      Foundation Layer                          |
|                            |                                                |
|   +-----------+    +-------v-------+    +-------------+                     |
|   |signing/   |    |    algo/      |    |   cache/   |                     |
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
├── engine.go              # Engine struct, NewEngine(), configuration options
├── errors.go              # Sentinel errors (ErrNoAlgodClient, ErrNotConnected, etc.)
├── results.go             # Result types (StatusResult, BalanceResult, etc.)
├── accounts.go            # Account queries, balance checks, participation status
├── app_call.go            # Raw and ABI-backed app call preparation
├── app_deploy.go          # Application deployment
├── app_read.go            # App state reads (global, local, box)
├── asa.go                 # ASA-oriented engine entry points
├── assets.go              # ASA info, resolver-backed metadata access
├── atomic.go              # Atomic transaction group helpers
├── cache.go               # Alias and set management
├── connect/               # Signer HTTP client and SSH tunnel lifecycle state
├── connection.go          # Signer connection (direct and SSH tunnel)
├── group.go               # PreparedGroup, grouped preparation and execution
├── guarded_submit.go      # Guarded-account sign/assemble submission flow
├── init.go                # Package initialization
├── keymgmt.go             # Key management operations
├── keyreg.go              # Key registration (online/offline)
├── output_error.go        # Output/error formatting helpers for results
├── payment.go             # Payment preparation
├── plugin_pregrouped.go   # Pre-grouped plugin transaction submission
├── plugin_presign.go      # Plugin pre-sign planning flow (mixed managed/plugin groups)
├── plugin_signing.go      # Shared helpers for plugin transaction submission
├── plugin_transactions.go # Plugin transaction processing
├── rekey.go               # Rekey/unrekey operations
├── sentry_endpoint.go     # Sentry endpoint resolution for guarded signing
├── signer_cache.go        # Signer cache helpers and guarded metadata access
├── signing.go             # SigningContext, auth address handling
├── status_sync.go         # /status keyset-revision synchronization
├── transaction.go         # Transaction submission and confirmation
├── txnwrite.go            # Transaction JSON file writing
└── *_test.go              # Unit tests
```

Shared ASA metadata and amount handling lives in `internal/asa`.
`internal/engine` consumes that package for:

- network-aware ASA reference resolution,
- metadata lookup through canonical built-ins, cache, and live sources,
- raw/display amount conversion boundaries,
- consistent operator-facing formatting.

`internal/asa/registry` owns built-in ASA metadata and explicit convenience
aliases. `internal/cache` is the persistence/fetch layer for cached ASA
metadata, while `internal/asa` is the preferred caller-facing API for
amount/ref handling. Current-network cached metadata is checked before
registry aliases so local cache entries can override convenience names; unknown
or ambiguous symbolic references fail instead of silently choosing an asset.

## Engine Structure

### Core Type

```go
// Engine contains all business logic and state, independent of any UI.
type Engine struct {
    // State owns APCLIENT_DATA, network, algod, and client-side caches.
    *clientstate.State

    // Connection owns signer HTTP client and SSH tunnel lifecycle.
    Connection *connect.ConnectionState

    // watcher owns disk-backed client cache refresh behavior.
    watcher *clientstate.CacheWatcher

    // Configuration
    WriteMode bool
    Verbose   bool // Controls detailed signing output (default: false)
    Simulate  bool // Simulate mode (default: false)
}
```

Submission and confirmation diagnostics are returned on typed result values as
`Output` strings and structured warnings. Shell rendering lives in
`internal/apshellcli`, so `internal/engine` does not own a user-facing output
writer.

The Engine exposes resolver-backed ASA access through methods such as:

- `ASAResolver()`
- `ResolveASAReference(...)`
- `GetASAInfo(...)`

Callers use those entry points or `internal/asa` directly rather than reaching into `AsaCache` for reference resolution or display formatting.

### Functional Options Pattern

The Engine uses functional options for configuration:

```go
eng, err := engine.NewEngine("testnet",
    engine.WithDataDir(dataDir),
    engine.WithAlgodClient(client),
    engine.WithASACache(asaCache),
    engine.WithAliasCache(aliasCache),
    engine.WithSignerCache(signerCache),
    engine.WithAuthCache(authCache),
    engine.WithSetCache(setCache),
)
```

## Error Types

The Engine defines sentinel errors for common conditions:

```go
var (
    ErrNotConnected      = errors.New("not connected to Signer")
    ErrInvalidAddress    = errors.New("invalid address or alias")
    ErrInvalidAmount     = errors.New("invalid amount")
    ErrInvalidAssetID    = errors.New("invalid asset ID")
    ErrNoSigningKey      = errors.New("no signing key available for address")
    ErrTransactionFailed = errors.New("transaction failed")
    ErrAlreadyConnected  = errors.New("already connected")
    ErrConnectionFailed  = errors.New("connection failed")
    ErrInvalidNetwork    = errors.New("invalid network")
    ErrSimulationFailed  = signing.ErrSimulationFailed
    ErrSignerLocked      = errors.New("signer is locked — unlock via apadmin before signing")
    ErrNoAlgodClient     = errors.New("algod client not configured")
    ErrAliasNotFound     = errors.New("alias not found")
    ErrSetNotFound       = errors.New("set not found")
)
```

These allow callers to handle specific error conditions:

```go
result, err := engine.SignAndSubmit(ctx, prep, true)
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
    Locked       bool
    ErrorMessage string
}

// ParticipationResult holds consensus participation status for an account
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
prep, balanceCheck, err := engine.PreparePayment(ctx, SendPaymentParams{
    From:   "ABC123...",  // Pre-resolved address
    To:     "DEF456...",  // Pre-resolved address
    Amount: 1000000,      // 1 ALGO in microAlgos
})

// UI can display balance warnings from balanceCheck
if !balanceCheck.SufficientFunds {
    fmt.Printf("Warning: Insufficient funds\n")
}

// Phase 2: Sign and submit
result, err := engine.SignAndSubmit(ctx, prep, true) // wait for confirmation
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
| `PrepareAppDeploy` | Prepare app creation |
| `PrepareAppCallRaw` | Prepare raw app call |
| `PrepareAppCallMethod` | Prepare ABI-backed app call |
| `PrepareGroup` | Assemble prepared transactions into a group |
| `ExecutePreparedGroup` | Sign and submit a prepared group |
| `SignAndSubmit` | Sign and submit single transaction |
| `SignAndSubmitAtomic` | Sign and submit atomic group |
| `SignAndSubmitTransactions` | Sign pre-built transactions |
| `SignAndSubmitWithPluginSigners` | Run the pre-sign planning flow for mixed plugin/managed groups |
| `ValidateAtomicPayments` | Validate atomic ALGO payments |
| `ValidateAtomicASATransfers` | Validate atomic ASA transfers |
| `WaitForConfirmation` | Wait for transaction confirmation |

## Signing API

### SigningContext

The Engine builds signing contexts that encapsulate all information needed to sign:

```go
type SigningContext struct {
    Address     string // Resolved address (the account)
    SigningAddr string // Auth address (may differ if rekeyed)
    KeyType     string // e.g., "ed25519", "aplane.falcon1024.v1", "aplane.timed-whitelist.v1"
    SigSize     int    // Crypto signature size (for fee calculation), 0 for ed25519 and generic lsigs
    IsLSig      bool   // true for LSig-based accounts (DSA or generic)
}

// BuildSigningContext handles:
// 1. Alias resolution (accepts address or alias)
// 2. Auth address lookup (for rekeyed accounts)
// 3. Key type and LSig metadata retrieval
signingCtx, err := engine.BuildSigningContext(ctx, "ABC123...")
```

### Auth and Signing Helpers

```go
// RefreshAuthCacheWithContext refreshes auth addresses from blockchain
err := engine.RefreshAuthCacheWithContext(ctx)

// IsRekeyed checks if address is rekeyed
isRekeyed, authAddr := engine.IsRekeyed(address)

// CanSignForAddress checks signing capability
canSign, isLsig := engine.CanSignForAddress(address)
```

## Connection API

### SSH Tunnel Connection

`ConnectWithTunnel` is the product-facing remote connection path used by
`apshell`. It creates or reuses a local tunnel to the signer HTTP API and
populates the signer cache after connection.

```go
result, err := engine.ConnectWithTunnel(
    target,      // "user@host"
    host,        // "host.example.com"
    sshPort,     // 1127
    localPort,   // 11270
    signerPort,  // 11270
    token,       // API token (HTTP auth)
    identityFile,    // SSH private key path (optional, uses agent if empty)
    knownHostsPath,  // known_hosts file for SSH verification
    hostKeyApproval, // TOFU callback for unknown SSH host keys
    onDisconnect,    // optional lifecycle callback
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

// Request a new token through the SSH provisioning flow
token, err := engine.RequestToken(host, sshPort, identityFile, knownHostsPath, hostKeyApproval, onProvisioningStart)
```

## Cache Management API

### Aliases

```go
// List all aliases
aliases := engine.ListAliases()

// Get specific alias
alias := engine.GetAlias("alice")

// Add/update alias
result, err := engine.AddAliasWithContext(ctx, "alice", "ABC123...")

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

### Cache Staleness & Integrity

Caches are optimistic — they can become stale if external state changes mid-session.
The design ensures that **staleness can only cause failed transactions, never incorrect ones**:

| Cache | Source of Truth | Staleness Cause | Worst Case |
|-------|----------------|-----------------|------------|
| **SignerCache** | apsigner `/keys` | Key added/deleted on signer | Missing key → signing error; stale key → server rejects |
| **AuthCache** | Blockchain `auth-addr` | Account rekeyed externally | Wrong signer → transaction rejected by network |
| **AliasCache** | User commands | User-managed only | N/A — user controls all mutations |
| **SetCache** | User commands | User-managed only | N/A — user controls all mutations |
| **ASACache** | Blockchain + builtins | Asset params changed (rare) | Wrong decimals in display; amounts are base units at signing |

**Note**: There is no LSig cache in the Engine. LSig bytecode is stored in the signer's key files and retrieved per-signing-operation.

**Key safety property**: No cache staleness can cause funds to be sent to a wrong address
or signed by an unintended key. The blockchain and apsigner enforce correctness at
submission time — caches only affect address resolution and display.

**Self-healing mechanisms**:
- SignerCache: rebuilt from `/keys` on `keys`/`accounts` commands, tab completion,
  `/status` keyset-revision changes, and guarded submit paths whose cached
  signer row is missing current signing-flow or sentry metadata
- AuthCache: auto-refreshes individual entries when a cached auth address leads to an unsignable key
- ASACache: fetches from blockchain on cache miss

### Algod Client

The algod HTTP client uses a 30-second `ResponseHeaderTimeout` — the maximum time to wait for the server to begin responding. This prevents indefinite hangs when using remote algod providers (e.g., Nodely). The timeout does not limit response body reads, only the initial server response.

## Account API

```go
// Get balance
result, err := engine.GetBalance(ctx, address)

// Get account info (all known accounts)
accounts, err := engine.ListAccounts()

// Get participation status
result, err := engine.GetParticipationStatus(ctx, address)

// Check incentive eligibility
eligible, err := engine.GetIncentiveEligibility(ctx, address)
```

## Thread Safety

Connection state is protected by a mutex:

```go
type ConnectionState struct {
    Mu                sync.Mutex
    SignerClient      *signerclient.Client
    SignerProgressOut io.Writer
    SSHTunnelClient   *sshtunnel.Client
    TunnelConnected   bool
    TunnelCtx         context.Context
    TunnelCancel      context.CancelFunc
    ConnectionTarget  string
    connectingTarget  string
    portDialTimeout   func(network, address string, timeout time.Duration) (net.Conn, error)
}

func (e *Engine) IsConnected() bool {
    return e.Connection.IsConnected()
}
```

## Commands Using Engine

| Command | Engine Methods Used |
|---------|---------------------|
| send | `PreparePayment`, `PrepareASATransfer`, `SignAndSubmit` |
| optin | `PrepareOptIn`, `SignAndSubmit` |
| optout | `PrepareOptOut`, `SignAndSubmit` |
| rekey/unrekey | `PrepareRekey`, `SignAndSubmit` |
| close | `PrepareClose`, `SignAndSubmit` |
| sweep | `PreparePayment`, `PrepareASATransfer`, `SignAndSubmit` |
| sign | `SignAndSubmitTransactions` |
| keyreg | `PrepareKeyReg`, `SignAndSubmit` |
| app | `PrepareAppDeploy`, `PrepareAppCallRaw`, `PrepareAppCallMethod`, `ExecutePreparedGroup` |
| alias | ListAliases, GetAlias, AddAlias, RemoveAlias |
| sets | ListSets, GetSet, AddSet, RemoveSet, AddToSet, RemoveFromSet |
| balance | `GetBalance`, `GetASAInfoWithContext` |
| accounts | `ListAccounts` |
| participation | `GetParticipationStatus` |
| status | `GetStatus` |
| connect | `ConnectWithTunnel`, `RequestToken`, `Disconnect` |
| rekey refresh | `RefreshAuthCacheWithContext`, `RefreshAuthAddressWithContext` |

## Benefits of the Engine Pattern

1. **Single Source of Truth** - All business logic lives in one place
2. **Testability** - Engine methods can be unit tested independently
3. **Consistency** - Identical behavior across REPL, JS, MCP, and CLI
4. **Maintainability** - Clear separation of concerns
5. **Extensibility** - New UIs can be added with thin adapters
6. **Documentation** - Parameter types serve as contracts

## Related Documentation

- [ARCH_OVERVIEW.md](ARCH_OVERVIEW.md) - Overall system architecture
- [ARCH_CRYPTO.md](ARCH_CRYPTO.md) - Cryptography layer (signing, key generation)
- [ARCH_REPL.md](ARCH_REPL.md) - apshell REPL architecture
- [ARCH_MCP.md](ARCH_MCP.md) - apshell MCP server and tool surface
- [ARCH_TUI.md](ARCH_TUI.md) - signer admin TUI (apadmin)
- [USER_CONFIG.md](USER_CONFIG.md) - Configuration reference
