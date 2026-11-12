# Shell Architecture

> The client side of APlane: the `internal/engine` mechanics beneath `apshell`,
> the REPL surface, application interaction, and the MCP surface.

Compatibility-bearing parts of this document are the
[parsing contracts](#parsing-contracts) and the
[MCP tool contract](#tool-surface); [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md)
indexes them.

This document does not define the signer HTTP API, the admin protocol, or the
signing flow; see [ARCH_SIGNING.md](ARCH_SIGNING.md#http-api-contract),
[ARCH_ADMIN.md](ARCH_ADMIN.md#admin-protocol-contract), and
[ARCH_SIGNING.md](ARCH_SIGNING.md).

## Contents

- [Overview](#overview)
- [Layering](#layering)
- [Design Philosophy](#design-philosophy)
- [Engine](#engine)
- [REPL Surface](#repl-surface)
- [App Interaction](#app-interaction)
- [MCP Surface](#mcp-surface)
- [Client Output and Logging](#client-output-and-logging)
- [Key Files](#key-files)
- [Related Documentation](#related-documentation)

## Overview

The Engine subsystem (`internal/engine/`) is the core business-operations layer
for APlane Shell. It sits beneath the shell application layer in
`internal/apshellapp`, which owns shell-facing command semantics and workflow
orchestration. The engine provides reusable transaction logic, cache-backed
runtime state, signer connectivity, and network operations that can be shared
across `apshell` REPL, MCP, scripting, and CLI one-shot flows. It is not the
backend for `apadmin` or `apapprover`, which talk to `apsigner` over the admin
protocol over local IPC.

`apshell` is the interactive shell for APlane. The REPL surface handles user
interaction (readline, tab completion, colored output) and delegates command
semantics to `internal/apshellapp` above `internal/engine`. The MCP surface
shares the same parsing and rendering pipeline but produces structured JSON
instead of terminal text; see [MCP Surface](#mcp-surface). The signer admin
TUI is a separate client over the admin protocol; see [ARCH_ADMIN.md](ARCH_ADMIN.md#signer-admin-tui).

## Layering

```
+-----------------------------------------------------------+
|                       apshell UI                          |
|   REPL (readline)            MCP server (stdio JSON-RPC)  |
+--------------------+--------------------------------------+
|     internal/shellrepl  +  internal/cmdspec  (parsing)    |
+-----------------------------------------------------------+
| internal/apshellcli (shared result + text/machine rendering) |
+-----------------------------------------------------------+
|     internal/addressbook  (alias / set / @signers / @all) |
+-----------------------------------------------------------+
|     internal/apshellapp   (shell command workflows)       |
+-----------------------------------------------------------+
|     internal/engine       (reusable client mechanics)     |
+-----------------------------------------------------------+
```

REPL-specific state remains in `REPLState`. Shell command workflows live in
`internal/apshellapp`. Lower-level client mechanics live in `internal/engine`
behind the app facade. The same `apshellapp` boundary is consumed by the MCP
server.

### Architecture Diagram

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

## Engine

This section covers `internal/engine/`, the reusable client mechanics beneath
`internal/apshellapp`.

### File Organization

```
internal/engine/
├── core.go                # Shared client infrastructure and runtime state
├── engine.go              # Engine facade embedding *Core, constructor, options
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
├── connect/               # Signer HTTP requests and SSH tunnel lifecycle state
│   ├── client.go          # Signer client construction and request helpers
│   ├── lifecycle.go       # Connect/disconnect and tunnel lifecycle
│   ├── cosigner_endpoint.go # Cosigner endpoint connection helpers
│   ├── local_port.go      # Free loopback port selection for tunnels
│   ├── signing.go         # Signer-facing plan/sign requests
│   └── state.go           # Mutex-protected ConnectionState
├── connection.go          # Core-facing connection facade
├── consensus.go           # Algod consensus compatibility checks
├── cosigner_status.go     # Cosigner endpoint and account inventory status
├── group.go               # PreparedGroup, grouped preparation and execution
├── cosigned.go             # Cosigned package wiring and public re-exports
├── cosigned/               # Isolated cosigned-account client orchestration
│   ├── discovery.go       # Cosigner endpoint/key discovery
│   ├── inspect.go         # Setup-time cosigner endpoint inspection
│   ├── signer.go          # Narrow dependency surface and Signer type
│   ├── status.go          # Point-in-time route and connection observations
│   └── submit.go          # Cosigned and bounded-cosigner component signing, assembly, and submission
├── init.go                # Package initialization
├── keygen_params.go       # Key-generation parameter normalization
├── keymgmt.go             # Key management operations
├── keyreg.go              # Key registration (online/offline)
├── output_error.go        # Output/error formatting helpers for results
├── payment.go             # Payment preparation
├── plugin_pregrouped.go   # Pre-grouped plugin transaction submission
├── plugin_presign.go      # Plugin pre-sign planning flow (mixed managed/plugin groups)
├── plugin_signing.go      # Shared helpers for plugin transaction submission
├── plugin_transactions.go # Plugin transaction processing
├── rekey.go               # Rekey/unrekey operations
├── rotating.go            # Rotating-account queries and signer status lines
├── signer_cache.go        # Signer cache helpers and cosigned metadata access
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

### Engine Structure

#### Core Infrastructure and Engine Facade

```go
// Core owns infrastructure shared by Engine domain operations.
type Core struct {
    *clientstate.State
    Connection *connect.ConnectionState
    // cache watcher, signer-cache synchronization, execution flags,
    // and cosigner endpoint configuration
}

// Engine is the application facade. Domain operations are methods on Engine
// and reach shared infrastructure through the embedded Core.
type Engine struct {
    *Core
}
```

`clientstate.State` owns the client data directory, selected network, algod
client, and client-side caches. `connect.ConnectionState` owns signer HTTP and
SSH tunnel lifecycle state. `Core` adds the client-data lock, cache watcher,
signer-cache synchronization, and shared address/signability/asset resolution.
Domain command operations such as payments, assets, apps, key management, and
cosigned signing remain methods on `Engine`.

Cosigned signing is intentionally isolated in `internal/engine/cosigned`. It does
not import `internal/engine`; the facade constructs a short-lived
`cosigned.Signer` from concrete connection/cache/algod dependencies plus a
narrow read-only signer-cache view. `cosigned.go` owns that wiring and re-exports
the discovery types and error sentinels used by existing engine callers. The
dependency and exported-surface boundaries are pinned by `test/arch`.

The same isolated package dispatches explicit inventory flow labels. `cosigned1`
uses user-first bounded component release, cosigner-role component signing, and
bounded assembly, for spends and rekeys, on a plain or bounded host. Each bounded-base component names its
path; the client asks the cosigner for every target but a `listed_rekey` one,
sends no cosigner request when no target needs one, and budgets each cosigned
position in a mixed group on its component's path. It rejects unknown labels,
`bounded-cosigner1` and the retired `cosigner1` among them. Accounts with the
overlays but no online cosigner advertise `bounded1` and continue through
ordinary signing. A `plain1` account has no fee ceiling: the client caches each
account's contract and checks a planned fee only against a `bounded2` account's
`max_fee`.

Submission and confirmation diagnostics are returned on typed result values as
`Output` strings and structured warnings. Shell rendering lives in
`internal/apshellcli`, so `internal/engine` does not own a user-facing output
writer.

The Engine exposes resolver-backed ASA access through methods such as:

- `ASAResolver()`
- `ResolveASAReference(...)`
- `GetASAInfoWithContext(...)`

Callers use those entry points or `internal/asa` directly rather than reaching into `AsaCache` for reference resolution or display formatting.

#### Functional Options Pattern

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

### Error Types

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

### Result Types

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

### Transaction API

#### Parameter Types

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
    Close      bool   // close the account to To
    LsigArgs   map[string][]byte // optional per-call LogicSig arguments (e.g. HTLC preimage)
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
    LsigArgs   map[string][]byte // optional per-call LogicSig arguments (e.g. HTLC preimage)
}

// OptInParams for ASA opt-in
type OptInParams struct {
    Account    string // Resolved address (58-char)
    AssetID    uint64
    Fee        uint64
    UseFlatFee bool
    LsigArgs   map[string][]byte // optional per-call LogicSig arguments (e.g. HTLC preimage)
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
    LsigArgs          map[string][]byte // optional per-call LogicSig arguments (e.g. HTLC preimage)
}

// RekeyParams for rekeying accounts
type RekeyParams struct {
    From       string // Account to rekey
    To         string // New auth address
    Fee        uint64
    UseFlatFee bool
    LsigArgs   map[string][]byte // optional per-call LogicSig arguments (e.g. HTLC preimage)
}

// CloseAccountParams for closing accounts
type CloseAccountParams struct {
    From       string // Account to close
    CloseTo    string // Recipient of remaining ALGO
    Fee        uint64
    UseFlatFee bool
    LsigArgs   map[string][]byte // optional per-call LogicSig arguments (e.g. HTLC preimage)
}

// OptOutParams for ASA opt-out
type OptOutParams struct {
    Account    string
    AssetID    uint64
    CloseTo    string // Recipient of remaining balance
    Fee        uint64
    UseFlatFee bool
    LsigArgs   map[string][]byte // optional per-call LogicSig arguments (e.g. HTLC preimage)
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

#### Prepare-Then-Submit Pattern

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

#### Available Transaction Methods

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

### Signing API

#### SigningContext

The Engine builds signing contexts that encapsulate all information needed to sign:

```go
type SigningContext struct {
    Address           string // Resolved address (the account)
    SigningAddr       string // Auth address (may differ if rekeyed)
    KeyType           string // e.g., "ed25519", "aplane.falcon1024.v1", "aplane.htlc.v1"
    SigSize           int    // Crypto signature size (for fee calculation), 0 for ed25519 and generic lsigs
    IsLSig            bool   // true for LSig-based accounts (DSA or generic)
    AuthorizationKind algorithm.AuthorizationKind
}

// BuildSigningContext handles:
// 1. Alias resolution (accepts address or alias)
// 2. Auth address lookup (for rekeyed accounts)
// 3. Key type and LSig metadata retrieval
signingCtx, err := engine.BuildSigningContext(ctx, "ABC123...")
```

#### Auth and Signing Helpers

```go
// RefreshAuthCache refreshes auth addresses from blockchain
err := engine.RefreshAuthCache(ctx)

// IsRekeyed checks if address is rekeyed
isRekeyed, authAddr := engine.IsRekeyed(address)

// CanSignForAddress checks signing capability
canSign, isLsig := engine.CanSignForAddress(address)
```

### Connection API

#### SSH Tunnel Connection

`ConnectWithTunnel` is the product-facing remote connection path used by
`apshell`. It creates or reuses a local tunnel to the signer HTTP API and
populates the signer cache after connection.

```go
result, err := engine.ConnectWithTunnel(
    target,      // display label, e.g. "host.example.com (ssh:1127)"
    host,        // "host.example.com"
    sshPort,     // 1127
    localPort,   // free loopback port chosen by the caller
    identityFile,    // SSH private key path (optional, uses agent if empty); the enrolled key is the credential
    knownHostsPath,  // known_hosts file for SSH verification
    hostKeyApproval, // TOFU callback for unknown SSH host keys
    onDisconnect,    // optional lifecycle callback
)
```

#### Connection Management

```go
// Check connection status
if engine.IsConnected() { ... }
if engine.IsTunnelConnected() { ... }

// Get connection info
target := engine.GetConnectionTarget()

// Disconnect
err := engine.Disconnect()

// Ask the node to enroll this client's key; returns at once with the key's
// SHA256 fingerprint and whether the request now waits for the operator
// (Pending) or the key was already enrolled
result, err := engine.RequestEnrollmentWithContext(ctx, host, sshPort, identityFile,
    knownHostsPath, label, hostKeyApproval, onEnrollmentStart)
```

### Cache Management API

#### Aliases

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

#### Sets

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

#### Cache Staleness & Integrity

Caches can become stale when chain state or another process changes shared
client data. Signer and network checks reject some stale authority/state inputs,
but cache validation is not a guarantee that resolved addresses or amounts
match an operator's intent:

| Cache | Source of Truth | Staleness Cause | Worst Case |
|-------|----------------|-----------------|------------|
| **SignerCache** | apsigner `/keys` | Key added/deleted on signer | Missing key → signing error; stale key → server rejects |
| **AuthCache** | Blockchain `auth-addr` | Account rekeyed externally | Wrong signer → transaction rejected by network |
| **AliasCache** | Persisted operator alias state | Another client changes an alias | A stale resolved address may still be a valid recipient; inspect the resolved transaction |
| **SetCache** | Persisted operator set state | Another client changes membership | Stale recipients may still be valid addresses |
| **ASACache** | Blockchain + builtins | Stale or incorrect metadata | Display-unit conversion may select unintended base units; the signer sees those base units |

**Note**: There is no LSig cache in the Engine. LSig bytecode is stored in the signer's key files and retrieved per-signing-operation.

The blockchain enforces the effective authorizer, and apsigner applies policy
to decoded transaction bytes. Neither can infer an intended recipient or
display-unit amount from a stale alias/set/ASA cache. Shared client mutations
use the cooperative lock, and passive cache watching refreshes snapshots at
command boundaries; those mechanisms improve freshness rather than prove intent.

**Self-healing mechanisms**:
- SignerCache: rebuilt from `/keys` on `keys`/`accounts` commands, tab completion,
  `/status` keyset-revision changes, and cosigned submit paths whose cached
  signer row is missing current signing-flow or cosigner metadata
- AuthCache: auto-refreshes individual entries when a cached auth address leads to an unsignable key
- ASACache: fetches from blockchain on cache miss

#### Algod Client

The algod HTTP client uses a 30-second `ResponseHeaderTimeout` — the maximum time to wait for the server to begin responding. This prevents indefinite hangs when using remote algod providers (e.g., Nodely). The timeout does not limit response body reads, only the initial server response.

### Account API

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

### Thread Safety

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

### Commands Using Engine

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
| alias | ListAliases, GetAlias, AddAliasWithContext, RemoveAlias |
| sets | ListSets, GetSet, AddSet, RemoveSet, AddToSet, RemoveFromSet |
| balance | `GetBalance`, `GetASAInfoWithContext` |
| accounts | `ListAccounts` |
| participation | `GetParticipationStatus` |
| status | `GetStatus` |
| connect | `ConnectWithTunnel` |
| disconnect | `Disconnect` |
| enroll, endpoints add | `RequestEnrollmentWithContext` |
| rekey refresh | `RefreshAuthCache`, `RefreshAuthAddressWithContext` |

### Benefits of the Engine Pattern

1. **Single Source of Truth** - All business logic lives in one place
2. **Testability** - Engine methods can be unit tested independently
3. **Consistency** - Identical behavior across REPL, JS, MCP, and CLI
4. **Maintainability** - Clear separation of concerns
5. **Extensibility** - New UIs can be added with thin adapters
6. **Documentation** - Parameter types serve as contracts

## REPL Surface

This section covers the interactive `apshell` surface in `internal/apshellcli`,
`internal/shellrepl`, and `internal/cmdspec`.

### Session State

`internal/apshellcli/state.go` defines `REPLState`:

```go
type REPLState struct {
    Out                    io.Writer
    App                    *apshellapp.App
    DataDir                string
    CommandRegistry        *command.Registry
    Scripts                ScriptSession
    LineReader             func() (string, error)
    LineReaderContext      func(context.Context) (string, error) // cancellation-aware line reader for embedded hosts
    SetPrompt              func(string)
    AutoConfirm            bool
    HostKeyApproval        func(host, fingerprint string) (bool, error)
    HostKeyApprovalContext func(context.Context, string, string) (bool, error) // cancellation-aware host-key approval for embedded hosts
    ProgressLine           func(string)
    currentCommandCtx      context.Context
    runtimeMu              sync.Mutex // serializes background signer-cache polling with command execution and readline completion
}
```

`REPLState` holds no copy of the client config. The app owns it: commands read
`App.Config`, and endpoint aliases resolve in `apshellapp`, which keeps the
config and the engine's endpoint registry on the same view of
`endpoints.yaml`. `test/arch` enforces this.

Command text rendering flows through an injected `io.Writer`. MCP does not
capture that writer: it marshals the already-computed command result. The
terminal-only `config` display remains the reviewed process-global-output
exception and is blocked from MCP automation.

### Command Handler Pattern

```go
func (r *REPLState) cmdSend(args []string, _ interface{}) (command.Result, error) {
    // 1. PARSE: shell tokens to structured params
    params, err := shellrepl.ParseSendCommand(args)

    // 2. APP: delegate workflow semantics and engine orchestration
    result, err := r.app().Send(r.commandContext(), apshellapp.SendRequest{...})

    // 3. RESULT: bind presentation-only renderers to computed data
    return newShellCommandResult(renderSend(result), projectSend(result))
}
```

### Command Parsing

`internal/shellrepl/` owns top-level tokenization and per-command parsers that
return structured parameter types:

```go
cmdName, args, err := ParseCommand(line)
params, err := ParseSendCommand(args)                  // TransactionParams
params, err := ParseOptinCommand(args)                 // OptInParams
params, err := ParseOptoutCommand(args)                // OptOutParams
params, err := ParseCloseCommand(args)                 // CloseParams
params, err := ParseRekeyCommand(args, isUnrekey)      // RekeyParams (rekey vs unrekey)
params, err := ParseSweepCommand(args)                 // SweepParams
params, err := ParseTakeCommand(args)                  // KeyRegParams
```

`internal/cmdspec/` owns shared primitives that handlers consume rather than
re-implementing: bracket-aware `key=value` parsing, byte-value decoding,
address and address-list handling, and semantic ASA input helpers.

#### Parsing Contracts

The `apshell` command surface remains compatibility-sensitive even when internal parsing is refactored.

Parsing contracts:

- bracketed address lists such as `[ A1 A2 ]` and `[A1 A2]` are accepted where a command already accepts address-list input,
- `generate` parameter parsing is bracket-aware for `key=value` arguments,
- `generate` reads its own flags, `--boundary <file>` and `--result <file>`, and sends neither to the signer; every `param=value` is the signer's. A boundary file sets every parameter, so it cannot be combined with others,
- LogicSig `arg:name=value` parsing keeps the `arg:name=` split local to `internal/cmdspec/lsigarg.go` and uses the shared byte parser for the value side,
- byte-oriented shell inputs support `hex:`, `b64:`, `text:`/`str:`, `int:`, `addr:`, and `0x...`; bare text is accepted only where command behavior allows it, and never when it contains a colon,
- ASA-facing commands may parse shell input into semantic values (`AssetRef`, `AmountText`) before command execution, but this does not change user syntax,
- `send` and `sweep` parse their required `from`/`to`/`leaving` structure first and only treat later tokens as trailing options, so positional address/account inputs may legitimately equal keywords such as `atomic`, `nowait`, or `leaving` without being reinterpreted as flags.
- an option that takes one value is given once: a second value is refused with `<option> given more than once` (`cmdspec.SeenOptions`, and `cmdspec.AddLsigArg` for `arg:<name>=`), never read as the last value. An option with two spellings, such as `--pay`/`pay=`, is one option. List options (`--arg`, `arg-raw=`, `account=`, `app=`, `asset=`, `box=`) and `arg:` with different names repeat; flags without a value (`nowait`, `atomic`) may repeat to no effect. `generate` refuses a repeated parameter key in `cmdspec.ParseKeyValueArgs`.

### Address Resolution

`internal/addressbook/resolver.go` converts user-friendly names to addresses.
The resolver consults the alias and set caches, plus optional providers
(`SignerProvider`, `AllAddressesProvider`, `HoldersProvider`) attached through
`WithSignerProvider`/`WithAllProvider`/`WithHoldersProvider` for the reserved
`@signers`, `@all`, and `@holders(...)` dynamic sets:

```go
resolver := addressbook.NewResolver(&aliasCache, &setCache).
    WithSignerProvider(signerAddresses).
    WithAllProvider(allAddresses).
    WithHoldersProvider(holdersOf)

addr,  err := resolver.ResolveSingle("alice")
addrs, err := resolver.ResolveList([]string{"alice", "@team", "@signers"})
```

`ResolveList` accepts a mix of aliases, raw addresses, user-defined `@setname`
references, and the dynamic `@signers`/`@all`/`@holders(<asset>)` sets.
`ResolveSingle` enforces a single result and returns `MultipleAddressError`
when a set expands to more than one address.

### Tab Completion

`internal/shellrepl/autocomplete.go` provides context-aware tab completion using
`ArgSpec` definitions from the command registry. External plugins declare their
argument types in `manifest.json` via `arg_specs` and support address, asset,
set, keyword, number, file, and conditional branching. The `custom` type is
reserved for plugin-provided completion; the runtime returns no custom
suggestions.

Built-in commands complete in two layers. `ContextCompleter.Do` first tries
context paths that understand a command's argument positions and match account
addresses case-insensitively (`completeAddressFromCommand`, plus dedicated
`alias`, `rekey`, and `rotate` completers). Only lines none of them claim fall
through to the readline prefix tree, which compares case-sensitively against
uppercase addresses, so a lowercase prefix finds nothing there. A command
whose arguments include accounts should therefore be covered by a context
path. Keywords stay case-sensitive where the command handler compares them
exactly: readline only appends the rest of a suggestion, so folding case would
complete `RE` into a word the handler rejects.

### Command Result Rendering

Every registered handler returns a `command.Result`:

```go
type Result interface {
    RenderText(w io.Writer) error
    MarshalMachine() ([]byte, error)
}
```

The REPL executes once and calls `RenderText`; MCP resolves the canonical
command, enforces its explicit structured/blocked policy, executes once, and
calls `MarshalMachine`. Renderers operate only on already-computed data and may
be called repeatedly without network reads, signing, submission, or mutation.

Machine projections in `command_projections.go` are explicit security
allowlists. Plugin projection filters the reserved `localSigners` field.
One-shot `simulate <transaction-command>` invokes the same result-bearing
executor while simulation is temporarily forced and restores the prior mode
with deferred cleanup.

### Command Dispatch

```go
func (r *REPLState) executeCommand(cmd Command) error {
    result, err := r.executeCommandResult(cmd)
    // ... handle errors, then render result once
    return result.RenderText(r.Out)
}
```

Built-in commands are registered at startup via `initCommandRegistry()` with
`Handler: command.NewInternalHandler(r.cmdSend)`:

```go
mustRegister(registry, &command.Command{
    Name:    "send",
    Handler: command.NewInternalHandler(r.cmdSend),
})
```

Built-in automation policies are not set inline. They live in the central
`builtInAutomationPolicies` map in `registry.go`, and `mustRegister` applies
the matching policy, panicking for a built-in command that has none.

External plugins are never added to the registry. They are discovered at
runtime by the plugin manager and matched by command name from their
`manifest.json`. Plugin results flow through the same result-bearing execution
and presentation system as built-in commands. See
[ARCH_PLUGINS.md](ARCH_PLUGINS.md) for plugin details.

### Generate Options

`--boundary` and `--result` are apshell's own flags. `App.SplitGenerateOptions` in
`internal/apshellapp` takes them out of `generate`'s arguments, as `--flag file` or
`--flag=file`, and refuses any other `--` argument, a missing or empty file, and a flag
given twice. Every `param=value` is the signer's, so a template may declare a parameter
called `boundary` or `result` and receive it, and no lookup is needed to tell them apart.

`--boundary` alone reads the signer's key types (`App.CheckBoundaryKeyType`), before the
file is read: a type without `boundary_schema` `aplane.boundary.v1` is refused (the plain
hosts report it), and so is a failed lookup or a type the signer doesn't report. That is the
path's only lookup, since `GenerateKeyFromLiterals` fetches none. Generation without
`--boundary` gains no dependency on it.

This only picks a client flow. See "Client routing" in
[ARCH_KEYTYPES.md](ARCH_KEYTYPES.md) for what the field does and doesn't promise.

### Error Handling

| Mode | Behavior |
|------|----------|
| REPL | Print error message, continue loop |
| MCP  | Return `NewToolResultError(msg)`, continue serving |

The TUI uses its own error display; see [ARCH_ADMIN.md](ARCH_ADMIN.md#signer-admin-tui).

### Approval CLI (apapprover)

`apapprover` is a minimal interactive approval client for signer IPC. It is a
separate CLI surface from `apshell` and the `apadmin` TUI and is intended for
focused approval workflows.

| Aspect | Detail |
|--------|--------|
| Input | stdin `y/n` approval loop |
| Output | FIFO approval queue rendered to terminal |
| State | In-memory pending queue of signing and client-enrollment requests |
| Transport | Local IPC admin protocol |

Signing and client-enrollment requests share a single FIFO queue. Policy
violations included in sign requests are shown to the approver. Signing
approval requests time out after the product runtime's effective `approval_wait` value,
which defaults to 60 seconds. Enrollment requests do not use the signing
approval timeout: they persist in the signer's queue for up to seven days after
the latest request for that key, every request still waiting is announced to
`apapprover` when it connects, and `y`/`n` answers one by fingerprint with
`approve_enrollment` or `reject_enrollment`.

## App Interaction

App interaction extends APlane from a transaction-centric shell into an
application-aware execution layer for Algorand smart contracts.

It supports:
- application state reads
- raw application calls
- ARC-4 / ABI-backed method calls
- grouped app execution with companion payments
- scripting access through the JS runtime
- signer-side approval descriptions for app calls

### Scope

App interaction includes:
- app state reads from algod
- app call transaction preparation in `internal/engine`
- shell-facing app command orchestration in `internal/apshellapp`
- explicit ABI loading from local files
- grouped execution through a first-class `PreparedGroup`
- CLI and JS user surfaces
- signer approval rendering for application calls

App interaction does not include:
- interactive `group create/add/build/send` REPL state
- ABI discovery from network sources
- provider-layer redesign
- external authorizers such as ECDSA / EIP-712
- protocol-specific adapters for individual dApps

### Core Invariant

The main architectural invariant is:

**`PreparedGroup` is the canonical boundary between transaction preparation and grouped execution.**

App interaction does not introduce a new authorization abstraction, but it makes
grouped app execution explicit rather than treating it as ad hoc
`[]types.Transaction` plumbing at the outer layers.

This keeps the app interaction work compatible with the signer flow.

### Design Goals

#### Engine-first

Core app preparation lives in `internal/engine`. Shell-facing command
workflows, alias resolution, and result shaping sit above that layer in
`internal/apshellapp`. `internal/apshellcli` owns shell command parsing, REPL
handling, and rendering, while `cmd/apshell` stays the thin binary adapter for
flags, provider registration, bootstrap, and mode selection.

This follows the same design rule as the rest of APlane:
- the engine operates on resolved addresses, numeric IDs, and prepared inputs
- `internal/apshellapp` owns shell command semantics and app-facing orchestration
- UI layers parse user syntax and format results

#### Explicit ABI sourcing

ABI-backed calls require an explicit local ABI path. The system does not attempt
to discover ARC-4 contracts from the network.

This keeps method resolution deterministic and avoids introducing network
coupling, caches, or ambiguous discovery semantics into the engine.

#### Group-first for real dApp flows

Many Algorand app interactions require more than one transaction. Companion
payments are the common first example.

Grouped execution is an engine primitive instead of modeling app calls only as
standalone transactions.

#### Reuse the signer pipeline

App interaction prepares richer transaction plans, then routes them through
the shell-app to engine to signer path.

### Architecture

#### App Interaction Layering

```
┌──────────────────────────────────────────────────────────────┐
│ User Surfaces                                                │
│                                                              │
│  apshell CLI         apshell JS API          MCP exposure    │
│                                                              │
├──────────────────────────────────────────────────────────────┤
│ Shell Application Layer                                      │
│                                                              │
│  app read commands   raw call workflows   deploy workflows   │
│  method-call workflows                                       │
│                                                              │
├──────────────────────────────────────────────────────────────┤
│ Engine                                                       │
│                                                              │
│  app reads   raw app calls   ABI method calls   groups       │
│                                                              │
├──────────────────────────────────────────────────────────────┤
│ Existing signer/submission path                              │
│                                                              │
│  group planning   approval prompts   signing   submission    │
│                                                              │
├──────────────────────────────────────────────────────────────┤
│ Algod / Algorand SDK                                         │
└──────────────────────────────────────────────────────────────┘
```

#### Main packages

| Package | Responsibility |
|---------|----------------|
| `internal/apshellapp/` | Shell-facing app command orchestration and result shaping |
| `internal/engine/app_read.go` | App info/global/local/box reads |
| `internal/engine/app_call.go` | Raw and ABI-backed app call preparation |
| `internal/engine/app_deploy.go` | App deployment preparation and created-app lookup |
| `internal/appspec/` | ARC-4 contract loading, method resolution, argument encoding |
| `internal/engine/group.go` | `PreparedGroup`, grouped preparation, grouped execution |
| `internal/appinput/` | Shared parsing helpers used by CLI and JS |
| `internal/apshellcli/commands_app*.go` | CLI adapter and app command parsing surface |
| `internal/jsapi/apps.go` | JS app interaction bindings |
| `internal/txnreview/describe.go` | The description of a transaction, app calls included, shown by the signer's approval prompt and by apshell's plugin group review |
| `internal/txnreview/findings.go` | What a reviewer must not miss: rekeys, closes, clawbacks, app updates, deletes and clear-states, asset reconfigures, destroys and freezes, and an unusually high fee. The signer's approval warnings (`internal/signerapp/approvalpolicy`) and the plugin group review are both built from it |

### App State Reads

App interaction provides five engine read operations:
- `ReadAppInfo(ctx, appID)`
- `ReadAppGlobalState(ctx, appID)`
- `ReadAppLocalState(ctx, address, appID)`
- `ReadAppBox(ctx, appID, name)`
- `ListAppBoxes(ctx, appID)`

The CLI exposes these as:
- `app read info <app-id>`
- `app read global <app-id>`
- `app read local <app-id> <account>`
- `app read box <app-id> <box-name>`
- `app read boxes <app-id>`

Results are returned as structured JSON objects. Box names and values are
represented in both raw-safe and human-readable forms where possible so the same
surface works for scripting and manual inspection.

### App Call Preparation

#### Raw calls

Raw app calls are prepared directly from explicit app arguments and references.

Supported preparation inputs include:
- sender
- app arguments
- foreign accounts
- foreign apps
- foreign assets
- box references
- on-completion
- update-only approval and clear programs
- per-call LogicSig arguments
- note
- fee / flat-fee control

The engine entrypoint is:
- `PrepareAppCallRaw(ctx, params RawAppCallParams)`

The CLI surface is:
- `app call raw <app-id> from <account> ...`

Raw-call CLI arguments also include:
- `approval=` / `approval-teal=` / `approval-bin=` and `clear=` / `clear-teal=` / `clear-bin=` when `oncomp=update`
- `arg:name=value` for per-call LogicSig arguments passed through the existing signer flow

This path is the protocol-level fallback and does not depend on ABI metadata.

#### App deploy

Application deployment is also prepared in the engine so program loading,
compilation, schema sizing, and sender/signing context all live below the UI
layer.

Supported deployment inputs include:
- sender
- approval program path
- clear program path
- source vs compiled program selection
- global and local schema sizing
- extra pages
- note
- fee / flat-fee control

The engine entrypoint is:
- `PrepareAppDeploy(ctx, params AppDeployParams)`

The CLI surface is:
- `app deploy from <account> approval=<path>|approval-teal=<path>|approval-bin=<path> clear=<path>|clear-teal=<path>|clear-bin=<path> ...`

After confirmed submission, the engine can also resolve the created
application:
- `LookupCreatedApplication(ctx, txID)`

#### ABI-backed method calls

ARC-4 method calls build on top of the raw path.

The ABI layer:
- loads a contract JSON file from disk
- resolves a method by name or full signature
- encodes typed arguments
- prepends the selector
- delegates to the raw preparation path

The engine entrypoint is:
- `PrepareAppCallMethod(ctx, params MethodAppCallParams)`

The CLI surface is:
- `app call <app-id> <method> --abi <path> from <account> --arg ...`

This keeps ABI handling out of the signer and out of the low-level transaction
execution path.

### `PreparedGroup`

Grouped execution is represented by `PreparedGroup`:

```go
type PreparedGroup struct {
    Entries []PreparedGroupEntry
}

type PreparedGroupEntry struct {
    Transaction    types.Transaction
    SigningContext *SigningContext
    LsigArgs       map[string][]byte
    AppCallInfo    *signerapi.AppCallInfo
}
```

This type is owned by the engine. It represents:
- ordered transactions
- their derived signing metadata
- any per-entry LogicSig args

It does not represent authorization proofs, wallet sessions, or external
signing workflows.

#### Why `PreparedGroup` exists

It serves three roles:

1. It gives grouped app execution a stable engine-level type.
2. It preserves transaction-order metadata needed by the signer path.
3. It provides a clean boundary for companion-payment flows without requiring an
   interactive group builder.

#### Group preparation and execution

The engine exposes:
- `PrepareGroup(preps ...*TransactionPrepResult)`
- `PreparePaymentAppGroupWithContext(ctx, prepper, payment, app)`
- `PreparePaymentMethodGroupWithContext(ctx, prepper, payment, app)`
- `ExecutePreparedGroup(ctx, group, wait)`

The first concrete grouped dApp pattern is companion payment plus app call.

Both CLI and JS support this through a `pay` option:
- ABI-backed calls can prepend a payment to the app address
- raw calls can do the same without ABI metadata

The resulting group is signed and submitted through the group flow
rather than through a special-purpose protocol.

The paired helper methods are convenience helpers for the concrete grouped
patterns. More complex composition should
prepare transactions independently and compose them through
`PrepareGroup(...)` rather than multiplying bespoke helper functions.

This also marks a complexity boundary for `apshell`: the shell exposes
common app-interaction primitives and lightweight grouped patterns, but
it is not a general-purpose protocol orchestration DSL. When a
workflow requires richer multi-step composition, protocol-specific planning, or
substantial off-chain logic, the preferred approach is a custom script,
program, or adapter built on the same engine primitives.

### User Surfaces

#### CLI

The primary user surface is `apshell`.

Supported commands include:
- `app read info|global|local|box|boxes`
- `app deploy ...`
- `app call raw ...`
- `app call <app-id> <method> --abi <path> ...`
- grouped companion-payment calls with `--pay <microalgos>`
- `simulate <command>` using the simulate prefix

The CLI remains responsible for:
- numeric and byte parsing
- user-facing syntax
- command help and completion

Alias resolution and asset-name resolution for app calls are owned by
`internal/apshellapp` before requests reach `internal/engine`.

#### JavaScript API

App interaction also exposes bindings to the Goja-based scripting layer.

The JS API includes:
- `appDeploy(from, approvalPath, clearPath, opts)`
- `appInfo(appId)`
- `appGlobal(appId)`
- `appLocal(appId, account)`
- `appBox(appId, boxName)`
- `appBoxes(appId)`
- `appCallRaw(appId, from, appArgs, opts)`
- `appCall(appId, method, abiPath, from, args, opts)`

This is a convenience surface, not a separate architecture. JS bindings call
into the same engine primitives as the CLI.

One binding calls a shell workflow instead: `sweep()` runs `apshellapp`'s
sweep through `jsapi.Sweeper`, which the app hands to the runner
(`apshellapp/script_runtime.go`). `apshellapp` imports `jsapi`, so the
dependency points that way. The function and the command are one
implementation. The other bindings that share a command's name (`close()`,
`rekey()`) still prepare their transaction through the engine themselves.

#### Shared input parsing

`internal/appinput/` holds app-specific parsing helpers reused by shell and JS
surfaces, including:
- byte value decoding
- on-completion parsing

This keeps app-call input handling consistent across user surfaces.

#### MCP

MCP exposure is not a separate execution architecture. It is another thin user
surface over the same engine methods described in this document.

That means:
- MCP does not define its own transaction-preparation model
- MCP does not bypass `PreparedGroup`
- MCP should not accumulate app semantics that differ from CLI or JS

The engine remains the source of truth for app reads, app call preparation, and
grouped execution regardless of which surface invokes it.

### Reference Normalization

Application calls may include explicit references such as:
- foreign accounts
- foreign apps
- foreign assets
- box references

These are treated as engine preparation inputs rather than as surface-specific
concerns. The architectural rule is:

- user surfaces parse and resolve inputs
- the engine owns transaction construction
- any canonicalization or merge policy belongs in the engine, not in CLI, JS,
  or MCP wrappers

App interaction does not include a rich reference-planning abstraction. The
engine's merge policy is small and fixed:

- References the caller lists are sent exactly as given: in order, with
  repeats, and with the called app if it is listed. A program reads them by
  position, so the engine never deduplicates or reorders them. A zero app or
  asset ID is refused, not dropped.
- An app needed only by a box reference is appended, and only when the list
  doesn't already have it.
- A box written without an app ID is parsed with app ID 0, the called app,
  and always encodes as index 0, so its bytes don't depend on the rest of the
  list. Don't normalise 0 to the called app's ID: that would move it.
- A box with an app ID follows the Algorand SDK's rule: the first matching
  entry in the list, and index 0 when the ID is the called app's and the list
  doesn't have it.

Any later merge rule between ABI-derived and user-supplied references belongs
in the engine too, and has to keep the caller's entries where they were put.

### Signer Approval Descriptions

`apsigner` describes application calls during approval.

The signer renders:
- app ID
- sender
- on-completion label
- formatted app arguments
- foreign accounts, apps, and assets
- box references

This does not make the signer ABI-aware in a general sense. It makes app calls
reviewable at the approval boundary by improving raw transaction visibility.

### Testing Strategy

App interaction uses a repo-owned integration fixture rather than relying
only on third-party contracts.

#### Test fixture

The fixture app in `test/fixtures/testapp/` is small and focused.
It supports:
- global state mutation
- local state
- box writes and reads
- grouped companion-payment deposit flow

#### Integration harness

The harness in `test/integration/harness/testapp.go` deploys and seeds the test
app directly for integration tests.

#### Coverage

The integration suite exercises:
- app deploy and created-app lookup
- app info reads
- app reads
- raw app calls
- ABI-backed app calls
- grouped payment + app call execution
- grouped simulation
- JS API bindings

This gives app interaction a stable in-repo validation environment instead of
depending on protocol-specific external fixtures.

### Relationship to Transaction Flow

App interaction does not replace the transaction flow documented in
`ARCH_SIGNING.md`. It extends the preparation side of that flow.

The engine produces richer prepared transactions and prepared groups, but
authorization and submission go through the signer pipeline.

This is an important architectural constraint:
- app interaction is additive
- signer providers are unchanged
- grouped execution reuses the canonicalization and submission path

## MCP Surface

MCP mode (`apshell --mcp`) exposes apshell as an MCP server over stdio,
allowing LLM clients to drive shell commands and JavaScript
programmatically. It shares the same parsing layer, `apshellapp` workflows,
and result-bearing execution as the REPL (see [REPL Surface](#repl-surface))
but produces structured JSON instead of terminal text.

```
+----------+  JSON-RPC/stdio  +------------------+  SSH tunnel  +-----------+
|   LLM    | <--------------> |  apshell --mcp   | <----------> |  apsigner |
|  client  |                  |  (8 MCP tools)   |              |  (signer) |
+----------+                  +------------------+              +-----------+
```

### Tool Surface

**Compatibility-bearing.** The tool names, parameters, and response shapes in
this section, including the [`js`](#js-tool), [`doc`](#doc-tool),
[`jssave`](#jssave-tool), and [`jslist`](#jslist-tool) subsections, are the MCP
tool contract that [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md) indexes. MCP clients
and LLM prompts depend on them; change them only as a deliberate contract
change.

The MCP server registers eight tools:

| Tool | Parameters | Purpose |
|------|-----------|---------|
| `execute` | `command` (string) | Run a shell command (built-in or plugin) |
| `mcp_reference` | none | Live command reference generated from the registry, including plugin commands |
| `js` | `code` (string) | Execute JavaScript in the Goja runtime, returns `{value, output}` |
| `js_reference` | none | Embedded `USER_JSAPI.md` reference text (stateless) |
| `mcp_manual` | none | Embedded `USER_MCP_MANUAL.md` operating manual (stateless) |
| `doc` | `name` (string, optional) | List or return a bundled curated reference doc (embedded, with `<dataDir>/docs` overlay) |
| `jssave` | `path` (string), `code` (string, optional), `last` (bool, optional), `overwrite` (bool, optional) | Save JavaScript by filename into `scripts/` (or absolute path) |
| `jslist` | none | List saved scripts as `[{name, size, mtime}, ...]` |

The `jssave` and `jslist` handlers share `saveJSScript` and `listJSScripts`
with the REPL counterparts, and the `js` handler uses the MCP-only
`captureJSExecution`. All three produce structured JSON directly without going
through the shell parser. The REPL `js` command accepts a `-help` flag that prints the JS
API reference; MCP clients fetch the same reference via `js_reference`.

LLMs pull command and API references on demand via `mcp_reference` and
`js_reference`, the operating manual via `mcp_manual`, and the deep reference
docs via `doc`, rather than having them injected periodically.

#### `js` tool

Executes JavaScript in the Goja runtime.

Response shape:

```json
{"value": <return-value>, "output": "<print-output>"}
```

- `value`: the JSON-serialized return value of the last expression (omitted if `undefined`/`null`)
- `output`: captured `print()` output (omitted if empty)

Errors are returned as MCP error results. If `print()` output was produced before the error, it is prepended to the error message.

The `code` argument is required.

#### `doc` tool

Lists or fetches bundled curated reference docs. With no `name`, it returns the
curated bundled doc index. With `name`, it returns the matching bundled
Markdown doc; names may be supplied with or without `.md`.

#### `jssave` tool

Saves JavaScript code to a file for later execution via `js <file.js>`.

- `path` is required
- `code` is required unless `last=true`
- if `path` contains no `/`, it is saved under the data directory's `scripts/` folder
- otherwise, `path` must be absolute, so `/` must be the first character
- `.js` is appended if missing
- existing files are rejected unless `overwrite=true`

Returns `{"path": "<absolute path>"}` on success.

#### `jslist` tool

Returns saved JavaScript scripts in the data directory's `scripts/` folder.

No parameters. Response shape:

```json
[{"name": "<filename>", "size": <bytes>, "mtime": <unix seconds>}, ...]
```

Entries are sorted by name. Returns an empty array if the directory does not exist or contains no `.js` files.

### Configuration

The installer writes `$APCLIENT_DATA/.mcp.json` and
`$APCLIENT_DATA/.codex/config.toml` for the installed `apshell` binary and data
directory. `.mcp.json` supports MCP clients that read Claude-style JSON
configuration:

```json
{
  "mcpServers": {
    "my_aplane": {
      "command": "/path/to/my_aplane/bin/apshell",
      "args": ["--mcp", "-d", "/path/to/my_aplane/apclient"]
    },
    "my_aplane_2": {
      "command": "/path/to/my_aplane_2/bin/apshell",
      "args": ["--mcp", "-d", "/path/to/my_aplane_2/apclient"]
    }
  }
}
```

Codex reads project-scoped MCP configuration from `.codex/config.toml` when the
client data directory is opened as a trusted Codex project:

```toml
[mcp_servers.my_aplane]
command = "/path/to/my_aplane/bin/apshell"
args = ["--mcp", "-d", "/path/to/my_aplane/apclient"]
```

Each server instance uses its own data directory (`-d` flag), which determines
the config, caches, SSH identity, plugin catalog, and plugin activation config.

### Startup Sequence

1. Run the shared `clientenroll.LoadEnrolledClient` preflight: a default signer endpoint and a trusted signer host in the endpoint `known_hosts_path` are required, with MCP-specific hints. Whether the client's key is enrolled is known only to the signer, so an unenrolled key fails the startup connection instead. Failure exits non-zero before any other startup work.
2. Create `REPLState` with initialized runtime state and app facade.
3. Set `AutoConfirm: true` (non-interactive) and redirect REPL/app output to `os.Stderr`.
4. Save the real stdout for MCP transport, then redirect `os.Stdout` to `os.Stderr` so stray prints do not corrupt the JSON-RPC stream.
5. Initialize the command registry and the plugin runtime (`initPluginRuntime`).
6. Require an operational startup signer connection (`attemptStartupConnection`); MCP exits if the connection cannot be established.
7. Build the `execute` tool description (base reference plus discovered plugin `mcp.md` files).
8. Register the eight tools and serve over stdio using the saved real stdout.

### `execute` Routing

MCP and the REPL use the same parser, canonical registry lookup, handler, and
already-computed command result:

```
Command received
    |
    v
+------------------+
| Resolve built-in |-------> Aliases inherit their primary command policy
+--------+---------+
         |
         v
+------------------+
| Blocked?         |--yes--> Error before handler invocation
+--------+---------+
         | no
         v
+------------------+
| Execute once     |-------> command.Result
+--------+---------+
         |
         v
+------------------+
| MarshalMachine   |-------> JSON bytes in MCP text-content envelope
+------------------+
```

Every automation-enabled built-in and external plugin command returns a
`command.Result`. The REPL calls `RenderText`; MCP calls `MarshalMachine`.
Machine projections are explicit allowlists and never reconstruct results by
capturing terminal output. A structured success with nil, empty, or invalid
JSON is rejected.

Machine projections are allowlists. They omit secrets, authorization headers,
credential paths, raw config, signed transaction bytes not deliberately in the
contract, terminal-only render lines, and the plugin-reserved `localSigners`
data field.

JSON results are returned as text containing JSON bytes via `mcp.NewToolResultText(string(data))`, not as typed JSON content objects.

#### Blocked Commands

| Command | Reason |
|---------|--------|
| `js` | Use the `js` MCP tool instead |
| `jssave` | Use the `jssave` MCP tool instead |
| `jslist` | Use the `jslist` MCP tool instead |
| `help`, `h` | Use `mcp_reference` instead |
| `config` | Use the safe `status` command instead |
| `script` | Issue commands individually or use `js` |
| `enroll` | Client enrollment needs interactive host trust; run it in a real apshell |
| `cosigner` | `cosigner status` and the forwarding alias `cosigner add` are unavailable through MCP; use apshell directly (guided setup is now `endpoints add`) |
| `endpoints add` | Guided cosigner endpoint setup needs interactive host trust and an operator approval wait; other `endpoints` subcommands remain structured |
| `clear`, `cls` | Terminal clearing has no machine meaning |
| `quit`, `exit`, `q` | Use MCP disconnect instead |
| `keyreg` (no args) | Paste mode requires interactive input |

Policies are attached to primary registry commands after alias resolution, so
aliases cannot bypass a block. Explicit `keyreg` arguments and non-`add`
`endpoints` subcommands remain structured.

### stdout/stderr Separation

MCP uses stdout exclusively for JSON-RPC transport. All other output goes to
stderr:

```go
mcpStdout := os.Stdout    // Save real stdout for MCP
os.Stdout = os.Stderr     // Redirect process stdout to stderr
state.SetOutput(os.Stderr) // REPL/app output goes to stderr
```

This prevents stray `fmt.Printf` calls from corrupting the MCP transport.

### Plugin Behavior

#### success:false Handling

Plugin commands that return `success: false` (e.g., usage messages, validation
errors) are returned as normal MCP tool results with the full JSON payload,
not as MCP transport errors. This matches the REPL contract where these are
informational messages, not hard failures.

#### Plugin Documentation (mcp.md)

Plugins can include an `mcp.md` file in their directory to provide
LLM-specific instructions. At startup, the MCP server discovers plugins and
appends any `mcp.md` content to the `execute` tool description.

```
plugins.available/my-plugin/
|-- manifest.json
|-- my-plugin
|-- mcp.md            <-- Auto-loaded into MCP tool description
`-- checksums.sha256
```

The `mcp.md` should describe commands, parameters, return data shapes, and
usage notes that help the LLM use the plugin correctly. Example:

```markdown
# My Plugin

- `my-plugin action <account>` — Example command description

Document commands, parameters, return data shapes, and usage notes that help
the LLM use the plugin correctly.
```

### Concurrency

A mutex protects `REPLState` during command execution since MCP calls may
overlap:

```go
mu.Lock()
defer mu.Unlock()
```

## Client Output and Logging

Client programs produce four kinds of output, and each has one owner:

| Class | What it is | Path |
|---|---|---|
| Result | The answer to a command, or something the user must keep | Typed application result, rendered by the host (`r.Out`, `command.Result`) |
| Prompt | Asks for a decision or input | The line reader, or the host's approval handler |
| Progress | Status that matters while an operation runs | `ProgressLine`, `SignerProgressOut`, or a host callback |
| Log | Operational diagnostics | `log/slog`, through the handler the host installs |

If a command's answer would be incomplete without a message, it is a result, and
no log level may hide it.

### Logging Pipeline

Packages call `log/slog` and import nothing of ours, so a shared package doesn't
need to know whether it runs under a terminal, a TUI, or an MCP host. Each host
calls `clientlog.Install` once, before it builds anything that can log.

A source gets its logger at call time:

```go
func logger() *slog.Logger { return slog.With("component", "cache") }
```

A package variable built with `slog.With` would bind the default handler during
package initialization, before the host installs one, and bypass the pipeline.

The handler renders one readable line, keeping every attribute and escaping the
whole line, since names, values, and errors can all carry outside text:

```text
[cache] warning: failed to save auth cache error="disk full"
[plugin mithras stderr] cannot find module foo
```

A plugin's output has `component=plugin` and its name in a separate attribute,
because a plugin chooses its name and could otherwise pass as `cache`.

| Level | Meaning | Examples |
|---|---|---|
| `error` | A failure nothing else reports | Recovered keepalive panic |
| `warn` | The operator should know or act | Cache tampering, connection loss, key revocation, skipped plugin, failed plugin's last lines |
| `info` | Routine detail | Plugin stderr, sandbox line, host key saved |
| `debug` | Detail for diagnosing the client | Cache hits, forwarded-connection errors, response-close errors |

The default level is `warn`, except that `--mcp` starts at `info`, because its
stderr is the host's log rather than a display. `APSHELL_DEBUG` starts any mode at
`debug`, and `loglevel` changes the level at runtime. Text that reaches the
standard `log` package has no level, so the host assigns it `warn` rather than
hide it.

| Host | Where logs go |
|---|---|
| `apshell` REPL | stderr, through readline while it runs so the prompt is redrawn |
| `apshell --script`, `--mcp`, `apapprover`, `apadmin` batch modes | stderr |
| apconsole | `clientlog.Deferred`, pulled into the shell pane; written out on exit if the node has no shell |
| `apadmin` TUI | `clientlog.Deferred`, written out on exit; lost notifications are shown live |
| `appolicy`, `aplocalnet`, `applugin-checksum` | No handler, because they can't log (see [Enforcement](#enforcement)) |
| `apstore`, `apsigner` | Outside this contract |

An admin TUI shows lost notifications as a count in its status bar, independently
of any log level, so that one condition doesn't depend on log delivery. Any other
diagnostic a pane-less TUI must show live needs its own decision about how.

### Deferred Delivery

While a TUI owns the terminal, nothing may write to it directly, and a log call
can come from the TUI's own update loop, so a writer can't wait for the display.
`clientlog.Deferred` is a bounded queue the TUI pulls from with a blocking
`tea.Cmd`. It holds records from before the TUI exists, so warnings raised during
startup still reach the pane.

- Records leave in submission order. Severity only affects eviction: when the
  queue is full, ordinary records go first, so lower-level traffic can't evict a
  warning. Warning traffic can, and a marker reports it. The queue promises order
  and accounting, not that nothing is lost.
- A batch stays held until `Update` has stored it and acknowledged it, so a batch
  the TUI never received is still there when it stops.
- `Flush` waits for what was submitted before the call, so a command's own
  diagnostics appear above its result. A dropped record counts once its marker is
  delivered.
- `Close` runs as soon as the TUI stops, before anything that can exit. It writes
  everything unacknowledged, and later records go straight to stderr.

### What This Doesn't Promise

A bounded queue can lose warnings under warning overflow, though it reports that.
Synchronous stderr can block or fail. An acknowledgment means the TUI stored a
line, not that anyone read it. With `info` on, a failed plugin's lines are
best-effort: another source can evict them from a TUI's queue.

### What Stays Outside the Pipeline

- The key-scan warning in `internal/keys` is shared with the signer and writes to
  stderr itself. Client hosts never reach it.
- A program's reason for stopping, such as apconsole's `logErrorf`, stays a direct
  write, because it must not depend on a log level.
- `apapprover` uses `cmdlog` for its interface. Only its diagnostics are logs.
- `apadmin` prints its startup warnings before the TUI opens. They describe optional
  capabilities, and using one reports its own error, so they need no live display.
- Terminal output from `internal/apshellcli` belongs to the host, not to a source.

### Enforcement

`test/arch/client_logging_test.go` keeps client packages from writing diagnostics
directly, keeps packages from retaining the default logger during initialization,
and limits process logging setup to `cmd/*`. It also rejects `slog.NewLogLogger` and
direct handler calls, and requires every binary that links a logging source to
install a handler or be listed with a reason. Its exceptions are result and progress
fallbacks, and the list shrinks as those writers become required.

`make logging-reach-check` proves a binary with no handler can't log. It analyzes
each binary as built for production and requires `Logger.log` and `Logger.logAttrs`
to be listed as unreachable, so a call that becomes reachable fails it even if no
dependency changed, and so does a Go release that renames them. It applies to the
platform it runs on and to ordinary logging only, which is why the test above
rejects the other routes.

`analysis/keylog` checks structured logging arguments by name. That is not secret
detection: it can't see a secret inside a struct. Plugin stderr can hold anything a
plugin prints, so it is kept off disk, and failure replay is a deliberate exception
to its usual filtering.

## Key Files

Engine files are listed in [File Organization](#file-organization) and app
interaction packages in [Main packages](#main-packages).

| File | Purpose |
|------|---------|
| `internal/apshellcli/state.go` | `REPLState` definition |
| `internal/apshellcli/commands.go` | Command dispatch |
| `internal/apshellcli/command_result.go` | Shared command-result implementation |
| `internal/apshellcli/command_projections.go` | Safe machine projection types |
| `internal/apshellcli/mcp.go` | MCP server, policy enforcement, tool description, plugin doc loading |
| `internal/apshellcli/render.go` | Human presentation helpers |
| `internal/apshellcli/external_plugins.go` | Plugin execution and `PluginResult` construction |
| `internal/shellrepl/command.go` | Top-level tokenization (`ParseCommand`) |
| `internal/shellrepl/parser.go` | Per-command parsers |
| `internal/shellrepl/autocomplete.go` | Tab completion |
| `internal/cmdspec/` | Shared parsing helpers (`key=value`, bytes, addresses, asset refs) |
| `internal/apshellapp/` | Shell command semantics and runtime facade |
| `internal/appresult/` | Shared structured result types |
| `internal/command/help.go` | Help rendering (writes to `io.Writer`) |
| `internal/addressbook/resolver.go` | Address resolution (aliases, sets, `@signers`, `@all`) |

## Related Documentation

- [ARCH_OVERVIEW.md](ARCH_OVERVIEW.md) - Overall system architecture
- [ARCH_CRYPTO.md](ARCH_CRYPTO.md) - Cryptography layer (signing, key generation)
- [ARCH_SIGNING.md](ARCH_SIGNING.md) - Transaction signing flow
- [ARCH_PLUGINS.md](ARCH_PLUGINS.md) - Plugin manifests, `mcp.md`, and lifecycle
- [ARCH_ADMIN.md](ARCH_ADMIN.md#signer-admin-tui) - Signer admin TUI (separate admin-protocol client)
- [USER_CONFIG.md](USER_CONFIG.md) - Configuration reference
- [USER_JSAPI.md](USER_JSAPI.md) - JavaScript API reference exposed via `js_reference`
- [USER_MCP_MANUAL.md](USER_MCP_MANUAL.md) - Condensed operating manual exposed via `mcp_manual`
