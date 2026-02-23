# UI Layer Architecture

> **Version**: 0.38+
> **Status**: Implementation documentation

## Overview

The aPlane Shell suite supports multiple user interface modes that share a common Engine layer for business logic. This document describes the UI layer architecture, responsibilities, and integration patterns.

## Architecture Principle

**Separation of Concerns**: The UI layer handles user interaction while the Engine layer handles business logic. This separation enables:

- Multiple interface modes (REPL, TUI, CLI)
- Consistent behavior across all modes
- Independent testing of each layer
- Easy addition of new interface types

## Layer Diagram

```
+-----------------------------------------------------------------------------+
|                              UI Layer                                        |
|                                                                             |
|   +--------------+    +--------------+    +--------------+                  |
|   | CLI One-Shot |    | REPL (Shell) |    | TUI (Bubble) |                  |
|   |              |    |              |    |              |                  |
|   | - Args parse |    | - Readline   |    | - Screen     |                  |
|   | - Exit codes |    | - Tab compl  |    | - Key events |                  |
|   | - Stdout     |    | - History    |    | - IPC conn   |                  |
|   | - Stateless  |    | - Colored    |    | - State mach |                  |
|   +------+-------+    +------+-------+    +------+-------+                  |
|          |                   |                   |                          |
|          |    +--------------+--------------+    |                          |
|          |    |      Command Parsing Layer   |    |                          |
|          |    |      internal/repl/parser.go |    |                          |
|          |    |                              |    |                          |
|          |    |  ParseSendCommand(args)      |    |                          |
|          |    |  ParseOptinCommand(args)     |    |                          |
|          |    |  ParseOptoutCommand(args)    |    |                          |
|          |    |  ParseCloseCommand(args)     |    |                          |
|          |    |  ParseRekeyCommand(args)     |    |                          |
|          |    |  ParseSweepCommand(args)     |    |                          |
|          |    |  ParseTakeCommand(args)      |    |                          |
|          |    +--------------+---------------+    |                          |
|          |                   |                    |                          |
|          |    +--------------+--------------+     |                          |
|          |    |       Resolution Layer       |     |                          |
|          |    |    internal/util/resolver.go |     |                          |
|          |    |                              |     |                          |
|          |    |  "alice" -> "ABC123..."      |     |                          |
|          |    |  "@team" -> ["A", "B", "C"]  |     |                          |
|          |    |  "1.5" ALGO -> 1500000       |     |                          |
|          |    |  "USDC" -> 31566704          |     |                          |
|          |    +--------------+---------------+     |                          |
+--------------------------+-----------------------------------------------+
                           |
                 +---------v---------+
                 |                   |
                 |  internal/engine  |
                 |  (Business Logic) |
                 |                   |
                 +-------------------+
```

## UI Layer Responsibilities

### 1. Input Handling

| Mode | Input Method | Example |
|------|--------------|---------|
| CLI | Command-line args | `apshell send 1 algo from alice to bob` |
| REPL | Readline with history | `send 1 algo from alice to bob` |
| TUI | Key events, forms | Navigate with arrows, Enter to submit |

### 2. Output Formatting

| Mode | Output Style |
|------|--------------|
| CLI | Plain text, exit codes for scripting |
| REPL | Colored terminal output |
| TUI | Rendered screen with layouts and borders |

### 3. Name Resolution

Before calling Engine methods, the UI layer resolves:

```go
// Alias resolution
"alice" -> "ABC123DEF456..." (58-char address)

// Set expansion
"@validators" -> ["ADDR1...", "ADDR2...", "ADDR3..."]

// Amount conversion
"1.5" ALGO -> 1500000 (microAlgos)
"100" USDC -> 100000000 (base units with 6 decimals)

// Asset resolution
"USDC" -> 31566704 (mainnet ASA ID)
```

### 4. State Management

| Mode | State Model |
|------|-------------|
| CLI | Stateless - each invocation is independent |
| REPL | Session state - maintains caches, connection, history |
| TUI | Application state - managed by bubbletea model |

## Command Parsing (internal/repl/)

The `internal/repl/` package provides command parsing that returns structured parameter types.

### Parser Functions

```go
// Parse "send 1 algo from alice to bob nowait fee=1000"
params, err := ParseSendCommand(args)

// Parse "optin usdc for alice"
params, err := ParseOptinCommand(args)

// Parse "optout usdc from alice to bob"
params, err := ParseOptoutCommand(args)

// Parse "close alice to bob"
params, err := ParseCloseCommand(args)

// Parse "rekey alice to bob" or "unrekey alice"
params, err := ParseRekeyCommand(args, isUnrekey)

// Parse "sweep algo from [alice bob] to treasury leaving 1.5"
params, err := ParseSweepCommand(args)

// Parse "keyreg alice online votekey=... selkey=... sproofkey=..."
params, err := ParseTakeCommand(args)
```

### Parameter Types

```go
// TransactionParams from ParseSendCommand
type TransactionParams struct {
    Amount     string   // Raw amount string (e.g., "1.5")
    Asset      string   // "algo" or ASA reference
    FromRaw    []string // Unresolved senders (aliases, sets, addresses)
    ToRaw      []string // Unresolved receivers
    Note       string
    Atomic     bool     // Use atomic group
    Wait       bool     // Wait for confirmation
    Fee        uint64
    UseFlatFee bool
}

// OptInParams from ParseOptinCommand
type OptInParams struct {
    ASARef     string // "usdc" or asset ID
    From       string // Alias or address
    Wait       bool
    Fee        uint64
    UseFlatFee bool
}

// OptOutParams from ParseOptoutCommand
type OptOutParams struct {
    ASARef     string // "usdc" or asset ID
    Account    string // Account to opt out
    CloseTo    string // Where to send remaining balance (optional)
    Wait       bool
    Fee        uint64
    UseFlatFee bool
}

// CloseParams from ParseCloseCommand
type CloseParams struct {
    Account    string // Account to close
    CloseTo    string // Where to send remaining balance
    Wait       bool
    Fee        uint64
    UseFlatFee bool
}

// RekeyParams from ParseRekeyCommand
type RekeyParams struct {
    Account    string // Account to rekey
    Signer     string // New auth address (self for unrekey)
    Wait       bool
    Fee        uint64
    UseFlatFee bool
}

// SweepParams from ParseSweepCommand
type SweepParams struct {
    Asset      string
    FromRaw    []string // nil = all signable accounts
    ToRaw      string
    Leaving    string   // Amount to leave (default "0")
    Wait       bool
    Fee        uint64
    UseFlatFee bool
}

// KeyRegParams from ParseTakeCommand
type KeyRegParams struct {
    From              string
    Mode              string // "online" or "offline"
    Online            bool
    VoteKey           string
    SelKey            string
    SProofKey         string
    VoteFirst         uint64
    VoteLast          uint64
    KeyDilution       uint64
    IncentiveEligible bool
    Wait              bool
}
```

## Address Resolution (internal/util/)

The `AddressResolver` handles conversion from user-friendly names to addresses:

```go
resolver := util.NewAddressResolver(&aliasCache, &setCache)

// Resolve single address or alias
addr, err := resolver.ResolveSingle("alice")     // Returns "ABC123..."
addr, err := resolver.ResolveSingle("ABC123...") // Pass-through

// Resolve potentially multiple addresses (alias, set, or address)
addrs, err := resolver.ResolveList([]string{"alice", "@team", "XYZ789..."})
// Returns ["ABC123...", "DEF456...", "GHI789...", "XYZ789..."]

// Expand set reference
addrs, err := resolver.ExpandSet("@validators")
// Returns ["ADDR1...", "ADDR2...", "ADDR3..."]
```

## REPL Session State (cmd/apshell/state.go)

The REPL wraps the Engine and adds UI-specific state:

```go
// REPLState holds the global state for the REPL.
// It wraps an Engine (the single source of truth for business logic state)
// and adds UI-specific state that doesn't belong in the Engine.
type REPLState struct {
    // Core Engine (single source of truth for business logic state)
    // Access caches, network, clients via: r.Engine.Network, r.Engine.AliasCache, etc.
    Engine *engine.Engine

    // UI-specific state (not shared with Engine)
    CommandRegistry *command.Registry // Command registry for plugin-ready command system
    PluginManager   *manager.Manager  // External plugin manager
}

// NewREPLState creates a new REPLState with an initialized Engine.
func NewREPLState(network string) (*REPLState, error)
```

**Key Design**: All shared state (caches, network, clients) is accessed via `r.Engine.X`. This eliminates duplicate state and manual synchronization.

## REPL Command Handler Pattern

Each REPL command follows this pattern:

```go
func (r *REPLState) cmdSend(args []string, _ interface{}) error {
    // 1. PARSE: Convert args to structured params
    params, err := repl.ParseSendCommand(args)
    if err != nil {
        return err
    }

    // 2. RESOLVE: Convert names to addresses
    resolver := util.NewAddressResolver(&r.Engine.AliasCache, &r.Engine.SetCache)
    fromAddrs, err := resolver.ResolveList(params.FromRaw)
    if err != nil {
        return err
    }

    // 3. CONVERT: Amounts to base units
    amountMicro, err := convertToMicroAlgos(params.Amount)
    if err != nil {
        return err
    }

    // 4. VALIDATE: Check preconditions
    if len(fromAddrs) == 0 {
        return fmt.Errorf("no sender addresses")
    }

    // 5. ENGINE: Call business logic with resolved values
    prep, balanceCheck, err := r.Engine.PreparePayment(engine.SendPaymentParams{
        From:       fromAddrs[0],
        To:         toAddrs[0],
        Amount:     amountMicro,
        Note:       params.Note,
        Fee:        params.Fee,
        UseFlatFee: params.UseFlatFee,
    })
    if err != nil {
        return err
    }

    // 6. DISPLAY: Show warnings/confirmations (UI responsibility)
    if !balanceCheck.SufficientFunds {
        fmt.Printf("Warning: Insufficient funds\n")
    }

    // 7. SUBMIT: Execute the operation
    result, err := r.Engine.SignAndSubmit(prep, params.Wait)
    if err != nil {
        return err
    }

    // 8. OUTPUT: Format result for display (UI responsibility)
    fmt.Printf("Transaction %s submitted\n", result.TxID)

    return nil
}
```

## TUI Architecture (internal/tui/)

The TUI uses bubbletea for apadmin and communicates with Signer via IPC (Unix socket).

### File Structure

```
internal/tui/
├── model.go            # Model struct, ViewState enum, initialization
├── messages.go         # Message types for async operations
├── ipc_client.go       # IPC connection to Signer
│
├── update.go           # Main Update() dispatcher
├── update_auth.go      # Unlock/authentication event handlers
├── update_keylist.go   # Key list navigation and actions
├── update_signing.go   # Signing request approval flow
├── update_forms.go     # Generate/import/export/delete forms
│
├── view.go             # Main View() dispatcher
├── view_helpers.go     # Shared rendering utilities (borders, colors)
├── view_auth.go        # Unlock screen rendering
├── view_keylist.go     # Key list and status bar rendering
├── view_signing.go     # Signing popup rendering
└── view_forms.go       # Form rendering (generate, import, export, delete)
```

**Design Principle**: View and Update logic are split by domain (auth, keylist, signing, forms) to keep each file focused and under ~200 lines.

### View States

```go
type ViewState int

const (
    ViewUnlock ViewState = iota      // Passphrase entry
    ViewKeyList                       // Main key list view
    ViewSigningPopup                  // Signing request popup
    ViewGenerateForm                  // Key generation form
    ViewImportForm                    // Mnemonic import form
    ViewExportConfirm                 // Confirm address before export
    ViewExportDisplay                 // Shows exported mnemonic
    ViewDeleteConfirm                 // Delete confirmation dialog
    ViewError                         // Error display
)
```

### TUI Model

```go
type Model struct {
    // Current view state
    viewState ViewState

    // Connection state
    connectionState ConnectionState
    ipcPath         string

    // Signer state
    signerLocked bool
    keyCount    int

    // Key list
    keys         []KeyInfo
    selectedKey  int

    // Passphrase input
    passphraseInput  string
    passphraseMasked bool
    passphraseError  string

    // Pending signing request
    pendingSign      *PendingSignRequest
    pendingSignFocus int // 0 = approve, 1 = reject

    // Form states (generate, import, export, delete)
    // ... various form fields

    // Screen dimensions
    width  int
    height int
}
```

### Message Types

```go
// Async operation results
type ConnectedMsg struct{}
type DisconnectedMsg struct{ Error error }
type SignerStatusMsg struct{ Locked bool; KeyCount int }
type UnlockResultMsg struct{ Success bool; KeyCount int; Error string }
type SignRequestReceivedMsg struct{ Request PendingSignRequest }
type KeysListMsg struct{ Keys []KeyInfo }
type GenerateResultMsg struct{ Success bool; Address, KeyType, Error string }
type DeleteResultMsg struct{ Success bool; Error string }
type ExportResultMsg struct{ Success bool; Address, KeyType, Mnemonic string; WordCount int; Error string }
type ImportResultMsg struct{ Success bool; Address, KeyType, Error string }
```

## Tab Completion (internal/repl/autocomplete.go)

The REPL provides context-aware tab completion:

```go
// Completer provides tab completion for commands
func (r *REPLState) Complete(line string, pos int) ([]string, int) {
    // Complete command names
    if !strings.Contains(line, " ") {
        return r.completeCommands(line)
    }

    // Complete arguments based on command context
    parts := strings.Fields(line)
    switch parts[0] {
    case "send":
        return r.completeSendArgs(parts, pos)
    case "alias":
        return r.completeAliasArgs(parts, pos)
    case "balances":
        return r.completeAddressArgs(parts, pos)
    }
    return nil, pos
}
```

## Error Handling

Each UI mode handles errors appropriately:

| Mode | Error Handling |
|------|----------------|
| CLI | Print to stderr, exit with non-zero code |
| REPL | Print error message, continue loop |
| TUI | Display error in status area, allow retry |

```go
// REPL error handling
func (r *REPLState) executeCommand(cmd string, args []string) {
    err := r.dispatch(cmd, args)
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        // Continue REPL loop
    }
}

// CLI error handling
func main() {
    err := runCommand(os.Args[1:])
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error: %v\n", err)
        os.Exit(1)
    }
}
```

## Command Registry and Plugins

The REPL uses a command registry that supports both built-in and external plugins:

```go
// REPLState has a command registry
type REPLState struct {
    Engine          *engine.Engine
    CommandRegistry *command.Registry
    PluginManager   *manager.Manager
}

// Commands are registered with the registry
registry.Register(&command.Command{
    Name:        "send",
    Description: "Send ALGO or ASA",
    Execute:     r.cmdSend,
})

// External plugins are loaded via PluginManager
// See ARCH_PLUGINS.md for details
```

## Related Documentation

- [ARCH_OVERVIEW.md](ARCH_OVERVIEW.md) - Overall system architecture
- [ARCH_ENGINE.md](ARCH_ENGINE.md) - Engine layer architecture
- [ARCH_CRYPTO.md](ARCH_CRYPTO.md) - Provider layer architecture
- [ARCH_PLUGINS.md](ARCH_PLUGINS.md) - Plugin system (core and external)
- [CONFIG.md](CONFIG.md) - Configuration reference
