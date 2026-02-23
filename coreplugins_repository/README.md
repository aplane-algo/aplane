# aPlane Shell Plugins

This directory contains statically-compiled plugins that extend apshell functionality.

## Overview

aPlane Shell uses **static compilation** for plugins:

- ✅ **Security** - All plugins reviewed at compile time, no runtime code loading
- ✅ **Distribution** - Single binary, no version/dependency conflicts
- ✅ **Deterministic** - Plugins explicitly imported, can't accidentally load malicious code
- ✅ **Cross-platform** - Works everywhere Go works

Plugins are written as separate Go packages in this directory and registered via `init()` functions.

## Plugin Architecture

Plugins are Go packages that register themselves at compile time via `init()` functions:

```go
package myplugin

import "apshell/internal/command"

func init() {
    command.RegisterStaticPlugin(&command.Command{
        Name:        "mycommand",
        Description: "...",
        Usage:       "mycommand <args>",
        Category:    command.CategoryTransaction,
        Handler:     &MyHandler{},
    })
}

type MyHandler struct{}

func (h *MyHandler) Execute(args []string, ctx *command.Context) error {
    // Access REPLState via ctx.Internal.REPLState using reflection
    // ...
}
```

**Advantages:**
- ✅ Direct access to REPLState (algod client, caches, signing infrastructure)
- ✅ Full type safety with Go at compile time
- ✅ Can reuse internal packages (transaction, util, algo, etc.)
- ✅ No serialization overhead
- ✅ Single binary distribution
- ✅ No version/dependency conflicts
- ✅ Explicit security model (code review at compile time)

**Trade-offs:**
- ⚠️ Must recompile apshell to add/remove plugins (explicit = secure)
- ⚠️ Uses reflection to access REPLState (no compile-time field safety)
- ℹ️ Can only be written in Go (appropriate for this use case)

## Available Plugins

### selfping

A sample plugin that demonstrates:
- Building and sending Algorand transactions
- Working with both Falcon-1024 and Ed25519 keys
- Using Signer for remote signing
- Waiting for transaction confirmation

See [`selfping/README.md`](selfping/README.md) for details.

## Creating a New Plugin

### 1. Create Plugin Directory

```bash
mkdir plugins/myplugin
cd plugins/myplugin
```

### 2. Create Plugin Code

Create `myplugin.go`:

```go
package myplugin

import (
    "fmt"
    "reflect"
    "apshell/internal/command"
    // Import other packages as needed
)

// Register plugin at compile time
func init() {
    command.RegisterStaticPlugin(&command.Command{
        Name:        "myplugin",
        Description: "My custom command",
        Usage:       "myplugin <args>",
        Category:    command.CategoryOrchestration,
        Handler:     &Handler{},
    })
}

// Handler implements command.Handler interface
type Handler struct{}

func (h *Handler) Execute(args []string, ctx *command.Context) error {
    // Access REPLState via Context.Internal
    // Use reflection to access fields (avoids import cycle issues)
    v := reflect.ValueOf(ctx.Internal.REPLState).Elem()

    // Extract needed fields
    network := v.FieldByName("Network").String()
    algodClient := v.FieldByName("AlgodClient").Interface().(*algod.Client)

    // Your implementation here
    fmt.Printf("My plugin running on %s!\n", network)

    return nil
}
```

### 3. Import Plugin in main.go

Edit `cmd/apshell/main.go` to import your plugin:

```go
import (
    // ... existing imports

    // Static plugins (explicitly imported for security)
    _ "apshell/plugins/selfping"
    _ "apshell/plugins/myplugin"  // ADD THIS LINE
)
```

**Important:** The blank import `_` triggers the plugin's `init()` function, registering it automatically.

### 4. Build apshell

```bash
cd /path/to/apshell
go build -o apshell ./cmd/apshell
```

### 5. Test Plugin

Your command is now part of the apshell binary:

```
$ ./apshell
testnet> help
...
Orchestration:
  myplugin         My custom command
...

testnet> myplugin
My plugin running on testnet!
```

## Available REPLState Fields

Plugins access REPLState via `ctx.Internal.REPLState` using reflection:

```go
// In your Execute method:
v := reflect.ValueOf(ctx.Internal.REPLState).Elem()

// Available fields:
network := v.FieldByName("Network").String()                                              // "mainnet", "testnet", "betanet"
algodClient := v.FieldByName("AlgodClient").Interface().(*algod.Client)                   // Algorand node client
asaCache := v.FieldByName("AsaCache").Interface().(util.ASACache)                         // ASA metadata cache
aliasCache := v.FieldByName("AliasCache").Interface().(util.AliasCache)                   // Address aliases
lsigCache := v.FieldByName("LsigCache").Interface().(util.LSigCache)                      // Falcon LogicSig cache
signerCache := v.FieldByName("SignerCache").Interface().(util.SignerCache)                // Available signing keys
authCache := v.FieldByName("AuthCache").Interface().(util.AuthAddressCache)               // Rekeyed auth addresses
algoSignerClient := v.FieldByName("SignerClient").Interface().(*util.SignerClient) // Remote signing service
writeMode := v.FieldByName("WriteMode").Bool()                                            // Transaction write mode
variables := v.FieldByName("Variables").Interface().(map[string]string)                   // User variables
registry := v.FieldByName("CommandRegistry").Interface().(*command.Registry)              // Command registry
```

**Why Reflection?** Go plugins cannot type-assert to structs in `package main`. Reflection accesses fields by name at runtime, avoiding import cycles and type mismatches.

## Useful Internal Packages

- `apshell/internal/algo` - Algorand client helpers, account operations
- `apshell/internal/util` - Caches, key management, encryption
- `apshell/internal/command` - Command infrastructure
- `apshell/internal/repl` - REPL helpers

## Command Categories

Use these constants for your command's `Category` field:

- `command.CategorySetup` - Setup commands
- `command.CategoryTransaction` - Transaction commands
- `command.CategoryAlias` - Alias management
- `command.CategoryRekey` - Rekey management
- `command.CategoryInfo` - Information commands
- `command.CategoryKeyMgmt` - Key management
- `command.CategoryASA` - ASA management
- `command.CategoryConfig` - Configuration
- `command.CategoryVariables` - Variables
- `command.CategoryAutomation` - Automation (scripts)
- `command.CategoryRemote` - Remote signing
- `command.CategoryOrchestration` - Orchestration (complex workflows)

## Best Practices

### 1. Error Handling

Always return descriptive errors:

```go
if err != nil {
    return fmt.Errorf("failed to build transaction: %w", err)
}
```

### 2. Address Resolution

Support both addresses and aliases:

```go
resolvedAddr, err := replState.AliasCache.ResolveAddress(address)
if err != nil {
    return fmt.Errorf("failed to resolve address: %w", err)
}
```

### 3. Key Type Detection

Handle both Falcon and Ed25519 keys:

```go
keyType := replState.SignerCache.GetKeyType(address)
var lsig *util.FalconLSig
if keyType == "falcon1024" {
    lsig, err = replState.LsigCache.GetLSig(address)
    // ...
}
```

### 4. Reuse Transaction Helpers

Don't reimplement signing - use existing helpers:

```go
txID, txn, err := transaction.SendFalconTxnWithNote(
    replState.AlgodClient,
    lsig,
    to,
    amount,
    from,
    signingAddr,
    note,
    description,
    replState.SignerClient,
    // ...
)
```

### 5. User Feedback

Provide clear feedback during long operations:

```go
fmt.Println("Building transaction...")
// ... build transaction
fmt.Println("Signing transaction...")
// ... sign
fmt.Println("Submitting to network...")
// ... submit
fmt.Printf("✓ Transaction ID: %s\n", txID)
```

## Plugin Registration

Plugins are **statically registered** at compile time:

1. Plugin's `init()` function calls `command.RegisterStaticPlugin()`
2. Plugin is imported with blank import in `cmd/apshell/main.go`
3. `initCommandRegistry()` calls `command.GetStaticPlugins()` to register all
4. Plugins are part of the compiled binary

**Security benefit:** You must explicitly import each plugin. No runtime loading means no accidental execution of malicious code.

## Troubleshooting

### Plugin Not Showing in Help

**Problem:** Added plugin but it doesn't appear in `help` output

**Solution:** Did you import it in `cmd/apshell/main.go`?

```go
_ "apshell/plugins/yourplugin"  // Add this
```

Then rebuild apshell.

### Compilation Errors

**Error:** `imported and not used: "apshell/plugins/myplugin"`

**Solution:** Use a blank import: `_ "apshell/plugins/myplugin"` (note the underscore)

### Reflection Panics

**Error:** `panic: reflect: call of reflect.Value.Interface on zero Value`

**Solution:** The field name is wrong or doesn't exist. Double-check field names:

```go
// Correct:
network := v.FieldByName("Network").String()

// Wrong (will panic):
network := v.FieldByName("NetworkName").String()  // No such field
```

Check `cmd/apshell/main.go` for the actual REPLState field names.

## Example Plugins

See the following example plugins:

- **selfping** - Send zero ALGO transaction to self (transaction basics)
- *(More examples coming soon)*

## Contributing

When contributing a new plugin:

1. Create a new directory under `plugins/`
2. Include a `README.md` with usage instructions
3. Include a `build.sh` script
4. Document all required arguments and behavior
5. Follow the best practices outlined above
6. Test with both Falcon-1024 and Ed25519 keys
7. Test on different networks (mainnet/testnet/betanet)

## License

Same as apshell (MIT)
