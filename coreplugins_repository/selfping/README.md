# SelfPing Plugin

A sample statically-compiled plugin that sends a zero ALGO payment transaction from an address to itself.

**Note:** This plugin is statically compiled into apshell (not a .so file) for better security and distribution.

## Purpose

This plugin demonstrates:
- How to create a shared object (.so) plugin for apshell
- How to access REPLState (network, algod client, key session)
- How to build, sign, and submit Algorand transactions
- How to wait for transaction confirmation
- A simple "self-ping" transaction pattern for testing

## Building

This plugin is **statically compiled** into apshell. To enable it:

1. **Import the plugin** in `cmd/apshell/main.go`:
   ```go
   import (
       // ... other imports
       _ "apshell/plugins/selfping"  // Blank import triggers init()
   )
   ```

2. **Build apshell**:
   ```bash
   cd /path/to/apshell
   go build -o apshell ./cmd/apshell
   ```

The plugin is automatically registered at compile time via its `init()` function.

**Why Static Compilation?**
- ✅ **Security** - No runtime code loading, all plugins reviewed at compile time
- ✅ **Distribution** - Single binary, no version/dependency conflicts
- ✅ **Deterministic** - Explicitly imported, can't accidentally include malicious .so files
- ✅ **Cross-platform** - Works everywhere Go works

## Usage

The plugin is automatically available in apshell (no installation needed):

```
testnet> selfping <address>
```

Example:
```
testnet> selfping EXAMPLEADDRESSXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
Building zero ALGO self-payment for EXAM... using ed25519...

✓ Transaction submitted successfully!
  Transaction ID: ABC123...
  From:   EXAM...
  To:     EXAM...
  Amount: 0 ALGO
  Fee:    0.001000 ALGO

View on testnet explorer:
  https://testnet.algoexplorer.io/tx/ABC123...

Waiting for confirmation...
✓ Transaction confirmed in round 12345
```

The plugin will:
1. Validate the address format
2. Check that you have signing capability for the address
3. Build a 0 ALGO payment transaction from the address to itself
4. Display transaction details
5. Sign the transaction (may prompt for approval via Signer)
6. Submit the transaction to the network
7. Wait for confirmation
8. Display the transaction ID and explorer link

## What is a "Self-Ping"?

A self-ping is a zero-amount payment transaction where the sender and receiver are the same address. It's useful for:
- Testing that an account is active and can sign transactions
- Updating an account's last activity timestamp
- Verifying that your signing infrastructure works
- Demonstrating transaction flows in examples

The only cost is the minimum transaction fee (usually 0.001 ALGO).

## Plugin Architecture

This is a **statically compiled plugin**. Key characteristics:

- Written in Go
- Compiled directly into apshell binary
- Registers via `init()` function calling `command.RegisterStaticPlugin()`
- Has direct access to REPLState via `ctx.Internal.REPLState`
- Loaded at compile time (part of the binary)
- Zero version/dependency conflicts

## Code Structure

```go
package selfping

// Register plugin at compile time
func init() {
    command.RegisterStaticPlugin(&command.Command{
        Name:        "selfping",
        Description: "Send zero ALGO payment to itself",
        Usage:       "selfping <address>",
        Category:    command.CategoryTransaction,
        Handler:     &Handler{},
    })
}

// Handler implements command.Handler interface
type Handler struct{}

func (h *Handler) Execute(args []string, ctx *command.Context) error {
    // Access REPLState via Context.Internal
    // Use reflection to access fields (avoids import cycle issues)
    v := reflect.ValueOf(ctx.Internal.REPLState).Elem()

    network := v.FieldByName("Network").String()
    algodClient := v.FieldByName("AlgodClient").Interface().(*algod.Client)
    aliasCache := v.FieldByName("AliasCache").Interface().(util.AliasCache)
    // ... access other fields as needed

    // Plugin implementation using reflected fields
    // ...
}
```

**Key differences from .so plugins:**
- Package name is the plugin name (not `main`)
- Uses `init()` for registration (not `GetCommand()`)
- No `stateInterface` parameter needed
- Compiled directly into apshell

The plugin has full access to `REPLState` fields via `ctx.Internal.REPLState`:
- `AlgodClient` - Algorand node client
- `SignerCache` - Available signing keys
- `LsigCache` - Falcon LogicSig cache
- `SignerClient` - Remote signing service
- `Network` - Current network (mainnet/testnet/betanet)
- `AliasCache` - Address aliases
- `AuthCache` - Rekeyed auth addresses
- `WriteMode` - Transaction write mode
- `CommandRegistry` - Command registry (for meta-operations)

## Implementation Details

This plugin demonstrates several key patterns:

1. **Reflection-Based Field Access**: Uses Go reflection to access REPLState fields without import cycles or type assertion issues
2. **Address Resolution**: Uses `AliasCache.ResolveAddress()` to support aliases
3. **Key Type Detection**: Checks if address uses Falcon-1024 or Ed25519
4. **LogicSig Handling**: Automatically retrieves Falcon lsig when needed
5. **Unified Transaction API**: Uses `SendFalconTxnWithNote()` which handles both key types
6. **Remote Signing**: Transparently uses Signer for key operations
7. **Transaction Confirmation**: Uses `algo.WaitForConfirmation()` with visual feedback

The plugin reuses existing transaction infrastructure instead of reimplementing signing logic, making it concise and maintainable.

### Why Reflection?

Go plugins cannot directly type assert to structs defined in `package main` (which cannot be imported). Even if we duplicate the struct definition in the plugin, Go's type system treats them as different types. Reflection allows us to access fields by name at runtime, bypassing compile-time type checking.

**Alternative approaches considered:**
1. **Explicit Context fields** - Add commonly-needed fields to `command.Context` (better compile-time safety, but verbose and couples Context to many types)
2. **Helper interface** - Define methods like `GetAlgodClient()` on REPLState (type-safe, versioned API, but requires boilerplate)
3. **Reflection via Context.Internal** - Current approach (flexible, follows intended design pattern, still needs reflection)

## Extending This Plugin

You can modify this plugin to:
- Send transactions with custom notes (modify `note` parameter)
- Send to different recipients (change `to` address)
- Send specific amounts (change `amount` from 0)
- Include asset transfers (use `SendFalconASATransfer` instead)
- Build application calls (use `transaction.MakeApplicationCallTxn`)
- Create multi-signature transactions (build transaction group)
- Implement custom transaction patterns (compose multiple calls)

## Security Notes

- The plugin uses the same security model as apshell
- Transaction signing may require user approval (depending on Signer mode)
- Private keys are handled securely via KeySession
- All transaction parameters are displayed before signing

## License

Same as apshell (MIT)
