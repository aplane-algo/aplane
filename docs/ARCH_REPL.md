# REPL Architecture (apshell)

`apshell` is the interactive shell for APlane. The REPL surface handles user
interaction (readline, tab completion, colored output) and delegates command
semantics to `internal/apshellapp` above `internal/engine`. The MCP surface
shares the same parsing and rendering pipeline but produces structured JSON
instead of terminal text; see [ARCH_MCP.md](ARCH_MCP.md). The signer admin
TUI is a separate client over the admin protocol; see [ARCH_TUI.md](ARCH_TUI.md).

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

## Session State

`internal/apshellcli/state.go` defines `REPLState`:

```go
type REPLState struct {
    Out               io.Writer
    App               *apshellapp.App
    DataDir           string
    Config            config.Config
    CommandRegistry   *command.Registry
    Scripts           ScriptSession
    LineReader        func() (string, error)
    SetPrompt         func(string)
    AutoConfirm       bool
    HostKeyApproval   func(host, fingerprint string) (bool, error)
    ProgressLine      func(string)
    currentCommandCtx context.Context
}
```

Command text rendering flows through an injected `io.Writer`. MCP does not
capture that writer: it marshals the already-computed command result. The
terminal-only `config` display remains the reviewed process-global-output
exception and is blocked from MCP automation.

## Command Handler Pattern

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

## Command Parsing

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

## Address Resolution

`internal/addressbook/resolver.go` converts user-friendly names to addresses.
The resolver consults the alias and set caches, plus optional providers
(`SignerProvider`, `AllProvider`, `HoldersProvider`) attached through
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

## Tab Completion

`internal/shellrepl/autocomplete.go` provides context-aware tab completion using
`ArgSpec` definitions from the command registry. External plugins declare their
argument types in `manifest.json` via `arg_specs` and support address, asset,
set, keyword, number, file, and conditional branching. The `custom` type is
reserved for plugin-provided completion; the runtime returns no custom
suggestions.

## Command Result Rendering

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

## Command Dispatch

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
    Automation: command.StructuredAutomation,
})
```

External plugins are never added to the registry. They are discovered at
runtime by the plugin manager and matched by command name from their
`manifest.json`. Plugin results flow through the same result-bearing execution
and presentation system as built-in commands. See
[ARCH_PLUGINS.md](ARCH_PLUGINS.md) for plugin details.

## Error Handling

| Mode | Behavior |
|------|----------|
| REPL | Print error message, continue loop |
| MCP  | Return `NewToolResultError(msg)`, continue serving |

The TUI uses its own error display; see [ARCH_TUI.md](ARCH_TUI.md).

## Approval CLI (apapprover)

`apapprover` is a minimal interactive approval client for signer IPC. It is a
separate CLI surface from `apshell` and the `apadmin` TUI and is intended for
focused approval workflows.

| Aspect | Detail |
|--------|--------|
| Input | stdin `y/n` approval loop |
| Output | FIFO approval queue rendered to terminal |
| State | In-memory pending queue of signing and token-provisioning requests |
| Transport | Local IPC admin protocol |

Signing and token-provisioning requests share a single FIFO queue. Policy
violations included in sign requests are shown to the approver. Signing
approval requests time out after the product runtime's effective `approval_wait` value,
which defaults to 60 seconds.

## Key Files

| File | Purpose |
|------|---------|
| `internal/apshellcli/state.go` | `REPLState` definition |
| `internal/apshellcli/commands.go` | Command dispatch |
| `internal/apshellcli/command_result.go` | Shared command-result implementation |
| `internal/apshellcli/command_projections.go` | Safe machine projection types |
| `internal/apshellcli/render.go` | Human presentation helpers |
| `internal/apshellcli/external_plugins.go` | Plugin execution and `PluginResult` construction |
| `internal/shellrepl/parser.go` | Top-level tokenization and per-command parsers |
| `internal/shellrepl/autocomplete.go` | Tab completion |
| `internal/cmdspec/` | Shared parsing helpers (`key=value`, bytes, addresses, asset refs) |
| `internal/apshellapp/` | Shell command semantics and runtime facade |
| `internal/appresult/` | Shared structured result types |
| `internal/command/help.go` | Help rendering (writes to `io.Writer`) |
| `internal/addressbook/resolver.go` | Address resolution (aliases, sets, `@signers`, `@all`) |

## Related Documentation

- [ARCH_MCP.md](ARCH_MCP.md) — MCP tool surface that consumes this pipeline
- [ARCH_TUI.md](ARCH_TUI.md) — Signer admin TUI (separate admin-protocol client)
- [ARCH_OVERVIEW.md](ARCH_OVERVIEW.md) — Overall system architecture
- [ARCH_ENGINE.md](ARCH_ENGINE.md) — Engine layer architecture
- [ARCH_PLUGINS.md](ARCH_PLUGINS.md) — External plugin system
