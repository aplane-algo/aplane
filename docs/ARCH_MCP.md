# MCP Integration (apshell)

MCP mode (`apshell --mcp`) exposes apshell as an MCP server over stdio,
allowing LLM clients to drive shell commands and JavaScript
programmatically. It shares the same parsing layer, `apshellapp` workflows,
and `CommandResult` rendering as the REPL (see [ARCH_REPL.md](ARCH_REPL.md))
but produces structured JSON instead of terminal text.

```
+----------+  JSON-RPC/stdio  +------------------+  SSH tunnel  +-----------+
|   LLM    | <--------------> |  apshell --mcp   | <----------> |  apsigner |
|  client  |                  |  (6 MCP tools)   |              |  (signer) |
+----------+                  +------------------+              +-----------+
```

## Tool Surface

The MCP server registers six tools:

| Tool | Purpose |
|------|---------|
| `execute` | Run a shell command (built-in or plugin) |
| `mcp_reference` | Live command reference (captures `help` output) |
| `js` | Execute JavaScript in the Goja runtime, returns `{value, output}` |
| `js_reference` | Embedded `USER_JSAPI.md` reference text (stateless) |
| `jssave` | Save JavaScript by filename into `scripts/` (or absolute path) |
| `jslist` | List saved scripts as `[{name, size, mtime}, ...]` |

The `js`, `jssave`, and `jslist` handlers share the helpers
(`captureJSExecution`, `saveJSScript`, `listJSScripts`) used by the REPL
counterparts but produce structured JSON directly without going through the
shell parser. The REPL `js` command accepts a `-help` flag that prints the JS
API reference; MCP clients fetch the same reference via `js_reference`.

LLMs pull command and API references on demand via `mcp_reference` and
`js_reference` rather than having them injected periodically.

## Configuration

The installer writes `$APCLIENT_DATA/.mcp.json` for the installed `apshell`
binary and data directory. To configure manually:

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

Each server instance uses its own data directory (`-d` flag), which determines
the config, caches, token, plugin catalog, and plugin activation config.

## Startup Sequence

1. Run the shared `clientenroll.LoadEnrolledClient` preflight: `ssh:` config, `aplane.token`, and a trusted signer host in `known_hosts` are required, with MCP-specific hints. Failure exits non-zero before any other startup work.
2. Create `REPLState` with initialized runtime state and app facade.
3. Set `AutoConfirm: true` (non-interactive) and redirect REPL/app output to `os.Stderr`.
4. Save the real stdout for MCP transport, then redirect `os.Stdout` to `os.Stderr` so stray prints do not corrupt the JSON-RPC stream.
5. Initialize the command registry and the plugin runtime (`initPluginRuntime`).
6. Require an operational startup signer connection (`attemptStartupConnection`); MCP exits if the connection cannot be established.
7. Build the `execute` tool description (base reference plus discovered plugin `mcp.md` files).
8. Register the six tools and serve over stdio using the saved real stdout.

## `execute` Routing

`mcpStructured()` routes commands through three tiers:

```
Command received
    |
    v
+------------------+
| Blocked?         |--yes--> Error: "not available via MCP"
| (js, jssave,     |         (redirected to dedicated MCP tools,
|  jslist, quit)   |          or interactive commands)
+--------+---------+
         | no
         v
+------------------+
| Structured?      |--yes--> CommandResult.RenderJSON()
| (keys, verbose,  |
|  write, ...)     |
+--------+---------+
         | no
         v
+------------------+
| Plugin?          |--yes--> PluginResult.RenderJSON()
+--------+---------+
         | no
         v
+------------------+
| Text capture     |-------> Redirect state.Out to buffer,
| (fallback)       |         execute, return captured text
+------------------+
```

### Structured Path

Built-in commands that implement `CommandResult` return typed results that
serialize to stable JSON. The MCP handler invokes the same `exec*()` helper
that the REPL handler uses, then calls `RenderJSON()` instead of `RenderText()`:

```go
case "keys":
    result, err := execKeys(state)
    return jsonOK(result.RenderJSON())
```

`internal/apshellcli/render_mcp.go` also defines direct projection helpers for
commands such as `status`, `accounts`, `balance`, `holders`, `participation`,
`keytypes`, `info`, `app read`, `alias`, `sets`, and `asa list`.

### Text Capture Fallback

Commands without a `CommandResult` are handled by redirecting `state.Out` to a
buffer:

```go
var buf bytes.Buffer
state.SetOutput(&buf)
state.executeCommand(cmd)
state.SetOutput(os.Stderr)
return mcp.NewToolResultText(buf.String()), nil
```

This works for every command because output flows through `state.Out`
(`io.Writer`), not `os.Stdout`.

### Blocked Commands

| Command | Reason |
|---------|--------|
| `js` | Use the `js` MCP tool instead |
| `jssave` | Use the `jssave` MCP tool instead |
| `jslist` | Use the `jslist` MCP tool instead |
| `request-token` | Token request requires interactive approval |
| `quit`, `exit` | Use MCP disconnect instead |
| `keyreg` (no args) | Paste mode requires interactive input |

## stdout/stderr Separation

MCP uses stdout exclusively for JSON-RPC transport. All other output goes to
stderr:

```go
mcpStdout := os.Stdout    // Save real stdout for MCP
os.Stdout = os.Stderr     // Redirect process stdout to stderr
state.SetOutput(os.Stderr) // REPL/app output goes to stderr
```

This prevents stray `fmt.Printf` calls from corrupting the MCP transport.

## Plugin Behavior

### success:false Handling

Plugin commands that return `success: false` (e.g., usage messages, validation
errors) are returned as normal MCP tool results with the full JSON payload,
not as MCP transport errors. This matches the REPL contract where these are
informational messages, not hard failures.

### Plugin Documentation (mcp.md)

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

## Concurrency

A mutex protects `REPLState` during command execution since MCP calls may
overlap:

```go
mu.Lock()
defer mu.Unlock()
```

## Key Files

| File | Purpose |
|------|---------|
| `internal/apshellcli/mcp.go` | MCP server, routing, tool description, plugin doc loading |
| `internal/apshellcli/render_mcp.go` | Direct MCP projections for non-`CommandResult` commands |
| `internal/apshellcli/render.go` | `CommandResult.RenderJSON()` implementations |

## Related Documentation

- [ARCH_REPL.md](ARCH_REPL.md) — Shared parsing, dispatch, and `CommandResult`
- [ARCH_PLUGINS.md](ARCH_PLUGINS.md) — Plugin manifests, `mcp.md`, and lifecycle
- [USER_JSAPI.md](USER_JSAPI.md) — JavaScript API reference exposed via `js_reference`
- [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md) — MCP tool contract under compatibility surfaces
