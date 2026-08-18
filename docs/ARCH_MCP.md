# MCP Integration (apshell)

MCP mode (`apshell --mcp`) exposes apshell as an MCP server over stdio,
allowing LLM clients to drive shell commands and JavaScript
programmatically. It shares the same parsing layer, `apshellapp` workflows,
and result-bearing execution as the REPL (see [ARCH_REPL.md](ARCH_REPL.md))
but produces structured JSON instead of terminal text.

```
+----------+  JSON-RPC/stdio  +------------------+  SSH tunnel  +-----------+
|   LLM    | <--------------> |  apshell --mcp   | <----------> |  apsigner |
|  client  |                  |  (8 MCP tools)   |              |  (signer) |
+----------+                  +------------------+              +-----------+
```

## Tool Surface

The MCP server registers eight tools:

| Tool | Purpose |
|------|---------|
| `execute` | Run a shell command (built-in or plugin) |
| `mcp_reference` | Live command reference generated from the registry |
| `js` | Execute JavaScript in the Goja runtime, returns `{value, output}` |
| `js_reference` | Embedded `USER_JSAPI.md` reference text (stateless) |
| `mcp_manual` | Embedded `USER_MCP_MANUAL.md` operating manual (stateless) |
| `doc` | List or return a bundled curated reference doc (embedded, with `<dataDir>/docs` overlay) |
| `jssave` | Save JavaScript by filename into `scripts/` (or absolute path) |
| `jslist` | List saved scripts as `[{name, size, mtime}, ...]` |

The `js`, `jssave`, and `jslist` handlers share the helpers
(`captureJSExecution`, `saveJSScript`, `listJSScripts`) used by the REPL
counterparts but produce structured JSON directly without going through the
shell parser. The REPL `js` command accepts a `-help` flag that prints the JS
API reference; MCP clients fetch the same reference via `js_reference`.

LLMs pull command and API references on demand via `mcp_reference` and
`js_reference`, the operating manual via `mcp_manual`, and the deep reference
docs via `doc`, rather than having them injected periodically.

## Configuration

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
the config, caches, token, plugin catalog, and plugin activation config.

## Startup Sequence

1. Run the shared `clientenroll.LoadEnrolledClient` preflight: a default signer endpoint, that endpoint's token file, and a trusted signer host in the endpoint `known_hosts_path` are required, with MCP-specific hints. Failure exits non-zero before any other startup work.
2. Create `REPLState` with initialized runtime state and app facade.
3. Set `AutoConfirm: true` (non-interactive) and redirect REPL/app output to `os.Stderr`.
4. Save the real stdout for MCP transport, then redirect `os.Stdout` to `os.Stderr` so stray prints do not corrupt the JSON-RPC stream.
5. Initialize the command registry and the plugin runtime (`initPluginRuntime`).
6. Require an operational startup signer connection (`attemptStartupConnection`); MCP exits if the connection cannot be established.
7. Build the `execute` tool description (base reference plus discovered plugin `mcp.md` files).
8. Register the eight tools and serve over stdio using the saved real stdout.

## `execute` Routing

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

### Blocked Commands

| Command | Reason |
|---------|--------|
| `js` | Use the `js` MCP tool instead |
| `jssave` | Use the `jssave` MCP tool instead |
| `jslist` | Use the `jslist` MCP tool instead |
| `help` | Use `mcp_reference` instead |
| `config` | Use the safe `status` command instead |
| `script` | Issue commands individually or use `js` |
| `request-token` | Token request requires interactive approval |
| `clear` | Terminal clearing has no machine meaning |
| `quit`, `exit`, `q` | Use MCP disconnect instead |
| `keyreg` (no args) | Paste mode requires interactive input |

Policies are attached to primary registry commands after alias resolution, so
aliases cannot bypass a block. Explicit `keyreg` arguments remain structured.

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
| `internal/apshellcli/mcp.go` | MCP server, policy enforcement, tool description, plugin doc loading |
| `internal/apshellcli/command_result.go` | Shared human/machine command result implementation |
| `internal/apshellcli/command_projections.go` | Explicit safe machine projections |

## Related Documentation

- [ARCH_REPL.md](ARCH_REPL.md) — Shared parsing, dispatch, and command results
- [ARCH_PLUGINS.md](ARCH_PLUGINS.md) — Plugin manifests, `mcp.md`, and lifecycle
- [USER_JSAPI.md](USER_JSAPI.md) — JavaScript API reference exposed via `js_reference`
- [USER_MCP_MANUAL.md](USER_MCP_MANUAL.md) — condensed operating manual exposed via `mcp_manual`
- [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md) — MCP tool contract under compatibility surfaces
