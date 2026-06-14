// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/clientenroll"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/docassets"
	"github.com/aplane-algo/aplane/internal/version"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// runMCPMode starts an MCP server over stdio, exposing apshell as eight MCP tools:
// execute (shell commands), mcp_reference (shell command reference),
// js (JavaScript execution), js_reference (JavaScript API reference),
// jssave (save JS to file), jslist (list saved scripts), mcp_manual
// (condensed operating manual), and doc (bundled reference docs).
func runMCPMode(network string, cfg config.Config, dataDir string) {
	if _, err := clientenroll.LoadEnrolledClient(dataDir, clientenroll.Options{
		Product:              "apshell --mcp",
		MissingSSHHint:       "MCP cannot perform first-time enrollment; run interactive apshell request-token first",
		MissingTokenHint:     fmt.Sprintf("MCP cannot perform first-time enrollment; run interactive apshell -d %s request-token first", dataDir),
		MissingKnownHostHint: "MCP cannot trust a new signer host non-interactively; run interactive apshell request-token or connect first",
	}); err != nil {
		fmt.Fprintf(os.Stderr, "MCP startup refused: %v\n", err)
		os.Exit(1)
	}

	// Create REPLState with initialized runtime state and app facade.
	state, err := NewREPLState(network, &cfg, dataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to initialize: %v\n", err)
		os.Exit(1)
	}

	state.Config = cfg
	state.AutoConfirm = true   // Non-interactive: skip confirmation prompts
	state.SetOutput(os.Stderr) // stdout is MCP transport; all output goes to stderr

	// Save the real stdout for MCP transport, then redirect os.Stdout to stderr.
	// This prevents any stray fmt.Printf in signing/confirmation paths from
	// corrupting the MCP JSON-RPC transport.
	mcpStdout := os.Stdout
	os.Stdout = os.Stderr
	mcpExitCode := 0
	defer func() {
		shutdownRuntime(state)
		os.Stdout = mcpStdout
		if mcpExitCode != 0 {
			os.Exit(mcpExitCode)
		}
	}()
	state.CommandRegistry = state.initCommandRegistry()

	if err := initPluginRuntime(state); err != nil {
		fmt.Fprintf(os.Stderr, "MCP startup refused: failed to initialize plugins: %v\n", err)
		mcpExitCode = 1
		return
	}
	if err := attemptStartupConnection(state); err != nil {
		fmt.Fprintf(os.Stderr, "MCP startup refused: apshell --mcp requires an operational signer connection at startup: %v\n", err)
		mcpExitCode = 1
		return
	}

	// Mutex protects state during command execution (MCP calls may overlap)
	var mu sync.Mutex

	// Build tool description: base commands + plugin mcp.md instructions
	toolDescription := mcpBuildDescription(state.app().Plugins)

	// Create MCP server
	mcpServer := server.NewMCPServer(
		"apshell",
		version.String(),
		server.WithToolCapabilities(true),
	)

	// Register the "execute" tool for shell commands
	mcpServer.AddTool(mcp.NewTool("execute",
		mcp.WithDescription(toolDescription),
		mcp.WithString("command", mcp.Required(), mcp.Description("The apshell command to execute")),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		cmdStr, ok := request.Params.Arguments["command"].(string)
		if !ok || cmdStr == "" {
			return mcp.NewToolResultError("command is required"), nil
		}

		mu.Lock()
		defer mu.Unlock()
		state.applyClientCacheUpdates()

		cmd, err := parseShellCommand(cmdStr)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("invalid command: %v", err)), nil
		}
		if cmd.Name == "" {
			return mcp.NewToolResultError("empty command"), nil
		}

		// Structured JSON path for supported commands
		if r, handled := mcpStructured(state, cmd.Name, cmd.Args); handled {
			return r, nil
		}

		// Fallback: capture text output
		var buf bytes.Buffer
		state.SetOutput(&buf)

		err = state.executeCommand(cmd)

		// Restore output to stderr (stdout is MCP transport)
		state.SetOutput(os.Stderr)

		return mcpFallbackResult(buf.String(), err), nil
	})

	// Register the "js" tool for JavaScript execution with structured results.
	mcpServer.AddTool(mcp.NewTool("js",
		mcp.WithDescription(`Execute JavaScript in the apshell Goja runtime and return structured JSON.

The last expression's value is JSON-serialized in "value"; any print() output
is captured in "output".

Use the js_reference tool to fetch the JavaScript API reference.`),
		mcp.WithString("code", mcp.Required(), mcp.Description("JavaScript code to execute.")),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		code, ok := request.Params.Arguments["code"].(string)
		if !ok || strings.TrimSpace(code) == "" {
			return mcp.NewToolResultError("code is required"), nil
		}

		mu.Lock()
		defer mu.Unlock()
		state.applyClientCacheUpdates()

		return mcpJSExecutionResult(ctx, state, code), nil
	})

	// Register the "js_reference" tool for on-demand JS API reference.
	mcpServer.AddTool(mcp.NewTool("js_reference",
		mcp.WithDescription("Return the JavaScript API reference for apshell scripting. Call this when you need available JS functions, signatures, and return types."),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return mcp.NewToolResultText(docassets.UserJSAPI), nil
	})

	// Register the "mcp_manual" tool for the condensed operating manual.
	mcpServer.AddTool(mcp.NewTool("mcp_manual",
		mcp.WithDescription("Return the apshell MCP operating manual: the system/trust model, tool surface, key model, transaction and signing flow, policy and approval behavior, and common workflows. Read this first to understand how the pieces fit together; use mcp_reference and js_reference for exact command and API signatures."),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return mcp.NewToolResultText(docassets.UserMCPManual), nil
	})

	// Register the "doc" tool for on-demand bundled reference docs.
	mcpServer.AddTool(mcp.NewTool("doc",
		mcp.WithDescription("List or fetch the bundled APlane reference docs that mcp_manual points to. Call with no arguments to list available docs (name + one-line summary); pass name to return that doc's full Markdown (e.g. name=\"WP_CORRIDORS\")."),
		mcp.WithString("name", mcp.Description("Doc name to fetch, with or without the .md suffix (e.g. \"ARCH_TXNFLOW\"). Omit to list all available docs.")),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		name, _ := request.Params.Arguments["name"].(string)
		return mcpDocResult(dataDir, name), nil
	})

	// Register the "jssave" tool for saving JavaScript code to files
	mcpServer.AddTool(mcp.NewTool("jssave",
		mcp.WithDescription(`Save JavaScript code for later execution via js <file.js>.

If path is a single filename with no "/", it is saved under the data
directory's scripts/ folder. Otherwise, the path must be absolute and start
with "/". Appends .js extension if not already present. Fails if the file
already exists unless overwrite is true. Set last to true to save the most
recently executed JavaScript code instead of providing code.`),
		mcp.WithString("path", mcp.Required(), mcp.Description("A single filename to save under the data directory's scripts/ folder, or an absolute path starting with '/'.")),
		mcp.WithString("filename", mcp.Description("Deprecated alias for path.")),
		mcp.WithString("code", mcp.Description("JavaScript code to save (required unless last is true)")),
		mcp.WithBoolean("last", mcp.Description("Save the last executed JavaScript code (default false)")),
		mcp.WithBoolean("overwrite", mcp.Description("Overwrite existing file (default false)")),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		scriptPath, _ := request.Params.Arguments["path"].(string)
		filename, _ := request.Params.Arguments["filename"].(string)
		code, _ := request.Params.Arguments["code"].(string)
		last, _ := request.Params.Arguments["last"].(bool)
		overwrite, _ := request.Params.Arguments["overwrite"].(bool)
		if strings.TrimSpace(scriptPath) == "" {
			scriptPath = filename
		}
		if strings.TrimSpace(scriptPath) == "" {
			return mcp.NewToolResultError("path is required"), nil
		}

		mu.Lock()
		defer mu.Unlock()

		if last {
			if state.Scripts.LastCode == "" {
				return mcp.NewToolResultError("no previously executed JavaScript code"), nil
			}
			code = state.Scripts.LastCode
		}
		if code == "" {
			return mcp.NewToolResultError("code is required (or set last to true)"), nil
		}

		dest, err := saveJSScript(dataDir, scriptPath, code, overwrite)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		data, marshalErr := json.Marshal(map[string]string{"path": dest})
		if marshalErr != nil {
			return mcp.NewToolResultText(fmt.Sprintf("Saved to %s", dest)), nil
		}
		return mcp.NewToolResultText(string(data)), nil
	})

	// Register the "jslist" tool for listing saved JavaScript scripts
	mcpServer.AddTool(mcp.NewTool("jslist",
		mcp.WithDescription("List saved JavaScript scripts in the data directory's scripts/ folder. Returns a JSON array of {name, size, mtime} entries sorted by name."),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		mu.Lock()
		defer mu.Unlock()

		entries, err := listJSScripts(dataDir)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		if entries == nil {
			entries = []jsScriptEntry{}
		}
		data, marshalErr := json.Marshal(entries)
		if marshalErr != nil {
			return mcp.NewToolResultError(marshalErr.Error()), nil
		}
		return mcp.NewToolResultText(string(data)), nil
	})

	// Register the "mcp_reference" tool for on-demand shell command reference
	mcpServer.AddTool(mcp.NewTool("mcp_reference",
		mcp.WithDescription("Return the shell command reference for the execute tool, including all available commands and plugin commands."),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		mu.Lock()
		defer mu.Unlock()

		helpText := mcpCaptureHelp(state)
		if helpText == "" {
			return mcp.NewToolResultText("No commands available"), nil
		}
		return mcp.NewToolResultText(helpText), nil
	})

	// Serve over stdio using saved stdout (os.Stdout is now redirected to stderr)
	stdioServer := server.NewStdioServer(mcpServer)
	if err := stdioServer.Listen(context.Background(), os.Stdin, mcpStdout); err != nil {
		fmt.Fprintf(os.Stderr, "MCP server error: %v\n", err)
		mcpExitCode = 1
		return
	}
}

// mcpBlockedCommands are commands that cannot be used via the execute tool.
var mcpBlockedCommands = map[string]string{
	"js":            "Use the js MCP tool instead",
	"jssave":        "Use the jssave MCP tool instead",
	"jslist":        "Use the jslist MCP tool instead",
	"request-token": "Token request requires interactive approval — run via apshell directly",
	"quit":          "Use MCP disconnect instead",
	"exit":          "Use MCP disconnect instead",
}

// mcpStructured handles commands that return structured JSON instead of text.
// Returns (result, true) if handled, or (nil, false) to fall through to text capture.
func mcpStructured(state *REPLState, cmdName string, args []string) (*mcp.CallToolResult, bool) {
	// Block interactive commands
	if reason, blocked := mcpBlockedCommands[cmdName]; blocked {
		return mcp.NewToolResultError(fmt.Sprintf("command '%s' not available via MCP: %s", cmdName, reason)), true
	}

	// Block keyreg paste mode (no args) — requires interactive input
	if cmdName == "keyreg" && len(args) == 0 {
		return mcp.NewToolResultError("keyreg paste mode not available via MCP — provide arguments directly (e.g., 'keyreg alice online')"), true
	}

	// Helper: return JSON result or error
	jsonOK := func(data []byte) (*mcp.CallToolResult, bool) {
		return mcpJSONTextResult(data), true
	}
	jsonErr := func(err error) (*mcp.CallToolResult, bool) {
		return mcp.NewToolResultError(err.Error()), true
	}

	switch cmdName {
	// --- Read-only info commands ---
	case "keys":
		result, err := execKeys(state)
		if err != nil {
			return jsonErr(err)
		}
		return jsonOK(result.RenderJSON())
	case "status":
		return jsonOK(state.mcpStatus())
	case "accounts":
		data, err := state.mcpAccounts()
		if err != nil {
			return jsonErr(err)
		}
		return jsonOK(data)
	case "balance":
		data, err := state.mcpBalance(args)
		if err != nil {
			return jsonErr(err)
		}
		return jsonOK(data)
	case "holders":
		data, err := state.mcpHolders(args)
		if err != nil {
			return jsonErr(err)
		}
		return jsonOK(data)
	case "participation":
		data, err := state.mcpParticipation(args)
		if err != nil {
			return jsonErr(err)
		}
		return jsonOK(data)
	case "keytypes":
		data, err := state.mcpKeytypes()
		if err != nil {
			return jsonErr(err)
		}
		return jsonOK(data)
	case "info":
		data, err := state.mcpInfo(args)
		if err != nil {
			return jsonErr(err)
		}
		return jsonOK(data)
	case "app":
		if len(args) > 0 && args[0] == "read" {
			result, err := execApp(state, args)
			if err != nil {
				return jsonErr(err)
			}
			return jsonOK(result.RenderJSON())
		}

	// --- Alias/set listing (list subcommand returns JSON, mutations fall through to text) ---
	case "alias":
		if len(args) == 1 && args[0] == "list" {
			return jsonOK(state.mcpAliases())
		}
	case "sets":
		if len(args) == 1 && args[0] == "list" {
			return jsonOK(state.mcpSets())
		}

	// --- ASA cache (list subcommand returns JSON) ---
	case "asa":
		if len(args) == 1 && args[0] == "list" {
			return jsonOK(state.mcpASAList())
		}

	// --- Toggle commands ---
	case "verbose":
		result, err := execVerbose(state, args)
		if err != nil {
			return jsonErr(err)
		}
		return jsonOK(result.RenderJSON())
	case "write":
		result, err := execWrite(state, args)
		if err != nil {
			return jsonErr(err)
		}
		return jsonOK(result.RenderJSON())
	}

	// Check if this is an external plugin command
	if _, ok := state.CommandRegistry.Lookup(cmdName); !ok {
		if result, isPlugin := execPlugin(state, cmdName, args); isPlugin {
			return jsonOK(result.RenderJSON())
		}
	}

	return nil, false
}

func mcpJSONTextResult(data []byte) *mcp.CallToolResult {
	return mcp.NewToolResultText(string(data))
}

func mcpFallbackResult(output string, err error) *mcp.CallToolResult {
	if err != nil {
		if output != "" {
			return mcp.NewToolResultError(output + "\nError: " + err.Error())
		}
		return mcp.NewToolResultError(err.Error())
	}
	if output == "" {
		output = "OK"
	}
	return mcp.NewToolResultText(output)
}

// mcpCaptureHelp runs the bare "help" command and captures its text output.
func mcpCaptureHelp(state *REPLState) string {
	var buf bytes.Buffer
	oldOut := state.Out
	state.SetOutput(&buf)
	cmd := Command{Name: "help", Args: nil, RawArgs: ""}
	_ = state.executeCommand(cmd)
	state.SetOutput(oldOut)
	return strings.TrimSpace(buf.String())
}

// mcpJSResult is the structured response from the js MCP tool.
type mcpJSResult struct {
	Value  interface{} `json:"value,omitempty"`
	Output string      `json:"output,omitempty"`
}

// captureJSExecution runs JS code with print() output captured into the returned
// result. The runner's output callback is restored to state.println after the call.
func captureJSExecution(ctx context.Context, state *REPLState, code string) (mcpJSResult, error) {
	state.ensureJSRunner()

	var printBuf bytes.Buffer
	state.Scripts.Runner.SetOutput(func(msg string) {
		printBuf.WriteString(msg)
	})
	defer state.Scripts.Runner.SetOutput(func(msg string) {
		state.println(msg)
	})

	result, err := state.Scripts.Runner.RunWithContext(ctx, code)
	out := printBuf.String()
	if err != nil {
		return mcpJSResult{Output: out}, err
	}

	state.Scripts.LastCode = code

	resp := mcpJSResult{}
	if out != "" {
		resp.Output = out
	}
	if !result.IsEmpty {
		resp.Value = result.Value
	}
	return resp, nil
}

// mcpJSExecutionResult wraps captureJSExecution for the MCP js tool.
func mcpJSExecutionResult(ctx context.Context, state *REPLState, code string) *mcp.CallToolResult {
	resp, err := captureJSExecution(ctx, state, code)
	if err != nil {
		msg := err.Error()
		if resp.Output != "" {
			msg = resp.Output + "\nError: " + msg
		}
		return mcp.NewToolResultError(msg)
	}
	data, marshalErr := json.Marshal(resp)
	if marshalErr != nil {
		return mcp.NewToolResultText(fmt.Sprintf("value: %v\noutput: %s", resp.Value, resp.Output))
	}
	return mcp.NewToolResultText(string(data))
}

const mcpBaseDescription = `Execute an apshell command on the Algorand blockchain.

New here? Call mcp_manual first for the operating model (architecture, key model, signing flow, policy, and workflows).
Use the doc tool to list or fetch the full reference docs mcp_manual points to (e.g. doc name=WP_CORRIDORS).
Run "help <command>" for detailed syntax on a specific command.
Use mcp_reference to see all available shell commands.
Use the js tool to execute JavaScript code.
Use js_reference to fetch the JavaScript API reference.
Use the jssave tool to save a JavaScript snippet for later, and jslist to enumerate saved scripts.

Addresses can be aliases or set references (@setname, @all, @signers).
Assets can be IDs or cached names (e.g., "usdc" instead of "10458941").
Amounts are in human units (e.g., "5 algo" = 5 ALGO, "100 usdc" = 100 USDC).`

// mcpBuildDescription builds the MCP tool description by combining the base
// command reference with any mcp.md files found in discovered plugin directories.
func mcpBuildDescription(pm apshellapp.PluginRuntime) string {
	if pm == nil {
		return mcpBaseDescription
	}

	plugins, err := pm.DiscoverPluginsCached()
	if err != nil || len(plugins) == 0 {
		return mcpBaseDescription
	}

	var pluginDocs []string
	for _, p := range plugins {
		mcpMD := filepath.Join(p.Dir, "mcp.md")
		data, err := os.ReadFile(mcpMD)
		if err != nil {
			continue
		}
		content := strings.TrimSpace(string(data))
		if content != "" {
			pluginDocs = append(pluginDocs, content)
		}
	}

	if len(pluginDocs) == 0 {
		return mcpBaseDescription
	}

	return mcpBaseDescription + "\n\n" + strings.Join(pluginDocs, "\n\n")
}
