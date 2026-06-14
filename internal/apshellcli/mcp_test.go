// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/aplane-algo/aplane/internal/appresult"
	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/docassets"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/plugin/jsonrpc"
)

func TestMCPJSONTextResultReturnsTextContent(t *testing.T) {
	result := mcpJSONTextResult([]byte(`{"ok":true}`))

	if result.IsError {
		t.Fatal("expected success result")
	}
	if got := mcpResultText(t, result); got != `{"ok":true}` {
		t.Fatalf("text = %q, want JSON text payload", got)
	}
}

func TestMCPFallbackResultSilentSuccessIsOK(t *testing.T) {
	result := mcpFallbackResult("", nil)

	if result.IsError {
		t.Fatal("expected success result")
	}
	if got := mcpResultText(t, result); got != "OK" {
		t.Fatalf("text = %q, want OK", got)
	}
}

func TestMCPFallbackResultPreservesPlainText(t *testing.T) {
	result := mcpFallbackResult("done\n", nil)

	if result.IsError {
		t.Fatal("expected success result")
	}
	if got := mcpResultText(t, result); got != "done\n" {
		t.Fatalf("text = %q, want original fallback text", got)
	}
}

func TestMCPFallbackResultErrorIncludesCapturedOutput(t *testing.T) {
	result := mcpFallbackResult("partial output", errors.New("boom"))

	if !result.IsError {
		t.Fatal("expected error result")
	}
	if got := mcpResultText(t, result); got != "partial output\nError: boom" {
		t.Fatalf("text = %q, want combined output and error", got)
	}
}

func TestMCPStructuredBlockedCommandReturnsError(t *testing.T) {
	result, handled := mcpStructured(nil, "quit", nil)

	if !handled {
		t.Fatal("expected blocked command to be handled")
	}
	if !result.IsError {
		t.Fatal("expected error result")
	}
	if got := mcpResultText(t, result); got != "command 'quit' not available via MCP: Use MCP disconnect instead" {
		t.Fatalf("text = %q, want blocked-command error", got)
	}
}

func TestMCPStructuredKeyregPasteBlocked(t *testing.T) {
	result, handled := mcpStructured(nil, "keyreg", nil)

	if !handled {
		t.Fatal("expected keyreg paste mode to be handled")
	}
	if !result.IsError {
		t.Fatal("expected error result")
	}
	if got := mcpResultText(t, result); got != "keyreg paste mode not available via MCP — provide arguments directly (e.g., 'keyreg alice online')" {
		t.Fatalf("text = %q, want keyreg paste-mode error", got)
	}
}

func TestMCPBalanceParsesAssetOnlyQueryLikeREPL(t *testing.T) {
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	state := &REPLState{App: apshellapp.New(eng, config.DefaultConfig(), t.TempDir())}

	account, assetRef, err := state.parseMCPBalanceArgs([]string{"usdc"})
	if err == nil {
		if account != "@all" || assetRef != "usdc" {
			t.Fatalf("parseMCPBalanceArgs() = (%q, %q), want (@all, usdc)", account, assetRef)
		}
		return
	}
	t.Fatalf("parseMCPBalanceArgs() error = %v", err)
}

func TestMCPStructuredWriteReturnsJSON(t *testing.T) {
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	state := &REPLState{App: apshellapp.New(eng, config.DefaultConfig(), t.TempDir())}

	result, handled := mcpStructured(state, "write", []string{"on"})
	if !handled {
		t.Fatal("expected write command to be handled")
	}
	if result.IsError {
		t.Fatal("expected success result")
	}
	if got := mcpResultText(t, result); got != `{"name":"write","enabled":true}` {
		t.Fatalf("text = %q, want structured toggle JSON", got)
	}
}

func TestMCPStructuredWritePrefersStructuredResultOverTextRendering(t *testing.T) {
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	state := &REPLState{App: apshellapp.New(eng, config.DefaultConfig(), t.TempDir())}

	textResult, err := execWrite(state, []string{"on"})
	if err != nil {
		t.Fatalf("execWrite() error = %v", err)
	}
	var text bytes.Buffer
	state.SetOutput(&text)
	textResult.RenderText(&text, state)
	if got := text.String(); got != "✓ Write mode enabled\n" {
		t.Fatalf("RenderText() = %q, want human text output", got)
	}

	if _, err := state.App.SetWriteMode(false); err != nil {
		t.Fatalf("SetWriteMode(false) error = %v", err)
	}
	mcpResult, handled := mcpStructured(state, "write", []string{"on"})
	if !handled {
		t.Fatal("expected write command to be handled")
	}
	if mcpResult.IsError {
		t.Fatal("expected success result")
	}
	if got := mcpResultText(t, mcpResult); got != `{"name":"write","enabled":true}` {
		t.Fatalf("MCP text = %q, want structured JSON", got)
	}
	if got := mcpResultText(t, mcpResult); got == text.String() {
		t.Fatalf("MCP result unexpectedly matched text fallback output %q", got)
	}
}

func TestMCPPluginResultProjectionPreservesStructuredJSONAndFiltersShellOnlyData(t *testing.T) {
	result := &PluginResult{Plugin: appresult.Plugin{
		Plugin:  "swap",
		Success: true,
		Message: "ok",
		TxIDs:   []string{"TX1"},
		Data: map[string]any{
			"amount":       123,
			"localSigners": []any{"ADDR1"},
		},
		Presentation: &jsonrpc.Presentation{
			Title:   "Swap Quote",
			Summary: "1 route available",
		},
		Steps: []appresult.PluginStep{{
			Message: "submitted",
			TxIDs:   []string{"TX1"},
		}},
	}}

	mcpResult := mcpJSONTextResult(result.RenderJSON())
	if mcpResult.IsError {
		t.Fatal("expected success result")
	}

	var got map[string]any
	if err := json.Unmarshal([]byte(mcpResultText(t, mcpResult)), &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if got["plugin"] != "swap" {
		t.Fatalf("plugin = %#v, want swap", got["plugin"])
	}
	if got["success"] != true {
		t.Fatalf("success = %#v, want true", got["success"])
	}
	data, ok := got["data"].(map[string]any)
	if !ok {
		t.Fatalf("data type = %T, want map", got["data"])
	}
	if _, exists := data["localSigners"]; exists {
		t.Fatalf("data.localSigners unexpectedly present in MCP projection: %#v", data)
	}
	if data["amount"] != float64(123) {
		t.Fatalf("data.amount = %#v, want 123", data["amount"])
	}
	presentation, ok := got["presentation"].(map[string]any)
	if !ok {
		t.Fatalf("presentation type = %T, want map", got["presentation"])
	}
	if presentation["title"] != "Swap Quote" {
		t.Fatalf("presentation.title = %#v, want Swap Quote", presentation["title"])
	}
}

func TestPluginRenderTextPrefersPresentationOverRawMessage(t *testing.T) {
	result := &PluginResult{Plugin: appresult.Plugin{
		Plugin:  "reti",
		Success: true,
		Message: "raw fallback",
		Presentation: &jsonrpc.Presentation{
			Title:   "Reti Validators",
			Summary: "Showing 2 validators",
			Sections: []jsonrpc.PresentationSection{{
				Kind:    "table",
				Columns: []string{"ID", "Staked"},
				Rows: []jsonrpc.PresentationTableRow{
					{Cells: []string{"1", "100.0"}},
					{Cells: []string{"2", "200.0"}},
				},
			}},
		},
	}}

	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	state := &REPLState{App: apshellapp.New(eng, config.DefaultConfig(), t.TempDir())}
	var out bytes.Buffer
	state.SetOutput(&out)

	result.RenderText(&out, state)

	got := out.String()
	if !bytes.Contains(out.Bytes(), []byte("Reti Validators")) {
		t.Fatalf("RenderText() output missing presentation title: %q", got)
	}
	if !bytes.Contains(out.Bytes(), []byte("Showing 2 validators")) {
		t.Fatalf("RenderText() output missing presentation summary: %q", got)
	}
	if !bytes.Contains(out.Bytes(), []byte("ID")) || !bytes.Contains(out.Bytes(), []byte("Staked")) {
		t.Fatalf("RenderText() output missing table headers: %q", got)
	}
	if bytes.Contains(out.Bytes(), []byte("raw fallback")) {
		t.Fatalf("RenderText() unexpectedly used fallback message: %q", got)
	}
}

func TestMCPStructuredConcurrentReadOnlyCommandsReturnIndependentPayloads(t *testing.T) {
	store := cache.NewStore(t.TempDir())
	eng, err := engine.NewEngine("testnet",
		engine.WithCacheStore(store),
		engine.WithAliasCache(cache.LoadAliasCacheFromStore(store)),
	)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	state := &REPLState{App: apshellapp.New(eng, config.DefaultConfig(), t.TempDir())}

	addr := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"
	if _, err := eng.AddAliasWithContext(context.Background(), "alice", addr); err != nil {
		t.Fatalf("AddAlias() error = %v", err)
	}
	eng.SignerCache.Keys[addr] = "ed25519"

	type outcome struct {
		cmd  string
		text string
		err  error
	}

	results := make(chan outcome, 3)
	var wg sync.WaitGroup
	for _, tc := range []struct {
		cmd  string
		args []string
	}{
		{cmd: "alias", args: []string{"list"}},
		{cmd: "accounts", args: nil},
		{cmd: "status", args: nil},
	} {
		wg.Add(1)
		go func(cmd string, args []string) {
			defer wg.Done()
			result, handled := mcpStructured(state, cmd, args)
			if !handled {
				results <- outcome{cmd: cmd, err: errors.New("not handled")}
				return
			}
			if result.IsError {
				results <- outcome{cmd: cmd, err: errors.New(mcpResultText(t, result))}
				return
			}
			results <- outcome{cmd: cmd, text: mcpResultText(t, result)}
		}(tc.cmd, tc.args)
	}
	wg.Wait()
	close(results)

	got := map[string]string{}
	for result := range results {
		if result.err != nil {
			t.Fatalf("%s error = %v", result.cmd, result.err)
		}
		got[result.cmd] = result.text
	}

	var aliases []map[string]any
	if err := json.Unmarshal([]byte(got["alias"]), &aliases); err != nil {
		t.Fatalf("alias JSON error = %v", err)
	}
	if len(aliases) != 1 || aliases[0]["name"] != "alice" || aliases[0]["address"] != addr {
		t.Fatalf("alias payload = %#v, want alice/%s", aliases, addr)
	}

	var accounts []map[string]any
	if err := json.Unmarshal([]byte(got["accounts"]), &accounts); err != nil {
		t.Fatalf("accounts JSON error = %v", err)
	}
	if len(accounts) != 1 || accounts[0]["alias"] != "alice" || accounts[0]["address"] != addr {
		t.Fatalf("accounts payload = %#v, want alice/%s", accounts, addr)
	}

	var status map[string]any
	if err := json.Unmarshal([]byte(got["status"]), &status); err != nil {
		t.Fatalf("status JSON error = %v", err)
	}
	if status["network"] != "testnet" {
		t.Fatalf("status payload = %#v, want network testnet", status)
	}
	if got["alias"] == got["accounts"] || got["alias"] == got["status"] || got["accounts"] == got["status"] {
		t.Fatalf("concurrent MCP payloads unexpectedly matched: %#v", got)
	}
}

func TestMCPStructuredBlocksJSTool(t *testing.T) {
	for _, cmd := range []string{"js", "jssave", "jslist"} {
		result, handled := mcpStructured(nil, cmd, nil)

		if !handled {
			t.Fatalf("expected %s to be handled (blocked)", cmd)
		}
		if !result.IsError {
			t.Fatalf("%s: expected error result", cmd)
		}
		if got := mcpResultText(t, result); !strings.Contains(got, "MCP tool") {
			t.Fatalf("%s text = %q, want message referencing MCP tool", cmd, got)
		}
	}
}

func TestMCPBaseDescriptionReferencesExplicitManualTools(t *testing.T) {
	if !strings.Contains(mcpBaseDescription, "mcp_reference") {
		t.Fatalf("mcpBaseDescription missing mcp_reference: %q", mcpBaseDescription)
	}
	if !strings.Contains(mcpBaseDescription, "js_reference") {
		t.Fatalf("mcpBaseDescription missing js_reference: %q", mcpBaseDescription)
	}
	if !strings.Contains(mcpBaseDescription, "mcp_manual") {
		t.Fatalf("mcpBaseDescription missing mcp_manual: %q", mcpBaseDescription)
	}
	if !strings.Contains(mcpBaseDescription, "doc tool") {
		t.Fatalf("mcpBaseDescription missing doc tool: %q", mcpBaseDescription)
	}
	if strings.Contains(mcpBaseDescription, "execute_commands") {
		t.Fatalf("mcpBaseDescription still references execute_commands: %q", mcpBaseDescription)
	}
}

func TestMCPJSExecutionResultReturnsStructuredValue(t *testing.T) {
	state := testREPLForJS(t)

	result := mcpJSExecutionResult(context.Background(), state, `({name: "alice", count: 3})`)
	if result.IsError {
		t.Fatal("expected success result")
	}

	var got mcpJSResult
	if err := json.Unmarshal([]byte(mcpResultText(t, result)), &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	valueMap, ok := got.Value.(map[string]interface{})
	if !ok {
		t.Fatalf("value type = %T, want map", got.Value)
	}
	if valueMap["name"] != "alice" {
		t.Fatalf("value.name = %v, want alice", valueMap["name"])
	}
	if valueMap["count"] != float64(3) {
		t.Fatalf("value.count = %v, want 3", valueMap["count"])
	}
	if got.Output != "" {
		t.Fatalf("output = %q, want empty", got.Output)
	}
}

func TestMCPJSExecutionResultCapturesPrintOutput(t *testing.T) {
	state := testREPLForJS(t)

	result := mcpJSExecutionResult(context.Background(), state, `print("hello world")`)
	if result.IsError {
		t.Fatal("expected success result")
	}

	var got mcpJSResult
	if err := json.Unmarshal([]byte(mcpResultText(t, result)), &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if !strings.Contains(got.Output, "hello world") {
		t.Fatalf("output = %q, want 'hello world'", got.Output)
	}
}

func TestMCPJSExecutionResultHandlesErrors(t *testing.T) {
	state := testREPLForJS(t)

	result := mcpJSExecutionResult(context.Background(), state, `throw new Error("boom")`)
	if !result.IsError {
		t.Fatal("expected error result")
	}
	if got := mcpResultText(t, result); !strings.Contains(got, "boom") {
		t.Fatalf("error text = %q, want 'boom'", got)
	}
}

func TestMCPJSExecutionResultEmpty(t *testing.T) {
	state := testREPLForJS(t)

	result := mcpJSExecutionResult(context.Background(), state, `var x = 1`)
	if result.IsError {
		t.Fatal("expected success result")
	}

	got := mcpResultText(t, result)
	if got != "{}" {
		t.Fatalf("text = %q, want empty JSON object", got)
	}
}

func TestMCPJSExecutionResultValueAndOutputTogether(t *testing.T) {
	state := testREPLForJS(t)

	result := mcpJSExecutionResult(context.Background(), state, `print("side effect"); 42`)
	if result.IsError {
		t.Fatal("expected success result")
	}

	var got mcpJSResult
	if err := json.Unmarshal([]byte(mcpResultText(t, result)), &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if got.Value != float64(42) {
		t.Fatalf("value = %v, want 42", got.Value)
	}
	if !strings.Contains(got.Output, "side effect") {
		t.Fatalf("output = %q, want 'side effect'", got.Output)
	}
}

func TestEmbeddedUserJSAPIContent(t *testing.T) {
	content := docassets.UserJSAPI
	if content == "" {
		t.Fatal("embedded USER_JSAPI.md is empty")
	}
	if !strings.Contains(content, "JavaScript API Reference") {
		t.Fatal("embedded content missing expected header")
	}
}

func TestEmbeddedUserMCPManualContent(t *testing.T) {
	content := docassets.UserMCPManual
	if content == "" {
		t.Fatal("embedded USER_MCP_MANUAL.md is empty")
	}
	if !strings.Contains(content, "apshell MCP Manual") {
		t.Fatal("embedded content missing expected header")
	}
}

func TestBundledDocsListAndFetch(t *testing.T) {
	entries := listDocs("")
	if len(entries) == 0 {
		t.Fatal("expected embedded curated docs in listing")
	}
	found := false
	for _, e := range entries {
		if e.Name == "WP_CORRIDORS" {
			found = true
			if e.Description == "" {
				t.Fatal("WP_CORRIDORS missing description in listing")
			}
		}
	}
	if !found {
		t.Fatal("WP_CORRIDORS not present in curated doc listing")
	}

	for _, name := range []string{"WP_CORRIDORS", "WP_CORRIDORS.md"} {
		content, err := readDoc("", name)
		if err != nil {
			t.Fatalf("readDoc(%q) error = %v", name, err)
		}
		if !strings.Contains(content, "CORRIDOR") {
			t.Fatalf("readDoc(%q) returned unexpected content", name)
		}
	}

	for _, bad := range []string{"", "../secret", "a/b", "DOES_NOT_EXIST"} {
		if _, err := readDoc("", bad); err == nil {
			t.Fatalf("readDoc(%q) expected error, got nil", bad)
		}
	}
}

func TestSaveJSScriptAndListJSScripts(t *testing.T) {
	dataDir := t.TempDir()
	scriptsDir := filepath.Join(dataDir, "scripts")
	helloPath := "hello"
	otherPath := filepath.Join(scriptsDir, "other.js")

	dest, err := saveJSScript(dataDir, helloPath, `print("hi")`, false)
	if err != nil {
		t.Fatalf("saveJSScript() error = %v", err)
	}
	if dest != filepath.Join(scriptsDir, "hello.js") {
		t.Fatalf("dest = %q, want %q", dest, filepath.Join(scriptsDir, "hello.js"))
	}

	// Second save without overwrite should fail.
	if _, err := saveJSScript(dataDir, helloPath, `print("again")`, false); err == nil {
		t.Fatal("saveJSScript() expected error on existing file without overwrite")
	}

	// Save with overwrite should succeed.
	if _, err := saveJSScript(dataDir, helloPath, `print("again")`, true); err != nil {
		t.Fatalf("saveJSScript(overwrite) error = %v", err)
	}

	// A second script should appear in the list.
	if _, err := saveJSScript(dataDir, otherPath, `print("other")`, false); err != nil {
		t.Fatalf("saveJSScript(other) error = %v", err)
	}

	entries, err := listJSScripts(dataDir)
	if err != nil {
		t.Fatalf("listJSScripts() error = %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %d, want 2 (%v)", len(entries), entries)
	}
	if entries[0].Name != "hello.js" || entries[1].Name != "other.js" {
		t.Fatalf("sort order = %v, want %q then %q", entries, "hello.js", "other.js")
	}
	if entries[0].Size == 0 {
		t.Fatalf("entries[0].Size = 0, want >0")
	}
}

func TestSaveJSScriptRejectsRelativePathWithSlashAndAcceptsAbsolutePath(t *testing.T) {
	dataDir := t.TempDir()

	if _, err := saveJSScript(dataDir, "hello.js", `print("hi")`, false); err != nil {
		t.Fatalf("saveJSScript() bare filename error = %v", err)
	}
	if _, err := saveJSScript(dataDir, "nested/hello.js", `print("hi")`, false); err == nil {
		t.Fatal("saveJSScript() expected error for relative path with slash")
	}
	if _, err := saveJSScript(dataDir, filepath.Join(dataDir, "other", "hello.js"), `print("hi")`, false); err != nil {
		t.Fatalf("saveJSScript() absolute path outside scripts dir error = %v", err)
	}
}

func TestListJSScriptsMissingDirectory(t *testing.T) {
	entries, err := listJSScripts(t.TempDir())
	if err != nil {
		t.Fatalf("listJSScripts() error = %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("entries = %v, want empty", entries)
	}
}

func TestParseUint64RejectsOverflow(t *testing.T) {
	if _, err := parseUint64("18446744073709551616"); err == nil {
		t.Fatal("expected overflow error")
	}
}

func mcpResultText(t *testing.T, result *mcp.CallToolResult) string {
	t.Helper()
	if len(result.Content) != 1 {
		t.Fatalf("content length = %d, want 1", len(result.Content))
	}
	text, ok := result.Content[0].(mcp.TextContent)
	if !ok {
		t.Fatalf("content type = %T, want mcp.TextContent", result.Content[0])
	}
	return text.Text
}
