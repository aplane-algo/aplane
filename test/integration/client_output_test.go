// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package integration_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/plugin/integrity"
	"github.com/aplane-algo/aplane/test/integration/harness"
)

// failingPlugin logs a reason and dies, as a plugin with a broken install does.
const failingPlugin = `#!/bin/sh
echo "cannot find module foo" >&2
exit 1
`

func installFailingPlugin(t *testing.T, clientDataDir string) {
	t.Helper()
	pluginDir := filepath.Join(clientDataDir, "plugins.available", "failing")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, "failing.sh"), []byte(failingPlugin), 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := fmt.Sprintf(`{"name": "failing", "version": "1.0.0", "description": "always fails",
 "executable": "./failing.sh", "commands": [{"name": "failing", "description": "fail", "usage": "failing"}],
 "networks": [%q], "timeout": 10, "manifest_format": "2.0"}`, harness.IntegrationNetwork())
	if err := os.WriteFile(filepath.Join(pluginDir, "manifest.json"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	checksums, err := integrity.GenerateChecksums(pluginDir, []string{"manifest.json", "failing.sh"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, "checksums.sha256"), []byte(checksums), 0o644); err != nil {
		t.Fatal(err)
	}
	activation := []byte("enabled_plugins:\n  - failing\n")
	if err := os.WriteFile(filepath.Join(clientDataDir, "plugins.yaml"), activation, 0o644); err != nil {
		t.Fatal(err)
	}
}

// requireJSONRPC fails unless a stdout line is a JSON-RPC message. Anything else
// on this stream breaks the MCP host's connection.
func requireJSONRPC(t *testing.T, line string) int {
	t.Helper()
	var message struct {
		JSONRPC string `json:"jsonrpc"`
		ID      *int   `json:"id"`
	}
	if err := json.Unmarshal([]byte(line), &message); err != nil {
		t.Fatalf("stdout carried something other than JSON-RPC: %q", line)
	}
	if message.JSONRPC != "2.0" {
		t.Fatalf("stdout line is not JSON-RPC 2.0: %q", line)
	}
	if message.ID == nil {
		return 0
	}
	return *message.ID
}

func awaitMCPResponse(t *testing.T, session *harness.MCPSession, id int) string {
	t.Helper()
	timeout := time.After(60 * time.Second)
	for {
		select {
		case line, ok := <-session.Lines():
			if !ok {
				t.Fatalf("stdout closed while waiting for response %d", id)
			}
			if requireJSONRPC(t, line) == id {
				return line
			}
		case <-timeout:
			t.Fatalf("timed out waiting for response %d", id)
		}
	}
}

func mcpExecute(id int, command string) string {
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"execute","arguments":{"command":%q}}}`, id, command)
}

// TestMCPStdoutStaysJSONRPCThroughAPluginFailure holds apshell --mcp to its transport
// contract through startup, an ordinary call, a failing plugin, and shutdown. It runs
// at info, so plugin output is being written the whole time.
func TestMCPStdoutStaysJSONRPCThroughAPluginFailure(t *testing.T) {
	env := harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{})
	writeCurrentKnownHosts(t, env.ClientDataDir, filepath.Join(env.SignerDataDir, ".ssh", "ssh_host_key.pub"))
	installFailingPlugin(t, env.ClientDataDir)

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	session, err := harness.NewApshellHarness(t).StartMCP()
	if err != nil {
		t.Fatalf("StartMCP() error = %v", err)
	}

	send := func(message string) {
		t.Helper()
		if err := session.Send(message); err != nil {
			t.Fatalf("send: %v", err)
		}
	}
	send(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`)
	awaitMCPResponse(t, session, 1)
	send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)

	send(mcpExecute(2, "status"))
	awaitMCPResponse(t, session, 2)

	send(mcpExecute(3, "failing"))
	failure := awaitMCPResponse(t, session, 3)
	// A plugin's failure is a normal tool result, not a transport error.
	if !strings.Contains(failure, `\"success\":false`) {
		t.Fatalf("plugin failure response = %q, want success:false in the result", failure)
	}

	send(mcpExecute(4, "status"))
	awaitMCPResponse(t, session, 4)

	stderr, err := session.Close(30 * time.Second)
	if err != nil {
		t.Logf("apshell --mcp exit: %v", err)
	}
	for line := range session.Lines() {
		requireJSONRPC(t, line)
	}
	if !strings.Contains(stderr, "[plugin failing stderr]") {
		t.Fatalf("stderr = %q, want the plugin's output in the host's log", stderr)
	}
}
