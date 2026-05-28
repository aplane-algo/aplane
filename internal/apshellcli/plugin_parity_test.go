// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Developers

package apshellcli

import (
	"encoding/json"
	"io"
	"os/exec"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/command"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/plugin/discovery"
	"github.com/aplane-algo/aplane/internal/plugin/jsonrpc"
	pluginmanager "github.com/aplane-algo/aplane/internal/plugin/manager"
	"github.com/aplane-algo/aplane/internal/plugin/manifest"
)

func TestPluginCommandAvailabilityMatchesShellAdapterAndMCP(t *testing.T) {
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	pm := pluginmanager.NewManager()
	var started []*pluginmanager.Instance
	pm.SetCachedPluginsForTest([]*discovery.Plugin{
		{
			Manifest: &manifest.Manifest{
				Name:     "plugin-a",
				Commands: []manifest.Command{{Name: "swap", Description: "swap command"}},
				Timeout:  1,
			},
		},
	})
	pm.SetTestHooks(pluginmanager.TestHooks{
		StartPluginInstance: func(plugin *discovery.Plugin) (*pluginmanager.Instance, error) {
			inst := newApshellResponsivePluginInstance(t, plugin)
			started = append(started, inst)
			return inst, nil
		},
		InitializePlugin: func(*pluginmanager.Instance) error { return nil },
	})
	t.Cleanup(func() {
		for _, inst := range started {
			inst.Stop()
		}
	})

	state := &REPLState{
		App:             apshellapp.New(eng, config.DefaultConfig(), t.TempDir()),
		CommandRegistry: command.NewRegistry(),
	}
	state.App.Plugins = pm

	adapter := &PluginExecutorAdapter{repl: state}
	gotCommands := adapter.ListPluginCommands()
	if len(gotCommands) != 1 || gotCommands[0] != "swap" {
		t.Fatalf("ListPluginCommands() = %#v, want [swap]", gotCommands)
	}
	for _, cmd := range gotCommands {
		if cmd == "lend" {
			t.Fatalf("unexpected absent plugin command %q present in shell adapter list", cmd)
		}
	}

	result, handled := mcpStructured(state, "swap", []string{"--fast"})
	if !handled {
		t.Fatal("mcpStructured() did not handle plugin command present in shell adapter list")
	}
	if result.IsError {
		t.Fatalf("mcpStructured() returned error: %s", mcpResultText(t, result))
	}

	var got map[string]any
	if err := json.Unmarshal([]byte(mcpResultText(t, result)), &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if got["plugin"] != "plugin-a" {
		t.Fatalf("plugin = %#v, want plugin-a", got["plugin"])
	}
	if got["message"] != "ok" {
		t.Fatalf("message = %#v, want ok", got["message"])
	}

	missing, handled := mcpStructured(state, "lend", nil)
	if handled {
		t.Fatalf("mcpStructured() unexpectedly handled absent plugin command: %s", mcpResultText(t, missing))
	}
}

func newApshellResponsivePluginInstance(t *testing.T, plugin *discovery.Plugin) *pluginmanager.Instance {
	t.Helper()

	cmd := exec.Command("sh", "-c", "cat >/dev/null")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe() error = %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe() error = %v", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatalf("StderrPipe() error = %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("cmd.Start() error = %v", err)
	}

	serverToClientReader, serverToClientWriter := io.Pipe()
	clientToServerReader, clientToServerWriter := io.Pipe()
	client := jsonrpc.NewClient(serverToClientReader, clientToServerWriter)
	client.Start()

	go func() {
		dec := json.NewDecoder(clientToServerReader)
		enc := json.NewEncoder(serverToClientWriter)
		for {
			var req map[string]any
			if err := dec.Decode(&req); err != nil {
				_ = clientToServerReader.Close()
				_ = serverToClientWriter.Close()
				return
			}

			method, _ := req["method"].(string)
			switch method {
			case jsonrpc.MethodExecute:
				_ = enc.Encode(map[string]any{
					"jsonrpc": jsonrpc.Version,
					"id":      req["id"],
					"result": map[string]any{
						"success": true,
						"message": "ok",
						"data": map[string]any{
							"localSigners": []any{"ADDR1"},
							"amount":       123,
						},
					},
				})
			case jsonrpc.MethodShutdown:
				_ = enc.Encode(map[string]any{
					"jsonrpc": jsonrpc.Version,
					"id":      req["id"],
					"result":  map[string]any{"success": true},
				})
				return
			default:
				_ = enc.Encode(map[string]any{
					"jsonrpc": jsonrpc.Version,
					"id":      req["id"],
					"result":  map[string]any{"success": true, "version": "1.0.0"},
				})
			}
		}
	}()

	return pluginmanager.NewTestInstanceForHooks(plugin, cmd, client, stdin, stdout, stderr, time.Now())
}
