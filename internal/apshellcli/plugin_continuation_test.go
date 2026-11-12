// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/appresult"
	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/command"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/plugin/discovery"
	"github.com/aplane-algo/aplane/internal/plugin/jsonrpc"
	pluginmanager "github.com/aplane-algo/aplane/internal/plugin/manager"
	"github.com/aplane-algo/aplane/internal/plugin/manifest"
)

// scriptedPlugin answers each execute call with the next of its results and
// records the parameters it was called with.
type scriptedPlugin struct {
	mu      sync.Mutex
	results []map[string]any
	calls   []jsonrpc.ExecuteParams
}

func (p *scriptedPlugin) executeCalls() []jsonrpc.ExecuteParams {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]jsonrpc.ExecuteParams(nil), p.calls...)
}

func (p *scriptedPlugin) instance(t *testing.T, plugin *discovery.Plugin) *pluginmanager.Instance {
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
			var req struct {
				ID     any             `json:"id"`
				Method string          `json:"method"`
				Params json.RawMessage `json:"params"`
			}
			if err := dec.Decode(&req); err != nil {
				_ = clientToServerReader.Close()
				_ = serverToClientWriter.Close()
				return
			}
			result := map[string]any{"success": true, "version": "1.0.0"}
			if req.Method == jsonrpc.MethodExecute {
				var params jsonrpc.ExecuteParams
				_ = json.Unmarshal(req.Params, &params)
				p.mu.Lock()
				n := len(p.calls)
				p.calls = append(p.calls, params)
				p.mu.Unlock()
				result = map[string]any{"success": false, "message": "no scripted result left"}
				if n < len(p.results) {
					result = p.results[n]
				}
			}
			_ = enc.Encode(map[string]any{"jsonrpc": jsonrpc.Version, "id": req.ID, "result": result})
			if req.Method == jsonrpc.MethodShutdown {
				return
			}
		}
	}()
	return pluginmanager.NewTestInstanceForHooks(plugin, cmd, client, stdin, stdout, stderr, time.Now())
}

// scriptedPluginShell is a shell with one plugin, "workflow", whose command
// "wf" answers with results in order.
func scriptedPluginShell(t *testing.T, results ...map[string]any) (*REPLState, *scriptedPlugin) {
	t.Helper()
	eng, err := newIsolatedTestEngine(t, "testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	scripted := &scriptedPlugin{results: results}
	pm := pluginmanager.NewManager()
	var started []*pluginmanager.Instance
	pm.SetCachedPluginsForTest([]*discovery.Plugin{{
		Manifest: &manifest.Manifest{
			Name:     "workflow",
			Commands: []manifest.Command{{Name: "wf", Description: "a multi-step workflow"}},
			Timeout:  5,
		},
	}})
	pm.SetTestHooks(pluginmanager.TestHooks{
		StartPluginInstance: func(plugin *discovery.Plugin) (*pluginmanager.Instance, error) {
			inst := scripted.instance(t, plugin)
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
		AutoConfirm:     true,
	}
	state.App.Plugins = pm
	return state, scripted
}

func runScript(t *testing.T, state *REPLState, code string) (string, error) {
	t.Helper()
	state.ensureJSRunner()
	result, err := state.Scripts.Runner.RunWithContext(context.Background(), code)
	if err != nil {
		return "", err
	}
	value, _ := result.Value.(string)
	return value, nil
}

// plugin() follows a plugin's continuation, as the REPL and MCP do, and
// returns only after the last step, with that step's result. The
// continuation's command, arguments and context reach the plugin.
func TestJSPluginFollowsContinuations(t *testing.T) {
	state, scripted := scriptedPluginShell(t,
		map[string]any{
			"success": true, "message": "step 1",
			"continuation": map[string]any{"command": "wf", "args": []string{"_step2", "x"}, "context": map[string]any{"escrow": "E"}},
		},
		map[string]any{
			"success": true, "message": "step 2",
			"continuation": map[string]any{"command": "wf", "args": []string{"_step3"}},
		},
		map[string]any{"success": true, "message": "done", "data": map[string]any{"result": "ok"}},
	)

	out, err := runScript(t, state, `JSON.stringify(plugin("wf", "start"))`)
	if err != nil {
		t.Fatalf("plugin() error = %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("plugin() returned %q: %v", out, err)
	}
	if got["success"] != true || got["message"] != "done" || !reflect.DeepEqual(got["data"], map[string]any{"result": "ok"}) {
		t.Fatalf("plugin() = %v, want the last step's result (message done, data {result: ok})", got)
	}
	calls := scripted.executeCalls()
	if len(calls) != 3 {
		t.Fatalf("plugin executed %d step(s), want 3", len(calls))
	}
	if calls[1].Command != "wf" || !reflect.DeepEqual(calls[1].Args, []string{"_step2", "x"}) ||
		!reflect.DeepEqual(calls[1].Context.Continuation, map[string]any{"escrow": "E"}) {
		t.Fatalf("second step called with %+v, want the continuation's command, args and context", calls[1])
	}
	if calls[2].Command != "wf" || !reflect.DeepEqual(calls[2].Args, []string{"_step3"}) {
		t.Fatalf("third step called with %+v", calls[2])
	}
}

// An error in a step after the first is an error from plugin(), not a
// success that reports the first step.
func TestJSPluginErrorInALaterStepIsAnError(t *testing.T) {
	for name, step2 := range map[string]map[string]any{
		"invalid continuation": {"success": true, "continuation": map[string]any{"command": ""}},
		"transactions with success=false": {
			"success": false, "transactions": []map[string]any{{"type": "raw", "encoded": "AA=="}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			state, scripted := scriptedPluginShell(t,
				map[string]any{"success": true, "message": "step 1", "continuation": map[string]any{"command": "wf", "args": []string{"_step2"}}},
				step2,
			)
			_, err := runScript(t, state, `JSON.stringify(plugin("wf", "start"))`)
			if err == nil || !strings.Contains(err.Error(), "plugin() error") {
				t.Fatalf("plugin() error = %v, want the later step's failure as an error", err)
			}
			if got := len(scripted.executeCalls()); got != 2 {
				t.Fatalf("plugin executed %d step(s), want 2", got)
			}
		})
	}
}

// Once a step has submitted transactions, a later step that fails, is
// cancelled or reports failure is an error that names what was submitted.
// Before anything is submitted, a cancel or the plugin's failure is still a
// {success: false} result. A finished run reports every submitted ID.
func TestJSPluginOutcome(t *testing.T) {
	twoSteps := []appresult.PluginStep{{Message: "fund", TxIDs: []string{"T1"}}, {Message: "claim", TxIDs: []string{"T2", "T3"}}}
	later := errors.New("continuation failed: plugin crashed")
	tests := []struct {
		name        string
		pr          PluginResult
		runErr      error
		wantErr     []string
		wantSuccess bool
		wantMessage string
		wantData    any
	}{
		{name: "later step fails", pr: PluginResult{Plugin: appresult.Plugin{Steps: twoSteps[:1]}}, runErr: later,
			wantErr: []string{"continuation failed: plugin crashed", "earlier steps already submitted transaction(s) T1"}},
		{name: "later step cancelled", pr: PluginResult{Plugin: appresult.Plugin{Steps: twoSteps[:1]}}, runErr: errPluginTransactionCancelled,
			wantErr: []string{"transaction cancelled by user", "T1"}},
		{name: "last step reports failure", pr: PluginResult{Plugin: appresult.Plugin{Success: false, Message: "no counterparty", Steps: twoSteps[:1]}},
			wantErr: []string{"plugin reported failure: no counterparty", "T1"}},
		{name: "first step cancelled", runErr: errPluginTransactionCancelled,
			wantMessage: "Transaction cancelled by user"},
		{name: "first step fails", runErr: errors.New("not connected to signer"), wantErr: []string{"not connected to signer"}},
		{name: "plugin's own failure, nothing submitted", pr: PluginResult{Plugin: appresult.Plugin{Success: false, Message: "bad input"}},
			wantMessage: "bad input"},
		{name: "one step", pr: PluginResult{Plugin: appresult.Plugin{Success: true, Message: "ok", TxIDs: []string{"T1"},
			Data: map[string]any{"escrow": "E", "txids": "forged", "localSigners": []any{"X"}}}},
			wantSuccess: true, wantMessage: "ok", wantData: map[string]any{"escrow": "E", "txids": []string{"T1"}}},
		{name: "two steps", pr: PluginResult{Plugin: appresult.Plugin{Success: true, Message: "claimed", Steps: twoSteps}},
			wantSuccess: true, wantMessage: "claimed", wantData: map[string]any{"txids": []string{"T1", "T2", "T3"}, "steps": twoSteps}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			success, message, data, _, err := jsPluginOutcome(&tt.pr, tt.runErr)
			if len(tt.wantErr) > 0 {
				if err == nil {
					t.Fatalf("outcome = (%v, %q, %v), want an error", success, message, data)
				}
				for _, want := range tt.wantErr {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("error = %q, want it to contain %q", err, want)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("error = %v", err)
			}
			if success != tt.wantSuccess || message != tt.wantMessage {
				t.Fatalf("outcome = (%v, %q), want (%v, %q)", success, message, tt.wantSuccess, tt.wantMessage)
			}
			if tt.wantData != nil && !reflect.DeepEqual(data, tt.wantData) {
				t.Fatalf("data = %#v, want %#v", data, tt.wantData)
			}
		})
	}
}
