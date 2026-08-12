// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package manager

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/plugin/discovery"
	"github.com/aplane-algo/aplane/internal/plugin/jsonrpc"
	"github.com/aplane-algo/aplane/internal/plugin/manifest"
)

func TestFindByCommandRejectsDuplicateProviders(t *testing.T) {
	m := NewManager()
	m.cachedPlugins = []*discovery.Plugin{
		{
			Manifest: &manifest.Manifest{
				Name:     "plugin-a",
				Commands: []manifest.Command{{Name: "swap", Description: "a"}},
			},
		},
		{
			Manifest: &manifest.Manifest{
				Name:     "plugin-b",
				Commands: []manifest.Command{{Name: "swap", Description: "b"}},
			},
		},
	}

	_, err := m.FindByCommand("swap")
	if !errors.Is(err, ErrDuplicatePluginCommand) {
		t.Fatalf("FindByCommand() error = %v, want ErrDuplicatePluginCommand", err)
	}
}

func TestStartPluginDoesNotHoldManagerLockDuringStartup(t *testing.T) {
	m := NewManager()
	m.SetStderrWriter(io.Discard)
	m.cachedPlugins = []*discovery.Plugin{
		{
			Manifest: &manifest.Manifest{
				Name:     "plugin-a",
				Commands: []manifest.Command{{Name: "echo", Description: "echo"}},
			},
		},
	}
	m.startPluginInstanceHook = func(plugin *discovery.Plugin, cfg runtimeConfig) (*Instance, error) {
		_, _ = m.stderr().Write([]byte("startup banner\n"))
		return newTestPluginInstance(t), nil
	}
	m.initializePluginHook = func(instance *Instance, cfg runtimeConfig) error { return nil }

	done := make(chan error, 1)
	go func() {
		_, err := m.StartPlugin("plugin-a")
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("StartPlugin() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("StartPlugin() deadlocked while plugin startup read manager stderr state")
	}

	if err := m.StopPlugin("plugin-a"); err != nil {
		t.Fatalf("StopPlugin() error = %v", err)
	}
}

func TestStopPluginDoesNotHoldManagerLockDuringShutdown(t *testing.T) {
	m := NewManager()
	shutdownStarted := make(chan struct{})
	releaseShutdown := make(chan struct{})
	m.instances["plugin-a"] = newBlockingShutdownPluginInstance(t, shutdownStarted, releaseShutdown)

	stopDone := make(chan error, 1)
	go func() {
		stopDone <- m.StopPlugin("plugin-a")
	}()

	select {
	case <-shutdownStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("StopPlugin() did not start plugin shutdown")
	}

	runningDone := make(chan []string, 1)
	go func() {
		runningDone <- m.GetRunningPlugins()
	}()
	select {
	case running := <-runningDone:
		if len(running) != 0 {
			t.Fatalf("GetRunningPlugins() while stopping = %#v, want empty", running)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("GetRunningPlugins() blocked behind plugin shutdown")
	}

	close(releaseShutdown)
	select {
	case err := <-stopDone:
		if err != nil {
			t.Fatalf("StopPlugin() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("StopPlugin() did not finish after shutdown response")
	}
}

func TestStartPluginInitializationFailureDoesNotRetainStaleInstance(t *testing.T) {
	m := NewManager()
	m.cachedPlugins = []*discovery.Plugin{
		{
			Manifest: &manifest.Manifest{
				Name:     "plugin-a",
				Commands: []manifest.Command{{Name: "swap", Description: "a"}},
			},
		},
	}

	var started []*Instance
	m.startPluginInstanceHook = func(plugin *discovery.Plugin, cfg runtimeConfig) (*Instance, error) {
		inst := newTestPluginInstance(t)
		started = append(started, inst)
		return inst, nil
	}

	initCalls := 0
	m.initializePluginHook = func(instance *Instance, cfg runtimeConfig) error {
		initCalls++
		if initCalls == 1 {
			return errors.New("helper init failed")
		}
		return nil
	}

	_, err := m.StartPlugin("plugin-a")
	if err == nil || err.Error() != "failed to initialize plugin: helper init failed" {
		t.Fatalf("StartPlugin(fail-init) error = %v, want initialize failure", err)
	}
	if running := m.GetRunningPlugins(); len(running) != 0 {
		t.Fatalf("GetRunningPlugins() after failed init = %#v, want empty", running)
	}
	if _, exists := m.instances["plugin-a"]; exists {
		t.Fatal("failed plugin init should not retain instance in manager map")
	}
	if len(started) != 1 {
		t.Fatalf("started instances = %d, want 1 after first attempt", len(started))
	}
	waitForStoppedProcess(t, started[0].Process)

	inst, err := m.StartPlugin("plugin-a")
	if err != nil {
		t.Fatalf("StartPlugin(retry) error = %v", err)
	}
	if inst == nil || !inst.IsRunning() {
		t.Fatal("successful retry did not return a running instance")
	}
	if running := m.GetRunningPlugins(); len(running) != 1 || running[0] != "plugin-a" {
		t.Fatalf("GetRunningPlugins() after retry = %#v, want [plugin-a]", running)
	}

	if err := m.StopPlugin("plugin-a"); err != nil {
		t.Fatalf("StopPlugin() error = %v", err)
	}
	if running := m.GetRunningPlugins(); len(running) != 0 {
		t.Fatalf("GetRunningPlugins() after stop = %#v, want empty", running)
	}
}

func TestExecuteCommandProtocolFailureDoesNotPoisonSubsequentRetry(t *testing.T) {
	m := NewManager()
	m.cachedPlugins = []*discovery.Plugin{
		{
			Manifest: &manifest.Manifest{
				Name:     "plugin-a",
				Commands: []manifest.Command{{Name: "swap", Description: "a"}},
				Timeout:  1,
			},
		},
	}
	m.initializePluginHook = func(instance *Instance, cfg runtimeConfig) error { return nil }

	var started []*Instance
	attempt := 0
	m.startPluginInstanceHook = func(plugin *discovery.Plugin, cfg runtimeConfig) (*Instance, error) {
		attempt++
		var inst *Instance
		if attempt == 1 {
			inst = newClosedClientPluginInstance(t)
		} else {
			inst = newResponsivePluginInstance(t, func(req map[string]interface{}) map[string]interface{} {
				id := req["id"]
				return map[string]interface{}{
					"jsonrpc": jsonrpc.Version,
					"id":      id,
					"result": map[string]interface{}{
						"success": true,
						"message": "ok",
						"version": jsonrpc.PluginProtocolVersion,
					},
				}
			})
		}
		started = append(started, inst)
		return inst, nil
	}

	if _, err := m.ExecuteCommand("plugin-a", "swap", nil, jsonrpc.Context{}); err == nil || !errors.Is(err, jsonrpc.ErrConnectionClosed) {
		t.Fatalf("ExecuteCommand(first) error = %v, want connection closed", err)
	}
	if running := m.GetRunningPlugins(); len(running) != 0 {
		t.Fatalf("GetRunningPlugins() after failed execute = %#v, want empty", running)
	}
	if len(started) != 1 {
		t.Fatalf("started instances after failed execute = %d, want 1", len(started))
	}
	waitForStoppedProcess(t, started[0].Process)

	result, err := m.ExecuteCommand("plugin-a", "swap", nil, jsonrpc.Context{})
	if err != nil {
		t.Fatalf("ExecuteCommand(retry) error = %v", err)
	}
	if result == nil || !result.Success || result.Message != "ok" {
		t.Fatalf("ExecuteCommand(retry) result = %#v, want success/ok", result)
	}
	if attempt != 2 {
		t.Fatalf("startPluginInstanceHook attempts = %d, want 2", attempt)
	}

	if err := m.StopPlugin("plugin-a"); err != nil {
		t.Fatalf("StopPlugin() error = %v", err)
	}
}

func TestInitializePluginRequiresSupportedProtocolVersion(t *testing.T) {
	tests := []struct {
		name        string
		echoVersion string
		wantErr     string
	}{
		{name: "supported", echoVersion: jsonrpc.PluginProtocolVersion},
		{name: "missing", echoVersion: "", wantErr: `unsupported plugin protocol version ""`},
		{name: "mismatch", echoVersion: "1.0", wantErr: `unsupported plugin protocol version "1.0"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seenVersion := make(chan string, 1)
			inst := newResponsivePluginInstance(t, func(req map[string]interface{}) map[string]interface{} {
				params, _ := req["params"].(map[string]interface{})
				version, _ := params["version"].(string)
				seenVersion <- version
				result := map[string]interface{}{
					"success": true,
					"message": "ok",
				}
				if tt.echoVersion != "" {
					result["version"] = tt.echoVersion
				}
				return map[string]interface{}{
					"jsonrpc": jsonrpc.Version,
					"id":      req["id"],
					"result":  result,
				}
			})
			defer inst.Stop()

			err := NewManager().initializePlugin(inst, runtimeConfig{network: "testnet"})
			if got := <-seenVersion; got != jsonrpc.PluginProtocolVersion {
				t.Fatalf("initialize version = %q, want %q", got, jsonrpc.PluginProtocolVersion)
			}
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("initializePlugin() error = %v, want nil", err)
				}
				return
			}
			if err == nil || !bytes.Contains([]byte(err.Error()), []byte(tt.wantErr)) {
				t.Fatalf("initializePlugin() error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func newTestPluginInstance(t *testing.T) *Instance {
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

	reader, writer := io.Pipe()
	_ = writer.Close()
	client := jsonrpc.NewClient(reader, &bytes.Buffer{})
	client.Start()

	return &Instance{
		Plugin: &discovery.Plugin{
			Manifest: &manifest.Manifest{Name: "plugin-a", Timeout: 1},
		},
		Process: cmd,
		Client:  client,
		stdin:   stdin,
		stdout:  stdout,
		stderr:  stderr,
		Started: time.Now(),
	}
}

func newClosedClientPluginInstance(t *testing.T) *Instance {
	t.Helper()

	inst := newTestPluginInstance(t)
	reader, writer := io.Pipe()
	_ = writer.Close()
	inst.Client = jsonrpc.NewClient(reader, &bytes.Buffer{})
	inst.Client.Start()
	return inst
}

func newResponsivePluginInstance(t *testing.T, respond func(req map[string]interface{}) map[string]interface{}) *Instance {
	t.Helper()

	inst := newTestPluginInstance(t)

	serverToClientReader, serverToClientWriter := io.Pipe()
	clientToServerReader, clientToServerWriter := io.Pipe()
	inst.Client = jsonrpc.NewClient(serverToClientReader, clientToServerWriter)
	inst.Client.Start()

	go func() {
		dec := json.NewDecoder(clientToServerReader)
		enc := json.NewEncoder(serverToClientWriter)
		for {
			var req map[string]interface{}
			if err := dec.Decode(&req); err != nil {
				_ = clientToServerReader.Close()
				_ = serverToClientWriter.Close()
				return
			}
			resp := respond(req)
			if err := enc.Encode(resp); err != nil {
				return
			}
		}
	}()

	return inst
}

func newBlockingShutdownPluginInstance(t *testing.T, shutdownStarted chan<- struct{}, releaseShutdown <-chan struct{}) *Instance {
	t.Helper()

	serverToClientReader, serverToClientWriter := io.Pipe()
	clientToServerReader, clientToServerWriter := io.Pipe()
	inst := &Instance{
		Plugin: &discovery.Plugin{
			Manifest: &manifest.Manifest{Name: "plugin-a", Timeout: 1},
		},
		Client:  jsonrpc.NewClient(serverToClientReader, clientToServerWriter),
		Started: time.Now(),
	}
	inst.Client.Start()

	go func() {
		dec := json.NewDecoder(clientToServerReader)
		enc := json.NewEncoder(serverToClientWriter)
		var req map[string]interface{}
		if err := dec.Decode(&req); err != nil {
			_ = clientToServerReader.Close()
			_ = serverToClientWriter.Close()
			return
		}
		if method, _ := req["method"].(string); method == jsonrpc.MethodShutdown {
			close(shutdownStarted)
			<-releaseShutdown
		}
		_ = enc.Encode(map[string]interface{}{
			"jsonrpc": jsonrpc.Version,
			"id":      req["id"],
			"result": map[string]interface{}{
				"success": true,
				"message": "ok",
			},
		})
		_ = clientToServerReader.Close()
		_ = serverToClientWriter.Close()
	}()

	return inst
}

func waitForStoppedProcess(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("plugin process did not stop after failed initialization cleanup")
}
