// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/clientlog"
	"github.com/aplane-algo/aplane/internal/command"
	"github.com/aplane-algo/aplane/internal/config"
	pluginmanager "github.com/aplane-algo/aplane/internal/plugin/manager"
)

func TestSessionPromptMatchesInteractivePrompt(t *testing.T) {
	session, err := NewSession("testnet", config.DefaultConfig(), t.TempDir(), nil)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	defer session.Shutdown()

	got := session.Prompt()
	want := session.state.promptString()
	if got != want {
		t.Fatalf("Prompt() = %q, want %q", got, want)
	}
	if !strings.Contains(got, "\x1b[") || !strings.Contains(got, "\x1b[0m") {
		t.Fatalf("Prompt() = %q, want ANSI-styled interactive prompt", got)
	}
}

func TestSessionHistoryUsesApshellHistoryFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(home, ".apshell_history")
	if err := os.WriteFile(path, []byte("status\n\n network testnet \n"), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	session, err := NewSession("testnet", config.DefaultConfig(), t.TempDir(), nil)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	defer session.Shutdown()

	got := session.History()
	want := []string{"status", "network testnet"}
	if !slices.Equal(got, want) {
		t.Fatalf("History() = %#v, want %#v", got, want)
	}

	session.RecordHistory("balance")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !strings.HasSuffix(string(data), "balance\n") {
		t.Fatalf("history file = %q, want balance appended", string(data))
	}
}

func TestSessionStartupConnectSkipsWithoutDefaultEndpoint(t *testing.T) {
	session, err := NewSession("testnet", config.DefaultConfig(), t.TempDir(), nil)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	defer session.Shutdown()

	output, err := session.StartupConnect()
	if err != nil {
		t.Fatalf("StartupConnect() error = %v", err)
	}
	if output != "" {
		t.Fatalf("StartupConnect() output = %q, want no connection attempt without a default endpoint", output)
	}
}

func TestLogLevelCommand(t *testing.T) {
	session, err := NewSession("testnet", config.DefaultConfig(), t.TempDir(), nil)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	defer session.Shutdown()
	previous := clientlog.Level()
	t.Cleanup(func() { clientlog.SetLevel(previous) })
	clientlog.SetLevel(slog.LevelWarn)

	output, _, err := session.ExecuteLineCaptured("loglevel")
	if err != nil || !strings.Contains(output, "Log level: warn") {
		t.Fatalf("loglevel = %q, %v", output, err)
	}

	output, _, err = session.ExecuteLineCaptured("loglevel INFO")
	if err != nil || !strings.Contains(output, "Log level set to info") {
		t.Fatalf("loglevel INFO = %q, %v", output, err)
	}
	if clientlog.Level() != slog.LevelInfo {
		t.Fatalf("level = %v, want info", clientlog.Level())
	}

	for _, line := range []string{"loglevel loud", "loglevel info debug"} {
		_, _, err = session.ExecuteLineCaptured(line)
		if err == nil || !strings.Contains(err.Error(), "usage: loglevel [error|warn|info|debug]") {
			t.Fatalf("%s error = %v, want usage", line, err)
		}
		if clientlog.Level() != slog.LevelInfo {
			t.Fatalf("%s changed the level to %v", line, clientlog.Level())
		}
	}
}

func TestVerboseDoesNotChangeTheLogLevel(t *testing.T) {
	session, err := NewSession("testnet", config.DefaultConfig(), t.TempDir(), nil)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	defer session.Shutdown()
	previous := clientlog.Level()
	t.Cleanup(func() { clientlog.SetLevel(previous) })
	clientlog.SetLevel(slog.LevelWarn)

	if _, _, err := session.ExecuteLineCaptured("verbose on"); err != nil {
		t.Fatalf("verbose on: %v", err)
	}
	if clientlog.Level() != slog.LevelWarn {
		t.Fatalf("level = %v, verbose must stay separate", clientlog.Level())
	}
}

// Shutdown while a command runs, as apconsole does when it quits, cancels
// the command and returns only once it has unwound: the command's own
// cleanup still reads the session's state.
func TestSessionShutdownWaitsForTheCancelledCommand(t *testing.T) {
	session, err := NewSession("testnet", config.DefaultConfig(), t.TempDir(), nil)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	state := session.state
	started := make(chan struct{})
	var unwound atomic.Bool
	if err := state.CommandRegistry.Register(&command.Command{
		Name: "waits", Category: command.CategoryInfo, Automation: command.StructuredAutomation,
		Handler: command.NewInternalHandler(func([]string, interface{}) (command.Result, error) {
			close(started)
			<-state.commandContext().Done()
			time.Sleep(50 * time.Millisecond) // the command takes a moment to unwind
			unwound.Store(true)
			return nil, state.commandContext().Err()
		}),
	}); err != nil {
		t.Fatal(err)
	}

	panicked := make(chan any, 1)
	go func() {
		defer func() { panicked <- recover() }()
		_, _, _ = session.ExecuteLineCaptured("waits")
	}()
	<-started
	session.Shutdown()
	returnedAfterTheCommand := unwound.Load()
	if p := <-panicked; p != nil {
		t.Fatalf("the cancelled command panicked while it unwound: %v", p)
	}
	if !returnedAfterTheCommand {
		t.Fatal("Shutdown returned before the cancelled command had unwound")
	}
	if _, _, err := session.ExecuteLineCaptured("status"); err == nil || err.Error() != "apshell session is shut down" {
		t.Fatalf("a line after Shutdown returned %v, want the session shut down", err)
	}
}

// waitForFile waits for path to exist: a shell command in flight made it.
func waitForFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s never appeared", path)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A `!` command runs on the line's context: Shutdown, which cancels it,
// returns at once rather than when the shell command would have ended.
func TestSessionShutdownStopsAShellCommandInFlight(t *testing.T) {
	session, err := NewSession("testnet", config.DefaultConfig(), t.TempDir(), nil)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	started := filepath.Join(t.TempDir(), "started")
	returned := make(chan error, 1)
	go func() {
		_, _, err := session.ExecuteLineCaptured("!touch " + started + "; sleep 10")
		returned <- err
	}()
	waitForFile(t, started)

	begin := time.Now()
	session.Shutdown()
	if took := time.Since(begin); took > 2*time.Second {
		t.Fatalf("Shutdown took %v with a shell command in flight, want it stopped", took)
	}
	if err := <-returned; err == nil || !strings.Contains(err.Error(), "shell command stopped") {
		t.Fatalf("the shell command's line returned %v, want it stopped", err)
	}
}

// A plugin command runs on the line's context: cancelling the line, as the
// pane's Ctrl-C or Shutdown does, ends the plugin call at once and kills the
// plugin, which is still running the abandoned command, rather than waiting
// for the manifest's timeout.
func TestSessionCancelStopsAPluginCommandInFlight(t *testing.T) {
	for _, stop := range []string{"cancel", "shutdown"} {
		t.Run(stop, func(t *testing.T) {
			state, scripted := scriptedPluginShell(t, map[string]any{"_hang": true}) // the manifest's timeout is 5 s
			state.CommandRegistry = state.initCommandRegistry()
			session := &Session{state: state}
			returned := make(chan error, 1)
			go func() {
				_, _, err := session.ExecuteLineCaptured("wf go")
				returned <- err
			}()
			deadline := time.Now().Add(5 * time.Second)
			for len(scripted.executeCalls()) == 0 {
				if time.Now().After(deadline) {
					t.Fatal("the plugin was never called")
				}
				time.Sleep(10 * time.Millisecond)
			}

			begin := time.Now()
			if stop == "cancel" {
				session.Cancel()
				err := <-returned
				if err == nil || !strings.Contains(err.Error(), "context canceled") {
					t.Fatalf("the line returned %v, want the plugin call abandoned", err)
				}
				if running := state.App.Plugins.(*pluginmanager.Manager).GetRunningPlugins(); len(running) != 0 {
					t.Fatalf("plugins %v still running after the abandoned call", running)
				}
			} else {
				session.Shutdown()
				<-returned
			}
			if took := time.Since(begin); took > 2*time.Second {
				t.Fatalf("%s took %v with a plugin command in flight", stop, took)
			}
		})
	}
}

// The startup connect runs on a context Shutdown reaches: a connect waiting
// on an SSH handshake the node never answers ends with it, rather than at
// the handshake's 60 s timeout.
func TestSessionShutdownStopsTheStartupConnect(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan net.Conn, 1)
	go func() { // a node that takes the connection and never speaks SSH
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	dir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.Endpoints = config.ClientEndpointRegistry{Default: "node", Endpoints: map[string]config.ClientEndpointConfig{
		"node": {Role: config.ClientEndpointRoleSigner, URL: "ssh://" + listener.Addr().String(),
			IdentityFile: filepath.Join(dir, "id_ed25519"), KnownHostsPath: filepath.Join(dir, "known_hosts")},
	}}
	session, err := NewSession("testnet", cfg, t.TempDir(), nil)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	returned := make(chan error, 1)
	go func() {
		_, err := session.StartupConnect()
		returned <- err
	}()
	select {
	case conn := <-accepted:
		t.Cleanup(func() { _ = conn.Close() })
	case err := <-returned:
		t.Fatalf("StartupConnect() returned %v before reaching the node", err)
	case <-time.After(5 * time.Second):
		t.Fatal("StartupConnect() never reached the node")
	}

	begin := time.Now()
	session.Shutdown()
	if took := time.Since(begin); took > 2*time.Second {
		t.Fatalf("Shutdown took %v with the startup connect in its handshake", took)
	}
	if err := <-returned; err == nil {
		t.Fatal("the interrupted startup connect reported success")
	}
}

// A line that starts once Shutdown has begun is refused at once, without
// running: Shutdown's cancel found nothing to cancel, so a line that slipped
// in after it and took execMu first would run uncancelled while Shutdown
// waited for it.
func TestSessionRefusesALineOnceShutdownBegins(t *testing.T) {
	session, err := NewSession("testnet", config.DefaultConfig(), t.TempDir(), nil)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	var ran atomic.Bool
	if err := session.state.CommandRegistry.Register(&command.Command{
		Name: "records", Category: command.CategoryInfo, Automation: command.StructuredAutomation,
		Handler: command.NewInternalHandler(func([]string, interface{}) (command.Result, error) {
			ran.Store(true)
			return nil, nil
		}),
	}); err != nil {
		t.Fatal(err)
	}

	session.execMu.Lock() // a step that holds the session while Shutdown begins
	shutDown := make(chan struct{})
	go func() {
		session.Shutdown()
		close(shutDown)
	}()
	waitForShutdownToBegin(t, session)

	returned := make(chan error, 1)
	go func() {
		_, _, err := session.ExecuteLineCaptured("records")
		returned <- err
	}()
	var lineErr error
	refused := false
	select {
	case lineErr = <-returned:
		refused = true
	case <-time.After(time.Second):
	}
	session.execMu.Unlock()
	<-shutDown
	if !refused {
		lineErr = <-returned
	}
	if ran.Load() {
		t.Fatal("a line that started after Shutdown began ran")
	}
	if !refused {
		t.Fatalf("the line waited for the session, then returned %v, instead of being refused", lineErr)
	}
	if lineErr == nil || lineErr.Error() != "apshell session is shut down" {
		t.Fatalf("the line returned %v, want it refused", lineErr)
	}
}

func waitForShutdownToBegin(t *testing.T, session *Session) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !session.isClosing() {
		if time.Now().After(deadline) {
			t.Fatal("Shutdown never began")
		}
		time.Sleep(time.Millisecond)
	}
}

// Shutdown cancels every operation the session has begun, not only the
// latest: a running line, or one a second line queued behind, ends, so
// Shutdown does not wait on it.
func TestSessionShutdownCancelsEveryActiveLine(t *testing.T) {
	session, err := NewSession("testnet", config.DefaultConfig(), t.TempDir(), nil)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	state := session.state
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	if err := state.CommandRegistry.Register(&command.Command{
		Name: "waits", Category: command.CategoryInfo, Automation: command.StructuredAutomation,
		Handler: command.NewInternalHandler(func([]string, interface{}) (command.Result, error) {
			started <- struct{}{}
			select {
			case <-state.commandContext().Done():
			case <-release:
			}
			return nil, state.commandContext().Err()
		}),
	}); err != nil {
		t.Fatal(err)
	}

	go func() { _, _, _ = session.ExecuteLineCaptured("waits") }()
	<-started
	go func() { _, _, _ = session.ExecuteLineCaptured("waits") }() // queued behind the first
	waitForActiveLines(t, session, 2)

	shutDown := make(chan struct{})
	go func() {
		session.Shutdown()
		close(shutDown)
	}()
	select {
	case <-shutDown:
	case <-time.After(2 * time.Second):
		t.Fatal("Shutdown waited on the running line, which it never cancelled")
	}
}

func waitForActiveLines(t *testing.T, session *Session, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		session.activeMu.Lock()
		active := len(session.active)
		session.activeMu.Unlock()
		if active >= n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d line(s) active, want %d", active, n)
		}
		time.Sleep(time.Millisecond)
	}
}
