// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/clientlog"
	"github.com/aplane-algo/aplane/internal/config"
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
