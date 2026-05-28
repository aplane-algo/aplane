// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

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

func TestSessionStartupConnectReportsMissingToken(t *testing.T) {
	session, err := NewSession("testnet", config.DefaultConfig(), t.TempDir(), nil)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	defer session.Shutdown()

	output, err := session.StartupConnect()
	if err != nil {
		t.Fatalf("StartupConnect() error = %v", err)
	}
	if !strings.Contains(output, missingAplaneTokenStartupMessage) {
		t.Fatalf("StartupConnect() output = %q, want missing token message", output)
	}
	if strings.Contains(output, "Verifying Signer") {
		t.Fatalf("StartupConnect() output = %q, should not attempt connect without token", output)
	}
}
