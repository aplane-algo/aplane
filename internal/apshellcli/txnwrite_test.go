// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/config"
)

func testREPLForSimulate(t *testing.T) *REPLState {
	t.Helper()

	eng, err := newIsolatedTestEngine(t, "testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	repl := &REPLState{
		App:     apshellapp.New(eng, config.DefaultConfig(), t.TempDir()),
		DataDir: t.TempDir(),
	}
	repl.CommandRegistry = repl.initCommandRegistry()
	repl.SetOutput(&bytes.Buffer{})
	return repl
}

func executeSimulateForTest(r *REPLState, args []string) error {
	result, err := executeSimulate(r, args)
	if err != nil {
		return err
	}
	if terminal, ok := result.(interface{ terminalFailure() error }); ok {
		return terminal.terminalFailure()
	}
	return nil
}

func TestToggleSimulateRejectsNonTransactionCommands(t *testing.T) {
	repl := testREPLForSimulate(t)

	tests := [][]string{
		{"help"},
		{"js", "1", "+", "2"},
		{"jssave", "foo.js", "1"},
		{"jslist"},
	}

	for _, args := range tests {
		err := executeSimulateForTest(repl, args)
		if err == nil {
			t.Fatalf("toggleSimulate(%q) error = nil, want rejection", strings.Join(args, " "))
		}
		if !strings.Contains(err.Error(), "simulate only supports transaction commands") {
			t.Fatalf("toggleSimulate(%q) error = %q, want transaction-only message", strings.Join(args, " "), err)
		}
		if repl.app().IsSimulateEnabled() {
			t.Fatalf("toggleSimulate(%q) left simulate mode enabled", strings.Join(args, " "))
		}
	}
}

func TestToggleSimulateAllowsTransactionCommandPath(t *testing.T) {
	repl := testREPLForSimulate(t)

	err := executeSimulateForTest(repl, []string{"send"})
	if err == nil {
		t.Fatal("toggleSimulate(send) error = nil, want downstream send usage error")
	}
	if strings.Contains(err.Error(), "simulate only supports transaction commands") {
		t.Fatalf("toggleSimulate(send) unexpectedly rejected transaction command: %v", err)
	}
	if repl.app().IsSimulateEnabled() {
		t.Fatal("toggleSimulate(send) left simulate mode enabled")
	}
}

func TestToggleSimulateAllowsExternalPluginCommandPath(t *testing.T) {
	repl := testREPLForSimulate(t)

	err := executeSimulateForTest(repl, []string{"reti", "deposit"})
	if err == nil {
		t.Fatal("toggleSimulate(reti deposit) error = nil, want downstream plugin error")
	}
	if strings.Contains(err.Error(), "simulate only supports transaction commands") {
		t.Fatalf("toggleSimulate(reti deposit) unexpectedly rejected plugin command: %v", err)
	}
	if repl.app().IsSimulateEnabled() {
		t.Fatal("toggleSimulate(reti deposit) left simulate mode enabled")
	}
}
