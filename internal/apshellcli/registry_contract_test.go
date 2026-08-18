// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"bytes"
	"io"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestBuiltInCommandAndAliasInventory(t *testing.T) {
	state := &REPLState{}
	registry := state.initCommandRegistry()

	gotNames := make([]string, 0, len(registry.All()))
	gotAliases := make(map[string]string)
	for _, cmd := range registry.All() {
		gotNames = append(gotNames, cmd.Name)
		for _, alias := range cmd.Aliases {
			resolved, ok := registry.Lookup(alias)
			if !ok {
				t.Fatalf("alias %q is not registered", alias)
			}
			gotAliases[alias] = resolved.Name
		}
	}
	sort.Strings(gotNames)

	wantNames := []string{
		"accounts", "alias", "app", "asa", "balance", "clear", "close",
		"config", "connect", "delete", "disconnect", "endpoints", "generate",
		"help", "holders", "info", "js", "jslist", "jssave", "keyreg", "keys",
		"keytypes", "network", "optin", "optout", "participation", "plugins",
		"quit", "rekey", "request-token", "script", "send", "sets", "sign",
		"simulate", "status", "sweep", "unrekey", "validate", "verbose", "write",
	}
	wantAliases := map[string]string{
		"bal":  "balance",
		"cls":  "clear",
		"exit": "quit",
		"h":    "help",
		"q":    "quit",
	}

	if !reflect.DeepEqual(gotNames, wantNames) {
		t.Fatalf("built-in command inventory changed\n got: %v\nwant: %v", gotNames, wantNames)
	}
	if !reflect.DeepEqual(gotAliases, wantAliases) {
		t.Fatalf("built-in alias inventory changed\n got: %#v\nwant: %#v", gotAliases, wantAliases)
	}
}

func TestConfigCommandCurrentlySplitsGlobalAndInjectedOutput(t *testing.T) {
	readPipe, writePipe, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() error = %v", err)
	}
	oldStdout := os.Stdout
	os.Stdout = writePipe
	t.Cleanup(func() {
		os.Stdout = oldStdout
		_ = readPipe.Close()
		_ = writePipe.Close()
	})

	var injected bytes.Buffer
	state := &REPLState{DataDir: t.TempDir()}
	state.SetOutput(&injected)
	if err := state.cmdConfig(nil, nil); err != nil {
		t.Fatalf("cmdConfig() error = %v", err)
	}

	os.Stdout = oldStdout
	if err := writePipe.Close(); err != nil {
		t.Fatalf("stdout pipe close error = %v", err)
	}
	direct, err := io.ReadAll(readPipe)
	if err != nil {
		t.Fatalf("stdout pipe read error = %v", err)
	}

	if !strings.Contains(string(direct), "Current Configuration:") {
		t.Fatalf("direct stdout = %q, want configuration display", direct)
	}
	if strings.Contains(injected.String(), "Current Configuration:") {
		t.Fatalf("injected output unexpectedly contains direct configuration display: %q", injected.String())
	}
	if got := injected.String(); got != "Note: Config is read-only. Edit config.yaml in the data directory manually.\n" {
		t.Fatalf("injected output = %q, want only read-only note", got)
	}
}
