// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"reflect"
	"sort"
	"testing"

	"github.com/aplane-algo/aplane/internal/command"
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
		"config", "connect", "cosigner", "delete", "disconnect", "endpoints", "enroll",
		"generate", "help", "holders", "info", "js", "jslist", "jssave", "keyreg", "keys",
		"keytypes", "loglevel", "network", "optin", "optout", "participation", "plugins",
		"quit", "rekey", "rotate", "script", "send", "sets", "sign",
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

func TestBuiltInAutomationDispositionInventory(t *testing.T) {
	state := &REPLState{}
	registry := state.initCommandRegistry()
	blocked := map[string]bool{
		"help": true, "config": true, "script": true, "js": true,
		"jssave": true, "jslist": true, "enroll": true, "cosigner": true,
		"clear": true, "quit": true,
	}
	for _, cmd := range registry.All() {
		want := command.AutomationStructured
		if blocked[cmd.Name] {
			want = command.AutomationBlocked
		}
		if cmd.Automation.Disposition != want {
			t.Errorf("command %q disposition = %v, want %v", cmd.Name, cmd.Automation.Disposition, want)
		}
		for _, alias := range cmd.Aliases {
			resolved, ok := registry.Lookup(alias)
			if !ok || resolved != cmd {
				t.Errorf("alias %q does not resolve to primary command %q", alias, cmd.Name)
			}
		}
	}
	if len(registry.All()) != len(builtInAutomationPolicies) {
		t.Fatalf("registered commands = %d, policy inventory = %d", len(registry.All()), len(builtInAutomationPolicies))
	}
}
