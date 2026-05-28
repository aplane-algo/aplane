// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"reflect"
	"testing"
)

func TestParseShellCommandPreservesQuotedNoteAndRawArgs(t *testing.T) {
	raw := `send 0.000001 algo from anonymous to whale note="stake with us at RETI, never lose rewards. weget.algo"`

	cmd, err := parseShellCommand(raw)
	if err != nil {
		t.Fatalf("parseShellCommand() error = %v", err)
	}

	wantArgs := []string{
		"0.000001",
		"algo",
		"from",
		"anonymous",
		"to",
		"whale",
		"note=stake with us at RETI, never lose rewards. weget.algo",
	}
	if cmd.Name != "send" {
		t.Fatalf("Name = %q, want send", cmd.Name)
	}
	if !reflect.DeepEqual(cmd.Args, wantArgs) {
		t.Fatalf("Args = %#v, want %#v", cmd.Args, wantArgs)
	}
	wantRawArgs := `0.000001 algo from anonymous to whale note="stake with us at RETI, never lose rewards. weget.algo"`
	if cmd.RawArgs != wantRawArgs {
		t.Fatalf("RawArgs = %q, want %q", cmd.RawArgs, wantRawArgs)
	}
}

func TestParseInputCommandUsesSharedShellParser(t *testing.T) {
	cmd, err := (&REPLState{}).parseInputCommand(`alias add "staking account" ADDR123`)
	if err != nil {
		t.Fatalf("parseInputCommand() error = %v", err)
	}

	wantArgs := []string{"add", "staking account", "ADDR123"}
	if cmd.Name != "alias" {
		t.Fatalf("Name = %q, want alias", cmd.Name)
	}
	if !reflect.DeepEqual(cmd.Args, wantArgs) {
		t.Fatalf("Args = %#v, want %#v", cmd.Args, wantArgs)
	}
}
