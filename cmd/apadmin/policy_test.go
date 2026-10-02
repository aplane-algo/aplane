// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/signerapp/policycmd"
)

func TestParsePolicyCommandGrammar(t *testing.T) {
	const keyID = "MYJZE3UF7G4JXR5STMQK5TSL5FNE7PE224BSKLZ2H4AJWJIPBEBQ"
	tests := []struct {
		name       string
		args       []string
		wantVerb   policycmd.Verb
		wantArgs   []string
		wantKey    string
		wantRescue bool
		wantErr    string
	}{
		{name: "verb required", wantErr: "requires a verb"},
		{name: "edit retired", args: []string{"edit"}, wantErr: "unknown policy command"},
		{name: "digest retired", args: []string{"digest"}, wantErr: "unknown policy command"},
		{name: "status", args: []string{"status"}, wantVerb: policycmd.VerbStatus},
		{name: "export key", args: []string{"export", "--key", keyID}, wantVerb: policycmd.VerbExport, wantKey: keyID},
		{name: "check files", args: []string{"check", "a.json", "b.json"}, wantVerb: policycmd.VerbCheck, wantArgs: []string{"a.json", "b.json"}},
		{name: "rescue apply", args: []string{"rescue", "apply", "policy.json"}, wantVerb: policycmd.VerbApply, wantArgs: []string{"policy.json"}, wantRescue: true},
		{name: "apply stdin", args: []string{"apply", "-"}, wantVerb: policycmd.VerbApply, wantArgs: []string{"-"}},
		{name: "remove keys", args: []string{"remove", keyID}, wantVerb: policycmd.VerbRemove, wantArgs: []string{keyID}},
		{name: "apply requires a file", args: []string{"apply"}, wantErr: "requires at least one policy file"},
		{name: "stdin must be alone", args: []string{"check", "-", "a.json"}, wantErr: "sole file"},
		{name: "remove requires a key", args: []string{"remove"}, wantErr: "requires at least one Witness Key ID"},
		{name: "key only for export", args: []string{"status", "--key", keyID}, wantErr: "--key applies only"},
		{name: "status takes no files", args: []string{"status", "a.json"}, wantErr: "takes no arguments"},
		{name: "retired flag", args: []string{"--check"}, wantErr: "is retired"},
		{name: "target retired", args: []string{"check", "--target", "signer", "a.json"}, wantErr: "is retired"},
		{name: "unknown verb", args: []string{"frobnicate"}, wantErr: "unknown policy command"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			command, rescue, err := parsePolicyCommand(tt.args, io.Discard)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("parsePolicyCommand() error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if command.Verb != tt.wantVerb || command.Key != tt.wantKey || rescue != tt.wantRescue ||
				strings.Join(command.Args, ",") != strings.Join(tt.wantArgs, ",") {
				t.Fatalf("command = %#v rescue=%t", command, rescue)
			}
		})
	}
}

func TestProductionAndTestmodeCommandCatalogsAreDisjoint(t *testing.T) {
	production := make(map[string]bool)
	for command, kind := range productionSubcommands {
		production[command] = true
		switch kind {
		case productionPolicy, productionCatalog, productionStore:
		default:
			t.Fatalf("production command %q has unroutable kind %d", command, kind)
		}
	}
	for _, command := range testModeCommandNames {
		if production[command] {
			t.Fatalf("command %q is both production and testmode-only", command)
		}
	}
	if !isProductionSubcommand([]string{"policy", "check"}) {
		t.Fatal("policy command did not reach production dispatch")
	}
}

func TestPolicyHelpDocumentsSecurityBoundaries(t *testing.T) {
	var stderr bytes.Buffer
	code := runPolicyCommand(context.Background(), []string{"--help"}, policyGlobalOptions{}, policyStreams{
		stdin: strings.NewReader(""), stdout: io.Discard, stderr: &stderr,
	})
	if code != 0 {
		t.Fatalf("runPolicyCommand() code = %d", code)
	}
	for _, want := range []string{"Online commands authenticate and unlock", "APSIGNER_PASSPHRASE", "IPC commands may read", "rescue commands"} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("help missing %q:\n%s", want, stderr.String())
		}
	}
}

func TestPolicyRescueRejectsOnlineTransportFlagsBeforeWork(t *testing.T) {
	t.Setenv("APPOLICY_PASSPHRASE", "")
	var stderr bytes.Buffer
	code := runPolicyCommand(context.Background(), []string{"rescue", "check", "policy.json"}, policyGlobalOptions{
		ipcPathPassed: true,
	}, policyStreams{stdin: strings.NewReader(""), stdout: io.Discard, stderr: &stderr})
	if code != 2 || !strings.Contains(stderr.String(), "rescue cannot use") {
		t.Fatalf("runPolicyCommand() code=%d stderr=%q", code, stderr.String())
	}
}

func TestPolicyRescueDataDirectoryFailureIsRuntimeError(t *testing.T) {
	t.Setenv("APPOLICY_PASSPHRASE", "")
	t.Setenv("APSIGNER_DATA", "")
	var stderr bytes.Buffer
	code := runPolicyCommand(context.Background(), []string{"rescue", "status"}, policyGlobalOptions{}, policyStreams{
		stdin: strings.NewReader(""), stdout: io.Discard, stderr: &stderr,
	})
	if code != 1 {
		t.Fatalf("runPolicyCommand() code=%d stderr=%q, want runtime failure code 1", code, stderr.String())
	}
}

func TestPolicyCommandRejectsRetiredPassphraseEnvironment(t *testing.T) {
	t.Setenv("APPOLICY_PASSPHRASE", "legacy")
	var stderr bytes.Buffer
	code := runPolicyCommand(context.Background(), []string{"status"}, policyGlobalOptions{}, policyStreams{
		stdin: strings.NewReader(""), stdout: io.Discard, stderr: &stderr,
	})
	if code != 2 || !strings.Contains(stderr.String(), "APPOLICY_PASSPHRASE is retired") {
		t.Fatalf("runPolicyCommand() code=%d stderr=%q", code, stderr.String())
	}
}
