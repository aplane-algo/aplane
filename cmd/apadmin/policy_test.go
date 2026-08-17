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
	"github.com/aplane-algo/aplane/internal/signerapp/policyeditor"
)

func TestParsePolicyCommandGrammar(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantVerb   policycmd.Verb
		wantTarget policyeditor.Target
		wantSource string
		wantRescue bool
		wantErr    string
	}{
		{name: "policy aliases edit", wantVerb: policycmd.VerbEdit, wantTarget: policyeditor.TargetAuto},
		{name: "online check file", args: []string{"check", "draft.yaml"}, wantVerb: policycmd.VerbCheck, wantTarget: policyeditor.TargetAuto, wantSource: "draft.yaml"},
		{name: "targeted rescue", args: []string{"rescue", "export", "--target", "sentry", "draft.yaml"}, wantVerb: policycmd.VerbExport, wantTarget: policyeditor.TargetSentry, wantSource: "draft.yaml", wantRescue: true},
		{name: "apply stdin", args: []string{"apply", "-"}, wantVerb: policycmd.VerbApply, wantTarget: policyeditor.TargetAuto, wantSource: "-"},
		{name: "apply requires source", args: []string{"apply"}, wantErr: "requires a YAML file"},
		{name: "retired flag", args: []string{"--check"}, wantErr: "is retired"},
		{name: "unknown verb", args: []string{"frobnicate"}, wantErr: "unknown policy command"},
		{name: "to-sentry rejects sentry target", args: []string{"to-sentry", "--target", "sentry"}, wantErr: "requires signer-policy input"},
		{name: "too many sources", args: []string{"check", "one.yaml", "two.yaml"}, wantErr: "at most one"},
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
			if command.Verb != tt.wantVerb || command.Target != tt.wantTarget || command.Source != tt.wantSource || rescue != tt.wantRescue {
				t.Fatalf("command = %#v rescue=%t", command, rescue)
			}
		})
	}
}

func TestProductionAndTestmodeCommandCatalogsAreDisjoint(t *testing.T) {
	production := make(map[string]bool)
	for _, command := range productionSubcommands {
		production[command] = true
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

func TestPolicyRescueRejectsOnlineTransportFlagsBeforeWork(t *testing.T) {
	t.Setenv("APPOLICY_PASSPHRASE", "")
	var stderr bytes.Buffer
	code := runPolicyCommand(context.Background(), []string{"rescue", "check", "draft.yaml"}, policyGlobalOptions{
		remote: true,
	}, policyStreams{stdin: strings.NewReader(""), stdout: io.Discard, stderr: &stderr})
	if code != 2 || !strings.Contains(stderr.String(), "rescue cannot use") {
		t.Fatalf("runPolicyCommand() code=%d stderr=%q", code, stderr.String())
	}
}

func TestPolicyCommandRejectsRetiredPassphraseEnvironment(t *testing.T) {
	t.Setenv("APPOLICY_PASSPHRASE", "legacy")
	var stderr bytes.Buffer
	code := runPolicyCommand(context.Background(), []string{"check"}, policyGlobalOptions{}, policyStreams{
		stdin: strings.NewReader(""), stdout: io.Discard, stderr: &stderr,
	})
	if code != 2 || !strings.Contains(stderr.String(), "APPOLICY_PASSPHRASE is retired") {
		t.Fatalf("runPolicyCommand() code=%d stderr=%q", code, stderr.String())
	}
}
