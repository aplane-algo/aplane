// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestValidateFlagSpelling(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name: "long flags use double dash",
			args: []string{"--remote", "--client-data", "/tmp/apclient", "--version", "--print-manifest"},
		},
		{
			name: "short data dir flag remains single dash",
			args: []string{"-d", "/tmp/apsigner"},
		},
		{
			name: "short data dir flag accepts equals form",
			args: []string{"-d=/tmp/apsigner"},
		},
		{
			name:    "single dash long remote is rejected",
			args:    []string{"-remote"},
			wantErr: true,
		},
		{
			name:    "single dash long client data is rejected",
			args:    []string{"-client-data", "/tmp/apclient"},
			wantErr: true,
		},
		{
			name: "double dash stops spelling validation",
			args: []string{"--", "-remote"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateFlagSpelling(tt.args)
			if tt.wantErr && err == nil {
				t.Fatal("validateFlagSpelling() error = nil, want error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("validateFlagSpelling() error = %v, want nil", err)
			}
		})
	}
}

func TestCatalogCommandRejectsUsageBeforeCredentialOrConnection(t *testing.T) {
	var stderr bytes.Buffer
	code := runCatalogCommand("template", []string{"show", "example.v1"}, adminBatchGlobalOptions{}, adminBatchStreams{
		stdin: strings.NewReader("would-be-passphrase\n"), stdout: io.Discard, stderr: &stderr,
	})
	if code != 2 {
		t.Fatalf("code = %d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "--show-sensitive-template") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestAdminBatchPromptUsesOneReaderForPassphraseAndConfirmation(t *testing.T) {
	var stderr bytes.Buffer
	prompt := newAdminBatchPrompt(strings.NewReader("secret\nyes\n"), &stderr)
	secret, err := prompt.passphrase(true)
	if err != nil {
		t.Fatal(err)
	}
	if string(secret) != "secret" || !prompt.confirm("Proceed? ") {
		t.Fatalf("secret=%q confirmation=false", secret)
	}
}

func TestRemoteAdminBatchPromptIgnoresLocalEnvironment(t *testing.T) {
	t.Setenv("APSIGNER_PASSPHRASE", "ambient-local-secret")
	prompt := newAdminBatchPrompt(strings.NewReader("explicit-remote-secret\n"), io.Discard)
	secret, err := prompt.passphrase(true)
	if err != nil {
		t.Fatal(err)
	}
	if string(secret) != "explicit-remote-secret" {
		t.Fatalf("remote passphrase = %q", secret)
	}
}
