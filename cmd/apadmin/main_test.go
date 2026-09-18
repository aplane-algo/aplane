// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/protocol"
)

func TestCatalogPassphraseKeepsEnvelopeStdinReserved(t *testing.T) {
	t.Setenv("APSIGNER_PASSPHRASE", "local-secret")
	prompt := newAdminBatchPrompt(strings.NewReader("public-envelope"), io.Discard)
	secret, closer, err := catalogPassphrase("sentry", []string{"import", "-", "lab"}, prompt, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if closer != nil {
		t.Fatal("catalogPassphrase() returned a terminal closer while using the local environment")
	}
	if string(secret) != "local-secret" {
		t.Fatalf("passphrase = %q, want local environment value", secret)
	}
}

func TestCatalogPassphraseKeepsEnrollmentBundleStdinReserved(t *testing.T) {
	t.Setenv("APSIGNER_PASSPHRASE", "local-secret")
	prompt := newAdminBatchPrompt(strings.NewReader("enrollment-bundle"), io.Discard)
	secret, closer, err := catalogPassphrase(
		"sentry", []string{"enrollment", "import", "-", "--name", "lab"}, prompt, io.Discard,
	)
	if err != nil {
		t.Fatal(err)
	}
	if closer != nil {
		t.Fatal("catalogPassphrase() returned a terminal closer while using the local environment")
	}
	if string(secret) != "local-secret" {
		t.Fatalf("passphrase = %q, want local environment value", secret)
	}
}

func TestCatalogPassphraseUsesControllingTerminalForLocalStdinImport(t *testing.T) {
	t.Setenv("APSIGNER_PASSPHRASE", "")
	tty, err := os.CreateTemp(t.TempDir(), "tty")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tty.WriteString("local-terminal-secret\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := tty.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	originalOpen := openControllingTerminal
	openControllingTerminal = func() (*os.File, error) { return tty, nil }
	t.Cleanup(func() { openControllingTerminal = originalOpen })

	prompt := newAdminBatchPrompt(strings.NewReader("public-envelope"), io.Discard)
	secret, closer, err := catalogPassphrase("sentry", []string{"import", "-", "lab"}, prompt, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if closer == nil {
		t.Fatal("catalogPassphrase() did not return the controlling terminal closer")
	}
	if string(secret) != "local-terminal-secret" {
		t.Fatalf("passphrase = %q", secret)
	}
	_ = closer.Close()
}

func TestCatalogPassphraseRejectsHeadlessLocalStdinImport(t *testing.T) {
	t.Setenv("APSIGNER_PASSPHRASE", "")
	originalOpen := openControllingTerminal
	openControllingTerminal = func() (*os.File, error) { return nil, errors.New("no terminal") }
	t.Cleanup(func() { openControllingTerminal = originalOpen })

	prompt := newAdminBatchPrompt(strings.NewReader("public-envelope"), io.Discard)
	secret, closer, err := catalogPassphrase("sentry", []string{"import", "-", "lab"}, prompt, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "APSIGNER_PASSPHRASE or a controlling terminal") {
		t.Fatalf("error = %v", err)
	}
	if secret != nil || closer != nil {
		t.Fatalf("secret=%q closer=%v, want neither", secret, closer)
	}
}

func TestValidateFlagSpelling(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name: "long flags use double dash",
			args: []string{"--ipc-path", "/tmp/aplane.sock", "--version", "--print-manifest"},
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
	secret, err := prompt.passphrase()
	if err != nil {
		t.Fatal(err)
	}
	if string(secret) != "secret" || !prompt.confirm("Proceed? ") {
		t.Fatalf("secret=%q confirmation=false", secret)
	}
}

func TestCommandSecretDoesNotReuseAdminPassphraseEnvironment(t *testing.T) {
	t.Setenv("APSIGNER_PASSPHRASE", "admin-secret")
	prompt := newAdminBatchPrompt(strings.NewReader("archive-secret\n"), io.Discard)
	secret, err := prompt.secret("Archive passphrase: ", false)
	if err != nil {
		t.Fatal(err)
	}
	if string(secret) != "archive-secret" {
		t.Fatalf("command secret = %q", secret)
	}
}

func TestAdminBatchPromptRejectsEmptySecretBeforeCommand(t *testing.T) {
	prompt := newAdminBatchPrompt(strings.NewReader("\n"), io.Discard)
	if _, err := prompt.secret("Archive passphrase: ", false); err == nil || !strings.Contains(err.Error(), "cannot be empty") {
		t.Fatalf("secret() error = %v, want empty-passphrase rejection", err)
	}
}

func TestChangePassphraseCancellationUsesExplicitInputAndNeverConnects(t *testing.T) {
	t.Setenv("APSIGNER_PASSPHRASE", "ambient-must-not-be-used")
	var stderr bytes.Buffer
	code := runStoreCommand("changepass", nil, adminBatchGlobalOptions{}, adminBatchStreams{
		stdin: strings.NewReader("current\nnew\nnew\nno\n"), stdout: io.Discard, stderr: &stderr,
	})
	if code != 0 || !strings.Contains(stderr.String(), "cancelled") {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
}

func TestChangePassphraseRejectsEqualSecretBeforeConnection(t *testing.T) {
	var stderr bytes.Buffer
	code := runStoreCommand("changepass", nil, adminBatchGlobalOptions{}, adminBatchStreams{
		stdin: strings.NewReader("same\nsame\nsame\n"), stdout: io.Discard, stderr: &stderr,
	})
	if code != 1 || !strings.Contains(stderr.String(), "must be different") {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
}

func TestAdminBatchExitCodeUsesStructuredProtocolCode(t *testing.T) {
	for _, test := range []struct {
		code string
		want int
	}{
		{protocol.ErrCodeAuthenticationFailed, 3},
		{protocol.ResultCodeRestoreRateLimited, 4},
		{protocol.ResultCodeKeyTypeInUse, 5},
		{"verification_failed", 6},
	} {
		err := protocol.WithCode(test.code, fmt.Errorf("opaque failure"))
		if got := adminBatchExitCode(err); got != test.want {
			t.Fatalf("code %q mapped to %d, want %d", test.code, got, test.want)
		}
	}
}
