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
	secret, err := catalogPassphrase("cosigner", []string{"import", "-", "lab"}, prompt, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if string(secret) != "local-secret" {
		t.Fatalf("passphrase = %q, want local environment value", secret)
	}
}

func TestCatalogPassphraseKeepsCosignerKeyStdinReserved(t *testing.T) {
	t.Setenv("APSIGNER_PASSPHRASE", "local-secret")
	prompt := newAdminBatchPrompt(strings.NewReader("cosigner-key-json"), io.Discard)
	secret, err := catalogPassphrase(
		"cosigner", []string{"import", "-", "lab"}, prompt, io.Discard,
	)
	if err != nil {
		t.Fatal(err)
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
	secret, err := catalogPassphrase("cosigner", []string{"import", "-", "lab"}, prompt, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if string(secret) != "local-terminal-secret" {
		t.Fatalf("passphrase = %q", secret)
	}
	// The terminal is closed once the passphrase is read.
	if err := tty.Close(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("closing the terminal again: %v, want it already closed", err)
	}
}

// An import reading its input from stdin takes the passphrase from the
// controlling terminal, whichever spelling of the command Run accepts, so the
// piped public key is never read as the passphrase. Any other command reads
// the passphrase from stdin.
func TestCatalogPassphraseReservesStdinForEveryImportSpelling(t *testing.T) {
	const pipedKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample client@example\n"
	tests := []struct {
		name         string
		command      string
		args         []string
		wantReserved bool
	}{
		{name: "clients label after", command: "clients", args: []string{"import", "-", "--label", "ops"}, wantReserved: true},
		{name: "clients label first", command: "clients", args: []string{"import", "--label", "ops", "-"}, wantReserved: true},
		{name: "clients label equals first", command: "clients", args: []string{"import", "--label=ops", "-"}, wantReserved: true},
		{name: "clients after double dash", command: "clients", args: []string{"import", "--", "-"}, wantReserved: true},
		{name: "cosigner", command: "cosigner", args: []string{"import", "-", "lab"}, wantReserved: true},
		{name: "source token from stdin", command: "source", args: []string{"token", "set", "default", "screening", "--token-stdin"}, wantReserved: true},
		{name: "source token prompted", command: "source", args: []string{"token", "set", "default", "screening"}},
		{name: "clients from file", command: "clients", args: []string{"import", "--label", "ops", "client.pub"}},
		{name: "cosigner named dash", command: "cosigner", args: []string{"import", "cosigner.json", "-"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("APSIGNER_PASSPHRASE", "")
			tty, err := os.CreateTemp(t.TempDir(), "tty")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tty.WriteString("terminal-secret\n"); err != nil {
				t.Fatal(err)
			}
			if _, err := tty.Seek(0, io.SeekStart); err != nil {
				t.Fatal(err)
			}
			originalOpen := openControllingTerminal
			openControllingTerminal = func() (*os.File, error) { return tty, nil }
			t.Cleanup(func() { openControllingTerminal = originalOpen })

			stdin := strings.NewReader(pipedKey)
			prompt := newAdminBatchPrompt(stdin, io.Discard)
			secret, err := catalogPassphrase(tt.command, tt.args, prompt, io.Discard)
			if err != nil {
				t.Fatal(err)
			}
			if !tt.wantReserved {
				if string(secret) != strings.TrimSpace(pipedKey) {
					t.Fatalf("passphrase = %q, want the stdin line", secret)
				}
				return
			}
			if string(secret) != "terminal-secret" {
				t.Fatalf("passphrase = %q, want the controlling terminal's", secret)
			}
			if stdin.Len() != len(pipedKey) {
				t.Fatalf("stdin read before the import: %d of %d bytes left", stdin.Len(), len(pipedKey))
			}
		})
	}
}

func TestCatalogPassphraseRejectsHeadlessLocalStdinImport(t *testing.T) {
	t.Setenv("APSIGNER_PASSPHRASE", "")
	originalOpen := openControllingTerminal
	openControllingTerminal = func() (*os.File, error) { return nil, errors.New("no terminal") }
	t.Cleanup(func() { openControllingTerminal = originalOpen })

	prompt := newAdminBatchPrompt(strings.NewReader("public-envelope"), io.Discard)
	secret, err := catalogPassphrase("cosigner", []string{"import", "-", "lab"}, prompt, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "APSIGNER_PASSPHRASE or a controlling terminal") {
		t.Fatalf("error = %v", err)
	}
	if secret != nil {
		t.Fatalf("secret=%q, want none", secret)
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

// A batch error, which can carry what the daemon sent, prints on one line
// with terminal controls and line breaks escaped.
func TestPrintBatchErrorEscapesDaemonText(t *testing.T) {
	var buf bytes.Buffer
	printBatchError(&buf, errors.New("archive entry escapes destination: ../\x1b[2J\nfake line"))
	if got, want := buf.String(), `apadmin: archive entry escapes destination: ../\x1b[2J\nfake line`+"\n"; got != want {
		t.Fatalf("printBatchError() = %q, want %q", got, want)
	}
}

// A malformed source token command is a usage error, refused before any
// passphrase prompt or connection; a token on the command line is refused.
func TestSourceTokenUsageErrorsExitTwoBeforeAnyPrompt(t *testing.T) {
	for _, args := range [][]string{
		{"token", "set", "default"},
		{"token", "set", "default", "screening", "tok-on-the-command-line"},
		{"token", "set", "default", "screening", "--token=tok-on-the-command-line"},
		{"token", "list", "a", "b"},
		{"tokens"},
	} {
		var stderr bytes.Buffer
		stdin := strings.NewReader("would-be-passphrase\n")
		code := runCatalogCommand("source", args, adminBatchGlobalOptions{}, adminBatchStreams{stdin: stdin, stdout: io.Discard, stderr: &stderr})
		if code != 2 || !strings.Contains(stderr.String(), "usage: apadmin source token") || stdin.Len() != len("would-be-passphrase\n") {
			t.Fatalf("source %v: code %d, stderr %q, %d stdin bytes read", args, code, stderr.String(), len("would-be-passphrase\n")-stdin.Len())
		}
		if strings.Contains(stderr.String(), "tok-on-the-command-line") {
			t.Fatalf("source %v: the usage error echoes the token: %q", args, stderr.String())
		}
	}
}

// The token prompt reads the line after the passphrase from the same reader,
// and names a token, not a passphrase, in its errors.
func TestAdminBatchPromptReadsTheTokenAfterThePassphrase(t *testing.T) {
	t.Setenv("APSIGNER_PASSPHRASE", "")
	prompt := newAdminBatchPrompt(strings.NewReader("store-secret\ntok-123\n\n"), io.Discard)
	passphrase, err := prompt.passphrase()
	if err != nil || string(passphrase) != "store-secret" {
		t.Fatalf("passphrase = %q, %v", passphrase, err)
	}
	token, err := prompt.token("Enter the token for source screening: ")
	if err != nil || string(token) != "tok-123" {
		t.Fatalf("token = %q, %v", token, err)
	}
	if _, err := prompt.token("Enter the token for source screening: "); err == nil || err.Error() != "token cannot be empty" {
		t.Fatalf("an empty token: %v", err)
	}
}
