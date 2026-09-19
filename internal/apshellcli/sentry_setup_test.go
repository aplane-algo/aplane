// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/sentry/enrollment"
	"github.com/aplane-algo/aplane/internal/witness"
)

func TestParseSentrySetupArgs(t *testing.T) {
	options, err := parseSentrySetupArgs([]string{
		"add", "handoff.json", "--alias", "Field", "--endpoint", "ssh://Sentry.example:2223/path",
		"--sentry-port", "12270", "--replace", "--dry-run",
	})
	if err != nil {
		t.Fatal(err)
	}
	if options.path != "handoff.json" || options.request.Alias != "Field" ||
		options.request.URL != "ssh://Sentry.example:2223/path" || options.request.SignerPort != 12270 ||
		!options.replace || !options.request.DryRun {
		t.Fatalf("options = %#v", options)
	}
}

func TestParseSentrySetupArgsRejectsLocalPort(t *testing.T) {
	_, err := parseSentrySetupArgs([]string{
		"add", "handoff.json", "--alias", "field", "--local-port", "12271",
	})
	if err == nil || !strings.Contains(err.Error(), sentrySetupUsage) {
		t.Fatalf("parseSentrySetupArgs() error = %v, want usage error", err)
	}
}

func TestSentrySetupPasteRequiresInteractiveReader(t *testing.T) {
	state := &REPLState{AutoConfirm: true}
	_, err := state.cmdSentry([]string{"add", "--alias", "field", "--endpoint", "ssh://sentry.example"}, nil)
	if err == nil || !strings.Contains(err.Error(), "provide a file") {
		t.Fatalf("cmdSentry() error = %v, want file guidance", err)
	}
}

func TestReadSentrySetupPasteCapturesOneCompleteDocument(t *testing.T) {
	document := testCLIWitnessDocument(t)
	lines := strings.Split(strings.TrimSuffix(string(document), "\n"), "\n")
	lines = append(lines, "status")
	reads := 0
	state := &REPLState{
		Out: &bytes.Buffer{},
		LineReaderContext: func(context.Context) (string, error) {
			line := lines[reads]
			reads++
			return line, nil
		},
	}
	got, err := state.readSentrySetupPaste()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := enrollment.ParseArtifact(got); err != nil {
		t.Fatalf("captured document is invalid: %v", err)
	}
	if reads != len(lines)-1 {
		t.Fatalf("read %d lines, want %d; trailing command was consumed", reads, len(lines)-1)
	}
}

func TestSentrySetupScriptRejectsConflictingReplacement(t *testing.T) {
	dataDir := t.TempDir()
	if _, err := config.UpsertStoredClientEndpoint(dataDir, "field", config.ClientEndpointConfig{
		Role: config.ClientEndpointRoleSentry, URL: "ssh://old.example",
	}, true); err != nil {
		t.Fatal(err)
	}
	documentPath := filepath.Join(dataDir, "handoff.json")
	if err := os.WriteFile(documentPath, testCLIWitnessDocument(t), 0o600); err != nil {
		t.Fatal(err)
	}
	eng, err := newIsolatedTestEngine(t, "testnet")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadConfig(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	state := &REPLState{
		Out: &bytes.Buffer{}, App: apshellapp.New(eng, cfg, dataDir), DataDir: dataDir,
		Config: cfg, AutoConfirm: true, currentCommandCtx: context.Background(),
	}
	_, err = state.cmdSentry([]string{
		"add", documentPath, "--alias", "field", "--endpoint", "ssh://new.example", "--replace",
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "review the replacement in interactive apshell") {
		t.Fatalf("cmdSentry() error = %v, want script replacement rejection", err)
	}
	registry, _, err := config.LoadStoredClientEndpointRegistry(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if endpoint, _ := registry.Endpoint("field"); endpoint.URL != "ssh://old.example" {
		t.Fatalf("script replacement changed endpoint: %#v", endpoint)
	}
}

func TestReadSentrySetupPasteRejectsOversizedLine(t *testing.T) {
	state := &REPLState{
		Out: &bytes.Buffer{},
		LineReader: func() (string, error) {
			return `{"padding":"` + strings.Repeat("x", enrollment.MaxEnvelopeBytes) + `"}`, nil
		},
	}
	_, err := state.readSentrySetupPaste()
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("readSentrySetupPaste() error = %v, want size rejection", err)
	}
}

func TestReadSentrySetupPasteDrainsOversizedMultilineDocument(t *testing.T) {
	lines := []string{"{", `"padding":"` + strings.Repeat("x", enrollment.MaxEnvelopeBytes) + `"`, "}", "status"}
	reads := 0
	state := &REPLState{
		Out: &bytes.Buffer{},
		LineReader: func() (string, error) {
			line := lines[reads]
			reads++
			return line, nil
		},
	}
	_, err := state.readSentrySetupPaste()
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("readSentrySetupPaste() error = %v, want size rejection", err)
	}
	if reads != 3 {
		t.Fatalf("read %d lines, want 3; oversized document was not drained exactly", reads)
	}
}

func TestReadRequiredSetupValuePreservesCase(t *testing.T) {
	state := &REPLState{
		Out: &bytes.Buffer{},
		LineReader: func() (string, error) {
			return " ssh://Sentry.EXAMPLE/CaseSensitivePath ", nil
		},
	}
	got, err := state.readRequiredSetupValue("Endpoint: ")
	if err != nil {
		t.Fatal(err)
	}
	if got != "ssh://Sentry.EXAMPLE/CaseSensitivePath" {
		t.Fatalf("value = %q, want original case", got)
	}
}

func TestSentrySetupDryRunDoesNotWriteOrConnect(t *testing.T) {
	dataDir := t.TempDir()
	documentPath := filepath.Join(dataDir, "handoff.json")
	if err := os.WriteFile(documentPath, testCLIWitnessDocument(t), 0o600); err != nil {
		t.Fatal(err)
	}
	eng, err := newIsolatedTestEngine(t, "testnet")
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	var out bytes.Buffer
	state := &REPLState{
		Out: &out, App: apshellapp.New(eng, cfg, dataDir), DataDir: dataDir,
		Config: cfg, AutoConfirm: true, currentCommandCtx: context.Background(),
	}
	result, err := state.cmdSentry([]string{
		"add", documentPath, "--alias", "field", "--endpoint", "ssh://sentry.example", "--dry-run",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := result.RenderText(&out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "no files changed; no network or trust checks performed") {
		t.Fatalf("output = %q", out.String())
	}
	if _, err := os.Stat(config.GetClientEndpointsPath(dataDir)); !os.IsNotExist(err) {
		t.Fatalf("endpoints.yaml stat error = %v, want absent", err)
	}
}

func TestSentrySetupRefreshesREPLConfigBeforeVerificationFailure(t *testing.T) {
	dataDir := t.TempDir()
	documentPath := filepath.Join(dataDir, "handoff.json")
	if err := os.WriteFile(documentPath, testCLIWitnessDocument(t), 0o600); err != nil {
		t.Fatal(err)
	}
	eng, err := newIsolatedTestEngine(t, "testnet")
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	state := &REPLState{
		Out: &bytes.Buffer{}, App: apshellapp.New(eng, cfg, dataDir), DataDir: dataDir,
		Config: cfg, AutoConfirm: true, currentCommandCtx: context.Background(),
	}

	_, err = state.cmdSentry([]string{
		"add", documentPath, "--alias", "field", "--endpoint", "http://127.0.0.1:1",
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "automatic enrollment requires ssh://") {
		t.Fatalf("cmdSentry() error = %v, want missing direct-endpoint token error", err)
	}
	endpoint, ok := state.Config.Endpoints.Endpoint("field")
	if !ok || endpoint.URL != "http://127.0.0.1:1" {
		t.Fatalf("REPL endpoint after partial setup = %#v/%v, want persisted field endpoint", endpoint, ok)
	}
	if appEndpoint, appOK := state.App.Config.Endpoints.Endpoint("field"); !appOK || appEndpoint != endpoint {
		t.Fatalf("REPL and application config diverged: repl=%#v app=%#v/%v", endpoint, appEndpoint, appOK)
	}
}

func TestContextAwarePromptAdaptersReturnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	state := &REPLState{
		currentCommandCtx: ctx,
		LineReaderContext: func(ctx context.Context) (string, error) {
			<-ctx.Done()
			return "", ctx.Err()
		},
		HostKeyApprovalContext: func(ctx context.Context, _, _ string) (bool, error) {
			<-ctx.Done()
			return false, ctx.Err()
		},
	}
	if _, err := state.readInteractiveLine(); !errors.Is(err, context.Canceled) {
		t.Fatalf("readInteractiveLine() error = %v, want context.Canceled", err)
	}
	if _, err := buildHostKeyApproval(state)("host", "fingerprint"); !errors.Is(err, context.Canceled) {
		t.Fatalf("host approval error = %v, want context.Canceled", err)
	}
}

func testCLIWitnessDocument(t *testing.T) []byte {
	t.Helper()
	publicKey := bytes.Repeat([]byte{0x4a}, witness.Falcon1024PublicKeySize)
	keyID, err := witness.ID(witness.Falcon1024V1, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	reference, err := witness.NewPublicReference(witness.Falcon1024V1, keyID, hex.EncodeToString(publicKey))
	if err != nil {
		t.Fatal(err)
	}
	document, err := enrollment.MarshalWitness(reference)
	if err != nil {
		t.Fatal(err)
	}
	return document
}

func TestSentryStatusWorksWithoutSignerAndProjectsResults(t *testing.T) {
	dir := t.TempDir()
	eng, err := newIsolatedTestEngine(t, "testnet")
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	state := &REPLState{App: apshellapp.New(eng, cfg, dir), DataDir: dir, Config: cfg, AutoConfirm: true}
	result, err := state.cmdSentry([]string{"status"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := result.RenderText(&out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "No sentry connections") || !strings.Contains(out.String(), "Unavailable:") {
		t.Fatalf("status=%s", out.String())
	}
	if _, err := state.cmdSentry([]string{"status", "extra"}, nil); err == nil {
		t.Fatal("accepted extra argument")
	}
}
