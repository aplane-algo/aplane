// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/cosigner/enrollment"
	"github.com/aplane-algo/aplane/internal/witness"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

func TestParseEndpointsAddArgs(t *testing.T) {
	options, err := parseEndpointsAddArgs([]string{
		"handoff.json", "--alias", "Field", "--endpoint", "ssh://Cosigner.example:2223/path",
		"--cosigner-port", "12270", "--replace", "--dry-run",
	})
	if err != nil {
		t.Fatal(err)
	}
	if options.path != "handoff.json" || options.request.Alias != "Field" ||
		options.request.URL != "ssh://Cosigner.example:2223/path" || options.request.SignerPort != 12270 ||
		!options.replace || !options.request.DryRun {
		t.Fatalf("options = %#v", options)
	}
}

func TestParseEndpointsAddArgsRejectsLocalPort(t *testing.T) {
	_, err := parseEndpointsAddArgs([]string{
		"handoff.json", "--alias", "field", "--local-port", "12271",
	})
	if err == nil || !strings.Contains(err.Error(), endpointsAddUsage) {
		t.Fatalf("parseEndpointsAddArgs() error = %v, want usage error", err)
	}
}

func TestEndpointsAddPasteRequiresInteractiveReader(t *testing.T) {
	state := &REPLState{AutoConfirm: true, Out: &bytes.Buffer{}}
	_, err := state.runEndpointsAdd([]string{"--alias", "field"})
	if err == nil || !strings.Contains(err.Error(), "provide a file or --endpoint") {
		t.Fatalf("runEndpointsAdd() error = %v, want file guidance", err)
	}
}

func TestReadCosignerSetupPasteCapturesOneCompleteDocument(t *testing.T) {
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
	got, err := state.readCosignerSetupPaste()
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

func TestCosignerSetupScriptRejectsConflictingReplacement(t *testing.T) {
	dataDir := t.TempDir()
	if _, err := config.UpsertStoredClientEndpoint(dataDir, "field", config.ClientEndpointConfig{
		Role: config.ClientEndpointRoleCosigner, URL: "ssh://old.example",
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
		AutoConfirm: true, currentCommandCtx: context.Background(),
	}
	_, err = state.cmdCosigner([]string{
		"add", documentPath, "--alias", "field", "--endpoint", "ssh://new.example", "--replace",
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "review the replacement in interactive apshell") {
		t.Fatalf("cmdCosigner() error = %v, want script replacement rejection", err)
	}
	registry, _, err := config.LoadStoredClientEndpointRegistry(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if endpoint, _ := registry.Endpoint("field"); endpoint.URL != "ssh://old.example" {
		t.Fatalf("script replacement changed endpoint: %#v", endpoint)
	}
}

func TestReadCosignerSetupPasteRejectsOversizedLine(t *testing.T) {
	state := &REPLState{
		Out: &bytes.Buffer{},
		LineReader: func() (string, error) {
			return `{"padding":"` + strings.Repeat("x", enrollment.MaxEnvelopeBytes) + `"}`, nil
		},
	}
	_, err := state.readCosignerSetupPaste()
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("readCosignerSetupPaste() error = %v, want size rejection", err)
	}
}

func TestReadCosignerSetupPasteDrainsOversizedMultilineDocument(t *testing.T) {
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
	_, err := state.readCosignerSetupPaste()
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("readCosignerSetupPaste() error = %v, want size rejection", err)
	}
	if reads != 3 {
		t.Fatalf("read %d lines, want 3; oversized document was not drained exactly", reads)
	}
}

func TestReadRequiredSetupValuePreservesCase(t *testing.T) {
	state := &REPLState{
		Out: &bytes.Buffer{},
		LineReader: func() (string, error) {
			return " ssh://Cosigner.EXAMPLE/CaseSensitivePath ", nil
		},
	}
	got, err := state.readRequiredSetupValue("Endpoint: ")
	if err != nil {
		t.Fatal(err)
	}
	if got != "ssh://Cosigner.EXAMPLE/CaseSensitivePath" {
		t.Fatalf("value = %q, want original case", got)
	}
}

func TestCosignerSetupDryRunDoesNotWriteOrConnect(t *testing.T) {
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
		AutoConfirm: true, currentCommandCtx: context.Background(),
	}
	result, err := state.cmdCosigner([]string{
		"add", documentPath, "--alias", "field", "--endpoint", "ssh://cosigner.example", "--dry-run",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := result.RenderText(&out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "no files changed; host trust, access, node role, key, and routes were not checked") {
		t.Fatalf("output = %q", out.String())
	}
	if _, err := os.Stat(config.GetClientEndpointsPath(dataDir)); !os.IsNotExist(err) {
		t.Fatalf("endpoints.yaml stat error = %v, want absent", err)
	}
}

func TestCosignerSetupRefreshesREPLConfigBeforeVerificationFailure(t *testing.T) {
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
		AutoConfirm: true, currentCommandCtx: context.Background(),
	}

	_, err = state.cmdCosigner([]string{
		"add", documentPath, "--alias", "field", "--endpoint", "http://127.0.0.1:1",
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "automatic enrollment requires ssh://") {
		t.Fatalf("cmdCosigner() error = %v, want missing direct-endpoint token error", err)
	}
	endpoint, ok := state.App.Config.Endpoints.Endpoint("field")
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

func TestCosignerStatusWorksWithoutSignerAndProjectsResults(t *testing.T) {
	dir := t.TempDir()
	eng, err := newIsolatedTestEngine(t, "testnet")
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	state := &REPLState{App: apshellapp.New(eng, cfg, dir), DataDir: dir, AutoConfirm: true}
	result, err := state.cmdCosigner([]string{"status"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := result.RenderText(&out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "No cosigner connections") || !strings.Contains(out.String(), "Unavailable:") {
		t.Fatalf("status=%s", out.String())
	}
	if _, err := state.cmdCosigner([]string{"status", "extra"}, nil); err == nil {
		t.Fatal("accepted extra argument")
	}
}

func newEndpointsAddTestState(t *testing.T, dataDir string, out *bytes.Buffer) *REPLState {
	t.Helper()
	eng, err := newIsolatedTestEngine(t, "testnet")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadConfig(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	return &REPLState{
		Out: out, App: apshellapp.New(eng, cfg, dataDir), DataDir: dataDir,
		AutoConfirm: true, currentCommandCtx: context.Background(),
	}
}

// newCLICosignerNode serves the node role and key inventory guided setup reads.
func newCLICosignerNode(t *testing.T, token string, reference witness.PublicReference) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "aplane "+token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/status":
			_ = json.NewEncoder(w).Encode(signerapi.StatusResponse{NodeRole: "cosigner", State: "unlocked"})
		case "/keys":
			_ = json.NewEncoder(w).Encode(signerapi.KeysResponse{Count: 1, Keys: []signerapi.KeyInfo{{
				Address: reference.WitnessKeyID, PublicKeyHex: reference.PublicKeyHex,
				KeyType: reference.KeyType, IsWitnessKey: true,
			}}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func writeCLICosignerConnection(t *testing.T, dataDir, alias, rawURL, token string) {
	t.Helper()
	if _, err := config.UpsertStoredClientEndpoint(dataDir, alias, config.ClientEndpointConfig{
		Role: config.ClientEndpointRoleCosigner, URL: rawURL,
	}, true); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dataDir, "tokens", alias+".token")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A second key on a connected cosigner needs no client change: running setup
// again with the new file reuses the connection without a name or a prompt.
func TestEndpointsAddReusesExistingConnectionWithoutAlias(t *testing.T) {
	dataDir := t.TempDir()
	document := testCLIWitnessDocument(t)
	artifact, err := enrollment.ParseArtifact(document)
	if err != nil {
		t.Fatal(err)
	}
	server := newCLICosignerNode(t, "token", artifact.Witness)
	writeCLICosignerConnection(t, dataDir, "treasury", server.URL, "token")
	documentPath := filepath.Join(dataDir, "second-key.json")
	if err := os.WriteFile(documentPath, document, 0o600); err != nil {
		t.Fatal(err)
	}
	endpointsPath := config.GetClientEndpointsPath(dataDir)
	before, err := os.ReadFile(endpointsPath)
	if err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	state := newEndpointsAddTestState(t, dataDir, &out)
	result, err := state.cmdEndpoints([]string{"add", documentPath, "--endpoint", server.URL}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := result.RenderText(&out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Already configured as treasury. Checking access...",
		"Connection treasury ready.",
		"Key from the setup file found.",
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("output = %q, want %q", out.String(), want)
		}
	}
	after, err := os.ReadFile(endpointsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("endpoints.yaml changed on a rerun:\n%s\nwant:\n%s", after, before)
	}
}

func TestEndpointsAddScriptRequiresAliasForNewConnection(t *testing.T) {
	dataDir := t.TempDir()
	state := newEndpointsAddTestState(t, dataDir, &bytes.Buffer{})
	_, err := state.cmdEndpoints([]string{"add", "--endpoint", "ssh://cosigner.example"}, nil)
	if err == nil || !strings.Contains(err.Error(), "--alias is required in script mode") {
		t.Fatalf("cmdEndpoints() error = %v, want the script alias requirement", err)
	}
	if _, statErr := os.Stat(config.GetClientEndpointsPath(dataDir)); !os.IsNotExist(statErr) {
		t.Fatalf("endpoints.yaml stat error = %v, want absent", statErr)
	}
}

func TestEndpointsAddRefusesSecondNameForConfiguredCosigner(t *testing.T) {
	dataDir := t.TempDir()
	writeCLICosignerConnection(t, dataDir, "treasury", "ssh://cosigner.example:1127", "token")
	state := newEndpointsAddTestState(t, dataDir, &bytes.Buffer{})
	_, err := state.cmdEndpoints([]string{"add", "--endpoint", "ssh://cosigner.example:1127", "--alias", "second"}, nil)
	if !errors.Is(err, apshellapp.ErrCosignerEndpointAlreadyConfigured) || !strings.Contains(err.Error(), "--alias treasury") {
		t.Fatalf("cmdEndpoints() error = %v, want guidance to reuse treasury", err)
	}
}

func TestCosignerAddForwardsToEndpointsAddWithNotice(t *testing.T) {
	dataDir := t.TempDir()
	var out bytes.Buffer
	state := newEndpointsAddTestState(t, dataDir, &out)
	result, err := state.cmdCosigner([]string{
		"add", "--alias", "field", "--endpoint", "ssh://cosigner.example", "--dry-run",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := result.RenderText(&out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), cosignerAddForwardNotice) || !strings.Contains(out.String(), "Cosigner connection dry run:") {
		t.Fatalf("output = %q, want the forwarding notice and the dry run", out.String())
	}
}

func TestEndpointsAddIsBlockedForAutomationOnly(t *testing.T) {
	if err := guardAutomatedEndpoints([]string{"add", "handoff.json"}); err == nil {
		t.Fatal("guardAutomatedEndpoints() allowed guided setup")
	}
	for _, args := range [][]string{{"list"}, {"show", "field"}, {"import", "--alias", "a"}, {"create"}, {"discover-cosigners"}, nil} {
		if err := guardAutomatedEndpoints(args); err != nil {
			t.Fatalf("guardAutomatedEndpoints(%v) error = %v, want allowed", args, err)
		}
	}
}
