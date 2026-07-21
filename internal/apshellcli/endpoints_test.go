// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/tokenfile"
	"github.com/aplane-algo/aplane/internal/witness"
)

func TestEndpointCreateSentryCommandWritesManualEndpoint(t *testing.T) {
	dataDir := t.TempDir()
	cfg := config.DefaultConfig()
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	var out bytes.Buffer
	state := &REPLState{
		Out:               &out,
		App:               apshellapp.New(eng, cfg, dataDir),
		DataDir:           dataDir,
		Config:            cfg,
		currentCommandCtx: context.Background(),
	}

	err = state.cmdEndpoints([]string{
		"create",
		"--alias", "sentry-local",
		"--endpoint", "ssh://127.0.0.1:2223",
		"--sentryport", "12270",
	}, nil)
	if err != nil {
		t.Fatalf("cmdEndpoints(create) error = %v", err)
	}
	rendered := out.String()
	if !strings.Contains(rendered, "Configured sentry endpoint sentry-local") ||
		!strings.Contains(rendered, "sentry port: 12270") ||
		!strings.Contains(rendered, "request-token --endpoint sentry-local") {
		t.Fatalf("output missing create details:\n%s", rendered)
	}

	cfg, err = config.LoadConfig(dataDir)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	endpoint, ok := cfg.Endpoints.Endpoint("sentry-local")
	if !ok {
		t.Fatal("sentry-local endpoint missing")
	}
	if endpoint.Role != config.ClientEndpointRoleSentry || endpoint.URL != "ssh://127.0.0.1:2223" || endpoint.SignerPort != 12270 {
		t.Fatalf("endpoint = %#v, want sentry ssh endpoint with signer_port 12270", endpoint)
	}
}

func TestParseEndpointCreateSentryArgsAcceptsHyphenatedPortFlag(t *testing.T) {
	req, err := parseEndpointCreateSentryArgs([]string{
		"--alias", "sentry-local",
		"--endpoint", "ssh://127.0.0.1:2223",
		"--sentry-port", "12270",
		"--dry-run",
	})
	if err != nil {
		t.Fatalf("parseEndpointCreateSentryArgs() error = %v", err)
	}
	if req.Alias != "sentry-local" || req.URL != "ssh://127.0.0.1:2223" || req.SentryPort != 12270 || !req.DryRun {
		t.Fatalf("request = %#v, want parsed manual sentry endpoint", req)
	}
}

func TestEndpointSyncSentriesProgressListsComponentsBeforePrompt(t *testing.T) {
	dataDir := t.TempDir()
	publicKeyHex := strings.Repeat("ab", witness.Falcon1024PublicKeySize)
	componentKey := endpointCLITestComponentSelector(t, witness.Falcon1024V1, publicKeyHex)
	server := newEndpointCLIKeysServer(t, "sentry-token", []signerapi.KeyInfo{{
		Address:      componentKey,
		PublicKeyHex: publicKeyHex,
		KeyType:      witness.Falcon1024V1,
		IsWitnessKey: true,
	}})

	if _, err := config.UpsertStoredClientEndpoint(dataDir, "sentry-local", config.ClientEndpointConfig{
		Role: config.ClientEndpointRoleSentry,
		URL:  server.URL,
	}, true); err != nil {
		t.Fatalf("UpsertStoredClientEndpoint() error = %v", err)
	}
	tokenPath := filepath.Join(dataDir, "tokens", "sentry-local.token")
	if err := os.MkdirAll(filepath.Dir(tokenPath), 0o700); err != nil {
		t.Fatalf("MkdirAll(tokens) error = %v", err)
	}
	if err := tokenfile.WriteToken(tokenPath, "sentry-token"); err != nil {
		t.Fatalf("WriteToken() error = %v", err)
	}

	cfg, err := config.LoadConfig(dataDir)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	var out bytes.Buffer
	var progress []string
	state := &REPLState{
		Out:     &out,
		App:     apshellapp.New(eng, cfg, dataDir),
		DataDir: dataDir,
		Config:  cfg,
		LineReader: func() (string, error) {
			t.Fatal("sync-sentries should fail before prompting when signer is not connected")
			return "", nil
		},
		ProgressLine: func(line string) {
			progress = append(progress, line)
		},
		currentCommandCtx: context.Background(),
	}

	err = state.cmdEndpoints([]string{"sync-sentries"}, nil)
	if err == nil {
		t.Fatal("cmdEndpoints(sync-sentries) error = nil, want not connected")
	}
	if !strings.Contains(err.Error(), "not connected to Signer") {
		t.Fatalf("cmdEndpoints(sync-sentries) error = %v, want not connected", err)
	}
	joined := strings.Join(progress, "\n")
	if !strings.Contains(joined, componentKey) {
		t.Fatalf("progress output = %q, want Sentry Key ID %s", joined, componentKey)
	}
	if strings.Contains(joined, publicKeyHex) || strings.Contains(joined, strings.ToUpper(publicKeyHex)) {
		t.Fatalf("progress output leaked raw sentry public key: %q", joined)
	}
	if strings.Contains(out.String(), componentKey) {
		t.Fatalf("captured output = %q, Sentry Key ID should be live progress before prompt", out.String())
	}
}

func TestRenderEndpointSentriesOmitsLastSeen(t *testing.T) {
	var out bytes.Buffer
	state := &REPLState{Out: &out}

	publicKeyHex := strings.Repeat("ab", witness.Falcon1024PublicKeySize)
	componentKey := endpointCLITestComponentSelector(t, witness.Falcon1024V1, publicKeyHex)
	state.renderEndpointSentries(&apshellapp.EndpointSentriesResult{
		Sentries: []apshellapp.EndpointSentryEntry{{
			EndpointAlias: "sentry-local",
			ComponentKey:  componentKey,
			KeyType:       witness.Falcon1024V1,
			LastSeenAt:    "2026-06-04T00:00:00Z",
		}},
	})

	rendered := out.String()
	if strings.Contains(rendered, "LAST SEEN") || strings.Contains(rendered, "2026-06-04T00:00:00Z") {
		t.Fatalf("rendered sentries = %q, want no last-seen column or timestamp", rendered)
	}
	if !strings.Contains(rendered, "SENTRY KEY") || strings.Contains(rendered, "COMPONENT") || strings.Contains(rendered, "ATTESTORS") {
		t.Fatalf("rendered sentries header = %q, want SENTRY KEY without legacy labels", rendered)
	}
	if !strings.Contains(rendered, componentKey) {
		t.Fatalf("rendered sentries = %q, want Sentry Key ID", rendered)
	}
	if strings.Contains(rendered, publicKeyHex) || strings.Contains(rendered, strings.ToUpper(publicKeyHex)) {
		t.Fatalf("rendered sentries leaked raw sentry public key: %q", rendered)
	}
}

func TestRenderEndpointShowIncludesSentryLastSeen(t *testing.T) {
	var out bytes.Buffer
	state := &REPLState{Out: &out}

	publicKeyHex := strings.Repeat("cd", witness.Falcon1024PublicKeySize)
	componentKey := endpointCLITestComponentSelector(t, witness.Falcon1024V1, publicKeyHex)
	state.renderEndpointShow(&apshellapp.EndpointShowResult{
		Endpoint: apshellapp.EndpointEntry{
			Alias: "sentry-local",
			Role:  config.ClientEndpointRoleSentry,
			URL:   "ssh://127.0.0.1:2223",
			PublishedSentryComponents: []string{
				componentKey,
			},
			PublishedSentries: []apshellapp.EndpointSentryEntry{{
				EndpointAlias: "sentry-local",
				ComponentKey:  componentKey,
				KeyType:       witness.Falcon1024V1,
				LastSeenAt:    "2026-06-04T00:00:00Z",
			}},
		},
	})

	rendered := out.String()
	if !strings.Contains(rendered, "LAST SEEN") || !strings.Contains(rendered, "2026-06-04T00:00:00Z") {
		t.Fatalf("rendered endpoint show = %q, want last-seen detail", rendered)
	}
	if !strings.Contains(rendered, "SENTRY KEY") || strings.Contains(rendered, "COMPONENT") || strings.Contains(rendered, "ATTESTORS") {
		t.Fatalf("rendered endpoint show header = %q, want SENTRY KEY without legacy labels", rendered)
	}
	if !strings.Contains(rendered, componentKey) {
		t.Fatalf("rendered endpoint show = %q, want Sentry Key ID", rendered)
	}
	if strings.Contains(rendered, publicKeyHex) || strings.Contains(rendered, strings.ToUpper(publicKeyHex)) {
		t.Fatalf("rendered endpoint show leaked raw sentry public key: %q", rendered)
	}
}

func TestRenderEndpointsListUsesSentryKeyHeader(t *testing.T) {
	var out bytes.Buffer
	state := &REPLState{Out: &out}

	state.renderEndpointsList(&apshellapp.EndpointsListResult{
		Endpoints: []apshellapp.EndpointEntry{{
			Alias:                     "sentry-local",
			Role:                      config.ClientEndpointRoleSentry,
			URL:                       "ssh://127.0.0.1:2223",
			PublishedSentryComponents: []string{"SENTRYKEY"},
		}},
	})

	rendered := out.String()
	if !strings.Contains(rendered, "SENTRY KEYS") || strings.Contains(rendered, "ATTESTORS") || strings.Contains(rendered, "COMPONENT") {
		t.Fatalf("rendered endpoint list header = %q, want SENTRY KEYS without legacy labels", rendered)
	}
}

func endpointCLITestComponentSelector(t *testing.T, keyType, publicKeyHex string) string {
	t.Helper()
	publicKey, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		t.Fatalf("DecodeString(publicKeyHex) error = %v", err)
	}
	selector, err := witness.ID(keyType, publicKey)
	if err != nil {
		t.Fatalf("witness.ID() error = %v", err)
	}
	return selector
}

func newEndpointCLIKeysServer(t *testing.T, token string, keys []signerapi.KeyInfo) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/keys" {
			http.NotFound(w, r)
			return
		}
		if got := r.Header.Get("Authorization"); got != "aplane "+token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(signerapi.KeysResponse{
			Count: len(keys),
			Keys:  keys,
		})
	}))
	t.Cleanup(server.Close)
	return server
}
