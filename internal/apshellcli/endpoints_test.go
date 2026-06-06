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
	"github.com/aplane-algo/aplane/internal/attestor/keytypes"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/tokenfile"
)

func TestEndpointSyncAttestorsProgressListsComponentsBeforePrompt(t *testing.T) {
	dataDir := t.TempDir()
	publicKeyHex := strings.Repeat("ab", 32)
	componentKey := endpointCLITestComponentSelector(t, keytypes.AttestorComponentEd25519V1, publicKeyHex)
	server := newEndpointCLIKeysServer(t, "att-token", []signerapi.KeyInfo{{
		Address:        componentKey,
		PublicKeyHex:   publicKeyHex,
		KeyType:        keytypes.AttestorComponentEd25519V1,
		IsComponentKey: true,
	}})

	if _, err := config.UpsertStoredClientEndpoint(dataDir, "attestor-local", config.ClientEndpointConfig{
		Role: config.ClientEndpointRoleAttestor,
		URL:  server.URL,
	}, true); err != nil {
		t.Fatalf("UpsertStoredClientEndpoint() error = %v", err)
	}
	tokenPath := filepath.Join(dataDir, "tokens", "attestor-local.token")
	if err := os.MkdirAll(filepath.Dir(tokenPath), 0o700); err != nil {
		t.Fatalf("MkdirAll(tokens) error = %v", err)
	}
	if err := tokenfile.WriteToken(tokenPath, "att-token"); err != nil {
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
			t.Fatal("sync-attestors should fail before prompting when signer is not connected")
			return "", nil
		},
		ProgressLine: func(line string) {
			progress = append(progress, line)
		},
		currentCommandCtx: context.Background(),
	}

	err = state.cmdEndpoints([]string{"sync-attestors"}, nil)
	if err == nil {
		t.Fatal("cmdEndpoints(sync-attestors) error = nil, want not connected")
	}
	if !strings.Contains(err.Error(), "not connected to Signer") {
		t.Fatalf("cmdEndpoints(sync-attestors) error = %v, want not connected", err)
	}
	joined := strings.Join(progress, "\n")
	if !strings.Contains(joined, componentKey) {
		t.Fatalf("progress output = %q, want component key %s", joined, componentKey)
	}
	if strings.Contains(joined, publicKeyHex) || strings.Contains(joined, strings.ToUpper(publicKeyHex)) {
		t.Fatalf("progress output leaked raw attestor public key: %q", joined)
	}
	if strings.Contains(out.String(), componentKey) {
		t.Fatalf("captured output = %q, component key should be live progress before prompt", out.String())
	}
}

func TestRenderEndpointAttestorsOmitsLastSeen(t *testing.T) {
	var out bytes.Buffer
	state := &REPLState{Out: &out}

	publicKeyHex := strings.Repeat("ab", 32)
	componentKey := endpointCLITestComponentSelector(t, keytypes.AttestorComponentEd25519V1, publicKeyHex)
	state.renderEndpointAttestors(&apshellapp.EndpointAttestorsResult{
		Attestors: []apshellapp.EndpointAttestorEntry{{
			EndpointAlias: "attestor-local",
			ComponentKey:  componentKey,
			KeyType:       keytypes.AttestorComponentEd25519V1,
			LastSeenAt:    "2026-06-04T00:00:00Z",
		}},
	})

	rendered := out.String()
	if strings.Contains(rendered, "LAST SEEN") || strings.Contains(rendered, "2026-06-04T00:00:00Z") {
		t.Fatalf("rendered attestors = %q, want no last-seen column or timestamp", rendered)
	}
	if !strings.Contains(rendered, componentKey) {
		t.Fatalf("rendered attestors = %q, want component key", rendered)
	}
	if strings.Contains(rendered, publicKeyHex) || strings.Contains(rendered, strings.ToUpper(publicKeyHex)) {
		t.Fatalf("rendered attestors leaked raw attestor public key: %q", rendered)
	}
}

func TestRenderEndpointShowIncludesAttestorLastSeen(t *testing.T) {
	var out bytes.Buffer
	state := &REPLState{Out: &out}

	publicKeyHex := strings.Repeat("cd", 32)
	componentKey := endpointCLITestComponentSelector(t, keytypes.AttestorComponentEd25519V1, publicKeyHex)
	state.renderEndpointShow(&apshellapp.EndpointShowResult{
		Endpoint: apshellapp.EndpointEntry{
			Alias: "attestor-local",
			Role:  config.ClientEndpointRoleAttestor,
			URL:   "ssh://127.0.0.1:2223",
			PublishedAttestorComponents: []string{
				componentKey,
			},
			PublishedAttestors: []apshellapp.EndpointAttestorEntry{{
				EndpointAlias: "attestor-local",
				ComponentKey:  componentKey,
				KeyType:       keytypes.AttestorComponentEd25519V1,
				LastSeenAt:    "2026-06-04T00:00:00Z",
			}},
		},
	})

	rendered := out.String()
	if !strings.Contains(rendered, "LAST SEEN") || !strings.Contains(rendered, "2026-06-04T00:00:00Z") {
		t.Fatalf("rendered endpoint show = %q, want last-seen detail", rendered)
	}
	if !strings.Contains(rendered, componentKey) {
		t.Fatalf("rendered endpoint show = %q, want component key", rendered)
	}
	if strings.Contains(rendered, publicKeyHex) || strings.Contains(rendered, strings.ToUpper(publicKeyHex)) {
		t.Fatalf("rendered endpoint show leaked raw attestor public key: %q", rendered)
	}
}

func endpointCLITestComponentSelector(t *testing.T, keyType, publicKeyHex string) string {
	t.Helper()
	publicKey, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		t.Fatalf("DecodeString(publicKeyHex) error = %v", err)
	}
	selector, err := keytypes.ComponentKeySelector(keyType, publicKey)
	if err != nil {
		t.Fatalf("ComponentKeySelector() error = %v", err)
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
