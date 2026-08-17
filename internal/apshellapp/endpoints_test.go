// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/endpointrefs"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/witness"
)

func TestEndpointImportDryRunDoesNotWriteFiles(t *testing.T) {
	dataDir := t.TempDir()
	app := newEndpointTestApp(t, dataDir)
	result, err := app.EndpointImport(t.Context(), EndpointImportRequest{
		Alias: "sentry-local", Role: config.ClientEndpointRoleSentry,
		Path: writeEndpointEnvelope(t, dataDir), DryRun: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.DryRun || !result.Created {
		t.Fatalf("result = %#v, want dry-run create", result)
	}
	if _, err := os.Stat(config.GetClientEndpointsPath(dataDir)); !os.IsNotExist(err) {
		t.Fatalf("endpoints.yaml stat error = %v, want absent", err)
	}
}

func TestEndpointImportWritesV2ConnectionProfileOnly(t *testing.T) {
	dataDir := t.TempDir()
	app := newEndpointTestApp(t, dataDir)
	_, err := app.EndpointImport(t.Context(), EndpointImportRequest{
		Alias: "sentry-local", Role: config.ClientEndpointRoleSentry,
		Path: writeEndpointEnvelope(t, dataDir),
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(config.GetClientEndpointsPath(dataDir))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "schema_version: 2") || strings.Contains(string(data), "published_sentries") {
		t.Fatalf("endpoints.yaml = %q, want v2 connection profile only", data)
	}
	if _, ok := app.eng.EndpointRegistry.Endpoint("sentry-local"); !ok {
		t.Fatal("live engine endpoint registry was not refreshed")
	}
}

func TestEndpointCreateSentryAndListContainNoCachedInventory(t *testing.T) {
	dataDir := t.TempDir()
	app := newEndpointTestApp(t, dataDir)
	_, err := app.EndpointCreateSentry(t.Context(), EndpointCreateSentryRequest{
		Alias: "sentry-local", URL: "ssh://127.0.0.1:2223", SentryPort: 11270,
	})
	if err != nil {
		t.Fatal(err)
	}
	list, err := app.EndpointsList(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Endpoints) != 1 || list.Endpoints[0].Alias != "sentry-local" || list.Endpoints[0].Role != config.ClientEndpointRoleSentry {
		t.Fatalf("endpoints = %#v", list.Endpoints)
	}
	show, err := app.EndpointShow(t.Context(), "sentry-local")
	if err != nil || show.Endpoint.URL != "ssh://127.0.0.1:2223" {
		t.Fatalf("EndpointShow() = %#v, %v", show, err)
	}
}

func TestEndpointDiscoverSentriesIsReadOnly(t *testing.T) {
	dataDir := t.TempDir()
	publicKey := testSentryPublicKeyHex()
	componentKey := testComponentSelector(t, witness.Falcon1024V1, publicKey)
	server := newEndpointKeysServer(t, "sentry-token", []signerapi.KeyInfo{{
		Address: componentKey, PublicKeyHex: publicKey, KeyType: witness.Falcon1024V1, IsWitnessKey: true,
	}})
	writeLiveSentryEndpoint(t, dataDir, "sentry-local", server.URL, "sentry-token")
	before, err := os.ReadFile(config.GetClientEndpointsPath(dataDir))
	if err != nil {
		t.Fatal(err)
	}
	app := newEndpointTestApp(t, dataDir)
	result, err := app.EndpointDiscoverSentries(t.Context(), EndpointDiscoverSentriesRequest{})
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(config.GetClientEndpointsPath(dataDir))
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("read-only discovery changed endpoints.yaml\nbefore: %s\nafter: %s", before, after)
	}
	if result.PublicKeyCount != 1 || len(result.Endpoints) != 1 || len(result.Endpoints[0].Keys) != 1 {
		t.Fatalf("discovery result = %#v", result)
	}
	assertHumanEndpointOutputUsesComponentOnly(t, result.RenderLines, publicKey, componentKey)
}

func TestEndpointDiscoverSentriesRejectsDuplicatePublication(t *testing.T) {
	dataDir := t.TempDir()
	publicKey := testSentryPublicKeyHex()
	componentKey := testComponentSelector(t, witness.Falcon1024V1, publicKey)
	keys := []signerapi.KeyInfo{{Address: componentKey, PublicKeyHex: publicKey, KeyType: witness.Falcon1024V1, IsWitnessKey: true}}
	first := newEndpointKeysServer(t, "token-a", keys)
	second := newEndpointKeysServer(t, "token-b", keys)
	writeLiveSentryEndpoint(t, dataDir, "sentry-a", first.URL, "token-a")
	writeLiveSentryEndpoint(t, dataDir, "sentry-b", second.URL, "token-b")
	app := newEndpointTestApp(t, dataDir)
	_, err := app.EndpointDiscoverSentries(t.Context(), EndpointDiscoverSentriesRequest{})
	if err == nil || !strings.Contains(err.Error(), "advertised by both endpoint aliases") {
		t.Fatalf("EndpointDiscoverSentries() error = %v, want duplicate rejection", err)
	}
}

func TestEndpointDiscoverSentriesReportsUnavailableEndpoint(t *testing.T) {
	dataDir := t.TempDir()
	writeLiveSentryEndpoint(t, dataDir, "sentry-offline", "http://127.0.0.1:1", "token")
	app := newEndpointTestApp(t, dataDir)
	result, err := app.EndpointDiscoverSentries(t.Context(), EndpointDiscoverSentriesRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Endpoints) != 1 || !result.Endpoints[0].Skipped || result.Endpoints[0].Error == "" {
		t.Fatalf("discovery result = %#v, want skipped unavailable endpoint", result)
	}
}

func TestEndpointDiscoverSentriesRejectsAuthenticationAndMalformedMetadata(t *testing.T) {
	tests := []struct {
		name    string
		server  func(*testing.T) *httptest.Server
		wantErr string
	}{
		{
			name: "authentication",
			server: func(t *testing.T) *httptest.Server {
				return newEndpointKeysStatusServer(t, "different-token", http.StatusUnauthorized, `{"error":"unauthorized"}`)
			},
			wantErr: "authentication",
		},
		{
			name: "metadata",
			server: func(t *testing.T) *httptest.Server {
				return newEndpointKeysServer(t, "token", []signerapi.KeyInfo{{
					Address: "INVALID", PublicKeyHex: "zz", KeyType: witness.Falcon1024V1, IsWitnessKey: true,
				}})
			},
			wantErr: "invalid sentry discovery metadata",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dataDir := t.TempDir()
			server := tt.server(t)
			writeLiveSentryEndpoint(t, dataDir, "sentry-local", server.URL, "token")
			app := newEndpointTestApp(t, dataDir)
			_, err := app.EndpointDiscoverSentries(t.Context(), EndpointDiscoverSentriesRequest{})
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("EndpointDiscoverSentries() error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestEndpointSyncSentriesDryRunUsesLiveDiscovery(t *testing.T) {
	dataDir := t.TempDir()
	publicKey := testSentryPublicKeyHex()
	componentKey := testComponentSelector(t, witness.Falcon1024V1, publicKey)
	server := newEndpointKeysServer(t, "sentry-token", []signerapi.KeyInfo{{
		Address: componentKey, PublicKeyHex: publicKey, KeyType: witness.Falcon1024V1, IsWitnessKey: true,
	}})
	writeLiveSentryEndpoint(t, dataDir, "sentry-local", server.URL, "sentry-token")
	app := newEndpointTestApp(t, dataDir)
	result, err := app.EndpointSyncSentries(t.Context(), EndpointSyncSentriesRequest{DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if result.CandidateCount != 1 || len(result.Records) != 1 || result.Records[0].ComponentKey != componentKey {
		t.Fatalf("sync result = %#v", result)
	}
	assertHumanEndpointOutputUsesComponentOnly(t, result.RenderLines, publicKey, componentKey)
}

func TestEndpointDefaultAndDeleteUpdateLiveRegistry(t *testing.T) {
	dataDir := t.TempDir()
	if _, err := config.UpsertStoredClientEndpoint(dataDir, "primary", config.ClientEndpointConfig{Role: config.ClientEndpointRoleSigner, URL: "self"}, true); err != nil {
		t.Fatal(err)
	}
	if _, err := config.UpsertStoredClientEndpoint(dataDir, "secondary", config.ClientEndpointConfig{Role: config.ClientEndpointRoleSentry, URL: "self"}, true); err != nil {
		t.Fatal(err)
	}
	app := newEndpointTestApp(t, dataDir)
	if _, err := app.EndpointDefault(t.Context(), "primary"); err != nil {
		t.Fatal(err)
	}
	if _, err := app.EndpointDelete(t.Context(), "secondary"); err != nil {
		t.Fatal(err)
	}
	if _, ok := app.eng.EndpointRegistry.Endpoint("secondary"); ok {
		t.Fatal("deleted endpoint remained in live registry")
	}
}

func newEndpointTestApp(t *testing.T, dataDir string) *App {
	t.Helper()
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatal(err)
	}
	return New(eng, config.DefaultConfig(), dataDir)
}

func writeEndpointEnvelope(t *testing.T, dir string) string {
	t.Helper()
	data, err := endpointrefs.Marshal(endpointrefs.Envelope{Schema: endpointrefs.Schema, URL: "ssh://127.0.0.1:2223", SignerPort: 11270})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "sentry-local.endpoint.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeLiveSentryEndpoint(t *testing.T, dir, alias, rawURL, token string) {
	t.Helper()
	if _, err := config.UpsertStoredClientEndpoint(dir, alias, config.ClientEndpointConfig{
		Role: config.ClientEndpointRoleSentry, URL: rawURL,
	}, true); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "tokens", alias+".token")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func testSentryPublicKeyHex() string {
	return strings.Repeat("ab", witness.Falcon1024PublicKeySize)
}

func testComponentSelector(t *testing.T, keyType, publicKeyHex string) string {
	t.Helper()
	publicKey, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	selector, err := witness.ID(keyType, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	return selector
}

func assertHumanEndpointOutputUsesComponentOnly(t *testing.T, lines []string, publicKeyHex, componentID string) {
	t.Helper()
	output := strings.Join(lines, "\n")
	if !strings.Contains(output, componentID) {
		t.Fatalf("endpoint output = %q, want Witness Key ID %s", output, componentID)
	}
	if strings.Contains(output, publicKeyHex) || strings.Contains(output, strings.ToUpper(publicKeyHex)) {
		t.Fatalf("endpoint output leaked raw sentry public key: %q", output)
	}
}

func newEndpointKeysServer(t *testing.T, token string, keys []signerapi.KeyInfo) *httptest.Server {
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
		_ = json.NewEncoder(w).Encode(signerapi.KeysResponse{Count: len(keys), Keys: keys})
	}))
	t.Cleanup(server.Close)
	return server
}

func newEndpointKeysStatusServer(t *testing.T, token string, status int, body string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "aplane "+token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	return server
}
