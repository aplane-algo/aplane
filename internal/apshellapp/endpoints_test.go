// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/endpointrefs"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/witness"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

func TestEndpointImportDryRunDoesNotWriteFiles(t *testing.T) {
	dataDir := t.TempDir()
	app := newEndpointTestApp(t, dataDir)
	result, err := app.EndpointImport(t.Context(), EndpointImportRequest{
		Alias: "cosigner-local", Role: config.ClientEndpointRoleCosigner,
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
	result, err := app.EndpointImport(t.Context(), EndpointImportRequest{
		Alias: "cosigner-local", Role: config.ClientEndpointRoleCosigner,
		Path: writeEndpointEnvelope(t, dataDir),
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(config.GetClientEndpointsPath(dataDir))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "schema_version: 2") || strings.Contains(string(data), "published_cosigners") {
		t.Fatalf("endpoints.yaml = %q, want v2 connection profile only", data)
	}
	if result.LocalPort != 0 || strings.Contains(string(data), "local_port") {
		t.Fatalf("import retained cosigner local port: result = %#v, endpoints.yaml = %q", result, data)
	}
	if _, ok := app.eng.EndpointRegistry.Endpoint("cosigner-local"); !ok {
		t.Fatal("live engine endpoint registry was not refreshed")
	}
}

func TestEndpointImportRejectsLocalPortForCosignerRole(t *testing.T) {
	dataDir := t.TempDir()
	data, err := endpointrefs.Marshal(endpointrefs.Envelope{
		Schema: endpointrefs.Schema, URL: "ssh://127.0.0.1:2223", SignerPort: 11270, LocalPort: 12271,
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dataDir, "cosigner-with-local-port.endpoint.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = newEndpointTestApp(t, dataDir).EndpointImport(t.Context(), EndpointImportRequest{
		Alias: "cosigner-local", Role: config.ClientEndpointRoleCosigner, Path: path,
	})
	if err == nil || !strings.Contains(err.Error(), "local_port is not supported for cosigner endpoints") {
		t.Fatalf("EndpointImport() error = %v, want cosigner local_port rejection", err)
	}
	if _, statErr := os.Stat(config.GetClientEndpointsPath(dataDir)); !os.IsNotExist(statErr) {
		t.Fatalf("endpoints.yaml stat error = %v, want absent", statErr)
	}
}

func TestEndpointImportPointsCosignerKeyDocumentsAtEndpointsAdd(t *testing.T) {
	documents := map[string]string{
		"witness": `{"schema":"aplane.witness-key-public.v1","key_type":"aplane.witness-falcon1024.v1"}`,
	}
	for name, document := range documents {
		t.Run(name, func(t *testing.T) {
			dataDir := t.TempDir()
			path := filepath.Join(dataDir, "lab.aplane-cosigner.json")
			if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
				t.Fatal(err)
			}

			_, err := newEndpointTestApp(t, dataDir).EndpointImport(t.Context(), EndpointImportRequest{
				Alias: "cosigner-local", Role: config.ClientEndpointRoleCosigner, Path: path,
			})
			want := "the signer imports it (apadmin cosigner import); on this client run 'endpoints add <cosigner-url> --alias cosigner-local'"
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("EndpointImport() error = %v, want hint %q", err, want)
			}
			if _, statErr := os.Stat(config.GetClientEndpointsPath(dataDir)); !os.IsNotExist(statErr) {
				t.Fatalf("endpoints.yaml stat error = %v, want absent", statErr)
			}
		})
	}
}

func TestEndpointCreateCosignerAndListContainNoCachedInventory(t *testing.T) {
	dataDir := t.TempDir()
	app := newEndpointTestApp(t, dataDir)
	_, err := app.EndpointCreateCosigner(t.Context(), EndpointCreateCosignerRequest{
		Alias: "cosigner-local", URL: "ssh://127.0.0.1:2223", CosignerPort: 11270,
	})
	if err != nil {
		t.Fatal(err)
	}
	list, err := app.EndpointsList(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Endpoints) != 1 || list.Endpoints[0].Alias != "cosigner-local" || list.Endpoints[0].Role != config.ClientEndpointRoleCosigner {
		t.Fatalf("endpoints = %#v", list.Endpoints)
	}
	show, err := app.EndpointShow(t.Context(), "cosigner-local")
	if err != nil || show.Endpoint.URL != "ssh://127.0.0.1:2223" {
		t.Fatalf("EndpointShow() = %#v, %v", show, err)
	}
}

func TestEndpointDiscoverCosignersIsReadOnly(t *testing.T) {
	dataDir := t.TempDir()
	publicKey := testCosignerPublicKeyHex()
	componentKey := testComponentSelector(t, witness.Falcon1024V1, publicKey)
	server := newEndpointKeysServer(t, "cosigner-token", []signerapi.KeyInfo{{
		Address: componentKey, PublicKeyHex: publicKey, KeyType: witness.Falcon1024V1, IsWitnessKey: true,
	}})
	writeLiveCosignerEndpoint(t, dataDir, "cosigner-local", server.URL, "cosigner-token")
	before, err := os.ReadFile(config.GetClientEndpointsPath(dataDir))
	if err != nil {
		t.Fatal(err)
	}
	app := newEndpointTestApp(t, dataDir)
	result, err := app.EndpointDiscoverCosigners(t.Context(), EndpointDiscoverCosignersRequest{})
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

func TestEndpointDiscoverCosignersRejectsDuplicatePublication(t *testing.T) {
	dataDir := t.TempDir()
	publicKey := testCosignerPublicKeyHex()
	componentKey := testComponentSelector(t, witness.Falcon1024V1, publicKey)
	keys := []signerapi.KeyInfo{{Address: componentKey, PublicKeyHex: publicKey, KeyType: witness.Falcon1024V1, IsWitnessKey: true}}
	first := newEndpointKeysServer(t, "token-a", keys)
	second := newEndpointKeysServer(t, "token-b", keys)
	writeLiveCosignerEndpoint(t, dataDir, "cosigner-a", first.URL, "token-a")
	writeLiveCosignerEndpoint(t, dataDir, "cosigner-b", second.URL, "token-b")
	app := newEndpointTestApp(t, dataDir)
	_, err := app.EndpointDiscoverCosigners(t.Context(), EndpointDiscoverCosignersRequest{})
	if err == nil || !strings.Contains(err.Error(), "advertised by both endpoint aliases") {
		t.Fatalf("EndpointDiscoverCosigners() error = %v, want duplicate rejection", err)
	}
}

func TestEndpointDiscoverCosignersReportsUnavailableEndpoint(t *testing.T) {
	dataDir := t.TempDir()
	writeLiveCosignerEndpoint(t, dataDir, "cosigner-offline", "http://127.0.0.1:1", "token")
	app := newEndpointTestApp(t, dataDir)
	result, err := app.EndpointDiscoverCosigners(t.Context(), EndpointDiscoverCosignersRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Endpoints) != 1 || !result.Endpoints[0].Skipped || result.Endpoints[0].Error == "" {
		t.Fatalf("discovery result = %#v, want skipped unavailable endpoint", result)
	}
}

func TestEndpointDiscoverCosignersRejectsAuthenticationAndMalformedMetadata(t *testing.T) {
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
			wantErr: "invalid cosigner discovery metadata",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dataDir := t.TempDir()
			server := tt.server(t)
			writeLiveCosignerEndpoint(t, dataDir, "cosigner-local", server.URL, "token")
			app := newEndpointTestApp(t, dataDir)
			_, err := app.EndpointDiscoverCosigners(t.Context(), EndpointDiscoverCosignersRequest{})
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("EndpointDiscoverCosigners() error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestEndpointDefaultAndDeleteUpdateLiveRegistry(t *testing.T) {
	dataDir := t.TempDir()
	if _, err := config.UpsertStoredClientEndpoint(dataDir, "primary", config.ClientEndpointConfig{Role: config.ClientEndpointRoleSigner, URL: "ssh://signer.example"}, true); err != nil {
		t.Fatal(err)
	}
	if _, err := config.UpsertStoredClientEndpoint(dataDir, "secondary", config.ClientEndpointConfig{Role: config.ClientEndpointRoleCosigner, URL: "ssh://cosigner.example"}, true); err != nil {
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

func TestConcurrentEndpointCreatesPreserveBothAliases(t *testing.T) {
	dataDir := t.TempDir()
	appA := newEndpointTestApp(t, dataDir)
	appB := newEndpointTestApp(t, dataDir)
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, item := range []struct {
		app   *App
		alias string
		url   string
	}{{appA, "cosigner-a", "ssh://a.example"}, {appB, "cosigner-b", "ssh://b.example"}} {
		wg.Add(1)
		go func(item struct {
			app   *App
			alias string
			url   string
		}) {
			defer wg.Done()
			<-start
			_, err := item.app.EndpointCreateCosigner(context.Background(), EndpointCreateCosignerRequest{
				Alias: item.alias, URL: item.url, CosignerPort: 11270,
			})
			errs <- err
		}(item)
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	registry, _, err := config.LoadStoredClientEndpointRegistry(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, alias := range []string{"cosigner-a", "cosigner-b"} {
		if _, ok := registry.Endpoint(alias); !ok {
			t.Fatalf("concurrent endpoint %q was lost: %#v", alias, registry.Endpoints)
		}
	}
}

func TestConcurrentEndpointCreatesReportAppliedPlan(t *testing.T) {
	const workers = 32
	dataDir := t.TempDir()
	apps := make([]*App, workers)
	for i := range apps {
		apps[i] = newEndpointTestApp(t, dataDir)
	}

	start := make(chan struct{})
	results := make(chan *EndpointCreateCosignerResult, workers)
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for _, app := range apps {
		wg.Add(1)
		go func(app *App) {
			defer wg.Done()
			<-start
			result, err := app.EndpointCreateCosigner(context.Background(), EndpointCreateCosignerRequest{
				Alias: "shared", URL: "ssh://cosigner.example:2223", CosignerPort: 11270,
			})
			if err != nil {
				errs <- err
				return
			}
			results <- result
		}(app)
	}
	close(start)
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}

	created := 0
	for result := range results {
		if result.Created {
			created++
		}
		if result.Updated {
			t.Fatalf("identical concurrent upsert reported update: %#v", result)
		}
	}
	if created != 1 {
		t.Fatalf("created results = %d, want exactly one applied creation", created)
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
	data, err := endpointrefs.Marshal(endpointrefs.Envelope{
		Schema: endpointrefs.Schema, URL: "ssh://127.0.0.1:2223", SignerPort: 11270,
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "cosigner-local.endpoint.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeLiveCosignerEndpoint(t *testing.T, dir, alias, rawURL, token string) {
	t.Helper()
	if _, err := config.UpsertStoredClientEndpoint(dir, alias, config.ClientEndpointConfig{
		Role: config.ClientEndpointRoleCosigner, URL: rawURL,
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

func testCosignerPublicKeyHex() string {
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
		t.Fatalf("endpoint output leaked raw cosigner public key: %q", output)
	}
}

func newEndpointKeysServer(t *testing.T, token string, keys []signerapi.KeyInfo) *httptest.Server {
	t.Helper()
	return newEndpointRoleKeysServer(t, token, "cosigner", keys)
}

// newEndpointRoleKeysServer serves /status with nodeRole and /keys with keys,
// and records every bearer token presented to it.
func newEndpointRoleKeysServer(t *testing.T, token, nodeRole string, keys []signerapi.KeyInfo) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || (r.URL.Path != "/keys" && r.URL.Path != "/status") {
			http.NotFound(w, r)
			return
		}
		if got := r.Header.Get("Authorization"); got != "aplane "+token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/status" {
			_ = json.NewEncoder(w).Encode(signerapi.StatusResponse{NodeRole: nodeRole, State: "unlocked", ReadyForSigning: true})
			return
		}
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

func TestEndpointChangeReportsFailedConfigReload(t *testing.T) {
	dataDir := t.TempDir()
	app := New(nil, config.DefaultConfig(), dataDir)
	if err := os.WriteFile(config.GetConfigPath(dataDir), []byte("network: [unclosed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := app.EndpointCreateCosigner(context.Background(), EndpointCreateCosignerRequest{
		Alias: "cosigner", URL: "ssh://127.0.0.1:2223", CosignerPort: 12270,
	})
	if err == nil || !strings.Contains(err.Error(), "endpoint change was saved, but reloading the client config failed") {
		t.Fatalf("EndpointCreateCosigner() error = %v, want the failed reload reported", err)
	}
	if _, ok := app.Config.Endpoints.Endpoint("cosigner"); ok {
		t.Fatal("app adopted a config it could not reload")
	}
}
