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
	"testing"

	"github.com/aplane-algo/aplane/internal/attestor/keytypes"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/endpointrefs"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/tokenfile"
)

func TestEndpointImportDryRunDoesNotWriteFiles(t *testing.T) {
	dataDir := t.TempDir()
	app := newEndpointTestApp(t, dataDir)
	envelopePath := writeEndpointEnvelope(t, dataDir)

	result, err := app.EndpointImport(context.Background(), EndpointImportRequest{
		Alias:  "attestor-local",
		Path:   envelopePath,
		DryRun: true,
	})
	if err != nil {
		t.Fatalf("EndpointImport(dry-run) error = %v", err)
	}
	if !result.DryRun {
		t.Fatal("DryRun = false, want true")
	}
	if _, err := os.Stat(filepath.Join(dataDir, config.ClientEndpointsFile)); !os.IsNotExist(err) {
		t.Fatalf("endpoints.yaml stat error = %v, want not exist", err)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "config.yaml")); !os.IsNotExist(err) {
		t.Fatalf("config.yaml stat error = %v, want not exist", err)
	}
}

func TestEndpointImportWritesEndpointOnly(t *testing.T) {
	dataDir := t.TempDir()
	app := newEndpointTestApp(t, dataDir)
	envelopePath := writeEndpointEnvelope(t, dataDir)

	result, err := app.EndpointImport(context.Background(), EndpointImportRequest{
		Alias: "attestor-local",
		Path:  envelopePath,
	})
	if err != nil {
		t.Fatalf("EndpointImport() error = %v", err)
	}
	if !result.Created {
		t.Fatal("Created = false, want true")
	}
	if result.DefaultChanged {
		t.Fatal("DefaultChanged = true, want false for attestation-only endpoint")
	}

	cfg, err := config.LoadConfig(dataDir)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	endpoint, ok := cfg.Endpoints.Endpoint("attestor-local")
	if !ok {
		t.Fatal("attestor-local endpoint missing")
	}
	if endpoint.TokenFile != filepath.Join(dataDir, "tokens", "attestor-local.token") {
		t.Fatalf("TokenFile = %q, want resolved endpoint token path", endpoint.TokenFile)
	}
	if len(cfg.AttestorEndpoints) != 0 {
		t.Fatalf("AttestorEndpoints = %#v, want none from endpoint import", cfg.AttestorEndpoints)
	}
}

func TestEndpointImportReplacesSameAlias(t *testing.T) {
	dataDir := t.TempDir()
	app := newEndpointTestApp(t, dataDir)
	firstPath := writeEndpointEnvelopeWithOptions(t, dataDir, "attestor-local", "ssh://127.0.0.1:2223", 11270)
	if _, err := app.EndpointImport(context.Background(), EndpointImportRequest{
		Alias: "attestor-local",
		Path:  firstPath,
	}); err != nil {
		t.Fatalf("EndpointImport(first) error = %v", err)
	}

	secondPath := writeEndpointEnvelopeWithOptions(t, dataDir, "attestor-local-updated", "ssh://127.0.0.1:2224", 12270)
	result, err := app.EndpointImport(context.Background(), EndpointImportRequest{
		Alias: "attestor-local",
		Path:  secondPath,
	})
	if err != nil {
		t.Fatalf("EndpointImport(replace) error = %v", err)
	}
	if !result.Updated || result.Created {
		t.Fatalf("replace result Created/Updated = %v/%v, want false/true", result.Created, result.Updated)
	}

	cfg, err := config.LoadConfig(dataDir)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	endpoint, ok := cfg.Endpoints.Endpoint("attestor-local")
	if !ok {
		t.Fatal("attestor-local endpoint missing")
	}
	if endpoint.URL != "ssh://127.0.0.1:2224" || endpoint.SignerPort != 12270 {
		t.Fatalf("endpoint after replace = %#v, want updated url/signer_port", endpoint)
	}
}

func TestEndpointImportRejectsExistingURLWithDifferentAlias(t *testing.T) {
	dataDir := t.TempDir()
	app := newEndpointTestApp(t, dataDir)
	firstPath := writeEndpointEnvelopeWithOptions(t, dataDir, "attestor-local", "ssh://127.0.0.1:2223/", 11270)
	if _, err := app.EndpointImport(context.Background(), EndpointImportRequest{
		Alias: "attestor-local",
		Path:  firstPath,
	}); err != nil {
		t.Fatalf("EndpointImport(first) error = %v", err)
	}

	secondPath := writeEndpointEnvelopeWithOptions(t, dataDir, "attestor-copy", "ssh://127.0.0.1:2223", 11270)
	_, err := app.EndpointImport(context.Background(), EndpointImportRequest{
		Alias: "attestor-copy",
		Path:  secondPath,
	})
	if err == nil {
		t.Fatal("EndpointImport(duplicate URL) error = nil, want conflict")
	}
	if !strings.Contains(err.Error(), "already belongs to alias") {
		t.Fatalf("EndpointImport(duplicate URL) error = %v, want duplicate URL conflict", err)
	}

	cfg, err := config.LoadConfig(dataDir)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	if _, ok := cfg.Endpoints.Endpoint("attestor-copy"); ok {
		t.Fatal("attestor-copy endpoint was written despite duplicate URL conflict")
	}
}

func TestEndpointsListAndShowUseResolvedLocalState(t *testing.T) {
	dataDir := t.TempDir()
	app := newEndpointTestApp(t, dataDir)
	envelopePath := writeEndpointEnvelope(t, dataDir)
	if _, err := app.EndpointImport(context.Background(), EndpointImportRequest{
		Alias: "attestor-local",
		Path:  envelopePath,
	}); err != nil {
		t.Fatalf("EndpointImport() error = %v", err)
	}
	publicKeyHex := testAttestorPublicKeyHex()
	writePublishedAttestor(t, dataDir, "attestor-local", publicKeyHex)
	tokenPath := filepath.Join(dataDir, "tokens", "attestor-local.token")
	if err := os.MkdirAll(filepath.Dir(tokenPath), 0o700); err != nil {
		t.Fatalf("MkdirAll(tokens) error = %v", err)
	}
	if err := tokenfile.WriteToken(tokenPath, "token-value"); err != nil {
		t.Fatalf("WriteToken() error = %v", err)
	}

	list, err := app.EndpointsList(context.Background())
	if err != nil {
		t.Fatalf("EndpointsList() error = %v", err)
	}
	if len(list.Endpoints) != 1 {
		t.Fatalf("EndpointsList entries = %d, want 1", len(list.Endpoints))
	}
	entry := list.Endpoints[0]
	if entry.Alias != "attestor-local" || !entry.TokenPresent {
		t.Fatalf("list entry = %#v, want attestor-local with token present", entry)
	}
	if got := entry.PublishedAttestorPublicKeys; len(got) != 1 || got[0] != publicKeyHex {
		t.Fatalf("PublishedAttestorPublicKeys = %#v, want %s", got, publicKeyHex)
	}

	show, err := app.EndpointShow(context.Background(), "attestor-local")
	if err != nil {
		t.Fatalf("EndpointShow() error = %v", err)
	}
	if show.Endpoint.IdentityFile != filepath.Join(dataDir, ".ssh", "id_ed25519") {
		t.Fatalf("IdentityFile = %q, want local default", show.Endpoint.IdentityFile)
	}
	if show.Endpoint.KnownHostsPath != filepath.Join(dataDir, ".ssh", "known_hosts") {
		t.Fatalf("KnownHostsPath = %q, want local default", show.Endpoint.KnownHostsPath)
	}
}

func TestEndpointDiscoverAttestorsRebuildsMappingsFromAllEndpoints(t *testing.T) {
	dataDir := t.TempDir()
	app := newEndpointTestApp(t, dataDir)

	publicKeyHex := testAttestorPublicKeyHex()
	componentSelector := testComponentSelector(t, keytypes.AttestorComponentEd25519V1, publicKeyHex)
	attestorServer := newEndpointKeysServer(t, "att-token", []signerapi.KeyInfo{{
		Address:        componentSelector,
		PublicKeyHex:   strings.ToUpper(publicKeyHex),
		KeyType:        keytypes.AttestorComponentEd25519V1,
		IsComponentKey: true,
	}})
	signerServer := newEndpointKeysServer(t, "sign-token", []signerapi.KeyInfo{{
		Address: "ADDR",
		KeyType: keytypes.AttestedFalcon1024AttEd25519V1,
	}})

	if _, err := config.UpsertStoredClientEndpoint(dataDir, "signer-local", config.ClientEndpointConfig{
		URL: signerServer.URL,
	}, true); err != nil {
		t.Fatalf("UpsertStoredClientEndpoint(signer-local) error = %v", err)
	}
	if _, err := config.UpsertStoredClientEndpoint(dataDir, "attestor-local", config.ClientEndpointConfig{
		URL: attestorServer.URL,
	}, true); err != nil {
		t.Fatalf("UpsertStoredClientEndpoint(attestor-local) error = %v", err)
	}
	writeEndpointToken(t, dataDir, "signer-local", "sign-token")
	writeEndpointToken(t, dataDir, "attestor-local", "att-token")
	staleKeyHex := strings.Repeat("cd", 32)
	writePublishedAttestor(t, dataDir, "attestor-local", staleKeyHex)

	result, err := app.EndpointDiscoverAttestors(context.Background(), EndpointDiscoverAttestorsRequest{})
	if err != nil {
		t.Fatalf("EndpointDiscoverAttestors() error = %v", err)
	}
	if result.PublicKeyCount != 1 || result.PreviousPublishedCount != 1 {
		t.Fatalf("discovery counts = public:%d previous:%d, want 1/1", result.PublicKeyCount, result.PreviousPublishedCount)
	}
	if len(result.Endpoints) != 2 {
		t.Fatalf("discovered endpoints = %d, want 2", len(result.Endpoints))
	}

	cfg, err := config.LoadConfig(dataDir)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	route, ok := cfg.AttestorEndpoints[publicKeyHex]
	if !ok {
		t.Fatalf("attestor endpoint route for %s missing from %#v", publicKeyHex, cfg.AttestorEndpoints)
	}
	if route.Endpoint != "attestor-local" {
		t.Fatalf("route endpoint = %q, want attestor-local", route.Endpoint)
	}
	if _, ok := cfg.AttestorEndpoints[staleKeyHex]; ok {
		t.Fatalf("stale attestor endpoint route %s remained after discovery", staleKeyHex)
	}
	if _, ok := app.eng.AttestorEndpoints[publicKeyHex]; !ok {
		t.Fatalf("engine attestor routing was not refreshed for %s", publicKeyHex)
	}
}

func TestEndpointDiscoverAttestorsDryRunDoesNotWriteMappings(t *testing.T) {
	dataDir := t.TempDir()
	app := newEndpointTestApp(t, dataDir)
	publicKeyHex := testAttestorPublicKeyHex()
	attestorServer := newEndpointKeysServer(t, "att-token", []signerapi.KeyInfo{{
		Address:        testComponentSelector(t, keytypes.AttestorComponentEd25519V1, publicKeyHex),
		PublicKeyHex:   publicKeyHex,
		KeyType:        keytypes.AttestorComponentEd25519V1,
		IsComponentKey: true,
	}})
	if _, err := config.UpsertStoredClientEndpoint(dataDir, "attestor-local", config.ClientEndpointConfig{
		URL: attestorServer.URL,
	}, true); err != nil {
		t.Fatalf("UpsertStoredClientEndpoint(attestor-local) error = %v", err)
	}
	writeEndpointToken(t, dataDir, "attestor-local", "att-token")

	result, err := app.EndpointDiscoverAttestors(context.Background(), EndpointDiscoverAttestorsRequest{DryRun: true})
	if err != nil {
		t.Fatalf("EndpointDiscoverAttestors(dry-run) error = %v", err)
	}
	if !result.DryRun || result.PublicKeyCount != 1 {
		t.Fatalf("dry-run result = dry:%v public:%d, want true/1", result.DryRun, result.PublicKeyCount)
	}
	cfg, err := config.LoadConfig(dataDir)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	if len(cfg.AttestorEndpoints) != 0 {
		t.Fatalf("AttestorEndpoints = %#v, want none after dry-run", cfg.AttestorEndpoints)
	}
}

func TestEndpointDefaultSetsSigningEndpoint(t *testing.T) {
	dataDir := t.TempDir()
	app := newEndpointTestApp(t, dataDir)
	envelopePath := writeEndpointEnvelopeWithName(t, dataDir, "signer-local")
	if _, err := app.EndpointImport(context.Background(), EndpointImportRequest{
		Alias: "signer-local",
		Path:  envelopePath,
	}); err != nil {
		t.Fatalf("EndpointImport() error = %v", err)
	}

	result, err := app.EndpointDefault(context.Background(), "signer-local")
	if err != nil {
		t.Fatalf("EndpointDefault() error = %v", err)
	}
	if result.Alias != "signer-local" {
		t.Fatalf("Alias = %q, want signer-local", result.Alias)
	}
	cfg, err := config.LoadConfig(dataDir)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	alias, _, ok := cfg.Endpoints.DefaultEndpoint()
	if !ok || alias != "signer-local" {
		t.Fatalf("DefaultEndpoint() = %q/%v, want signer-local/true", alias, ok)
	}
}

func TestEndpointDeleteRejectsMappedAttestorEndpoint(t *testing.T) {
	dataDir := t.TempDir()
	app := newEndpointTestApp(t, dataDir)
	envelopePath := writeEndpointEnvelope(t, dataDir)
	if _, err := app.EndpointImport(context.Background(), EndpointImportRequest{
		Alias: "attestor-local",
		Path:  envelopePath,
	}); err != nil {
		t.Fatalf("EndpointImport() error = %v", err)
	}
	publicKeyHex := testAttestorPublicKeyHex()
	writePublishedAttestor(t, dataDir, "attestor-local", publicKeyHex)

	_, err := app.EndpointDelete(context.Background(), "attestor-local")
	if err == nil {
		t.Fatal("EndpointDelete(mapped) error = nil, want rejection")
	}
	if !strings.Contains(err.Error(), publicKeyHex) {
		t.Fatalf("EndpointDelete(mapped) error = %v, want blocking key", err)
	}
}

func TestEndpointDeleteRemovesUnreferencedEndpoint(t *testing.T) {
	dataDir := t.TempDir()
	app := newEndpointTestApp(t, dataDir)
	primaryPath := writeEndpointEnvelopeWithName(t, dataDir, "primary")
	if _, err := app.EndpointImport(context.Background(), EndpointImportRequest{
		Alias: "primary",
		Path:  primaryPath,
	}); err != nil {
		t.Fatalf("EndpointImport(primary) error = %v", err)
	}
	secondaryPath := writeEndpointEnvelopeWithOptions(t, dataDir, "secondary", "ssh://127.0.0.1:2224", 11270)
	if _, err := app.EndpointImport(context.Background(), EndpointImportRequest{
		Alias: "secondary",
		Path:  secondaryPath,
	}); err != nil {
		t.Fatalf("EndpointImport(secondary) error = %v", err)
	}

	if _, err := app.EndpointDelete(context.Background(), "secondary"); err != nil {
		t.Fatalf("EndpointDelete(secondary) error = %v", err)
	}
	cfg, err := config.LoadConfig(dataDir)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	if _, ok := cfg.Endpoints.Endpoint("secondary"); ok {
		t.Fatal("secondary endpoint still present after delete")
	}
	if alias, _, ok := cfg.Endpoints.DefaultEndpoint(); ok || alias != "" {
		t.Fatalf("DefaultEndpoint() = %q/%v, want none after import-only flow", alias, ok)
	}
}

func newEndpointTestApp(t *testing.T, dataDir string) *App {
	t.Helper()
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	return New(eng, config.DefaultConfig(), dataDir)
}

func writeEndpointEnvelope(t *testing.T, dir string) string {
	t.Helper()
	return writeEndpointEnvelopeWithName(t, dir, "attestor-local")
}

func writeEndpointEnvelopeWithName(t *testing.T, dir, name string) string {
	t.Helper()
	return writeEndpointEnvelopeWithOptions(t, dir, name, "ssh://127.0.0.1:2223", 11270)
}

func writeEndpointEnvelopeWithOptions(t *testing.T, dir, name, rawURL string, signerPort int) string {
	t.Helper()
	data, err := endpointrefs.Marshal(endpointrefs.Envelope{
		Schema:     endpointrefs.Schema,
		URL:        rawURL,
		SignerPort: signerPort,
	})
	if err != nil {
		t.Fatalf("endpointrefs.Marshal() error = %v", err)
	}
	path := filepath.Join(dir, name+".endpoint.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile(endpoint) error = %v", err)
	}
	return path
}

func writePublishedAttestor(t *testing.T, dir, alias, publicKeyHex string) {
	t.Helper()
	_, err := config.RebuildStoredClientEndpointPublishedAttestors(dir, map[string]map[string]config.ClientEndpointPublishedAttestor{
		alias: {
			publicKeyHex: {
				ComponentKey: testComponentSelector(t, keytypes.AttestorComponentEd25519V1, publicKeyHex),
				KeyType:      keytypes.AttestorComponentEd25519V1,
				LastSeenAt:   "2026-06-04T00:00:00Z",
			},
		},
	})
	if err != nil {
		t.Fatalf("RebuildStoredClientEndpointPublishedAttestors() error = %v", err)
	}
}

func testAttestorPublicKeyHex() string {
	return strings.Repeat("ab", 32)
}

func writeEndpointToken(t *testing.T, dir, alias, token string) {
	t.Helper()
	path := filepath.Join(dir, "tokens", alias+".token")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll(tokens) error = %v", err)
	}
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(token) error = %v", err)
	}
}

func testComponentSelector(t *testing.T, keyType, publicKeyHex string) string {
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
		_ = json.NewEncoder(w).Encode(signerapi.KeysResponse{
			Count: len(keys),
			Keys:  keys,
		})
	}))
	t.Cleanup(server.Close)
	return server
}
