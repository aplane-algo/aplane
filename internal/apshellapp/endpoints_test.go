// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/attestor/keytypes"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/endpointrefs"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/tokenfile"
)

func TestEndpointImportDryRunDoesNotWriteFiles(t *testing.T) {
	dataDir := t.TempDir()
	app := newEndpointTestApp(t, dataDir)
	envelopePath, publicKeyHex := writeEndpointEnvelope(t, dataDir, endpointrefs.RoleAttestation)

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
	if got := result.AttestorPublicKeys; len(got) != 1 || got[0] != publicKeyHex {
		t.Fatalf("AttestorPublicKeys = %#v, want %s", got, publicKeyHex)
	}
	if _, err := os.Stat(filepath.Join(dataDir, config.ClientEndpointsFile)); !os.IsNotExist(err) {
		t.Fatalf("endpoints.yaml stat error = %v, want not exist", err)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "config.yaml")); !os.IsNotExist(err) {
		t.Fatalf("config.yaml stat error = %v, want not exist", err)
	}
}

func TestEndpointImportWritesEndpointAndAttestorMapping(t *testing.T) {
	dataDir := t.TempDir()
	app := newEndpointTestApp(t, dataDir)
	envelopePath, publicKeyHex := writeEndpointEnvelope(t, dataDir, endpointrefs.RoleAttestation)

	result, err := app.EndpointImport(context.Background(), EndpointImportRequest{Alias: "attestor-local", Path: envelopePath})
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
	route, ok := cfg.AttestorEndpoints[publicKeyHex]
	if !ok {
		t.Fatalf("attestor route for %s missing", publicKeyHex)
	}
	if route.Endpoint != "attestor-local" {
		t.Fatalf("route.Endpoint = %q, want attestor-local", route.Endpoint)
	}
	if route.URL != endpoint.URL {
		t.Fatalf("route.URL = %q, want %q", route.URL, endpoint.URL)
	}
}

func TestEndpointsListAndShowUseResolvedLocalState(t *testing.T) {
	dataDir := t.TempDir()
	app := newEndpointTestApp(t, dataDir)
	envelopePath, publicKeyHex := writeEndpointEnvelope(t, dataDir, endpointrefs.RoleAttestation)
	if _, err := app.EndpointImport(context.Background(), EndpointImportRequest{Alias: "attestor-local", Path: envelopePath}); err != nil {
		t.Fatalf("EndpointImport() error = %v", err)
	}
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
	if got := entry.LocalAttestorPublicKeys; len(got) != 1 || got[0] != publicKeyHex {
		t.Fatalf("LocalAttestorPublicKeys = %#v, want %s", got, publicKeyHex)
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

func TestEndpointDefaultRejectsAttestationEndpoint(t *testing.T) {
	dataDir := t.TempDir()
	app := newEndpointTestApp(t, dataDir)
	envelopePath, _ := writeEndpointEnvelope(t, dataDir, endpointrefs.RoleAttestation)
	if _, err := app.EndpointImport(context.Background(), EndpointImportRequest{Alias: "attestor-local", Path: envelopePath}); err != nil {
		t.Fatalf("EndpointImport() error = %v", err)
	}

	_, err := app.EndpointDefault(context.Background(), "attestor-local")
	if err == nil {
		t.Fatal("EndpointDefault(attestation) error = nil, want rejection")
	}
}

func TestEndpointDefaultSetsSigningEndpoint(t *testing.T) {
	dataDir := t.TempDir()
	app := newEndpointTestApp(t, dataDir)
	envelopePath, _ := writeEndpointEnvelopeWithName(t, dataDir, "signer-local", endpointrefs.RoleSigning)
	if _, err := app.EndpointImport(context.Background(), EndpointImportRequest{Alias: "signer-local", Path: envelopePath}); err != nil {
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
	envelopePath, publicKeyHex := writeEndpointEnvelope(t, dataDir, endpointrefs.RoleAttestation)
	if _, err := app.EndpointImport(context.Background(), EndpointImportRequest{Alias: "attestor-local", Path: envelopePath}); err != nil {
		t.Fatalf("EndpointImport() error = %v", err)
	}

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
	primaryPath, _ := writeEndpointEnvelopeWithName(t, dataDir, "primary", endpointrefs.RoleSigning)
	if _, err := app.EndpointImport(context.Background(), EndpointImportRequest{Alias: "primary", Path: primaryPath}); err != nil {
		t.Fatalf("EndpointImport(primary) error = %v", err)
	}
	secondaryPath, _ := writeEndpointEnvelopeWithName(t, dataDir, "secondary", endpointrefs.RoleSigning)
	if _, err := app.EndpointImport(context.Background(), EndpointImportRequest{Alias: "secondary", Path: secondaryPath}); err != nil {
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
	if alias, _, ok := cfg.Endpoints.DefaultEndpoint(); !ok || alias != "primary" {
		t.Fatalf("DefaultEndpoint() = %q/%v, want primary/true", alias, ok)
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

func writeEndpointEnvelope(t *testing.T, dir, role string) (string, string) {
	t.Helper()
	return writeEndpointEnvelopeWithName(t, dir, "attestor-local", role)
}

func writeEndpointEnvelopeWithName(t *testing.T, dir, name, role string) (string, string) {
	t.Helper()
	publicKey := make([]byte, 32)
	for i := range publicKey {
		publicKey[i] = byte(i)
	}
	componentKey, err := keytypes.ComponentKeySelector(keytypes.AttestorComponentEd25519V1, publicKey)
	if err != nil {
		t.Fatalf("ComponentKeySelector() error = %v", err)
	}
	publicKeyHex := hex.EncodeToString(publicKey)
	data, err := endpointrefs.Marshal(endpointrefs.Envelope{
		Kind:          endpointrefs.Kind,
		SchemaVersion: endpointrefs.SchemaVersion,
		Role:          role,
		URL:           "ssh://127.0.0.1:2223",
		SignerPort:    11270,
		AttestorPublicKeys: []endpointrefs.AttestorPublicKey{{
			KeyType:      keytypes.AttestorComponentEd25519V1,
			PublicKeyHex: publicKeyHex,
			ComponentKey: componentKey,
		}},
	})
	if err != nil {
		t.Fatalf("endpointrefs.Marshal() error = %v", err)
	}
	path := filepath.Join(dir, name+".endpoint.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile(endpoint) error = %v", err)
	}
	return path, publicKeyHex
}
