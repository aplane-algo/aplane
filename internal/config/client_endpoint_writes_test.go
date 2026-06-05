// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package config

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/attestor/keytypes"
)

const endpointPublishedTestSeenAt = "2026-06-04T00:00:00Z"

func TestUpsertStoredClientEndpointDoesNotAutoDefault(t *testing.T) {
	dataDir := t.TempDir()
	registry, err := UpsertStoredClientEndpoint(dataDir, "attestor-local", ClientEndpointConfig{
		Role:       ClientEndpointRoleAttestor,
		URL:        "ssh://127.0.0.1:2223",
		SignerPort: 11270,
	}, false)
	if err != nil {
		t.Fatalf("UpsertStoredClientEndpoint(first) error = %v", err)
	}
	if registry.Default != "" {
		t.Fatalf("Default = %q, want empty for first endpoint", registry.Default)
	}

	cfg, err := LoadConfig(dataDir)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	if alias, _, ok := cfg.Endpoints.DefaultEndpoint(); ok || alias != "" {
		t.Fatalf("DefaultEndpoint() = %q/%v, want none", alias, ok)
	}
	endpoint, ok := cfg.Endpoints.Endpoint("attestor-local")
	if !ok {
		t.Fatal("attestor-local endpoint missing after LoadConfig")
	}
	if endpoint.TokenFile != filepath.Join(dataDir, "tokens", "attestor-local.token") {
		t.Fatalf("TokenFile = %q, want resolved default token path", endpoint.TokenFile)
	}
}

func TestUpsertStoredClientEndpointRejectsConflict(t *testing.T) {
	dataDir := t.TempDir()
	if _, err := UpsertStoredClientEndpoint(dataDir, "attestor-local", ClientEndpointConfig{
		Role: ClientEndpointRoleAttestor,
		URL:  "ssh://127.0.0.1:2223",
	}, false); err != nil {
		t.Fatalf("UpsertStoredClientEndpoint(first) error = %v", err)
	}
	_, err := UpsertStoredClientEndpoint(dataDir, "attestor-local", ClientEndpointConfig{
		Role: ClientEndpointRoleAttestor,
		URL:  "ssh://127.0.0.1:2224",
	}, false)
	if err == nil {
		t.Fatal("UpsertStoredClientEndpoint(conflict) error = nil, want conflict")
	}
	if !strings.Contains(err.Error(), "already exists with different settings") {
		t.Fatalf("conflict error = %v", err)
	}
	registry, _, err := LoadStoredClientEndpointRegistry(dataDir)
	if err != nil {
		t.Fatalf("LoadStoredClientEndpointRegistry() error = %v", err)
	}
	if got := registry.Endpoints["attestor-local"].URL; got != "ssh://127.0.0.1:2223" {
		t.Fatalf("stored URL = %q, want original URL", got)
	}
}

func TestUpsertStoredClientEndpointRejectsDuplicateURLAcrossAliases(t *testing.T) {
	dataDir := t.TempDir()
	if _, err := UpsertStoredClientEndpoint(dataDir, "attestor-local", ClientEndpointConfig{
		Role: ClientEndpointRoleAttestor,
		URL:  "ssh://127.0.0.1:2223/",
	}, false); err != nil {
		t.Fatalf("UpsertStoredClientEndpoint(first) error = %v", err)
	}

	_, err := UpsertStoredClientEndpoint(dataDir, "attestor-copy", ClientEndpointConfig{
		Role: ClientEndpointRoleAttestor,
		URL:  "ssh://127.0.0.1:2223",
	}, true)
	if err == nil {
		t.Fatal("UpsertStoredClientEndpoint(duplicate URL) error = nil, want conflict")
	}
	if !strings.Contains(err.Error(), "already belongs to alias") {
		t.Fatalf("duplicate URL error = %v", err)
	}

	registry, _, err := LoadStoredClientEndpointRegistry(dataDir)
	if err != nil {
		t.Fatalf("LoadStoredClientEndpointRegistry() error = %v", err)
	}
	if _, ok := registry.Endpoints["attestor-copy"]; ok {
		t.Fatal("attestor-copy endpoint was written despite duplicate URL conflict")
	}
}

func TestUpsertStoredClientEndpointAllowsDuplicateURLAcrossRoles(t *testing.T) {
	dataDir := t.TempDir()
	if _, err := UpsertStoredClientEndpoint(dataDir, "main", ClientEndpointConfig{
		Role: ClientEndpointRoleSigner,
		URL:  "ssh://127.0.0.1:2223",
	}, true); err != nil {
		t.Fatalf("UpsertStoredClientEndpoint(signer) error = %v", err)
	}
	if _, err := UpsertStoredClientEndpoint(dataDir, "local-attestor", ClientEndpointConfig{
		Role: ClientEndpointRoleAttestor,
		URL:  "ssh://127.0.0.1:2223",
	}, true); err != nil {
		t.Fatalf("UpsertStoredClientEndpoint(attestor same URL) error = %v", err)
	}
}

func TestUpsertStoredClientEndpointRejectsDuplicateLegacyPrimaryURL(t *testing.T) {
	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, "config.yaml"), []byte(`
ssh:
  host: signer.example
  port: 2222
signer_port: 12270
`), 0o600); err != nil {
		t.Fatalf("WriteFile(config) error = %v", err)
	}

	_, err := UpsertStoredClientEndpoint(dataDir, "signer-local", ClientEndpointConfig{
		Role: ClientEndpointRoleSigner,
		URL:  "ssh://signer.example:2222",
	}, true)
	if err == nil {
		t.Fatal("UpsertStoredClientEndpoint(legacy duplicate URL) error = nil, want conflict")
	}
	if !strings.Contains(err.Error(), `alias "primary"`) {
		t.Fatalf("legacy duplicate URL error = %v, want primary alias conflict", err)
	}

	registry, _, err := LoadStoredClientEndpointRegistry(dataDir)
	if err != nil {
		t.Fatalf("LoadStoredClientEndpointRegistry() error = %v", err)
	}
	if _, ok := registry.Endpoints["signer-local"]; ok {
		t.Fatal("signer-local endpoint was written despite legacy primary URL conflict")
	}
}

func TestRebuildStoredClientEndpointPublishedAttestorsReplacesInventory(t *testing.T) {
	dataDir := t.TempDir()
	if _, err := UpsertStoredClientEndpoint(dataDir, "attestor-local", ClientEndpointConfig{
		Role: ClientEndpointRoleAttestor,
		URL:  "ssh://127.0.0.1:2223",
	}, true); err != nil {
		t.Fatalf("UpsertStoredClientEndpoint(attestor-local) error = %v", err)
	}
	staleKey := attestorEndpointTestHex("a1")
	if _, err := RebuildStoredClientEndpointPublishedAttestors(dataDir, map[string]map[string]ClientEndpointPublishedAttestor{
		"attestor-local": {
			staleKey: endpointPublishedTestAttestor(t, staleKey),
		},
	}); err != nil {
		t.Fatalf("RebuildStoredClientEndpointPublishedAttestors(stale) error = %v", err)
	}

	newKey := attestorEndpointTestHex("b2")
	plan, err := RebuildStoredClientEndpointPublishedAttestors(dataDir, map[string]map[string]ClientEndpointPublishedAttestor{
		"attestor-local": {
			newKey: endpointPublishedTestAttestor(t, newKey),
		},
	})
	if err != nil {
		t.Fatalf("RebuildStoredClientEndpointPublishedAttestors(new) error = %v", err)
	}
	if plan.PublicKeyCount != 1 || plan.PreviousPublishedCount != 1 {
		t.Fatalf("plan counts = public:%d previous:%d, want 1/1", plan.PublicKeyCount, plan.PreviousPublishedCount)
	}

	cfg, err := LoadConfig(dataDir)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	published := cfg.Endpoints.Endpoints["attestor-local"].PublishedAttestors
	if _, ok := published[staleKey]; ok {
		t.Fatalf("stale published attestor %s remained in %#v", staleKey, published)
	}
	if got := published[newKey]; got.ComponentKey == "" || got.KeyType != keytypes.AttestorComponentEd25519V1 {
		t.Fatalf("new published attestor = %#v, want Ed25519 component metadata", got)
	}
	if route := cfg.AttestorEndpoints[newKey]; route.Endpoint != "attestor-local" {
		t.Fatalf("derived route = %#v, want attestor-local", route)
	}
}

func TestRebuildStoredClientEndpointPublishedAttestorsRejectsDuplicatePublicKey(t *testing.T) {
	dataDir := t.TempDir()
	for _, alias := range []string{"attestor-a", "attestor-b"} {
		if _, err := UpsertStoredClientEndpoint(dataDir, alias, ClientEndpointConfig{
			Role: ClientEndpointRoleAttestor,
			URL:  "ssh://" + alias + ":2223",
		}, true); err != nil {
			t.Fatalf("UpsertStoredClientEndpoint(%s) error = %v", alias, err)
		}
	}
	publicKey := attestorEndpointTestHex("c3")
	_, err := PlanStoredClientEndpointPublishedAttestorRebuild(dataDir, map[string]map[string]ClientEndpointPublishedAttestor{
		"attestor-a": {
			publicKey: endpointPublishedTestAttestor(t, publicKey),
		},
		"attestor-b": {
			publicKey: endpointPublishedTestAttestor(t, publicKey),
		},
	})
	if err == nil {
		t.Fatal("PlanStoredClientEndpointPublishedAttestorRebuild() error = nil, want duplicate rejection")
	}
	if !strings.Contains(err.Error(), "advertised by both endpoint aliases") {
		t.Fatalf("duplicate error = %v", err)
	}
}

func TestSetStoredClientEndpointDefaultMaterializesLegacyPrimary(t *testing.T) {
	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, "config.yaml"), []byte(`
ssh:
  host: signer.example
  port: 2222
signer_port: 12270
`), 0o600); err != nil {
		t.Fatalf("WriteFile(config) error = %v", err)
	}

	registry, err := SetStoredClientEndpointDefault(dataDir, "primary")
	if err != nil {
		t.Fatalf("SetStoredClientEndpointDefault(primary) error = %v", err)
	}
	if registry.Default != "primary" {
		t.Fatalf("Default = %q, want primary", registry.Default)
	}
	endpoint := registry.Endpoints["primary"]
	if endpoint.URL != "ssh://signer.example:2222" || endpoint.TokenFile != "aplane.token" {
		t.Fatalf("primary endpoint = %#v, want legacy primary materialized", endpoint)
	}
}

func endpointPublishedTestAttestor(t *testing.T, publicKeyHex string) ClientEndpointPublishedAttestor {
	t.Helper()
	return ClientEndpointPublishedAttestor{
		ComponentKey: attestorEndpointTestComponentKey(t, keytypes.AttestorComponentEd25519V1, publicKeyHex),
		KeyType:      keytypes.AttestorComponentEd25519V1,
		LastSeenAt:   endpointPublishedTestSeenAt,
	}
}

func attestorEndpointTestComponentKey(t *testing.T, keyType, publicKeyHex string) string {
	t.Helper()
	publicKey, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		t.Fatalf("DecodeString(publicKeyHex) error = %v", err)
	}
	componentKey, err := keytypes.ComponentKeySelector(keyType, publicKey)
	if err != nil {
		t.Fatalf("ComponentKeySelector() error = %v", err)
	}
	return componentKey
}
