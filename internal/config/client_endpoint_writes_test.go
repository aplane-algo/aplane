// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package config

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
)

const endpointPublishedTestSeenAt = "2026-06-04T00:00:00Z"

func TestUpsertStoredClientEndpointDoesNotAutoDefault(t *testing.T) {
	dataDir := t.TempDir()
	registry, err := UpsertStoredClientEndpoint(dataDir, "sentry-local", ClientEndpointConfig{
		Role:       ClientEndpointRoleSentry,
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
	endpoint, ok := cfg.Endpoints.Endpoint("sentry-local")
	if !ok {
		t.Fatal("sentry-local endpoint missing after LoadConfig")
	}
	if endpoint.TokenFile != filepath.Join(dataDir, "tokens", "sentry-local.token") {
		t.Fatalf("TokenFile = %q, want resolved default token path", endpoint.TokenFile)
	}
}

func TestUpsertStoredClientEndpointDoesNotMaterializeLegacyPrimaryForAttestor(t *testing.T) {
	dataDir := t.TempDir()
	writeLegacyClientEndpointConfig(t, dataDir)

	registry, err := UpsertStoredClientEndpoint(dataDir, "sentry-local", ClientEndpointConfig{
		Role:       ClientEndpointRoleSentry,
		URL:        "ssh://127.0.0.1:2223",
		SignerPort: 11271,
	}, false)
	if err != nil {
		t.Fatalf("UpsertStoredClientEndpoint(sentry) error = %v", err)
	}
	if registry.Default != "" {
		t.Fatalf("Default = %q, want empty", registry.Default)
	}
	if _, ok := registry.Endpoints[DefaultClientEndpointName]; ok {
		t.Fatal("primary endpoint was materialized from legacy config")
	}
	if _, ok := registry.Endpoints["sentry-local"]; !ok {
		t.Fatal("sentry-local endpoint missing")
	}

	stored, exists, err := LoadStoredClientEndpointRegistry(dataDir)
	if err != nil {
		t.Fatalf("LoadStoredClientEndpointRegistry() error = %v", err)
	}
	if !exists {
		t.Fatal("endpoints.yaml was not written")
	}
	if _, ok := stored.Endpoints[DefaultClientEndpointName]; ok {
		t.Fatal("stored primary endpoint was materialized from legacy config")
	}
}

func TestUpsertStoredClientEndpointRejectsConflict(t *testing.T) {
	dataDir := t.TempDir()
	if _, err := UpsertStoredClientEndpoint(dataDir, "sentry-local", ClientEndpointConfig{
		Role: ClientEndpointRoleSentry,
		URL:  "ssh://127.0.0.1:2223",
	}, false); err != nil {
		t.Fatalf("UpsertStoredClientEndpoint(first) error = %v", err)
	}
	_, err := UpsertStoredClientEndpoint(dataDir, "sentry-local", ClientEndpointConfig{
		Role: ClientEndpointRoleSentry,
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
	if got := registry.Endpoints["sentry-local"].URL; got != "ssh://127.0.0.1:2223" {
		t.Fatalf("stored URL = %q, want original URL", got)
	}
}

func TestUpsertStoredClientEndpointRejectsDuplicateURLAcrossAliases(t *testing.T) {
	dataDir := t.TempDir()
	if _, err := UpsertStoredClientEndpoint(dataDir, "sentry-local", ClientEndpointConfig{
		Role: ClientEndpointRoleSentry,
		URL:  "ssh://127.0.0.1:2223/",
	}, false); err != nil {
		t.Fatalf("UpsertStoredClientEndpoint(first) error = %v", err)
	}

	_, err := UpsertStoredClientEndpoint(dataDir, "sentry-copy", ClientEndpointConfig{
		Role: ClientEndpointRoleSentry,
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
	if _, ok := registry.Endpoints["sentry-copy"]; ok {
		t.Fatal("sentry-copy endpoint was written despite duplicate URL conflict")
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
	if _, err := UpsertStoredClientEndpoint(dataDir, "local-sentry", ClientEndpointConfig{
		Role: ClientEndpointRoleSentry,
		URL:  "ssh://127.0.0.1:2223",
	}, true); err != nil {
		t.Fatalf("UpsertStoredClientEndpoint(sentry same URL) error = %v", err)
	}
}

func TestRebuildStoredClientEndpointPublishedSentriesReplacesInventory(t *testing.T) {
	dataDir := t.TempDir()
	if _, err := UpsertStoredClientEndpoint(dataDir, "sentry-local", ClientEndpointConfig{
		Role: ClientEndpointRoleSentry,
		URL:  "ssh://127.0.0.1:2223",
	}, true); err != nil {
		t.Fatalf("UpsertStoredClientEndpoint(sentry-local) error = %v", err)
	}
	staleKey := attestorEndpointTestHex("a1")
	if _, err := RebuildStoredClientEndpointPublishedSentries(dataDir, map[string]map[string]ClientEndpointPublishedSentry{
		"sentry-local": {
			staleKey: endpointPublishedTestAttestor(t, staleKey),
		},
	}); err != nil {
		t.Fatalf("RebuildStoredClientEndpointPublishedSentries(stale) error = %v", err)
	}

	newKey := attestorEndpointTestHex("b2")
	plan, err := RebuildStoredClientEndpointPublishedSentries(dataDir, map[string]map[string]ClientEndpointPublishedSentry{
		"sentry-local": {
			newKey: endpointPublishedTestAttestor(t, newKey),
		},
	})
	if err != nil {
		t.Fatalf("RebuildStoredClientEndpointPublishedSentries(new) error = %v", err)
	}
	if plan.PublicKeyCount != 1 || plan.PreviousPublishedCount != 1 {
		t.Fatalf("plan counts = public:%d previous:%d, want 1/1", plan.PublicKeyCount, plan.PreviousPublishedCount)
	}

	cfg, err := LoadConfig(dataDir)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	published := cfg.Endpoints.Endpoints["sentry-local"].PublishedSentries
	if _, ok := published[staleKey]; ok {
		t.Fatalf("stale published sentry %s remained in %#v", staleKey, published)
	}
	if got := published[newKey]; got.ComponentKey == "" || got.KeyType != keytypes.SentryComponentEd25519V1 {
		t.Fatalf("new published sentry = %#v, want Ed25519 component metadata", got)
	}
	if route := cfg.AttestorEndpoints[newKey]; route.Endpoint != "sentry-local" {
		t.Fatalf("derived route = %#v, want sentry-local", route)
	}
}

func TestRebuildStoredClientEndpointPublishedSentriesRejectsDuplicatePublicKey(t *testing.T) {
	dataDir := t.TempDir()
	for _, alias := range []string{"sentry-a", "sentry-b"} {
		if _, err := UpsertStoredClientEndpoint(dataDir, alias, ClientEndpointConfig{
			Role: ClientEndpointRoleSentry,
			URL:  "ssh://" + alias + ":2223",
		}, true); err != nil {
			t.Fatalf("UpsertStoredClientEndpoint(%s) error = %v", alias, err)
		}
	}
	publicKey := attestorEndpointTestHex("c3")
	_, err := PlanStoredClientEndpointPublishedSentryRebuild(dataDir, map[string]map[string]ClientEndpointPublishedSentry{
		"sentry-a": {
			publicKey: endpointPublishedTestAttestor(t, publicKey),
		},
		"sentry-b": {
			publicKey: endpointPublishedTestAttestor(t, publicKey),
		},
	})
	if err == nil {
		t.Fatal("PlanStoredClientEndpointPublishedSentryRebuild() error = nil, want duplicate rejection")
	}
	if !strings.Contains(err.Error(), "advertised by both endpoint aliases") {
		t.Fatalf("duplicate error = %v", err)
	}
}

func TestSetStoredClientEndpointDefaultDoesNotMaterializeLegacyPrimary(t *testing.T) {
	dataDir := t.TempDir()
	writeLegacyClientEndpointConfig(t, dataDir)

	_, err := SetStoredClientEndpointDefault(dataDir, "primary")
	if err == nil {
		t.Fatal("SetStoredClientEndpointDefault(primary) error = nil, want missing endpoint")
	}
	if !strings.Contains(err.Error(), "not defined") {
		t.Fatalf("error = %v, want not defined", err)
	}
}

func TestCheckSupportedClientEndpointConfigRejectsLegacySSH(t *testing.T) {
	dataDir := t.TempDir()
	writeLegacyClientEndpointConfig(t, dataDir)

	err := CheckSupportedClientEndpointConfig(dataDir)
	if err == nil {
		t.Fatal("CheckSupportedClientEndpointConfig() error = nil, want unsupported config")
	}
	if !strings.Contains(err.Error(), "new-install-only") {
		t.Fatalf("error = %v, want new-install-only guidance", err)
	}
}

func TestCheckSupportedClientEndpointConfigRejectsLegacySSHWithSignerEndpoint(t *testing.T) {
	dataDir := t.TempDir()
	writeLegacyClientEndpointConfig(t, dataDir)
	if err := os.WriteFile(filepath.Join(dataDir, ClientEndpointsFile), []byte(`
schema_version: 1
default: primary
endpoints:
  primary:
    role: signer
    url: ssh://signer.example:2222
    signer_port: 12270
`), 0o600); err != nil {
		t.Fatalf("WriteFile(endpoints) error = %v", err)
	}

	err := CheckSupportedClientEndpointConfig(dataDir)
	if err == nil {
		t.Fatal("CheckSupportedClientEndpointConfig() error = nil, want unsupported config")
	}
	if !strings.Contains(err.Error(), "top-level ssh") {
		t.Fatalf("error = %v, want top-level ssh guidance", err)
	}
}

func TestCheckSupportedClientEndpointConfigRejectsMalformedLegacySSH(t *testing.T) {
	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, "config.yaml"), []byte(`
network: testnet
ssh: {}
`), 0o600); err != nil {
		t.Fatalf("WriteFile(config) error = %v", err)
	}

	err := CheckSupportedClientEndpointConfig(dataDir)
	if err == nil {
		t.Fatal("CheckSupportedClientEndpointConfig() error = nil, want unsupported config")
	}
	if !strings.Contains(err.Error(), "top-level ssh") {
		t.Fatalf("error = %v, want top-level ssh guidance", err)
	}
}

func endpointPublishedTestAttestor(t *testing.T, publicKeyHex string) ClientEndpointPublishedSentry {
	t.Helper()
	return ClientEndpointPublishedSentry{
		ComponentKey: attestorEndpointTestComponentKey(t, keytypes.SentryComponentEd25519V1, publicKeyHex),
		KeyType:      keytypes.SentryComponentEd25519V1,
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

func writeLegacyClientEndpointConfig(t *testing.T, dataDir string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dataDir, "config.yaml"), []byte(`
ssh:
  host: signer.example
  port: 2222
signer_port: 12270
`), 0o600); err != nil {
		t.Fatalf("WriteFile(config) error = %v", err)
	}
}
