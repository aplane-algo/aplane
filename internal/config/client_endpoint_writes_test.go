// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUpsertStoredClientEndpointFirstImportDefaultRules(t *testing.T) {
	dataDir := t.TempDir()
	registry, err := UpsertStoredClientEndpoint(dataDir, "attestor-local", ClientEndpointConfig{
		Role:       "attestation",
		URL:        "ssh://127.0.0.1:2223",
		SignerPort: 11270,
	}, false)
	if err != nil {
		t.Fatalf("UpsertStoredClientEndpoint(attestation) error = %v", err)
	}
	if registry.Default != "" {
		t.Fatalf("Default = %q, want empty for first attestation endpoint", registry.Default)
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

	signingDir := t.TempDir()
	registry, err = UpsertStoredClientEndpoint(signingDir, "primary", ClientEndpointConfig{
		Role: "signing",
		URL:  "ssh://signer.example:2222",
	}, false)
	if err != nil {
		t.Fatalf("UpsertStoredClientEndpoint(signing) error = %v", err)
	}
	if registry.Default != "primary" {
		t.Fatalf("Default = %q, want primary", registry.Default)
	}
}

func TestUpsertStoredClientEndpointRejectsConflict(t *testing.T) {
	dataDir := t.TempDir()
	if _, err := UpsertStoredClientEndpoint(dataDir, "attestor-local", ClientEndpointConfig{
		Role: "attestation",
		URL:  "ssh://127.0.0.1:2223",
	}, false); err != nil {
		t.Fatalf("UpsertStoredClientEndpoint(first) error = %v", err)
	}
	_, err := UpsertStoredClientEndpoint(dataDir, "attestor-local", ClientEndpointConfig{
		Role: "attestation",
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
		Role: "attestation",
		URL:  "ssh://127.0.0.1:2223/",
	}, false); err != nil {
		t.Fatalf("UpsertStoredClientEndpoint(first) error = %v", err)
	}

	_, err := UpsertStoredClientEndpoint(dataDir, "attestor-copy", ClientEndpointConfig{
		Role: "attestation",
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

	_, err := UpsertStoredClientEndpoint(dataDir, "attestor-local", ClientEndpointConfig{
		Role: "attestation",
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
	if _, ok := registry.Endpoints["attestor-local"]; ok {
		t.Fatal("attestor-local endpoint was written despite legacy primary URL conflict")
	}
}

func TestUpsertClientAttestorEndpointAliasesAtomicConflict(t *testing.T) {
	dataDir := t.TempDir()
	publicKey1 := attestorEndpointTestHex("a1")
	publicKey2 := attestorEndpointTestHex("b2")
	if err := UpsertClientAttestorEndpointAliases(dataDir, "attestor-local", []string{publicKey1}); err != nil {
		t.Fatalf("UpsertClientAttestorEndpointAliases(first) error = %v", err)
	}

	err := UpsertClientAttestorEndpointAliases(dataDir, "other-attestor", []string{publicKey1, publicKey2})
	if err == nil {
		t.Fatal("UpsertClientAttestorEndpointAliases(conflict) error = nil, want conflict")
	}
	if !strings.Contains(err.Error(), "already maps to endpoint alias") {
		t.Fatalf("conflict error = %v", err)
	}

	mappings, err := ClientAttestorEndpointMappingsByAlias(dataDir)
	if err != nil {
		t.Fatalf("ClientAttestorEndpointMappingsByAlias() error = %v", err)
	}
	if got := mappings["attestor-local"]; len(got) != 1 || got[0] != publicKey1 {
		t.Fatalf("attestor-local mappings = %#v, want only publicKey1", got)
	}
	if got := mappings["other-attestor"]; len(got) != 0 {
		t.Fatalf("other-attestor mappings = %#v, want none after atomic conflict", got)
	}
}

func TestUpsertClientAttestorEndpointAliasesRejectsInlineRoute(t *testing.T) {
	dataDir := t.TempDir()
	publicKey := attestorEndpointTestHex("c3")
	if err := os.WriteFile(filepath.Join(dataDir, "config.yaml"), []byte(`
attestor_endpoints:
  `+publicKey+`:
    url: self
`), 0o600); err != nil {
		t.Fatalf("WriteFile(config) error = %v", err)
	}

	err := UpsertClientAttestorEndpointAliases(dataDir, "attestor-local", []string{publicKey})
	if err == nil {
		t.Fatal("UpsertClientAttestorEndpointAliases(inline) error = nil, want conflict")
	}
	if !strings.Contains(err.Error(), "inline route") {
		t.Fatalf("inline conflict error = %v", err)
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
