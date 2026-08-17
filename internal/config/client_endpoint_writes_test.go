// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

func TestUpsertStoredClientEndpointDoesNotMaterializeLegacyPrimaryForSentry(t *testing.T) {
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

func TestStoredClientEndpointV1ReadDropsPublishedInventoryAndWritesV2(t *testing.T) {
	dataDir := t.TempDir()
	path := GetClientEndpointsPath(dataDir)
	legacy := `schema_version: 1
endpoints:
  sentry-local:
    role: sentry
    url: ssh://127.0.0.1:2223
    published_sentries:
      deadbeef:
        component_key: LEGACY
        key_type: legacy
`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	registry, _, err := LoadStoredClientEndpointRegistry(dataDir)
	if err != nil {
		t.Fatalf("LoadStoredClientEndpointRegistry() error = %v", err)
	}
	if registry.SchemaVersion != ClientEndpointSchemaVersion {
		t.Fatalf("schema version = %d, want %d", registry.SchemaVersion, ClientEndpointSchemaVersion)
	}
	if err := SaveStoredClientEndpointRegistry(dataDir, registry); err != nil {
		t.Fatal(err)
	}
	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(written), "published_sentries") || !strings.Contains(string(written), "schema_version: 2") {
		t.Fatalf("rewritten endpoints.yaml = %q, want v2 without retired inventory", written)
	}
}

func TestStoredClientEndpointV2RejectsPublishedInventory(t *testing.T) {
	dataDir := t.TempDir()
	data := `schema_version: 2
endpoints:
  sentry-local:
    role: sentry
    url: self
    published_sentries: {}
`
	if err := os.WriteFile(GetClientEndpointsPath(dataDir), []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := LoadStoredClientEndpointRegistry(dataDir)
	if err == nil || !strings.Contains(err.Error(), "field published_sentries not found") {
		t.Fatalf("LoadStoredClientEndpointRegistry() error = %v, want strict v2 rejection", err)
	}
}

func TestStoredClientEndpointSentryLimit(t *testing.T) {
	registry := emptyClientEndpointRegistry()
	for i := 0; i < MaxClientSentryEndpoints; i++ {
		alias := fmt.Sprintf("sentry-%02d", i)
		registry.Endpoints[alias] = ClientEndpointConfig{Role: ClientEndpointRoleSentry, URL: "self"}
	}
	if err := SaveStoredClientEndpointRegistry(t.TempDir(), registry); err != nil {
		t.Fatalf("SaveStoredClientEndpointRegistry(12) error = %v", err)
	}
	registry.Endpoints["sentry-overflow"] = ClientEndpointConfig{Role: ClientEndpointRoleSentry, URL: "self"}
	err := SaveStoredClientEndpointRegistry(t.TempDir(), registry)
	if err == nil || !strings.Contains(err.Error(), "configures 13 sentry endpoints; maximum is 12") {
		t.Fatalf("SaveStoredClientEndpointRegistry(13) error = %v, want explicit limit", err)
	}
}

func TestLoadClientEndpointRegistrySentryLimit(t *testing.T) {
	for count := MaxClientSentryEndpoints; count <= MaxClientSentryEndpoints+1; count++ {
		t.Run(fmt.Sprintf("count-%d", count), func(t *testing.T) {
			dataDir := t.TempDir()
			var contents strings.Builder
			contents.WriteString("schema_version: 2\nendpoints:\n")
			for i := 0; i < count; i++ {
				fmt.Fprintf(&contents, "  sentry-%02d:\n    role: sentry\n    url: self\n", i)
			}
			if err := os.WriteFile(GetClientEndpointsPath(dataDir), []byte(contents.String()), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := LoadClientEndpointRegistry(dataDir)
			if count == MaxClientSentryEndpoints && err != nil {
				t.Fatalf("LoadClientEndpointRegistry(%d) error = %v", count, err)
			}
			if count > MaxClientSentryEndpoints && (err == nil || !strings.Contains(err.Error(), "configures 13 sentry endpoints; maximum is 12")) {
				t.Fatalf("LoadClientEndpointRegistry(%d) error = %v, want explicit limit", count, err)
			}
		})
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
	if !strings.Contains(err.Error(), "automatic endpoint-routing migration is unsupported") {
		t.Fatalf("error = %v, want endpoint-routing migration guidance", err)
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

func TestCheckSupportedClientEndpointConfigRejectsLegacySignerPort(t *testing.T) {
	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, "config.yaml"), []byte(`
network: testnet
signer_port: 12270
`), 0o600); err != nil {
		t.Fatalf("WriteFile(config) error = %v", err)
	}

	err := CheckSupportedClientEndpointConfig(dataDir)
	if err == nil {
		t.Fatal("CheckSupportedClientEndpointConfig() error = nil, want unsupported config")
	}
	if !strings.Contains(err.Error(), "top-level signer_port") {
		t.Fatalf("error = %v, want top-level signer_port guidance", err)
	}
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
