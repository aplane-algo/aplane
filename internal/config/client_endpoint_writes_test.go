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
	registry, err := UpsertStoredClientEndpoint(dataDir, "cosigner-local", ClientEndpointConfig{
		Role: ClientEndpointRoleCosigner,
		URL:  "ssh://127.0.0.1:2223",
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
	if _, ok := cfg.Endpoints.Endpoint("cosigner-local"); !ok {
		t.Fatal("cosigner-local endpoint missing after LoadConfig")
	}
}

func TestUpsertStoredClientEndpointDoesNotMaterializeLegacyPrimaryForCosigner(t *testing.T) {
	dataDir := t.TempDir()
	writeLegacyClientEndpointConfig(t, dataDir)

	registry, err := UpsertStoredClientEndpoint(dataDir, "cosigner-local", ClientEndpointConfig{
		Role: ClientEndpointRoleCosigner,
		URL:  "ssh://127.0.0.1:2223",
	}, false)
	if err != nil {
		t.Fatalf("UpsertStoredClientEndpoint(cosigner) error = %v", err)
	}
	if registry.Default != "" {
		t.Fatalf("Default = %q, want empty", registry.Default)
	}
	if _, ok := registry.Endpoints[DefaultClientEndpointName]; ok {
		t.Fatal("primary endpoint was materialized from legacy config")
	}
	if _, ok := registry.Endpoints["cosigner-local"]; !ok {
		t.Fatal("cosigner-local endpoint missing")
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
	if _, err := UpsertStoredClientEndpoint(dataDir, "cosigner-local", ClientEndpointConfig{
		Role: ClientEndpointRoleCosigner,
		URL:  "ssh://127.0.0.1:2223",
	}, false); err != nil {
		t.Fatalf("UpsertStoredClientEndpoint(first) error = %v", err)
	}
	_, err := UpsertStoredClientEndpoint(dataDir, "cosigner-local", ClientEndpointConfig{
		Role: ClientEndpointRoleCosigner,
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
	if got := registry.Endpoints["cosigner-local"].URL; got != "ssh://127.0.0.1:2223" {
		t.Fatalf("stored URL = %q, want original URL", got)
	}
}

func TestUpsertStoredClientEndpointRejectsDuplicateURLAcrossAliases(t *testing.T) {
	dataDir := t.TempDir()
	if _, err := UpsertStoredClientEndpoint(dataDir, "cosigner-local", ClientEndpointConfig{
		Role: ClientEndpointRoleCosigner,
		URL:  "ssh://127.0.0.1:2223/",
	}, false); err != nil {
		t.Fatalf("UpsertStoredClientEndpoint(first) error = %v", err)
	}

	_, err := UpsertStoredClientEndpoint(dataDir, "cosigner-copy", ClientEndpointConfig{
		Role: ClientEndpointRoleCosigner,
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
	if _, ok := registry.Endpoints["cosigner-copy"]; ok {
		t.Fatal("cosigner-copy endpoint was written despite duplicate URL conflict")
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
	if _, err := UpsertStoredClientEndpoint(dataDir, "local-cosigner", ClientEndpointConfig{
		Role: ClientEndpointRoleCosigner,
		URL:  "ssh://127.0.0.1:2223",
	}, true); err != nil {
		t.Fatalf("UpsertStoredClientEndpoint(cosigner same URL) error = %v", err)
	}
}

func TestStoredClientEndpointRejectsRetiredSchemaVersions(t *testing.T) {
	for _, contents := range []string{
		"default: primary\nendpoints: {}\n",
		"schema_version: 1\ndefault: primary\nendpoints: {}\n",
	} {
		dataDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dataDir, ClientEndpointsFile), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := LoadStoredClientEndpointRegistry(dataDir); err == nil || !strings.Contains(err.Error(), "want 2") {
			t.Errorf("LoadStoredClientEndpointRegistry(%q) error = %v, want a schema_version rejection", contents, err)
		}
	}
}

func TestStoredClientEndpointV2RejectsPublishedInventory(t *testing.T) {
	dataDir := t.TempDir()
	data := `schema_version: 2
endpoints:
  cosigner-local:
    role: cosigner
    url: ssh://cosigner.example
    published_cosigners: {}
`
	if err := os.WriteFile(GetClientEndpointsPath(dataDir), []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := LoadStoredClientEndpointRegistry(dataDir)
	if err == nil || !strings.Contains(err.Error(), "field published_cosigners not found") {
		t.Fatalf("LoadStoredClientEndpointRegistry() error = %v, want strict v2 rejection", err)
	}
}

func TestStoredClientEndpointCosignerLimit(t *testing.T) {
	registry := emptyClientEndpointRegistry()
	for i := 0; i < MaxClientCosignerEndpoints; i++ {
		alias := fmt.Sprintf("cosigner-%02d", i)
		registry.Endpoints[alias] = ClientEndpointConfig{Role: ClientEndpointRoleCosigner, URL: fmt.Sprintf("ssh://cosigner-%02d.example", i)}
	}
	if err := SaveStoredClientEndpointRegistry(t.TempDir(), registry); err != nil {
		t.Fatalf("SaveStoredClientEndpointRegistry(12) error = %v", err)
	}
	registry.Endpoints["cosigner-overflow"] = ClientEndpointConfig{Role: ClientEndpointRoleCosigner, URL: "ssh://cosigner-overflow.example"}
	err := SaveStoredClientEndpointRegistry(t.TempDir(), registry)
	if err == nil || !strings.Contains(err.Error(), "configures 13 cosigner endpoints; maximum is 12") {
		t.Fatalf("SaveStoredClientEndpointRegistry(13) error = %v, want explicit limit", err)
	}
}

func TestLoadClientEndpointRegistryCosignerLimit(t *testing.T) {
	for count := MaxClientCosignerEndpoints; count <= MaxClientCosignerEndpoints+1; count++ {
		t.Run(fmt.Sprintf("count-%d", count), func(t *testing.T) {
			dataDir := t.TempDir()
			var contents strings.Builder
			contents.WriteString("schema_version: 2\nendpoints:\n")
			for i := 0; i < count; i++ {
				fmt.Fprintf(&contents, "  cosigner-%02d:\n    role: cosigner\n    url: ssh://cosigner-%02d.example\n", i, i)
			}
			if err := os.WriteFile(GetClientEndpointsPath(dataDir), []byte(contents.String()), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := LoadClientEndpointRegistry(dataDir)
			if count == MaxClientCosignerEndpoints && err != nil {
				t.Fatalf("LoadClientEndpointRegistry(%d) error = %v", count, err)
			}
			if count > MaxClientCosignerEndpoints && (err == nil || !strings.Contains(err.Error(), "configures 13 cosigner endpoints; maximum is 12")) {
				t.Fatalf("LoadClientEndpointRegistry(%d) error = %v, want explicit limit", count, err)
			}
		})
	}
}

func TestStoredClientEndpointRejectsSelfForEveryRole(t *testing.T) {
	for _, role := range []string{ClientEndpointRoleSigner, ClientEndpointRoleCosigner} {
		t.Run(role, func(t *testing.T) {
			dataDir := t.TempDir()
			_, err := UpsertStoredClientEndpoint(dataDir, role, ClientEndpointConfig{
				Role: role,
				URL:  "self",
			}, false)
			if err == nil || !strings.Contains(err.Error(), `url "self" is not supported`) {
				t.Fatalf("UpsertStoredClientEndpoint() error = %v, want unsupported self URL", err)
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
schema_version: 2
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

// Earlier builds wrote signer_port and local_port into endpoints.yaml. They
// are ignored on load and dropped by the next write, so an existing registry
// keeps working and cleans itself up.
func TestLoadClientEndpointRegistryDropsRetiredPortFields(t *testing.T) {
	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, ClientEndpointsFile), []byte(`
schema_version: 2
default: primary
endpoints:
  primary:
    role: signer
    url: ssh://signer.example:2222
    signer_port: 12270
    local_port: 18080
  cosigner-local:
    role: cosigner
    url: ssh://cosigner.example:2223
    signer_port: 12271
`), 0o600); err != nil {
		t.Fatal(err)
	}
	registry, err := LoadClientEndpointRegistry(dataDir)
	if err != nil {
		t.Fatalf("LoadClientEndpointRegistry() error = %v, want the retired fields ignored", err)
	}
	if endpoint, ok := registry.Endpoint("primary"); !ok || endpoint.URL != "ssh://signer.example:2222" {
		t.Fatalf("primary = %#v, %v", endpoint, ok)
	}
	if _, err := UpsertStoredClientEndpoint(dataDir, "cosigner-local", ClientEndpointConfig{
		Role: ClientEndpointRoleCosigner, URL: "ssh://cosigner.example:2223", IdentityFile: "/custom/id",
	}, true); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dataDir, ClientEndpointsFile))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "signer_port") || strings.Contains(string(data), "local_port") {
		t.Fatalf("retired fields survived a write:\n%s", data)
	}
	// Removal keeps every other value exactly as written: a numeric alias
	// stays a key, a retired token_file is dropped whatever it looks like,
	// and an identity_file that looks like a number stays that text.
	if err := os.WriteFile(filepath.Join(dataDir, ClientEndpointsFile), []byte(`
schema_version: 2
endpoints:
  123:
    role: cosigner
    url: ssh://cosigner.example:2223
    signer_port: 12271
    token_file: 2026-10-06
  "quoted.alias":
    role: cosigner
    url: "ssh://other.example:2223"
    local_port: 0
    identity_file: 007
`), 0o600); err != nil {
		t.Fatal(err)
	}
	registry, err = LoadClientEndpointRegistry(dataDir)
	if err != nil {
		t.Fatalf("LoadClientEndpointRegistry() error = %v, want numeric alias and date-like values preserved", err)
	}
	if endpoint, ok := registry.Endpoint("123"); !ok || endpoint.URL != "ssh://cosigner.example:2223" {
		t.Fatalf("numeric alias = %#v, %v, want the entry kept with token_file ignored", endpoint, ok)
	}
	if endpoint, ok := registry.Endpoint("quoted.alias"); !ok || endpoint.IdentityFile != filepath.Join(dataDir, "007") || endpoint.URL != "ssh://other.example:2223" {
		t.Fatalf("quoted.alias = %#v, %v, want identity_file 007 as written", endpoint, ok)
	}

	// Any other unknown field is still an error.
	if err := os.WriteFile(filepath.Join(dataDir, ClientEndpointsFile), []byte(`
schema_version: 2
endpoints:
  cosigner-local:
    role: cosigner
    url: ssh://cosigner.example:2223
    cosigner_port: 12271
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadClientEndpointRegistry(dataDir); err == nil || !strings.Contains(err.Error(), "cosigner_port") {
		t.Fatalf("LoadClientEndpointRegistry() error = %v, want unknown field cosigner_port", err)
	}
}

// A destination change is reported so callers can say the alias now names a
// different node; nothing else happens, since the client's key is its only
// credential and the node, not the client, records enrollment.
func TestUpsertStoredClientEndpointReportsDestinationChange(t *testing.T) {
	dataDir := t.TempDir()
	first, err := PlanStoredClientEndpointUpsert(dataDir, "cos", ClientEndpointConfig{Role: ClientEndpointRoleCosigner, URL: "ssh://old.example"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if first.DestinationChanged || !first.Created {
		t.Fatalf("first plan = %+v", first)
	}
	if err := ApplyStoredClientEndpointUpsert(dataDir, first); err != nil {
		t.Fatal(err)
	}
	same, err := PlanStoredClientEndpointUpsert(dataDir, "cos", ClientEndpointConfig{Role: ClientEndpointRoleCosigner, URL: "ssh://old.example"}, true)
	if err != nil || same.DestinationChanged || same.Created || same.Updated {
		t.Fatalf("unchanged plan = %+v, %v", same, err)
	}
	moved, err := PlanStoredClientEndpointUpsert(dataDir, "cos", ClientEndpointConfig{Role: ClientEndpointRoleCosigner, URL: "ssh://new.example"}, true)
	if err != nil || !moved.DestinationChanged || !moved.Updated {
		t.Fatalf("moved plan = %+v, %v", moved, err)
	}
	if _, err := RemoveStoredClientEndpoint(dataDir, "cos"); err != nil {
		t.Fatalf("RemoveStoredClientEndpoint() error = %v", err)
	}
	registry, _, err := LoadStoredClientEndpointRegistry(dataDir)
	if err != nil || len(registry.Endpoints) != 0 {
		t.Fatalf("registry after removal = %+v, %v", registry, err)
	}
}

// Only ssh:// endpoints exist: a node is reached through its SSH server,
// which authenticates the client's enrolled key, and no raw HTTP endpoint
// could carry that identity.
func TestStoredClientEndpointRejectsNonSSHSchemes(t *testing.T) {
	dataDir := t.TempDir()
	for _, url := range []string{"http://127.0.0.1:11270", "https://signer.example", "ftp://x"} {
		if _, err := PlanStoredClientEndpointUpsert(dataDir, "e", ClientEndpointConfig{Role: ClientEndpointRoleSigner, URL: url}, false); err == nil || !strings.Contains(err.Error(), "ssh://") {
			t.Fatalf("PlanStoredClientEndpointUpsert(%s) error = %v, want ssh-only rejection", url, err)
		}
	}
}
