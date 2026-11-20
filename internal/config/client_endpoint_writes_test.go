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

func TestUpsertStoredCosignerEndpointLeavesNoSignerEndpoint(t *testing.T) {
	dataDir := t.TempDir()
	registry, err := upsertStoredClientEndpoint(dataDir, "cosigner-local", ClientEndpointConfig{
		Role: ClientEndpointRoleCosigner,
		URL:  "ssh://127.0.0.1:2223",
	}, false)
	if err != nil {
		t.Fatalf("upsertStoredClientEndpoint(first) error = %v", err)
	}
	if alias, _, ok := registry.SignerEndpoint(); ok {
		t.Fatalf("SignerEndpoint() = %q, want none for a cosigner endpoint", alias)
	}

	cfg, err := LoadConfig(dataDir)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	if alias, _, ok := cfg.Endpoints.SignerEndpoint(); ok || alias != "" {
		t.Fatalf("SignerEndpoint() = %q/%v, want none", alias, ok)
	}
	if _, ok := cfg.Endpoints.Endpoint("cosigner-local"); !ok {
		t.Fatal("cosigner-local endpoint missing after LoadConfig")
	}
}

func TestUpsertStoredClientEndpointRejectsConflict(t *testing.T) {
	dataDir := t.TempDir()
	if _, err := upsertStoredClientEndpoint(dataDir, "cosigner-local", ClientEndpointConfig{
		Role: ClientEndpointRoleCosigner,
		URL:  "ssh://127.0.0.1:2223",
	}, false); err != nil {
		t.Fatalf("upsertStoredClientEndpoint(first) error = %v", err)
	}
	_, err := upsertStoredClientEndpoint(dataDir, "cosigner-local", ClientEndpointConfig{
		Role: ClientEndpointRoleCosigner,
		URL:  "ssh://127.0.0.1:2224",
	}, false)
	if err == nil {
		t.Fatal("upsertStoredClientEndpoint(conflict) error = nil, want conflict")
	}
	if !strings.Contains(err.Error(), "already exists with different settings") {
		t.Fatalf("conflict error = %v", err)
	}
	registry, err := LoadStoredClientEndpointRegistry(dataDir)
	if err != nil {
		t.Fatalf("LoadStoredClientEndpointRegistry() error = %v", err)
	}
	if got := registry.Endpoints["cosigner-local"].URL; got != "ssh://127.0.0.1:2223" {
		t.Fatalf("stored URL = %q, want original URL", got)
	}
}

func TestUpsertStoredClientEndpointRejectsDuplicateURLAcrossAliases(t *testing.T) {
	dataDir := t.TempDir()
	if _, err := upsertStoredClientEndpoint(dataDir, "cosigner-local", ClientEndpointConfig{
		Role: ClientEndpointRoleCosigner,
		URL:  "ssh://127.0.0.1:2223/",
	}, false); err != nil {
		t.Fatalf("upsertStoredClientEndpoint(first) error = %v", err)
	}

	_, err := upsertStoredClientEndpoint(dataDir, "cosigner-copy", ClientEndpointConfig{
		Role: ClientEndpointRoleCosigner,
		URL:  "ssh://127.0.0.1:2223",
	}, true)
	if err == nil {
		t.Fatal("upsertStoredClientEndpoint(duplicate URL) error = nil, want conflict")
	}
	if !strings.Contains(err.Error(), "already belongs to alias") {
		t.Fatalf("duplicate URL error = %v", err)
	}

	registry, err := LoadStoredClientEndpointRegistry(dataDir)
	if err != nil {
		t.Fatalf("LoadStoredClientEndpointRegistry() error = %v", err)
	}
	if _, ok := registry.Endpoints["cosigner-copy"]; ok {
		t.Fatal("cosigner-copy endpoint was written despite duplicate URL conflict")
	}
}

func TestUpsertStoredClientEndpointAllowsDuplicateURLAcrossRoles(t *testing.T) {
	dataDir := t.TempDir()
	if _, err := upsertStoredClientEndpoint(dataDir, "main", ClientEndpointConfig{
		Role: ClientEndpointRoleSigner,
		URL:  "ssh://127.0.0.1:2223",
	}, true); err != nil {
		t.Fatalf("upsertStoredClientEndpoint(signer) error = %v", err)
	}
	if _, err := upsertStoredClientEndpoint(dataDir, "local-cosigner", ClientEndpointConfig{
		Role: ClientEndpointRoleCosigner,
		URL:  "ssh://127.0.0.1:2223",
	}, true); err != nil {
		t.Fatalf("upsertStoredClientEndpoint(cosigner same URL) error = %v", err)
	}
}

func TestStoredClientEndpointRejectsRetiredSchemaVersions(t *testing.T) {
	for _, contents := range []string{
		"endpoints: {}\n",
		"schema_version: 1\nendpoints: {}\n",
	} {
		dataDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dataDir, ClientEndpointsFile), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadStoredClientEndpointRegistry(dataDir); err == nil || !strings.Contains(err.Error(), "want 2") {
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
	_, err := LoadStoredClientEndpointRegistry(dataDir)
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
			_, err := upsertStoredClientEndpoint(dataDir, role, ClientEndpointConfig{
				Role: role,
				URL:  "self",
			}, false)
			if err == nil || !strings.Contains(err.Error(), `unsupported url scheme ""; endpoints are ssh://host[:port]`) {
				t.Fatalf("upsertStoredClientEndpoint() error = %v, want unsupported self URL", err)
			}
		})
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
	if err := SaveStoredClientEndpointRegistry(dataDir, first.Registry); err != nil {
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
	if err := RemoveStoredClientEndpoint(dataDir, "cos"); err != nil {
		t.Fatalf("RemoveStoredClientEndpoint() error = %v", err)
	}
	registry, err := LoadStoredClientEndpointRegistry(dataDir)
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

// upsertStoredClientEndpoint plans and writes one endpoint upsert.
func upsertStoredClientEndpoint(dataDir, alias string, endpoint ClientEndpointConfig, replace bool) (ClientEndpointRegistry, error) {
	plan, err := PlanStoredClientEndpointUpsert(dataDir, alias, endpoint, replace)
	if err != nil {
		return ClientEndpointRegistry{}, err
	}
	if err := SaveStoredClientEndpointRegistry(dataDir, plan.Registry); err != nil {
		return ClientEndpointRegistry{}, err
	}
	return plan.Registry, nil
}
