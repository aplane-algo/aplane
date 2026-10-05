// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/fsutil"
)

func TestUpsertStoredClientEndpointDoesNotAutoDefault(t *testing.T) {
	dataDir := t.TempDir()
	registry, err := UpsertStoredClientEndpoint(dataDir, "cosigner-local", ClientEndpointConfig{
		Role:       ClientEndpointRoleCosigner,
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
	endpoint, ok := cfg.Endpoints.Endpoint("cosigner-local")
	if !ok {
		t.Fatal("cosigner-local endpoint missing after LoadConfig")
	}
	if endpoint.TokenFile != filepath.Join(dataDir, "tokens", "cosigner-local.token") {
		t.Fatalf("TokenFile = %q, want resolved default token path", endpoint.TokenFile)
	}
}

func TestStoredClientEndpointLocalPortIsSignerOnly(t *testing.T) {
	dataDir := t.TempDir()
	_, err := UpsertStoredClientEndpoint(dataDir, "field", ClientEndpointConfig{
		Role: ClientEndpointRoleCosigner, URL: "ssh://cosigner.example", LocalPort: 12271,
	}, false)
	if err == nil || !strings.Contains(err.Error(), "local_port is not supported for cosigner endpoints") {
		t.Fatalf("UpsertStoredClientEndpoint(cosigner local_port) error = %v, want role error", err)
	}

	if _, err := UpsertStoredClientEndpoint(dataDir, "primary", ClientEndpointConfig{
		Role: ClientEndpointRoleSigner, URL: "ssh://signer.example", LocalPort: 12272,
	}, false); err != nil {
		t.Fatalf("UpsertStoredClientEndpoint(signer local_port) error = %v", err)
	}
}

func TestUpsertStoredClientEndpointDoesNotMaterializeLegacyPrimaryForCosigner(t *testing.T) {
	dataDir := t.TempDir()
	writeLegacyClientEndpointConfig(t, dataDir)

	registry, err := UpsertStoredClientEndpoint(dataDir, "cosigner-local", ClientEndpointConfig{
		Role:       ClientEndpointRoleCosigner,
		URL:        "ssh://127.0.0.1:2223",
		SignerPort: 11271,
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

func writeTestEndpointToken(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("issued-by-previous-destination\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestUpsertStoredClientEndpointRetiresTokenWhenDestinationChanges(t *testing.T) {
	tests := []struct {
		name     string
		previous ClientEndpointConfig
		next     ClientEndpointConfig
		retired  bool
	}{
		{
			name:     "url",
			previous: ClientEndpointConfig{Role: ClientEndpointRoleCosigner, URL: "ssh://old.example:22"},
			next:     ClientEndpointConfig{Role: ClientEndpointRoleCosigner, URL: "ssh://new.example:22"},
			retired:  true,
		},
		{
			name:     "ssh api port",
			previous: ClientEndpointConfig{Role: ClientEndpointRoleCosigner, URL: "ssh://cosigner.example", SignerPort: 11270},
			next:     ClientEndpointConfig{Role: ClientEndpointRoleCosigner, URL: "ssh://cosigner.example", SignerPort: 12270},
			retired:  true,
		},
		{
			name:     "https url",
			previous: ClientEndpointConfig{Role: ClientEndpointRoleCosigner, URL: "https://old.example"},
			next:     ClientEndpointConfig{Role: ClientEndpointRoleCosigner, URL: "https://new.example"},
			retired:  true,
		},
		{
			name:     "default ssh api port spelled out",
			previous: ClientEndpointConfig{Role: ClientEndpointRoleCosigner, URL: "ssh://cosigner.example"},
			next:     ClientEndpointConfig{Role: ClientEndpointRoleCosigner, URL: "ssh://cosigner.example", SignerPort: DefaultRESTPort},
			retired:  false,
		},
		{
			name:     "client-local settings only",
			previous: ClientEndpointConfig{Role: ClientEndpointRoleCosigner, URL: "ssh://cosigner.example"},
			next:     ClientEndpointConfig{Role: ClientEndpointRoleCosigner, URL: "ssh://cosigner.example", IdentityFile: "/custom/id"},
			retired:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dataDir := t.TempDir()
			if _, err := UpsertStoredClientEndpoint(dataDir, "field", tt.previous, true); err != nil {
				t.Fatal(err)
			}
			tokenPath := filepath.Join(dataDir, "tokens", "field.token")
			writeTestEndpointToken(t, tokenPath)

			plan, err := PlanStoredClientEndpointUpsert(dataDir, "field", tt.next, true)
			if err != nil {
				t.Fatal(err)
			}
			if plan.DestinationChanged != tt.retired || plan.RetiresExistingToken != tt.retired {
				t.Fatalf("plan = %#v, want destination change %v", plan, tt.retired)
			}
			if _, err := os.Stat(tokenPath); err != nil {
				t.Fatalf("planning touched the token file: %v", err)
			}
			if err := ApplyStoredClientEndpointUpsert(dataDir, plan); err != nil {
				t.Fatal(err)
			}
			_, statErr := os.Stat(tokenPath)
			if tt.retired && !os.IsNotExist(statErr) {
				t.Fatalf("token stat error = %v, want the previous destination's token removed", statErr)
			}
			if !tt.retired && statErr != nil {
				t.Fatalf("token stat error = %v, want the token kept for an unchanged destination", statErr)
			}
		})
	}
}

func TestUpsertStoredClientEndpointRetiresTokenBeforePublishingRoute(t *testing.T) {
	dataDir := t.TempDir()
	if _, err := UpsertStoredClientEndpoint(dataDir, "field", ClientEndpointConfig{
		Role: ClientEndpointRoleCosigner, URL: "ssh://old.example",
	}, true); err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(dataDir, "tokens", "field.token")
	writeTestEndpointToken(t, tokenPath)
	plan, err := PlanStoredClientEndpointUpsert(dataDir, "field", ClientEndpointConfig{
		Role: ClientEndpointRoleCosigner, URL: "ssh://new.example",
	}, true)
	if err != nil {
		t.Fatal(err)
	}

	// Interrupt the route publication. The token removal must already be
	// synced by then, so the interruption leaves the old route without a
	// token rather than the new route with the old one.
	interrupted := errors.New("interrupted before the route was published")
	tokenDirSynced := false
	fsutil.TestHook = func(op fsutil.HookOp, path string) error {
		if op == fsutil.OpDirSync && path == filepath.Dir(tokenPath) {
			tokenDirSynced = true
		}
		if op == fsutil.OpRename {
			if !tokenDirSynced {
				t.Errorf("route publication began before the token removal was synced")
			}
			return interrupted
		}
		return nil
	}
	t.Cleanup(func() { fsutil.TestHook = nil })

	if err := ApplyStoredClientEndpointUpsert(dataDir, plan); !errors.Is(err, interrupted) {
		t.Fatalf("ApplyStoredClientEndpointUpsert() error = %v, want the injected interruption", err)
	}
	fsutil.TestHook = nil
	if _, err := os.Stat(tokenPath); !os.IsNotExist(err) {
		t.Fatalf("token stat error = %v, want the token retired", err)
	}
	registry, _, err := LoadStoredClientEndpointRegistry(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if endpoint := registry.Endpoints["field"]; endpoint.URL != "ssh://old.example" {
		t.Fatalf("endpoint after interruption = %#v, want the old route", endpoint)
	}
}

func TestUpsertStoredClientEndpointRefusesToRetireSharedTokenFile(t *testing.T) {
	dataDir := t.TempDir()
	shared := filepath.Join(dataDir, "tokens", "shared.token")
	// The two profiles name one file through different spellings. The upsert
	// refuses to create such a pair, so this is a hand-written registry.
	writeSharedTokenRegistry(t, dataDir, shared)
	writeTestEndpointToken(t, shared)

	_, err := PlanStoredClientEndpointUpsert(dataDir, "field", ClientEndpointConfig{
		Role: ClientEndpointRoleCosigner, URL: "ssh://new.example", TokenFile: filepath.Join("tokens", "shared.token"),
	}, true)
	if err == nil || !strings.Contains(err.Error(), `shares token file`) || !strings.Contains(err.Error(), `"other"`) {
		t.Fatalf("PlanStoredClientEndpointUpsert() error = %v, want shared token refusal naming the other alias", err)
	}
	if _, statErr := os.Stat(shared); statErr != nil {
		t.Fatalf("shared token stat error = %v, want the shared credential kept", statErr)
	}

	// A symlinked spelling of the same file is the same credential.
	link := filepath.Join(dataDir, "linked.token")
	if err := os.Symlink(shared, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := PlanStoredClientEndpointUpsert(dataDir, "field", ClientEndpointConfig{
		Role: ClientEndpointRoleCosigner, URL: "ssh://new.example", TokenFile: link,
	}, true); err == nil || !strings.Contains(err.Error(), `shares token file`) {
		t.Fatalf("PlanStoredClientEndpointUpsert() via symlink error = %v, want shared token refusal", err)
	}
}

// writeSharedTokenRegistry stores two cosigner profiles, field and other, that
// name one token file through a relative and an absolute spelling.
func writeSharedTokenRegistry(t *testing.T, dataDir, shared string) {
	t.Helper()
	rel, err := filepath.Rel(dataDir, shared)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveStoredClientEndpointRegistry(dataDir, ClientEndpointRegistry{
		SchemaVersion: ClientEndpointSchemaVersion,
		Endpoints: map[string]ClientEndpointConfig{
			"field": {Role: ClientEndpointRoleCosigner, URL: "ssh://old.example", TokenFile: rel},
			"other": {Role: ClientEndpointRoleCosigner, URL: "ssh://other.example", TokenFile: shared},
		},
	}); err != nil {
		t.Fatal(err)
	}
}

// A token file already at a new alias's path was left by an earlier profile of
// that name. Creating the alias retires it, whatever the scheme, so it is never
// presented to the new destination.
func TestUpsertStoredClientEndpointRetiresLeftoverTokenOnCreate(t *testing.T) {
	for _, rawURL := range []string{"ssh://new.example", "https://new.example", "http://127.0.0.1:9"} {
		t.Run(rawURL, func(t *testing.T) {
			dataDir := t.TempDir()
			tokenPath := filepath.Join(dataDir, "tokens", "field.token")
			writeTestEndpointToken(t, tokenPath)

			plan, err := PlanStoredClientEndpointUpsert(dataDir, "field", ClientEndpointConfig{
				Role: ClientEndpointRoleCosigner, URL: rawURL,
			}, true)
			if err != nil {
				t.Fatal(err)
			}
			if !plan.Created || plan.DestinationChanged || !plan.RetiresExistingToken || plan.RetireTokenPath != tokenPath {
				t.Fatalf("plan = %#v, want a create that retires the leftover token", plan)
			}
			if err := ApplyStoredClientEndpointUpsert(dataDir, plan); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(tokenPath); !os.IsNotExist(err) {
				t.Fatalf("token stat error = %v, want the leftover token removed", err)
			}

			// A token installed after the profile exists is kept by a rerun.
			writeTestEndpointToken(t, tokenPath)
			rerun, err := PlanStoredClientEndpointUpsert(dataDir, "field", ClientEndpointConfig{
				Role: ClientEndpointRoleCosigner, URL: rawURL,
			}, true)
			if err != nil {
				t.Fatal(err)
			}
			if rerun.Created || rerun.RetireTokenPath != "" || rerun.RetiresExistingToken {
				t.Fatalf("rerun plan = %#v, want no retirement for an unchanged profile", rerun)
			}
			if err := ApplyStoredClientEndpointUpsert(dataDir, rerun); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(tokenPath); err != nil {
				t.Fatalf("token stat error = %v, want a token installed after creation kept", err)
			}
		})
	}
}

func TestUpsertStoredClientEndpointRefusesCreateOverSharedTokenFile(t *testing.T) {
	dataDir := t.TempDir()
	if _, err := UpsertStoredClientEndpoint(dataDir, "other", ClientEndpointConfig{
		Role: ClientEndpointRoleCosigner, URL: "ssh://other.example", TokenFile: filepath.Join("tokens", "shared.token"),
	}, true); err != nil {
		t.Fatal(err)
	}
	shared := filepath.Join(dataDir, "tokens", "shared.token")
	writeTestEndpointToken(t, shared)

	_, err := PlanStoredClientEndpointUpsert(dataDir, "field", ClientEndpointConfig{
		Role: ClientEndpointRoleCosigner, URL: "ssh://new.example", TokenFile: shared,
	}, true)
	if err == nil || !strings.Contains(err.Error(), "creating it would retire a shared credential") || !strings.Contains(err.Error(), `"other"`) {
		t.Fatalf("PlanStoredClientEndpointUpsert() error = %v, want shared token refusal naming the other alias", err)
	}
	if _, statErr := os.Stat(shared); statErr != nil {
		t.Fatalf("shared token stat error = %v, want the shared credential kept", statErr)
	}
}

// A retry after a failed directory sync must sync again: the earlier attempt
// removed the file without making the removal durable.
func TestUpsertStoredClientEndpointResyncsRetirementAfterSyncFailure(t *testing.T) {
	dataDir := t.TempDir()
	if _, err := UpsertStoredClientEndpoint(dataDir, "field", ClientEndpointConfig{
		Role: ClientEndpointRoleCosigner, URL: "ssh://old.example",
	}, true); err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(dataDir, "tokens", "field.token")
	writeTestEndpointToken(t, tokenPath)
	next := ClientEndpointConfig{Role: ClientEndpointRoleCosigner, URL: "ssh://new.example"}

	syncFailed := errors.New("injected directory sync failure")
	fsutil.TestHook = func(op fsutil.HookOp, path string) error {
		if op == fsutil.OpDirSync && path == filepath.Dir(tokenPath) {
			return syncFailed
		}
		return nil
	}
	t.Cleanup(func() { fsutil.TestHook = nil })
	plan, err := PlanStoredClientEndpointUpsert(dataDir, "field", next, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyStoredClientEndpointUpsert(dataDir, plan); !errors.Is(err, syncFailed) {
		t.Fatalf("ApplyStoredClientEndpointUpsert() error = %v, want the injected sync failure", err)
	}
	registry, _, err := LoadStoredClientEndpointRegistry(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if registry.Endpoints["field"].URL != "ssh://old.example" {
		t.Fatalf("endpoint after failed sync = %#v, want the old route", registry.Endpoints["field"])
	}

	tokenDirSynced := false
	fsutil.TestHook = func(op fsutil.HookOp, path string) error {
		if op == fsutil.OpDirSync && path == filepath.Dir(tokenPath) {
			tokenDirSynced = true
		}
		if op == fsutil.OpRename && !tokenDirSynced {
			t.Errorf("route publication began before the token removal was synced")
		}
		return nil
	}
	plan, err = PlanStoredClientEndpointUpsert(dataDir, "field", next, true)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.DestinationChanged || plan.RetiresExistingToken {
		t.Fatalf("retry plan = %#v, want a destination change with the file already gone", plan)
	}
	if err := ApplyStoredClientEndpointUpsert(dataDir, plan); err != nil {
		t.Fatal(err)
	}
	if !tokenDirSynced {
		t.Fatal("retry published the route without syncing the token directory")
	}
}

func TestRemoveStoredClientEndpointRetiresItsToken(t *testing.T) {
	t.Run("own token", func(t *testing.T) {
		dataDir := t.TempDir()
		if _, err := UpsertStoredClientEndpoint(dataDir, "field", ClientEndpointConfig{
			Role: ClientEndpointRoleCosigner, URL: "ssh://old.example",
		}, true); err != nil {
			t.Fatal(err)
		}
		tokenPath := filepath.Join(dataDir, "tokens", "field.token")
		writeTestEndpointToken(t, tokenPath)

		// The token is retired before the route is removed.
		tokenDirSynced := false
		fsutil.TestHook = func(op fsutil.HookOp, path string) error {
			if op == fsutil.OpDirSync && path == filepath.Dir(tokenPath) {
				tokenDirSynced = true
			}
			if op == fsutil.OpRename && !tokenDirSynced {
				t.Errorf("route removal began before the token removal was synced")
			}
			return nil
		}
		t.Cleanup(func() { fsutil.TestHook = nil })

		removal, err := RemoveStoredClientEndpoint(dataDir, "field")
		if err != nil {
			t.Fatal(err)
		}
		if !removal.TokenRetired || removal.TokenShared {
			t.Fatalf("removal = %#v, want the alias's token retired", removal)
		}
		if _, err := os.Stat(tokenPath); !os.IsNotExist(err) {
			t.Fatalf("token stat error = %v, want the token removed with its alias", err)
		}
		if _, ok := removal.Registry.Endpoints["field"]; ok {
			t.Fatal("alias was not removed")
		}
	})
	t.Run("shared token is kept", func(t *testing.T) {
		dataDir := t.TempDir()
		shared := filepath.Join(dataDir, "tokens", "shared.token")
		writeSharedTokenRegistry(t, dataDir, shared)
		writeTestEndpointToken(t, shared)

		removal, err := RemoveStoredClientEndpoint(dataDir, "field")
		if err != nil {
			t.Fatal(err)
		}
		if removal.TokenRetired || !removal.TokenShared {
			t.Fatalf("removal = %#v, want the shared token left in place", removal)
		}
		if _, err := os.Stat(shared); err != nil {
			t.Fatalf("shared token stat error = %v, want the other alias's credential kept", err)
		}
	})
}
