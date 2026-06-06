// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package config

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/attestor/keytypes"
)

func TestLoadConfigSignerStatusPollInterval(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(`
network: testnet
signer_status_poll_interval: "30s"
networks:
  testnet:
    algod:
      server: http://localhost:4001
`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := LoadConfigFromPath(path)
	if err != nil {
		t.Fatalf("LoadConfigFromPath: %v", err)
	}
	if cfg.SignerStatusPollInterval != "30s" {
		t.Fatalf("signer_status_poll_interval = %q, want 30s", cfg.SignerStatusPollInterval)
	}
	if got := cfg.SignerStatusPollIntervalDuration(); got != 30*time.Second {
		t.Fatalf("SignerStatusPollIntervalDuration() = %s, want 30s", got)
	}
}

func TestLoadConfigSignerStatusPollIntervalDisabled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(`
network: testnet
signer_status_poll_interval: "0"
networks:
  testnet:
    algod:
      server: http://localhost:4001
`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := LoadConfigFromPath(path)
	if err != nil {
		t.Fatalf("LoadConfigFromPath: %v", err)
	}
	if got := cfg.SignerStatusPollIntervalDuration(); got != 0 {
		t.Fatalf("SignerStatusPollIntervalDuration() = %s, want disabled", got)
	}
}

func TestLoadConfigRejectsInvalidSignerStatusPollInterval(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(`
network: testnet
signer_status_poll_interval: "500ms"
networks:
  testnet:
    algod:
      server: http://localhost:4001
`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := LoadConfigFromPath(path)
	if err == nil {
		t.Fatal("LoadConfigFromPath error = nil, want invalid interval error")
	}
	if !strings.Contains(err.Error(), "invalid signer_status_poll_interval") {
		t.Fatalf("LoadConfigFromPath error = %q, want signer_status_poll_interval", err)
	}
}

func TestLoadConfigRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(`
network: testnet
unknown_setting: true
`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := LoadConfigFromPath(path)
	if err == nil {
		t.Fatal("LoadConfigFromPath error = nil, want unknown field error")
	}
	if !strings.Contains(err.Error(), "field unknown_setting not found") {
		t.Fatalf("LoadConfigFromPath error = %q, want unknown_setting", err)
	}
}

func TestLoadConfigRejectsUnknownNestedFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(`
network: testnet
ssh:
  host: localhost
  surprise: true
`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := LoadConfigFromPath(path)
	if err == nil {
		t.Fatal("LoadConfigFromPath error = nil, want unknown nested field error")
	}
	if !strings.Contains(err.Error(), "field surprise not found") {
		t.Fatalf("LoadConfigFromPath error = %q, want surprise", err)
	}
}

func TestLoadConfigRejectsAttestorEndpointsField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(fmt.Sprintf(`
network: testnet
attestor_endpoints:
  %s:
    url: self
`, attestorEndpointTestHex("d6"))), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := LoadConfigFromPath(path)
	if err == nil {
		t.Fatal("LoadConfigFromPath error = nil, want unknown attestor_endpoints field")
	}
	if !strings.Contains(err.Error(), "field attestor_endpoints not found") {
		t.Fatalf("LoadConfigFromPath error = %q, want attestor_endpoints unknown field", err)
	}
}

func TestLoadConfigEndpointRegistryDerivesAttestorRoutesFromPublishedInventory(t *testing.T) {
	dataDir := t.TempDir()
	publicKey := attestorEndpointTestHex("d6")
	componentKey := attestorEndpointConfigTestComponentKey(t, keytypes.AttestorComponentEd25519V1, publicKey)
	if err := os.WriteFile(filepath.Join(dataDir, "config.yaml"), []byte(`
network: testnet
signer_port: 12270
ssh:
  host: signer.example
  port: 2222
`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, ClientEndpointsFile), []byte(fmt.Sprintf(`
schema_version: 1
endpoints:
  attestor-local:
    role: attestor
    url: ssh://127.0.0.1:2223
    signer_port: 12271
    published_attestors:
      %s:
        component_key: %s
        key_type: %s
        last_seen_at: "2026-06-04T00:00:00Z"
`, publicKey, componentKey, keytypes.AttestorComponentEd25519V1)), 0o600); err != nil {
		t.Fatalf("write endpoints: %v", err)
	}

	cfg, err := LoadConfig(dataDir)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	route, ok := cfg.AttestorEndpoints[publicKey]
	if !ok {
		t.Fatalf("derived attestor route for %s missing from %#v", publicKey, cfg.AttestorEndpoints)
	}
	if route.Endpoint != "attestor-local" || route.URL != "ssh://127.0.0.1:2223" {
		t.Fatalf("derived route = %#v, want attestor-local ssh endpoint", route)
	}
	published := cfg.Endpoints.Endpoints["attestor-local"].PublishedAttestors[publicKey]
	if published.ComponentKey != componentKey || published.KeyType != keytypes.AttestorComponentEd25519V1 {
		t.Fatalf("published attestor = %#v, want component/key type", published)
	}
}

func TestClientConfigExamplesUseKnownFields(t *testing.T) {
	repoRoot := filepath.Clean(filepath.Join("..", ".."))
	installer, err := os.ReadFile(filepath.Join(repoRoot, "install.sh"))
	if err != nil {
		t.Fatalf("read install.sh: %v", err)
	}

	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "examples/config/apclient/config.yaml.example",
			data: mustReadTestFile(t, filepath.Join(repoRoot, "examples", "config", "apclient", "config.yaml.example")),
		},
		{
			name: "install.sh write_apshell_local_config",
			data: []byte(strings.NewReplacer(
				"$signer_port", "11270",
				"$ssh_port", "1127",
			).Replace(extractInstallHereDocAfter(
				t,
				string(installer),
				"write_apshell_local_config() {",
				`cat > "$target" <<EOF`,
			))),
		},
		{
			name: "install.sh remote apshell config",
			data: []byte(extractInstallHereDoc(t, string(installer), `cat > "$APCLIENT_CONFIG" <<'EOF'`)),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := decodeClientConfigKnownFields(tt.data); err != nil {
				t.Fatalf("config contains fields outside internal/config.Config: %v", err)
			}
		})
	}
}

func TestClientEndpointExamplesUseKnownFields(t *testing.T) {
	repoRoot := filepath.Clean(filepath.Join("..", ".."))
	installer, err := os.ReadFile(filepath.Join(repoRoot, "install.sh"))
	if err != nil {
		t.Fatalf("read install.sh: %v", err)
	}

	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "examples/config/apclient/endpoints.yaml.example",
			data: mustReadTestFile(t, filepath.Join(repoRoot, "examples", "config", "apclient", "endpoints.yaml.example")),
		},
		{
			name: "install.sh write_apshell_endpoint_registry",
			data: []byte(strings.NewReplacer(
				"$host", "localhost",
				"$signer_port", "11270",
				"$ssh_port", "1127",
			).Replace(extractInstallHereDocAfter(
				t,
				string(installer),
				"write_apshell_endpoint_registry() {",
				`cat > "$target" <<EOF`,
			))),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := decodeClientEndpointRegistryKnownFields(tt.data); err != nil {
				t.Fatalf("endpoint registry contains invalid fields: %v", err)
			}
		})
	}
}

func mustReadTestFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}

func extractInstallHereDoc(t *testing.T, installer, marker string) string {
	t.Helper()
	start := strings.Index(installer, marker)
	if start == -1 {
		t.Fatalf("install.sh heredoc marker not found: %s", marker)
	}
	bodyStart := strings.Index(installer[start:], "\n")
	if bodyStart == -1 {
		t.Fatalf("install.sh heredoc marker has no body: %s", marker)
	}
	body := installer[start+bodyStart+1:]
	end := strings.Index(body, "\nEOF")
	if end == -1 {
		t.Fatalf("install.sh heredoc terminator not found after marker: %s", marker)
	}
	return body[:end]
}

func extractInstallHereDocAfter(t *testing.T, installer, after, marker string) string {
	t.Helper()
	sectionStart := strings.Index(installer, after)
	if sectionStart == -1 {
		t.Fatalf("install.sh section marker not found: %s", after)
	}
	return extractInstallHereDoc(t, installer[sectionStart:], marker)
}

func decodeClientConfigKnownFields(data []byte) error {
	var cfg Config
	if err := unmarshalKnownFields(data, &cfg); err != nil {
		return err
	}
	return nil
}

func decodeClientEndpointRegistryKnownFields(data []byte) error {
	var registry ClientEndpointRegistry
	if err := unmarshalKnownFields(data, &registry); err != nil {
		return err
	}
	return normalizeStoredClientEndpointRegistry(&registry)
}

func attestorEndpointTestHex(prefix string) string {
	return attestorEndpointTestHexN(prefix, 32)
}

func attestorEndpointTestHexN(prefix string, size int) string {
	return prefix + strings.Repeat("00", size-1)
}

func attestorEndpointConfigTestComponentKey(t *testing.T, keyType, publicKeyHex string) string {
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
