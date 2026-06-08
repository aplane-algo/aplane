// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package config

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
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

func TestDisplayConfigPointsSignerRoutingAtEndpoints(t *testing.T) {
	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, "config.yaml"), []byte(`
network: testnet
networks:
  testnet:
    algod:
      server: http://localhost:4001
`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	out := captureStdout(t, func() {
		DisplayConfig(dataDir)
	})
	if strings.Contains(out, "add ssh block to config.yaml") {
		t.Fatalf("DisplayConfig output points at legacy ssh config:\n%s", out)
	}
	if !strings.Contains(out, "current signer routing is endpoints.yaml") {
		t.Fatalf("DisplayConfig output missing endpoint routing guidance:\n%s", out)
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

func TestLoadConfigRejectsSentryEndpointsField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(fmt.Sprintf(`
network: testnet
sentry_endpoints:
  %s:
    url: self
`, sentryEndpointTestHex("d6"))), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := LoadConfigFromPath(path)
	if err == nil {
		t.Fatal("LoadConfigFromPath error = nil, want unknown sentry_endpoints field")
	}
	if !strings.Contains(err.Error(), "field sentry_endpoints not found") {
		t.Fatalf("LoadConfigFromPath error = %q, want sentry_endpoints unknown field", err)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	t.Cleanup(func() {
		os.Stdout = oldStdout
	})

	fn()

	if err := w.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	os.Stdout = oldStdout

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("close reader: %v", err)
	}
	return string(out)
}

func TestLoadConfigEndpointRegistryDerivesSentryRoutesFromPublishedInventory(t *testing.T) {
	dataDir := t.TempDir()
	publicKey := sentryEndpointTestHex("d6")
	componentKey := sentryEndpointConfigTestComponentKey(t, keytypes.SentryComponentEd25519V1, publicKey)
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
  sentry-local:
    role: sentry
    url: ssh://127.0.0.1:2223
    signer_port: 12271
    published_sentries:
      %s:
        component_key: %s
        key_type: %s
        last_seen_at: "2026-06-04T00:00:00Z"
`, publicKey, componentKey, keytypes.SentryComponentEd25519V1)), 0o600); err != nil {
		t.Fatalf("write endpoints: %v", err)
	}

	cfg, err := LoadConfig(dataDir)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	route, ok := cfg.SentryEndpoints[publicKey]
	if !ok {
		t.Fatalf("derived sentry route for %s missing from %#v", publicKey, cfg.SentryEndpoints)
	}
	if route.Endpoint != "sentry-local" || route.URL != "ssh://127.0.0.1:2223" {
		t.Fatalf("derived route = %#v, want sentry-local ssh endpoint", route)
	}
	published := cfg.Endpoints.Endpoints["sentry-local"].PublishedSentries[publicKey]
	if published.ComponentKey != componentKey || published.KeyType != keytypes.SentryComponentEd25519V1 {
		t.Fatalf("published sentry = %#v, want component/key type", published)
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
		{
			name: "install.sh write_apshell_sentry_endpoint_registry",
			data: []byte(strings.NewReplacer(
				"$host", "localhost",
				"$signer_port", "11270",
				"$ssh_port", "1127",
			).Replace(extractInstallHereDocAfter(
				t,
				string(installer),
				"write_apshell_sentry_endpoint_registry() {",
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

func sentryEndpointTestHex(prefix string) string {
	return sentryEndpointTestHexN(prefix, 32)
}

func sentryEndpointTestHexN(prefix string, size int) string {
	return prefix + strings.Repeat("00", size-1)
}

func sentryEndpointConfigTestComponentKey(t *testing.T, keyType, publicKeyHex string) string {
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
