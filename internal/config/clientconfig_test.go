// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	falconfamily "github.com/aplane-algo/aplane/lsig/falcon1024/family"
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

func TestLoadConfigAttestorEndpointsCanonicalizesSelectors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	selector := "0X" + strings.ToUpper(attestorEndpointTestHex("d6"))
	if err := os.WriteFile(path, []byte(fmt.Sprintf(`
network: testnet
attestor_endpoints:
  %s:
    url: self
`, selector)), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := LoadConfigFromPath(path)
	if err != nil {
		t.Fatalf("LoadConfigFromPath: %v", err)
	}
	want := attestorEndpointTestHex("d6")
	endpoint, ok := cfg.AttestorEndpoints[want]
	if !ok {
		t.Fatalf("canonical endpoint %s missing from %#v", want, cfg.AttestorEndpoints)
	}
	if endpoint.URL != "self" {
		t.Fatalf("endpoint URL = %q, want self", endpoint.URL)
	}
}

func TestLoadConfigAttestorEndpointsAcceptFalcon1024Selectors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	selector := "0X" + strings.ToUpper(attestorEndpointTestHexN("d6", falconfamily.PublicKeySize))
	if err := os.WriteFile(path, []byte(fmt.Sprintf(`
network: testnet
attestor_endpoints:
  ? "%s"
  :
    url: self
`, selector)), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := LoadConfigFromPath(path)
	if err != nil {
		t.Fatalf("LoadConfigFromPath: %v", err)
	}
	want := attestorEndpointTestHexN("d6", falconfamily.PublicKeySize)
	endpoint, ok := cfg.AttestorEndpoints[want]
	if !ok {
		t.Fatalf("canonical endpoint %s missing from %#v", want, cfg.AttestorEndpoints)
	}
	if endpoint.URL != "self" {
		t.Fatalf("endpoint URL = %q, want self", endpoint.URL)
	}
}

func TestLoadConfigAttestorEndpointsRequireValidSelector(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(`
network: testnet
attestor_endpoints:
  deadbeef:
    url: self
`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := LoadConfigFromPath(path)
	if err == nil {
		t.Fatal("LoadConfigFromPath error = nil, want invalid attestor endpoint selector")
	}
	if !strings.Contains(err.Error(), "attestor public key length") {
		t.Fatalf("LoadConfigFromPath error = %q, want attestor public key length", err)
	}
}

func TestLoadConfigAttestorEndpointsRejectDuplicateCanonicalSelectors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	selector := attestorEndpointTestHex("d6")
	if err := os.WriteFile(path, []byte(fmt.Sprintf(`
network: testnet
attestor_endpoints:
  %s:
    url: self
  0X%s:
    url: self
`, selector, strings.ToUpper(selector))), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := LoadConfigFromPath(path)
	if err == nil {
		t.Fatal("LoadConfigFromPath error = nil, want duplicate canonical selector")
	}
	if !strings.Contains(err.Error(), "duplicate endpoint") {
		t.Fatalf("LoadConfigFromPath error = %q, want duplicate endpoint", err)
	}
}

func TestLoadConfigAttestorEndpointsRequireTokenForNonSelf(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(fmt.Sprintf(`
network: testnet
attestor_endpoints:
  %s:
    url: https://attestor.example
`, attestorEndpointTestHex("d6"))), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := LoadConfigFromPath(path)
	if err == nil {
		t.Fatal("LoadConfigFromPath error = nil, want missing token_file")
	}
	if !strings.Contains(err.Error(), "token_file is required") {
		t.Fatalf("LoadConfigFromPath error = %q, want token_file", err)
	}
}

func TestLoadConfigAttestorEndpointsRejectRemoteHTTP(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(fmt.Sprintf(`
network: testnet
attestor_endpoints:
  %s:
    url: http://attestor.example:11270
    token_file: token
`, attestorEndpointTestHex("d6"))), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := LoadConfigFromPath(path)
	if err == nil {
		t.Fatal("LoadConfigFromPath error = nil, want remote http rejection")
	}
	if !strings.Contains(err.Error(), "raw http endpoints must be loopback") {
		t.Fatalf("LoadConfigFromPath error = %q, want raw http endpoints must be loopback", err)
	}
}

func TestLoadConfigAttestorEndpointsResolvePaths(t *testing.T) {
	dataDir := t.TempDir()
	path := filepath.Join(dataDir, "config.yaml")
	selector := attestorEndpointTestHex("d6")
	if err := os.WriteFile(path, []byte(fmt.Sprintf(`
network: testnet
signer_port: 12270
ssh:
  host: signer.example
attestor_endpoints:
  %s:
    url: ssh://attestor.example:2222
    token_file: tokens/attestor.token
`, selector)), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := LoadConfig(dataDir)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	endpoint := cfg.AttestorEndpoints[selector]
	if endpoint.TokenFile != filepath.Join(dataDir, "tokens", "attestor.token") {
		t.Fatalf("token_file = %q, want data-dir relative", endpoint.TokenFile)
	}
	if endpoint.IdentityFile != filepath.Join(dataDir, ".ssh", "id_ed25519") {
		t.Fatalf("identity_file = %q, want default relative to data dir", endpoint.IdentityFile)
	}
	if endpoint.KnownHostsPath != filepath.Join(dataDir, ".ssh", "known_hosts") {
		t.Fatalf("known_hosts_path = %q, want default relative to data dir", endpoint.KnownHostsPath)
	}
	if endpoint.SignerPort != 12270 {
		t.Fatalf("signer_port = %d, want 12270", endpoint.SignerPort)
	}
}

func TestLoadConfigEndpointRegistryResolvesAttestorEndpointAlias(t *testing.T) {
	dataDir := t.TempDir()
	selector := attestorEndpointTestHex("d6")
	if err := os.WriteFile(filepath.Join(dataDir, "config.yaml"), []byte(fmt.Sprintf(`
network: testnet
signer_port: 12270
ssh:
  host: signer.example
  port: 2222
attestor_endpoints:
  %s:
    endpoint: attestor-local
`, selector)), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, ClientEndpointsFile), []byte(`
schema_version: 1
default: primary
endpoints:
  attestor-local:
    role: attestation
    url: ssh://127.0.0.1:2223
    signer_port: 12271
`), 0o600); err != nil {
		t.Fatalf("write endpoints: %v", err)
	}

	cfg, err := LoadConfig(dataDir)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if _, ok := cfg.Endpoints.Endpoints[DefaultClientEndpointName]; !ok {
		t.Fatalf("implicit primary endpoint missing from %#v", cfg.Endpoints.Endpoints)
	}
	attestor, ok := cfg.Endpoints.Endpoints["attestor-local"]
	if !ok {
		t.Fatalf("attestor-local endpoint missing from %#v", cfg.Endpoints.Endpoints)
	}
	if attestor.TokenFile != filepath.Join(dataDir, "tokens", "attestor-local.token") {
		t.Fatalf("attestor token_file = %q, want default endpoint token path", attestor.TokenFile)
	}
	if attestor.Role != "" {
		t.Fatalf("attestor role = %q, want deprecated role field cleared", attestor.Role)
	}
	if attestor.IdentityFile != filepath.Join(dataDir, ".ssh", "id_ed25519") {
		t.Fatalf("attestor identity_file = %q, want default SSH identity", attestor.IdentityFile)
	}

	route := cfg.AttestorEndpoints[selector]
	if route.Endpoint != "attestor-local" {
		t.Fatalf("attestor route endpoint = %q, want attestor-local", route.Endpoint)
	}
	if route.URL != "ssh://127.0.0.1:2223" {
		t.Fatalf("attestor route url = %q, want endpoint URL", route.URL)
	}
	if route.TokenFile != filepath.Join(dataDir, "tokens", "attestor-local.token") {
		t.Fatalf("attestor route token_file = %q, want resolved endpoint token path", route.TokenFile)
	}
	if route.SignerPort != 12271 {
		t.Fatalf("attestor route signer_port = %d, want endpoint signer port", route.SignerPort)
	}
}

func TestLoadConfigEndpointRegistryRejectsUnknownAttestorEndpointAlias(t *testing.T) {
	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, "config.yaml"), []byte(fmt.Sprintf(`
network: testnet
ssh:
  host: signer.example
attestor_endpoints:
  %s:
    endpoint: missing
`, attestorEndpointTestHex("d6"))), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, ClientEndpointsFile), []byte(`
schema_version: 1
default: primary
endpoints: {}
`), 0o600); err != nil {
		t.Fatalf("write endpoints: %v", err)
	}

	_, err := LoadConfig(dataDir)
	if err == nil {
		t.Fatal("LoadConfig error = nil, want unknown endpoint alias")
	}
	if !strings.Contains(err.Error(), "unknown endpoint alias") {
		t.Fatalf("LoadConfig error = %q, want unknown endpoint alias", err)
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
	if cfg.SignerPort == 0 {
		return fmt.Errorf("signer_port must be set in example config")
	}
	return nil
}

func attestorEndpointTestHex(prefix string) string {
	return attestorEndpointTestHexN(prefix, 32)
}

func attestorEndpointTestHexN(prefix string, size int) string {
	return prefix + strings.Repeat("00", size-1)
}
