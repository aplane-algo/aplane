// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package serverconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	apconfig "github.com/aplane-algo/aplane/internal/config"
)

func TestLoadServerConfigDefaultsUserAutoApprove(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("schema_version: 1\n"), 0o640); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg, err := LoadServerConfig(dir)
	if err != nil {
		t.Fatalf("LoadServerConfig: %v", err)
	}
	if cfg.UserAutoApprove {
		t.Fatal("user_auto_approve default = true, want false")
	}
	if cfg.ApprovalWait != DefaultApprovalWaitString {
		t.Fatalf("approval_wait default = %q, want %q", cfg.ApprovalWait, DefaultApprovalWaitString)
	}
	if cfg.Endpoint.SSH.ListenAddress != apconfig.DefaultSSHListenAddress {
		t.Fatalf("endpoint.ssh.listen_address default = %q, want %q", cfg.Endpoint.SSH.ListenAddress, apconfig.DefaultSSHListenAddress)
	}
}

func TestLoadServerConfigUserAutoApprove(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("user_auto_approve: true\n"), 0o640); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg, err := LoadServerConfig(dir)
	if err != nil {
		t.Fatalf("LoadServerConfig: %v", err)
	}
	if !cfg.UserAutoApprove {
		t.Fatalf("user_auto_approve = %+v, want true", cfg.UserAutoApprove)
	}
}

func TestLoadServerConfigRejectsManualApproval(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("manual_approval: true\n"), 0o640); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := LoadServerConfig(dir)
	if err == nil {
		t.Fatal("LoadServerConfig error = nil, want unknown-field rejection")
	}
	if !strings.Contains(err.Error(), `config field "manual_approval" is unknown or no longer supported`) {
		t.Fatalf("LoadServerConfig error = %q, want manual_approval unknown-field guidance", err)
	}
}

func TestLoadServerConfigRejectsInvalidApprovalWait(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("approval_wait: 10s\n"), 0o640); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if _, err := LoadServerConfig(dir); err == nil {
		t.Fatal("LoadServerConfig error = nil, want invalid approval_wait error")
	}
}

// An invalid passphrase_timeout is refused like an invalid approval_wait. It
// was once read as 0, which turned the admin idle timeout off.
func TestLoadServerConfigRejectsInvalidPassphraseTimeout(t *testing.T) {
	t.Parallel()

	for _, value := range []string{"15mins", "-5m"} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("passphrase_timeout: "+value+"\n"), 0o640); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}

		_, err := LoadServerConfig(dir)
		if err == nil || !strings.Contains(err.Error(), "invalid passphrase_timeout") {
			t.Fatalf("LoadServerConfig(passphrase_timeout: %s) error = %v, want invalid passphrase_timeout", value, err)
		}
	}
}

func TestLoadServerConfigSchemaVersion(t *testing.T) {
	t.Parallel()

	t.Run("explicit v1 accepted", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("schema_version: 1\napproval_wait: 60s\n"), 0o640); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}

		cfg, err := LoadServerConfig(dir)
		if err != nil {
			t.Fatalf("LoadServerConfig: %v", err)
		}
		if cfg.SchemaVersion != apconfig.ConfigSchemaVersion {
			t.Fatalf("SchemaVersion = %d, want %d", cfg.SchemaVersion, apconfig.ConfigSchemaVersion)
		}
	})

	t.Run("absent means v1", func(t *testing.T) {
		t.Parallel()

		cfg := DefaultServerConfig()
		if cfg.SchemaVersion != apconfig.ConfigSchemaVersion {
			t.Fatalf("DefaultServerConfig().SchemaVersion = %d, want %d", cfg.SchemaVersion, apconfig.ConfigSchemaVersion)
		}
	})

	t.Run("newer version rejected", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("schema_version: 2\n"), 0o640); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}

		_, err := LoadServerConfig(dir)
		if err == nil {
			t.Fatal("LoadServerConfig error = nil, want schema_version rejection")
		}
		if !strings.Contains(err.Error(), "schema_version = 2, want 1") {
			t.Fatalf("LoadServerConfig error = %q, want schema_version mismatch", err)
		}
	})
}

func TestLoadServerConfigRejectsUnknownFields(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("surprise: true\n"), 0o640); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := LoadServerConfig(dir)
	if err == nil {
		t.Fatal("LoadServerConfig error = nil, want unknown field error")
	}
	if !strings.Contains(err.Error(), "field surprise not found") {
		t.Fatalf("LoadServerConfig error = %q, want surprise", err)
	}
	if !strings.Contains(err.Error(), "is unknown or no longer supported; remove it") {
		t.Fatalf("LoadServerConfig error = %q, want the remove-it guidance", err)
	}
}

// A field this version no longer reads, such as theme, which earlier
// apadmin versions wrote here before the setting moved to the product runtime
// config, is refused by name with the advice to remove it. The error once
// said the file was written by a newer version.
func TestLoadServerConfigNamesARemovedField(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("approval_wait: 5m\ntheme: dark\n"), 0o640); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := LoadServerConfig(dir)
	if err == nil {
		t.Fatal("LoadServerConfig error = nil, want the removed field refused")
	}
	msg := err.Error()
	if !strings.Contains(msg, `config field "theme" is unknown or no longer supported; remove it from the file`) {
		t.Fatalf("LoadServerConfig error = %q, want theme named with the remove-it guidance", msg)
	}
	if strings.Contains(msg, "newer version") {
		t.Fatalf("LoadServerConfig error = %q, blames a newer version for a field an earlier one wrote", msg)
	}
}

func TestLoadServerConfigRejectsLegacyTopLevelEndpointFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		data         string
		wantErrPiece string
	}{
		{
			name:         "signer_port",
			data:         "signer_port: 11270\n",
			wantErrPiece: "field signer_port not found",
		},
		{
			name: "ssh",
			data: `ssh:
  listen_address: 127.0.0.1
  port: 1127
`,
			wantErrPiece: "field ssh not found",
		},
		{
			name:         "advertise_url",
			data:         "advertise_url: ssh://signer.example.com:1127\n",
			wantErrPiece: "field advertise_url not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(tt.data), 0o640); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}

			_, err := LoadServerConfig(dir)
			if err == nil {
				t.Fatal("LoadServerConfig error = nil, want legacy endpoint field rejection")
			}
			if !strings.Contains(err.Error(), tt.wantErrPiece) {
				t.Fatalf("LoadServerConfig error = %q, want %q", err, tt.wantErrPiece)
			}
		})
	}
}

func TestLoadServerConfigRejectsUnknownNestedFields(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(`
endpoint:
  ssh:
    port: 1127
    surprise: true
`), 0o640); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := LoadServerConfig(dir)
	if err == nil {
		t.Fatal("LoadServerConfig error = nil, want unknown nested field error")
	}
	if !strings.Contains(err.Error(), "field surprise not found") {
		t.Fatalf("LoadServerConfig error = %q, want surprise", err)
	}
}

func TestLoadServerConfigAcceptsEndpointAdvertiseURL(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(`
endpoint:
  advertise_url: ssh://signer.example:2223
`), 0o640); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg, err := LoadServerConfig(dir)
	if err != nil {
		t.Fatalf("LoadServerConfig error = %v", err)
	}
	if cfg.Endpoint.AdvertiseURL != "ssh://signer.example:2223" {
		t.Fatalf("AdvertiseURL = %q, want configured URL", cfg.Endpoint.AdvertiseURL)
	}
}

func TestLoadServerConfigRejectsInvalidEndpointAdvertiseURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data string
	}{
		{
			name: "self",
			data: `
endpoint:
  advertise_url: self
`,
		},
		{
			name: "remote http",
			data: `
endpoint:
  advertise_url: http://signer.example:11270
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(tt.data), 0o640); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}

			_, err := LoadServerConfig(dir)
			if err == nil {
				t.Fatal("LoadServerConfig error = nil, want invalid endpoint.advertise_url error")
			}
			if !strings.Contains(err.Error(), "invalid endpoint.advertise_url") {
				t.Fatalf("LoadServerConfig error = %q, want endpoint.advertise_url", err)
			}
		})
	}
}

// The URL rules for endpoint.advertise_url, which apadmin endpoint export
// writes into an envelope. An accepted URL is kept without surrounding space
// or a trailing slash; an empty one means none is advertised.
func TestLoadServerConfigEndpointAdvertiseURLRules(t *testing.T) {
	t.Parallel()

	tests := []struct {
		raw     string
		wantURL string
		wantErr string // after "invalid endpoint.advertise_url in config: "
	}{
		{raw: "", wantURL: ""},
		{raw: "ssh://signer.example", wantURL: "ssh://signer.example"},
		{raw: " ssh://signer.example:2223/ ", wantURL: "ssh://signer.example:2223"},
		{raw: "ssh://[::1]:2223", wantURL: "ssh://[::1]:2223"},
		{raw: "ssh://signer.example:0", wantErr: `invalid url port "0"`},
		{raw: "ssh:///path", wantErr: "url host is required"},
		{raw: "https://signer.example:8443", wantErr: `unsupported url scheme "https"; endpoints are ssh://host[:port]`},
		{raw: "http://127.0.0.1:11270", wantErr: `unsupported url scheme "http"; endpoints are ssh://host[:port]`},
		{raw: "http://localhost:11270", wantErr: `unsupported url scheme "http"; endpoints are ssh://host[:port]`},
		{raw: "http://[::1]:11270", wantErr: `unsupported url scheme "http"; endpoints are ssh://host[:port]`},
		{raw: "http://signer.example:11270", wantErr: `unsupported url scheme "http"; endpoints are ssh://host[:port]`},
		{raw: "ftp://signer.example", wantErr: `unsupported url scheme "ftp"; endpoints are ssh://host[:port]`},
		{raw: "self", wantErr: `unsupported url scheme ""; endpoints are ssh://host[:port]`},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			dir := t.TempDir()
			data := fmt.Sprintf("endpoint:\n  advertise_url: %q\n", tt.raw)
			if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(data), 0o640); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			cfg, err := LoadServerConfig(dir)
			if tt.wantErr != "" {
				if err == nil || err.Error() != "invalid endpoint.advertise_url in config: "+tt.wantErr {
					t.Fatalf("LoadServerConfig error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil || cfg.Endpoint.AdvertiseURL != tt.wantURL {
				t.Fatalf("LoadServerConfig = %q, %v; want %q", cfg.Endpoint.AdvertiseURL, err, tt.wantURL)
			}
		})
	}
}

func TestLoadServerConfigSSHListenAddress(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		data         string
		want         string
		wantErrPiece string
	}{
		{
			name: "explicit IPv4",
			data: `
endpoint:
  ssh:
    listen_address: 0.0.0.0
`,
			want: "0.0.0.0",
		},
		{
			name: "explicit hostname",
			data: `
endpoint:
  ssh:
    listen_address: signer.local
`,
			want: "signer.local",
		},
		{
			name: "reject URL",
			data: `
endpoint:
  ssh:
    listen_address: ssh://127.0.0.1
`,
			wantErrPiece: "invalid endpoint.ssh.listen_address",
		},
		{
			name: "reject host port",
			data: `
endpoint:
  ssh:
    listen_address: 127.0.0.1:1127
`,
			wantErrPiece: "invalid endpoint.ssh.listen_address",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(tt.data), 0o640); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}

			cfg, err := LoadServerConfig(dir)
			if tt.wantErrPiece != "" {
				if err == nil {
					t.Fatal("LoadServerConfig error = nil, want rejection")
				}
				if !strings.Contains(err.Error(), tt.wantErrPiece) {
					t.Fatalf("LoadServerConfig error = %q, want %q", err, tt.wantErrPiece)
				}
				return
			}
			if err != nil {
				t.Fatalf("LoadServerConfig error = %v", err)
			}
			if cfg.Endpoint.SSH.ListenAddress != tt.want {
				t.Fatalf("Endpoint.SSH.ListenAddress = %q, want %q", cfg.Endpoint.SSH.ListenAddress, tt.want)
			}
		})
	}
}

func TestParseApprovalWait(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		value   string
		want    time.Duration
		wantErr bool
	}{
		{name: "empty default", value: "", want: DefaultApprovalWait},
		{name: "valid", value: "10m", want: 10 * time.Minute},
		{name: "zero", value: "0", wantErr: true},
		{name: "negative", value: "-1m", wantErr: true},
		{name: "below minimum", value: "29s", wantErr: true},
		{name: "above maximum", value: "31m", wantErr: true},
		{name: "bad format", value: "soon", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseApprovalWait(tt.value)
			if tt.wantErr {
				if err == nil {
					t.Fatal("ParseApprovalWait error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseApprovalWait error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("ParseApprovalWait = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestServerConfigExamplesUseKnownFields(t *testing.T) {
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
			name: "examples/config/apsigner/config.yaml.example",
			data: mustReadTestFile(t, filepath.Join(repoRoot, "examples", "config", "apsigner", "config.yaml.example")),
		},
		{
			name: "examples/config/apsigner/config.yaml.example.auto",
			data: mustReadTestFile(t, filepath.Join(repoRoot, "examples", "config", "apsigner", "config.yaml.example.auto")),
		},
		{
			name: "install.sh write_apsigner_config",
			data: []byte(strings.NewReplacer(
				"$signer_port", "11270",
				"$ssh_port", "1127",
				"$require_memory_protection", "false",
				"$advertise_line", `  advertise_url: "ssh://cosigner.example:1127"`,
				"$listen_address", "0.0.0.0",
			).Replace(extractInstallHereDocAfter(
				t,
				string(installer),
				"write_signer_config() {",
				`cat > "$target" <<EOF`,
			))),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := decodeServerConfigKnownFields(tt.data); err != nil {
				t.Fatalf("config contains fields outside internal/config.ServerConfig: %v", err)
			}
		})
	}
}

func decodeServerConfigKnownFields(data []byte) error {
	var cfg ServerConfig
	return apconfig.UnmarshalKnownFields(data, &cfg)
}

func TestServerConfigCloneDeepCopiesMutableFields(t *testing.T) {
	lockOnDisconnect := true
	cfg := ServerConfig{
		UserAutoApprove:  true,
		LockOnDisconnect: &lockOnDisconnect,
		Algod: apconfig.AlgodConfig{
			"testnet": {Server: "http://algod", Token: "token"},
		},
		GenesisHashNetworks: map[string]string{"hash": "voi_mainnet"},
		Networks: ServerNetworkConfigs{
			"localnet": {Algod: &apconfig.AlgodNetworkConfig{Server: "http://localnet", Token: "token"}, GenesisHash: "hash2"},
		},
	}

	clone := cfg.Clone()
	clone.UserAutoApprove = false
	*clone.LockOnDisconnect = false
	clone.Algod["testnet"].Server = "changed"

	if *cfg.LockOnDisconnect != true {
		t.Fatal("Clone shared LockOnDisconnect pointer")
	}
	if cfg.Algod["testnet"].Server != "http://algod" {
		t.Fatal("Clone shared Algod nested config")
	}
	clone.GenesisHashNetworks["hash"] = "changed"
	if cfg.GenesisHashNetworks["hash"] != "voi_mainnet" {
		t.Fatal("Clone shared GenesisHashNetworks map")
	}
	clone.Networks["localnet"].Algod.Server = "changed"
	if cfg.Networks["localnet"].Algod.Server != "http://localnet" {
		t.Fatal("Clone shared Networks nested algod config")
	}
	clone.Networks["localnet"].GenesisHash = "changed"
	if cfg.Networks["localnet"].GenesisHash != "hash2" {
		t.Fatal("Clone shared Networks nested config")
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

func extractInstallHereDocAfter(t *testing.T, installer, after, marker string) string {
	t.Helper()
	sectionStart := strings.Index(installer, after)
	if sectionStart == -1 {
		t.Fatalf("install.sh section marker not found: %s", after)
	}
	return extractInstallHereDoc(t, installer[sectionStart:], marker)
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

func TestServerConfigRotatingStageHorizonDefaultsAndOverrides(t *testing.T) {
	t.Parallel()

	if got := DefaultServerConfig().Rotating.StageHorizon; got != DefaultStageHorizon {
		t.Fatalf("default stage_horizon = %d, want %d", got, DefaultStageHorizon)
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("schema_version: 1\n"), 0o640); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	cfg, err := LoadServerConfig(dir)
	if err != nil {
		t.Fatalf("LoadServerConfig: %v", err)
	}
	if cfg.Rotating.StageHorizon != DefaultStageHorizon {
		t.Fatalf("stage_horizon without a rotating block = %d, want default", cfg.Rotating.StageHorizon)
	}

	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("rotating:\n  stage_horizon: 512\n"), 0o640); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	cfg, err = LoadServerConfig(dir)
	if err != nil {
		t.Fatalf("LoadServerConfig: %v", err)
	}
	if cfg.Rotating.StageHorizon != 512 {
		t.Fatalf("stage_horizon = %d, want 512", cfg.Rotating.StageHorizon)
	}
	if cfg.Clone().Rotating.StageHorizon != 512 {
		t.Fatal("Clone dropped the rotating settings")
	}
	// Recovery settings default alongside the horizon and load from the
	// same block; zero disables automatic recovery and is kept as given.
	if cfg.Rotating.RecoveryMaxStages != DefaultRecoveryMaxStages || cfg.Rotating.RecoveryTimeout != DefaultRecoveryTimeout {
		t.Fatalf("recovery defaults = %d, %v", cfg.Rotating.RecoveryMaxStages, cfg.Rotating.RecoveryTimeout)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("rotating:\n  recovery_max_stages: 0\n  recovery_timeout: 90s\n"), 0o640); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	cfg, err = LoadServerConfig(dir)
	if err != nil {
		t.Fatalf("LoadServerConfig: %v", err)
	}
	if cfg.Rotating.RecoveryMaxStages != 0 || cfg.Rotating.RecoveryTimeout != 90*time.Second || cfg.Rotating.StageHorizon != DefaultStageHorizon {
		t.Fatalf("recovery overrides = %+v", cfg.Rotating)
	}
}
