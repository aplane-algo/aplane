// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package serverconfig

import (
	apconfig "github.com/aplane-algo/aplane/internal/config"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestSaveSettingPreservesOtherFields(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	initial := `user_auto_approve: false
theme: auto
passphrase_timeout: "15m"
`
	if err := os.WriteFile(path, []byte(initial), 0o640); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if err := SaveSetting(dir, "theme", "dark"); err != nil {
		t.Fatalf("SaveSetting: %v", err)
	}

	cfg, err := LoadServerConfig(dir)
	if err != nil {
		t.Fatalf("LoadServerConfig: %v", err)
	}

	if cfg.Theme != "dark" {
		t.Fatalf("theme = %q, want %q", cfg.Theme, "dark")
	}
	if cfg.UserAutoApprove {
		t.Fatal("user_auto_approve = true, want false")
	}
	if cfg.PassphraseTimeout != "15m" {
		t.Fatalf("passphrase_timeout = %q, want %q", cfg.PassphraseTimeout, "15m")
	}
}

func TestLoadServerConfigDefaultsUserAutoApprove(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("theme: auto\n"), 0o640); err != nil {
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

func TestLoadServerConfigAcceptsLegacyManualApproval(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		config       string
		wantAuto     bool
		wantErr      bool
		wantErrPiece string
	}{
		{
			name:     "manual true means auto approve false",
			config:   "manual_approval: true\n",
			wantAuto: false,
		},
		{
			name:     "manual false means auto approve true",
			config:   "manual_approval: false\n",
			wantAuto: true,
		},
		{
			name:     "consistent with current field",
			config:   "manual_approval: true\nuser_auto_approve: false\n",
			wantAuto: false,
		},
		{
			name:         "conflicts with current field",
			config:       "manual_approval: true\nuser_auto_approve: true\n",
			wantErr:      true,
			wantErrPiece: "manual_approval is deprecated and conflicts with user_auto_approve",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(tt.config), 0o640); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}

			cfg, err := LoadServerConfig(dir)
			if tt.wantErr {
				if err == nil {
					t.Fatal("LoadServerConfig error = nil")
				}
				if !strings.Contains(err.Error(), tt.wantErrPiece) {
					t.Fatalf("LoadServerConfig error = %q, want %q", err, tt.wantErrPiece)
				}
				return
			}
			if err != nil {
				t.Fatalf("LoadServerConfig: %v", err)
			}
			if cfg.UserAutoApprove != tt.wantAuto {
				t.Fatalf("user_auto_approve = %v, want %v", cfg.UserAutoApprove, tt.wantAuto)
			}
		})
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

func TestConfigFileChangedDetectsThemeUserAutoApproveAndApprovalWait(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		modified string
	}{
		{
			name: "theme changed",
			modified: `user_auto_approve: false
theme: dark
passphrase_timeout: "15m"
`,
		},
		{
			name: "user_auto_approve changed",
			modified: `user_auto_approve: true
theme: auto
passphrase_timeout: "15m"
`,
		},
		{
			name: "approval_wait changed",
			modified: `user_auto_approve: false
theme: auto
passphrase_timeout: "15m"
approval_wait: "10m"
`,
		},
		{
			name: "endpoint signer_port changed",
			modified: `user_auto_approve: false
theme: auto
passphrase_timeout: "15m"
endpoint:
  signer_port: 22222
`,
		},
		{
			name: "endpoint ssh port changed",
			modified: `user_auto_approve: false
theme: auto
passphrase_timeout: "15m"
endpoint:
  ssh:
    port: 2222
`,
		},
		{
			name: "endpoint ssh listen address changed",
			modified: `user_auto_approve: false
theme: auto
passphrase_timeout: "15m"
endpoint:
  ssh:
    listen_address: 0.0.0.0
`,
		},
		{
			name: "endpoint advertise url changed",
			modified: `user_auto_approve: false
theme: auto
passphrase_timeout: "15m"
endpoint:
  advertise_url: ssh://signer.example:1127
`,
		},
		{
			name: "passphrase command env changed",
			modified: `user_auto_approve: false
theme: auto
passphrase_timeout: "15m"
passphrase_command_env:
  CREDENTIALS_DIRECTORY: /run/credentials/aplane
`,
		},
		{
			name: "networks changed",
			modified: `user_auto_approve: false
theme: auto
passphrase_timeout: "15m"
networks:
  testnet:
    algod:
      server: https://testnet-api.4160.nodely.dev
      token: ""
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.yaml")
			initial := `user_auto_approve: false
theme: auto
passphrase_timeout: "15m"
`
			if err := os.WriteFile(path, []byte(initial), 0o640); err != nil {
				t.Fatalf("WriteFile initial: %v", err)
			}

			startup, err := LoadServerConfig(dir)
			if err != nil {
				t.Fatalf("LoadServerConfig: %v", err)
			}

			if err := os.WriteFile(path, []byte(tt.modified), 0o640); err != nil {
				t.Fatalf("WriteFile modified: %v", err)
			}

			changed, err := ConfigFileChanged(dir, startup)
			if err != nil {
				t.Fatalf("ConfigFileChanged: %v", err)
			}
			if !changed {
				t.Fatal("changed = false, want true")
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
		UserAutoApprove:       true,
		LockOnDisconnect:      &lockOnDisconnect,
		PassphraseCommandArgv: []string{"appass-file", "/tmp/pass"},
		PassphraseCommandEnv:  map[string]string{"A": "B"},
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
	clone.PassphraseCommandArgv[0] = "changed"
	clone.PassphraseCommandEnv["A"] = "C"
	clone.Algod["testnet"].Server = "changed"

	if *cfg.LockOnDisconnect != true {
		t.Fatal("Clone shared LockOnDisconnect pointer")
	}
	if cfg.PassphraseCommandArgv[0] != "appass-file" {
		t.Fatal("Clone shared PassphraseCommandArgv slice")
	}
	if cfg.PassphraseCommandEnv["A"] != "B" {
		t.Fatal("Clone shared PassphraseCommandEnv map")
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

func TestSaveSettingPreservesFileMetadata(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	initial := []byte("theme: auto\n")
	if err := os.WriteFile(path, initial, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	before, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat before: %v", err)
	}
	beforeStat, ok := before.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("Stat before missing syscall metadata")
	}

	if err := SaveSetting(dir, "theme", "dark"); err != nil {
		t.Fatalf("SaveSetting: %v", err)
	}

	after, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat after: %v", err)
	}
	afterStat, ok := after.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("Stat after missing syscall metadata")
	}

	if after.Mode().Perm() != before.Mode().Perm() {
		t.Fatalf("mode = %04o, want %04o", after.Mode().Perm(), before.Mode().Perm())
	}
	if afterStat.Uid != beforeStat.Uid {
		t.Fatalf("uid = %d, want %d", afterStat.Uid, beforeStat.Uid)
	}
	if afterStat.Gid != beforeStat.Gid {
		t.Fatalf("gid = %d, want %d", afterStat.Gid, beforeStat.Gid)
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
