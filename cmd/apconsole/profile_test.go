// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/adminipc"
)

func TestLoadConsoleProfileLocalResolvesRelativePaths(t *testing.T) {
	root := t.TempDir()
	writeConsoleProfile(t, root, `
mode: local
client_data: ./apclient
signer_data: ./apsigner
`)

	profile, err := loadConsoleProfile(filepath.Join(root, consoleProfileName))
	if err != nil {
		t.Fatalf("loadConsoleProfile failed: %v", err)
	}
	if profile.Mode != consoleModeLocal {
		t.Fatalf("Mode = %q, want local", profile.Mode)
	}
	if profile.ClientData != filepath.Join(root, "apclient") {
		t.Fatalf("ClientData = %q", profile.ClientData)
	}
	if profile.SignerData != filepath.Join(root, "apsigner") {
		t.Fatalf("SignerData = %q", profile.SignerData)
	}
}

func TestLoadConsoleProfileRemoteAllowsNoSignerData(t *testing.T) {
	root := t.TempDir()
	writeConsoleProfile(t, root, `
mode: remote
client_data: ./apclient
`)

	profile, err := loadConsoleProfile(filepath.Join(root, consoleProfileName))
	if err != nil {
		t.Fatalf("loadConsoleProfile failed: %v", err)
	}
	if profile.Mode != consoleModeRemote {
		t.Fatalf("Mode = %q, want remote", profile.Mode)
	}
	if profile.SignerData != "" {
		t.Fatalf("SignerData = %q, want empty", profile.SignerData)
	}
}

func TestLoadConsoleProfileRejectsLocalWithoutSignerData(t *testing.T) {
	root := t.TempDir()
	writeConsoleProfile(t, root, `
mode: local
client_data: ./apclient
`)

	_, err := loadConsoleProfile(filepath.Join(root, consoleProfileName))
	if err == nil {
		t.Fatal("err = nil, want signer_data error")
	}
	if !strings.Contains(err.Error(), "signer_data is required") {
		t.Fatalf("err = %v", err)
	}
}

func TestResolveConsoleStartupDiscoversProfileFromApclientDir(t *testing.T) {
	root := t.TempDir()
	apclient := filepath.Join(root, "apclient")
	apsigner := filepath.Join(root, "apsigner")
	if err := os.MkdirAll(apclient, 0o700); err != nil {
		t.Fatalf("mkdir apclient: %v", err)
	}
	writeConsoleProfile(t, root, `
mode: local
client_data: ./apclient
signer_data: ./apsigner
`)

	cfg, err := resolveConsoleStartup(consoleStartupFlags{
		CurrentDir: apclient,
	})
	if err != nil {
		t.Fatalf("resolveConsoleStartup failed: %v", err)
	}
	if cfg.Mode != consoleModeLocal {
		t.Fatalf("Mode = %q, want local", cfg.Mode)
	}
	if cfg.ClientData != apclient {
		t.Fatalf("ClientData = %q, want %q", cfg.ClientData, apclient)
	}
	if cfg.SignerData != apsigner {
		t.Fatalf("SignerData = %q, want %q", cfg.SignerData, apsigner)
	}
	if cfg.ProfilePath != filepath.Join(root, consoleProfileName) {
		t.Fatalf("ProfilePath = %q", cfg.ProfilePath)
	}
}

func TestResolveConsoleStartupRemoteProfile(t *testing.T) {
	root := t.TempDir()
	writeConsoleProfile(t, root, `
mode: remote
client_data: ./apclient
`)

	cfg, err := resolveConsoleStartup(consoleStartupFlags{
		ConfigPath: filepath.Join(root, consoleProfileName),
	})
	if err != nil {
		t.Fatalf("resolveConsoleStartup failed: %v", err)
	}
	if cfg.Mode != consoleModeRemote {
		t.Fatalf("Mode = %q, want remote", cfg.Mode)
	}
	if cfg.ClientData != filepath.Join(root, "apclient") {
		t.Fatalf("ClientData = %q", cfg.ClientData)
	}
	if cfg.SignerData != "" {
		t.Fatalf("SignerData = %q, want empty", cfg.SignerData)
	}
}

func TestResolveConsoleStartupRejectsConflictingExplicitProfileAndFlags(t *testing.T) {
	root := t.TempDir()
	writeConsoleProfile(t, root, `
mode: remote
client_data: ./apclient
`)

	_, err := resolveConsoleStartup(consoleStartupFlags{
		ConfigPath:    filepath.Join(root, consoleProfileName),
		RemoteSet:     true,
		Remote:        false,
		ClientDataSet: true,
		ClientData:    filepath.Join(root, "other-client"),
		SignerDataSet: true,
		SignerData:    filepath.Join(root, "other-signer"),
	})
	if err == nil {
		t.Fatal("err = nil, want explicit conflict error")
	}
	if !strings.Contains(err.Error(), "conflicting mode values") {
		t.Fatalf("err = %v", err)
	}
}

func TestResolveConsoleStartupFallsBackToEnvWithoutProfile(t *testing.T) {
	cfg, err := resolveConsoleStartup(consoleStartupFlags{
		CurrentDir:    t.TempDir(),
		ClientDataEnv: filepath.Join(t.TempDir(), "apclient"),
		SignerDataEnv: filepath.Join(t.TempDir(), "apsigner"),
	})
	if err != nil {
		t.Fatalf("resolveConsoleStartup failed: %v", err)
	}
	if cfg.Mode != consoleModeLocal {
		t.Fatalf("Mode = %q, want local", cfg.Mode)
	}
	if cfg.ClientData == "" {
		t.Fatal("ClientData empty, want env fallback")
	}
	if cfg.SignerData == "" {
		t.Fatal("SignerData empty, want env fallback")
	}
}

func TestResolveConsoleIPCPathPreservesSourcePrecedence(t *testing.T) {
	const environmentIPCPath = "/run/environment/aplane.sock"
	t.Setenv(adminipc.SocketPathEnv, environmentIPCPath)

	t.Run("explicit profile selects its store", func(t *testing.T) {
		root := t.TempDir()
		dataDir := filepath.Join(root, "signer")
		if err := os.MkdirAll(dataDir, 0o700); err != nil {
			t.Fatal(err)
		}
		configuredIPCPath := filepath.Join(dataDir, "configured.sock")
		if err := os.WriteFile(filepath.Join(dataDir, "config.yaml"), []byte("ipc_path: "+configuredIPCPath+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		writeConsoleProfile(t, root, `
mode: local
client_data: ./client
signer_data: ./signer
`)
		cfg, err := resolveConsoleStartup(consoleStartupFlags{ConfigPath: filepath.Join(root, consoleProfileName)})
		if err != nil {
			t.Fatal(err)
		}
		got, err := resolveConsoleIPCPath(cfg.SignerData, "", cfg.signerDataSource)
		if err != nil {
			t.Fatal(err)
		}
		if got != configuredIPCPath {
			t.Fatalf("resolved IPC path = %q, want explicit profile path %q", got, configuredIPCPath)
		}
	})

	t.Run("signer environment retains IPC pairing", func(t *testing.T) {
		cfg, err := resolveConsoleStartup(consoleStartupFlags{
			CurrentDir:    t.TempDir(),
			SignerDataEnv: filepath.Join(t.TempDir(), "signer"),
			ClientDataEnv: filepath.Join(t.TempDir(), "client"),
		})
		if err != nil {
			t.Fatal(err)
		}
		got, err := resolveConsoleIPCPath(cfg.SignerData, "", cfg.signerDataSource)
		if err != nil {
			t.Fatal(err)
		}
		if got != environmentIPCPath {
			t.Fatalf("resolved IPC path = %q, want paired environment path %q", got, environmentIPCPath)
		}
	})

	t.Run("auto profile remains below IPC environment", func(t *testing.T) {
		root := t.TempDir()
		clientDir := filepath.Join(root, "client")
		if err := os.MkdirAll(clientDir, 0o700); err != nil {
			t.Fatal(err)
		}
		writeConsoleProfile(t, root, `
mode: local
client_data: ./client
signer_data: ./signer
`)
		cfg, err := resolveConsoleStartup(consoleStartupFlags{CurrentDir: clientDir})
		if err != nil {
			t.Fatal(err)
		}
		got, err := resolveConsoleIPCPath(cfg.SignerData, "", cfg.signerDataSource)
		if err != nil {
			t.Fatal(err)
		}
		if got != environmentIPCPath {
			t.Fatalf("resolved IPC path = %q, want higher-precedence environment path %q", got, environmentIPCPath)
		}
	})
}

func TestResolveConsoleStartupEnvOverridesAutoProfileWithNotice(t *testing.T) {
	root := t.TempDir()
	apclient := filepath.Join(root, "apclient")
	if err := os.MkdirAll(apclient, 0o700); err != nil {
		t.Fatalf("mkdir apclient: %v", err)
	}
	writeConsoleProfile(t, root, `
mode: local
client_data: ./apclient
signer_data: ./apsigner
`)

	overrideClient := filepath.Join(root, "override-client")
	overrideSigner := filepath.Join(root, "override-signer")
	cfg, err := resolveConsoleStartup(consoleStartupFlags{
		CurrentDir:    apclient,
		ClientDataEnv: overrideClient,
		SignerDataEnv: overrideSigner,
	})
	if err != nil {
		t.Fatalf("resolveConsoleStartup failed: %v", err)
	}
	if cfg.ClientData != overrideClient {
		t.Fatalf("ClientData = %q, want %q", cfg.ClientData, overrideClient)
	}
	if cfg.SignerData != overrideSigner {
		t.Fatalf("SignerData = %q, want %q", cfg.SignerData, overrideSigner)
	}
	if len(cfg.Notices) != 2 {
		t.Fatalf("Notices = %#v, want 2 notices", cfg.Notices)
	}
	if !strings.Contains(cfg.Notices[0], "environment APCLIENT_DATA") {
		t.Fatalf("notice = %q", cfg.Notices[0])
	}
	if !strings.Contains(cfg.Notices[1], "environment APSIGNER_DATA") {
		t.Fatalf("notice = %q", cfg.Notices[1])
	}
}

func TestResolveConsoleStartupRejectsConflictingFlagAndEnv(t *testing.T) {
	_, err := resolveConsoleStartup(consoleStartupFlags{
		ClientDataEnv: filepath.Join(t.TempDir(), "env-client"),
		ClientDataSet: true,
		ClientData:    filepath.Join(t.TempDir(), "flag-client"),
	})
	if err == nil {
		t.Fatal("err = nil, want explicit conflict error")
	}
	if !strings.Contains(err.Error(), "conflicting client_data values") {
		t.Fatalf("err = %v", err)
	}
}

func TestResolveConsoleStartupRejectsConflictingExplicitProfileAndEnv(t *testing.T) {
	root := t.TempDir()
	writeConsoleProfile(t, root, `
mode: local
client_data: ./apclient
signer_data: ./apsigner
`)

	_, err := resolveConsoleStartup(consoleStartupFlags{
		ConfigPath:    filepath.Join(root, consoleProfileName),
		ClientDataEnv: filepath.Join(root, "other-client"),
	})
	if err == nil {
		t.Fatal("err = nil, want explicit conflict error")
	}
	if !strings.Contains(err.Error(), "conflicting client_data values") {
		t.Fatalf("err = %v", err)
	}
}

func writeConsoleProfile(t *testing.T, root, contents string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, consoleProfileName), []byte(strings.TrimSpace(contents)+"\n"), 0o600); err != nil {
		t.Fatalf("write apconsole profile: %v", err)
	}
}
