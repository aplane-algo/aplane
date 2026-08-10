// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminipc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveDaemonPath(t *testing.T) {
	dataDir := "/var/lib/example-signer"
	legacy := filepath.Join(dataDir, "aplane.sock")
	for _, test := range []struct {
		name       string
		configured string
		managed    bool
		want       string
	}{
		{name: "managed default", configured: legacy, managed: true, want: SystemSocketPath},
		{name: "managed empty", managed: true, want: SystemSocketPath},
		{name: "managed custom", configured: "/secure/custom.sock", managed: true, want: "/secure/custom.sock"},
		{name: "same uid", configured: legacy, want: legacy},
		{name: "relative same uid", configured: "run/aplane.sock", want: filepath.Join(dataDir, "run/aplane.sock")},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := ResolveDaemonPath(dataDir, test.configured, test.managed); got != test.want {
				t.Fatalf("ResolveDaemonPath() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestResolveDaemonPathWithRelativeDataDirectory(t *testing.T) {
	dataDir := filepath.Join("relative", "signer")
	legacy := filepath.Join(dataDir, "aplane.sock")

	if got := ResolveDaemonPath(dataDir, "", false); got != legacy {
		t.Fatalf("ResolveDaemonPath(relative, unmanaged) = %q, want %q", got, legacy)
	}
	if got := ResolveDaemonPath(dataDir, "", true); got != SystemSocketPath {
		t.Fatalf("ResolveDaemonPath(relative, managed) = %q, want %q", got, SystemSocketPath)
	}
	if got := ResolveDaemonPath(dataDir, filepath.Join("run", "custom.sock"), false); got != filepath.Join(dataDir, "run", "custom.sock") {
		t.Fatalf("ResolveDaemonPath(relative custom) = %q", got)
	}
}

func TestResolveDaemonPathForDataDirRejectsManagedInStoreCustomPath(t *testing.T) {
	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, ".prod"), []byte("systemd-managed\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, configured := range []string{
		filepath.Join(dataDir, "run", "custom.sock"),
		"run/custom.sock",
	} {
		if _, managed, err := ResolveDaemonPathForDataDir(dataDir, configured); err == nil || !managed {
			t.Fatalf("ResolveDaemonPathForDataDir(%q) = managed %t, error %v; want managed rejection", configured, managed, err)
		}
	}
}

func TestResolveDaemonPathForDataDirAllowsManagedProtectedCustomPath(t *testing.T) {
	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, ".prod"), []byte("systemd-managed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	custom := filepath.Join(filepath.Dir(dataDir), "protected-runtime", "custom.sock")

	got, managed, err := ResolveDaemonPathForDataDir(dataDir, custom)
	if err != nil {
		t.Fatal(err)
	}
	if !managed || got != custom {
		t.Fatalf("ResolveDaemonPathForDataDir() = %q, %t; want %q, true", got, managed, custom)
	}
}

func TestResolveLegacyStoreSocketPathUsesExactConfiguredInStorePath(t *testing.T) {
	dataDir := t.TempDir()
	custom := filepath.Join(dataDir, "run", "custom.sock")

	got, err := ResolveLegacyStoreSocketPath(dataDir, custom)
	if err != nil {
		t.Fatal(err)
	}
	if got != custom {
		t.Fatalf("ResolveLegacyStoreSocketPath() = %q, want %q", got, custom)
	}
}

func TestResolveLegacyStoreSocketPathUsesDefaultForExternalCustomPath(t *testing.T) {
	dataDir := t.TempDir()
	external := filepath.Join(filepath.Dir(dataDir), "runtime", "custom.sock")
	want := filepath.Join(dataDir, "aplane.sock")

	got, err := ResolveLegacyStoreSocketPath(dataDir, external)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("ResolveLegacyStoreSocketPath() = %q, want %q", got, want)
	}
}

func TestResolveDaemonPathForDataDirUsesManagedMarker(t *testing.T) {
	dataDir := t.TempDir()
	legacy := filepath.Join(dataDir, "aplane.sock")

	path, managed, err := ResolveDaemonPathForDataDir(dataDir, legacy)
	if err != nil {
		t.Fatal(err)
	}
	if managed || path != legacy {
		t.Fatalf("unmanaged path = %q, managed=%t; want %q, false", path, managed, legacy)
	}

	if err := os.WriteFile(filepath.Join(dataDir, ".prod"), []byte("systemd-managed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path, managed, err = ResolveDaemonPathForDataDir(dataDir, legacy)
	if err != nil {
		t.Fatal(err)
	}
	if !managed || path != SystemSocketPath {
		t.Fatalf("managed path = %q, managed=%t; want %q, true", path, managed, SystemSocketPath)
	}
}

func TestResolveClientPathExplicitAndEnvironment(t *testing.T) {
	t.Setenv(SocketPathEnv, "/env/socket")
	got, err := ResolveClientPath(ClientPathRequest{IPCPath: "/flag/socket"})
	if err != nil || got != "/flag/socket" {
		t.Fatalf("ResolveClientPath(explicit) = %q, %v", got, err)
	}
	got, err = ResolveClientPath(ClientPathRequest{})
	if err != nil || got != "/env/socket" {
		t.Fatalf("ResolveClientPath(env) = %q, %v", got, err)
	}
}

func TestResolveClientPathReadsLegacyConfig(t *testing.T) {
	t.Setenv(SocketPathEnv, "")
	dataDir := t.TempDir()
	custom := filepath.Join(dataDir, "custom.sock")
	if err := os.WriteFile(filepath.Join(dataDir, "config.yaml"), []byte("ipc_path: "+custom+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(config): %v", err)
	}
	got, err := ResolveClientPath(ClientPathRequest{DataDir: dataDir})
	if err != nil {
		t.Fatalf("ResolveClientPath() error = %v", err)
	}
	if got != custom {
		t.Fatalf("ResolveClientPath() = %q, want %q", got, custom)
	}
}

func TestResolveClientPathPrefersSelectedLocalDataDirectory(t *testing.T) {
	t.Setenv(SocketPathEnv, "")
	dataDir := t.TempDir()
	want := filepath.Join(dataDir, "aplane.sock")

	got, err := ResolveClientPath(ClientPathRequest{DataDir: dataDir})
	if err != nil {
		t.Fatalf("ResolveClientPath() error = %v", err)
	}
	if got != want {
		t.Fatalf("ResolveClientPath() = %q, want %q", got, want)
	}
}

func TestResolveClientPathExplicitDataDirectoryOutranksEnvironmentSocket(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv(SocketPathEnv, "/run/other-signer.sock")
	want := filepath.Join(dataDir, "aplane.sock")

	got, err := ResolveClientPath(ClientPathRequest{DataDir: dataDir, DataDirExplicit: true})
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("explicit data-dir resolution = %q, want %q", got, want)
	}

	got, err = ResolveClientPath(ClientPathRequest{DataDir: dataDir})
	if err != nil {
		t.Fatal(err)
	}
	if got != "/run/other-signer.sock" {
		t.Fatalf("environment-selected resolution = %q, want environment IPC override", got)
	}
}

func TestResolveClientPathMapsReadableManagedDefaultToSystemRuntime(t *testing.T) {
	t.Setenv(SocketPathEnv, "")
	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, ".prod"), []byte("systemd-managed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "config.yaml"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := ResolveClientPath(ClientPathRequest{DataDir: dataDir})
	if err != nil {
		t.Fatalf("ResolveClientPath() error = %v", err)
	}
	if got != SystemSocketPath {
		t.Fatalf("ResolveClientPath() = %q, want %q", got, SystemSocketPath)
	}
}

func TestResolveClientPathWithoutDataUsesSystemPath(t *testing.T) {
	t.Setenv(SocketPathEnv, "")
	got, err := ResolveClientPath(ClientPathRequest{})
	if err != nil {
		t.Fatalf("ResolveClientPath() error = %v", err)
	}
	if got != SystemSocketPath {
		t.Fatalf("ResolveClientPath() = %q, want %q", got, SystemSocketPath)
	}
}

func TestResolveClientPathRejectsMissingSelectedDataDirectory(t *testing.T) {
	t.Setenv(SocketPathEnv, "")
	missing := filepath.Join(t.TempDir(), "removed-local-store")

	_, err := ResolveClientPath(ClientPathRequest{DataDir: missing})
	if err == nil || !strings.Contains(err.Error(), "selected signer data directory does not exist") {
		t.Fatalf("ResolveClientPath() error = %v, want missing selected-directory diagnostic", err)
	}
}

func TestResolveClientPathRejectsPermissionDeniedCustomDataDirectory(t *testing.T) {
	t.Setenv(SocketPathEnv, "")
	parent := t.TempDir()
	dataDir := filepath.Join(parent, "custom-signer")
	if err := os.Mkdir(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o700) })

	_, err := ResolveClientPath(ClientPathRequest{DataDir: dataDir})
	if err == nil || !strings.Contains(err.Error(), "refusing to fall back") {
		t.Fatalf("ResolveClientPath() error = %v, want cross-store fallback rejection", err)
	}
	if !strings.Contains(err.Error(), "with explicit -d, pass --ipc-path") ||
		!strings.Contains(err.Error(), "pair APSIGNER_IPC_PATH with APSIGNER_DATA") {
		t.Fatalf("ResolveClientPath() error = %v, want actionable explicit and environment guidance", err)
	}
}

func TestResolveClientPathAllowsExplicitSocketForPrivateCustomDataDirectory(t *testing.T) {
	parent := t.TempDir()
	dataDir := filepath.Join(parent, "custom-signer")
	if err := os.Mkdir(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o700) })

	const socket = "/secure/custom/aplane.sock"
	got, err := ResolveClientPath(ClientPathRequest{DataDir: dataDir, IPCPath: socket})
	if err != nil || got != socket {
		t.Fatalf("ResolveClientPath(explicit) = %q, %v; want %q", got, err, socket)
	}
}

func TestPrivateDataDirectoryFallbackAllowsOnlyConventionalSystemStore(t *testing.T) {
	if _, resolved, err := privateDataDirectoryFallback(SystemDataDir, os.ErrPermission); err != nil || resolved {
		t.Fatalf("privateDataDirectoryFallback(system) = resolved %t, error %v", resolved, err)
	}
	if _, _, err := privateDataDirectoryFallback("/srv/other-signer", os.ErrPermission); err == nil {
		t.Fatal("privateDataDirectoryFallback(custom) accepted singleton runtime fallback")
	}
}

func TestValidateRuntimeDirectoryRejectsGroupWrite(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o770); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		t.Fatalf("Lstat: %v", err)
	}
	if err := validateRuntimeDirectory(dir, info); err == nil {
		t.Fatal("validateRuntimeDirectory accepted group-writable path")
	}
}

func TestValidateRuntimeDirectoryAcceptsGroupTraverse(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		t.Fatalf("Lstat: %v", err)
	}
	if err := validateRuntimeDirectory(dir, info); err != nil {
		t.Fatalf("validateRuntimeDirectory() error = %v", err)
	}
}
