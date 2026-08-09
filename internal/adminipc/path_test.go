// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminipc

import (
	"os"
	"path/filepath"
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
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := ResolveDaemonPath(dataDir, test.configured, test.managed); got != test.want {
				t.Fatalf("ResolveDaemonPath() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestResolveClientPathExplicitAndEnvironment(t *testing.T) {
	t.Setenv(SocketPathEnv, "/env/socket")
	got, err := ResolveClientPath("", "/flag/socket")
	if err != nil || got != "/flag/socket" {
		t.Fatalf("ResolveClientPath(explicit) = %q, %v", got, err)
	}
	got, err = ResolveClientPath("", "")
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
	got, err := ResolveClientPath(dataDir, "")
	if err != nil {
		t.Fatalf("ResolveClientPath() error = %v", err)
	}
	if got != custom {
		t.Fatalf("ResolveClientPath() = %q, want %q", got, custom)
	}
}

func TestResolveClientPathWithoutDataUsesSystemPath(t *testing.T) {
	t.Setenv(SocketPathEnv, "")
	got, err := ResolveClientPath("", "")
	if err != nil {
		t.Fatalf("ResolveClientPath() error = %v", err)
	}
	if got != SystemSocketPath {
		t.Fatalf("ResolveClientPath() = %q, want %q", got, SystemSocketPath)
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
