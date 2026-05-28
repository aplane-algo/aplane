// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package harness

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCloneSharedTestEnvUsesOriginalSharedSource(t *testing.T) {
	sharedRoot := t.TempDir()
	sharedSigner := filepath.Join(sharedRoot, "apadmin")
	sharedClient := filepath.Join(sharedRoot, "apclient")

	mustMkdirAll(t, filepath.Join(sharedSigner, "identities", "default", "keys"))
	mustMkdirAll(t, filepath.Join(sharedSigner, "identities", "default", "keytypes"))
	mustMkdirAll(t, filepath.Join(sharedSigner, ".ssh"))
	mustMkdirAll(t, filepath.Join(sharedClient, ".ssh"))

	mustWriteFile(t, filepath.Join(sharedSigner, "passphrase"), []byte("test-passphrase\n"), 0o600)
	mustWriteFile(t, filepath.Join(sharedSigner, "config.yaml"), []byte("signer_port: 55195\n"), 0o600)
	mustWriteFile(t, filepath.Join(sharedSigner, ".ssh", "ssh_host_key.pub"), []byte("ssh-ed25519 AAAAHOST test\n"), 0o600)
	mustWriteFile(t, filepath.Join(sharedClient, "config.yaml"), []byte("signer_port: 55195\nssh:\n  host: 127.0.0.1\n  port: 55295\n"), 0o600)
	mustWriteFile(t, filepath.Join(sharedClient, ".ssh", "id_ed25519.pub"), []byte("ssh-ed25519 AAAATEST test\n"), 0o600)

	t.Setenv("APLANE_SHARED_APSIGNER_DATA", sharedSigner)
	t.Setenv("APLANE_SHARED_APCLIENT_DATA", sharedClient)

	first := CloneSharedTestEnv(t, TestEnvCloneOptions{})
	templatePath := filepath.Join(first.SignerDataDir, "identities", "default", "keytypes", "aplane.custom.v1.template")
	mustWriteFile(t, templatePath, []byte("custom template"), 0o600)

	second := CloneSharedTestEnv(t, TestEnvCloneOptions{})
	if _, err := os.Stat(filepath.Join(second.SignerDataDir, "identities", "default", "keytypes", "aplane.custom.v1.template")); !os.IsNotExist(err) {
		t.Fatalf("second clone unexpectedly copied template from first clone, stat err=%v", err)
	}
}

func TestSyncClonedKnownHostsAllowsMissingSignerHostKey(t *testing.T) {
	signerDataDir := t.TempDir()
	clientDataDir := t.TempDir()
	mustWriteFile(t, filepath.Join(clientDataDir, "config.yaml"), []byte("ssh:\n  host: 127.0.0.1\n  port: 55295\n"), 0o600)

	if err := syncClonedKnownHosts(signerDataDir, clientDataDir); err != nil {
		t.Fatalf("syncClonedKnownHosts() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(clientDataDir, ".ssh", "known_hosts")); !os.IsNotExist(err) {
		t.Fatalf("known_hosts should not be created without signer host key, stat err=%v", err)
	}
}

func TestReserveTCPPortsReturnsDistinctPorts(t *testing.T) {
	ports, err := reserveTCPPorts(2)
	if err != nil {
		t.Fatalf("reserveTCPPorts() error = %v", err)
	}
	if len(ports) != 2 {
		t.Fatalf("reserveTCPPorts() returned %d ports, want 2", len(ports))
	}
	if ports[0] == ports[1] {
		t.Fatalf("reserveTCPPorts() returned duplicate port %d", ports[0])
	}
}

func mustMkdirAll(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("MkdirAll(%s) error = %v", path, err)
	}
}

func mustWriteFile(t *testing.T, path string, data []byte, perm os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, perm); err != nil {
		t.Fatalf("WriteFile(%s) error = %v", path, err)
	}
}
