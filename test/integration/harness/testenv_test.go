// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package harness

import (
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/genstore/genstoretest"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"os"
	"path/filepath"
	"testing"
)

func TestCloneSharedTestEnvUsesOriginalSharedSource(t *testing.T) {
	sharedRoot := t.TempDir()
	sharedSigner := filepath.Join(sharedRoot, "apadmin")
	sharedClient := filepath.Join(sharedRoot, "apclient")

	sharedPaths := storepaths.NewPaths(sharedSigner)
	kr, _ := genstoretest.MintFirstAtomic(t, sharedPaths, []byte("test-passphrase"))
	kr.Zero()
	mustMkdirAll(t, filepath.Join(sharedSigner, ".ssh"))
	mustMkdirAll(t, filepath.Join(sharedClient, ".ssh"))

	mustWriteFile(t, filepath.Join(sharedSigner, "passphrase"), []byte("test-passphrase\n"), 0o600)
	mustWriteFile(t, filepath.Join(sharedSigner, "config.yaml"), []byte("endpoint:\n  signer_port: 55195\n"), 0o600)
	mustWriteFile(t, filepath.Join(sharedSigner, ".ssh", "ssh_host_key.pub"), []byte("ssh-ed25519 AAAAHOST test\n"), 0o600)
	mustWriteFile(t, filepath.Join(sharedClient, "config.yaml"), []byte("network: testnet\n"), 0o600)
	mustWriteFile(t, filepath.Join(sharedClient, "endpoints.yaml"), []byte("schema_version: 2\ndefault: primary\nendpoints:\n  primary:\n    role: signer\n    url: ssh://127.0.0.1:55295\n    signer_port: 55195\n    identity_file: .ssh/id_ed25519\n    known_hosts_path: .ssh/known_hosts\n    token_file: aplane.token\n"), 0o600)
	mustWriteFile(t, filepath.Join(sharedClient, ".ssh", "id_ed25519.pub"), []byte("ssh-ed25519 AAAATEST test\n"), 0o600)

	t.Setenv("APLANE_SHARED_APSIGNER_DATA", sharedSigner)
	t.Setenv("APLANE_SHARED_APCLIENT_DATA", sharedClient)

	first := CloneSharedTestEnv(t, TestEnvCloneOptions{})
	firstActive, firstKeyring, err := genstore.ResolveStoreRoot(
		storepaths.NewPaths(first.SignerDataDir), []byte("test-passphrase"),
	)
	if err != nil {
		t.Fatalf("ResolveStoreRoot(first clone): %v", err)
	}
	firstKeyring.Zero()
	templatePath := firstActive.KeyTypeTemplate("aplane.custom.v1")
	mustWriteFile(t, templatePath, []byte("custom template"), 0o600)

	second := CloneSharedTestEnv(t, TestEnvCloneOptions{})
	secondActive, secondKeyring, err := genstore.ResolveStoreRoot(
		storepaths.NewPaths(second.SignerDataDir), []byte("test-passphrase"),
	)
	if err != nil {
		t.Fatalf("ResolveStoreRoot(second clone): %v", err)
	}
	secondKeyring.Zero()
	if _, err := os.Stat(secondActive.KeyTypeTemplate("aplane.custom.v1")); !os.IsNotExist(err) {
		t.Fatalf("second clone unexpectedly copied template from first clone, stat err=%v", err)
	}
}

func TestSyncClonedKnownHostsAllowsMissingSignerHostKey(t *testing.T) {
	signerDataDir := t.TempDir()
	clientDataDir := t.TempDir()
	mustWriteFile(t, filepath.Join(clientDataDir, "config.yaml"), []byte("network: testnet\n"), 0o600)
	mustWriteFile(t, filepath.Join(clientDataDir, "endpoints.yaml"), []byte("schema_version: 2\ndefault: primary\nendpoints:\n  primary:\n    role: signer\n    url: ssh://127.0.0.1:55295\n    signer_port: 55195\n"), 0o600)

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
