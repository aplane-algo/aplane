// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/config"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestTrustLocalSignerHostKeyWritesKnownHosts(t *testing.T) {
	clientDir := t.TempDir()
	hostKeyPath := writeTestSSHHostKey(t, t.TempDir())
	stubLocalSignerHostKeyProbe(t, nil)
	if err := os.WriteFile(filepath.Join(clientDir, "config.yaml"), []byte(`
network: testnet
`), 0o600); err != nil {
		t.Fatalf("write client config: %v", err)
	}
	writeClientEndpointRegistry(t, clientDir, `
schema_version: 1
default: primary
endpoints:
  primary:
    role: signer
    url: ssh://localhost:56870
    signer_port: 11270
    identity_file: .ssh/id_ed25519
    known_hosts_path: .ssh/known_hosts
    token_file: aplane.token
`)

	notice, err := trustLocalSignerHostKey(clientDir, config.ServerConfig{
		SSH: config.SSHServerConfig{HostKeyPath: hostKeyPath},
	})
	if err != nil {
		t.Fatalf("trustLocalSignerHostKey failed: %v", err)
	}
	if !strings.Contains(notice, "[localhost]:56870") {
		t.Fatalf("notice = %q", notice)
	}

	knownHostsPath := filepath.Join(clientDir, ".ssh/known_hosts")
	data, err := os.ReadFile(knownHostsPath)
	if err != nil {
		t.Fatalf("read known_hosts: %v", err)
	}
	if !strings.Contains(string(data), "[localhost]:56870") {
		t.Fatalf("known_hosts missing localhost entry: %s", data)
	}
	if mode := fileMode(t, knownHostsPath); mode != 0o600 {
		t.Fatalf("known_hosts mode = %o, want 600", mode)
	}
}

func TestTrustLocalSignerHostKeySkipsRemoteHost(t *testing.T) {
	clientDir := t.TempDir()
	hostKeyPath := writeTestSSHHostKey(t, t.TempDir())
	probed := false
	stubLocalSignerHostKeyProbe(t, func(string, int, ssh.PublicKey) error {
		probed = true
		return nil
	})
	if err := os.WriteFile(filepath.Join(clientDir, "config.yaml"), []byte(`
network: testnet
signer_port: 11270
ssh:
  host: signer.example.com
  port: 56870
  identity_file: .ssh/id_ed25519
  known_hosts_path: .ssh/known_hosts
`), 0o600); err != nil {
		t.Fatalf("write client config: %v", err)
	}

	notice, err := trustLocalSignerHostKey(clientDir, config.ServerConfig{
		SSH: config.SSHServerConfig{HostKeyPath: hostKeyPath},
	})
	if err != nil {
		t.Fatalf("trustLocalSignerHostKey failed: %v", err)
	}
	if notice != "" {
		t.Fatalf("notice = %q, want empty", notice)
	}
	if _, err := os.Stat(filepath.Join(clientDir, ".ssh/known_hosts")); !os.IsNotExist(err) {
		t.Fatalf("known_hosts stat err = %v, want not exist", err)
	}
	if probed {
		t.Fatal("probe called for remote host")
	}
}

func TestTrustLocalSignerHostKeyDoesNotDuplicateEntry(t *testing.T) {
	clientDir := t.TempDir()
	hostKeyPath := writeTestSSHHostKey(t, t.TempDir())
	hostKey := loadTestSSHPublicKey(t, hostKeyPath)
	stubLocalSignerHostKeyProbe(t, nil)
	knownHostsPath := filepath.Join(clientDir, ".ssh/known_hosts")
	if err := os.MkdirAll(filepath.Dir(knownHostsPath), 0o700); err != nil {
		t.Fatalf("mkdir known_hosts dir: %v", err)
	}
	line := knownhosts.Line([]string{"[127.0.0.1]:56870"}, hostKey)
	if err := os.WriteFile(knownHostsPath, []byte(line+"\n"), 0o600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}
	if err := os.WriteFile(filepath.Join(clientDir, "config.yaml"), []byte(`
network: testnet
signer_port: 11270
ssh:
  host: 127.0.0.1
  port: 56870
  identity_file: .ssh/id_ed25519
  known_hosts_path: .ssh/known_hosts
`), 0o600); err != nil {
		t.Fatalf("write client config: %v", err)
	}

	notice, err := trustLocalSignerHostKey(clientDir, config.ServerConfig{
		SSH: config.SSHServerConfig{HostKeyPath: hostKeyPath},
	})
	if err != nil {
		t.Fatalf("trustLocalSignerHostKey failed: %v", err)
	}
	if notice != "" {
		t.Fatalf("notice = %q, want empty for existing entry", notice)
	}
	data, err := os.ReadFile(knownHostsPath)
	if err != nil {
		t.Fatalf("read known_hosts: %v", err)
	}
	if got := strings.Count(string(data), line); got != 1 {
		t.Fatalf("entry count = %d, want 1\n%s", got, data)
	}
}

func TestTrustLocalSignerHostKeyRejectsForwardedLoopbackEndpoint(t *testing.T) {
	clientDir := t.TempDir()
	hostKeyPath := writeTestSSHHostKey(t, t.TempDir())
	stubLocalSignerHostKeyProbe(t, func(host string, port int, _ ssh.PublicKey) error {
		if host != "127.0.0.1" || port != 56870 {
			t.Fatalf("probe target = %s:%d", host, port)
		}
		return fmt.Errorf("local signer SSH host key mismatch at 127.0.0.1:56870")
	})
	if err := os.WriteFile(filepath.Join(clientDir, "config.yaml"), []byte(`
network: testnet
signer_port: 11270
ssh:
  host: 127.0.0.1
  port: 56870
  identity_file: .ssh/id_ed25519
  known_hosts_path: .ssh/known_hosts
`), 0o600); err != nil {
		t.Fatalf("write client config: %v", err)
	}

	notice, err := trustLocalSignerHostKey(clientDir, config.ServerConfig{
		SSH: config.SSHServerConfig{HostKeyPath: hostKeyPath},
	})
	if err == nil {
		t.Fatal("trustLocalSignerHostKey error = nil, want mismatch")
	}
	if notice != "" {
		t.Fatalf("notice = %q, want empty", notice)
	}
	if _, err := os.Stat(filepath.Join(clientDir, ".ssh/known_hosts")); !os.IsNotExist(err) {
		t.Fatalf("known_hosts stat err = %v, want not exist", err)
	}
}

func writeTestSSHHostKey(t *testing.T, dir string) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	path := filepath.Join(dir, "ssh_host_key")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}
	return path
}

func loadTestSSHPublicKey(t *testing.T, path string) ssh.PublicKey {
	t.Helper()
	key, err := loadSSHPublicKeyFromPrivateKey(path)
	if err != nil {
		t.Fatalf("load host key: %v", err)
	}
	return key
}

func fileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return info.Mode().Perm()
}

func writeClientEndpointRegistry(t *testing.T, dir string, contents string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "endpoints.yaml"), []byte(strings.TrimSpace(contents)+"\n"), 0o600); err != nil {
		t.Fatalf("write endpoints: %v", err)
	}
}

func stubLocalSignerHostKeyProbe(t *testing.T, fn func(string, int, ssh.PublicKey) error) {
	t.Helper()
	prev := localSignerHostKeyProbe
	localSignerHostKeyProbe = fn
	t.Cleanup(func() {
		localSignerHostKeyProbe = prev
	})
}
