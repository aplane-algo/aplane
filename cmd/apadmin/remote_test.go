// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/aplane-algo/aplane/internal/tokenfile"
)

func TestFormatRemoteConnectErrorAddsBatchBootstrapHint(t *testing.T) {
	err := errors.New("SSH connection failed: unknown SSH host signer.example (key abc)")

	got := formatRemoteConnectError(err, false)
	if got == nil {
		t.Fatal("formatRemoteConnectError() = nil, want error")
	}
	if !strings.Contains(got.Error(), "requires a trusted signer host") {
		t.Fatalf("error = %q, want remote test hint", got.Error())
	}
}

func TestFormatRemoteConnectErrorAddsInteractiveBootstrapHint(t *testing.T) {
	err := errors.New("SSH connection failed: unknown SSH host signer.example (key abc)")

	got := formatRemoteConnectError(err, true)
	if got == nil {
		t.Fatal("formatRemoteConnectError() = nil, want error")
	}
	if !strings.Contains(got.Error(), "requires a trusted signer host") {
		t.Fatalf("error = %q, want bootstrap hint", got.Error())
	}
}

func TestLoadRemoteAdminConfigRequiresKnownHost(t *testing.T) {
	dir := t.TempDir()
	writeRemoteConfig(t, dir, `
network: testnet
`)
	writeRemoteEndpointRegistry(t, dir, `
schema_version: 1
default: primary
endpoints:
  primary:
    role: signer
    url: ssh://signer.local:1127
    signer_port: 11270
    identity_file: .ssh/id_ed25519
    known_hosts_path: .ssh/known_hosts
    token_file: aplane.token
`)
	if err := tokenfile.WriteToken(filepath.Join(dir, "aplane.token"), "test-token"); err != nil {
		t.Fatalf("write token: %v", err)
	}

	cfg, err := loadRemoteAdminConfig(dir, false)
	if err == nil {
		t.Fatal("err = nil, want missing known_hosts error")
	}
	if cfg != nil {
		t.Fatalf("cfg = %#v, want nil", cfg)
	}
	if !strings.Contains(err.Error(), "requires the signer host") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadRemoteAdminConfigRejectsDummyKnownHostEntry(t *testing.T) {
	dir := t.TempDir()
	writeRemoteConfig(t, dir, `
network: testnet
`)
	writeRemoteEndpointRegistry(t, dir, `
schema_version: 1
default: primary
endpoints:
  primary:
    role: signer
    url: ssh://signer.local:2222
    signer_port: 11270
    identity_file: .ssh/id_ed25519
    known_hosts_path: hosts/known_hosts
    token_file: aplane.token
`)
	if err := tokenfile.WriteToken(filepath.Join(dir, "aplane.token"), "test-token"); err != nil {
		t.Fatalf("write token: %v", err)
	}
	writeDummyKnownHost(t, filepath.Join(dir, "hosts/known_hosts"), "signer.local", 2222)

	cfg, err := loadRemoteAdminConfig(dir, false)
	if err == nil {
		t.Fatal("err = nil, want dummy known_hosts rejection")
	}
	if cfg != nil {
		t.Fatalf("cfg = %#v, want nil", cfg)
	}
	if !strings.Contains(err.Error(), "invalid placeholder key") {
		t.Fatalf("err = %v, want placeholder key rejection", err)
	}
}

func TestLoadRemoteAdminConfigRequiresToken(t *testing.T) {
	dir := t.TempDir()
	writeRemoteConfig(t, dir, `
network: testnet
`)
	writeRemoteEndpointRegistry(t, dir, `
schema_version: 1
default: primary
endpoints:
  primary:
    role: signer
    url: ssh://signer.local:1127
    signer_port: 11270
    identity_file: .ssh/id_ed25519
    known_hosts_path: .ssh/known_hosts
    token_file: aplane.token
`)

	cfg, err := loadRemoteAdminConfig(dir, false)
	if err == nil {
		t.Fatal("err = nil, want missing token error")
	}
	if cfg != nil {
		t.Fatalf("cfg = %#v, want nil", cfg)
	}
	if !strings.Contains(err.Error(), "no token configured") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadRemoteAdminConfigBuildsConnectorWithTrustedHost(t *testing.T) {
	dir := t.TempDir()
	writeRemoteConfig(t, dir, `
network: testnet
`)
	writeRemoteEndpointRegistry(t, dir, `
schema_version: 1
default: primary
endpoints:
  primary:
    role: signer
    url: ssh://signer.local:2222
    signer_port: 11270
    identity_file: keys/operator
    known_hosts_path: hosts/known_hosts
    token_file: tokens/primary.token
`)
	tokenPath := filepath.Join(dir, "tokens/primary.token")
	if err := os.MkdirAll(filepath.Dir(tokenPath), 0o700); err != nil {
		t.Fatalf("mkdir token dir: %v", err)
	}
	if err := tokenfile.WriteToken(tokenPath, "test-token"); err != nil {
		t.Fatalf("write token: %v", err)
	}
	writeKnownHost(t, filepath.Join(dir, "hosts/known_hosts"), "signer.local", 2222)

	cfg, err := loadRemoteAdminConfig(dir, true)
	if err != nil {
		t.Fatalf("loadRemoteAdminConfig failed: %v", err)
	}
	if cfg.token != "test-token" {
		t.Fatalf("token = %q, want test-token", cfg.token)
	}
	if cfg.connector.Host != "signer.local" {
		t.Fatalf("Host = %q", cfg.connector.Host)
	}
	if cfg.connector.Port != 2222 {
		t.Fatalf("Port = %d", cfg.connector.Port)
	}
	if cfg.connector.Token != "test-token" {
		t.Fatalf("connector token = %q", cfg.connector.Token)
	}
	if cfg.connector.HostKeyApproval != nil {
		t.Fatal("HostKeyApproval != nil, want no interactive approval in remote apadmin")
	}
}

func writeRemoteConfig(t *testing.T, dir string, contents string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(strings.TrimSpace(contents)+"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

func writeRemoteEndpointRegistry(t *testing.T, dir string, contents string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "endpoints.yaml"), []byte(strings.TrimSpace(contents)+"\n"), 0o600); err != nil {
		t.Fatalf("write endpoints: %v", err)
	}
}

func writeKnownHost(t *testing.T, path, host string, port int) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh public key: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir known_hosts dir: %v", err)
	}
	address := host
	if port != 22 {
		address = "[" + host + "]:" + strconv.Itoa(port)
	}
	line := knownhosts.Line([]string{address}, sshPub) + "\n"
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}
}

func writeDummyKnownHost(t *testing.T, path, host string, port int) {
	t.Helper()
	sshPub, err := dummyHostPublicKey()
	if err != nil {
		t.Fatalf("dummy host key: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir known_hosts dir: %v", err)
	}
	address := host
	if port != 22 {
		address = "[" + host + "]:" + strconv.Itoa(port)
	}
	line := knownhosts.Line([]string{address}, sshPub) + "\n"
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}
}
