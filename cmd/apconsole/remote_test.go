// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/aplane-algo/aplane/internal/tokenfile"
)

func TestLoadRemoteAdminConfigRequiresClientDataDir(t *testing.T) {
	t.Setenv("APCLIENT_DATA", "")

	cfg, err := loadRemoteAdminConfig("")
	if err == nil {
		t.Fatal("err = nil, want missing client data error")
	}
	if cfg != nil {
		t.Fatalf("cfg = %#v, want nil", cfg)
	}
	if !strings.Contains(err.Error(), "client data directory not specified") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadRemoteAdminConfigRequiresDefaultSignerEndpoint(t *testing.T) {
	dir := t.TempDir()

	cfg, err := loadRemoteAdminConfig(dir)
	if err == nil {
		t.Fatal("err = nil, want missing signer endpoint error")
	}
	if cfg != nil {
		t.Fatalf("cfg = %#v, want nil", cfg)
	}
	if !strings.Contains(err.Error(), "requires a default signer endpoint") {
		t.Fatalf("err = %v", err)
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

	cfg, err := loadRemoteAdminConfig(dir)
	if err == nil {
		t.Fatal("err = nil, want missing token error")
	}
	if cfg != nil {
		t.Fatalf("cfg = %#v, want nil", cfg)
	}
	if !strings.Contains(err.Error(), "requires an enrolled client token") {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(err.Error(), filepath.Join(dir, "aplane.token")) {
		t.Fatalf("err = %v, want token path", err)
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

	cfg, err := loadRemoteAdminConfig(dir)
	if err == nil {
		t.Fatal("err = nil, want missing known_hosts error")
	}
	if cfg != nil {
		t.Fatalf("cfg = %#v, want nil", cfg)
	}
	if !strings.Contains(err.Error(), "requires the signer host") {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(err.Error(), filepath.Join(dir, ".ssh/known_hosts")) {
		t.Fatalf("err = %v, want known_hosts path", err)
	}
}

func TestLoadRemoteAdminConfigBuildsSSHConnector(t *testing.T) {
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

	cfg, err := loadRemoteAdminConfig(dir)
	if err != nil {
		t.Fatalf("loadRemoteAdminConfig failed: %v", err)
	}
	if cfg.dataDir != dir {
		t.Fatalf("dataDir = %q, want %q", cfg.dataDir, dir)
	}
	if cfg.token != "test-token" {
		t.Fatalf("token = %q", cfg.token)
	}
	if cfg.connector.Host != "signer.local" {
		t.Fatalf("Host = %q", cfg.connector.Host)
	}
	if cfg.connector.Port != 2222 {
		t.Fatalf("Port = %d", cfg.connector.Port)
	}
	if want := filepath.Join(dir, "keys/operator"); cfg.connector.IdentityFile != want {
		t.Fatalf("IdentityFile = %q, want %q", cfg.connector.IdentityFile, want)
	}
	if want := filepath.Join(dir, "hosts/known_hosts"); cfg.connector.KnownHostsPath != want {
		t.Fatalf("KnownHostsPath = %q, want %q", cfg.connector.KnownHostsPath, want)
	}
	if cfg.connector.Token != "test-token" {
		t.Fatalf("connector Token = %q", cfg.connector.Token)
	}
	if cfg.connector.HostKeyApproval != nil {
		t.Fatal("HostKeyApproval != nil, want apconsole to wire it after program creation")
	}
}

func TestLoadRemoteAdminConfigUsesDefaults(t *testing.T) {
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
    token_file: aplane.token
`)
	if err := tokenfile.WriteToken(filepath.Join(dir, "aplane.token"), "test-token"); err != nil {
		t.Fatalf("write token: %v", err)
	}
	writeKnownHost(t, filepath.Join(dir, ".ssh/known_hosts"), "signer.local", 1127)

	cfg, err := loadRemoteAdminConfig(dir)
	if err != nil {
		t.Fatalf("loadRemoteAdminConfig failed: %v", err)
	}
	if cfg.connector.Port == 0 {
		t.Fatal("Port = 0, want default SSH port")
	}
	if cfg.connector.IdentityFile != filepath.Join(dir, ".ssh/id_ed25519") {
		t.Fatalf("IdentityFile = %q", cfg.connector.IdentityFile)
	}
	if cfg.connector.KnownHostsPath != filepath.Join(dir, ".ssh/known_hosts") {
		t.Fatalf("KnownHostsPath = %q", cfg.connector.KnownHostsPath)
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
