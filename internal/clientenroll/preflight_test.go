// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package clientenroll

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

func TestLoadEnrolledClientRequiresDefaultSignerEndpoint(t *testing.T) {
	dir := t.TempDir()

	got, err := LoadEnrolledClient(dir, testOptions())
	if err == nil {
		t.Fatal("err = nil, want missing signer endpoint error")
	}
	if got != nil {
		t.Fatalf("got = %#v, want nil", got)
	}
	if !strings.Contains(err.Error(), "requires a default signer endpoint") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadEnrolledClientRequiresToken(t *testing.T) {
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

	got, err := LoadEnrolledClient(dir, testOptions())
	if err == nil {
		t.Fatal("err = nil, want missing token error")
	}
	if got != nil {
		t.Fatalf("got = %#v, want nil", got)
	}
	if !strings.Contains(err.Error(), "requires an enrolled client token") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadEnrolledClientRequiresKnownHost(t *testing.T) {
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

	got, err := LoadEnrolledClient(dir, testOptions())
	if err == nil {
		t.Fatal("err = nil, want missing known_hosts error")
	}
	if got != nil {
		t.Fatalf("got = %#v, want nil", got)
	}
	if !strings.Contains(err.Error(), "requires the signer host") {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(err.Error(), filepath.Join(dir, ".ssh/known_hosts")) {
		t.Fatalf("err = %v, want known_hosts path", err)
	}
}

func TestLoadEnrolledClientRejectsDummyKnownHostEntry(t *testing.T) {
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

	got, err := LoadEnrolledClient(dir, testOptions())
	if err == nil {
		t.Fatal("err = nil, want dummy known_hosts rejection")
	}
	if got != nil {
		t.Fatalf("got = %#v, want nil", got)
	}
	if !strings.Contains(err.Error(), "invalid placeholder key") {
		t.Fatalf("err = %v, want placeholder key rejection", err)
	}
}

func TestLoadEnrolledClientRefusesUnsupportedClientEndpointConfig(t *testing.T) {
	dir := t.TempDir()
	writeRemoteConfig(t, dir, `
network: testnet
ssh:
  host: signer.local
`)

	got, err := LoadEnrolledClient(dir, testOptions())
	if err == nil {
		t.Fatal("err = nil, want unsupported endpoint config error")
	}
	if got != nil {
		t.Fatalf("got = %#v, want nil", got)
	}
	if !strings.Contains(err.Error(), "unsupported apclient endpoint config") {
		t.Fatalf("err = %v, want unsupported endpoint config message", err)
	}
}

func TestLoadEnrolledClientBuildsPrereqs(t *testing.T) {
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

	got, err := LoadEnrolledClient(dir, testOptions())
	if err != nil {
		t.Fatalf("LoadEnrolledClient failed: %v", err)
	}
	if got.DataDir != dir {
		t.Fatalf("DataDir = %q, want %q", got.DataDir, dir)
	}
	if got.Token != "test-token" {
		t.Fatalf("Token = %q, want test-token", got.Token)
	}
	if got.SSH.Host != "signer.local" {
		t.Fatalf("Host = %q", got.SSH.Host)
	}
	if got.SSH.KnownHostsPath != filepath.Join(dir, "hosts/known_hosts") {
		t.Fatalf("KnownHostsPath = %q", got.SSH.KnownHostsPath)
	}
}

func testOptions() Options {
	return Options{
		Product:              "test-surface",
		MissingSSHHint:       "run setup first",
		MissingTokenHint:     "run request-token first",
		MissingKnownHostHint: "run connect first",
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
