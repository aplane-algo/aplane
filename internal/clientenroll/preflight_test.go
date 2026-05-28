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

func TestLoadEnrolledClientRequiresSSHConfig(t *testing.T) {
	dir := t.TempDir()

	got, err := LoadEnrolledClient(dir, testOptions())
	if err == nil {
		t.Fatal("err = nil, want missing ssh config error")
	}
	if got != nil {
		t.Fatalf("got = %#v, want nil", got)
	}
	if !strings.Contains(err.Error(), "requires ssh configuration") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadEnrolledClientRequiresToken(t *testing.T) {
	dir := t.TempDir()
	writeRemoteConfig(t, dir, `
network: testnet
ssh:
  host: signer.local
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
ssh:
  host: signer.local
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
ssh:
  host: signer.local
  port: 2222
  known_hosts_path: hosts/known_hosts
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

func TestLoadEnrolledClientBuildsPrereqs(t *testing.T) {
	dir := t.TempDir()
	writeRemoteConfig(t, dir, `
network: testnet
ssh:
  host: signer.local
  port: 2222
  identity_file: keys/operator
  known_hosts_path: hosts/known_hosts
`)
	if err := tokenfile.WriteToken(filepath.Join(dir, "aplane.token"), "test-token"); err != nil {
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
	if got.Config.SSH.Host != "signer.local" {
		t.Fatalf("Host = %q", got.Config.SSH.Host)
	}
	if got.Config.SSH.KnownHostsPath != filepath.Join(dir, "hosts/known_hosts") {
		t.Fatalf("KnownHostsPath = %q", got.Config.SSH.KnownHostsPath)
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
