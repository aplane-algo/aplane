// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestTrustLocalSignerHostKeyWritesKnownHosts(t *testing.T) {
	clientDir := t.TempDir()
	hostKeyPath := writeTestSSHHostKey(t, t.TempDir())
	stubLocalSignerHostKeyProbe(t, func(string, int, ssh.PublicKey) error { return nil })
	if err := os.WriteFile(filepath.Join(clientDir, "config.yaml"), []byte(`
network: testnet
`), 0o600); err != nil {
		t.Fatalf("write client config: %v", err)
	}
	writeClientEndpointRegistry(t, clientDir, `
schema_version: 2
endpoints:
  primary:
    role: signer
    url: ssh://localhost:56870
    identity_file: .ssh/id_ed25519
    known_hosts_path: .ssh/known_hosts
`)

	notice, err := trustLocalSignerHostKey(clientDir, testSignerConfigWithHostKey(hostKeyPath), 0)
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
`), 0o600); err != nil {
		t.Fatalf("write client config: %v", err)
	}
	writeClientEndpointRegistry(t, clientDir, `
schema_version: 2
endpoints:
  primary:
    role: signer
    url: ssh://signer.example.com:56870
    identity_file: .ssh/id_ed25519
    known_hosts_path: .ssh/known_hosts
`)

	notice, err := trustLocalSignerHostKey(clientDir, testSignerConfigWithHostKey(hostKeyPath), 0)
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
	stubLocalSignerHostKeyProbe(t, func(string, int, ssh.PublicKey) error { return nil })
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
`), 0o600); err != nil {
		t.Fatalf("write client config: %v", err)
	}
	writeClientEndpointRegistry(t, clientDir, `
schema_version: 2
endpoints:
  primary:
    role: signer
    url: ssh://127.0.0.1:56870
    identity_file: .ssh/id_ed25519
    known_hosts_path: .ssh/known_hosts
`)

	notice, err := trustLocalSignerHostKey(clientDir, testSignerConfigWithHostKey(hostKeyPath), 0)
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
`), 0o600); err != nil {
		t.Fatalf("write client config: %v", err)
	}
	writeClientEndpointRegistry(t, clientDir, `
schema_version: 2
endpoints:
  primary:
    role: signer
    url: ssh://127.0.0.1:56870
    identity_file: .ssh/id_ed25519
    known_hosts_path: .ssh/known_hosts
`)

	notice, err := trustLocalSignerHostKey(clientDir, testSignerConfigWithHostKey(hostKeyPath), 0)
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

func testSignerConfigWithHostKey(hostKeyPath string) serverconfig.ServerConfig {
	return serverconfig.ServerConfig{
		Endpoint: serverconfig.ServerEndpointConfig{
			SSH: serverconfig.SSHServerConfig{HostKeyPath: hostKeyPath},
		},
	}
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

func writeLoopbackClientConfig(t *testing.T) string {
	t.Helper()
	clientDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(clientDir, "config.yaml"), []byte("network: testnet\n"), 0o600); err != nil {
		t.Fatalf("write client config: %v", err)
	}
	writeClientEndpointRegistry(t, clientDir, `
schema_version: 2
endpoints:
  primary:
    role: signer
    url: ssh://127.0.0.1:56870
    identity_file: .ssh/id_ed25519
    known_hosts_path: .ssh/known_hosts
`)
	return clientDir
}

func refusedProbeError() error {
	return fmt.Errorf("probe local signer SSH host key at 127.0.0.1:56870: %w",
		&net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)})
}

// An invalid client config must stop the trust step before anything is
// written to known_hosts.
func TestTrustLocalSignerHostKeyRefusesInvalidClientConfigBeforeWriting(t *testing.T) {
	clientDir := t.TempDir()
	hostKeyPath := writeTestSSHHostKey(t, t.TempDir())
	if err := os.WriteFile(filepath.Join(clientDir, "config.yaml"), []byte(`
network: testnet
signer_port: 11270
ssh:
  host: 127.0.0.1
  port: 56870
`), 0o600); err != nil {
		t.Fatalf("write client config: %v", err)
	}

	notice, err := trustLocalSignerHostKey(clientDir, testSignerConfigWithHostKey(hostKeyPath), 0)
	if err == nil || !strings.Contains(err.Error(), `config field "signer_port" is unknown or no longer supported`) {
		t.Fatalf("trustLocalSignerHostKey error = %v, want an unknown field rejection", err)
	}
	if notice != "" {
		t.Fatalf("notice = %q, want empty", notice)
	}
	if _, statErr := os.Stat(filepath.Join(clientDir, ".ssh", "known_hosts")); !os.IsNotExist(statErr) {
		t.Fatalf("known_hosts stat error = %v, want not exist", statErr)
	}
}
func TestTrustLocalSignerHostKeyRetriesRefusedProbeWhileDaemonStarts(t *testing.T) {
	clientDir := writeLoopbackClientConfig(t)
	hostKeyPath := writeTestSSHHostKey(t, t.TempDir())
	calls := 0
	stubLocalSignerHostKeyProbe(t, func(string, int, ssh.PublicKey) error {
		calls++
		if calls < 3 {
			return refusedProbeError()
		}
		return nil
	})

	notice, err := trustLocalSignerHostKey(clientDir, testSignerConfigWithHostKey(hostKeyPath), 2*time.Second)
	if err != nil {
		t.Fatalf("trustLocalSignerHostKey failed: %v", err)
	}
	if calls != 3 {
		t.Fatalf("probe calls = %d, want 3", calls)
	}
	if !strings.Contains(notice, "[127.0.0.1]:56870") {
		t.Fatalf("notice = %q", notice)
	}
}

func TestTrustLocalSignerHostKeyDoesNotRetryRefusedProbeWithoutWait(t *testing.T) {
	clientDir := writeLoopbackClientConfig(t)
	hostKeyPath := writeTestSSHHostKey(t, t.TempDir())
	calls := 0
	stubLocalSignerHostKeyProbe(t, func(string, int, ssh.PublicKey) error {
		calls++
		return refusedProbeError()
	})

	if _, err := trustLocalSignerHostKey(clientDir, testSignerConfigWithHostKey(hostKeyPath), 0); !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("error = %v, want connection refused", err)
	}
	if calls != 1 {
		t.Fatalf("probe calls = %d, want 1", calls)
	}
}

func TestTrustLocalSignerHostKeyDoesNotRetryOtherProbeErrors(t *testing.T) {
	clientDir := writeLoopbackClientConfig(t)
	hostKeyPath := writeTestSSHHostKey(t, t.TempDir())
	calls := 0
	stubLocalSignerHostKeyProbe(t, func(string, int, ssh.PublicKey) error {
		calls++
		return fmt.Errorf("local signer SSH host key mismatch at 127.0.0.1:56870")
	})

	if _, err := trustLocalSignerHostKey(clientDir, testSignerConfigWithHostKey(hostKeyPath), 2*time.Second); err == nil {
		t.Fatal("trustLocalSignerHostKey error = nil, want mismatch")
	}
	if calls != 1 {
		t.Fatalf("probe calls = %d, want 1", calls)
	}
}

// The console reads the signer's private host key only to derive its public
// half, and zeroes the bytes it read once they are parsed.
func TestLoadSSHPublicKeyZeroesTheHostKeyBytes(t *testing.T) {
	path := writeTestSSHHostKey(t, t.TempDir())
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ssh.ParsePrivateKey(want)
	if err != nil {
		t.Fatal(err)
	}
	var read []byte
	prev := readSignerHostKey
	readSignerHostKey = func(name string) ([]byte, error) {
		data, err := prev(name)
		read = data
		return data, err
	}
	t.Cleanup(func() { readSignerHostKey = prev })

	key, err := loadSSHPublicKeyFromPrivateKey(path)
	if err != nil {
		t.Fatalf("load host key: %v", err)
	}
	if !bytes.Equal(key.Marshal(), parsed.PublicKey().Marshal()) {
		t.Fatal("loaded a different public key")
	}
	if len(read) == 0 || !bytes.Equal(read, make([]byte, len(read))) {
		t.Fatal("the host key bytes read were left in memory")
	}
}

func TestTrustLocalSignerHostKeyReplacesRotatedKeyAndPreservesSpecialLines(t *testing.T) {
	clientDir := writeLoopbackClientConfig(t)
	oldKeyPath := writeTestSSHHostKey(t, t.TempDir())
	newKeyPath := writeTestSSHHostKey(t, t.TempDir())
	otherKeyPath := writeTestSSHHostKey(t, t.TempDir())
	oldKey := loadTestSSHPublicKey(t, oldKeyPath)
	newKey := loadTestSSHPublicKey(t, newKeyPath)
	otherKey := loadTestSSHPublicKey(t, otherKeyPath)

	stubLocalSignerHostKeyProbe(t, func(string, int, ssh.PublicKey) error { return nil })

	addr := "[127.0.0.1]:56870"
	oldLine := knownhosts.Line([]string{addr}, oldKey)
	newLine := knownhosts.Line([]string{addr}, newKey)
	revokedLine := "@revoked " + knownhosts.Line([]string{addr}, oldKey)
	caLine := "@cert-authority " + knownhosts.Line([]string{addr}, otherKey)
	hashedLine := "|1|c2FsdA==|aGFzaA== " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(otherKey)))
	multiHostLine := knownhosts.Line([]string{addr, "localhost"}, otherKey)
	otherHostLine := knownhosts.Line([]string{"[127.0.0.1]:56871"}, otherKey)
	commentLine := "# local signer trust file"

	knownHostsPath := filepath.Join(clientDir, ".ssh", "known_hosts")
	if err := os.MkdirAll(filepath.Dir(knownHostsPath), 0o700); err != nil {
		t.Fatal(err)
	}
	initial := strings.Join([]string{
		commentLine,
		revokedLine,
		caLine,
		hashedLine,
		multiHostLine,
		oldLine,
		otherHostLine,
		"",
	}, "\n")
	if err := os.WriteFile(knownHostsPath, []byte(initial), 0o600); err != nil {
		t.Fatal(err)
	}

	notice, err := trustLocalSignerHostKey(clientDir, testSignerConfigWithHostKey(newKeyPath), 0)
	if err != nil {
		t.Fatalf("trustLocalSignerHostKey() error = %v", err)
	}
	if !strings.Contains(notice, addr) {
		t.Fatalf("notice = %q, want address %s", notice, addr)
	}
	if mode := fileMode(t, knownHostsPath); mode != 0o600 {
		t.Fatalf("known_hosts mode = %o, want 600", mode)
	}

	data, err := os.ReadFile(knownHostsPath)
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	want := strings.Join([]string{
		commentLine,
		revokedLine,
		caLine,
		hashedLine,
		multiHostLine,
		otherHostLine,
		newLine,
		"",
	}, "\n")
	if got != want {
		t.Fatalf("known_hosts mismatch:\ngot:\n%s\nwant:\n%s", got, want)
	}

	// Second call is a no-op once newLine is the sole plain entry for addr.
	notice, err = trustLocalSignerHostKey(clientDir, testSignerConfigWithHostKey(newKeyPath), 0)
	if err != nil || notice != "" {
		t.Fatalf("second trustLocalSignerHostKey() = (%q, %v), want empty no-op", notice, err)
	}
}

func TestTrustLocalSignerHostKeyRemovesStaleEntryEvenWhenCurrentKeyAlsoPresent(t *testing.T) {
	clientDir := writeLoopbackClientConfig(t)
	oldKey := loadTestSSHPublicKey(t, writeTestSSHHostKey(t, t.TempDir()))
	newKeyPath := writeTestSSHHostKey(t, t.TempDir())
	newKey := loadTestSSHPublicKey(t, newKeyPath)
	stubLocalSignerHostKeyProbe(t, func(string, int, ssh.PublicKey) error { return nil })

	addr := "[127.0.0.1]:56870"
	oldLine := knownhosts.Line([]string{addr}, oldKey)
	newLine := knownhosts.Line([]string{addr}, newKey)

	knownHostsPath := filepath.Join(clientDir, ".ssh", "known_hosts")
	if err := os.MkdirAll(filepath.Dir(knownHostsPath), 0o700); err != nil {
		t.Fatal(err)
	}
	// Simulates a file written before rotation cleanup: old and new keys both present.
	if err := os.WriteFile(knownHostsPath, []byte(oldLine+"\n"+newLine+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	notice, err := trustLocalSignerHostKey(clientDir, testSignerConfigWithHostKey(newKeyPath), 0)
	if err != nil {
		t.Fatalf("trustLocalSignerHostKey() error = %v", err)
	}
	if notice == "" {
		t.Fatal("expected rewrite notice when cleaning up stale entry beside current entry")
	}
	data, err := os.ReadFile(knownHostsPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != newLine+"\n" {
		t.Fatalf("known_hosts = %q, want sole %q", string(data), newLine+"\n")
	}
}

func TestTrustLocalSignerHostKeyAppendsNewlineWhenExistingLacksTrailingNewline(t *testing.T) {
	clientDir := writeLoopbackClientConfig(t)
	newKeyPath := writeTestSSHHostKey(t, t.TempDir())
	newKey := loadTestSSHPublicKey(t, newKeyPath)
	otherKey := loadTestSSHPublicKey(t, writeTestSSHHostKey(t, t.TempDir()))
	stubLocalSignerHostKeyProbe(t, func(string, int, ssh.PublicKey) error { return nil })

	knownHostsPath := filepath.Join(clientDir, ".ssh", "known_hosts")
	if err := os.MkdirAll(filepath.Dir(knownHostsPath), 0o700); err != nil {
		t.Fatal(err)
	}
	otherLine := knownhosts.Line([]string{"other.example.com"}, otherKey)
	if err := os.WriteFile(knownHostsPath, []byte(otherLine), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := trustLocalSignerHostKey(clientDir, testSignerConfigWithHostKey(newKeyPath), 0); err != nil {
		t.Fatalf("trustLocalSignerHostKey() error = %v", err)
	}
	data, err := os.ReadFile(knownHostsPath)
	if err != nil {
		t.Fatal(err)
	}
	want := otherLine + "\n" + knownhosts.Line([]string{"[127.0.0.1]:56870"}, newKey) + "\n"
	if string(data) != want {
		t.Fatalf("known_hosts = %q, want %q", string(data), want)
	}
}

func TestTrustLocalSignerHostKeyRefusesSymlinkKnownHosts(t *testing.T) {
	clientDir := writeLoopbackClientConfig(t)
	newKeyPath := writeTestSSHHostKey(t, t.TempDir())
	stubLocalSignerHostKeyProbe(t, func(string, int, ssh.PublicKey) error { return nil })

	sshDir := filepath.Join(clientDir, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "real_known_hosts")
	if err := os.WriteFile(target, []byte("other.example.com ssh-ed25519 AAAA\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(sshDir, "known_hosts")); err != nil {
		t.Fatal(err)
	}

	if _, err := trustLocalSignerHostKey(clientDir, testSignerConfigWithHostKey(newKeyPath), 0); err == nil {
		t.Fatal("trustLocalSignerHostKey() succeeded on symlink known_hosts, want refusal")
	}
}
