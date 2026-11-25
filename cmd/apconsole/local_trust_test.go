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
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/fsutil"
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

// apshell follows a symlinked known_hosts or .ssh, so the console updates the
// file it leads to and leaves the link in place.
func TestTrustLocalSignerHostKeyFollowsSymlinks(t *testing.T) {
	hostKeyPath := writeTestSSHHostKey(t, t.TempDir())
	const addr = "[127.0.0.1]:56870"
	line := knownhosts.Line([]string{addr}, loadTestSSHPublicKey(t, hostKeyPath)) + "\n"
	otherLine := knownhosts.Line([]string{"other.example.com"}, loadTestSSHPublicKey(t, writeTestSSHHostKey(t, t.TempDir()))) + "\n"
	staleLine := knownhosts.Line([]string{addr}, loadTestSSHPublicKey(t, writeTestSSHHostKey(t, t.TempDir()))) + "\n"

	tests := []struct {
		name string
		// linkDir links the .ssh directory; otherwise known_hosts is linked.
		linkDir bool
		// existing is the target's content, with no target when missing.
		existing   string
		missing    bool
		want       string
		wantNotice bool
	}{
		{name: "file, already pinned", existing: otherLine + line, want: otherLine + line},
		{name: "file, not pinned", existing: otherLine, want: otherLine + line, wantNotice: true},
		{name: "file, rotated", existing: staleLine + otherLine, want: otherLine + line, wantNotice: true},
		{name: "file, target missing", missing: true, want: line, wantNotice: true},
		{name: "directory, not pinned", linkDir: true, existing: otherLine, want: otherLine + line, wantNotice: true},
		{name: "directory, file missing", linkDir: true, missing: true, want: line, wantNotice: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientDir := writeLoopbackClientConfig(t)
			stubLocalSignerHostKeyProbe(t, func(string, int, ssh.PublicKey) error { return nil })
			realDir := t.TempDir()
			target := filepath.Join(realDir, "known_hosts")
			if !tt.missing {
				if err := os.WriteFile(target, []byte(tt.existing), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			link, linkTo := filepath.Join(clientDir, ".ssh"), realDir
			if !tt.linkDir {
				if err := os.Mkdir(link, 0o700); err != nil {
					t.Fatal(err)
				}
				link, linkTo = filepath.Join(link, "known_hosts"), target
			}
			if err := os.Symlink(linkTo, link); err != nil {
				t.Fatal(err)
			}

			notice, err := trustLocalSignerHostKey(clientDir, testSignerConfigWithHostKey(hostKeyPath), 0)
			if err != nil {
				t.Fatalf("trustLocalSignerHostKey() error = %v", err)
			}
			if (notice != "") != tt.wantNotice {
				t.Fatalf("notice = %q, want one: %v", notice, tt.wantNotice)
			}
			data, err := os.ReadFile(target)
			if err != nil {
				t.Fatal(err)
			}
			if string(data) != tt.want {
				t.Fatalf("target = %q, want %q", data, tt.want)
			}
			if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink == 0 {
				t.Fatalf("%s is no longer a symlink (%v, %v)", link, info, err)
			}
		})
	}
}

// A key apshell appends while the console writes lands in the file being
// replaced, and is carried over to the new one.
func TestTrustLocalSignerHostKeyKeepsAKeySavedDuringTheWrite(t *testing.T) {
	savedLine := knownhosts.Line([]string{"saved.example.com"}, loadTestSSHPublicKey(t, writeTestSSHHostKey(t, t.TempDir()))) + "\n"
	otherLine := knownhosts.Line([]string{"other.example.com"}, loadTestSSHPublicKey(t, writeTestSSHHostKey(t, t.TempDir())))
	for name, existing := range map[string]string{
		"first run":           "",
		"existing entries":    otherLine + "\n",
		"no trailing newline": otherLine,
	} {
		t.Run(name, func(t *testing.T) {
			clientDir := writeLoopbackClientConfig(t)
			hostKeyPath := writeTestSSHHostKey(t, t.TempDir())
			stubLocalSignerHostKeyProbe(t, func(string, int, ssh.PublicKey) error { return nil })
			knownHostsPath := filepath.Join(clientDir, ".ssh", "known_hosts")
			if existing != "" {
				if err := os.Mkdir(filepath.Dir(knownHostsPath), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(knownHostsPath, []byte(existing), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			fsutil.TestHook = func(op fsutil.HookOp, path string) error {
				if op == fsutil.OpRename {
					return appendKnownHosts(path, []byte(savedLine))
				}
				return nil
			}
			t.Cleanup(func() { fsutil.TestHook = nil })

			if _, err := trustLocalSignerHostKey(clientDir, testSignerConfigWithHostKey(hostKeyPath), 0); err != nil {
				t.Fatalf("trustLocalSignerHostKey() error = %v", err)
			}
			data, err := os.ReadFile(knownHostsPath)
			if err != nil {
				t.Fatal(err)
			}
			want := knownhosts.Line([]string{"[127.0.0.1]:56870"}, loadTestSSHPublicKey(t, hostKeyPath)) + "\n" + savedLine
			if existing != "" {
				want = otherLine + "\n" + want
			}
			if string(data) != want {
				t.Fatalf("known_hosts = %q, want %q", data, want)
			}
		})
	}
}

// A known_hosts that can't be read is reported and left as it was.
func TestTrustLocalSignerHostKeyReportsUnreadableKnownHosts(t *testing.T) {
	clientDir := writeLoopbackClientConfig(t)
	stubLocalSignerHostKeyProbe(t, func(string, int, ssh.PublicKey) error { return nil })
	knownHostsPath := filepath.Join(clientDir, ".ssh", "known_hosts")
	if err := os.MkdirAll(knownHostsPath, 0o700); err != nil {
		t.Fatal(err)
	}

	notice, err := trustLocalSignerHostKey(clientDir, testSignerConfigWithHostKey(writeTestSSHHostKey(t, t.TempDir())), 0)
	if err == nil || notice != "" {
		t.Fatalf("trustLocalSignerHostKey() = (%q, %v), want an error", notice, err)
	}
	if info, err := os.Stat(knownHostsPath); err != nil || !info.IsDir() {
		t.Fatalf("known_hosts was replaced: %v, %v", info, err)
	}
}

func TestUpdateKnownHostsForLoopback(t *testing.T) {
	const (
		addr  = "[localhost]:56870"
		line  = addr + " ssh-ed25519 NEW"
		stale = addr + " ssh-ed25519 OLD"
	)
	tests := []struct {
		name     string
		existing string
		want     string
		changed  bool
	}{
		{"empty", "", line + "\n", true},
		{"current line", line + "\n", "", false},
		{"current line with CRLF", line + "\r\n", "", false},
		{"current line without newline", line, "", false},
		{"duplicate current lines", line + "\n" + line + "\n", line + "\n", true},
		{"stale line with CRLF", stale + "\r\n# kept\r\n", "# kept\r\n" + line + "\n", true},
		{"stale line in another case", "[LOCALHOST]:56870 ssh-ed25519 OLD\n", line + "\n", true},
		{"stale line with a comment", stale + " old signer\n", line + "\n", true},
		{"line with no key", addr + " ssh-ed25519\n", addr + " ssh-ed25519\n" + line + "\n", true},
		{"commented-out line", "# " + stale + "\n", "# " + stale + "\n" + line + "\n", true},
		{"other port", "[localhost]:56871 ssh-ed25519 OLD\n", "[localhost]:56871 ssh-ed25519 OLD\n" + line + "\n", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, changed := updateKnownHostsForLoopback([]byte(tt.existing), addr, line)
			if changed != tt.changed || string(got) != tt.want {
				t.Fatalf("updateKnownHostsForLoopback() = (%q, %v), want (%q, %v)", got, changed, tt.want, tt.changed)
			}
		})
	}
}

// Lines the update doesn't replace can still accept a rotated-out key, so each
// is reported, whether or not the file had to change.
func TestTrustLocalSignerHostKeyWarnsOfOtherTrustedKeys(t *testing.T) {
	hostKeyPath := writeTestSSHHostKey(t, t.TempDir())
	hostKey := loadTestSSHPublicKey(t, hostKeyPath)
	oldKey := loadTestSSHPublicKey(t, writeTestSSHHostKey(t, t.TempDir()))
	keyText := func(key ssh.PublicKey) string { return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))) }
	const addr = "[127.0.0.1]:56870"

	tests := []struct {
		name string
		line string
		warn bool
	}{
		{"no brackets", "127.0.0.1:56870 " + keyText(oldKey), true},
		{"trailing comma", addr + ", " + keyText(oldKey), true},
		{"several hosts", "[localhost]:56870," + addr + " " + keyText(oldKey), true},
		{"hashed host", knownhosts.HashHostname(addr) + " " + keyText(oldKey), true},
		{"wildcard", "[127.0.0.*]:56870 " + keyText(oldKey), true},
		{"several hosts with the current key", "[localhost]:56870," + addr + " " + keyText(hostKey), false},
		{"another port", "[127.0.0.1]:56871 " + keyText(oldKey), false},
		{"another host", "other.example.com " + keyText(oldKey), false},
		{"plain line, which is replaced", addr + " " + keyText(oldKey), false},
		{"unparsable file", "other.example.com ssh-ed25519 AAAA", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientDir := writeLoopbackClientConfig(t)
			stubLocalSignerHostKeyProbe(t, func(string, int, ssh.PublicKey) error { return nil })
			knownHostsPath := filepath.Join(clientDir, ".ssh", "known_hosts")
			if err := os.Mkdir(filepath.Dir(knownHostsPath), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(knownHostsPath, []byte("# first line\n"+tt.line+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			var logs bytes.Buffer
			prev := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
			t.Cleanup(func() { slog.SetDefault(prev) })

			for _, run := range []string{"pinning run", "run with nothing to change"} {
				logs.Reset()
				if _, err := trustLocalSignerHostKey(clientDir, testSignerConfigWithHostKey(hostKeyPath), 0); err != nil {
					t.Fatalf("%s: trustLocalSignerHostKey() error = %v", run, err)
				}
				want := 0
				if tt.warn {
					want = 1
				}
				if got := strings.Count(logs.String(), knownHostsPath+" line 2 also trusts another SSH host key"); got != want {
					t.Fatalf("%s: %d warnings for line 2, want %d:\n%s", run, got, want, logs.String())
				}
				if got := strings.Count(logs.String(), "also trusts"); got != want {
					t.Fatalf("%s: %d warnings in all, want %d:\n%s", run, got, want, logs.String())
				}
			}
		})
	}
}
