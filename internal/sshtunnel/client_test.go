// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package sshtunnel

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestKeepaliveStopSignalStopIsConcurrentSafe(t *testing.T) {
	signal := newKeepaliveStopSignal()
	var wg sync.WaitGroup

	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			signal.stop()
		}()
	}
	wg.Wait()

	select {
	case <-signal.done():
	default:
		t.Fatal("stop signal was not closed")
	}

	signal.stop()
}

func TestSSHDialTargetUsesIPv4ForLocalhost(t *testing.T) {
	network, addr := sshDialTarget("tcp", net.JoinHostPort("localhost", "58596"))
	if got, want := network, "tcp4"; got != want {
		t.Fatalf("network = %q, want %q", got, want)
	}
	if got, want := addr, net.JoinHostPort("127.0.0.1", "58596"); got != want {
		t.Fatalf("addr = %q, want %q", got, want)
	}
}

func TestSSHDialTargetPreservesNonLocalhost(t *testing.T) {
	original := net.JoinHostPort("example.com", "58596")
	network, addr := sshDialTarget("tcp", original)
	if got, want := network, "tcp"; got != want {
		t.Fatalf("network = %q, want %q", got, want)
	}
	if got, want := addr, original; got != want {
		t.Fatalf("addr = %q, want %q", got, want)
	}
}

func TestSSHDialTargetPreservesExplicitIPv6(t *testing.T) {
	original := net.JoinHostPort("::1", "58596")
	network, addr := sshDialTarget("tcp", original)
	if got, want := network, "tcp"; got != want {
		t.Fatalf("network = %q, want %q", got, want)
	}
	if got, want := addr, original; got != want {
		t.Fatalf("addr = %q, want %q", got, want)
	}
}

func TestClientResetCloseSignalAllowsReuseAfterClose(t *testing.T) {
	client := NewClient("example.com", 22, 0, 0, "", filepath.Join(t.TempDir(), "known_hosts"))
	close(client.closeChan)

	client.mu.Lock()
	client.resetCloseSignalLocked()
	ch := client.closeChan
	client.mu.Unlock()

	select {
	case <-ch:
		t.Fatal("close signal remained closed after reset")
	default:
	}
}

func TestGenerateIdentityKeyDoesNotOverwriteExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "id_ed25519")
	original := []byte("existing key")
	if err := os.WriteFile(path, original, 0o644); err != nil {
		t.Fatalf("WriteFile(existing) error = %v", err)
	}
	client := NewClient("example.com", 22, 0, 0, path, filepath.Join(t.TempDir(), "known_hosts"))

	if _, err := client.generateIdentityKey(path); err == nil {
		t.Fatal("generateIdentityKey(existing) error = nil, want create-new failure")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(existing) error = %v", err)
	}
	if string(got) != string(original) {
		t.Fatalf("existing key overwritten: got %q, want %q", got, original)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(existing) error = %v", err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("existing key mode = %04o, want 0644 unchanged", info.Mode().Perm())
	}
}

func TestHostKeyApprovalIsPerCallback(t *testing.T) {
	knownHostsPath := filepath.Join(t.TempDir(), "known_hosts")
	client := NewClient("example.com", 22, 0, 0, "", knownHostsPath)

	calls := 0
	client.SetHostKeyApprovalHandler(func(host string, fingerprint string) (bool, error) {
		calls++
		return true, nil
	})
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("NewSignerFromKey() error = %v", err)
	}
	remote := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}

	first, err := client.hostKeyCallback()
	if err != nil {
		t.Fatalf("hostKeyCallback(first) error = %v", err)
	}
	if err := first("example.com", remote, signer.PublicKey()); err != nil {
		t.Fatalf("first host key callback error = %v", err)
	}
	if err := os.Remove(knownHostsPath); err != nil {
		t.Fatalf("Remove(known_hosts) error = %v", err)
	}

	second, err := client.hostKeyCallback()
	if err != nil {
		t.Fatalf("hostKeyCallback(second) error = %v", err)
	}
	if err := second("example.com", remote, signer.PublicKey()); err != nil {
		t.Fatalf("second host key callback error = %v", err)
	}
	if calls != 2 {
		t.Fatalf("approval calls = %d, want 2 across separate connection attempts", calls)
	}
}

func TestHostKeyCallbackReturnsTypedTrustErrors(t *testing.T) {
	_, firstPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	firstSigner, err := ssh.NewSignerFromKey(firstPrivate)
	if err != nil {
		t.Fatal(err)
	}
	_, secondPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	secondSigner, err := ssh.NewSignerFromKey(secondPrivate)
	if err != nil {
		t.Fatal(err)
	}
	remote := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}

	t.Run("unknown", func(t *testing.T) {
		client := NewClient("unknown.example", 22, 0, 0, "", filepath.Join(t.TempDir(), "known_hosts"))
		callback, err := client.hostKeyCallback()
		if err != nil {
			t.Fatal(err)
		}
		if err := callback("unknown.example:22", remote, firstSigner.PublicKey()); !errors.Is(err, ErrUnknownHostKey) {
			t.Fatalf("host callback error = %v, want ErrUnknownHostKey", err)
		}
	})

	t.Run("mismatch", func(t *testing.T) {
		client := NewClient("pinned.example", 22, 0, 0, "", filepath.Join(t.TempDir(), "known_hosts"))
		client.SetHostKeyApprovalHandler(func(string, string) (bool, error) { return true, nil })
		callback, err := client.hostKeyCallback()
		if err != nil {
			t.Fatal(err)
		}
		if err := callback("pinned.example:22", remote, firstSigner.PublicKey()); err != nil {
			t.Fatal(err)
		}
		callback, err = client.hostKeyCallback()
		if err != nil {
			t.Fatal(err)
		}
		if err := callback("pinned.example:22", remote, secondSigner.PublicKey()); !errors.Is(err, ErrHostKeyMismatch) {
			t.Fatalf("host callback error = %v, want ErrHostKeyMismatch", err)
		}
	})

	t.Run("malformed known hosts", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "known_hosts")
		if err := os.WriteFile(path, []byte("not a known-hosts record\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		client := NewClient("bad.example", 22, 0, 0, "", path)
		_, err := client.hostKeyCallback()
		if !errors.Is(err, ErrKnownHostsFile) {
			t.Fatalf("hostKeyCallback() error = %v, want ErrKnownHostsFile", err)
		}
	})
}

func TestForwardInterceptedGlobalRequestDoesNotBlockWhenFull(t *testing.T) {
	filtered := make(chan *ssh.Request, 1)
	filtered <- &ssh.Request{Type: "queued"}
	done := make(chan bool, 1)

	go func() {
		done <- forwardInterceptedGlobalRequest(context.Background(), filtered, &ssh.Request{Type: "overflow"})
	}()

	select {
	case ok := <-done:
		if !ok {
			t.Fatal("forwardInterceptedGlobalRequest() = false, want true for dropped overflow")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("forwardInterceptedGlobalRequest blocked on full channel")
	}
}
