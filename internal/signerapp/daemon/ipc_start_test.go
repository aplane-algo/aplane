// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIPCServerStartRefusesLiveSocketCollision(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("Chmod(%q): %v", dir, err)
	}
	path := filepath.Join(dir, "aplane.sock")
	live, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = live.Close() }()
	before, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}

	server := NewIPCServer(path, nil)
	err = server.Start()
	if err == nil || !strings.Contains(err.Error(), "live IPC socket") {
		t.Fatalf("Start() error = %v, want live-socket refusal", err)
	}
	after, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("live socket disappeared: %v", err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("live socket was replaced")
	}

	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("original listener is no longer reachable: %v", err)
	}
	_ = conn.Close()
}

func TestIPCServerStartReplacesStaleOwnedSocket(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("Chmod(%q): %v", dir, err)
	}
	path := filepath.Join(dir, "aplane.sock")
	stale, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	unixListener, ok := stale.(*net.UnixListener)
	if !ok {
		t.Fatalf("listener type = %T, want *net.UnixListener", stale)
	}
	unixListener.SetUnlinkOnClose(false)
	if err := stale.Close(); err != nil {
		t.Fatal(err)
	}

	server := NewIPCServer(path, nil)
	if err := server.Start(); err != nil {
		t.Fatalf("Start() error = %v, want stale socket replacement", err)
	}
	defer server.Stop()
	if server.listener == nil {
		t.Fatal("listener was not started")
	}
}
