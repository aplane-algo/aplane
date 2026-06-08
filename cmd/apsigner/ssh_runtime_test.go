// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"path/filepath"
	"testing"

	"github.com/aplane-algo/aplane/internal/auth"
	apconfig "github.com/aplane-algo/aplane/internal/config"
)

func TestRestartSSHListenerRebindsRuntime(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	cfg := server.ConfigSnapshot()
	cfg.SSH.ListenAddress = "localhost"
	cfg.SSH.Port = 0
	cfg.SSH.HostKeyPath = filepath.Join(server.dataDir, ".ssh", "ssh_host_key")
	cfg.SSH.AuthorizedKeysPath = filepath.Join(server.dataDir, ".ssh", "authorized_keys")
	server.config = &cfg

	rt, err := startSSHRuntime(
		server,
		cfg.SSH.ListenAddress,
		cfg.SSH.Port,
		cfg.SSH.HostKeyPath,
		cfg.SSH.AuthorizedKeysPath,
		server.keyPaths.Root(),
		auth.CurrentProductIdentityID(),
		nil,
	)
	if err != nil {
		t.Fatalf("startSSHRuntime() error = %v", err)
	}
	server.setSSHRuntime(rt)
	t.Cleanup(func() {
		if err := server.stopSSHRuntime(); err != nil {
			t.Fatalf("stopSSHRuntime() error = %v", err)
		}
	})

	oldServer := server.currentSSHServer()
	if oldServer == nil {
		t.Fatal("currentSSHServer() = nil after start")
	}

	if err := server.RestartSSHListener(apconfig.DefaultSSHListenAddress); err != nil {
		t.Fatalf("RestartSSHListener() error = %v", err)
	}
	newServer := server.currentSSHServer()
	if newServer == nil {
		t.Fatal("currentSSHServer() = nil after restart")
	}
	if newServer == oldServer {
		t.Fatal("currentSSHServer() reused old server after restart")
	}
}
