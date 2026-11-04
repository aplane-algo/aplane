// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeRemoteConfig(t *testing.T, dir, contents string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadShellConsoleRefusesUnsupportedClientEndpointConfig(t *testing.T) {
	dir := t.TempDir()
	writeRemoteConfig(t, dir, `
network: testnet
ssh:
  host: signer.local
networks:
  testnet:
    algod:
      server: http://localhost:4001
`)

	session, lines := loadShellConsole(dir, "")
	if session != nil {
		t.Fatal("session != nil, want disabled shell session")
	}
	got := strings.Join(lines, "\n")
	if !strings.Contains(got, "unsupported apclient endpoint config") {
		t.Fatalf("startup lines = %q, want unsupported endpoint config message", got)
	}
	if !strings.Contains(got, "automatic endpoint-routing migration is unsupported") {
		t.Fatalf("startup lines = %q, want endpoint-routing migration guidance", got)
	}
}
