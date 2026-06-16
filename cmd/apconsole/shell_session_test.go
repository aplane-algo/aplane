// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"strings"
	"testing"
)

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
