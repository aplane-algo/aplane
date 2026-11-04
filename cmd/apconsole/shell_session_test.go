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

func TestShellPaneWriterDeliversLineWithoutNewline(t *testing.T) {
	var got []string
	w := shellPaneWriter(func(line string) { got = append(got, line) })

	input := "[mithras stderr]: hello\r\n"
	n, err := w.Write([]byte(input))
	if err != nil || n != len(input) {
		t.Fatalf("Write() = %d, %v, want %d, nil", n, err, len(input))
	}
	if len(got) != 1 || got[0] != "[mithras stderr]: hello" {
		t.Fatalf("lines = %q", got)
	}
}

func TestShellPaneShowsPluginStderrLine(t *testing.T) {
	m := newShellModel(nil, []string{"Ready."})

	w := shellPaneWriter(func(line string) {
		m, _ = m.Update(shellProgressLineMsg{text: line})
	})
	if _, err := w.Write([]byte("[mithras stderr]: hello\n")); err != nil {
		t.Fatal(err)
	}
	if last := m.lines[len(m.lines)-1]; last != "[mithras stderr]: hello" {
		t.Fatalf("last pane line = %q", last)
	}
}
