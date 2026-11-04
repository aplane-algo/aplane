// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"encoding/json"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/clientlog"
)

// tamperedClientData returns a client data directory whose alias cache fails its
// integrity check, made by a real shell session.
func tamperedClientData(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeRemoteConfig(t, dir, `
network: testnet
networks:
  testnet:
    algod:
      server: http://127.0.0.1:1
      token: "x"
`)
	session, _ := loadShellConsole(dir, "testnet")
	if session == nil {
		t.Fatal("loadShellConsole() returned no session")
	}
	const zeroAddress = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"
	if _, _, err := session.ExecuteLineCaptured("alias probe " + zeroAddress); err != nil {
		t.Fatalf("alias: %v", err)
	}
	session.Shutdown()

	path := filepath.Join(dir, "cache", "alias_cache.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	var signed map[string]any
	if err := json.Unmarshal(raw, &signed); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	signed["hmac"] = strings.Repeat("0", len(signed["hmac"].(string)))
	rewritten, err := json.Marshal(signed)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if err := os.WriteFile(path, rewritten, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return dir
}

// The warning fires while the shell session loads, before any pane exists. This
// follows it through the real queue into the pane, past a flood of ordinary lines.
func TestTamperWarningReachesThePaneThroughTheFlood(t *testing.T) {
	previous := slog.Default()
	flags := log.Flags()
	t.Cleanup(func() {
		slog.SetDefault(previous)
		log.SetOutput(os.Stderr)
		log.SetFlags(flags)
	})
	dir := tamperedClientData(t)

	logs := clientlog.NewDeferred()
	clientlog.Install(slog.LevelInfo, logs)
	session, _ := loadShellConsole(dir, "testnet")
	if session == nil {
		t.Fatal("loadShellConsole() returned no session")
	}
	defer session.Shutdown()
	for range 1000 {
		slog.Info("ordinary diagnostic")
	}

	m := shellWithLogs(logs)
	var found bool
	for range 10 {
		msg := pullShellLogs(logs)()
		batch, ok := msg.(shellLogBatchMsg)
		if !ok {
			t.Fatalf("message = %#v", msg)
		}
		m, _ = m.Update(batch)
		if slices.ContainsFunc(m.lines, func(line string) bool {
			return strings.HasPrefix(line, "[cache] warning: SECURITY: alias cache may have been tampered with")
		}) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("no tamper warning in the pane: %q", m.lines)
	}
}
