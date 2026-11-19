// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadConfiguresKeystorePathAndTimeout(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	configYAML := []byte("passphrase_timeout: 30m\nendpoint:\n  signer_port: 12345\n")
	if err := os.WriteFile(configPath, configYAML, 0600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	startup, err := Load(tmpDir)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if startup.DataDir != tmpDir {
		t.Fatalf("DataDir = %q, want %q", startup.DataDir, tmpDir)
	}
	if startup.PassphraseTimeout != 30*time.Minute {
		t.Fatalf("PassphraseTimeout = %s, want 30m", startup.PassphraseTimeout)
	}
	if startup.Paths.Root() != tmpDir {
		t.Fatalf("Paths.Root() = %q, want %q", startup.Paths.Root(), tmpDir)
	}
}

// A passphrase_timeout that does not parse stops startup; it once started
// the signer with the admin idle timeout off.
func TestLoadRefusesAnInvalidPassphraseTimeout(t *testing.T) {
	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "config.yaml"), []byte("passphrase_timeout: 15mins\n"), 0600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	startup, err := Load(tmpDir)
	if err == nil {
		t.Fatalf("Load() = %+v, want an invalid passphrase_timeout error", startup)
	}
	if !strings.Contains(err.Error(), "invalid passphrase_timeout") {
		t.Fatalf("Load() error = %v, want invalid passphrase_timeout", err)
	}
}

func TestLoadReturnsErrorWithoutDataDir(t *testing.T) {
	t.Setenv("APSIGNER_DATA", "")

	startup, err := Load("")
	if err == nil {
		t.Fatal("expected missing data dir error")
	}
	if startup != nil {
		t.Fatal("expected nil startup on missing data dir")
	}
}

func TestResolveDataDirReturnsErrorWithoutDataDir(t *testing.T) {
	t.Setenv("APSIGNER_DATA", "")

	dataDir, err := ResolveDataDir("")
	if err == nil {
		t.Fatal("expected missing data dir error")
	}
	if dataDir != "" {
		t.Fatalf("expected empty data dir, got %q", dataDir)
	}
}
