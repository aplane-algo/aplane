// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package serverconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A config file that is missing gives the defaults. One that exists but
// cannot be read is an error, not the defaults: starting on defaults would
// drop require_memory_protection, a custom IPC path and everything else the
// file sets.
func TestUnreadableConfigIsAnErrorNotTheDefaults(t *testing.T) {
	missing := t.TempDir()
	if cfg, err := LoadServerConfig(missing); err != nil || cfg.IPCPath != DefaultServerConfig().IPCPath {
		t.Fatalf("LoadServerConfig(no file) = %+v, %v; want the defaults", cfg, err)
	}

	// A directory where the file should be cannot be read as a file, for any
	// user, root included.
	unreadable := t.TempDir()
	if err := os.Mkdir(filepath.Join(unreadable, "config.yaml"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadServerConfig(unreadable); err == nil || !strings.Contains(err.Error(), "failed to read config file") {
		t.Fatalf("LoadServerConfig(unreadable file) error = %v, want a read error", err)
	}

	if os.Geteuid() != 0 {
		denied := t.TempDir()
		path := filepath.Join(denied, "config.yaml")
		if err := os.WriteFile(path, []byte("require_memory_protection: true\n"), 0o000); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadServerConfig(denied); err == nil {
			t.Fatal("LoadServerConfig(permission denied) returned the defaults")
		}
	}
}
