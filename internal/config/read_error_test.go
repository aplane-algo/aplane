// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A missing client config.yaml gives the defaults. One that exists but
// cannot be read is an error, not the defaults: the defaults allow every
// network, so falling back to them would lift the file's networks_allowed.
func TestUnreadableClientConfigIsAnErrorNotTheDefaults(t *testing.T) {
	missing := t.TempDir()
	if cfg, err := LoadConfig(missing); err != nil || len(cfg.NetworksAllowed) != 0 || cfg.Network != DefaultConfig().Network {
		t.Fatalf("LoadConfig(no file) = %+v, %v; want the defaults", cfg, err)
	}

	// A directory where the file should be cannot be read as a file, for any
	// user, root included.
	unreadable := t.TempDir()
	if err := os.Mkdir(filepath.Join(unreadable, "config.yaml"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(unreadable); err == nil || !strings.Contains(err.Error(), "failed to read config file") {
		t.Fatalf("LoadConfig(unreadable file) error = %v, want a read error", err)
	}

	if os.Geteuid() != 0 {
		denied := t.TempDir()
		path := filepath.Join(denied, "config.yaml")
		if err := os.WriteFile(path, []byte("network: testnet\nnetworks_allowed: [testnet]\n"), 0o000); err != nil {
			t.Fatal(err)
		}
		if cfg, err := LoadConfig(denied); err == nil {
			t.Fatalf("LoadConfig(permission denied) returned %+v, the defaults, which allow every network", cfg)
		}
	}
}
