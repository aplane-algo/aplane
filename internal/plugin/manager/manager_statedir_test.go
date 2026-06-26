// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package manager

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPluginStateDir(t *testing.T) {
	tmp := t.TempDir()
	m := &Manager{dataDir: tmp}

	dir, err := m.pluginStateDir("swap-tools")
	if err != nil {
		t.Fatalf("pluginStateDir: %v", err)
	}
	want := filepath.Join(tmp, "plugin-state", "swap-tools")
	if dir != want {
		t.Fatalf("dir = %q, want %q", dir, want)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if !info.IsDir() {
		t.Fatal("state dir is not a directory")
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Fatalf("perm = %o, want 700", perm)
	}

	t.Run("empty dataDir disables persistent state", func(t *testing.T) {
		m0 := &Manager{}
		dir, err := m0.pluginStateDir("foo")
		if err != nil || dir != "" {
			t.Fatalf("want empty dir and no error; got %q, %v", dir, err)
		}
	})

	t.Run("unsafe names rejected", func(t *testing.T) {
		for _, name := range []string{"", ".", "..", "../escape", "a/b", `a\b`, "x..y"} {
			if _, err := m.pluginStateDir(name); err == nil {
				t.Errorf("name %q should be rejected", name)
			}
		}
	})
}

func TestValidPluginStateName(t *testing.T) {
	valid := []string{"swap-tools", "mithras", "a", "a_b.c", "Plugin123"}
	for _, n := range valid {
		if !validPluginStateName(n) {
			t.Errorf("%q should be valid", n)
		}
	}
	invalid := []string{"", ".", "..", "../x", "a/b", `a\b`, "x..y", "/abs"}
	for _, n := range invalid {
		if validPluginStateName(n) {
			t.Errorf("%q should be invalid", n)
		}
	}
}
