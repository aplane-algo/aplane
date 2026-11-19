// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chzyer/readline"
)

// requireHistoryMode fails unless path is owner-only.
func requireHistoryMode(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%s) error = %v", path, err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("%s mode = %o, want 600", path, mode)
	}
}

// With the home directory unknown, history is off: it is never written to
// the directory apshell was started from.
func TestHistoryIsOffWithoutAHomeDirectory(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	t.Setenv("home", "")
	if path := historyFilePath(); path != "" {
		t.Fatalf("historyFilePath() = %q, want history off", path)
	}
}

// The history file is owner-only whether apconsole's session appends to it
// or readline creates or rewrites it, and a file an earlier apshell left
// readable by others is made owner-only.
func TestHistoryFileIsOwnerOnly(t *testing.T) {
	t.Run("session append", func(t *testing.T) {
		dir := t.TempDir()
		created := filepath.Join(dir, "created")
		appendHistoryFile(created, "balance @all")
		requireHistoryMode(t, created)

		earlier := filepath.Join(dir, "earlier")
		if err := os.WriteFile(earlier, []byte("send 1 algo from alice to bob\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(earlier, 0o644); err != nil {
			t.Fatal(err)
		}
		appendHistoryFile(earlier, "balance @all")
		requireHistoryMode(t, earlier)
		if got := loadHistoryFile(earlier, historyLimit); len(got) != 2 {
			t.Fatalf("history = %q, want both entries", got)
		}
	})

	newReadline := func(t *testing.T, path string) {
		t.Helper()
		rl, err := newReadlineWithPrivateHistory(&readline.Config{
			HistoryFile: path, HistoryLimit: 3,
			Stdin: io.NopCloser(strings.NewReader("")), Stdout: io.Discard, Stderr: io.Discard,
		})
		if err != nil {
			t.Fatalf("newReadlineWithPrivateHistory() error = %v", err)
		}
		// Reading to the end of the input first orders Close after
		// readline's terminal goroutine has started, which closing at once
		// races with.
		_, _ = rl.Readline()
		_ = rl.Close()
	}
	t.Run("readline creates", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "history")
		newReadline(t, path)
		requireHistoryMode(t, path)
	})
	t.Run("readline rewrites", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "history")
		if err := os.WriteFile(path, []byte("a\nb\nc\nd\ne\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		newReadline(t, path)
		requireHistoryMode(t, path)
		if got := loadHistoryFile(path, -1); len(got) != 3 {
			t.Fatalf("history = %q, want it rewritten to the last 3 entries", got)
		}
		if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
			t.Fatalf("Stat(%s.tmp) error = %v, want no temporary file left", path, err)
		}
	})
	t.Run("readline opens an earlier file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "history")
		if err := os.WriteFile(path, []byte("a\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		newReadline(t, path)
		requireHistoryMode(t, path)
		if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
			t.Fatalf("Stat(%s.tmp) error = %v, want no temporary file left", path, err)
		}
	})
}
