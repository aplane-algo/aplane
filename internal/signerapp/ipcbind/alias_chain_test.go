// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package ipcbind

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The alias chain is the socket path as written, symlinks and all. Each
// component is checked as what it is: a symlink by its owner alone, the
// socket's own directory by its owner and mode, and a directory above it by
// its owner and mode unless it is a trusted sticky temp root.
func TestSocketAliasChainChecksEachComponent(t *testing.T) {
	tempRoots := trustedStickyTempRoots()
	mkdir := func(t *testing.T, path string, mode os.FileMode) {
		t.Helper()
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	tests := []struct {
		name    string
		build   func(t *testing.T, root string) (socketDir string)
		wantErr string // empty: the chain is accepted
	}{
		{name: "a private directory", build: func(t *testing.T, root string) string {
			dir := filepath.Join(root, "run")
			mkdir(t, dir, 0o700)
			return dir
		}},
		{name: "a group-traversable directory", build: func(t *testing.T, root string) string {
			dir := filepath.Join(root, "run")
			mkdir(t, dir, 0o750)
			return dir
		}},
		{name: "a group-writable socket directory", build: func(t *testing.T, root string) string {
			dir := filepath.Join(root, "run")
			mkdir(t, dir, 0o770)
			return dir
		}, wantErr: "refusing IPC socket in group/other-writable directory: "},
		{name: "a world-writable socket directory", build: func(t *testing.T, root string) string {
			dir := filepath.Join(root, "run")
			mkdir(t, dir, 0o707)
			return dir
		}, wantErr: "refusing IPC socket in group/other-writable directory: "},
		{name: "a sticky world-writable socket directory", build: func(t *testing.T, root string) string {
			dir := filepath.Join(root, "run")
			mkdir(t, dir, 0o777|os.ModeSticky)
			return dir
		}, wantErr: "refusing IPC socket in group/other-writable directory: "},
		{name: "a group-writable directory above", build: func(t *testing.T, root string) string {
			dir := filepath.Join(root, "shared", "run")
			mkdir(t, dir, 0o700)
			mkdir(t, filepath.Join(root, "shared"), 0o770)
			return dir
		}, wantErr: "refusing IPC socket beneath group/other-writable directory: "},
		{name: "a sticky world-writable directory above that is no temp root", build: func(t *testing.T, root string) string {
			dir := filepath.Join(root, "shared", "run")
			mkdir(t, dir, 0o700)
			mkdir(t, filepath.Join(root, "shared"), 0o777|os.ModeSticky)
			return dir
		}, wantErr: "refusing IPC socket beneath group/other-writable directory: "},
		{name: "a symlink as the socket directory", build: func(t *testing.T, root string) string {
			mkdir(t, filepath.Join(root, "real"), 0o700)
			link := filepath.Join(root, "link")
			if err := os.Symlink(filepath.Join(root, "real"), link); err != nil {
				t.Fatal(err)
			}
			return link
		}},
		{name: "a symlink to a group-writable directory is judged as a symlink", build: func(t *testing.T, root string) string {
			mkdir(t, filepath.Join(root, "real"), 0o770)
			link := filepath.Join(root, "link")
			if err := os.Symlink(filepath.Join(root, "real"), link); err != nil {
				t.Fatal(err)
			}
			return link
		}},
		{name: "a symlink above the socket directory", build: func(t *testing.T, root string) string {
			mkdir(t, filepath.Join(root, "real", "run"), 0o700)
			link := filepath.Join(root, "link")
			if err := os.Symlink(filepath.Join(root, "real"), link); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(link, "run")
		}},
		{name: "a file as the socket directory", build: func(t *testing.T, root string) string {
			file := filepath.Join(root, "file")
			if err := os.WriteFile(file, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			return file
		}, wantErr: "refusing IPC socket path component that is not a real directory: "},
		{name: "a missing socket directory", build: func(t *testing.T, root string) string {
			return filepath.Join(root, "missing")
		}, wantErr: "failed to inspect IPC socket alias component "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The test's own directories are made under the umask, which may
			// leave them group-writable; the chain goes up through them.
			root := t.TempDir()
			for _, own := range []string{root, filepath.Dir(root)} {
				if err := os.Chmod(own, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			dir := tt.build(t, root)
			err := validateSocketAliasChain(filepath.Join(dir, "apsigner.sock"), tempRoots)
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("the chain was refused: %v", err)
			case tt.wantErr != "" && (err == nil || !strings.HasPrefix(err.Error(), tt.wantErr)):
				t.Fatalf("error = %v, want one starting %q", err, tt.wantErr)
			}
		})
	}
}
