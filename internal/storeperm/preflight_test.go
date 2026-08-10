// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package storeperm

import (
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestPreflightLegacyAcceptsClosedLegacyTreeWithoutMutation(t *testing.T) {
	root := workspaceTempDir(t)
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(root, "identities", "default")
	if err := os.MkdirAll(nested, 0o770); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(nested, "config.yaml")
	if err := os.WriteFile(path, []byte("legacy\n"), 0o660); err != nil {
		t.Fatal(err)
	}
	wantTime := time.Unix(1_700_000_000, 123_000_000)
	if err := os.Chtimes(path, wantTime, wantTime); err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}

	result, err := PreflightLegacy(root)
	if err != nil {
		t.Fatalf("PreflightLegacy() error = %v", err)
	}
	if result.Inspected != 4 {
		t.Fatalf("PreflightLegacy() result = %+v, want 4 inspected objects", result)
	}
	after, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "legacy\n" || after.Mode() != before.Mode() || !after.ModTime().Equal(before.ModTime()) {
		t.Fatalf("preflight mutated file: data=%q mode=%v mtime=%v; before mode=%v mtime=%v",
			data, after.Mode(), after.ModTime(), before.Mode(), before.ModTime())
	}
}

func TestPreflightLegacyAllowsSocketForLaterMigrationClassification(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix socket contract")
	}
	root := workspaceTempDir(t)
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	socketPath := filepath.Join(root, "custom.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}

	result, err := PreflightLegacy(root)
	if err != nil {
		t.Fatalf("PreflightLegacy() error = %v", err)
	}
	if result.Inspected != 2 {
		t.Fatalf("PreflightLegacy() result = %+v, want root and socket", result)
	}
	info, err := os.Lstat(socketPath)
	if err != nil || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("socket changed by preflight: info=%v err=%v", info, err)
	}
}

func TestPreflightLegacyRejectsSymlinkWithoutTouchingReferent(t *testing.T) {
	for _, relative := range []string{
		".prod",
		".apstore.lock",
		"install",
		filepath.Join("install", "service-principal.json"),
		filepath.Join("install", "uninstall.sh"),
		filepath.Join("install", "release.json"),
		"library",
		filepath.Join("identities", "default", "passphrase.cred"),
	} {
		t.Run(filepath.ToSlash(relative), func(t *testing.T) {
			root := workspaceTempDir(t)
			if err := os.Chmod(root, 0o700); err != nil {
				t.Fatal(err)
			}
			outsideDir := workspaceTempDir(t)
			outside := filepath.Join(outsideDir, "sentinel")
			if err := os.WriteFile(outside, []byte("outside\n"), 0o640); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Dir(filepath.Join(root, relative)), 0o770); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, filepath.Join(root, relative)); err != nil {
				t.Fatal(err)
			}
			before, err := os.Lstat(outside)
			if err != nil {
				t.Fatal(err)
			}

			_, err = PreflightLegacy(root)
			if err == nil || !strings.Contains(err.Error(), "refusing symlink") {
				t.Fatalf("PreflightLegacy() error = %v, want symlink rejection", err)
			}
			after, statErr := os.Lstat(outside)
			if statErr != nil {
				t.Fatal(statErr)
			}
			data, readErr := os.ReadFile(outside)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if string(data) != "outside\n" || after.Mode() != before.Mode() {
				t.Fatalf("symlink referent changed: data=%q mode=%v, want mode=%v", data, after.Mode(), before.Mode())
			}
		})
	}
}

func TestPreflightLegacyRejectsHardlinkedFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hardlink metadata contract")
	}
	root := workspaceTempDir(t)
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	original := filepath.Join(root, "config.yaml")
	if err := os.WriteFile(original, []byte("config\n"), 0o660); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(original, filepath.Join(root, "config-copy.yaml")); err != nil {
		t.Fatal(err)
	}

	_, err := PreflightLegacy(root)
	if err == nil || !strings.Contains(err.Error(), "refusing hardlinked file") {
		t.Fatalf("PreflightLegacy() error = %v, want hardlink rejection", err)
	}
}

func TestPreflightLegacyRequiresClosedRealRoot(t *testing.T) {
	root := workspaceTempDir(t)
	if err := os.Chmod(root, 0o770); err != nil {
		t.Fatal(err)
	}
	if _, err := PreflightLegacy(root); err == nil || !strings.Contains(err.Error(), "closed to group and other") {
		t.Fatalf("PreflightLegacy(group-accessible root) error = %v", err)
	}

	parent := workspaceTempDir(t)
	link := filepath.Join(parent, "store")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	if _, err := PreflightLegacy(link); err == nil || !strings.Contains(err.Error(), "not a real directory") {
		t.Fatalf("PreflightLegacy(symlink root) error = %v", err)
	}
}
