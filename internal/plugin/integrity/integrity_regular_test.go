// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package integrity

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

func TestVerifyPluginRejectsSymlinkedEntry(t *testing.T) {
	outside := t.TempDir()
	secretPath := filepath.Join(outside, "id_ed25519")
	if err := os.WriteFile(secretPath, []byte("PRIVATE KEY SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}

	pluginDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(pluginDir, "manifest.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, "plugin"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secretPath, filepath.Join(pluginDir, "leak.txt")); err != nil {
		t.Fatal(err)
	}

	content, err := GenerateChecksums(pluginDir, []string{"manifest.json", "plugin"})
	if err != nil {
		t.Fatal(err)
	}
	content += strings.Repeat("a", 64) + "  leak.txt\n"
	if err := os.WriteFile(filepath.Join(pluginDir, "checksums.sha256"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	err = NewVerifier().VerifyPlugin(pluginDir, "./plugin")
	if !errors.Is(err, ErrNonRegularFile) {
		t.Fatalf("VerifyPlugin(symlink entry) error = %v, want ErrNonRegularFile", err)
	}
	if errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("VerifyPlugin(symlink entry) leaked mismatch error: %v", err)
	}
}

func TestVerifyPluginRejectsSymlinkedSubdirectory(t *testing.T) {
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "target.js"), []byte("console.log(1)"), 0o644); err != nil {
		t.Fatal(err)
	}

	pluginDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(pluginDir, "manifest.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, "plugin"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(pluginDir, "lib")); err != nil {
		t.Fatal(err)
	}

	content, err := GenerateChecksums(pluginDir, []string{"manifest.json", "plugin"})
	if err != nil {
		t.Fatal(err)
	}
	content += strings.Repeat("a", 64) + "  lib/target.js\n"
	if err := os.WriteFile(filepath.Join(pluginDir, "checksums.sha256"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	err = NewVerifier().VerifyPlugin(pluginDir, "./plugin")
	if !errors.Is(err, ErrNonRegularFile) {
		t.Fatalf("VerifyPlugin(symlink subdir) error = %v, want ErrNonRegularFile", err)
	}
}

func TestVerifyPluginAllowsRegularSubdirectoryFile(t *testing.T) {
	pluginDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(pluginDir, "manifest.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, "plugin"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(pluginDir, "lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, "lib", "helper.js"), []byte("module.exports = {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	content, err := GenerateChecksums(pluginDir, []string{"manifest.json", "plugin", "lib/helper.js"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, "checksums.sha256"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := NewVerifier().VerifyPlugin(pluginDir, "./plugin"); err != nil {
		t.Fatalf("VerifyPlugin(regular subdir file) error = %v, want nil", err)
	}
}

func TestLoadChecksumsRejectsSymlinkAndOversize(t *testing.T) {
	outside := t.TempDir()
	realChecksums := filepath.Join(outside, "checksums.sha256")
	line := strings.Repeat("a", 64) + "  manifest.json\n"
	if err := os.WriteFile(realChecksums, []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}

	symlinkDir := t.TempDir()
	if err := os.Symlink(realChecksums, filepath.Join(symlinkDir, "checksums.sha256")); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadChecksums(symlinkDir); !errors.Is(err, ErrNonRegularFile) {
		t.Fatalf("LoadChecksums(symlink) error = %v, want ErrNonRegularFile", err)
	}

	oversizeDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(oversizeDir, "checksums.sha256"), []byte(line+line), 0o644); err != nil {
		t.Fatal(err)
	}
	oldLimit := maxChecksumsFileBytes
	maxChecksumsFileBytes = int64(len(line))
	t.Cleanup(func() { maxChecksumsFileBytes = oldLimit })

	if _, err := LoadChecksums(oversizeDir); !errors.Is(err, ErrFileTooLarge) {
		t.Fatalf("LoadChecksums(oversize) error = %v, want ErrFileTooLarge", err)
	}
}

func TestVerifyPluginRejectsOversizeEntryAndFIFO(t *testing.T) {
	pluginDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(pluginDir, "manifest.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, "plugin"), []byte("0123456789abcdef"), 0o755); err != nil {
		t.Fatal(err)
	}
	content, err := GenerateChecksums(pluginDir, []string{"manifest.json", "plugin"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, "checksums.sha256"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	oldLimit := maxChecksumEntryBytes
	maxChecksumEntryBytes = 8
	t.Cleanup(func() { maxChecksumEntryBytes = oldLimit })

	if err := NewVerifier().VerifyPlugin(pluginDir, "./plugin"); !errors.Is(err, ErrFileTooLarge) {
		t.Fatalf("VerifyPlugin(oversize entry) error = %v, want ErrFileTooLarge", err)
	}
	maxChecksumEntryBytes = oldLimit

	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		fifoPath := filepath.Join(pluginDir, "pipe")
		if err := syscall.Mkfifo(fifoPath, 0o600); err != nil {
			t.Fatalf("Mkfifo() error = %v", err)
		}
		fifoContent := content + strings.Repeat("b", 64) + "  pipe\n"
		if err := os.WriteFile(filepath.Join(pluginDir, "checksums.sha256"), []byte(fifoContent), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := NewVerifier().VerifyPlugin(pluginDir, "./plugin"); !errors.Is(err, ErrNonRegularFile) {
			t.Fatalf("VerifyPlugin(fifo) error = %v, want ErrNonRegularFile", err)
		}
	}
}
