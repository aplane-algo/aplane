// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backup

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func writeTestArchive(t *testing.T, entries int, entrySize int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.tar.gz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create archive: %v", err)
	}
	gzw := gzip.NewWriter(f)
	tw := tar.NewWriter(gzw)
	payload := make([]byte, entrySize)
	for i := 0; i < entries; i++ {
		if err := tw.WriteHeader(&tar.Header{
			Name:     fmt.Sprintf("apb/file-%05d.apb", i),
			Typeflag: tar.TypeReg,
			Mode:     0o640,
			Size:     int64(entrySize),
		}); err != nil {
			t.Fatalf("write header: %v", err)
		}
		if _, err := tw.Write(payload); err != nil {
			t.Fatalf("write payload: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gzw.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close file: %v", err)
	}
	return path
}

func TestExtractRefusesExcessiveEntryCount(t *testing.T) {
	archive := writeTestArchive(t, maxArchiveEntries+1, 1)
	if err := ExtractTarGzArchive(archive, t.TempDir()); err == nil {
		t.Fatal("extraction accepted an archive above the entry-count bound")
	}
}

func TestExtractWithinLimitsSucceeds(t *testing.T) {
	archive := writeTestArchive(t, 8, 64)
	dest := t.TempDir()
	if err := ExtractTarGzArchive(archive, dest); err != nil {
		t.Fatalf("ExtractTarGzArchive() error = %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(dest, "apb"))
	if err != nil || len(entries) != 8 {
		t.Fatalf("extracted = %d (%v), want 8", len(entries), err)
	}
}

func TestExtractRefusesSymlinkArchivePath(t *testing.T) {
	real := writeTestArchive(t, 1, 8)
	link := filepath.Join(t.TempDir(), "link.tar.gz")
	if err := os.Symlink(real, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	// Extraction opens with the same no-follow enforcement as recover.
	if err := ExtractTarGzArchive(link, t.TempDir()); err == nil {
		t.Fatal("extraction followed a symlinked archive path")
	}
}

func TestInspectSourcePolicyRejectsOversizedSnapshot(t *testing.T) {
	sourceRoot := t.TempDir()
	policyDir := filepath.Join(sourceRoot, "policy")
	if err := os.MkdirAll(policyDir, 0o750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	blob := make([]byte, maxSourcePolicyBytes+1)
	if err := os.WriteFile(filepath.Join(policyDir, "policy.yaml"), blob, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	// An oversized archive-supplied policy snapshot must be refused before
	// it is embedded in the encrypted batch manifest that every later
	// operation decrypts and parses.
	if _, _, _, err := inspectSourcePolicy(sourceRoot, "signer"); err == nil {
		t.Fatal("inspectSourcePolicy accepted an oversized policy snapshot")
	}

	// A normal-sized snapshot still inspects.
	if err := os.WriteFile(filepath.Join(policyDir, "policy.yaml"), []byte("schema_version: 1\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, _, _, err := inspectSourcePolicy(sourceRoot, "signer"); err != nil {
		t.Fatalf("inspectSourcePolicy(normal) error = %v", err)
	}
}
