// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backup

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCreateAndExtractTarGzArchive(t *testing.T) {
	srcDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(srcDir, "apb"), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "README.md"), []byte("hello"), 0o644); err != nil {
		t.Fatalf("WriteFile(README.md) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "apb", "ADDR.apb"), []byte("payload"), 0o600); err != nil {
		t.Fatalf("WriteFile(ADDR.apb) error = %v", err)
	}

	archivePath := filepath.Join(t.TempDir(), "backup.tar.gz")
	if err := CreateTarGzArchive(srcDir, archivePath); err != nil {
		t.Fatalf("CreateTarGzArchive() error = %v", err)
	}

	destDir := t.TempDir()
	if err := ExtractTarGzArchive(archivePath, destDir); err != nil {
		t.Fatalf("ExtractTarGzArchive() error = %v", err)
	}

	readme, err := os.ReadFile(filepath.Join(destDir, "README.md"))
	if err != nil {
		t.Fatalf("ReadFile(README.md) error = %v", err)
	}
	if string(readme) != "hello" {
		t.Fatalf("README contents = %q, want %q", string(readme), "hello")
	}

	payload, err := os.ReadFile(filepath.Join(destDir, "apb", "ADDR.apb"))
	if err != nil {
		t.Fatalf("ReadFile(ADDR.apb) error = %v", err)
	}
	if string(payload) != "payload" {
		t.Fatalf("archive payload = %q, want %q", string(payload), "payload")
	}
}

func TestCreateTarGzArchiveRefusesExistingDestination(t *testing.T) {
	srcDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(srcDir, "payload.txt"), []byte("payload"), 0o600); err != nil {
		t.Fatalf("WriteFile(payload) error = %v", err)
	}
	archivePath := filepath.Join(t.TempDir(), "backup.tar.gz")
	if err := os.WriteFile(archivePath, []byte("existing"), 0o600); err != nil {
		t.Fatalf("WriteFile(existing archive) error = %v", err)
	}

	err := CreateTarGzArchive(srcDir, archivePath)
	if err == nil {
		t.Fatal("CreateTarGzArchive() error = nil, want existing destination rejection")
	}
	if !strings.Contains(err.Error(), "archive already exists") {
		t.Fatalf("CreateTarGzArchive() error = %v, want archive already exists", err)
	}
	data, readErr := os.ReadFile(archivePath)
	if readErr != nil {
		t.Fatalf("ReadFile(existing archive) error = %v", readErr)
	}
	if string(data) != "existing" {
		t.Fatalf("existing archive content = %q, want unchanged", string(data))
	}
}

func TestExtractTarGzArchiveRejectsPathTraversal(t *testing.T) {
	archivePath := filepath.Join(t.TempDir(), "bad.tar.gz")
	file, err := os.Create(archivePath)
	if err != nil {
		t.Fatalf("Create(archive) error = %v", err)
	}
	gzw := gzip.NewWriter(file)
	tw := tar.NewWriter(gzw)
	if err := tw.WriteHeader(&tar.Header{Name: "../escape.txt", Mode: 0o644, Size: int64(len("evil"))}); err != nil {
		t.Fatalf("WriteHeader() error = %v", err)
	}
	if _, err := tw.Write([]byte("evil")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar.Close() error = %v", err)
	}
	if err := gzw.Close(); err != nil {
		t.Fatalf("gzip.Close() error = %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("file.Close() error = %v", err)
	}

	err = ExtractTarGzArchive(archivePath, t.TempDir())
	if err == nil {
		t.Fatal("ExtractTarGzArchive() error = nil, want traversal rejection")
	}
	if !strings.Contains(err.Error(), "escapes destination") {
		t.Fatalf("ExtractTarGzArchive() error = %v, want traversal rejection", err)
	}
}

func TestExtractTarGzArchiveRejectsLinkEntries(t *testing.T) {
	cases := []struct {
		name     string
		typeflag byte
	}{
		{"symlink", tar.TypeSymlink},
		{"hardlink", tar.TypeLink},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			archivePath := filepath.Join(t.TempDir(), "bad.tar.gz")
			file, err := os.Create(archivePath)
			if err != nil {
				t.Fatalf("Create(archive) error = %v", err)
			}
			gzw := gzip.NewWriter(file)
			tw := tar.NewWriter(gzw)
			if err := tw.WriteHeader(&tar.Header{
				Name:     "entry",
				Typeflag: tc.typeflag,
				Linkname: "../../outside",
				Mode:     0o644,
			}); err != nil {
				t.Fatalf("WriteHeader() error = %v", err)
			}
			if err := tw.Close(); err != nil {
				t.Fatalf("tar.Close() error = %v", err)
			}
			if err := gzw.Close(); err != nil {
				t.Fatalf("gzip.Close() error = %v", err)
			}
			if err := file.Close(); err != nil {
				t.Fatalf("file.Close() error = %v", err)
			}

			err = ExtractTarGzArchive(archivePath, t.TempDir())
			if err == nil {
				t.Fatal("ExtractTarGzArchive() error = nil, want link rejection")
			}
			if !strings.Contains(err.Error(), "unsupported archive entry type") {
				t.Fatalf("ExtractTarGzArchive() error = %v, want unsupported entry type", err)
			}
		})
	}
}
