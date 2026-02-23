// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package integrity

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/aplane-algo/aplane/internal/util"
)

func TestLoadChecksums(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		wantErr     error
		wantEntries int
	}{
		{
			name:        "valid single entry",
			content:     "a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd  manifest.json",
			wantEntries: 1,
		},
		{
			name: "valid multiple entries",
			content: `a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd  manifest.json
f1e2d3c4b5a6789012345678901234567890123456789012345678901234fedc  plugin`,
			wantEntries: 2,
		},
		{
			name: "with comments and blank lines",
			content: `# This is a comment
a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd  manifest.json

# Another comment
f1e2d3c4b5a6789012345678901234567890123456789012345678901234fedc  plugin
`,
			wantEntries: 2,
		},
		{
			name:    "invalid hash length",
			content: "abc123  manifest.json",
			wantErr: ErrInvalidChecksumsFormat,
		},
		{
			name:    "empty file",
			content: "",
			wantErr: ErrInvalidChecksumsFormat,
		},
		{
			name:    "only comments",
			content: "# just a comment\n# another comment",
			wantErr: ErrInvalidChecksumsFormat,
		},
		{
			name:        "single space separator",
			content:     "a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd manifest.json",
			wantEntries: 1,
		},
		{
			name:        "path with subdirectory",
			content:     "a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd  lib/helper.js",
			wantEntries: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			checksumPath := filepath.Join(tmpDir, "checksums.sha256")
			if err := os.WriteFile(checksumPath, []byte(tt.content), 0644); err != nil {
				t.Fatalf("Failed to write test file: %v", err)
			}

			cf, err := LoadChecksums(tmpDir)

			if tt.wantErr != nil {
				if err == nil {
					t.Fatalf("Expected error %v, got nil", tt.wantErr)
				}
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Expected error %v, got %v", tt.wantErr, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if len(cf.Entries) != tt.wantEntries {
				t.Errorf("Expected %d entries, got %d", tt.wantEntries, len(cf.Entries))
			}
		})
	}
}

func TestLoadChecksumsMissingFile(t *testing.T) {
	tmpDir := t.TempDir()
	_, err := LoadChecksums(tmpDir)

	if !errors.Is(err, ErrNoChecksums) {
		t.Errorf("Expected ErrNoChecksums, got %v", err)
	}
}

func TestChecksumFileFindEntry(t *testing.T) {
	cf := &ChecksumFile{
		Entries: []ChecksumEntry{
			{Hash: "abc123", Filename: "manifest.json"},
			{Hash: "def456", Filename: "./plugin"},
			{Hash: "ghi789", Filename: "lib/helper.js"},
		},
	}

	tests := []struct {
		name     string
		filename string
		wantHash string
	}{
		{"exact match", "manifest.json", "abc123"},
		{"with leading ./", "./manifest.json", "abc123"},
		{"find entry with ./", "plugin", "def456"},
		{"find entry without ./", "./plugin", "def456"},
		{"subdirectory path", "lib/helper.js", "ghi789"},
		{"not found", "nonexistent.txt", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := cf.FindEntry(tt.filename)
			if tt.wantHash == "" {
				if entry != nil {
					t.Errorf("Expected nil, got entry with hash %s", entry.Hash)
				}
				return
			}
			if entry == nil {
				t.Fatalf("Expected entry with hash %s, got nil", tt.wantHash)
			}
			if entry.Hash != tt.wantHash {
				t.Errorf("Expected hash %s, got %s", tt.wantHash, entry.Hash)
			}
		})
	}
}

func TestVerifyPlugin(t *testing.T) {
	tmpDir := t.TempDir()

	// Create manifest.json
	manifestContent := `{"name": "test-plugin", "version": "1.0.0"}`
	manifestPath := filepath.Join(tmpDir, "manifest.json")
	if err := os.WriteFile(manifestPath, []byte(manifestContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Create plugin executable
	pluginContent := []byte("#!/bin/bash\necho 'hello'")
	pluginPath := filepath.Join(tmpDir, "plugin")
	if err := os.WriteFile(pluginPath, pluginContent, 0755); err != nil {
		t.Fatal(err)
	}

	// Generate correct checksums
	content, err := GenerateChecksums(tmpDir, []string{"manifest.json", "plugin"})
	if err != nil {
		t.Fatal(err)
	}

	checksumPath := filepath.Join(tmpDir, "checksums.sha256")
	if err := os.WriteFile(checksumPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	// Test: valid verification should pass
	verifier := NewVerifier()
	err = verifier.VerifyPlugin(tmpDir, "./plugin")
	if err != nil {
		t.Errorf("Expected verification to pass, got: %v", err)
	}

	// Also test without leading ./
	err = verifier.VerifyPlugin(tmpDir, "plugin")
	if err != nil {
		t.Errorf("Expected verification to pass without ./, got: %v", err)
	}
}

func TestVerifyPluginMismatch(t *testing.T) {
	tmpDir := t.TempDir()

	// Create files
	manifestPath := filepath.Join(tmpDir, "manifest.json")
	if err := os.WriteFile(manifestPath, []byte(`{"test": true}`), 0644); err != nil {
		t.Fatal(err)
	}

	pluginPath := filepath.Join(tmpDir, "plugin")
	if err := os.WriteFile(pluginPath, []byte("original content"), 0755); err != nil {
		t.Fatal(err)
	}

	// Generate checksums
	content, err := GenerateChecksums(tmpDir, []string{"manifest.json", "plugin"})
	if err != nil {
		t.Fatal(err)
	}
	checksumPath := filepath.Join(tmpDir, "checksums.sha256")
	if err := os.WriteFile(checksumPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	// Modify the plugin file (simulating tampering)
	if err := os.WriteFile(pluginPath, []byte("MODIFIED content"), 0755); err != nil {
		t.Fatal(err)
	}

	// Verification should fail
	verifier := NewVerifier()
	err = verifier.VerifyPlugin(tmpDir, "./plugin")

	if err == nil {
		t.Error("Expected verification to fail after file modification")
	}
	if !errors.Is(err, ErrChecksumMismatch) {
		t.Errorf("Expected ErrChecksumMismatch, got %v", err)
	}
}

func TestVerifyPluginExecutableNotInChecksums(t *testing.T) {
	tmpDir := t.TempDir()

	// Create only manifest in checksums (not the executable)
	manifestPath := filepath.Join(tmpDir, "manifest.json")
	if err := os.WriteFile(manifestPath, []byte(`{}`), 0644); err != nil {
		t.Fatal(err)
	}

	pluginPath := filepath.Join(tmpDir, "plugin")
	if err := os.WriteFile(pluginPath, []byte("content"), 0755); err != nil {
		t.Fatal(err)
	}

	// Checksums only for manifest
	content, err := GenerateChecksums(tmpDir, []string{"manifest.json"})
	if err != nil {
		t.Fatal(err)
	}
	checksumPath := filepath.Join(tmpDir, "checksums.sha256")
	if err := os.WriteFile(checksumPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	verifier := NewVerifier()
	err = verifier.VerifyPlugin(tmpDir, "./plugin")

	if !errors.Is(err, ErrExecutableNotInChecksums) {
		t.Errorf("Expected ErrExecutableNotInChecksums, got %v", err)
	}
}

func TestVerifyPluginMissingFile(t *testing.T) {
	tmpDir := t.TempDir()

	// Create manifest
	manifestPath := filepath.Join(tmpDir, "manifest.json")
	if err := os.WriteFile(manifestPath, []byte(`{}`), 0644); err != nil {
		t.Fatal(err)
	}

	// Create plugin
	pluginPath := filepath.Join(tmpDir, "plugin")
	if err := os.WriteFile(pluginPath, []byte("content"), 0755); err != nil {
		t.Fatal(err)
	}

	// Generate checksums including a file that will be deleted
	content, err := GenerateChecksums(tmpDir, []string{"manifest.json", "plugin"})
	if err != nil {
		t.Fatal(err)
	}
	checksumPath := filepath.Join(tmpDir, "checksums.sha256")
	if err := os.WriteFile(checksumPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	// Delete manifest (simulating missing file)
	if err := os.Remove(manifestPath); err != nil {
		t.Fatal(err)
	}

	verifier := NewVerifier()
	err = verifier.VerifyPlugin(tmpDir, "./plugin")

	if !errors.Is(err, ErrMissingFile) {
		t.Errorf("Expected ErrMissingFile, got %v", err)
	}
}

func TestComputeSHA256(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a test file with known content
	testFile := filepath.Join(tmpDir, "test.txt")
	content := []byte("hello world")
	if err := os.WriteFile(testFile, content, 0644); err != nil {
		t.Fatal(err)
	}

	hash, err := util.ComputeSHA256(testFile)
	if err != nil {
		t.Fatalf("ComputeSHA256 failed: %v", err)
	}

	// SHA256 of "hello world" is known
	expectedHash := "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
	if hash != expectedHash {
		t.Errorf("Expected hash %s, got %s", expectedHash, hash)
	}
}

func TestGenerateChecksums(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test files
	if err := os.WriteFile(filepath.Join(tmpDir, "file1.txt"), []byte("content1"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "file2.txt"), []byte("content2"), 0644); err != nil {
		t.Fatal(err)
	}

	content, err := GenerateChecksums(tmpDir, []string{"file1.txt", "file2.txt"})
	if err != nil {
		t.Fatalf("GenerateChecksums failed: %v", err)
	}

	// Verify output contains expected structure
	if len(content) == 0 {
		t.Error("Generated content is empty")
	}

	// Should contain header comments
	if !contains(content, "# checksums.sha256") {
		t.Error("Missing header comment")
	}

	// Should contain both files
	if !contains(content, "file1.txt") {
		t.Error("Missing file1.txt entry")
	}
	if !contains(content, "file2.txt") {
		t.Error("Missing file2.txt entry")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
