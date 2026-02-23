// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package util

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadToken_SecurePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aplane.token")

	if err := os.WriteFile(path, []byte("deadbeef\n"), 0600); err != nil {
		t.Fatal(err)
	}

	token, err := ReadToken(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "deadbeef" {
		t.Fatalf("expected 'deadbeef', got %q", token)
	}
}

func TestReadToken_WarnsOnLoosePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aplane.token")

	// Write with group-readable permissions (0640)
	if err := os.WriteFile(path, []byte("deadbeef\n"), 0640); err != nil {
		t.Fatal(err)
	}

	// Capture stderr
	oldStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w

	token, readErr := ReadToken(path)

	_ = w.Close()
	os.Stderr = oldStderr

	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	stderr := string(buf[:n])
	_ = r.Close()

	if readErr != nil {
		t.Fatalf("unexpected error: %v", readErr)
	}
	if token != "deadbeef" {
		t.Fatalf("expected 'deadbeef', got %q", token)
	}

	// Should have warned about permissions
	if len(stderr) == 0 {
		t.Fatal("expected warning on stderr for loose permissions, got nothing")
	}
	if !contains(stderr, "WARNING") || !contains(stderr, "0640") || !contains(stderr, "chmod 600") {
		t.Fatalf("warning should mention WARNING, mode 0640, and chmod fix; got: %s", stderr)
	}
}

func TestReadToken_NoWarningOnSecurePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aplane.token")

	if err := os.WriteFile(path, []byte("deadbeef\n"), 0600); err != nil {
		t.Fatal(err)
	}

	// Capture stderr
	oldStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w

	_, readErr := ReadToken(path)

	_ = w.Close()
	os.Stderr = oldStderr

	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	stderr := string(buf[:n])
	_ = r.Close()

	if readErr != nil {
		t.Fatalf("unexpected error: %v", readErr)
	}
	if len(stderr) != 0 {
		t.Fatalf("expected no warning for 0600 permissions, got: %s", stderr)
	}
}

func TestReadToken_NonExistentFile(t *testing.T) {
	token, err := ReadToken("/nonexistent/path/aplane.token")
	if err != nil {
		t.Fatalf("unexpected error for missing file: %v", err)
	}
	if token != "" {
		t.Fatalf("expected empty string for missing file, got %q", token)
	}
}

func TestValidateToken(t *testing.T) {
	tests := []struct {
		name     string
		provided string
		expected string
		want     bool
	}{
		{"matching", "abc123", "abc123", true},
		{"mismatch", "abc123", "xyz789", false},
		{"empty provided", "", "abc123", false},
		{"empty expected", "abc123", "", false},
		{"both empty", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ValidateToken(tt.provided, tt.expected); got != tt.want {
				t.Errorf("ValidateToken(%q, %q) = %v, want %v", tt.provided, tt.expected, got, tt.want)
			}
		})
	}
}

func TestGenerateToken(t *testing.T) {
	token, err := GenerateToken()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 32 bytes hex-encoded = 64 characters
	if len(token) != 64 {
		t.Fatalf("expected 64-char hex token, got %d chars", len(token))
	}

	// Two generations should produce different tokens
	token2, err := GenerateToken()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token == token2 {
		t.Fatal("two generated tokens should differ")
	}
}
