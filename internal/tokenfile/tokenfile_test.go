// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tokenfile

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestReadTokenSecurePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aplane.token")

	if err := os.WriteFile(path, []byte("deadbeef\n"), 0o600); err != nil {
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

func TestReadTokenRejectsLoosePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aplane.token")

	if err := os.WriteFile(path, []byte("deadbeef\n"), 0o664); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o664); err != nil {
		t.Fatal(err)
	}

	token, readErr := ReadToken(path)
	if readErr == nil {
		t.Fatal("ReadToken() error = nil, want insecure mode error")
	}
	if token != "" {
		t.Fatalf("token = %q, want empty on insecure permissions", token)
	}
	if !strings.Contains(readErr.Error(), "insecure mode 0664") || !strings.Contains(readErr.Error(), "chmod 600") {
		t.Fatalf("error should mention insecure mode 0664 and chmod fix; got: %v", readErr)
	}
}

func TestReadTokenNoErrorOnSecurePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aplane.token")

	if err := os.WriteFile(path, []byte("deadbeef\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, readErr := ReadToken(path)
	if readErr != nil {
		t.Fatalf("unexpected error: %v", readErr)
	}
}

func TestWriteTokenWritesOwnerOnlyPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aplane.token")

	if err := WriteToken(path, "deadbeef"); err != nil {
		t.Fatalf("WriteToken() error = %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("token mode = %04o, want 0600", got)
	}

	token, err := ReadToken(path)
	if err != nil {
		t.Fatalf("ReadToken() error = %v", err)
	}
	if token != "deadbeef" {
		t.Fatalf("token = %q, want deadbeef", token)
	}
}

func TestReadTokenNonExistentFile(t *testing.T) {
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
		{name: "matching", provided: "abc123", expected: "abc123", want: true},
		{name: "mismatch", provided: "abc123", expected: "xyz789", want: false},
		{name: "empty provided", provided: "", expected: "abc123", want: false},
		{name: "empty expected", provided: "abc123", expected: "", want: false},
		{name: "both empty", provided: "", expected: "", want: false},
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
	if len(token) != 64 {
		t.Fatalf("expected 64-char hex token, got %d chars", len(token))
	}

	token2, err := GenerateToken()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token == token2 {
		t.Fatal("two generated tokens should differ")
	}
}

func TestLoadAPlaneTokenConcurrentBootstrapUsesSingleToken(t *testing.T) {
	root := t.TempDir()
	const workers = 32

	start := make(chan struct{})
	tokens := make([]string, workers)
	errs := make([]error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			tokens[i], errs[i] = LoadAPlaneToken(root, "alice")
		}(i)
	}

	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("worker %d LoadAPlaneToken() error = %v", i, err)
		}
	}
	for i := 1; i < workers; i++ {
		if tokens[i] != tokens[0] {
			t.Fatalf("worker %d token differs from worker 0", i)
		}
	}
	tokenPath := GetAPlaneTokenPathForRoot(root, "alice")
	diskToken, err := ReadToken(tokenPath)
	if err != nil {
		t.Fatalf("ReadToken() error = %v", err)
	}
	if diskToken != tokens[0] {
		t.Fatalf("disk token = %q, want returned token %q", diskToken, tokens[0])
	}
}

func TestWriteTokenIfAbsentDoesNotOverwriteExistingToken(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aplane.token")
	if err := WriteToken(path, "existing"); err != nil {
		t.Fatalf("WriteToken() error = %v", err)
	}

	created, err := writeTokenIfAbsent(path, "new")
	if err != nil {
		t.Fatalf("writeTokenIfAbsent() error = %v", err)
	}
	if created {
		t.Fatal("writeTokenIfAbsent() created = true, want existing token preserved")
	}
	token, err := ReadToken(path)
	if err != nil {
		t.Fatalf("ReadToken() error = %v", err)
	}
	if token != "existing" {
		t.Fatalf("token = %q, want existing", token)
	}
}
