//go:build unix

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package storeperm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestPreflightLegacyRejectsFIFO(t *testing.T) {
	root := workspaceTempDir(t)
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(root, "planted.fifo"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := PreflightLegacy(root)
	if err == nil || !strings.Contains(err.Error(), "refusing unexpected object") {
		t.Fatalf("PreflightLegacy() error = %v, want FIFO rejection", err)
	}
}
