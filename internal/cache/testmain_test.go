// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package cache

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	// Several cache tests intentionally exercise the legacy cwd-relative cache
	// APIs. Run the package from a temp directory so those tests do not leave
	// cache artifacts under internal/cache/.
	tmpDir, err := os.MkdirTemp("", "cache-package-test-*")
	if err != nil {
		panic("failed to create temp cache test dir: " + err.Error())
	}
	if err := os.Chdir(tmpDir); err != nil {
		panic("failed to chdir to temp cache test dir: " + err.Error())
	}
	code := m.Run()
	_ = os.RemoveAll(tmpDir)
	os.Exit(code)
}
