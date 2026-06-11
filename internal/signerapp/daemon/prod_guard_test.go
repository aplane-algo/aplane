// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	signerstartup "github.com/aplane-algo/aplane/internal/signerapp/startup"
)

func TestBlockManualProdStart(t *testing.T) {
	t.Run("allows local instance without marker", func(t *testing.T) {
		dataDir := t.TempDir()
		setNoSystemdEnv(t)
		if err := signerstartup.BlockManualProdStart(dataDir); err != nil {
			t.Fatalf("BlockManualProdStart() error = %v, want nil", err)
		}
	})

	t.Run("blocks managed marker outside systemd", func(t *testing.T) {
		dataDir := t.TempDir()
		setNoSystemdEnv(t)
		writeProdMarker(t, dataDir)

		err := signerstartup.BlockManualProdStart(dataDir)
		if err == nil {
			t.Fatal("BlockManualProdStart() error = nil, want refusal")
		}
		if !strings.Contains(err.Error(), "systemctl start apsigner") {
			t.Fatalf("BlockManualProdStart() error = %q, want systemctl hint", err.Error())
		}
	})

	t.Run("allows managed marker under systemd", func(t *testing.T) {
		dataDir := t.TempDir()
		writeProdMarker(t, dataDir)
		t.Setenv("APLANE_SYSTEMD_MANAGED", "1")

		if err := signerstartup.BlockManualProdStart(dataDir); err != nil {
			t.Fatalf("BlockManualProdStart() error = %v, want nil", err)
		}
	})

}

func writeProdMarker(t *testing.T, dataDir string) {
	t.Helper()
	path := filepath.Join(dataDir, ".prod")
	if err := os.WriteFile(path, []byte("systemd-managed\n"), 0o640); err != nil {
		t.Fatalf("WriteFile(%s) error = %v", path, err)
	}
}

func setNoSystemdEnv(t *testing.T) {
	t.Helper()
	t.Setenv("APLANE_SYSTEMD_MANAGED", "")
}
