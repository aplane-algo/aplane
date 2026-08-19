// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/signerapp/unlockconfig"
)

func TestRenderHomeViewWarnsNonRootProduction(t *testing.T) {
	m := Model{
		viewState: ViewHome,
		dataDir:   "/var/lib/apsigner",
		method:    "none",
		isLocal:   false,
		isRoot:    false,
	}
	m.menuItems = m.buildMenu()

	view := m.renderHomeView()
	if !strings.Contains(view, "Systemd mode changes require root") {
		t.Fatalf("renderHomeView() missing root warning:\n%s", view)
	}
	if !strings.Contains(view, "sudo appass -d /var/lib/apsigner") {
		t.Fatalf("renderHomeView() missing sudo command:\n%s", view)
	}
}

func TestStatusHelperInfoLabelsIdentityScopedPassphraseFile(t *testing.T) {
	dataDir := t.TempDir()
	passPath := filepath.Join(dataDir, "identities", "default", "passphrase")
	if err := unlockconfig.SaveUnlockConfig(dataDir, &unlockconfig.UnlockConfig{
		PassphraseCommandArgv: []string{"/usr/local/bin/appass-file", passPath},
	}); err != nil {
		t.Fatalf("save unlock config: %v", err)
	}

	m := Model{dataDir: dataDir, method: "passfile"}
	_, _, filePath, fileLabel, _ := m.statusHelperInfo()
	if fileLabel != "Passphrase file" {
		t.Fatalf("fileLabel = %q, want identity-scoped label", fileLabel)
	}
	if filePath != passPath {
		t.Fatalf("filePath = %q, want identity-scoped path", filePath)
	}
}
