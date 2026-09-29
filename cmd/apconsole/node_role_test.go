// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/noderole"
)

func TestShellPaneEnabledForNodeRole(t *testing.T) {
	if !shellPaneEnabledForNodeRole(noderole.RoleSigner) {
		t.Fatal("signer node shell pane enabled = false, want true")
	}
	if shellPaneEnabledForNodeRole(noderole.RoleCosigner) {
		t.Fatal("cosigner node shell pane enabled = true, want false")
	}
}

func TestCosignerShellDisabledLines(t *testing.T) {
	lines := cosignerShellDisabledLines([]string{"profile notice"})
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "profile notice") {
		t.Fatalf("startup lines missing profile notice:\n%s", joined)
	}
	if !strings.Contains(joined, "shell pane disabled on cosigner nodes") ||
		!strings.Contains(joined, "press p to edit cosigner policy") {
		t.Fatalf("startup lines missing cosigner shell guidance:\n%s", joined)
	}
}
