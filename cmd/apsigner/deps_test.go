// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"os/exec"
	"strings"
	"testing"
)

// TestDaemonDoesNotLinkClientStack pins the client/server layering boundary:
// the signer daemon must not transitively compile the signer HTTP client or
// client-side address book. Client submit orchestration lives in
// internal/clientsign; internal/signing stays a shared leaf.
//
// internal/cache is intentionally not asserted here: the daemon still reaches
// it through internal/signerapp/asametadata (signer-wide ASA metadata reuses
// the client cache schema), which is a separate, known coupling.
func TestDaemonDoesNotLinkClientStack(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Fatalf("go list -deps: %v", err)
	}

	forbidden := []string{
		"github.com/aplane-algo/aplane/internal/signerclient",
		"github.com/aplane-algo/aplane/internal/addressbook",
		"github.com/aplane-algo/aplane/internal/clientsign",
	}
	deps := string(out)
	for _, pkg := range forbidden {
		for _, line := range strings.Split(deps, "\n") {
			if strings.TrimSpace(line) == pkg {
				t.Errorf("cmd/apsigner transitively depends on client package %s", pkg)
			}
		}
	}
}
