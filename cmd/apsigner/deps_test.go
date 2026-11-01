// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"os/exec"
	"strings"
	"testing"
)

// TestDaemonDoesNotLinkClientStack pins the client/server layering boundary:
// the signer daemon must not transitively compile the signer HTTP client,
// client-side address book, or client caches. Client submit orchestration
// lives in internal/clientsign; internal/signing stays a shared leaf. The
// daemon's asset metadata is its ASA set (internal/asaset), never the
// client's ASA cache, so it does not link internal/cache or internal/asa,
// whose resolver reads that cache.
func TestDaemonDoesNotLinkClientStack(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Fatalf("go list -deps: %v", err)
	}

	forbidden := []string{
		"github.com/aplane-algo/aplane/internal/signerclient",
		"github.com/aplane-algo/aplane/internal/addressbook",
		"github.com/aplane-algo/aplane/internal/clientsign",
		"github.com/aplane-algo/aplane/internal/cache",
		"github.com/aplane-algo/aplane/internal/asa",
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
