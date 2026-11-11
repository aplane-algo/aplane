// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package txnreview

import (
	"os/exec"
	"strings"
	"testing"
)

// TestDescriberStaysClientSafe pins what this package depends on. apshell
// imports it for its review of a plugin-built group, and apshell's one-line
// summaries use it too, so nothing may be added here that belongs to the
// signer alone. What the signer knows of a chain (its policy context, its
// network resolver) is handed in through View and FindingContext by the
// signer's own packages.
//
// The list is the whole of today's closure inside this repository, so any new
// dependency fails the test and has to be decided on. internal/txeffects and
// what it pulls in are there on purpose: the findings read the same effect
// definitions the bounded-account classifier does, and apshell already links
// that package.
func TestDescriberStaysClientSafe(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Fatalf("go list -deps: %v", err)
	}
	const module = "github.com/aplane-algo/aplane/"
	allowed := map[string]bool{
		"internal/txnreview": true,
		// The describer's own needs.
		"internal/asaset": true, "internal/termsafe": true,
		"internal/config": true, "internal/asa/registry": true, "internal/fsutil": true,
		// internal/txeffects and its closure.
		"internal/txeffects": true, "internal/boundedmeta": true, "internal/witness": true,
		"internal/rekeylist": true, "internal/falconparams": true, "internal/lsigresource": true,
		"internal/crypto": true, "internal/storepaths": true, "internal/productmode": true,
	}
	for _, line := range strings.Split(string(out), "\n") {
		pkg := strings.TrimSpace(line)
		if !strings.HasPrefix(pkg, module) {
			continue
		}
		if rel := strings.TrimPrefix(pkg, module); !allowed[rel] {
			t.Errorf("internal/txnreview now depends on %s; it may depend on nothing that belongs to the signer alone", rel)
		}
	}
}
