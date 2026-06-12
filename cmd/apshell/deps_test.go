// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"os/exec"
	"strings"
	"testing"
)

// TestClientDoesNotLinkFalcon pins the client trust boundary: apshell does
// not verify component signatures, so it must not compile the Falcon
// implementation libraries (github.com/algorand/falcon is CGo, which would
// also break portable client builds). Component signatures are opaque to the
// client; they are verified by the signer during guarded assembly and,
// authoritatively, by the guarded LogicSig on-chain. Signature verification
// helpers live in internal/sentry/verify, which only signer-side code may
// import; clients use internal/sentry/canonical for group canonicalization.
func TestClientDoesNotLinkFalcon(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Fatalf("go list -deps: %v", err)
	}

	forbidden := []string{
		"github.com/algorand/falcon",
		"github.com/algorandfoundation/falcon-signatures/falcongo",
		"github.com/aplane-algo/aplane/internal/sentry/verify",
	}
	deps := string(out)
	for _, pkg := range forbidden {
		for _, line := range strings.Split(deps, "\n") {
			if strings.TrimSpace(line) == pkg {
				t.Errorf("cmd/apshell transitively depends on signature verification package %s", pkg)
			}
		}
	}
}
