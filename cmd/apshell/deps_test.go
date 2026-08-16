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

// TestClientDoesNotLinkSignerRegistration pins the client registration
// boundary: apshell registers client-safe key-type metadata only (catalogs,
// display metadata, address derivation), never signer-side machinery. Key
// generation, mnemonic handling, and signing providers live behind the
// per-family signerreg packages, which only signer binaries link.
func TestClientDoesNotLinkSignerRegistration(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Fatalf("go list -deps: %v", err)
	}

	forbidden := []string{
		"github.com/aplane-algo/aplane/internal/keygen",
		"github.com/aplane-algo/aplane/internal/mnemonic",
		"github.com/aplane-algo/aplane/internal/signing/ed25519/signerreg",
		"github.com/aplane-algo/aplane/internal/signing/falcon1024/signerreg",
		"github.com/aplane-algo/aplane/internal/signing/falcon1024/signerops",
		"github.com/aplane-algo/aplane/lsig/dsafamily/signerreg",
		"github.com/aplane-algo/aplane/lsig/signerreg",
	}
	deps := string(out)
	for _, pkg := range forbidden {
		for _, line := range strings.Split(deps, "\n") {
			if strings.TrimSpace(line) == pkg {
				t.Errorf("cmd/apshell transitively depends on signer-side registration package %s", pkg)
			}
		}
	}
}
