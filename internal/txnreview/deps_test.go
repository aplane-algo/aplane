// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package txnreview

import (
	"os/exec"
	"strings"
	"testing"
)

// TestDescriberStaysClientSafe pins the boundary that lets one describer
// serve both sides: apshell imports this package for its review of a
// plugin-built group, so it may depend on nothing that belongs to the signer.
// What the signer knows of a chain (its policy context, its network resolver)
// is handed in through View by internal/signerapp/txdesc.
func TestDescriberStaysClientSafe(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Fatalf("go list -deps: %v", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		pkg := strings.TrimSpace(line)
		for _, forbidden := range []string{
			"github.com/aplane-algo/aplane/internal/signerapp/",
			"github.com/aplane-algo/aplane/internal/policycontext",
			"github.com/aplane-algo/aplane/internal/policy",
			"github.com/aplane-algo/aplane/internal/keystore",
		} {
			if strings.HasPrefix(pkg, forbidden) {
				t.Errorf("internal/txnreview depends on signer-side package %s", pkg)
			}
		}
	}
}
