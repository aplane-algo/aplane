// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package guarded

import (
	"testing"

	"github.com/aplane-algo/aplane/pkg/signerapi"
)

func TestCanAuthorizeOtherAccounts(t *testing.T) {
	for flow, want := range map[string]bool{
		"":                             true,
		signerapi.SigningFlowBounded1:  true,
		signerapi.SigningFlowCosigned1: true,
		// The retired dedicated cosigned flow is unknown, so a leftover
		// account fails closed as a rekey target.
		"cosigner1":                    false,
		signerapi.SigningFlowRotating1: false,
		"rotating2":                    false,
	} {
		if got := CanAuthorizeOtherAccounts(flow); got != want {
			t.Errorf("CanAuthorizeOtherAccounts(%q) = %v, want %v", flow, got, want)
		}
	}
}
