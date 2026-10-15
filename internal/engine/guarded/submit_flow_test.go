// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package guarded

import (
	"testing"

	"github.com/aplane-algo/aplane/pkg/signerapi"
)

func TestCanAuthorizeOtherAccounts(t *testing.T) {
	for flow, want := range map[string]bool{
		"":                                    true,
		signerapi.SigningFlowBounded1:         true,
		signerapi.SigningFlowCosigner1:        true,
		signerapi.SigningFlowBoundedCosigner1: true,
		signerapi.SigningFlowRotating1:        false,
		"rotating2":                           false,
	} {
		if got := CanAuthorizeOtherAccounts(flow); got != want {
			t.Errorf("CanAuthorizeOtherAccounts(%q) = %v, want %v", flow, got, want)
		}
	}
}
