// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rest

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/noderole"
	signersigning "github.com/aplane-algo/aplane/internal/signerapp/signing"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// A cosigner component signs only on a cosigner node; a bounded-base
// component only on a signer.
func TestComponentTargetNodeRole(t *testing.T) {
	cases := []struct {
		role    noderole.Role
		kind    signerapi.ComponentTargetKind
		wantErr string
	}{
		{noderole.RoleCosigner, signerapi.ComponentTargetKindCosigner, ""},
		{noderole.RoleSigner, signerapi.ComponentTargetKindCosigner, `node role "signer" does not allow cosigner component signing`},
		{noderole.RoleSigner, signerapi.ComponentTargetKindBoundedBase, ""},
		{noderole.RoleCosigner, signerapi.ComponentTargetKindBoundedBase, `node role "cosigner" does not allow account component signing`},
		{noderole.RoleCosigner, "unknown", `unsupported component target kind "unknown"`},
	}
	for _, tc := range cases {
		t.Run(string(tc.role)+"/"+string(tc.kind), func(t *testing.T) {
			err := requireComponentTargetNodeRole(setupProductRuntimeWithRole(t, true, tc.role), tc.kind)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("err = %v, want none", err)
				}
				return
			}
			if err == nil || err.Kind != signersigning.ErrorForbidden || err.Message != tc.wantErr {
				t.Fatalf("err = %#v, want forbidden %q", err, tc.wantErr)
			}
		})
	}
}
