// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"testing"

	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// The signer's view differs when it is of another authorizer than apshell
// read now. A view the signer could not read has no authorizer and does not
// differ.
func TestSignerViewDiffers(t *testing.T) {
	for name, tc := range map[string]struct {
		now, seen string
		want      bool
	}{
		"the same authorizer":       {"STAGE7", "STAGE7", false},
		"an earlier authorizer":     {"STAGE7", "STAGE6", true},
		"the account not read":      {"STAGE7", "", false},
		"stage 0, the account self": {"ACCT", "ACCT", false},
	} {
		if got := signerViewDiffers(tc.now, signerapi.RotatingAccountStatus{Authorizer: tc.seen}); got != tc.want {
			t.Errorf("%s: signerViewDiffers = %v, want %v", name, got, tc.want)
		}
	}
}
