// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/boundary"
)

// The local summary describes every rekey setting the plain hosts take, a
// refused one and a timelock beside any setting included, and claims no refusal
// the signer no longer makes.
func TestBoundaryPreviewDescribesEveryRekeySetting(t *testing.T) {
	for _, test := range []struct {
		name    string
		preview apshellapp.BoundaryPreview
		want    []string
	}{
		{"no bounds, refused", apshellapp.BoundaryPreview{NoBounds: true, Rekey: boundary.RekeyRefused},
			[]string{"Bounds:     none", "never be rekeyed, but can still spend and close"}},
		{"bounded, refused", apshellapp.BoundaryPreview{Transfers: []string{"pay"}, AnyRecipient: true, Rekey: boundary.RekeyRefused},
			[]string{"Transfers:  pay", "leaves only by what it may spend"}},
		{"timelock, spending key", apshellapp.BoundaryPreview{Transfers: []string{"pay"}, UnlockRound: "9", Rekey: boundary.RekeySpendingKey},
			[]string{"spending key alone, which can rekey the account anywhere", "doesn't wait for the unlock round"}},
		{"timelock, plus cosigned", apshellapp.BoundaryPreview{Transfers: []string{"pay"}, UnlockRound: "9", Rekey: boundary.RekeyPlusCosigned,
			RekeyTo: []string{"A"}, Cosigner: "ops"}, []string{"or elsewhere with the cosigner", "way around the unlock round"}},
	} {
		var out bytes.Buffer
		renderBoundaryPreview(&REPLState{Out: &out}, &test.preview)
		text := out.String()
		for _, want := range test.want {
			if !strings.Contains(text, want) {
				t.Errorf("%s: summary lacks %q:\n%s", test.name, want, text)
			}
		}
		if strings.Contains(text, "will reject") {
			t.Errorf("%s: summary claims a refusal the signer doesn't make:\n%s", test.name, text)
		}
	}
}
