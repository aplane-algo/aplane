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
// refused one included, and claims no refusal
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
		{"bounded, spending key", apshellapp.BoundaryPreview{Transfers: []string{"pay"}, AnyRecipient: true, Rekey: boundary.RekeySpendingKey},
			[]string{"spending key alone, which can rekey the account anywhere"}},
		{"bounded, plus cosigned", apshellapp.BoundaryPreview{Transfers: []string{"pay"}, AnyRecipient: true, Rekey: boundary.RekeyPlusCosigned,
			RekeyTo: []string{"A"}, Cosigner: "ops"}, []string{"or elsewhere with the cosigner"}},
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

// A bounded account's summary states its fee limit: the default when the file
// names none, the file's own otherwise. An account with no bounds has no limit.
func TestBoundaryPreviewStatesTheFeeLimit(t *testing.T) {
	bounded := apshellapp.BoundaryPreview{Transfers: []string{"pay", "axfer"}, AnyRecipient: true, Rekey: boundary.RekeyRefused}
	for _, test := range []struct {
		name   string
		maxFee string
		want   string
	}{
		{"default", "", "  Fee limit:  10000 (default) microAlgos per transaction\n"},
		{"custom", "20000", "  Fee limit:  20000 microAlgos per transaction\n"},
		{"zero", "0", "  Fee limit:  0 microAlgos per transaction\n"},
		{"largest", "18446744073709551615", "  Fee limit:  18446744073709551615 microAlgos per transaction\n"},
	} {
		preview := bounded
		preview.MaxFee = test.maxFee
		var out bytes.Buffer
		renderBoundaryPreview(&REPLState{Out: &out}, &preview)
		text := out.String()
		if strings.Count(text, "Fee limit:") != 1 || !strings.Contains(text, test.want) {
			t.Errorf("%s: summary lacks %q:\n%s", test.name, test.want, text)
		}
		// It follows the transfer kinds it limits.
		if !strings.Contains(text, "  Transfers:  pay, axfer\n"+test.want) {
			t.Errorf("%s: the fee limit does not follow the transfers:\n%s", test.name, text)
		}
		if test.maxFee != "" && strings.Contains(text, "(default)") {
			t.Errorf("%s: a named limit reads as the default:\n%s", test.name, text)
		}
	}
	var out bytes.Buffer
	renderBoundaryPreview(&REPLState{Out: &out}, &apshellapp.BoundaryPreview{NoBounds: true, Rekey: boundary.RekeyRefused, MaxFee: "20000"})
	if text := out.String(); strings.Contains(text, "Fee limit:") || !strings.Contains(text, "no fee limit") {
		t.Errorf("an account with no bounds states a fee limit:\n%s", text)
	}
}
