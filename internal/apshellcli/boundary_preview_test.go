// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"bytes"
	"encoding/json"
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
		{"largest", "9007199254740991", "  Fee limit:  9007199254740991 microAlgos per transaction\n"},
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

// The record of a generation states the fee limit the signer stored and prints
// each piece of the signer's advice, after the account's other resolved values.
// An account at the default limit stores none, so states none, and a signer with
// no advice prints no warning.
func TestResolvedGenerationPrintsTheFeeLimitAndWarnings(t *testing.T) {
	render := func(result *apshellapp.GenerateKeyCommandResult) string {
		var out bytes.Buffer
		renderResolvedGeneration(&REPLState{Out: &out}, result)
		return out.String()
	}
	const warning = "Fee limit 0 is too low to pay alone. A transaction on its own costs more: spend (at least 2000). " +
		"Batch it with others that share the cost, or have another account in the group pay its fees."
	text := render(&apshellapp.GenerateKeyCommandResult{
		KeyType: "aplane.falcon1024.v1", Address: "ADDRESS", CosignerKeyID: "COSIGNER",
		Parameters: map[string]string{
			boundary.ParameterRekeyAuthority: boundary.RekeyOnlyThese, boundary.ParameterRekeyTo: "A,B",
			boundary.ParameterListEncoding: boundary.EncodingInline, boundary.ParameterMaxFee: "0",
		},
		Warnings: []string{warning, "a second note"},
	})
	want := "  Cosigner:       COSIGNER\n" +
		"  Rekey:          only_these\n" +
		"  Rekey-to:       A, B\n" +
		"  List encoding:  inline\n" +
		"  Fee limit:      0 microAlgos per transaction\n" +
		"  Warning:        " + warning + "\n" +
		"  Warning:        a second note\n"
	if text != want {
		t.Fatalf("record =\n%s\nwant\n%s", text, want)
	}

	for _, test := range []struct {
		name   string
		result apshellapp.GenerateKeyCommandResult
		want   string
	}{
		{"a named limit, no advice", apshellapp.GenerateKeyCommandResult{Parameters: map[string]string{boundary.ParameterMaxFee: "20000"}},
			"  Fee limit:      20000 microAlgos per transaction\n"},
		{"the largest limit", apshellapp.GenerateKeyCommandResult{Parameters: map[string]string{boundary.ParameterMaxFee: "9007199254740991"}},
			"  Fee limit:      9007199254740991 microAlgos per transaction\n"},
		{"the default limit is not a stored parameter", apshellapp.GenerateKeyCommandResult{Parameters: map[string]string{boundary.ParameterRekeyAuthority: boundary.RekeyRefused}},
			"  Rekey:          refused\n"},
		{"advice without a limit", apshellapp.GenerateKeyCommandResult{Warnings: []string{"a note"}}, "  Warning:        a note\n"},
		{"nothing resolved", apshellapp.GenerateKeyCommandResult{}, ""},
	} {
		if text := render(&test.result); text != test.want {
			t.Errorf("%s: record = %q, want %q", test.name, text, test.want)
		}
	}
}

// The structured result of generate carries the signer's warnings as a list,
// and no field when there are none.
func TestGeneratedKeyProjectionCarriesWarnings(t *testing.T) {
	data, err := json.Marshal(generatedKeyProjection{
		KeyType: "aplane.falcon1024.v1", Address: "ADDRESS", Parameters: map[string]string{"max_fee": "0"},
		Warnings: []string{"Fee limit 0 is too low to pay alone.", "a second note"},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"key_type":"aplane.falcon1024.v1","address":"ADDRESS","parameters":{"max_fee":"0"},"warnings":["Fee limit 0 is too low to pay alone.","a second note"]}`
	if string(data) != want {
		t.Fatalf("projection = %s, want %s", data, want)
	}
	quiet, err := json.Marshal(generatedKeyProjection{KeyType: "ed25519", Address: "ADDRESS"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(quiet), "warnings") {
		t.Fatalf("a projection without warnings has the field: %s", quiet)
	}
}
