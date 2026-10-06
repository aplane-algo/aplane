// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyreview

import (
	"reflect"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/policy"
)

func TestStripCommentsRemovesCommentsOutsideStrings(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{name: "no comments is unchanged", in: "{\n  \"a\": \"b\"  \n}\n", want: "{\n  \"a\": \"b\"  \n}\n"},
		{name: "line comment on its own line is dropped", in: "{\n  // note\n  \"a\": 1\n}\n", want: "{\n  \"a\": 1\n}\n"},
		{name: "trailing line comment is trimmed", in: "{\n  \"a\": 1 // note\n}\n", want: "{\n  \"a\": 1\n}\n"},
		{name: "block comment inline", in: "{\"a\": /* x */ 1}", want: "{\"a\":  1}"},
		{name: "block comment spanning lines", in: "{\n  /* one\n     two */\n  \"a\": 1\n}", want: "{\n  \"a\": 1\n}"},
		{name: "block comment ending mid line keeps the rest", in: "{\n  /* one\n  two */ \"a\": 1\n}", want: "{\n \"a\": 1\n}"},
		{name: "comment markers inside strings stay", in: "{\"url\": \"http://x/*y*/\", \"b\": \"\\\"//\"}", want: "{\"url\": \"http://x/*y*/\", \"b\": \"\\\"//\"}"},
		{name: "escaped quote does not end the string", in: "{\"a\": \"\\\\\" // c\n}", want: "{\"a\": \"\\\\\"\n}"},
		{name: "original blank lines stay", in: "{\n\n  // c\n\n  \"a\": 1\n}", want: "{\n\n\n  \"a\": 1\n}"},
		{name: "comment without final newline", in: "{\"a\": 1}\n// end", want: "{\"a\": 1}\n"},
		{name: "lone slash is left for the decoder", in: "{\"a\": 1 / 2}", want: "{\"a\": 1 / 2}"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := StripComments([]byte(tt.in))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tt.want {
				t.Fatalf("StripComments(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
	if _, err := StripComments([]byte("{\"a\": 1 /* open")); err == nil || !strings.Contains(err.Error(), "unterminated") {
		t.Fatalf("unterminated block comment error = %v", err)
	}
}

func TestBlankCommentsKeepsPositions(t *testing.T) {
	in := "{\n  // note\n  \"a\": /* x\n y */ 1 // t\n}"
	got, err := BlankComments([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	want := "{\n         \n  \"a\":     \n      1     \n}"
	if string(got) != want {
		t.Fatalf("BlankComments = %q, want %q", got, want)
	}
	if len(got) != len(in) || strings.Count(string(got), "\n") != strings.Count(in, "\n") {
		t.Fatal("BlankComments changed the length or line count")
	}
}

func TestReadDocumentsStripsCommentsBeforeTheNode(t *testing.T) {
	commented := "{\n  // the document type\n  \"format\": \"aplane.signer-policy.v1\", /* fee */\n  \"max_fee_microalgos\": \"2000\" // cap\n}\n"
	file := writePolicyFile(t, "policy.json", commented)
	docs, _, err := ReadDocuments([]string{file}, "signer", nil)
	if err != nil {
		t.Fatal(err)
	}
	want := "{\n  \"format\": \"aplane.signer-policy.v1\",\n  \"max_fee_microalgos\": \"2000\"\n}\n"
	if docs[0].Document != want {
		t.Fatalf("document sent = %q, want %q", docs[0].Document, want)
	}
	if _, err := policy.DecodeSignerPolicyV1([]byte(docs[0].Document)); err != nil {
		t.Fatalf("stripped document does not decode: %v", err)
	}
	docs, _, err = ReadRegularDocuments([]string{file}, "signer")
	if err != nil || docs[0].Document != want {
		t.Fatalf("ReadRegularDocuments = %q, %v", docs[0].Document, err)
	}
	doc, err := DocumentFromText("signer", "policy.json", commented)
	if err != nil || doc.Document != want {
		t.Fatalf("DocumentFromText = %q, %v", doc.Document, err)
	}
	// A cosigner key is read from the stripped text.
	cosigner := "{\n  \"format\": \"aplane.cosigner-policy.v1\",\n  // which key\n  \"key\": \"" + testKeyA + "\",\n  \"transfer_policy\": {\"routes\": []}\n}\n"
	doc, err = DocumentFromText("cosigner", "k.json", cosigner)
	if err != nil || doc.Key != testKeyA || strings.Contains(doc.Document, "//") {
		t.Fatalf("cosigner commented text: doc %+v err %v", doc, err)
	}

	for name, text := range map[string]string{
		"only comments": "// nothing here\n/* at all */\n",
		"unterminated":  "{\"format\": \"aplane.signer-policy.v1\"} /* open",
	} {
		if _, err := DocumentFromText("signer", "policy.json", text); err == nil {
			t.Fatalf("%s: text accepted", name)
		}
	}
}

// The templates are the starting documents with comments: stripped, they
// decode equal to what the node starts with, and with their example blocks
// enabled they are valid policy with the example route.
func TestStartingTemplatesMatchTheStartingDocuments(t *testing.T) {
	signer := SignerTemplate()
	stripped, err := StripComments([]byte(signer))
	if err != nil {
		t.Fatal(err)
	}
	got, err := policy.DecodeSignerPolicyV1(stripped)
	if err != nil {
		t.Fatalf("stripped signer template does not decode: %v\n%s", err, stripped)
	}
	want, err := policy.DecodeSignerPolicyV1(policy.InitialSignerPolicy)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("stripped signer template = %+v, want the initial policy %+v", got, want)
	}
	// The node holds strict JSON, so IsStartingDocument sees stripped text.
	if !IsStartingDocument("signer", "", string(policy.InitialSignerPolicy)) || !IsStartingDocument("signer", "", string(stripped)) {
		t.Fatal("IsStartingDocument rejects the signer starting document")
	}
	if IsStartingDocument("signer", "", signer) {
		t.Fatal("IsStartingDocument accepted text with comments")
	}
	if IsStartingDocument("signer", "", testSignerDoc) {
		t.Fatal("IsStartingDocument accepts a signer document with a fee cap")
	}

	cosigner, err := CosignerTemplate(testKeyA)
	if err != nil {
		t.Fatal(err)
	}
	stripped, err = StripComments([]byte(cosigner))
	if err != nil {
		t.Fatal(err)
	}
	gotCosigner, err := policy.DecodeCosignerPolicyV1(stripped, testKeyA)
	if err != nil {
		t.Fatalf("stripped cosigner template does not decode: %v\n%s", err, stripped)
	}
	locked, err := policy.StartingCosignerDocumentV1(testKeyA)
	if err != nil {
		t.Fatal(err)
	}
	wantCosigner, err := policy.DecodeCosignerPolicyV1([]byte(locked), testKeyA)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotCosigner, wantCosigner) {
		t.Fatalf("stripped cosigner template = %+v, want the starting document %+v", gotCosigner, wantCosigner)
	}
	if !IsStartingDocument("cosigner", testKeyA, locked) || !IsStartingDocument("cosigner", testKeyA, string(stripped)) {
		t.Fatal("IsStartingDocument rejects the cosigner starting document")
	}
	if IsStartingDocument("cosigner", testKeyA, testCosignerDoc(testKeyB)) || IsStartingDocument("operator", "", signer) {
		t.Fatal("IsStartingDocument accepts a document for another key or role")
	}

	if _, err := StartingTemplate("operator", ""); err == nil {
		t.Fatal("StartingTemplate accepted an unknown role")
	}
	if text, err := StartingTemplate("cosigner", testKeyA); err != nil || text != cosigner {
		t.Fatalf("StartingTemplate(cosigner) = %q, %v", text, err)
	}
}

func TestTemplateExampleBlocksAreValidPolicy(t *testing.T) {
	const address = "CEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEI7JH2AYM"
	enabled := strings.ReplaceAll(UncommentTemplate(SignerTemplate()), "<58-character address>", address)
	for _, line := range strings.Split(enabled, "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimLeft(line, " "), "//"); ok {
			if text := strings.TrimLeft(rest, " "); text != "" && strings.ContainsRune(`"{}[]`, rune(text[0])) {
				t.Fatalf("a JSON line stayed commented: %q", line)
			}
		}
	}
	stripped, err := StripComments([]byte(enabled))
	if err != nil {
		t.Fatal(err)
	}
	signer, err := policy.DecodeSignerPolicyV1(stripped)
	if err != nil {
		t.Fatalf("enabled signer template does not decode: %v\n%s", err, stripped)
	}
	if signer.TransferPolicy == nil || !signer.TransferPolicy.Enabled || len(signer.TransferPolicy.Routes) != 2 ||
		signer.TransferPolicy.Routes[0].ID != "treasury-to-ops" || signer.TransferPolicy.Routes[1].ID != policy.SelfTransferRouteID ||
		signer.MaxFeeMicroAlgos == nil || len(signer.Limits) == 0 || signer.RejectForeignRekey == nil || *signer.RejectForeignRekey {
		t.Fatalf("enabled signer template = %+v, want every example block in effect", signer)
	}

	template, err := CosignerTemplate(testKeyA)
	if err != nil {
		t.Fatal(err)
	}
	enabled = strings.ReplaceAll(UncommentTemplate(template), "<58-character address>", address)
	stripped, err = StripComments([]byte(enabled))
	if err != nil {
		t.Fatal(err)
	}
	cosigner, err := policy.DecodeCosignerPolicyV1(stripped, testKeyA)
	if err != nil {
		t.Fatalf("enabled cosigner template does not decode: %v\n%s", err, stripped)
	}
	if len(cosigner.Routes) != 2 || cosigner.Routes[0].ID != "treasury-to-ops" || cosigner.Routes[1].ID != policy.SelfTransferRouteID || len(cosigner.RekeyPolicy) != 1 ||
		cosigner.RejectRekey == nil || cosigner.MaxFeeMicroAlgos == nil || len(cosigner.Limits) == 0 {
		t.Fatalf("enabled cosigner template = %+v, want every example block in effect", cosigner)
	}
}
