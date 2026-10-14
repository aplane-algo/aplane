// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyreview

import (
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy/policytest"
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
		{name: "block comment inline", in: "{\"a\": /* x */ 1}", want: "{\"a\":   1}"},
		{name: "inline comment keeps tokens apart", in: "{\"a\":fa/* x */lse}", want: "{\"a\":fa lse}"},
		{name: "inline comment between tokens without spaces", in: "{\"a\":1/* x */,\"b\":2}", want: "{\"a\":1 ,\"b\":2}"},
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
	// A complete document with comments added: a whole line, and one inside a
	// line. Stripped, it is the document without them.
	clean := policytest.Signer(t, policy.DefaultKey, `{"max_fee_microalgos":"2000"}`)
	commented := strings.Replace(clean, "{\n", "{\n  // the document type\n", 1)
	commented = strings.Replace(commented, "\"max_fee_microalgos\": \"2000\",", "\"max_fee_microalgos\": \"2000\", /* fee */", 1)
	if commented == clean {
		t.Fatal("test did not add comments")
	}
	file := writePolicyFile(t, "default.json", commented)
	docs, _, err := ReadDocuments([]string{file}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if docs[0].Document != clean {
		t.Fatalf("document sent = %q, want %q", docs[0].Document, clean)
	}
	if _, err := policy.DecodePolicyV1([]byte(docs[0].Document), policy.DefaultKey, noderole.RoleSigner); err != nil {
		t.Fatalf("stripped document does not decode: %v", err)
	}
	docs, _, err = ReadRegularDocuments([]string{file})
	if err != nil || docs[0].Document != clean {
		t.Fatalf("ReadRegularDocuments = %q, %v", docs[0].Document, err)
	}
	doc, err := DocumentFromText("default.json", commented)
	if err != nil || doc.Document != clean {
		t.Fatalf("DocumentFromText = %q, %v", doc.Document, err)
	}
	// The key is read from the stripped text.
	cosigner := strings.Replace(testCosignerDoc(testKeyA), "\"key\":", "// which key\n  \"key\":", 1)
	doc, err = DocumentFromText("k.json", cosigner)
	if err != nil || doc.Key != testKeyA || strings.Contains(doc.Document, "//") {
		t.Fatalf("cosigner commented text: doc %+v err %v", doc, err)
	}

	for name, text := range map[string]string{
		"only comments": "// nothing here\n/* at all */\n",
		"unterminated":  "{\"key\": \"default\"} /* open",
	} {
		if _, err := DocumentFromText("default.json", text); err == nil {
			t.Fatalf("%s: text accepted", name)
		}
	}
	// A comment inside a token does not assemble one: the stripped text is
	// not a JSON object, so no key can be read from it and it is refused
	// exactly as the blanked text the TUI checks would be.
	split := "{\"key\": \"default\", \"reject_foreign_rekey\": fa/* note */lse}"
	if doc, err := DocumentFromText("default.json", split); err == nil || !strings.Contains(err.Error(), `"key" field`) {
		t.Fatalf("a token split by a comment was accepted: doc %+v err %v", doc, err)
	}
}

// A template is the default with the key filled in and a comment on top:
// stripped, it decodes equal to the default under the key's name.
func TestTemplatesAreTheDefaultUnderTheKeysName(t *testing.T) {
	for _, role := range []noderole.Role{noderole.RoleSigner, noderole.RoleCosigner} {
		def := policytest.EmbeddedDefault(t, role)
		key := "CEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEI7JH2AYM"
		if role == noderole.RoleCosigner {
			key = testKeyA
		}
		text, err := Template(role, key, []byte(def))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(text, "// Policy for key "+key) {
			t.Fatalf("%s template does not start with its comment:\n%s", role, text)
		}
		stripped, err := StripComments([]byte(text))
		if err != nil {
			t.Fatal(err)
		}
		got, err := policy.DecodePolicyV1(stripped, key, role)
		if err != nil {
			t.Fatalf("stripped %s template does not decode: %v\n%s", role, err, stripped)
		}
		want, err := policy.DecodePolicyV1([]byte(def), policy.DefaultKey, role)
		if err != nil {
			t.Fatal(err)
		}
		want.Key = key
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("stripped %s template = %+v, want the default under the key %+v", role, got, want)
		}

		// The default itself is annotated under its own name.
		own, err := Template(role, policy.DefaultKey, []byte(def))
		if err != nil {
			t.Fatal(err)
		}
		stripped, err = StripComments([]byte(own))
		if err != nil {
			t.Fatal(err)
		}
		if string(stripped) != def || !strings.Contains(own, "default policy") {
			t.Fatalf("%s default template = %q", role, own)
		}

		embedded, err := EmbeddedTemplate(role, key)
		if err != nil || embedded != text {
			t.Fatalf("EmbeddedTemplate(%s) = %q, %v", role, embedded, err)
		}
	}
	if _, err := Template(noderole.RoleSigner, testKeyA, []byte(policytest.EmbeddedDefault(t, noderole.RoleCosigner))); err == nil {
		t.Fatal("Template accepted a cosigner default on a signer node")
	}
	if _, err := Template(noderole.RoleSigner, policy.DefaultKey, []byte("{}")); err == nil {
		t.Fatal("Template accepted an invalid default")
	}
	if _, err := EmbeddedTemplate("operator", ""); err == nil {
		t.Fatal("EmbeddedTemplate accepted an unknown role")
	}
}
