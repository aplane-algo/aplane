// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyapply

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/signerapp/policyruntime"
)

// externalChecksDocument is the external checks contract fixture, whose
// screening and treasury sources take a token and ops takes none, keyed by
// key.
func externalChecksDocument(t *testing.T, key string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "test", "contracts", "policy", "v1", "cosigner_key_external_checks.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	doc["key"] = key
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func tokenWarnings(problems []adminproto.PolicyProblem) []string {
	var out []string
	for _, p := range problems {
		if strings.Contains(p.Pointer, "/token") {
			out = append(out, p.Key+" "+p.Pointer+" "+p.Message)
		}
	}
	return out
}

// A check warns, never refuses, for each source the document declares a
// token for that its selector has none of, checked against the selector's
// own token names.
func TestCheckWarnsOfASourceTokenTheSelectorLacks(t *testing.T) {
	key := manyWitnessKeyIDs(1)[0]
	current := &policyruntime.NodePolicy{Role: noderole.RoleCosigner, Documents: []policy.StoredDocument{cosignerDefaultDoc()}}
	req := adminproto.CheckPolicyRequest{Documents: []adminproto.PolicyDocument{
		{Key: policy.DefaultKey, Document: externalChecksDocument(t, policy.DefaultKey)},
		{Key: key, Document: externalChecksDocument(t, key)},
	}}
	env := Env{Role: noderole.RoleCosigner, HeldKeys: map[string]bool{key: true}, SourceTokens: SourceTokenNamesOf(map[string][]string{
		policy.DefaultKey: {"screening", "unrelated"},
		key:               {"treasury"},
	})}
	result := Check(env, current, req)
	if !result.Success || !result.Valid {
		t.Fatalf("Check() = %+v", result)
	}
	got := tokenWarnings(result.Warnings)
	want := []string{
		"default /external_sources/treasury/token source treasury takes a token and default has none set, so every lookup to it refuses; set one with apadmin source token set default treasury",
		key + " /external_sources/screening/token source screening takes a token and " + key + " has none set, so every lookup to it refuses; set one with apadmin source token set " + key + " screening",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("token warnings:\n got %q\nwant %q", got, want)
	}

	// Every token set: no warning. No token knowledge: none either.
	env.SourceTokens = SourceTokenNamesOf(map[string][]string{policy.DefaultKey: {"screening", "treasury"}, key: {"screening", "treasury"}})
	if got := tokenWarnings(Check(env, current, req).Warnings); len(got) != 0 {
		t.Fatalf("token warnings with every token set: %q", got)
	}
	env.SourceTokens = nil
	if got := tokenWarnings(Check(env, current, req).Warnings); len(got) != 0 {
		t.Fatalf("token warnings without token knowledge: %q", got)
	}
	// A lookup that does not know a selector's names says nothing of it.
	env.SourceTokens = func(string) ([]string, bool) { return nil, false }
	if got := tokenWarnings(Check(env, current, req).Warnings); len(got) != 0 {
		t.Fatalf("token warnings from a lookup that does not know: %q", got)
	}
}
