// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package admin

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/sourcetokens"
)

// publishTokens publishes, as an unlocked node's reload does, an index with
// tokens for selector's sources.
func publishTokens(t *testing.T, svc Service, selector string, sources ...string) {
	t.Helper()
	var f *sourcetokens.File
	for _, source := range sources {
		next, err := sourcetokens.SetToken(f, selector, source, []byte("tok-"+source), time.Unix(1_700_000_000, 0))
		if err != nil {
			t.Fatal(err)
		}
		f = next
	}
	var files []*sourcetokens.File
	if f != nil {
		files = append(files, f)
		defer f.Zero()
	}
	svc.Runtime.PublishSourceTokens(sourcetokens.NewIndex(files))
}

// A document read names no source token, whatever the session may do:
// token names are read with source_token_list, at policy.update.
func TestPolicyDocumentNamesNoSourceToken(t *testing.T) {
	svc, _ := setupPolicyAdmin(t, noderole.RoleCosigner)
	publishTokens(t, svc, policy.DefaultKey, "treasury", "screening")
	doc := svc.GetPolicyDocumentAt(adminproto.GetPolicyDocumentRequest{Key: policy.DefaultKey})
	if !doc.Success {
		t.Fatalf("GetPolicyDocumentAt() = %+v", doc)
	}
	wire, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(wire), "screening") || strings.Contains(string(wire), "SourceToken") {
		t.Fatalf("a document read names source tokens: %s", wire)
	}
}

// A check warns of a missing token only for a session that may read token
// names (policy.update), and only while the node knows its tokens: a locked
// node cannot tell, and a session with policy.view alone is told nothing of
// them.
func TestCheckPolicyWarnsOfNoTokenWhileTokensAreUnknown(t *testing.T) {
	svc, _ := setupPolicyAdmin(t, noderole.RoleCosigner)
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "test", "contracts", "policy", "v1", "cosigner_key_external_checks.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	doc["key"] = policy.DefaultKey
	text, _ := json.Marshal(doc)
	req := adminproto.CheckPolicyRequest{Documents: []adminproto.PolicyDocument{{Key: policy.DefaultKey, Document: string(text)}}, SourceTokensReadable: true}
	tokenWarnings := func() []string {
		t.Helper()
		result := svc.CheckPolicy(req)
		if !result.Success || !result.Valid {
			t.Fatalf("CheckPolicy() = %+v", result)
		}
		var out []string
		for _, w := range result.Warnings {
			if strings.HasSuffix(w.Pointer, "/token") {
				out = append(out, w.Pointer)
			}
		}
		return out
	}
	if got := tokenWarnings(); len(got) != 0 {
		t.Fatalf("token warnings while tokens are unknown: %v", got)
	}
	publishTokens(t, svc, policy.DefaultKey, "screening")
	if got := tokenWarnings(); !slices.Equal(got, []string{"/external_sources/treasury/token"}) {
		t.Fatalf("token warnings while unlocked = %v", got)
	}
	req.SourceTokensReadable = false
	if got := tokenWarnings(); len(got) != 0 {
		t.Fatalf("token warnings for a session that may not read token names: %v", got)
	}
}
