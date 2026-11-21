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

// A cosigner document read names the sources its selector has a token for,
// and says so, only while the node knows its tokens: not while locked, and
// never on a signer.
func TestPolicyDocumentNamesTheSelectorsSourceTokens(t *testing.T) {
	svc, _ := setupPolicyAdmin(t, noderole.RoleCosigner)
	read := func() adminproto.PolicyDocumentResult {
		t.Helper()
		doc := svc.GetPolicyDocumentAt(adminproto.GetPolicyDocumentRequest{Key: policy.DefaultKey})
		if !doc.Success {
			t.Fatalf("GetPolicyDocumentAt() = %+v", doc)
		}
		return doc
	}
	if doc := read(); doc.SourceTokensKnown || doc.SourceTokens != nil {
		t.Fatalf("a node with no token index claims to know its tokens: %+v", doc)
	}
	publishTokens(t, svc, policy.DefaultKey)
	if doc := read(); !doc.SourceTokensKnown || len(doc.SourceTokens) != 0 {
		t.Fatalf("an unlocked node with no tokens: %+v", doc)
	}
	publishTokens(t, svc, policy.DefaultKey, "treasury", "screening")
	if doc := read(); !doc.SourceTokensKnown || !slices.Equal(doc.SourceTokens, []string{"screening", "treasury"}) {
		t.Fatalf("an unlocked node with tokens: %+v", doc)
	}
	// A lock clears the index: the names are no longer known.
	svc.Runtime.PublishSourceTokens(nil)
	if doc := read(); doc.SourceTokensKnown || doc.SourceTokens != nil {
		t.Fatalf("a locked node claims to know its tokens: %+v", doc)
	}

	signer, _ := setupPolicyAdmin(t, noderole.RoleSigner)
	signer.Runtime.PublishSourceTokens(sourcetokens.NewIndex(nil))
	if doc := signer.GetPolicyDocumentAt(adminproto.GetPolicyDocumentRequest{Key: policy.DefaultKey}); !doc.Success || doc.SourceTokensKnown {
		t.Fatalf("a signer document claims to know source tokens: %+v", doc)
	}
}

// A check on a node that does not know its tokens, as a locked one, warns of
// no missing token: it cannot tell.
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
	req := adminproto.CheckPolicyRequest{Documents: []adminproto.PolicyDocument{{Key: policy.DefaultKey, Document: string(text)}}}
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
}
