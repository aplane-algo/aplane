// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keyadmin

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/policyruntime"
	"github.com/aplane-algo/aplane/internal/sourcetokens"
	"github.com/aplane-algo/aplane/internal/witness"
)

// sourcesTaking builds a document's sources: those named in tokens take a
// token, the rest take none.
func sourcesTaking(tokens []string, plain ...string) map[string]policy.ExternalSourceV1 {
	out := map[string]policy.ExternalSourceV1{}
	for _, name := range tokens {
		out[name] = policy.ExternalSourceV1{BaseURL: "https://" + name + ".example", Token: &policy.ExternalTokenV1{}}
	}
	for _, name := range plain {
		out[name] = policy.ExternalSourceV1{BaseURL: "https://" + name + ".example"}
	}
	return out
}

// publishPolicy installs a node policy whose default document has
// defaultSources and whose keys have their own documents with the sources
// given.
func publishPolicy(svc Service, defaultSources map[string]policy.ExternalSourceV1, own map[string]map[string]policy.ExternalSourceV1) {
	np := &policyruntime.NodePolicy{
		Role:    noderole.RoleCosigner,
		Default: &policy.Config{DocumentKey: policy.DefaultKey, ExternalSources: defaultSources},
		Keys:    map[string]*policy.Config{},
	}
	for key, sources := range own {
		np.Keys[key] = &policy.Config{DocumentKey: key, ExternalSources: sources}
	}
	svc.Runtime.SetVerifiedPolicyState(np, nil, nil)
}

func listingStates(listing adminproto.SourceTokenSelector) string {
	var parts []string
	for _, token := range listing.Tokens {
		set := "-"
		if !token.SetAt.IsZero() {
			set = "set"
		}
		parts = append(parts, token.Source+"="+token.State+"/"+set)
	}
	return fmt.Sprintf("%s %s [%s] %s", listing.Selector, listing.Policy, strings.Join(listing.Sources, ","), strings.Join(parts, " "))
}

func TestListSourceTokensReportsInUseUnusedAndNeeded(t *testing.T) {
	svc, keyID := cosignerWithKey(t)
	other, err := svc.GenerateKey(context.Background(), witness.Falcon1024V1, nil)
	if err != nil {
		t.Fatalf("GenerateKey(second cosigner) error = %#v", err)
	}
	follower := other.Address
	publishPolicy(svc,
		sourcesTaking([]string{"screening", "treasury"}, "ops"),
		map[string]map[string]policy.ExternalSourceV1{keyID: sourcesTaking([]string{"risk"})},
	)
	for _, set := range []struct{ selector, source string }{
		{sourcetokens.DefaultSelector, "screening"}, // in use
		{sourcetokens.DefaultSelector, "ops"},       // ops takes no token: unused
		{sourcetokens.DefaultSelector, "retired"},   // no such source: unused
		{keyID, "screening"},                        // the key's own document has no screening
		{follower, "screening"},                     // the key follows the default: unused
	} {
		if _, svcErr := svc.SetSourceToken(set.selector, set.source, []byte("tok-"+set.source)); svcErr != nil {
			t.Fatalf("SetSourceToken(%s, %s) error = %#v", set.selector, set.source, svcErr)
		}
	}

	all, omitted, svcErr := svc.ListSourceTokens("", "")
	if svcErr != nil || omitted != 0 {
		t.Fatalf("ListSourceTokens() = %d omitted, %#v", omitted, svcErr)
	}
	got := make([]string, len(all))
	for i, listing := range all {
		got[i] = listingStates(listing)
	}
	first, second := keyID, follower
	firstLine := first + " own [risk] risk=needed/- screening=unused/set"
	secondLine := second + " default [] screening=unused/set"
	if second < first {
		firstLine, secondLine = secondLine, firstLine
	}
	want := []string{
		"default own [ops,screening,treasury] ops=unused/set retired=unused/set screening=in_use/set treasury=needed/-",
		firstLine, secondLine,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("ListSourceTokens()\n got:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	// One key that follows the default: its own listing, then the default's,
	// whose tokens serve its checks.
	one, _, svcErr := svc.ListSourceTokens(follower, "")
	if svcErr != nil || len(one) != 2 || one[0].Selector != follower || one[0].Policy != adminproto.SourceTokenPolicyDefault ||
		one[1].Selector != sourcetokens.DefaultSelector {
		t.Fatalf("ListSourceTokens(follower) = %+v, %#v", one, svcErr)
	}
	// A key with its own document: that listing alone.
	one, _, svcErr = svc.ListSourceTokens(keyID, "")
	if svcErr != nil || len(one) != 1 || listingStates(one[0]) != keyID+" own [risk] risk=needed/- screening=unused/set" {
		t.Fatalf("ListSourceTokens(own) = %+v, %#v", one, svcErr)
	}
}

func TestListSourceTokensRefusals(t *testing.T) {
	svc, _ := cosignerWithKey(t)
	publishPolicy(svc, nil, nil)
	for _, tt := range []struct {
		selector string
		want     ErrorKind
	}{
		{unheldWitnessKeyID, ErrorNotFound},
		{"CEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEI7JH2AYM", ErrorInvalidInput},
	} {
		if _, _, svcErr := svc.ListSourceTokens(tt.selector, ""); svcErr == nil || svcErr.Kind != tt.want {
			t.Fatalf("ListSourceTokens(%s) error = %#v, want %v", tt.selector, svcErr, tt.want)
		}
	}
	svc.Runtime.Lock()
	if _, _, svcErr := svc.ListSourceTokens("", ""); svcErr == nil || svcErr.Kind != ErrorLocked {
		t.Fatalf("ListSourceTokens(locked) error = %#v", svcErr)
	}

	signer := Service{Runtime: setupProductRuntimeWithRole(t, noderole.RoleSigner)}
	if _, _, svcErr := signer.ListSourceTokens("", ""); svcErr == nil || svcErr.Kind != ErrorInvalidInput {
		t.Fatalf("ListSourceTokens(signer) error = %#v", svcErr)
	}
}

// A listing of every selector skips selectors with nothing to say and bounds
// how many it returns; a listing of one is always whole.
func TestListSourceTokensBoundsTheListingOfEverySelector(t *testing.T) {
	svc, _ := cosignerWithKey(t)
	own := map[string]map[string]policy.ExternalSourceV1{}
	for i := range MaxListedSourceTokenSelectors + 3 {
		own[fmt.Sprintf("K%04d", i)] = sourcesTaking([]string{"screening"})
	}
	own["QUIET"] = sourcesTaking(nil, "ops")
	publishPolicy(svc, sourcesTaking(nil, "ops"), own)
	all, omitted, svcErr := svc.ListSourceTokens("", "")
	if svcErr != nil || len(all) != MaxListedSourceTokenSelectors || omitted != 3 {
		t.Fatalf("ListSourceTokens() = %d listed, %d omitted, %#v", len(all), omitted, svcErr)
	}
	for _, listing := range all {
		if listing.Selector == "QUIET" || listing.Selector == sourcetokens.DefaultSelector {
			t.Fatalf("a selector with nothing to list is listed: %+v", listing)
		}
	}
}

// The IPC result of a change lists the selector's tokens with their states
// and never a value.
func TestSourceTokenChangeResultListsStatesWithoutValues(t *testing.T) {
	svc, _ := cosignerWithKey(t)
	publishPolicy(svc, sourcesTaking([]string{"screening", "treasury"}), nil)
	ipc := IPCService{Service: svc}
	result := ipc.SetSourceToken(adminproto.SetSourceTokenRequest{Selector: sourcetokens.DefaultSelector, Source: "screening", Token: []byte("tok-value-1")})
	if !result.Success || listingStates(adminproto.SourceTokenSelector{Selector: result.Selector, Tokens: result.Tokens}) !=
		"default  [] screening=in_use/set treasury=needed/-" {
		t.Fatalf("SetSourceToken() = %+v", result)
	}
	if strings.Contains(fmt.Sprintf("%+v", result), "tok-value-1") {
		t.Fatalf("the result carries the token: %+v", result)
	}
	removed := ipc.RemoveSourceToken(adminproto.RemoveSourceTokenRequest{Selector: sourcetokens.DefaultSelector, Source: "screening"})
	if !removed.Success || len(removed.Tokens) != 2 || removed.Tokens[0].State != adminproto.SourceTokenNeeded {
		t.Fatalf("RemoveSourceToken() = %+v", removed)
	}
	again := ipc.RemoveSourceToken(adminproto.RemoveSourceTokenRequest{Selector: sourcetokens.DefaultSelector, Source: "screening"})
	if again.Success || again.Code != protocol.ErrCodeSourceTokenNotSet || again.Error == "" {
		t.Fatalf("RemoveSourceToken(none set) = %+v, want %s", again, protocol.ErrCodeSourceTokenNotSet)
	}
	list := ipc.ListSourceTokens(adminproto.ListSourceTokensRequest{})
	if !list.Success || len(list.Selectors) != 1 || len(list.Selectors[0].Tokens) != 2 {
		t.Fatalf("ListSourceTokens() = %+v", list)
	}
}

// A listing of every selector pages: after names the last selector of the
// previous page, in the listing's order ("default" first, then the keys in
// order), and omitted counts what is left after the page.
func TestListSourceTokensPagesAfterASelector(t *testing.T) {
	svc, keyID := cosignerWithKey(t)
	other, err := svc.GenerateKey(context.Background(), witness.Falcon1024V1, nil)
	if err != nil {
		t.Fatalf("GenerateKey(second cosigner) error = %#v", err)
	}
	first, second := keyID, other.Address
	if second < first {
		first, second = second, first
	}
	publishPolicy(svc, sourcesTaking([]string{"screening"}), nil)
	for _, selector := range []string{first, second} {
		if _, svcErr := svc.SetSourceToken(selector, "screening", []byte("tok")); svcErr != nil {
			t.Fatalf("SetSourceToken(%s) error = %#v", selector, svcErr)
		}
	}
	after := func(selector string) string {
		var out []string
		for _, s := range []string{first, second} {
			if s > selector {
				out = append(out, s)
			}
		}
		return strings.Join(out, ",")
	}
	selectorsOf := func(listings []adminproto.SourceTokenSelector) string {
		var out []string
		for _, l := range listings {
			out = append(out, l.Selector)
		}
		return strings.Join(out, ",")
	}
	for _, tt := range []struct{ after, want string }{
		{"", "default," + first + "," + second},
		{"default", first + "," + second},
		{first, second},
		{second, ""},
		// A selector that is not listed still places the page.
		{unheldWitnessKeyID, after(unheldWitnessKeyID)},
	} {
		got, omitted, svcErr := svc.ListSourceTokens("", tt.after)
		if svcErr != nil || omitted != 0 || selectorsOf(got) != tt.want {
			t.Fatalf("ListSourceTokens(after %q) = %s, %d omitted, %#v; want %s", tt.after, selectorsOf(got), omitted, svcErr, tt.want)
		}
	}
	if _, _, svcErr := svc.ListSourceTokens(first, "default"); svcErr == nil || svcErr.Kind != ErrorInvalidInput {
		t.Fatalf("after with a selector: error = %#v, want invalid input", svcErr)
	}
	if _, _, svcErr := svc.ListSourceTokens("", "not-a-selector"); svcErr == nil || svcErr.Kind != ErrorInvalidInput {
		t.Fatalf("an invalid after: error = %#v, want invalid input", svcErr)
	}
}

// A page holds at most the limit, and omitted counts the selectors after it
// that a listing would show; selectors it would not show are not counted.
func TestPageSourceTokenSelectors(t *testing.T) {
	order := []string{"default", "A", "B", "C", "D"}
	listed := func(s string) bool { return s != "B" }
	for _, tt := range []struct {
		after   string
		page    string
		omitted int
	}{
		{"", "default,A", 2},
		{"A", "C,D", 0},
		{"B", "C,D", 0},
		{"default", "A,C", 1},
		{"D", "", 0},
	} {
		page, omitted := pageSourceTokenSelectors(order, listed, tt.after, 2)
		if strings.Join(page, ",") != tt.page || omitted != tt.omitted {
			t.Fatalf("after %q: page %v, %d omitted; want %s, %d", tt.after, page, omitted, tt.page, tt.omitted)
		}
	}
}
