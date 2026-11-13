// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package shellrepl

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/cmdspec"
	"github.com/aplane-algo/aplane/internal/plugin/discovery"
	"github.com/aplane-algo/aplane/internal/plugin/manifest"
)

// pluginCompleter builds the shell's completer over one plugin command with
// the given arg_specs and a signer cache holding address, the way the REPL
// and apconsole build it.
func pluginCompleter(specs []cmdspec.ArgSpec, address string) interface {
	Do([]rune, int) ([][]rune, int)
} {
	signerCache := cache.NewSignerCache()
	signerCache.AddAddress(address, "ed25519")
	plugin := &discovery.Plugin{Manifest: &manifest.Manifest{
		Name:     "branchy",
		Commands: []manifest.Command{{Name: "branchy", ArgSpecs: specs}},
	}}
	return CreateDynamicCompleter(&cache.AliasCache{Aliases: map[string]string{}}, &cache.ASACache{}, &cache.SetCache{}, &signerCache, nil, nil, []*discovery.Plugin{plugin})
}

// The manifest loader refuses these specs; completion still has to offer
// nothing for them rather than panic, at every position, for specs that did
// not come through it.
func TestPluginCompletionOffersNothingForUnreadableBranches(t *testing.T) {
	address := []cmdspec.ArgSpec{{Type: cmdspec.ArgTypeAddress}}
	tests := []struct {
		name  string
		specs []cmdspec.ArgSpec
	}{
		{
			name:  "negative index as the first spec",
			specs: []cmdspec.ArgSpec{{Branches: []cmdspec.ArgBranch{{When: cmdspec.ArgCondition{Arg: -1, Matches: ""}, Specs: address}}}},
		},
		{
			name: "negative index after a keyword",
			specs: []cmdspec.ArgSpec{{Type: cmdspec.ArgTypeKeyword, Values: []string{"pay"}}, {Branches: []cmdspec.ArgBranch{
				{When: cmdspec.ArgCondition{Arg: -1, Matches: ""}, Specs: address},
			}}},
		},
		{
			name: "matching branch without specs",
			specs: []cmdspec.ArgSpec{{Type: cmdspec.ArgTypeKeyword, Values: []string{"pay"}}, {Branches: []cmdspec.ArgBranch{
				{When: cmdspec.ArgCondition{Arg: 0, Matches: "^pay$"}},
			}}},
		},
		{
			name: "pattern that does not compile",
			specs: []cmdspec.ArgSpec{{Type: cmdspec.ArgTypeKeyword, Values: []string{"pay"}}, {Branches: []cmdspec.ArgBranch{
				{When: cmdspec.ArgCondition{Arg: 0, Matches: "(pay"}, Specs: address},
			}}},
		},
		{
			name: "negative index in a nested branch",
			specs: []cmdspec.ArgSpec{{Type: cmdspec.ArgTypeKeyword, Values: []string{"pay"}}, {Branches: []cmdspec.ArgBranch{
				{When: cmdspec.ArgCondition{Arg: 0, Matches: "^pay$"}, Specs: []cmdspec.ArgSpec{
					{Type: cmdspec.ArgTypeKeyword, Values: []string{"via"}},
					{Branches: []cmdspec.ArgBranch{{When: cmdspec.ArgCondition{Arg: -2, Matches: ""}, Specs: address}}},
				}},
			}}},
		},
	}
	// No line ends in a word such as "to" after which the shell offers
	// accounts for any command.
	addr := crypto.GenerateAccount().Address.String()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			completer := pluginCompleter(tt.specs, addr)
			for _, line := range []string{"branchy ", "branchy pay ", "branchy pay via ", "branchy pay via " + addr[:3], "branchy pa"} {
				suggestions, _ := completer.Do([]rune(line), len(line))
				for _, suggestion := range suggestions {
					if strings.Contains(addr, strings.TrimSpace(string(suggestion))) {
						t.Fatalf("Do(%q) suggested %q from a spec it cannot read", line, string(suggestion))
					}
				}
			}
		})
	}
}

func TestPluginCompletionFollowsNestedBranches(t *testing.T) {
	specs := []cmdspec.ArgSpec{
		{Type: cmdspec.ArgTypeKeyword, Values: []string{"pay"}},
		{Branches: []cmdspec.ArgBranch{{
			When: cmdspec.ArgCondition{Arg: 0, Matches: "^pay$"},
			Specs: []cmdspec.ArgSpec{
				{Type: cmdspec.ArgTypeKeyword, Values: []string{"to"}},
				{Branches: []cmdspec.ArgBranch{{
					When:  cmdspec.ArgCondition{Arg: 1, Matches: "^to$"},
					Specs: []cmdspec.ArgSpec{{Type: cmdspec.ArgTypeAddress}},
				}}},
			},
		}}},
	}
	addr := crypto.GenerateAccount().Address.String()
	completer := pluginCompleter(specs, addr)

	line := "branchy pay to "
	suggestions, offset := completer.Do([]rune(line), len(line))
	if offset != 0 || len(suggestions) != 1 || string(suggestions[0]) != addr+" " {
		t.Fatalf("Do(%q) = %q, %d; want the address", line, suggestions, offset)
	}
	line = "branchy pay "
	suggestions, _ = completer.Do([]rune(line), len(line))
	if len(suggestions) != 1 || string(suggestions[0]) != "to " {
		t.Fatalf("Do(%q) = %q; want the nested keyword", line, suggestions)
	}
}

// FuzzResolveArgSpec feeds arbitrary arg_specs, arguments and positions to
// the completion resolver: it may find no spec, but must never panic.
func FuzzResolveArgSpec(f *testing.F) {
	for _, seed := range []struct {
		specs, args string
		index       int
	}{
		{`[{"type":"address"}]`, "", 0},
		{`[{"branches":[{"when":{"arg":-1,"matches":""},"specs":[{"type":"address"}]}]}]`, "", 0},
		{`[{"type":"keyword"},{"branches":[{"when":{"arg":0,"matches":"^a$"},"specs":[]}]}]`, "a", 3},
		{`[{"type":"keyword"},{"branches":[{"when":{"arg":0,"matches":"("},"specs":[{"type":"address"}]}]}]`, "a", 1},
		{`[{"branches":[{"when":{"arg":0,"matches":""},"specs":[{"branches":[{"when":{"arg":1,"matches":"."},"specs":[{"type":"address"}]}]}]}]}]`, "a b c", 2},
		{`[{"type":"number"}]`, "a b", -4},
	} {
		f.Add(seed.specs, seed.args, seed.index)
	}
	f.Fuzz(func(t *testing.T, specsJSON, argLine string, index int) {
		var specs []cmdspec.ArgSpec
		if err := json.Unmarshal([]byte(specsJSON), &specs); err != nil {
			return
		}
		if index > 64 {
			index %= 64
		}
		if spec := resolveArgSpec(specs, strings.Fields(argLine), index); spec != nil && len(spec.Branches) > 0 {
			t.Fatalf("resolveArgSpec() returned a branching spec %#v", spec)
		}
	})
}
