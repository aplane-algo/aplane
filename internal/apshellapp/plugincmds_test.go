// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/cmdspec"
	"github.com/aplane-algo/aplane/internal/plugin/discovery"
	"github.com/aplane-algo/aplane/internal/plugin/jsonrpc"
	"github.com/aplane-algo/aplane/internal/plugin/manifest"
)

func TestNormalizePluginAddressArgs(t *testing.T) {
	specs := []cmdspec.ArgSpec{
		{Type: cmdspec.ArgTypeAddress},
		{Type: cmdspec.ArgTypeKeyword},
		{Type: cmdspec.ArgTypeFile},
	}
	args := []string{
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaay5hfkq",
		"to",
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}

	got, err := normalizePluginAddressArgs(specs, args)
	if err != nil {
		t.Fatalf("normalizePluginAddressArgs() error = %v", err)
	}

	if got[0] != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ" {
		t.Fatalf("arg0 = %q, want uppercase address", got[0])
	}
	if got[1] != "to" {
		t.Fatalf("arg1 = %q, want unchanged keyword", got[1])
	}
	if got[2] != "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" {
		t.Fatalf("arg2 = %q, want unchanged non-address", got[2])
	}
}

func TestValidatePluginResult(t *testing.T) {
	tests := []struct {
		name    string
		result  *jsonrpc.ExecuteResult
		wantErr bool
	}{
		{name: "success with txns", result: &jsonrpc.ExecuteResult{Success: true, Transactions: []jsonrpc.TransactionIntent{{Type: "raw"}}}},
		{name: "failure without txns", result: &jsonrpc.ExecuteResult{Success: false, Message: "nope"}},
		{name: "failure with txns", result: &jsonrpc.ExecuteResult{Success: false, Transactions: []jsonrpc.TransactionIntent{{Type: "raw"}}}, wantErr: true},
		{name: "failure with continuation", result: &jsonrpc.ExecuteResult{Success: false, Continuation: &jsonrpc.Continuation{Command: "next"}}, wantErr: true},
		{name: "empty continuation command", result: &jsonrpc.ExecuteResult{Success: true, Continuation: &jsonrpc.Continuation{}}, wantErr: true},
		{name: "nil result", result: nil, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePluginResult(tt.result)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validatePluginResult() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNormalizePluginCommandArgs(t *testing.T) {
	plugin := &discovery.Plugin{
		Manifest: &manifest.Manifest{
			Commands: []manifest.Command{{
				Name: "next",
				ArgSpecs: []cmdspec.ArgSpec{
					{Type: cmdspec.ArgTypeAddress},
					{Type: cmdspec.ArgTypeKeyword},
				},
			}},
		},
	}

	got, err := normalizePluginCommandArgs(plugin, "next", []string{
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaay5hfkq",
		"to",
	})
	if err != nil {
		t.Fatalf("normalizePluginCommandArgs() error = %v", err)
	}

	if got[0] != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ" {
		t.Fatalf("arg0 = %q, want uppercase address", got[0])
	}
	if got[1] != "to" {
		t.Fatalf("arg1 = %q, want unchanged keyword", got[1])
	}
}

// The manifest loader refuses these specs; argument normalization still has
// to answer them with an error, not a panic, for specs that did not come
// through it.
func TestNormalizePluginArgsRefusesUnreadableBranches(t *testing.T) {
	keywordThen := func(branches ...cmdspec.ArgBranch) []cmdspec.ArgSpec {
		return []cmdspec.ArgSpec{{Type: cmdspec.ArgTypeKeyword}, {Branches: branches}}
	}
	address := []cmdspec.ArgSpec{{Type: cmdspec.ArgTypeAddress}}
	tests := []struct {
		name  string
		specs []cmdspec.ArgSpec
		args  []string
		want  string
	}{
		{
			name:  "negative index",
			specs: keywordThen(cmdspec.ArgBranch{When: cmdspec.ArgCondition{Arg: -1, Matches: "^a$"}, Specs: address}),
			args:  []string{"a", "b"},
			want:  "when.arg is -1",
		},
		{
			name:  "matching branch without specs",
			specs: keywordThen(cmdspec.ArgBranch{When: cmdspec.ArgCondition{Arg: 0, Matches: "^a$"}}),
			args:  []string{"a", "b"},
			want:  "has no specs",
		},
		{
			name:  "pattern that does not compile",
			specs: keywordThen(cmdspec.ArgBranch{When: cmdspec.ArgCondition{Arg: 0, Matches: "(a"}, Specs: address}),
			args:  []string{"a", "b"},
			want:  "when.matches does not compile",
		},
		{
			name: "negative index in a nested branch",
			specs: keywordThen(cmdspec.ArgBranch{When: cmdspec.ArgCondition{Arg: 0, Matches: "^a$"}, Specs: []cmdspec.ArgSpec{
				{Type: cmdspec.ArgTypeKeyword},
				{Branches: []cmdspec.ArgBranch{{When: cmdspec.ArgCondition{Arg: -3, Matches: ""}, Specs: address}}},
			}}),
			args: []string{"a", "b", "c"},
			want: "when.arg is -3",
		},
		{
			name: "empty nested branch",
			specs: keywordThen(cmdspec.ArgBranch{When: cmdspec.ArgCondition{Arg: 0, Matches: "^a$"}, Specs: []cmdspec.ArgSpec{
				{Type: cmdspec.ArgTypeKeyword},
				{Branches: []cmdspec.ArgBranch{{When: cmdspec.ArgCondition{Arg: 2, Matches: "^c$"}}}},
			}}),
			args: []string{"a", "b", "c"},
			want: "has no specs",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := normalizePluginAddressArgs(tt.specs, tt.args)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("normalizePluginAddressArgs() error = %v, want %q", err, tt.want)
			}

			plugin := &discovery.Plugin{Manifest: &manifest.Manifest{
				Name:     "branchy",
				Commands: []manifest.Command{{Name: "go", ArgSpecs: tt.specs}},
			}}
			_, err = NormalizePluginCommandArgs(plugin, "go", tt.args)
			if err == nil || !strings.Contains(err.Error(), "plugin 'branchy' command 'go': arg_specs: ") {
				t.Fatalf("NormalizePluginCommandArgs() error = %v, want it to name the plugin and command", err)
			}
		})
	}
}

func TestNormalizePluginArgsFollowsNestedBranches(t *testing.T) {
	specs := []cmdspec.ArgSpec{
		{Type: cmdspec.ArgTypeKeyword},
		{Branches: []cmdspec.ArgBranch{{
			When: cmdspec.ArgCondition{Arg: 0, Matches: "^pay$"},
			Specs: []cmdspec.ArgSpec{
				{Type: cmdspec.ArgTypeKeyword},
				{Branches: []cmdspec.ArgBranch{{
					When:  cmdspec.ArgCondition{Arg: 1, Matches: "^to$"},
					Specs: []cmdspec.ArgSpec{{Type: cmdspec.ArgTypeAddress}},
				}}},
			},
		}}},
	}
	lower := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaay5hfkq"

	got, err := normalizePluginAddressArgs(specs, []string{"pay", "to", lower})
	if err != nil {
		t.Fatalf("normalizePluginAddressArgs() error = %v", err)
	}
	if got[2] != strings.ToUpper(lower) {
		t.Fatalf("arg2 = %q, want the nested address uppercased", got[2])
	}
}

// FuzzNormalizePluginAddressArgs feeds arbitrary arg_specs and arguments to
// the normalizer: it may refuse them, but must never panic.
func FuzzNormalizePluginAddressArgs(f *testing.F) {
	for _, seed := range []struct{ specs, args string }{
		{`[{"type":"address"}]`, "x"},
		{`[{"type":"keyword"},{"branches":[{"when":{"arg":-1,"matches":"^a$"},"specs":[{"type":"address"}]}]}]`, "a b"},
		{`[{"type":"keyword"},{"branches":[{"when":{"arg":0,"matches":"^a$"},"specs":[]}]}]`, "a b c"},
		{`[{"branches":[{"when":{"arg":0,"matches":"("},"specs":[{"type":"address"}]}]}]`, "a"},
		{`[{"branches":[{"when":{"arg":0,"matches":""},"specs":[{"branches":[{"when":{"arg":5,"matches":"."},"specs":[{"type":"address"}]}]}]}]}]`, "a b c d e f g"},
		{`[{"branches":[{"when":{"arg":9223372036854775807,"matches":""},"specs":[{"type":"address"}]}]}]`, "a"},
	} {
		f.Add(seed.specs, seed.args)
	}
	f.Fuzz(func(t *testing.T, specsJSON, argLine string) {
		var specs []cmdspec.ArgSpec
		if err := json.Unmarshal([]byte(specsJSON), &specs); err != nil {
			return
		}
		args := strings.Fields(argLine)
		got, err := normalizePluginAddressArgs(specs, args)
		if err == nil && len(got) != len(args) {
			t.Fatalf("normalizePluginAddressArgs() returned %d args for %d", len(got), len(args))
		}
	})
}
