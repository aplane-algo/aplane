// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"slices"
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

	got := normalizePluginCommandArgs(plugin, "next", []string{
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaay5hfkq",
		"to",
	})

	if got[0] != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ" {
		t.Fatalf("arg0 = %q, want uppercase address", got[0])
	}
	if got[1] != "to" {
		t.Fatalf("arg1 = %q, want unchanged keyword", got[1])
	}
}

const lowerPluginAddress = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaay5hfkq"

// captureDebugLog sends slog's default logger to a buffer at debug level for
// the rest of the test.
func captureDebugLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })
	var out bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&out, &slog.HandlerOptions{Level: slog.LevelDebug})))
	return &out
}

// The manifest loader refuses these specs. Normalization only uppercases
// addresses, so for specs that did not come through the loader it leaves the
// arguments from the unreadable branch on as typed, logs why at debug level,
// and still hands the arguments over.
func TestNormalizePluginArgsPassesArgumentsAtAnUnreadableBranchAsTyped(t *testing.T) {
	upper := strings.ToUpper(lowerPluginAddress)
	addressThen := func(branches ...cmdspec.ArgBranch) []cmdspec.ArgSpec {
		return []cmdspec.ArgSpec{{Type: cmdspec.ArgTypeAddress}, {Branches: branches}}
	}
	address := []cmdspec.ArgSpec{{Type: cmdspec.ArgTypeAddress}}
	tests := []struct {
		name  string
		specs []cmdspec.ArgSpec
		args  []string
		want  []string
		log   string
	}{
		{
			name:  "negative index",
			specs: addressThen(cmdspec.ArgBranch{When: cmdspec.ArgCondition{Arg: -1, Matches: ""}, Specs: address}),
			args:  []string{lowerPluginAddress, lowerPluginAddress},
			want:  []string{upper, lowerPluginAddress},
			log:   "argument 1: branches[0]: when.arg is -1",
		},
		{
			name:  "matching branch without specs",
			specs: addressThen(cmdspec.ArgBranch{When: cmdspec.ArgCondition{Arg: 0, Matches: ""}}),
			args:  []string{lowerPluginAddress, lowerPluginAddress},
			want:  []string{upper, lowerPluginAddress},
			log:   "specs is empty",
		},
		{
			name:  "pattern that does not compile",
			specs: addressThen(cmdspec.ArgBranch{When: cmdspec.ArgCondition{Arg: 0, Matches: "(a"}, Specs: address}),
			args:  []string{lowerPluginAddress, lowerPluginAddress},
			want:  []string{upper, lowerPluginAddress},
			log:   "when.matches does not compile",
		},
		{
			name: "negative index in a nested branch",
			specs: []cmdspec.ArgSpec{{Type: cmdspec.ArgTypeKeyword}, {Branches: []cmdspec.ArgBranch{{
				When: cmdspec.ArgCondition{Arg: 0, Matches: "^a$"},
				Specs: []cmdspec.ArgSpec{
					{Type: cmdspec.ArgTypeAddress},
					{Branches: []cmdspec.ArgBranch{{When: cmdspec.ArgCondition{Arg: -3, Matches: ""}, Specs: address}}},
				},
			}}}},
			args: []string{"a", lowerPluginAddress, lowerPluginAddress},
			want: []string{"a", upper, lowerPluginAddress},
			log:  "argument 2: branches[0]: when.arg is -3",
		},
		{
			name: "empty branch nested as a branch's first spec",
			specs: []cmdspec.ArgSpec{{Type: cmdspec.ArgTypeAddress}, {Branches: []cmdspec.ArgBranch{{
				When:  cmdspec.ArgCondition{Arg: 0, Matches: ""},
				Specs: []cmdspec.ArgSpec{{Branches: []cmdspec.ArgBranch{{When: cmdspec.ArgCondition{Arg: 0, Matches: ""}}}}},
			}}}},
			args: []string{lowerPluginAddress, lowerPluginAddress},
			want: []string{upper, lowerPluginAddress},
			log:  "specs is empty",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logged := captureDebugLog(t)
			plugin := &discovery.Plugin{Manifest: &manifest.Manifest{
				Name:     "branchy",
				Commands: []manifest.Command{{Name: "go", ArgSpecs: tt.specs}},
			}}
			got := NormalizePluginCommandArgs(plugin, "go", tt.args)
			if !slices.Equal(got, tt.want) {
				t.Fatalf("NormalizePluginCommandArgs() = %q, want %q", got, tt.want)
			}
			for _, want := range []string{"level=DEBUG", "component=plugins", "plugin=branchy", "command=go", tt.log} {
				if !strings.Contains(logged.String(), want) {
					t.Fatalf("log = %q, want it to contain %q", logged.String(), want)
				}
			}
		})
	}
}

// recordingPluginRuntime finds one plugin for every command and records the
// arguments each command is run with.
type recordingPluginRuntime struct {
	fakePluginRuntime
	plugin *discovery.Plugin
	ran    [][]string
}

func (r *recordingPluginRuntime) FindByCommand(string) (*discovery.Plugin, error) {
	return r.plugin, nil
}

func (r *recordingPluginRuntime) ExecuteCommand(_, _ string, args []string, _ jsonrpc.Context) (*jsonrpc.ExecuteResult, error) {
	r.ran = append(r.ran, args)
	return &jsonrpc.ExecuteResult{Success: true}, nil
}

// A plugin command, or a continuation step after earlier steps submitted
// transactions, is not refused for a spec normalization cannot read.
func TestPluginCommandsRunDespiteAnUnreadableBranch(t *testing.T) {
	captureDebugLog(t)
	specs := []cmdspec.ArgSpec{{Type: cmdspec.ArgTypeAddress}, {Branches: []cmdspec.ArgBranch{
		{When: cmdspec.ArgCondition{Arg: -1, Matches: ""}, Specs: []cmdspec.ArgSpec{{Type: cmdspec.ArgTypeAddress}}},
	}}}
	plugin := &discovery.Plugin{Manifest: &manifest.Manifest{
		Name:     "branchy",
		Commands: []manifest.Command{{Name: "go", ArgSpecs: specs}},
	}}
	plugins := &recordingPluginRuntime{plugin: plugin}
	app := newEndpointTestApp(t, t.TempDir())
	app.Plugins = plugins
	args := []string{lowerPluginAddress, lowerPluginAddress}
	want := []string{strings.ToUpper(lowerPluginAddress), lowerPluginAddress}

	if _, err := app.ExecutePluginCommand(context.Background(), "go", args); err != nil {
		t.Fatalf("ExecutePluginCommand() error = %v", err)
	}
	if _, err := app.ContinuePluginCommand(context.Background(), plugin, &jsonrpc.Continuation{Command: "go", Args: args}); err != nil {
		t.Fatalf("ContinuePluginCommand() error = %v", err)
	}
	if len(plugins.ran) != 2 || !slices.Equal(plugins.ran[0], want) || !slices.Equal(plugins.ran[1], want) {
		t.Fatalf("plugin ran with %q, want %q twice", plugins.ran, want)
	}
}

// A branch whose first spec branches again is followed, at any depth.
func TestNormalizePluginArgsFollowsNestedBranches(t *testing.T) {
	address := []cmdspec.ArgSpec{{Type: cmdspec.ArgTypeAddress}}
	tests := []struct {
		name  string
		specs []cmdspec.ArgSpec
		args  []string
		at    int
	}{
		{
			name: "after a keyword",
			specs: []cmdspec.ArgSpec{
				{Type: cmdspec.ArgTypeKeyword},
				{Branches: []cmdspec.ArgBranch{{
					When: cmdspec.ArgCondition{Arg: 0, Matches: "^pay$"},
					Specs: []cmdspec.ArgSpec{
						{Type: cmdspec.ArgTypeKeyword},
						{Branches: []cmdspec.ArgBranch{{When: cmdspec.ArgCondition{Arg: 1, Matches: "^to$"}, Specs: address}}},
					},
				}}},
			},
			args: []string{"pay", "to", lowerPluginAddress},
			at:   2,
		},
		{
			name: "as the branch's first spec",
			specs: []cmdspec.ArgSpec{
				{Type: cmdspec.ArgTypeKeyword},
				{Branches: []cmdspec.ArgBranch{{
					When: cmdspec.ArgCondition{Arg: 0, Matches: "^pay$"},
					Specs: []cmdspec.ArgSpec{{Branches: []cmdspec.ArgBranch{
						{When: cmdspec.ArgCondition{Arg: 0, Matches: "^info$"}, Specs: []cmdspec.ArgSpec{{Type: cmdspec.ArgTypeNumber}}},
						{When: cmdspec.ArgCondition{Arg: 0, Matches: "^pay$"}, Specs: address},
					}}},
				}}},
			},
			args: []string{"pay", lowerPluginAddress},
			at:   1,
		},
		{
			name: "three deep at one position",
			specs: []cmdspec.ArgSpec{{Branches: []cmdspec.ArgBranch{{
				When: cmdspec.ArgCondition{Arg: 0, Matches: ""},
				Specs: []cmdspec.ArgSpec{{Branches: []cmdspec.ArgBranch{{
					When:  cmdspec.ArgCondition{Arg: 0, Matches: ""},
					Specs: []cmdspec.ArgSpec{{Branches: []cmdspec.ArgBranch{{When: cmdspec.ArgCondition{Arg: 0, Matches: ""}, Specs: address}}}},
				}}}},
			}}}},
			args: []string{lowerPluginAddress},
			at:   0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizePluginAddressArgs(tt.specs, tt.args)
			if err != nil {
				t.Fatalf("normalizePluginAddressArgs() error = %v", err)
			}
			if got[tt.at] != strings.ToUpper(lowerPluginAddress) {
				t.Fatalf("arg%d = %q, want the nested address uppercased", tt.at, got[tt.at])
			}
		})
	}
}

// FuzzNormalizePluginAddressArgs feeds arbitrary arg_specs and arguments to
// the normalizer: it must never panic, and always hands back every argument.
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
		if got, _ := normalizePluginAddressArgs(specs, args); len(got) != len(args) {
			t.Fatalf("normalizePluginAddressArgs() returned %d args for %d", len(got), len(args))
		}
	})
}
