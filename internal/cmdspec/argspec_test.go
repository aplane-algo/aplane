// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package cmdspec

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

// specTypes returns the type of the spec ArgSpecAt selects at each position
// 0..n-1, with "-" where none applies, failing the test on an error.
func specTypes(t *testing.T, specs []ArgSpec, args []string, n int) []string {
	t.Helper()
	types := make([]string, n)
	for pos := range types {
		spec, err := ArgSpecAt(specs, args, pos)
		if err != nil {
			t.Fatalf("ArgSpecAt(%d) error = %v", pos, err)
		}
		types[pos] = "-"
		if spec != nil {
			types[pos] = spec.Type
		}
	}
	return types
}

func branchTo(arg int, matches string, specs ...ArgSpec) ArgBranch {
	return ArgBranch{When: ArgCondition{Arg: arg, Matches: matches}, Specs: specs}
}

func branching(branches ...ArgBranch) ArgSpec { return ArgSpec{Branches: branches} }

var (
	addressSpec = ArgSpec{Type: ArgTypeAddress}
	keywordSpec = ArgSpec{Type: ArgTypeKeyword}
	numberSpec  = ArgSpec{Type: ArgTypeNumber}
)

func TestArgSpecAtReadsBranches(t *testing.T) {
	tests := []struct {
		name  string
		specs []ArgSpec
		args  []string
		want  []string
	}{
		{
			name:  "plain list, then nothing",
			specs: []ArgSpec{addressSpec, keywordSpec},
			args:  []string{"a", "b", "c"},
			want:  []string{"address", "keyword", "-"},
		},
		{
			name:  "a branch's specs apply from its position on",
			specs: []ArgSpec{keywordSpec, branching(branchTo(0, "^pay$", addressSpec, numberSpec))},
			args:  []string{"pay", "x", "1", "y"},
			want:  []string{"keyword", "address", "number", "-"},
		},
		{
			name:  "the first matching branch wins",
			specs: []ArgSpec{keywordSpec, branching(branchTo(0, "^p", numberSpec), branchTo(0, "^pay$", addressSpec))},
			args:  []string{"pay", "x"},
			want:  []string{"keyword", "number"},
		},
		{
			name:  "no branch matches: nothing at that position or after, specs after the branch included",
			specs: []ArgSpec{keywordSpec, branching(branchTo(0, "^pay$", addressSpec)), numberSpec},
			args:  []string{"info", "x", "1"},
			want:  []string{"keyword", "-", "-"},
		},
		{
			name:  "a condition on an argument not typed does not match",
			specs: []ArgSpec{keywordSpec, branching(branchTo(5, "", addressSpec))},
			args:  []string{"pay", "x"},
			want:  []string{"keyword", "-"},
		},
		{
			name: "a branch later in a branch's specs",
			specs: []ArgSpec{keywordSpec, branching(branchTo(0, "^pay$",
				keywordSpec, branching(branchTo(1, "^to$", addressSpec)),
			))},
			args: []string{"pay", "to", "x"},
			want: []string{"keyword", "keyword", "address"},
		},
		{
			name: "a branch as a branch's first spec",
			specs: []ArgSpec{keywordSpec, branching(branchTo(0, "^pay$",
				branching(branchTo(0, "^info$", numberSpec), branchTo(0, "^pay$", addressSpec, keywordSpec)),
			))},
			args: []string{"pay", "x", "y"},
			want: []string{"keyword", "address", "keyword"},
		},
		{
			name: "three branches deep at the first position",
			specs: []ArgSpec{branching(branchTo(0, "",
				branching(branchTo(0, "",
					branching(branchTo(0, "", addressSpec, numberSpec)),
				)),
			))},
			args: []string{"x", "1"},
			want: []string{"address", "number"},
		},
		{
			name: "a nested branch that matches nothing",
			specs: []ArgSpec{keywordSpec, branching(branchTo(0, "^pay$",
				branching(branchTo(0, "^info$", addressSpec)),
			))},
			args: []string{"pay", "x"},
			want: []string{"keyword", "-"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := specTypes(t, tt.specs, tt.args, len(tt.want)); !slices.Equal(got, tt.want) {
				t.Fatalf("specs by position = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestArgSpecAtNegativePositionHasNoSpec(t *testing.T) {
	spec, err := ArgSpecAt([]ArgSpec{addressSpec}, []string{"a"}, -1)
	if spec != nil || err != nil {
		t.Fatalf("ArgSpecAt(-1) = %v, %v; want nil, nil", spec, err)
	}
}

// Discovery refuses these; ArgSpecAt reports them rather than panic.
func TestArgSpecAtReportsBranchesItCannotRead(t *testing.T) {
	tests := []struct {
		name  string
		specs []ArgSpec
		args  []string
		pos   int
		want  string
	}{
		{
			name:  "negative index",
			specs: []ArgSpec{keywordSpec, branching(branchTo(-1, "", addressSpec))},
			args:  []string{"a", "b"},
			pos:   1,
			want:  "argument 1: branches[0]: when.arg is -1; an argument index must not be negative",
		},
		{
			name:  "pattern that does not compile",
			specs: []ArgSpec{keywordSpec, branching(branchTo(0, "^a$", numberSpec), branchTo(0, "(a", addressSpec))},
			args:  []string{"b", "c"},
			pos:   1,
			want:  "argument 1: branches[1]: when.matches does not compile",
		},
		{
			name:  "branch without specs",
			specs: []ArgSpec{branching(branchTo(0, ""))},
			args:  []string{"a"},
			pos:   0,
			want:  "argument 0: branches[0]: specs is empty; a branch needs at least one spec",
		},
		{
			name:  "nested as a branch's first spec",
			specs: []ArgSpec{keywordSpec, branching(branchTo(0, "", branching(branchTo(-2, "", addressSpec))))},
			args:  []string{"a", "b"},
			pos:   1,
			want:  "argument 1: branches[0]: when.arg is -2",
		},
		{
			name:  "a later position walks through the defect",
			specs: []ArgSpec{branching(branchTo(0, ""))},
			args:  []string{"a", "b"},
			pos:   1,
			want:  "argument 0: branches[0]: specs is empty",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, err := ArgSpecAt(tt.specs, tt.args, tt.pos)
			if spec != nil || err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("ArgSpecAt() = %v, %v; want nil and an error containing %q", spec, err, tt.want)
			}
			if err := ValidateArgSpecs(tt.specs, "arg_specs"); err == nil {
				t.Fatal("ValidateArgSpecs() accepted specs ArgSpecAt cannot read")
			}
		})
	}
}

func TestValidateArgSpecsNamesTheBranch(t *testing.T) {
	specs := []ArgSpec{keywordSpec, branching(
		branchTo(0, "^a$", addressSpec),
		branchTo(0, "^b$", keywordSpec, branching(branchTo(1, "[0-", addressSpec))),
	)}
	err := ValidateArgSpecs(specs, "arg_specs")
	want := "arg_specs[1].branches[1].specs[1].branches[0]: when.matches does not compile"
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("ValidateArgSpecs() error = %v, want %q", err, want)
	}
}

// FuzzArgSpecAt feeds arbitrary specs, arguments and positions to the
// resolver: it must never panic or return a branching spec, and specs that
// pass ValidateArgSpecs must never give it an error.
func FuzzArgSpecAt(f *testing.F) {
	for _, seed := range []struct {
		specs, args string
		pos         int
	}{
		{`[{"type":"address"}]`, "", 0},
		{`[{"branches":[{"when":{"arg":-1,"matches":""},"specs":[{"type":"address"}]}]}]`, "", 0},
		{`[{"type":"keyword"},{"branches":[{"when":{"arg":0,"matches":"^a$"},"specs":[]}]}]`, "a", 3},
		{`[{"type":"keyword"},{"branches":[{"when":{"arg":0,"matches":"("},"specs":[{"type":"address"}]}]}]`, "a", 1},
		{`[{"branches":[{"when":{"arg":0,"matches":""},"specs":[{"branches":[{"when":{"arg":1,"matches":"."},"specs":[{"type":"address"}]}]}]}]}]`, "a b c", 2},
		{`[{"branches":[{"when":{"arg":9223372036854775807,"matches":""},"specs":[{"type":"address"}]}]}]`, "a", 0},
		{`[{"type":"number"}]`, "a b", -4},
	} {
		f.Add(seed.specs, seed.args, seed.pos)
	}
	f.Fuzz(func(t *testing.T, specsJSON, argLine string, pos int) {
		var specs []ArgSpec
		if err := json.Unmarshal([]byte(specsJSON), &specs); err != nil {
			return
		}
		if pos > 64 {
			pos %= 64
		}
		spec, err := ArgSpecAt(specs, strings.Fields(argLine), pos)
		if spec != nil && len(spec.Branches) > 0 {
			t.Fatalf("ArgSpecAt() returned a branching spec %#v", spec)
		}
		if err != nil && ValidateArgSpecs(specs, "arg_specs") == nil {
			t.Fatalf("ArgSpecAt() error = %v for specs ValidateArgSpecs accepts", err)
		}
	})
}
