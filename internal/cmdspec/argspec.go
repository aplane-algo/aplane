// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package cmdspec provides argument specification types shared across packages.
// These types define how command arguments are described for autocomplete and AI prompts.
package cmdspec

import (
	"errors"
	"fmt"
	"regexp"
)

// ArgType constants for autocomplete argument types
const (
	ArgTypeAddress = "address" // Algorand address (supports aliases)
	ArgTypeAsset   = "asset"   // ASA unit name or "algo"
	ArgTypeSet     = "set"     // Set name (with @ prefix)
	ArgTypeKeyword = "keyword" // Fixed keyword values
	ArgTypeNumber  = "number"  // Numeric value (no completion)
	ArgTypeFile    = "file"    // File path
	ArgTypeCustom  = "custom"  // Plugin-provided completion via RPC
)

// ArgCondition specifies when a branch should be activated.
// Matches against a previous argument using a regex pattern.
type ArgCondition struct {
	Arg     int    `json:"arg"`     // Argument index to check (0-based)
	Matches string `json:"matches"` // Regex pattern to match against
}

// ArgBranch represents a conditional branch in ArgSpecs.
// When the condition matches, these specs apply from the branching spec's
// position on (see ArgSpecAt).
type ArgBranch struct {
	When  ArgCondition `json:"when"`  // Condition to activate this branch
	Specs []ArgSpec    `json:"specs"` // ArgSpecs to use when condition matches
}

// ArgSpec describes an argument's autocomplete behavior.
// Used by external plugins to declare their argument types.
//
// Simple usage (non-branching):
//
//	ArgSpec{Type: ArgTypeAddress}
//	ArgSpec{Type: ArgTypeKeyword, Values: []string{"deposit", "withdraw"}}
//
// Branching usage (context-dependent completion):
//
//	ArgSpec{Branches: []ArgBranch{
//	    {When: ArgCondition{Arg: 0, Matches: "^deposit$"}, Specs: [...]},
//	    {When: ArgCondition{Arg: 0, Matches: "^withdraw$"}, Specs: [...]},
//	}}
type ArgSpec struct {
	Type     string      `json:"type,omitempty"`     // One of ArgType* constants
	Values   []string    `json:"values,omitempty"`   // For "keyword": valid values; for "custom": completer identifier
	Branches []ArgBranch `json:"branches,omitempty"` // Conditional branches (if set, Type is ignored)
}

// ArgSpecAt returns the spec that applies to the argument at position pos,
// with args the arguments typed (the command name excluded). It is the one
// reading of branches: plugin argument normalization and tab completion both
// use it.
//
// Specs apply by position. A spec with branches stands for the first of its
// branches whose when.matches matches args[when.arg]; that branch's specs
// then apply from the branching spec's position on, in place of the rest of
// the list it was in, and the first of them may branch again. When no branch
// matches, no spec applies at that position or after it.
//
// It returns nil when no spec applies, and an error naming a branch it cannot
// read: a negative when.arg, a when.matches that does not compile, or no
// specs. Discovery refuses those (ValidateArgSpecs); the checks are repeated
// here for specs that did not come through it.
func ArgSpecAt(specs []ArgSpec, args []string, pos int) (*ArgSpec, error) {
	if pos < 0 {
		return nil, nil
	}
	current, start := specs, 0 // current applies from position start on
	for i := 0; ; i++ {
		if i-start >= len(current) {
			return nil, nil
		}
		spec := current[i-start]
		for len(spec.Branches) > 0 {
			branch, err := matchBranch(spec.Branches, args)
			if err != nil {
				return nil, fmt.Errorf("argument %d: %w", i, err)
			}
			if branch == nil {
				return nil, nil
			}
			current, start = branch.Specs, i
			spec = current[0]
		}
		if i == pos {
			return &spec, nil
		}
	}
}

// matchBranch returns the first branch whose condition matches args, or nil.
// Each branch it reaches is checked as discovery checks it.
func matchBranch(branches []ArgBranch, args []string) (*ArgBranch, error) {
	for j := range branches {
		branch := &branches[j]
		pattern, err := branch.pattern()
		if err != nil {
			return nil, fmt.Errorf("branches[%d]: %w", j, err)
		}
		if branch.When.Arg < len(args) && pattern.MatchString(args[branch.When.Arg]) {
			return branch, nil
		}
	}
	return nil, nil
}

// pattern checks the branch for what ArgSpecAt needs to read it and returns
// its compiled when.matches.
func (b *ArgBranch) pattern() (*regexp.Regexp, error) {
	if b.When.Arg < 0 {
		return nil, fmt.Errorf("when.arg is %d; an argument index must not be negative", b.When.Arg)
	}
	pattern, err := regexp.Compile(b.When.Matches)
	if err != nil {
		return nil, fmt.Errorf("when.matches does not compile: %w", err)
	}
	if len(b.Specs) == 0 {
		return nil, errors.New("specs is empty; a branch needs at least one spec")
	}
	return pattern, nil
}

// ValidateArgSpecs checks every branch in specs, nested ones included, for
// what ArgSpecAt needs to read it. path names specs in the error, as in
// "arg_specs[1].branches[0]: when.arg is -1; ...".
func ValidateArgSpecs(specs []ArgSpec, path string) error {
	for i := range specs {
		for j := range specs[i].Branches {
			branch := &specs[i].Branches[j]
			at := fmt.Sprintf("%s[%d].branches[%d]", path, i, j)
			if _, err := branch.pattern(); err != nil {
				return fmt.Errorf("%s: %w", at, err)
			}
			if err := ValidateArgSpecs(branch.Specs, at+".specs"); err != nil {
				return err
			}
		}
	}
	return nil
}
