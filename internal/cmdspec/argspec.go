// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

// Package cmdspec provides argument specification types shared across packages.
// These types define how command arguments are described for autocomplete and AI prompts.
package cmdspec

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
// When the condition matches, use these specs for subsequent arguments.
type ArgBranch struct {
	When  ArgCondition `json:"when"`  // Condition to activate this branch
	Specs []ArgSpec    `json:"specs"` // ArgSpecs to use when condition matches
}

// ArgSpec describes an argument's autocomplete behavior.
// Used by both core and external plugins to declare their argument types.
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
