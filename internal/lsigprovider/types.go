// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package lsigprovider

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// Sentinel errors.
var (
	// ErrNotTemplate is returned when a provider doesn't implement Template.
	ErrNotTemplate = errors.New("provider is not a generic LogicSig template")
)

// Category constants for LSig types.
// These match the values used in key files and throughout the codebase.
const (
	// CategoryGenericLsig is for template-based LogicSigs without key material.
	// Examples: timed-whitelist, htlc
	CategoryGenericLsig = "generic_lsig"

	// CategoryDSALsig is for DSA-based LogicSigs that require key material.
	// Examples: aplane.falcon1024.v1, falcon-aplane.timed-whitelist.v1
	CategoryDSALsig = "dsa_lsig"
)

// InputMode defines an alternative way to provide a parameter value.
// When a parameter has multiple InputModes, the TUI shows a toggle to select between them.
type InputMode struct {
	Name       string // Internal name (e.g., "hash", "preimage")
	Label      string // Display label (e.g., "SHA256 Hash", "Preimage (will be hashed)")
	Transform  string // Transformation to apply: "", "sha256"
	ByteLength int    // Expected input byte length (0 = use parent MaxLength)
	InputType  string // Override input type: "string" for text, "" to inherit parent Type
}

// ParameterDef describes a parameter for LSig creation.
// This is used by UIs to dynamically render input fields.
type ParameterDef struct {
	Name        string // Internal name (e.g., "recipient", "unlock_round")
	Label       string // Human-readable label (e.g., "Recipient Address")
	Description string // Description for UI tooltips
	Type        string // "address", "address[]", "uint64", "uint64[]", "string", "bytes"
	Required    bool
	MaxLength   int         // For validation and input field sizing
	InputModes  []InputMode // Optional: alternative input modes (shown as toggle in UI)
	Options     []string    // Optional fixed option values for selection-style params
	MinItems    int         // For list types only (0 = no minimum)
	MaxItems    int         // For list types only (0 = no maximum)

	// UI hints
	Example     string // Example value shown in UI (e.g., "1000000")
	Placeholder string // Placeholder text for empty input fields

	// Constraints (for uint64)
	Min *uint64 // Minimum allowed value (nil = no minimum)
	Max *uint64 // Maximum allowed value (nil = no maximum)

	// Default value (applied if user provides empty input for optional params)
	Default string
}

// IsList reports whether the parameter type is a list type such as "address[]".
func (p ParameterDef) IsList() bool {
	return len(p.Type) > 2 && p.Type[len(p.Type)-2:] == "[]"
}

// ElementType returns the scalar element type for list parameters.
// For non-list parameters it returns the parameter type unchanged.
func (p ParameterDef) ElementType() string {
	if p.IsList() {
		return p.Type[:len(p.Type)-2]
	}
	return p.Type
}

// NormalizeCreationParams returns a copy of params with canonical formatting for
// parameters whose definitions require it. address[] and uint64[] values are
// unordered by definition and are sorted before validation or TEAL generation.
// Nil params remain nil to preserve caller intent.
func NormalizeCreationParams(params map[string]string, defs []ParameterDef) (map[string]string, error) {
	if params == nil {
		return nil, nil
	}

	normalized := make(map[string]string, len(params))
	for name, value := range params {
		normalized[name] = value
	}

	for _, def := range defs {
		value, ok := normalized[def.Name]
		if !ok || value == "" {
			continue
		}
		switch def.Type {
		case "address[]":
			items, err := splitListParam(value)
			if err != nil {
				return nil, fmt.Errorf("invalid %s: %w", def.Name, err)
			}
			sort.Strings(items)
			normalized[def.Name] = strings.Join(items, ",")
		case "uint64[]":
			items, err := splitListParam(value)
			if err != nil {
				return nil, fmt.Errorf("invalid %s: %w", def.Name, err)
			}
			if err := sortUint64Strings(items); err != nil {
				return nil, fmt.Errorf("invalid %s: %w", def.Name, err)
			}
			normalized[def.Name] = strings.Join(items, ",")
		}
	}

	return normalized, nil
}

func splitListParam(value string) ([]string, error) {
	parts := strings.Split(value, ",")
	items := make([]string, 0, len(parts))
	for _, part := range parts {
		item := strings.TrimSpace(part)
		if item == "" {
			return nil, fmt.Errorf("list contains an empty item")
		}
		items = append(items, item)
	}
	return items, nil
}

func sortUint64Strings(items []string) error {
	values := make([]uint64, 0, len(items))
	for _, item := range items {
		value, err := strconv.ParseUint(item, 10, 64)
		if err != nil {
			return fmt.Errorf("list item %q is not a valid uint64: %w", item, err)
		}
		values = append(values, value)
	}
	slices.Sort(values)
	for i, value := range values {
		items[i] = strconv.FormatUint(value, 10)
	}
	return nil
}

// RuntimeArgDef describes an argument required at transaction signing time.
// Unlike creation parameters (set at LSig creation), RuntimeArgs are provided
// when spending from the LogicSig address.
type RuntimeArgDef struct {
	Name        string // Internal name used in --lsig-arg (e.g., "preimage")
	Label       string // Human-readable label (e.g., "Secret Preimage")
	Description string // Description for help text
	Type        string // "bytes" (hex-encoded), "string", "uint64"
	Required    bool   // If true, transaction will fail without this arg
	ByteLength  int    // Expected byte length (0 = variable)
}

// ValidateAndOrderArgs validates runtime args against their definitions and returns
// them in declaration order. Rejects unknown arg names, enforces required args,
// and validates byte lengths.
func ValidateAndOrderArgs(argDefs []RuntimeArgDef, runtimeArgs map[string][]byte) ([][]byte, error) {
	// Reject unknown arg names
	validNames := make(map[string]bool, len(argDefs))
	for _, def := range argDefs {
		validNames[def.Name] = true
	}
	for name := range runtimeArgs {
		if !validNames[name] {
			return nil, fmt.Errorf("unknown arg: %s", name)
		}
	}

	var args [][]byte
	for _, argDef := range argDefs {
		val, ok := runtimeArgs[argDef.Name]
		if !ok {
			if argDef.Required {
				return nil, fmt.Errorf("missing required arg: %s", argDef.Name)
			}
			continue
		}
		if argDef.ByteLength > 0 && len(val) != argDef.ByteLength {
			return nil, fmt.Errorf("arg %s: expected %d bytes, got %d", argDef.Name, argDef.ByteLength, len(val))
		}
		args = append(args, val)
	}
	return args, nil
}
