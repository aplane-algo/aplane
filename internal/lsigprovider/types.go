// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package lsigprovider

import "errors"

// Sentinel errors.
var (
	// ErrNotTemplate is returned when a provider doesn't implement Template.
	ErrNotTemplate = errors.New("provider is not a generic LogicSig template")
)

// Category constants for LSig types.
// These match the values used in key files and throughout the codebase.
const (
	// CategoryGenericLsig is for template-based LogicSigs without key material.
	// Examples: timelock, hashlock
	CategoryGenericLsig = "generic_lsig"

	// CategoryDSALsig is for DSA-based LogicSigs that require key material.
	// Examples: falcon1024-v1, falcon-timelock-v1
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
	Type        string // "address", "uint64", "string", "bytes"
	Required    bool
	MaxLength   int         // For validation and input field sizing
	InputModes  []InputMode // Optional: alternative input modes (shown as toggle in UI)

	// UI hints
	Example     string // Example value shown in UI (e.g., "1000000")
	Placeholder string // Placeholder text for empty input fields

	// Constraints (for uint64)
	Min *uint64 // Minimum allowed value (nil = no minimum)
	Max *uint64 // Maximum allowed value (nil = no maximum)

	// Default value (applied if user provides empty input for optional params)
	Default string
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
