// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package multitemplate

import (
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/lsigprovider"
)

// ValidateParameterValue validates a single parameter value against its type.
// Supported types:
// - address: 58-char Algorand address with checksum validation
// - uint64: decimal number fitting in uint64
// - bytes: valid hexadecimal string (optionally with length enforcement)
func ValidateParameterValue(value, paramType string, byteLength int) error {
	switch paramType {
	case "address":
		return validateAddress(value)
	case "uint64":
		return validateUint64(value)
	case "bytes":
		return validateBytes(value, byteLength)
	default:
		return fmt.Errorf("unsupported parameter type: %s", paramType)
	}
}

// validateAddress validates an Algorand address.
// Uses the SDK's DecodeAddress which verifies length and checksum.
func validateAddress(value string) error {
	if len(value) != 58 {
		return fmt.Errorf("address must be 58 characters, got %d", len(value))
	}

	_, err := types.DecodeAddress(value)
	if err != nil {
		return fmt.Errorf("invalid address: %w", err)
	}

	return nil
}

// validateUint64 validates a uint64 value in decimal format.
func validateUint64(value string) error {
	if value == "" {
		return fmt.Errorf("value cannot be empty")
	}

	// Check for digits only (no negative numbers, no hex, no scientific notation)
	for _, c := range value {
		if c < '0' || c > '9' {
			return fmt.Errorf("uint64 must contain only digits 0-9, found '%c'", c)
		}
	}

	_, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid uint64: %w", err)
	}

	return nil
}

// validateUint64Constraints checks min/max constraints on a uint64 value.
// Assumes the value has already been validated as a valid uint64.
func validateUint64Constraints(value string, min, max *uint64) error {
	v, _ := strconv.ParseUint(value, 10, 64) // Already validated

	if min != nil && v < *min {
		return fmt.Errorf("value %d is below minimum %d", v, *min)
	}
	if max != nil && v > *max {
		return fmt.Errorf("value %d exceeds maximum %d", v, *max)
	}

	return nil
}

// validateBytes validates a hex-encoded byte string.
// If byteLength > 0, enforces exact byte length (not hex char length).
// Accepts input with or without 0x prefix for convenience.
func validateBytes(value string, byteLength int) error {
	if value == "" {
		return fmt.Errorf("value cannot be empty")
	}

	// Strip 0x prefix if present (user convenience)
	hexValue := value
	if len(value) >= 2 && (value[:2] == "0x" || value[:2] == "0X") {
		hexValue = value[2:]
	}

	// Reject empty hex after prefix strip (e.g., just "0x")
	if hexValue == "" {
		return fmt.Errorf("value cannot be empty")
	}

	// Validate hex characters
	decoded, err := hex.DecodeString(hexValue)
	if err != nil {
		return fmt.Errorf("invalid hex: %w", err)
	}

	// Enforce length if specified
	if byteLength > 0 && len(decoded) != byteLength {
		return fmt.Errorf("expected %d bytes, got %d", byteLength, len(decoded))
	}

	return nil
}

// ValidateParameterSpecs validates a slice of parameter specifications for
// correct names, types, and constraints. Used by both multitemplate and
// falcon1024template validation.
func ValidateParameterSpecs(params []ParameterSpec) error {
	seenNames := make(map[string]bool)
	for _, p := range params {
		if p.Name == "" {
			return fmt.Errorf("parameter name is required")
		}
		if seenNames[p.Name] {
			return fmt.Errorf("duplicate parameter name: %s", p.Name)
		}
		seenNames[p.Name] = true

		switch p.Type {
		case "address", "uint64", "bytes":
			// Valid types
		default:
			return fmt.Errorf("parameter %s has invalid type %q (must be address, uint64, or bytes)", p.Name, p.Type)
		}

		// Validate min/max only apply to uint64
		if (p.Min != nil || p.Max != nil) && p.Type != "uint64" {
			return fmt.Errorf("parameter %s: min/max constraints only valid for uint64 type", p.Name)
		}

		// Validate min <= max if both specified
		if p.Min != nil && p.Max != nil && *p.Min > *p.Max {
			return fmt.Errorf("parameter %s: min (%d) cannot be greater than max (%d)", p.Name, *p.Min, *p.Max)
		}

		// Validate default value if specified
		if p.Default != "" {
			if err := validateDefaultValue(p); err != nil {
				return fmt.Errorf("parameter %s: invalid default: %w", p.Name, err)
			}
		}
	}
	return nil
}

// ValidateRuntimeArgSpecs validates a slice of runtime argument specifications.
// Used by both multitemplate and falcon1024template validation.
func ValidateRuntimeArgSpecs(args []RuntimeArgSpec) error {
	seenNames := make(map[string]bool)
	for _, a := range args {
		if a.Name == "" {
			return fmt.Errorf("runtime_arg name is required")
		}
		if seenNames[a.Name] {
			return fmt.Errorf("duplicate runtime_arg name: %s", a.Name)
		}
		seenNames[a.Name] = true

		switch a.Type {
		case "bytes", "string", "uint64":
			// Valid types
		default:
			return fmt.Errorf("runtime_arg %s has invalid type %q (must be bytes, string, or uint64)", a.Name, a.Type)
		}
	}
	return nil
}

// ValidateParameterValues validates user-provided parameter values against
// parameter definitions. Checks for unknown parameters, missing required
// values, type correctness, byte lengths, and min/max constraints.
// This is the canonical validation function used by both generic templates
// and Falcon DSA compositions.
func ValidateParameterValues(params map[string]string, defs []lsigprovider.ParameterDef) error {
	// Build set of valid parameter names
	validNames := make(map[string]bool)
	for _, def := range defs {
		validNames[def.Name] = true
	}

	// Check for unknown parameters (catches typos like "recepient")
	for name := range params {
		if !validNames[name] {
			return fmt.Errorf("unknown parameter: %s", name)
		}
	}

	// Validate each defined parameter
	for _, def := range defs {
		value, ok := params[def.Name]

		// Check required parameters
		if def.Required && (!ok || value == "") {
			return fmt.Errorf("missing required parameter: %s", def.Name)
		}

		// Skip validation for empty optional parameters
		if !ok || value == "" {
			continue
		}

		// Determine byte length for bytes type (from MaxLength in hex chars)
		byteLength := 0
		if def.Type == "bytes" && def.MaxLength > 0 {
			byteLength = def.MaxLength / 2 // hex chars to bytes
		}

		// Validate the value
		if err := ValidateParameterValue(value, def.Type, byteLength); err != nil {
			return fmt.Errorf("invalid %s: %w", def.Name, err)
		}

		// Check min/max constraints for uint64
		if def.Type == "uint64" && (def.Min != nil || def.Max != nil) {
			if err := validateUint64Constraints(value, def.Min, def.Max); err != nil {
				return fmt.Errorf("invalid %s: %w", def.Name, err)
			}
		}
	}

	return nil
}

// ValidateParameters validates all parameters against a template spec.
// Convenience wrapper around ValidateParameterValues for TemplateSpec callers.
func ValidateParameters(params map[string]string, spec *TemplateSpec) error {
	return ValidateParameterValues(params, ParameterSpecToParameterDefs(spec.Parameters))
}
