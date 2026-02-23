// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

// Package tealsubst provides shared TEAL variable substitution utilities.
// Both generic templates (multitemplate) and Falcon DSA compositions use
// this package for @variable_name substitution in TEAL source.
package tealsubst

import (
	"fmt"
	"regexp"
	"sort"
)

// variablePattern matches @variable_name in TEAL source.
var variablePattern = regexp.MustCompile(`@([a-zA-Z_][a-zA-Z0-9_]*)`)

// ParamDef holds the name and type of a parameter for TEAL substitution.
type ParamDef struct {
	Name string
	Type string
}

// ExtractVariables extracts all unique variable names from TEAL source.
// Variables are identified by the pattern @variable_name.
// Returns a sorted list of unique variable names.
func ExtractVariables(teal string) []string {
	matches := variablePattern.FindAllStringSubmatch(teal, -1)
	seen := make(map[string]bool)
	var vars []string

	for _, match := range matches {
		if len(match) >= 2 {
			varName := match[1]
			if !seen[varName] {
				seen[varName] = true
				vars = append(vars, varName)
			}
		}
	}

	sort.Strings(vars)
	return vars
}

// SubstituteVariables replaces @variable_name placeholders in TEAL source
// with the corresponding values from the params map.
// Values are formatted appropriately for TEAL based on parameter type:
//   - addresses and uint64 values are inserted as-is
//   - bytes values are prefixed with 0x
//
// Returns an error if a variable referenced in TEAL is not found in params.
func SubstituteVariables(teal string, params map[string]string, paramDefs []ParamDef) (string, error) {
	paramTypes := make(map[string]string)
	for _, p := range paramDefs {
		paramTypes[p.Name] = p.Type
	}

	var substituteErr error

	result := variablePattern.ReplaceAllStringFunc(teal, func(match string) string {
		varName := match[1:]

		value, ok := params[varName]
		if !ok {
			substituteErr = fmt.Errorf("variable @%s referenced in TEAL but not found in parameters", varName)
			return match
		}

		paramType, hasType := paramTypes[varName]
		if !hasType {
			return value
		}

		return FormatValueForTEAL(value, paramType)
	})

	if substituteErr != nil {
		return "", substituteErr
	}

	return result, nil
}

// FormatValueForTEAL formats a parameter value appropriately for TEAL source.
//   - address: inserted as-is (TEAL addr opcode expects base32)
//   - uint64: inserted as-is (TEAL int opcode expects decimal)
//   - bytes: prefixed with 0x (TEAL byte opcode expects hex with prefix)
func FormatValueForTEAL(value, paramType string) string {
	switch paramType {
	case "address", "uint64":
		return value
	case "bytes":
		// Strip existing 0x/0X prefix if present, then add canonical 0x
		hexValue := value
		if len(value) >= 2 && (value[:2] == "0x" || value[:2] == "0X") {
			hexValue = value[2:]
		}
		return "0x" + hexValue
	default:
		return value
	}
}

// ValidateVariablesAgainstParams checks that all variables in the TEAL
// source have corresponding parameter definitions.
func ValidateVariablesAgainstParams(teal string, paramNames []string) error {
	vars := ExtractVariables(teal)

	nameSet := make(map[string]bool)
	for _, name := range paramNames {
		nameSet[name] = true
	}

	var missing []string
	for _, varName := range vars {
		if !nameSet[varName] {
			missing = append(missing, varName)
		}
	}

	if len(missing) > 0 {
		return fmt.Errorf("TEAL references undefined parameters: %v", missing)
	}

	return nil
}
