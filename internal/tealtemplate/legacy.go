// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Legacy (@variable) textual substitution and restricted list-template
// expansion, used by legacy- and generated-mode templates. Strict-mode
// templates use the $symbol constant-block renderer in template.go instead.
package tealtemplate

import (
	"fmt"
	"regexp"
	"sort"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// legacyVariablePattern matches @variable_name in TEAL source.
var legacyVariablePattern = regexp.MustCompile(`@([a-zA-Z_][a-zA-Z0-9_]*)`)

// ParamDef holds the name and type of a parameter for TEAL substitution.
type ParamDef struct {
	Name string
	Type string
}

// ExtractVariables extracts all unique variable names from TEAL source.
// Variables are identified by the pattern @variable_name.
// Returns a sorted list of unique variable names.
func ExtractVariables(teal string) []string {
	matches := legacyVariablePattern.FindAllStringSubmatch(teal, -1)
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

	result := legacyVariablePattern.ReplaceAllStringFunc(teal, func(match string) string {
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

		formatted, err := formatValueForTEAL(value, paramType)
		if err != nil {
			substituteErr = fmt.Errorf("invalid value for @%s (%s): %w", varName, paramType, err)
			return match
		}
		return formatted
	})

	if substituteErr != nil {
		return "", substituteErr
	}

	return result, nil
}

func formatValueForTEAL(value, paramType string) (string, error) {
	switch paramType {
	case "address", "uint64":
		return value, nil
	case "address_bytes":
		addr, err := types.DecodeAddress(value)
		if err != nil {
			return "", fmt.Errorf("invalid Algorand address %q", value)
		}
		return "0x" + fmt.Sprintf("%x", addr[:]), nil
	case "bytes":
		// Strip existing 0x/0X prefix if present, then add canonical 0x
		hexValue := value
		if len(value) >= 2 && (value[:2] == "0x" || value[:2] == "0X") {
			hexValue = value[2:]
		}
		return "0x" + hexValue, nil
	default:
		return value, nil
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
