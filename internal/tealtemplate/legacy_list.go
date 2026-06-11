// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tealtemplate

import (
	"fmt"
	"strings"
)

const (
	rangeOpenPrefix = "{{range @"
	rangeClose      = "{{end}}"
	itemPlaceholder = "{{.}}"
)

// ExpandLists expands the restricted list-template construct:
//
//	{{range @name}} ... {{.}} ... {{end}}
//
// The referenced parameter must be declared as a list parameter and supplied as
// a comma-separated string. Expansion is deterministic and uses the item order
// supplied by the caller. Callers must normalize list params before calling;
// address[] is unordered by definition. Unsupported constructs and nested ranges
// return an error.
func ExpandLists(teal string, params map[string]string, paramDefs []ParamDef) (string, error) {
	listTypes := make(map[string]string, len(paramDefs))
	for _, def := range paramDefs {
		if strings.HasSuffix(def.Type, "[]") {
			listTypes[def.Name] = strings.TrimSuffix(def.Type, "[]")
		}
	}

	var out strings.Builder
	remaining := teal
	for {
		start := strings.Index(remaining, "{{")
		if start < 0 {
			out.WriteString(remaining)
			break
		}

		out.WriteString(remaining[:start])
		remaining = remaining[start:]

		if !strings.HasPrefix(remaining, rangeOpenPrefix) {
			return "", fmt.Errorf("unsupported template list construct near %q", previewTemplateFragment(remaining))
		}

		openEnd := strings.Index(remaining, "}}")
		if openEnd < 0 {
			return "", fmt.Errorf("unterminated range directive")
		}
		paramName := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(remaining[:openEnd+2], rangeOpenPrefix), "}}"))
		if paramName == "" {
			return "", fmt.Errorf("range directive requires a parameter name")
		}
		elemType, ok := listTypes[paramName]
		if !ok {
			return "", fmt.Errorf("range parameter %q is not a declared list parameter", paramName)
		}

		bodyAndRest := remaining[openEnd+2:]
		closeIdx := strings.Index(bodyAndRest, rangeClose)
		if closeIdx < 0 {
			return "", fmt.Errorf("unterminated range block for %q", paramName)
		}

		body := bodyAndRest[:closeIdx]
		if strings.Contains(body, rangeOpenPrefix) {
			return "", fmt.Errorf("nested range blocks are not supported")
		}
		if strings.Contains(body, "{{") && !strings.Contains(body, itemPlaceholder) {
			return "", fmt.Errorf("unsupported template list construct inside range for %q", paramName)
		}

		rawValue, ok := params[paramName]
		if !ok || strings.TrimSpace(rawValue) == "" {
			remaining = bodyAndRest[closeIdx+len(rangeClose):]
			continue
		}
		items, err := parseListItems(rawValue)
		if err != nil {
			return "", fmt.Errorf("invalid list parameter %q: %w", paramName, err)
		}

		for _, item := range items {
			formatted, err := formatValueForTEAL(item, elemType)
			if err != nil {
				return "", fmt.Errorf("invalid list item for %q (%s): %w", paramName, elemType, err)
			}
			out.WriteString(strings.ReplaceAll(body, itemPlaceholder, formatted))
		}

		remaining = bodyAndRest[closeIdx+len(rangeClose):]
	}

	return out.String(), nil
}

// ValidateListTemplates verifies that TEAL uses only the restricted list
// template syntax accepted by ExpandLists.
func ValidateListTemplates(teal string, paramDefs []ParamDef) error {
	params := make(map[string]string)
	for _, def := range paramDefs {
		if !strings.HasSuffix(def.Type, "[]") {
			continue
		}
		switch strings.TrimSuffix(def.Type, "[]") {
		case "address", "address_bytes":
			params[def.Name] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"
		case "uint64":
			params[def.Name] = "0"
		default:
			params[def.Name] = "0"
		}
	}
	_, err := ExpandLists(teal, params, paramDefs)
	return err
}

func parseListItems(value string) ([]string, error) {
	parts := strings.Split(value, ",")
	items := make([]string, 0, len(parts))
	for _, part := range parts {
		item := strings.TrimSpace(part)
		if item == "" {
			return nil, fmt.Errorf("empty list item")
		}
		items = append(items, item)
	}
	return items, nil
}

func previewTemplateFragment(s string) string {
	const max = 24
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
