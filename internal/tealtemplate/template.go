// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package tealtemplate owns the TEAL template grammar for all three template
// modes. Strict mode renders $symbol references into typed generated constant
// blocks (this file); legacy and generated modes use @variable textual
// substitution and restricted list-template expansion (legacy.go,
// legacy_list.go). Mode resolution and validation dispatch live in
// lsig/generictemplate.ValidateTemplateSpecMode, shared by generic and
// composed templates.
package tealtemplate

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

const (
	ConstantInt  ConstantKind = "int"
	ConstantByte ConstantKind = "byte"

	SourceParameter = "parameter"
)

var (
	atVariablePattern  = regexp.MustCompile(`@[a-zA-Z_][a-zA-Z0-9_]*`)
	symbolPattern      = regexp.MustCompile(`\$([a-zA-Z_][a-zA-Z0-9_]*)`)
	goTemplatePatterns = []string{"{{range", "{{end", "{{."}
)

type ConstantKind string

// TemplateVariable is part of strict-template compatibility fingerprints.
// Adding or changing exported JSON fields here changes existing strict-template
// fingerprints and needs an explicit migration story.
type TemplateVariable struct {
	Name      string       `json:"name" yaml:"name"`
	Source    string       `json:"source" yaml:"source"`
	Parameter string       `json:"parameter" yaml:"parameter"`
	Type      string       `json:"type" yaml:"type"`
	Constant  ConstantKind `json:"constant" yaml:"constant"`
}

type ConstantSlot struct {
	Name      string
	Parameter string
	Kind      ConstantKind
	Type      string
	Index     int
	Value     string
}

type RenderedTemplate struct {
	TEAL           string
	ConstantBlocks string
	IntSlots       []ConstantSlot
	ByteSlots      []ConstantSlot
}

func ValidateStrictTemplate(teal string, variables []TemplateVariable) error {
	if err := rejectLegacySyntax(teal); err != nil {
		return err
	}
	decls, err := validateDeclarations(variables)
	if err != nil {
		return err
	}
	refs, err := validateSymbolRefs(teal, decls)
	if err != nil {
		return err
	}
	return validateDeclaredVariablesReferenced(variables, refs)
}

func RenderStrict(teal string, params map[string]string, variables []TemplateVariable) (RenderedTemplate, error) {
	rendered, err := RenderStrictFragment(teal, params, variables)
	if err != nil {
		return RenderedTemplate{}, err
	}
	rendered.TEAL = insertConstantBlocks(rendered.TEAL, rendered.IntSlots, rendered.ByteSlots)
	return rendered, nil
}

func RenderStrictFragment(teal string, params map[string]string, variables []TemplateVariable) (RenderedTemplate, error) {
	if err := rejectLegacySyntax(teal); err != nil {
		return RenderedTemplate{}, err
	}

	decls, err := validateDeclarations(variables)
	if err != nil {
		return RenderedTemplate{}, err
	}

	refs, err := validateSymbolRefs(teal, decls)
	if err != nil {
		return RenderedTemplate{}, err
	}
	if err := validateDeclaredVariablesReferenced(variables, refs); err != nil {
		return RenderedTemplate{}, err
	}

	intSlots, byteSlots, replacements, err := buildSlots(variables, params)
	if err != nil {
		return RenderedTemplate{}, err
	}

	body := symbolPattern.ReplaceAllStringFunc(teal, func(match string) string {
		name := match[1:]
		return replacements[name]
	})

	return RenderedTemplate{
		TEAL:           body,
		ConstantBlocks: strings.Join(renderConstantBlocks(intSlots, byteSlots), "\n"),
		IntSlots:       intSlots,
		ByteSlots:      byteSlots,
	}, nil
}

func rejectLegacySyntax(teal string) error {
	if match := atVariablePattern.FindString(teal); match != "" {
		return fmt.Errorf("strict templates do not support legacy scalar substitution %s", match)
	}
	for _, pattern := range goTemplatePatterns {
		if strings.Contains(teal, pattern) {
			return fmt.Errorf("strict templates do not support generated template syntax %q", pattern)
		}
	}
	return nil
}

func validateDeclarations(variables []TemplateVariable) (map[string]TemplateVariable, error) {
	decls := make(map[string]TemplateVariable, len(variables))
	for _, variable := range variables {
		if variable.Name == "" {
			return nil, fmt.Errorf("template variable name is required")
		}
		if _, exists := decls[variable.Name]; exists {
			return nil, fmt.Errorf("template variable %q is declared more than once", variable.Name)
		}
		if variable.Source != SourceParameter {
			return nil, fmt.Errorf("template variable %q uses unsupported source %q", variable.Name, variable.Source)
		}
		if variable.Parameter == "" {
			return nil, fmt.Errorf("template variable %q must name a source parameter", variable.Name)
		}
		if err := validateConstantType(variable); err != nil {
			return nil, err
		}
		decls[variable.Name] = variable
	}
	return decls, nil
}

func validateSymbolRefs(teal string, decls map[string]TemplateVariable) (map[string]bool, error) {
	refMatches := symbolPattern.FindAllStringSubmatch(teal, -1)
	refs := make(map[string]bool)
	for _, match := range refMatches {
		name := match[1]
		if _, ok := decls[name]; !ok {
			return nil, fmt.Errorf("template references undeclared variable $%s", name)
		}
		refs[name] = true
	}
	return refs, nil
}

func validateDeclaredVariablesReferenced(variables []TemplateVariable, refs map[string]bool) error {
	for _, variable := range variables {
		if !refs[variable.Name] {
			return fmt.Errorf("template variable %q is declared but not referenced", variable.Name)
		}
	}
	return nil
}

func validateConstantType(variable TemplateVariable) error {
	switch variable.Type {
	case "uint64":
		if variable.Constant != ConstantInt {
			return fmt.Errorf("template variable %q with type uint64 must use int constants", variable.Name)
		}
	case "bytes", "address":
		if variable.Constant != ConstantByte {
			return fmt.Errorf("template variable %q with type %s must use byte constants", variable.Name, variable.Type)
		}
	default:
		return fmt.Errorf("template variable %q uses unsupported type %q", variable.Name, variable.Type)
	}
	return nil
}

func buildSlots(variables []TemplateVariable, params map[string]string) ([]ConstantSlot, []ConstantSlot, map[string]string, error) {
	replacements := make(map[string]string, len(variables))
	intSlots := make([]ConstantSlot, 0)
	byteSlots := make([]ConstantSlot, 0)

	for _, variable := range variables {
		value, ok := params[variable.Parameter]
		if !ok {
			return nil, nil, nil, fmt.Errorf("missing template parameter %q for variable %q", variable.Parameter, variable.Name)
		}

		encoded, err := encodeValue(value, variable.Type)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("invalid value for template variable %q: %w", variable.Name, err)
		}

		switch variable.Constant {
		case ConstantInt:
			index := len(intSlots)
			intSlots = append(intSlots, ConstantSlot{
				Name:      variable.Name,
				Parameter: variable.Parameter,
				Kind:      ConstantInt,
				Type:      variable.Type,
				Index:     index,
				Value:     encoded,
			})
			replacements[variable.Name] = fmt.Sprintf("intc_%d", index)
		case ConstantByte:
			index := len(byteSlots)
			byteSlots = append(byteSlots, ConstantSlot{
				Name:      variable.Name,
				Parameter: variable.Parameter,
				Kind:      ConstantByte,
				Type:      variable.Type,
				Index:     index,
				Value:     encoded,
			})
			replacements[variable.Name] = fmt.Sprintf("bytec_%d", index)
		default:
			return nil, nil, nil, fmt.Errorf("template variable %q uses unsupported constant kind %q", variable.Name, variable.Constant)
		}
	}

	return intSlots, byteSlots, replacements, nil
}

func encodeValue(value, valueType string) (string, error) {
	switch valueType {
	case "uint64":
		parsed, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			return "", fmt.Errorf("expected uint64 decimal value")
		}
		return strconv.FormatUint(parsed, 10), nil
	case "bytes":
		hexValue := strings.TrimPrefix(strings.TrimPrefix(value, "0x"), "0X")
		if hexValue == "" {
			return "", fmt.Errorf("expected non-empty hex bytes")
		}
		decoded, err := hex.DecodeString(hexValue)
		if err != nil {
			return "", fmt.Errorf("expected hex bytes")
		}
		return "0x" + hex.EncodeToString(decoded), nil
	case "address":
		addr, err := types.DecodeAddress(value)
		if err != nil {
			return "", fmt.Errorf("expected Algorand address")
		}
		return "0x" + hex.EncodeToString(addr[:]), nil
	default:
		return "", fmt.Errorf("unsupported value type %q", valueType)
	}
}

func insertConstantBlocks(teal string, intSlots, byteSlots []ConstantSlot) string {
	if len(intSlots) == 0 && len(byteSlots) == 0 {
		return teal
	}

	lines := strings.Split(teal, "\n")
	insertAt := 0
	if len(lines) > 0 && strings.HasPrefix(strings.TrimSpace(lines[0]), "#pragma ") {
		insertAt = 1
	}

	blockLines := renderConstantBlocks(intSlots, byteSlots)
	out := make([]string, 0, len(lines)+len(blockLines)+1)
	out = append(out, lines[:insertAt]...)
	out = append(out, blockLines...)
	out = append(out, "")
	out = append(out, lines[insertAt:]...)
	return strings.Join(out, "\n")
}

func renderConstantBlocks(intSlots, byteSlots []ConstantSlot) []string {
	var lines []string
	if len(intSlots) > 0 {
		lines = append(lines, "intcblock "+joinSlotValues(intSlots))
	}
	if len(byteSlots) > 0 {
		lines = append(lines, "bytecblock "+joinSlotValues(byteSlots))
	}
	return lines
}

func joinSlotValues(slots []ConstantSlot) string {
	values := make([]string, len(slots))
	for i, slot := range slots {
		values[i] = slot.Value
	}
	return strings.Join(values, " ")
}
