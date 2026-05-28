// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package generictemplate

import (
	"github.com/aplane-algo/aplane/internal/tealsubst"
)

// SubstituteVariables replaces @variable_name placeholders in TEAL source
// with the corresponding values from the params map.
// Values are formatted appropriately for TEAL:
// - addresses and uint64 values are inserted as-is
// - bytes values are prefixed with 0x
//
// Returns an error if a variable referenced in TEAL is not found in params.
func SubstituteVariables(teal string, params map[string]string, spec *TemplateSpec) (string, error) {
	paramDefs := make([]tealsubst.ParamDef, len(spec.Parameters))
	for i, p := range spec.Parameters {
		paramDefs[i] = tealsubst.ParamDef{Name: p.Name, Type: p.Type}
	}
	return tealsubst.SubstituteVariables(teal, params, paramDefs)
}

// ExpandListTemplates expands restricted list-template blocks before scalar
// @variable substitution runs.
func ExpandListTemplates(teal string, params map[string]string, spec *TemplateSpec) (string, error) {
	paramDefs := make([]tealsubst.ParamDef, len(spec.Parameters))
	for i, p := range spec.Parameters {
		paramDefs[i] = tealsubst.ParamDef{Name: p.Name, Type: p.Type}
	}
	return tealsubst.ExpandLists(teal, params, paramDefs)
}

// ValidateListTemplateSyntax checks generated-mode TEAL for unsupported
// template constructs without requiring concrete parameter values.
func ValidateListTemplateSyntax(teal string, spec *TemplateSpec) error {
	paramDefs := make([]tealsubst.ParamDef, len(spec.Parameters))
	for i, p := range spec.Parameters {
		paramDefs[i] = tealsubst.ParamDef{Name: p.Name, Type: p.Type}
	}
	return tealsubst.ValidateListTemplates(teal, paramDefs)
}

// ValidateVariablesAgainstParams checks that all variables in the TEAL
// source have corresponding parameter definitions in the spec.
func ValidateVariablesAgainstParams(teal string, spec *TemplateSpec) error {
	paramNames := make([]string, len(spec.Parameters))
	for i, p := range spec.Parameters {
		paramNames[i] = p.Name
	}
	return tealsubst.ValidateVariablesAgainstParams(teal, paramNames)
}
