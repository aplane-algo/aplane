// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package generictemplate

import "github.com/aplane-algo/aplane/internal/tealtemplate"

// tealParamDefs is the spec's parameters as generated-mode TEAL substitution
// reads them.
func tealParamDefs(spec *TemplateSpec) []tealtemplate.ParamDef {
	paramDefs := make([]tealtemplate.ParamDef, len(spec.Parameters))
	for i, p := range spec.Parameters {
		paramDefs[i] = tealtemplate.ParamDef{Name: p.Name, Type: p.Type}
	}
	return paramDefs
}

// ValidateVariablesAgainstParams checks that all variables in the TEAL
// source have corresponding parameter definitions in the spec.
func ValidateVariablesAgainstParams(teal string, spec *TemplateSpec) error {
	paramNames := make([]string, len(spec.Parameters))
	for i, p := range spec.Parameters {
		paramNames[i] = p.Name
	}
	return tealtemplate.ValidateVariablesAgainstParams(teal, paramNames)
}
