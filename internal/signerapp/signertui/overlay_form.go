// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"strings"

	"github.com/aplane-algo/aplane/internal/boundary"
	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/witness"
	"github.com/aplane-algo/aplane/lsig/generictemplate"
)

// The overlay choices. On a key type that takes the overlays (the plain hosts and
// the general bounded type), Generate shows the type's bounds as one block, then
// three controls over its cosigner, rekey_to and rekey_authority parameters:
//
//   - Require a cosigner: the cosigner picker, labelled with the cosigner's
//     algorithm. Left empty, the account has none.
//   - Add rekey-to addresses: the list. With addresses, the rekey control is its
//     option: only these addresses, or these plus others with the cosigner.
//   - Allow rekeys: without a list, refused or by the spending key (with the
//     cosigner when there is one).
//
// Every combination the type declares is offered, and nothing here refuses or
// gates a choice: the review states what the account can do, and the signer
// checks the request. The stored rekey value is the operator's (or the
// preset's) last choice; while the control doesn't offer it, the control shows
// and sends its first option instead, and the choice returns when it fits again.
const (
	overlayCosigner = boundary.ParameterCosigner
	overlayList     = boundary.ParameterRekeyTo
	overlayRekey    = boundary.ParameterRekeyAuthority

	overlaySectionBounds   = "Bounds"
	overlaySectionOverlays = "Cosigner and rekeys"
)

// isOverlayParameter reports whether the overlay controls own name. The raw
// cosigner key and list root are filled by the signer from the picker's choice
// and the list, so they are never typed here.
func isOverlayParameter(name string) bool {
	switch name {
	case overlayCosigner, overlayList, overlayRekey,
		boundedmeta.CosignerPublicKeyParameter, boundedmeta.RekeyListRootParameter:
		return true
	}
	return false
}

func paramNamed(params []lsigprovider.ParameterDef, name string) (lsigprovider.ParameterDef, bool) {
	for _, param := range params {
		if param.Name == name {
			return param, true
		}
	}
	return lsigprovider.ParameterDef{}, false
}

// overlayRekeyOptions is what the rekey control offers: the type's declared
// rekey settings that fit whether there is a list and a cosigner, in the type's
// order. Plus cosigned needs a cosigner.
func overlayRekeyOptions(declared []string, listed, cosigned bool) []string {
	options := make([]string, 0, 2)
	for _, option := range declared {
		switch option {
		case boundary.RekeyRefused, boundary.RekeySpendingKey:
			if !listed {
				options = append(options, option)
			}
		case boundary.RekeyOnlyThese:
			if listed {
				options = append(options, option)
			}
		case boundary.RekeyPlusCosigned:
			if listed && cosigned {
				options = append(options, option)
			}
		}
	}
	return options
}

// overlayRekeyLabel names a rekey setting for the control.
func overlayRekeyLabel(value string, cosigned bool) string {
	switch value {
	case boundary.RekeyRefused:
		return "No, never"
	case boundary.RekeySpendingKey:
		if cosigned {
			return "Yes, spending key and cosigner"
		}
		return "Yes, spending key alone"
	case boundary.RekeyOnlyThese:
		return "Only these addresses"
	case boundary.RekeyPlusCosigned:
		return "These, plus others with the cosigner"
	}
	return value
}

// cosignerAlgorithmLabel is the cosigner control's label, naming the algorithm
// of the cosigner key the type takes.
func cosignerAlgorithmLabel(componentKeyType string) string {
	if name, ok := witness.AlgorithmName(componentKeyType); ok {
		return "Require a cosigner (" + name + ")"
	}
	return "Require a cosigner"
}

// overlaySpec is the Generate form of a type that takes the overlays, or nil for
// any other type. preset, when set, chooses the bounds and which overlays it
// needs; the operator can still change every overlay choice.
func (m Model) overlaySpec(keyType string, spec *paramSpec, preset *boundary.Preset) *paramSpec {
	info, ok := findServerKeyType(keyType)
	if !ok || !info.PerKeyContract || info.CosignerComponentKeyType == "" {
		return nil
	}
	rekeyDef, hasRekey := paramNamed(spec.Params, overlayRekey)
	listDef, hasList := paramNamed(spec.Params, overlayList)
	if !hasRekey || len(rekeyDef.Options) == 0 || !hasList {
		return nil
	}

	title, description := spec.DisplayName, spec.Description
	needs := map[string]bool{}
	var bounds []lsigprovider.ParameterDef
	if preset != nil {
		title, description = preset.Title, preset.Description
		for _, field := range preset.Fields {
			if isOverlayParameter(field) {
				needs[field] = true
				continue
			}
			if def, ok := paramNamed(spec.Params, field); ok {
				def.Required = true
				bounds = append(bounds, def)
			}
		}
	} else {
		for _, def := range spec.Params {
			if !isOverlayParameter(def.Name) {
				bounds = append(bounds, def)
			}
		}
	}

	values := m.forms.genericLSigParams
	cosigned := strings.TrimSpace(values[overlayCosigner]) != ""
	// A preset that needs a list shows the list's options from the start.
	listed := strings.TrimSpace(values[overlayList]) != "" || needs[overlayList]

	cosigner := lsigprovider.ParameterDef{
		Name:        overlayCosigner,
		Label:       cosignerAlgorithmLabel(info.CosignerComponentKeyType),
		Description: "An enrolled cosigner that must approve every spend. Leave it empty for none.",
		Type:        "select",
		Required:    needs[overlayCosigner],
	}
	list := listDef
	list.Label = "Add rekey-to addresses"
	list.Required = needs[overlayList]
	rekey := rekeyDef
	rekey.Required = true
	rekey.Default = ""
	rekey.Options = overlayRekeyOptions(rekeyDef.Options, listed, cosigned)
	rekey.Label = "Allow rekeys"
	if listed {
		rekey.Label = "Rekey-to option"
	}

	params := make([]lsigprovider.ParameterDef, 0, len(bounds)+3)
	params = append(params, bounds...)
	params = append(params, cosigner, list, rekey)
	var sections []paramSection
	if len(bounds) > 0 {
		sections = append(sections, paramSection{Start: 0, Title: overlaySectionBounds})
	}
	sections = append(sections, paramSection{Start: len(bounds), Title: overlaySectionOverlays})
	return &paramSpec{
		DisplayName: title,
		Description: description,
		Params:      params,
		Sections:    sections,
		Overlay:     true,
		Validate: func(values map[string]string) error {
			normalized, err := lsigprovider.NormalizeCreationParams(values, params)
			if err != nil {
				return err
			}
			return generictemplate.ValidateParameterValues(normalized, params)
		},
		OptionLabel: func(name, value string) string {
			if name == overlayRekey {
				return overlayRekeyLabel(value, cosigned)
			}
			return value
		},
	}
}

// dropEmptyParameters leaves out the fields left empty: an overlay form sends
// only what was chosen, so an empty cosigner or list is no cosigner or list.
func dropEmptyParameters(params map[string]string) map[string]string {
	out := make(map[string]string, len(params))
	for name, value := range params {
		if strings.TrimSpace(value) != "" {
			out[name] = value
		}
	}
	return out
}
