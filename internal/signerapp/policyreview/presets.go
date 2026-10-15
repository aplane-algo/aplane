// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyreview

import (
	"embed"
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
)

// A preset is a named starting document for one common intent, so an
// operator picks what a key should do instead of writing routes from
// nothing. Presets are starting text only: they change no policy semantics,
// and a preset goes through the same check, diff, and apply as any other
// document. Presets exist for the cosigner role, whose shipped default
// cosigns nothing and so leaves every new key unusable until it gets routes.
//
// A preset may carry comments, removed on apply, and placeholders such as
// "REPLACE-WITH-DESTINATION-ADDRESS" for values only the operator knows.
// A placeholder is never a valid value, so check rejects the document at
// the placeholder's JSON Pointer until it is filled in.

//go:embed presets/cosigner/*.jsonc
var presetFiles embed.FS

// Preset names one starting document and the intent it serves.
type Preset struct {
	Name    string
	Summary string
	// Placeholders reports that the document has values the operator must
	// fill in before check accepts it.
	Placeholders bool
}

// PresetPlaceholderPrefix starts every placeholder value in a preset.
const PresetPlaceholderPrefix = "REPLACE-WITH-"

var cosignerPresets = []Preset{
	{Name: "deny-all", Summary: "Cosign nothing"},
	{Name: "self-only", Summary: "Self-transfers only: opt-ins and self-payments; nothing leaves an account"},
	{Name: "listed-destinations", Summary: "Transfers to the addresses you list, and nowhere else", Placeholders: true},
	{Name: "capped-any", Summary: "Transfers anywhere, refusing any ALGO transfer above your per-network cap", Placeholders: true},
	{Name: "any-transfer", Summary: "Transfers anywhere; no spend protection (testing)"},
}

// Presets lists the presets for role, in the order to offer them. A role
// with no presets returns nil.
func Presets(role noderole.Role) []Preset {
	if role != noderole.RoleCosigner {
		return nil
	}
	return append([]Preset(nil), cosignerPresets...)
}

// PresetTemplate renders preset name for role as the starting document for
// key, or for the node default when key is policy.DefaultKey.
func PresetTemplate(role noderole.Role, name, key string) (string, error) {
	preset, ok := findPreset(role, name)
	if !ok {
		names := make([]string, 0, len(cosignerPresets))
		for _, p := range Presets(role) {
			names = append(names, p.Name)
		}
		if len(names) == 0 {
			return "", fmt.Errorf("there are no %s policy presets", role)
		}
		return "", fmt.Errorf("unknown %s policy preset %q; expected one of %s", role, name, strings.Join(names, ", "))
	}
	data, err := presetFiles.ReadFile("presets/" + string(role) + "/" + preset.Name + ".jsonc")
	if err != nil {
		return "", fmt.Errorf("read preset %s: %w", preset.Name, err)
	}
	body := string(data)
	var header string
	if key == policy.DefaultKey {
		header = fmt.Sprintf("// This node's default policy, from the %q preset:\n// %s.\n// It governs every %s key without a policy of its own. Every field is\n// required. Comments are removed on apply.\n", preset.Name, preset.Summary, role)
	} else {
		if body, err = renameDocumentKey(body, key); err != nil {
			return "", fmt.Errorf("preset %s: %w", preset.Name, err)
		}
		header = fmt.Sprintf("// Policy for key %s, from the %q preset:\n// %s.\n// This file replaces the default for that key: every field is required,\n// nothing is inherited. Comments are removed on apply.\n", key, preset.Name, preset.Summary)
	}
	if preset.Placeholders {
		header += fmt.Sprintf("// Fill in every %s... value before applying; check rejects the\n// document until you do.\n", PresetPlaceholderPrefix)
	}
	return header + body, nil
}

func findPreset(role noderole.Role, name string) (Preset, bool) {
	for _, p := range Presets(role) {
		if p.Name == name {
			return p, true
		}
	}
	return Preset{}, false
}
