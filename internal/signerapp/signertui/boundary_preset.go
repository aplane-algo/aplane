// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"slices"
	"strings"

	"github.com/aplane-algo/aplane/internal/boundary"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/lsig/generictemplate"
	tea "github.com/charmbracelet/bubbletea"
)

// paramSpecFor is the parameter form for keyType: the overlay choices for a type
// that takes them, otherwise its parameters. While a preset is active it shows
// only what that preset leaves to the operator.
func (m Model) paramSpecFor(keyType string) *paramSpec {
	spec := getParamSpecForKeyType(keyType)
	if spec == nil {
		return nil
	}
	preset := m.forms.boundaryPreset
	if preset != nil && keyType != m.forms.boundaryKeyType {
		preset = nil
	}
	if overlay := m.overlaySpec(keyType, spec, preset); overlay != nil {
		return overlay
	}
	if preset == nil {
		return spec
	}
	params := make([]lsigprovider.ParameterDef, 0, len(preset.Fields))
	for _, field := range preset.Fields {
		if field == boundary.ParameterCosigner {
			params = append(params, lsigprovider.ParameterDef{
				Name:        field,
				Label:       "Witness Key ID",
				Description: "Imported cosigner that must approve every spend",
				Type:        "select",
				Required:    true,
			})
			continue
		}
		index := slices.IndexFunc(spec.Params, func(p lsigprovider.ParameterDef) bool { return p.Name == field })
		if index < 0 {
			continue
		}
		param := spec.Params[index]
		param.Required = true
		params = append(params, param)
	}
	return &paramSpec{
		DisplayName: preset.Title,
		Description: preset.Description,
		Params:      params,
		Validate: func(values map[string]string) error {
			normalized, err := lsigprovider.NormalizeCreationParams(values, params)
			if err != nil {
				return err
			}
			return generictemplate.ValidateParameterValues(normalized, params)
		},
	}
}

// boundaryPresetRows is the presets plus the file route.
func boundaryPresetRows() int { return len(boundary.Presets()) + 1 }

func (m Model) handleBoundaryPresetKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m = m.endBoundaryFlow()
		m.forms.generateError = ""
		m.viewState = ViewGenerateForm
	case "up", "k":
		if m.forms.boundaryPresetIndex > 0 {
			m.forms.boundaryPresetIndex--
		}
	case "down", "j":
		if m.forms.boundaryPresetIndex < boundaryPresetRows()-1 {
			m.forms.boundaryPresetIndex++
		}
	case fileBrowserKey:
		if m.boundaryFileRowSelected() {
			return m.openFileBrowser(browseBoundaryFile, m.forms.boundaryFile, ""), nil
		}
	case "enter", " ":
		m.forms.generateError = ""
		if m.boundaryFileRowSelected() {
			if m.forms.boundaryFile == "" {
				return m.openFileBrowser(browseBoundaryFile, "", ""), nil
			}
			return m.submitBoundaryFile()
		}
		preset := boundary.Presets()[m.forms.boundaryPresetIndex]
		m.forms.boundaryPreset = &preset
		m.forms.boundaryFileRequest = false
		m = m.initGenericLSigParamsForKeyType(m.forms.boundaryKeyType)
		m.forms.generateFocus = 0
		m.viewState = ViewGenerateParams
	}
	return m, nil
}

func (m Model) boundaryFileRowSelected() bool {
	return m.forms.boundaryPresetIndex == len(boundary.Presets())
}

// submitBoundaryFile sends the file's public values for review. A cosigner name
// stays a name: the signer resolves it, and the review shows what it resolved to.
func (m Model) submitBoundaryFile() (tea.Model, tea.Cmd) {
	params, err := boundary.LoadFile(m.forms.boundaryFile)
	if err != nil {
		m.forms.generateError = err.Error()
		return m, nil
	}
	m.forms.boundaryPreset = nil
	m.forms.boundaryFileRequest = true
	m.forms.genericLSigParams = nil
	m.forms.pendingGenerateParams = params
	id := m.beginOperation(ViewGenerating)
	return m, tea.Batch(m.sendPrepareGenerateKeyCmd(m.forms.boundaryKeyType, params, id), m.waitForMessageCmd())
}

func (m Model) renderBoundaryPreset() string {
	var sb strings.Builder
	sb.WriteString(titleStyle.Render("New Bounded Account"))
	sb.WriteString("\n\n")
	row := func(index int, title, description string) {
		if index == m.forms.boundaryPresetIndex {
			sb.WriteString(selectedStyle.Render("> " + title))
		} else {
			sb.WriteString(normalStyle.Render("  " + title))
		}
		sb.WriteString("\n    ")
		sb.WriteString(subtitleStyle.Render(description))
		sb.WriteString("\n")
	}
	presets := boundary.Presets()
	for i, preset := range presets {
		row(i, preset.Title, preset.Description)
	}
	file := "Rules from a boundary file, for narrower transfer lists."
	if m.forms.boundaryFile != "" {
		file = middleEllipsize(m.forms.boundaryFile, 60)
	}
	row(len(presets), "Load boundary file", file)
	if m.forms.generateError != "" {
		sb.WriteString("\n")
		sb.WriteString(errorStyle.Render(wrapText(m.forms.generateError, 64)))
		sb.WriteString("\n")
	}
	return m.renderPopup(72, sb.String())
}
