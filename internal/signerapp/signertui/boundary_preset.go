// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"slices"
	"strings"

	"github.com/aplane-algo/aplane/internal/boundary"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// activeBoundaryPreset is the preset being filled in when it applies to
// keyType, otherwise nil.
func (m Model) activeBoundaryPreset(keyType string) *boundary.Preset {
	if keyType != m.forms.boundaryKeyType {
		return nil
	}
	return m.forms.boundaryPreset
}

// paramSpecFor is the parameter form for keyType: the overlay choices for a type
// that takes them, otherwise its parameters. While a preset is active it shows
// only what that preset leaves to the operator.
func (m Model) paramSpecFor(keyType string) *paramSpec {
	spec := getParamSpecForKeyType(keyType)
	if spec == nil {
		return nil
	}
	preset := m.activeBoundaryPreset(keyType)
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
		Validate:    validateParams(params),
	}
}

// The two choices the preset screen offers beside the presets: no bounds at
// all, and every bounds field without a file.
var (
	noBoundsPreset = boundary.Preset{
		Name:        "no-bounds",
		Title:       "No bounds",
		Description: "Standard unbounded",
	}
	customBoundsPreset = boundary.Preset{
		Name:        "custom-bounds",
		Title:       "Custom bounds",
		Description: "Every bounds field, without a file: transfer kinds, recipients, scope, encoding, fee limit.",
		Fields: []string{boundary.ParameterSpendEffects, boundary.ParameterRecipients, boundary.ParameterRecipientScope,
			boundary.ParameterListEncoding, boundary.ParameterMaxFee},
	}
)

// boundaryPresetChoices is what the preset screen lists before the file route:
// no bounds, the presets, and custom bounds.
func boundaryPresetChoices() []boundary.Preset {
	return append(append([]boundary.Preset{noBoundsPreset}, boundary.Presets()...), customBoundsPreset)
}

// boundaryPresetRows is the choices plus the file route.
func boundaryPresetRows() int { return len(boundaryPresetChoices()) + 1 }

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
		// From any row, as a form's path field takes it from any field. A
		// chosen file selects the boundary file row; Esc leaves the row as it was.
		return m.openFileBrowser(browseBoundaryFile, m.forms.boundaryFile, ""), nil
	case "enter", " ":
		m.forms.generateError = ""
		if m.boundaryFileRowSelected() {
			if m.forms.boundaryFile == "" {
				return m.openFileBrowser(browseBoundaryFile, "", ""), nil
			}
			return m.submitBoundaryFile()
		}
		preset := boundaryPresetChoices()[m.forms.boundaryPresetIndex]
		m.forms.boundaryPreset = &preset
		m.forms.boundaryFileRequest = false
		m = m.initGenericLSigParamsForKeyType(m.forms.boundaryKeyType)
		m.forms.generateFocus = 0
		m.viewState = ViewGenerateParams
	}
	return m, nil
}

func (m Model) boundaryFileRowSelected() bool {
	return m.forms.boundaryPresetIndex == len(boundaryPresetChoices())
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
	return m, m.sendPrepareGenerateKeyCmd(m.forms.boundaryKeyType, params, id)
}

func (m Model) renderBoundaryPreset() string {
	var sb strings.Builder
	sb.WriteString(titleStyle.Render("New " + displayKeyType(m.forms.boundaryKeyType) + " Account"))
	sb.WriteString("\n\n")
	var descriptions []string
	row := func(title, description string) {
		if len(descriptions) == m.forms.boundaryPresetIndex {
			sb.WriteString(selectedStyle.Render("> " + title))
		} else {
			sb.WriteString(normalStyle.Render("  " + title))
		}
		sb.WriteString("\n")
		descriptions = append(descriptions, description)
	}
	for _, preset := range boundaryPresetChoices() {
		row(preset.Title, preset.Description)
	}
	file := "Rules from a boundary file, with or without bounds."
	if m.forms.boundaryFile != "" {
		file = middleEllipsize(terminalSafe(m.forms.boundaryFile), 60)
	}
	row("Load boundary file", file)
	sb.WriteString("\n")
	sb.WriteString(selectionDescriptionBox(descriptions, m.forms.boundaryPresetIndex, m.popupBodyWidth(72)))
	sb.WriteString("\n")
	if m.forms.generateError != "" {
		sb.WriteString("\n")
		// A boundary file's load error can quote the file.
		sb.WriteString(errorStyle.Render(wrapText(terminalSafeLines(m.forms.generateError), 64)))
		sb.WriteString("\n")
	}
	return m.renderPopup(72, sb.String())
}

// selectionDescriptionBox draws the selected choice's description in a box
// width columns wide under a selection list. It is as tall as the longest
// description, so neither the list nor the box moves as the selection does.
func selectionDescriptionBox(descriptions []string, selected, width int) string {
	box := inputInactiveStyle.
		Foreground(subtitleStyle.GetForeground()).
		Width(width - inputInactiveStyle.GetHorizontalBorderSize())
	lines := 1
	for _, description := range descriptions {
		lines = max(lines, lipgloss.Height(box.Render(description))-box.GetVerticalFrameSize())
	}
	return box.Height(lines).Render(descriptions[selected])
}
