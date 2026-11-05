// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/signerapp/policytext"
	tea "github.com/charmbracelet/bubbletea"
)

// Editing the node default or a key that has no policy of its own first
// offers a choice of starting text: what the editor would open on anyway, or
// one of the role's presets (policytext.Presets), with the role's note on
// what they leave unchanged. A
// preset is only starting text; it reaches the node through the same check,
// diff review, and confirmed apply as any other edit. Editing a key's own
// policy opens the editor directly, since that edit starts from the key's
// current rules.

// policyPresetPickState is the starting-text picker.
type policyPresetPickState struct {
	row      policyRow
	presets  []policytext.Preset
	selected int
}

// policyPresetsOffered reports whether editing row starts with the picker.
func (m Model) policyPresetsOffered(row policyRow) bool {
	role, err := noderole.ParseRole(m.policies.policy.NodeRole)
	if err != nil || len(policytext.Presets(role)) == 0 {
		return false
	}
	return row.key == policy.DefaultKey || row.doc == nil
}

// openPolicyPresetPick shows the picker for row, or opens the editor when
// the node has no presets for this row.
func (m Model) openPolicyPresetPick(row policyRow) (tea.Model, tea.Cmd) {
	if !m.policyEditAvailable() {
		return m, nil
	}
	if !m.policyPresetsOffered(row) {
		return m.openPolicyEditForRow(row)
	}
	if row.key != policy.DefaultKey && !m.policyKeyHeld(row.key) {
		return m.openPolicyEditForRow(row)
	}
	role, _ := noderole.ParseRole(m.policies.policy.NodeRole)
	m.policies.presetPick = policyPresetPickState{row: row, presets: policytext.Presets(role)}
	m.policies.status = ""
	m.viewState = ViewPolicyPresetPick
	return m, nil
}

// policyPresetFirstChoice names the picker's first choice: the text the
// editor opens on without a preset.
func policyPresetFirstChoice(row policyRow) string {
	if row.doc == nil {
		return "Start from the node default"
	}
	return "Edit the current policy"
}

func (m Model) handlePolicyPresetPickKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	pick := &m.policies.presetPick
	choices := 1 + len(pick.presets)
	switch msg.String() {
	case "esc", "q":
		m.policies.presetPick = policyPresetPickState{}
		m.viewState = ViewPolicies
	case "up", "k":
		if pick.selected > 0 {
			pick.selected--
		}
	case "down", "j":
		if pick.selected < choices-1 {
			pick.selected++
		}
	case "enter":
		row := pick.row
		selected := pick.selected
		presets := pick.presets
		m.policies.presetPick = policyPresetPickState{}
		if selected == 0 {
			return m.openPolicyEditForRow(row)
		}
		role, err := noderole.ParseRole(m.policies.policy.NodeRole)
		var text string
		if err == nil {
			text, err = policytext.PresetTemplate(role, presets[selected-1].Name, row.key)
		}
		if err != nil {
			m.viewState = ViewPolicies
			m.policies.status = "Cannot start from that preset: " + err.Error()
			return m, nil
		}
		m = m.startPolicyEditor(row.key, text, row.doc == nil)
		if m.viewState == ViewPolicyEdit {
			m.policies.apply.edit.preset = presets[selected-1].Name
		}
		return m, nil
	}
	return m, nil
}

func (m Model) renderPolicyPresetPick() string {
	pick := m.policies.presetPick
	target := "the node default"
	if pick.row.key != policy.DefaultKey {
		target = "key " + pick.row.key
	}
	// Wrap to the terminal once its width is known; before the first
	// resize there is nothing to fit.
	wrap := func(text string) []string {
		if m.width > 0 {
			text = wrapText(text, max(20, m.width-4))
		}
		return strings.Split(strings.TrimRight(subtitleStyle.Render(text), "\n"), "\n")
	}
	var header []string
	header = append(header, titleStyle.Render("Start Policy"), "")
	header = append(header, wrap(fmt.Sprintf("Choose the starting text for %s. Nothing changes until you review and apply the edit.", target))...)
	if role, err := noderole.ParseRole(m.policies.policy.NodeRole); err == nil {
		if note := policytext.PresetNote(role); note != "" {
			header = append(header, wrap("Presets: "+note)...)
		}
	}
	header = append(header, "")

	// A summary wraps under itself, so each choice can span several lines;
	// the picker scrolls by line and follows the end of the selected choice.
	const summaryColumn = len("> Preset ") + 20 + 1
	summaryWidth := 0
	if m.width > 0 {
		summaryWidth = max(20, m.width-summaryColumn)
	}
	var lines []string
	selectedLine := 0
	for i := 0; i <= len(pick.presets); i++ {
		cursor := "  "
		if i == pick.selected {
			cursor = "> "
		}
		if i == 0 {
			lines = append(lines, cursor+policyPresetFirstChoice(pick.row))
		} else {
			preset := pick.presets[i-1]
			summary := preset.Summary
			if preset.Placeholders {
				summary += " (fill in placeholders)"
			}
			wrapped := strings.Split(wrapPlainText(summary, summaryWidth), "\n")
			lines = append(lines, fmt.Sprintf("%sPreset %-20s %s", cursor, preset.Name, wrapped[0]))
			for _, continuation := range wrapped[1:] {
				lines = append(lines, strings.Repeat(" ", summaryColumn)+continuation)
			}
		}
		if i == pick.selected {
			selectedLine = len(lines) - 1
		}
	}
	// Count rendered lines: a styled entry may span more than one.
	header = strings.Split(strings.Join(header, "\n"), "\n")
	return strings.Join(fitPresetPick(header, lines, selectedLine, m.windowBodyHeight()), "\n")
}

// fitPresetPick lays the picker into height lines (0 for no limit), so the
// selected line is always on screen: the lines scroll around it, and in a
// short window the header gives way before any choice does, from the bottom
// up, keeping the title.
func fitPresetPick(header, lines []string, selected, height int) []string {
	if height <= 0 || len(header)+len(lines) <= height {
		return append(header, lines...)
	}
	rows := max(1, min(len(lines), height-len(header)))
	if len(header)+rows > height {
		header = header[:max(1, height-rows)]
	}
	first := 0
	if selected >= rows {
		first = selected - rows + 1
	}
	return append(header, lines[first:first+rows]...)
}
