// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policytui

// Persistence and lifecycle: production apply, draft write,
// validation, passphrase/quit/write popups, clone/marshal helpers.

import (
	"context"
	"fmt"
	"os"
	"strings"
	"unicode/utf8"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/signerapp/policyeditor"
)

type productionPassphraseStore interface {
	RequiresPassphraseForSave() bool
	SetPassphrase([]byte)
}

type productionPassphraseClearer interface {
	ClearPassphrase()
}

type storeModeLabeler interface {
	ModeLabel() string
}

func (m Model) handleQuitConfirmKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.busy {
		return m, nil
	}
	switch msg.String() {
	case "q", "y", "ctrl+c":
		return m, tea.Quit
	case "a":
		m.quitAfterApply = true
		return m.applyProduction()
	case "esc", "n", "b", "backspace":
		m.screen = m.previousScreen
		m.quitAfterApply = false
		m.status = "exit canceled"
		m.err = ""
		return m, nil
	}
	return m, nil
}

func (m Model) handleApplyPassphraseKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.busy {
		return m, nil
	}
	if msg.String() == "ctrl+c" {
		m.clearApplyPassphrase()
		return m.requestQuit()
	}
	switch msg.Type {
	case tea.KeyEsc:
		m.clearApplyPassphrase()
		m.screen = m.previousScreen
		m.quitAfterApply = false
		m.status = "apply canceled"
		m.err = ""
		return m, nil
	case tea.KeyEnter:
		return m.submitApplyPassphrase()
	case tea.KeyBackspace, tea.KeyDelete, tea.KeyCtrlH:
		if len(m.applyPassphrase) > 0 {
			m.applyPassphrase[len(m.applyPassphrase)-1] = 0
			m.applyPassphrase = m.applyPassphrase[:len(m.applyPassphrase)-1]
		}
		m.err = ""
		return m, nil
	case tea.KeyCtrlU:
		m.clearApplyPassphrase()
		m.err = ""
		return m, nil
	case tea.KeySpace:
		m.applyPassphrase = append(m.applyPassphrase, ' ')
		m.err = ""
		return m, nil
	case tea.KeyRunes:
		m.applyPassphrase = append(m.applyPassphrase, msg.Runes...)
		m.err = ""
		return m, nil
	}
	return m, nil
}

func (m Model) handleWriteFileKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.busy {
		return m, nil
	}
	if msg.String() == "ctrl+c" {
		return m.requestQuit()
	}
	switch msg.Type {
	case tea.KeyEsc:
		m.screen = m.previousScreen
		m.writePath = ""
		m.status = "write canceled"
		m.err = ""
		return m, nil
	case tea.KeyEnter:
		return m.writeDraftFile()
	case tea.KeyBackspace, tea.KeyDelete, tea.KeyCtrlH:
		if m.writePath != "" {
			runes := []rune(m.writePath)
			m.writePath = string(runes[:len(runes)-1])
		}
		m.err = ""
		return m, nil
	case tea.KeyCtrlU:
		m.writePath = ""
		m.err = ""
		return m, nil
	case tea.KeySpace:
		m.writePath += " "
		m.err = ""
		return m, nil
	case tea.KeyRunes:
		m.writePath += string(msg.Runes)
		m.err = ""
		return m, nil
	}
	return m, nil
}

func (m Model) requestQuit() (tea.Model, tea.Cmd) {
	if !m.modified() {
		return m, tea.Quit
	}
	m.previousScreen = m.screen
	m.screen = screenQuitConfirm
	m.status = "production not applied"
	m.err = ""
	return m, nil
}

func (m Model) openWriteFile() (tea.Model, tea.Cmd) {
	m.previousScreen = m.screen
	m.screen = screenWriteFile
	m.writePath = ""
	m.status = fmt.Sprintf("write %s draft", m.target.StatusNoun())
	m.err = ""
	return m, nil
}

func (m Model) openApplyPassphrase() (tea.Model, tea.Cmd) {
	m.previousScreen = m.screen
	m.screen = screenApplyPassphrase
	m.clearApplyPassphrase()
	m.status = "store passphrase required"
	m.err = ""
	return m, nil
}

func (m Model) submitApplyPassphrase() (tea.Model, tea.Cmd) {
	if len(m.applyPassphrase) == 0 {
		m.err = "passphrase is required"
		m.status = "apply needs passphrase"
		return m, nil
	}
	store, ok := m.store.(productionPassphraseStore)
	if !ok {
		m.clearApplyPassphrase()
		m.err = "store does not accept an interactive passphrase"
		m.status = "apply failed"
		return m, nil
	}
	passphrase := passphraseRunesBytes(m.applyPassphrase)
	store.SetPassphrase(passphrase)
	for i := range passphrase {
		passphrase[i] = 0
	}
	m.clearApplyPassphrase()
	m.screen = m.previousScreen
	return m.applyProduction()
}

func (m *Model) clearApplyPassphrase() {
	for i := range m.applyPassphrase {
		m.applyPassphrase[i] = 0
	}
	m.applyPassphrase = nil
}

func passphraseRunesBytes(runes []rune) []byte {
	var out []byte
	for _, r := range runes {
		out = utf8.AppendRune(out, r)
	}
	return out
}

func (m Model) quitConfirmView() string {
	return m.renderHelp(renderLines(
		sectionStyle.Render("Production Not Applied"),
		"",
		statusWarnStyle.Render("This policy draft differs from production."),
		"",
		"Press a to apply to production and quit.",
		"Press q to quit without applying to production.",
		"Press esc to return to editing.",
		"",
		"keys: a apply+quit  q quit without applying  esc cancel",
	))
}

func (m Model) applyPassphraseView() string {
	value := strings.Repeat("*", len(m.applyPassphrase))
	var b strings.Builder
	b.WriteString(sectionStyle.Render("Apply To Production"))
	b.WriteString("\n\n")
	b.WriteString(descriptionStyle.Render(fmt.Sprintf("Enter the identity store passphrase to write %s and a fresh sidecar.", m.target.DocumentName())))
	b.WriteString("\n\n")
	b.WriteString(inputActiveStyle.Render(fixedWidthFieldLine(value, m.routeTextInputWidth())))
	b.WriteString("\n\n")
	b.WriteString("keys: type passphrase  backspace delete  ctrl+u clear  enter apply  esc cancel\n")
	return m.renderHelp(m.renderPopup(90, b.String()))
}

func (m Model) writeFileView() string {
	var b strings.Builder
	b.WriteString(sectionStyle.Render("Write " + m.target.Label() + " Draft"))
	b.WriteString("\n\n")
	b.WriteString(descriptionStyle.Render(fmt.Sprintf("Write the current in-memory %s draft to a YAML file without applying it to the identity store.", m.target.StatusNoun())))
	b.WriteString("\n\n")
	b.WriteString(inputActiveStyle.Render(fixedWidthFieldLine(m.writePathDisplayValue(), m.routeTextInputWidth())))
	b.WriteString("\n\n")
	b.WriteString("keys: type path  backspace delete  ctrl+u clear  enter write  esc cancel\n")
	return m.renderHelp(m.renderPopup(90, b.String()))
}

func (m Model) applyProduction() (tea.Model, tea.Cmd) {
	cp, baseline, err := m.cloneStored(m.policy)
	if err != nil {
		m.err = err.Error()
		m.status = "cannot apply"
		return m, nil
	}
	if store, ok := m.store.(productionPassphraseStore); ok && store.RequiresPassphraseForSave() {
		return m.openApplyPassphrase()
	}
	m.busy = true
	m.status = fmt.Sprintf("applying %s", m.target.StatusNoun())
	m.err = ""
	return m, func() tea.Msg {
		if err := m.store.Save(context.Background(), cp); err != nil {
			return productionApplyResultMsg{err: err}
		}
		return productionApplyResultMsg{baseline: baseline}
	}
}

func (m Model) writeDraftFile() (tea.Model, tea.Cmd) {
	path := strings.TrimSpace(m.writePath)
	if path == "" {
		m.err = "path is required"
		m.status = "write failed"
		return m, nil
	}
	data, err := m.marshalStored(m.policy)
	if err != nil {
		m.err = err.Error()
		m.status = "write failed"
		return m, nil
	}
	m.busy = true
	m.status = fmt.Sprintf("writing %s draft", m.target.StatusNoun())
	m.err = ""
	return m, func() tea.Msg {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			return writeFileResultMsg{path: path, err: err}
		}
		return writeFileResultMsg{path: path}
	}
}

func (m Model) validate() (tea.Model, tea.Cmd) {
	cp, _, err := m.cloneStored(m.policy)
	if err != nil {
		m.err = err.Error()
		m.status = "cannot validate"
		return m, nil
	}
	m.busy = true
	m.status = fmt.Sprintf("validating %s", m.target.StatusNoun())
	m.err = ""
	return m, func() tea.Msg {
		return validateResultMsg{err: m.store.Validate(context.Background(), cp)}
	}
}

func friendlyPolicyError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "asset_sources requires clawback.allow:true"):
		return msg + " (clear asset_sources for normal sends, or edit YAML to set clawback.allow:true for clawback routes)"
	case strings.Contains(msg, "clawback.allow:true requires asset_sources"):
		return msg + " (edit YAML to set asset_sources for clawback routes, or clear clawback.allow for normal routes)"
	case strings.Contains(msg, "self is not allowed in clawback route destinations"):
		return msg + " (clawback destinations must be explicit addresses or address sets, not self)"
	case strings.Contains(msg, "self is not allowed in asset_sources"):
		return msg + " (asset_sources names the clawback source account; use an address, set, or wildcard)"
	case strings.Contains(msg, "close.allow:true with wildcard destinations is not supported"):
		return msg + " (for close-out routes, replace wildcard Destinations with explicit addresses or address sets)"
	case strings.Contains(msg, "duplicate route id"):
		return msg + " (route IDs must be unique)"
	case strings.Contains(msg, "unresolved asset set"):
		return msg + " (define the asset set from Transfer Guards -> Asset Sets, then reference it as @name)"
	default:
		return msg
	}
}

func (m Model) modified() bool {
	current, err := m.marshalStored(m.policy)
	if err != nil {
		return true
	}
	return string(current) != string(m.baseline)
}

func (m *Model) cancelFormApply() {
	m.formApplyToken++
	m.busy = false
}

func (m Model) writePathDisplayValue() string {
	return m.routeTextDisplayValue(m.writePath)
}

func (m Model) cloneStored(stored *policy.StoredConfig) (*policy.StoredConfig, []byte, error) {
	return cloneStoredForTarget(stored, m.target)
}

func cloneStoredForTarget(stored *policy.StoredConfig, target policyeditor.Target) (*policy.StoredConfig, []byte, error) {
	data, err := marshalStoredForTarget(stored, target)
	if err != nil {
		return nil, nil, err
	}
	cp, err := target.Parse(data)
	if err != nil {
		return nil, nil, err
	}
	return cp, data, nil
}

func (m Model) marshalStored(stored *policy.StoredConfig) ([]byte, error) {
	return marshalStoredForTarget(stored, m.target)
}

func marshalStoredForTarget(stored *policy.StoredConfig, target policyeditor.Target) ([]byte, error) {
	data, err := target.Marshal(stored)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal stored %s: %w", target.StatusNoun(), err)
	}
	return data, nil
}
