// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/aplane-algo/aplane/internal/policyview"
)

func (m Model) handlePolicyViewerKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.policyLoadState != policyLoadIdle {
		return m.handlePolicyLoadKeys(msg)
	}
	if m.policyViewListPopupField != "" {
		return m.handlePolicyViewerListPopupKeys(msg)
	}

	switch msg.String() {
	case "q":
		m.viewState = m.policyViewerExitView()
		m.policyViewLoading = false
		return m, m.policyViewerExitCmd()

	case "esc":
		if m.policyViewMode != policyViewerModeOverview {
			m.policyViewMode = policyViewerModeOverview
			return m, nil
		}
		m.viewState = m.policyViewerExitView()
		m.policyViewLoading = false
		return m, m.policyViewerExitCmd()

	case "r", "R":
		m.policyViewLoading = true
		m.policyViewError = ""
		m.policyLoadStatus = ""
		m.policyViewListPopupField = ""
		m.policyViewListPopupScroll = 0
		return m, tea.Batch(m.sendGetPolicySnapshotCmd(), m.waitForMessageCmd())

	case "l", "L":
		if !m.policyViewLoaded || m.policySnapshot == nil || !m.policySnapshot.Success {
			m.lastError = "Policy load requires a current policy snapshot"
			return m, nil
		}
		m.policyLoadState = policyLoadPath
		m.policyLoadPath = ""
		m.policyLoadYAML = ""
		m.policyLoadBytes = 0
		m.policyLoadError = ""
		m.policyLoadStatus = ""
		return m, nil

	case "right":
		m.policyViewMode = nextPolicyViewerMode(m.policyViewMode)
		return m.ensurePolicyViewerModeVisible(), nil

	case "left":
		m.policyViewMode = previousPolicyViewerMode(m.policyViewMode)
		return m.ensurePolicyViewerModeVisible(), nil

	case "1":
		m.policyViewMode = policyViewerModeOverview
		return m, nil

	case "2", "g", "G":
		if m.policyViewGuardCount() > 0 {
			m.policyViewMode = policyViewerModeGuardDetail
		}
		return m.ensurePolicyViewerModeVisible(), nil

	case "3", "y", "Y":
		m.policyViewMode = policyViewerModeYAML
		return m.ensurePolicyViewYAMLVisible(), nil

	case "4", "o", "O":
		m.policyViewMode = policyViewerModeOverrides
		return m.ensurePolicyViewOverrideVisible(), nil
	}

	switch m.policyViewMode {
	case policyViewerModeGuardDetail:
		return m.handlePolicyViewerGuardDetailKeys(msg)
	case policyViewerModeYAML:
		return m.handlePolicyViewerYAMLKeys(msg)
	case policyViewerModeOverrides:
		return m.handlePolicyViewerOverrideKeys(msg)
	default:
		return m.handlePolicyViewerGuardKeys(msg)
	}
}

func (m Model) handlePolicyViewerGuardKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter":
		if m.policyViewGuardCount() > 0 {
			m.policyViewMode = policyViewerModeGuardDetail
		}
		return m.ensurePolicyViewerModeVisible(), nil

	case "up", "k":
		if m.policyViewSelectedGuard > 0 {
			m.policyViewSelectedGuard--
		}
		return m.ensurePolicyViewGuardVisible(), nil

	case "down", "j":
		if m.policyViewSelectedGuard < m.policyViewGuardCount()-1 {
			m.policyViewSelectedGuard++
		}
		return m.ensurePolicyViewGuardVisible(), nil

	case "home":
		m.policyViewSelectedGuard = 0
		return m.ensurePolicyViewGuardVisible(), nil

	case "end":
		if count := m.policyViewGuardCount(); count > 0 {
			m.policyViewSelectedGuard = count - 1
		}
		return m.ensurePolicyViewGuardVisible(), nil

	case "pgup":
		m.policyViewSelectedGuard -= m.policyViewerVisibleGuardRows()
		if m.policyViewSelectedGuard < 0 {
			m.policyViewSelectedGuard = 0
		}
		return m.ensurePolicyViewGuardVisible(), nil

	case "pgdown":
		count := m.policyViewGuardCount()
		if count > 0 {
			m.policyViewSelectedGuard += m.policyViewerVisibleGuardRows()
			if m.policyViewSelectedGuard >= count {
				m.policyViewSelectedGuard = count - 1
			}
		}
		return m.ensurePolicyViewGuardVisible(), nil
	}

	return m, nil
}

func (m Model) handlePolicyViewerGuardDetailKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		if m.policyViewSelectedGuardField > 0 {
			m.policyViewSelectedGuardField--
		}
		return m.ensurePolicyViewGuardFieldVisible(), nil

	case "down", "j":
		if m.policyViewSelectedGuardField < m.policyViewerGuardFieldCount()-1 {
			m.policyViewSelectedGuardField++
		}
		return m.ensurePolicyViewGuardFieldVisible(), nil

	case "home":
		m.policyViewSelectedGuardField = 0
		return m.ensurePolicyViewGuardFieldVisible(), nil

	case "end":
		if count := m.policyViewerGuardFieldCount(); count > 0 {
			m.policyViewSelectedGuardField = count - 1
		}
		return m.ensurePolicyViewGuardFieldVisible(), nil

	case "enter":
		field := m.currentPolicyViewerGuardField()
		if len(field.items) > 1 {
			m.policyViewListPopupField = field.key
			m.policyViewListPopupScroll = 0
		}
		return m.ensurePolicyViewListPopupVisible(), nil
	}

	return m, nil
}

func (m Model) handlePolicyViewerListPopupKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "enter", "q":
		m.policyViewListPopupField = ""
		m.policyViewListPopupScroll = 0
		return m, nil
	case "up", "k":
		if m.policyViewListPopupScroll > 0 {
			m.policyViewListPopupScroll--
		}
	case "down", "j":
		m.policyViewListPopupScroll++
	case "home":
		m.policyViewListPopupScroll = 0
	case "end":
		m.policyViewListPopupScroll = len(m.policyViewerListPopupItems())
	case "pgup":
		m.policyViewListPopupScroll -= m.policyViewerListPopupVisibleLines()
		if m.policyViewListPopupScroll < 0 {
			m.policyViewListPopupScroll = 0
		}
	case "pgdown":
		m.policyViewListPopupScroll += m.policyViewerListPopupVisibleLines()
	}
	return m.ensurePolicyViewListPopupVisible(), nil
}

func (m Model) handlePolicyLoadKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch m.policyLoadState {
	case policyLoadPath:
		switch msg.Type {
		case tea.KeyEsc:
			return m.cancelPolicyLoad(), nil
		case tea.KeyEnter:
			path := strings.TrimSpace(m.policyLoadPath)
			if path == "" {
				m.policyLoadError = "path is required"
				return m, nil
			}
			m.policyLoadState = policyLoadReading
			m.policyLoadError = ""
			return m, readPolicyLoadFileCmd(path)
		case tea.KeyBackspace, tea.KeyCtrlH:
			if m.policyLoadPath != "" {
				runes := []rune(m.policyLoadPath)
				m.policyLoadPath = string(runes[:len(runes)-1])
			}
			m.policyLoadError = ""
			return m, nil
		case tea.KeyCtrlU:
			m.policyLoadPath = ""
			m.policyLoadError = ""
			return m, nil
		case tea.KeySpace:
			m.policyLoadPath += " "
			m.policyLoadError = ""
			return m, nil
		case tea.KeyRunes:
			m.policyLoadPath += string(msg.Runes)
			m.policyLoadError = ""
			return m, nil
		default:
			return m, nil
		}

	case policyLoadConfirm:
		switch msg.String() {
		case "y", "Y", "enter":
			expectedSHA := ""
			if m.policySnapshot != nil {
				expectedSHA = m.policySnapshot.PolicySHA256
			}
			m.policyLoadState = policyLoadReplacing
			m.policyLoadError = ""
			return m, tea.Batch(m.sendReplacePolicyCmd(m.policyLoadYAML, expectedSHA), m.waitForMessageCmd())
		case "n", "N", "esc", "q":
			return m.cancelPolicyLoad(), nil
		default:
			return m, nil
		}

	case policyLoadReading, policyLoadReplacing:
		return m, nil
	default:
		return m, nil
	}
}

func (m Model) cancelPolicyLoad() Model {
	m.policyLoadState = policyLoadIdle
	m.policyLoadPath = ""
	m.policyLoadYAML = ""
	m.policyLoadBytes = 0
	m.policyLoadError = ""
	return m
}

func readPolicyLoadFileCmd(path string) tea.Cmd {
	return func() tea.Msg {
		expanded, err := expandPolicyLoadPath(path)
		if err != nil {
			return PolicyLoadFileMsg{Path: path, Error: err}
		}
		data, err := os.ReadFile(expanded)
		if err != nil {
			return PolicyLoadFileMsg{Path: expanded, Error: err}
		}
		return PolicyLoadFileMsg{
			Path:       expanded,
			PolicyYAML: string(data),
			Bytes:      len(data),
		}
	}
}

func expandPolicyLoadPath(raw string) (string, error) {
	path := strings.TrimSpace(os.ExpandEnv(raw))
	if path == "" {
		return "", fmt.Errorf("path is required")
	}
	if path == "~" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		path = home
	} else if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		path = filepath.Join(home, strings.TrimPrefix(path, "~/"))
	}
	return filepath.Clean(path), nil
}

func (m Model) applyPolicySnapshot(snapshot PolicySnapshot, errorPrefix string) Model {
	m.policySnapshot = &snapshot
	m.policyViewLoading = false
	m.policyViewLoaded = false
	m.policyViewError = ""
	if !snapshot.Success {
		errText := snapshot.Error
		if errText == "" {
			errText = "request failed"
		}
		m.policyViewError = errorPrefix + " failed: " + errText
		m.lastError = m.policyViewError
		return m
	}
	stored, err := policyview.ParseYAML(snapshot.PolicyYAML)
	if err != nil {
		m.policyViewError = errorPrefix + " parse failed: " + err.Error()
		m.lastError = m.policyViewError
		return m
	}
	m.policyView = policyview.Build(stored, snapshot.PolicyYAML)
	m.policyViewLoaded = true
	m.policyViewError = ""
	m.policyViewListPopupField = ""
	m.policyViewListPopupScroll = 0
	if strings.HasPrefix(m.lastError, "Policy snapshot ") || strings.HasPrefix(m.lastError, "Policy replacement ") {
		m.lastError = ""
	}
	m = m.ensurePolicyViewGuardVisible()
	m = m.ensurePolicyViewGuardFieldVisible()
	m = m.ensurePolicyViewOverrideVisible()
	m = m.ensurePolicyViewYAMLVisible()
	return m
}

func (m Model) handlePolicyViewerYAMLKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		if m.policyViewYAMLScrollOffset > 0 {
			m.policyViewYAMLScrollOffset--
		}
	case "down", "j":
		m.policyViewYAMLScrollOffset++
	case "home":
		m.policyViewYAMLScrollOffset = 0
	case "end":
		m.policyViewYAMLScrollOffset = m.policyViewYAMLLineCount()
	case "pgup":
		m.policyViewYAMLScrollOffset -= m.policyViewerYAMLVisibleLines()
		if m.policyViewYAMLScrollOffset < 0 {
			m.policyViewYAMLScrollOffset = 0
		}
	case "pgdown":
		m.policyViewYAMLScrollOffset += m.policyViewerYAMLVisibleLines()
	}
	return m.ensurePolicyViewYAMLVisible(), nil
}

func (m Model) handlePolicyViewerOverrideKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		if m.policyViewSelectedOverride > 0 {
			m.policyViewSelectedOverride--
		}
	case "down", "j":
		if m.policyViewSelectedOverride < m.policyViewOverrideCount()-1 {
			m.policyViewSelectedOverride++
		}
	case "home":
		m.policyViewSelectedOverride = 0
	case "end":
		if count := m.policyViewOverrideCount(); count > 0 {
			m.policyViewSelectedOverride = count - 1
		}
	case "pgup":
		m.policyViewSelectedOverride -= m.policyViewerOverrideVisibleRows()
		if m.policyViewSelectedOverride < 0 {
			m.policyViewSelectedOverride = 0
		}
	case "pgdown":
		count := m.policyViewOverrideCount()
		if count > 0 {
			m.policyViewSelectedOverride += m.policyViewerOverrideVisibleRows()
			if m.policyViewSelectedOverride >= count {
				m.policyViewSelectedOverride = count - 1
			}
		}
	}
	return m.ensurePolicyViewOverrideVisible(), nil
}

func (m Model) ensurePolicyViewerModeVisible() Model {
	switch m.policyViewMode {
	case policyViewerModeYAML:
		return m.ensurePolicyViewYAMLVisible()
	case policyViewerModeOverrides:
		return m.ensurePolicyViewOverrideVisible()
	default:
		return m.ensurePolicyViewGuardVisible()
	}
}

func (m Model) ensurePolicyViewGuardVisible() Model {
	count := m.policyViewGuardCount()
	if count == 0 {
		m.policyViewSelectedGuard = 0
		m.policyViewGuardScrollOffset = 0
		return m
	}
	if m.policyViewSelectedGuard < 0 {
		m.policyViewSelectedGuard = 0
	}
	if m.policyViewSelectedGuard >= count {
		m.policyViewSelectedGuard = count - 1
	}
	visible := m.policyViewerVisibleGuardRows()
	if m.policyViewGuardScrollOffset > m.policyViewSelectedGuard {
		m.policyViewGuardScrollOffset = m.policyViewSelectedGuard
	}
	if m.policyViewSelectedGuard >= m.policyViewGuardScrollOffset+visible {
		m.policyViewGuardScrollOffset = m.policyViewSelectedGuard - visible + 1
	}
	maxOffset := count - visible
	if maxOffset < 0 {
		maxOffset = 0
	}
	if m.policyViewGuardScrollOffset > maxOffset {
		m.policyViewGuardScrollOffset = maxOffset
	}
	if m.policyViewGuardScrollOffset < 0 {
		m.policyViewGuardScrollOffset = 0
	}
	m = m.ensurePolicyViewGuardFieldVisible()
	return m
}

func (m Model) ensurePolicyViewGuardFieldVisible() Model {
	count := m.policyViewerGuardFieldCount()
	if count == 0 {
		m.policyViewSelectedGuardField = 0
		return m
	}
	if m.policyViewSelectedGuardField < 0 {
		m.policyViewSelectedGuardField = 0
	}
	if m.policyViewSelectedGuardField >= count {
		m.policyViewSelectedGuardField = count - 1
	}
	return m
}

func (m Model) ensurePolicyViewListPopupVisible() Model {
	items := m.policyViewerListPopupItems()
	visible := m.policyViewerListPopupVisibleLines()
	maxOffset := len(items) - visible
	if maxOffset < 0 {
		maxOffset = 0
	}
	if m.policyViewListPopupScroll > maxOffset {
		m.policyViewListPopupScroll = maxOffset
	}
	if m.policyViewListPopupScroll < 0 {
		m.policyViewListPopupScroll = 0
	}
	return m
}

func (m Model) ensurePolicyViewYAMLVisible() Model {
	count := m.policyViewYAMLLineCount()
	visible := m.policyViewerYAMLVisibleLines()
	maxOffset := count - visible
	if maxOffset < 0 {
		maxOffset = 0
	}
	if m.policyViewYAMLScrollOffset > maxOffset {
		m.policyViewYAMLScrollOffset = maxOffset
	}
	if m.policyViewYAMLScrollOffset < 0 {
		m.policyViewYAMLScrollOffset = 0
	}
	return m
}

func (m Model) ensurePolicyViewOverrideVisible() Model {
	count := m.policyViewOverrideCount()
	if count == 0 {
		m.policyViewSelectedOverride = 0
		m.policyViewOverrideScrollOffset = 0
		return m
	}
	if m.policyViewSelectedOverride < 0 {
		m.policyViewSelectedOverride = 0
	}
	if m.policyViewSelectedOverride >= count {
		m.policyViewSelectedOverride = count - 1
	}
	visible := m.policyViewerOverrideVisibleRows()
	if m.policyViewOverrideScrollOffset > m.policyViewSelectedOverride {
		m.policyViewOverrideScrollOffset = m.policyViewSelectedOverride
	}
	if m.policyViewSelectedOverride >= m.policyViewOverrideScrollOffset+visible {
		m.policyViewOverrideScrollOffset = m.policyViewSelectedOverride - visible + 1
	}
	maxOffset := count - visible
	if maxOffset < 0 {
		maxOffset = 0
	}
	if m.policyViewOverrideScrollOffset > maxOffset {
		m.policyViewOverrideScrollOffset = maxOffset
	}
	if m.policyViewOverrideScrollOffset < 0 {
		m.policyViewOverrideScrollOffset = 0
	}
	return m
}

func (m Model) policyViewGuardCount() int {
	return len(m.policyView.TransferGuards)
}

func (m Model) policyViewerGuardFieldCount() int {
	return len(m.policyViewerGuardFields())
}

func (m Model) policyViewYAMLLineCount() int {
	if m.policyView.YAML == "" {
		return 0
	}
	return len(strings.Split(strings.TrimRight(m.policyView.YAML, "\n"), "\n"))
}

func (m Model) policyViewOverrideCount() int {
	return len(m.policyView.KeyTypeOverrides)
}

func (m Model) policyViewerExitView() ViewState {
	switch m.policyViewReturnView {
	case ViewKeyList, ViewAdminPanel:
		return m.policyViewReturnView
	default:
		return ViewAdminPanel
	}
}

func (m Model) policyViewerExitCmd() tea.Cmd {
	if m.viewState != ViewAdminPanel {
		return nil
	}
	return tea.Batch(m.sendGetAdminSettingsCmd(), adminRefreshTickCmd())
}

func nextPolicyViewerMode(mode policyViewerMode) policyViewerMode {
	switch mode {
	case policyViewerModeOverview:
		return policyViewerModeGuardDetail
	case policyViewerModeGuardDetail:
		return policyViewerModeYAML
	case policyViewerModeYAML:
		return policyViewerModeOverrides
	default:
		return policyViewerModeOverview
	}
}

func previousPolicyViewerMode(mode policyViewerMode) policyViewerMode {
	switch mode {
	case policyViewerModeOverrides:
		return policyViewerModeYAML
	case policyViewerModeYAML:
		return policyViewerModeGuardDetail
	case policyViewerModeGuardDetail:
		return policyViewerModeOverview
	default:
		return policyViewerModeOverrides
	}
}
