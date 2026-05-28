// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import tea "github.com/charmbracelet/bubbletea"

func (m Model) handleTemplateLibraryKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q":
		m.viewState = ViewAdminPanel
		m.templateInstallError = ""
		return m, nil

	case "r", "R":
		m.templateInstallError = ""
		m.templateInstallStatus = ""
		return m, tea.Batch(m.sendListLibraryTemplatesCmd(), m.waitForMessageCmd())

	case "up", "k":
		if m.selectedTemplate > 0 {
			m.selectedTemplate--
			m = m.ensureTemplateVisible()
		}
		return m, nil

	case "down", "j":
		if m.selectedTemplate < len(m.libraryTemplates)-1 {
			m.selectedTemplate++
			m = m.ensureTemplateVisible()
		}
		return m, nil

	case "t", "T":
		if len(m.libraryTemplates) == 0 || m.selectedTemplate < 0 || m.selectedTemplate >= len(m.libraryTemplates) {
			return m, nil
		}
		tmpl := m.libraryTemplates[m.selectedTemplate]
		m.libraryDetailsReturnView = ViewTemplateLibrary
		next, cmd, errMsg := m.openLibraryTemplateDetails(tmpl)
		if errMsg != "" {
			m = next
			m.templateInstallStatus = ""
			m.templateInstallError = errMsg
			return m, nil
		}
		return next, cmd

	case "enter":
		if len(m.libraryTemplates) == 0 || m.selectedTemplate < 0 || m.selectedTemplate >= len(m.libraryTemplates) {
			return m, nil
		}
		tmpl := m.libraryTemplates[m.selectedTemplate]
		if tmpl.Invalid != "" {
			m.templateInstallError = "Cannot " + libraryActionVerb(tmpl) + " invalid " + libraryEntryNoun(tmpl) + ": " + tmpl.Invalid
			m.templateInstallStatus = ""
			return m, nil
		}
		if tmpl.Conflict != "" {
			m.templateInstallError = "Cannot " + libraryActionVerb(tmpl) + " conflicting " + libraryEntryNoun(tmpl) + ": " + tmpl.Conflict
			m.templateInstallStatus = ""
			return m, nil
		}
		m.pendingTemplate = &tmpl
		m.templateInstallFocus = 0
		m.templateInstallError = ""
		m.templateInstallStatus = ""
		m.viewState = ViewTemplateInstallConfirm
		return m, nil
	}

	return m, nil
}

func (m Model) openLibraryTemplateDetails(tmpl LibraryTemplateInfo) (Model, tea.Cmd, string) {
	m.libraryDetailsKeyType = tmpl.KeyType
	m.libraryDetailsTemplateType = tmpl.TemplateType
	m.libraryDetailsSourceSHA256 = ""
	m.libraryDetailsSourceModTime = 0
	m.libraryDetailsContent = ""
	m.libraryDetailsError = ""
	m.libraryDetailsScrollOffset = 0
	if m.libraryDetailsReturnView == 0 {
		m.libraryDetailsReturnView = ViewTemplateLibrary
	}

	if isCompiledProviderLibraryEntry(tmpl) {
		// No YAML on disk for compiled providers; synthesize a parameter
		// listing from the metadata the server already shipped with the list.
		m.libraryDetailsSourcePath = ""
		m.libraryDetailsContent = renderCompiledProviderDetailsText(tmpl)
		m.libraryDetailsLoading = false
		m.viewState = ViewLibraryTemplateDetails
		return m, nil, ""
	}
	if tmpl.SourcePath == "" {
		return m, nil, displayKeyType(tmpl.KeyType) + " has no plaintext library YAML source to view."
	}
	m.libraryDetailsSourcePath = tmpl.SourcePath
	m.libraryDetailsLoading = true
	m.viewState = ViewLibraryTemplateDetails
	return m, tea.Batch(
		m.sendShowLibraryTemplateCmd(tmpl.KeyType, tmpl.TemplateType),
		m.waitForMessageCmd(),
	), ""
}

func (m Model) handleTemplateInstallConfirmKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "n", "N":
		m.viewState = ViewTemplateLibrary
		m.pendingTemplate = nil
		return m, nil

	case "tab", "left", "right", "h", "l":
		m.templateInstallFocus = (m.templateInstallFocus + 1) % 2
		return m, nil

	case "enter", " ":
		if m.templateInstallFocus == 0 {
			m.viewState = ViewTemplateLibrary
			m.pendingTemplate = nil
			return m, nil
		}
		if m.pendingTemplate == nil {
			m.templateInstallError = "No library entry selected"
			m.viewState = ViewTemplateLibrary
			return m, nil
		}
		tmpl := *m.pendingTemplate
		m.viewState = ViewTemplateInstalling
		return m, tea.Batch(
			m.libraryActionCmd(tmpl),
			m.waitForMessageCmd(),
		)

	case "y", "Y":
		if m.pendingTemplate == nil {
			m.templateInstallError = "No library entry selected"
			m.viewState = ViewTemplateLibrary
			return m, nil
		}
		tmpl := *m.pendingTemplate
		m.viewState = ViewTemplateInstalling
		return m, tea.Batch(
			m.libraryActionCmd(tmpl),
			m.waitForMessageCmd(),
		)
	}

	return m, nil
}

func (m Model) libraryActionCmd(tmpl LibraryTemplateInfo) tea.Cmd {
	if isCompiledProviderLibraryEntry(tmpl) {
		if tmpl.Installed {
			return m.sendDeactivateKeyTypeCmd(tmpl.KeyType)
		}
		return m.sendActivateKeyTypeCmd(tmpl.KeyType)
	}
	if tmpl.Installed {
		if tmpl.Enabled {
			return m.sendDeactivateKeyTypeCmd(tmpl.KeyType)
		}
		return m.sendActivateKeyTypeCmd(tmpl.KeyType)
	}
	return m.sendInstallLibraryTemplateCmd(tmpl.KeyType, tmpl.TemplateType)
}

func (m Model) ensureTemplateVisible() Model {
	visible := m.templateLibraryVisibleHeight()
	if m.selectedTemplate < m.templateScrollOffset {
		m.templateScrollOffset = m.selectedTemplate
	}
	if m.selectedTemplate >= m.templateScrollOffset+visible {
		m.templateScrollOffset = m.selectedTemplate - visible + 1
	}
	if m.templateScrollOffset < 0 {
		m.templateScrollOffset = 0
	}
	return m
}
