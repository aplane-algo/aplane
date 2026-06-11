// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import tea "github.com/charmbracelet/bubbletea"

func (m Model) handleTemplateLibraryKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q":
		m.viewState = ViewAdminPanel
		m.library.installError = ""
		return m, nil

	case "r", "R":
		m.library.installError = ""
		m.library.installStatus = ""
		return m, tea.Batch(m.sendListLibraryTemplatesCmd(), m.waitForMessageCmd())

	case "up", "k":
		if m.library.selectedTemplate > 0 {
			m.library.selectedTemplate--
			m = m.ensureTemplateVisible()
		}
		return m, nil

	case "down", "j":
		if m.library.selectedTemplate < len(m.library.templates)-1 {
			m.library.selectedTemplate++
			m = m.ensureTemplateVisible()
		}
		return m, nil

	case "t", "T":
		if len(m.library.templates) == 0 || m.library.selectedTemplate < 0 || m.library.selectedTemplate >= len(m.library.templates) {
			return m, nil
		}
		tmpl := m.library.templates[m.library.selectedTemplate]
		m.library.detailsReturnView = ViewTemplateLibrary
		next, cmd, errMsg := m.openLibraryTemplateDetails(tmpl)
		if errMsg != "" {
			m = next
			m.library.installStatus = ""
			m.library.installError = errMsg
			return m, nil
		}
		return next, cmd

	case "enter":
		if len(m.library.templates) == 0 || m.library.selectedTemplate < 0 || m.library.selectedTemplate >= len(m.library.templates) {
			return m, nil
		}
		tmpl := m.library.templates[m.library.selectedTemplate]
		if tmpl.Invalid != "" {
			m.library.installError = "Cannot " + libraryActionVerb(tmpl) + " invalid " + libraryEntryNoun(tmpl) + ": " + tmpl.Invalid
			m.library.installStatus = ""
			return m, nil
		}
		if tmpl.Conflict != "" {
			m.library.installError = "Cannot " + libraryActionVerb(tmpl) + " conflicting " + libraryEntryNoun(tmpl) + ": " + tmpl.Conflict
			m.library.installStatus = ""
			return m, nil
		}
		m.library.pendingTemplate = &tmpl
		m.library.installFocus = 0
		m.library.installError = ""
		m.library.installStatus = ""
		m.viewState = ViewTemplateInstallConfirm
		return m, nil
	}

	return m, nil
}

func (m Model) openLibraryTemplateDetails(tmpl LibraryTemplateInfo) (Model, tea.Cmd, string) {
	m.library.detailsKeyType = tmpl.KeyType
	m.library.detailsTemplateType = tmpl.TemplateType
	m.library.detailsSourceSHA256 = ""
	m.library.detailsSourceModTime = 0
	m.library.detailsContent = ""
	m.library.detailsError = ""
	m.library.detailsScrollOffset = 0
	if m.library.detailsReturnView == 0 {
		m.library.detailsReturnView = ViewTemplateLibrary
	}

	if isCompiledProviderLibraryEntry(tmpl) {
		// No YAML on disk for compiled providers; synthesize a parameter
		// listing from the metadata the server already shipped with the list.
		m.library.detailsSourcePath = ""
		m.library.detailsContent = renderCompiledProviderDetailsText(tmpl)
		m.library.detailsLoading = false
		m.viewState = ViewLibraryTemplateDetails
		return m, nil, ""
	}
	if tmpl.SourcePath == "" {
		return m, nil, displayKeyType(tmpl.KeyType) + " has no plaintext library YAML source to view."
	}
	m.library.detailsSourcePath = tmpl.SourcePath
	m.library.detailsLoading = true
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
		m.library.pendingTemplate = nil
		return m, nil

	case "tab", "left", "right", "h", "l":
		m.library.installFocus = (m.library.installFocus + 1) % 2
		return m, nil

	case "enter", " ":
		if m.library.installFocus == 0 {
			m.viewState = ViewTemplateLibrary
			m.library.pendingTemplate = nil
			return m, nil
		}
		if m.library.pendingTemplate == nil {
			m.library.installError = "No library entry selected"
			m.viewState = ViewTemplateLibrary
			return m, nil
		}
		tmpl := *m.library.pendingTemplate
		m.viewState = ViewTemplateInstalling
		return m, tea.Batch(
			m.libraryActionCmd(tmpl),
			m.waitForMessageCmd(),
		)

	case "y", "Y":
		if m.library.pendingTemplate == nil {
			m.library.installError = "No library entry selected"
			m.viewState = ViewTemplateLibrary
			return m, nil
		}
		tmpl := *m.library.pendingTemplate
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
	if m.library.selectedTemplate < m.library.scrollOffset {
		m.library.scrollOffset = m.library.selectedTemplate
	}
	if m.library.selectedTemplate >= m.library.scrollOffset+visible {
		m.library.scrollOffset = m.library.selectedTemplate - visible + 1
	}
	if m.library.scrollOffset < 0 {
		m.library.scrollOffset = 0
	}
	return m
}
