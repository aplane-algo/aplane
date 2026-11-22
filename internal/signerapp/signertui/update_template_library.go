// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	tea "github.com/charmbracelet/bubbletea"

	"github.com/aplane-algo/aplane/internal/keytypeux"
)

func (m Model) handleTemplateLibraryKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q":
		m.viewState = ViewAdminPanel
		m.library.installError = ""
		return m, nil

	case "r", "R":
		m.library.installError = ""
		m.library.installStatus = ""
		return m, m.sendListLibraryTemplatesCmd()

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
		tmpl, ok := m.selectedLibraryTemplate()
		if !ok {
			return m, nil
		}
		next, cmd, errMsg := m.openLibraryTemplateDetails(tmpl, ViewTemplateLibrary)
		if errMsg != "" {
			m = next
			m.library.installStatus = ""
			m.library.installError = errMsg
			return m, nil
		}
		return next, cmd

	case "enter":
		tmpl, ok := m.selectedLibraryTemplate()
		if !ok {
			return m, nil
		}
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

// selectedLibraryTemplate is the library entry under the cursor, if any.
func (m Model) selectedLibraryTemplate() (LibraryTemplateInfo, bool) {
	if m.library.selectedTemplate < 0 || m.library.selectedTemplate >= len(m.library.templates) {
		return LibraryTemplateInfo{}, false
	}
	return m.library.templates[m.library.selectedTemplate], true
}

// openLibraryTemplateDetails shows tmpl's details; Esc returns to returnView.
func (m Model) openLibraryTemplateDetails(tmpl LibraryTemplateInfo, returnView ViewState) (Model, tea.Cmd, string) {
	m.library.detailsReturnView = returnView
	m.library.detailsKeyType = tmpl.KeyType
	m.library.detailsTemplateType = tmpl.TemplateType
	m.library.detailsSourceSHA256 = ""
	m.library.detailsSourceModTime = 0
	m.library.detailsContent = ""
	m.library.detailsError = ""
	m.library.detailsScrollOffset = 0
	// A read that never settled, such as one a lock interrupted, is not
	// waited on here.
	m.library.detailsLoading = false
	m.library.detailsRequestID = ""

	if isCompiledProviderLibraryEntry(tmpl) {
		// No YAML on disk for compiled providers; synthesize a parameter
		// listing from the metadata the server already shipped with the list.
		m.library.detailsSourcePath = ""
		m.library.detailsContent = renderCompiledProviderDetailsText(tmpl)
		m.viewState = ViewLibraryTemplateDetails
		return m, nil, ""
	}
	m.library.detailsSourcePath = tmpl.SourcePath
	m.library.detailsInstalled = false
	if tmpl.SourcePath == "" {
		if !tmpl.Installed {
			return m, nil, displayKeyType(tmpl.KeyType) + " has no plaintext library YAML source to view."
		}
		// An installed template can outlive its library file, so show the
		// copy this identity stores.
		m.library.detailsInstalled = true
		m.library.detailsLoading = true
		m.library.detailsRequestID = newRequestID("tmpl-show-installed")
		m.viewState = ViewLibraryTemplateDetails
		return m, m.sendShowInstalledTemplateCmd(tmpl.KeyType, m.library.detailsRequestID), ""
	}
	m.library.detailsLoading = true
	m.library.detailsRequestID = newRequestID("tmpl-show-library")
	m.viewState = ViewLibraryTemplateDetails
	return m, m.sendShowLibraryTemplateCmd(tmpl.KeyType, tmpl.TemplateType, m.library.detailsRequestID), ""
}

// failPendingLibraryDetails settles the details read id names with err, so
// the pager shows the error rather than staying on Loading.
func (m Model) failPendingLibraryDetails(id string, err error) (Model, bool) {
	if id == "" || id != m.library.detailsRequestID {
		return m, false
	}
	m.library.detailsRequestID = ""
	if m.library.detailsLoading {
		m.library.detailsLoading = false
		m.library.detailsContent = ""
		m.library.detailsError = err.Error()
	}
	return m, true
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
		fallthrough

	case "y", "Y":
		if m.library.pendingTemplate == nil {
			m.library.installError = "No library entry selected"
			m.viewState = ViewTemplateLibrary
			return m, nil
		}
		tmpl := *m.library.pendingTemplate
		id := m.beginOperation(ViewTemplateInstalling)
		return m, m.libraryActionCmd(tmpl, id)
	}

	return m, nil
}

type libraryAction int

const (
	libraryActionInstall libraryAction = iota
	libraryActionActivate
	libraryActionDeactivate
)

func libraryActionFor(tmpl LibraryTemplateInfo) libraryAction {
	if !tmpl.Installed && !isCompiledProviderLibraryEntry(tmpl) {
		return libraryActionInstall
	}
	if libraryEntryEnabled(tmpl) {
		return libraryActionDeactivate
	}
	return libraryActionActivate
}

func (m Model) libraryActionCmd(tmpl LibraryTemplateInfo, id string) tea.Cmd {
	switch libraryActionFor(tmpl) {
	case libraryActionActivate:
		return m.sendActivateKeyTypeCmd(tmpl.KeyType, id)
	case libraryActionDeactivate:
		return m.sendDeactivateKeyTypeCmd(tmpl.KeyType, id)
	default:
		return m.sendInstallLibraryTemplateCmd(tmpl.KeyType, tmpl.TemplateType, id)
	}
}

func (m Model) ensureTemplateVisible() Model {
	m.library.scrollOffset = scrollToSelection(m.library.scrollOffset, m.library.selectedTemplate, len(m.library.templates), m.templateLibraryVisibleHeight())
	return m
}

// finishLibraryAction applies the result of installing, enabling, or disabling
// a KeyType Library entry, when id names the request its progress screen
// still waits on. A reply whose reload entered recovery ends the operation on
// the recovery screen with its cause, as a key change's does
// (isRecoveryBlockedReply).
func (m Model) finishLibraryAction(id string, success bool, code, status, errText, fallbackErr string) (tea.Model, tea.Cmd) {
	if m.isRecoveryBlockedReply(id, code) {
		m.library.installError = ""
		m.library.pendingTemplate = nil
		return m.showRecoveryBlockedReply("KeyType Library: " + errText)
	}
	if !m.takeOperationReply(id) {
		return m, nil
	}
	if !success {
		m.library.installError = errText
		if m.library.installError == "" {
			m.library.installError = fallbackErr
		}
		m.viewState = ViewTemplateInstallConfirm
		return m, nil
	}
	m.library.installError = ""
	m.library.installStatus = status
	m.library.pendingTemplate = nil
	m.viewState = ViewTemplateLibrary
	return m, tea.Batch(
		m.sendListLibraryTemplatesCmd(),
		m.sendListKeyTypesCmd(),
		m.sendListKeysCmd(),
	)
}

func libraryEnabledStatus(keyType string, alreadyExists bool) string {
	if alreadyExists {
		return displayKeyType(keyType) + " was already " + keytypeux.AvailableToCreate
	}
	return displayKeyType(keyType) + " " + keytypeux.AvailableToCreate
}
