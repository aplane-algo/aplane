// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import "strings"

func (m Model) viewFooterText() string {
	switch m.viewState {
	case ViewAuth, ViewUnlock:
		return m.passphraseFooterText()
	case ViewKeyList:
		if m.filterActive {
			return "Enter: Apply | Esc: Clear"
		}
		return keyListHelpText
	case ViewKeyDetails:
		parts := []string{"d=delete"}
		if m.detailsTEAL != "" {
			parts = append(parts, "t=TEAL", "s=save")
		}
		parts = append(parts, "esc/q: Back")
		return strings.Join(parts, " | ")
	case ViewTEALFullDisplay:
		footer := "Esc/q close"
		if len(strings.Split(m.detailsTEAL, "\n")) > m.tealFullDisplayVisibleLines() {
			footer += " | up/down/pgup/pgdown: Scroll"
		}
		return footer
	case ViewSigningPopup, ViewTokenProvisioningPopup:
		return "left/right/tab: Focus | enter/space: Submit | y/a: Approve | n/r/esc: Reject"
	case ViewBackupConfirm:
		return "Tab: Next | Enter: Create backup | Esc: Back"
	case ViewBackupDisplay, ViewGenerateDisplay, ViewImportDisplay:
		return "Enter/Esc: Back"
	case ViewRestoreList:
		return "Enter: Preview | r: Refresh | Esc: Back"
	case ViewRestorePassphrase:
		if m.restorePreviewing {
			return "Previewing backup archive"
		}
		return "Enter: Preview | Esc: Back"
	case ViewRestorePreview:
		return "Space: Toggle | a: Select all | o: Toggle overwrite | Enter: Restore | Esc: Back"
	case ViewRestoreDisplay:
		return "up/down: Select | Enter/Esc: Back"
	case ViewGenerateForm:
		return "up/down: Select | enter: Generate | t: Template | esc: Back"
	case ViewGenerateParams:
		return m.parameterModalFooterText(getKeyTypeByIndex(m.generateKeyType), "Generate")
	case ViewImportForm:
		return "up/down: Select key type | tab: Next | enter: Import | esc: Back"
	case ViewImportParams:
		return m.parameterModalFooterText(getImportKeyTypeByIndex(m.importKeyType), "Import")
	case ViewGenerating, ViewImporting, ViewDeleting, ViewTemplateInstalling, ViewBackingUp, ViewRestoring:
		return "q: Quit"
	case ViewDeleteConfirm:
		return "left/right/tab: Focus | enter/space: Select | y: Delete | n/esc: Cancel"
	case ViewRevokeTokenConfirm:
		return "left/right/tab: Focus | enter/space: Select | y: Revoke | n/esc: Cancel"
	case ViewLockConfirm:
		return "left/right/tab: Focus | enter/space: Select | y: Lock | n/esc: Cancel"
	case ViewDisplaceConfirm:
		return "left/right/tab: Focus | enter/space: Select | y: Proceed | n/esc: Cancel"
	case ViewAdminPanel:
		return "p: Policy | k: KeyTypes | t: Revoke Token | l: Lock | esc: Back"
	case ViewPolicyViewer:
		if m.policyLoadState != policyLoadIdle {
			return m.policyLoadFooterText()
		}
		return m.policyViewerHelp()
	case ViewPolicyPanel:
		return "enter: Toggle/Edit | esc: Back | empty numeric field = no limit"
	case ViewPolicyASAModal:
		return m.policyASAFooterText()
	case ViewTemplateLibrary:
		return "up/down: Select | enter: Toggle availability | t: Template | r: Refresh | esc: Back"
	case ViewTemplateInstallConfirm:
		return "left/right/tab: Focus | enter/space: Select | y: Confirm | n/esc: Cancel"
	case ViewLibraryTemplateDetails:
		return m.libraryTemplateDetailsFooterText()
	case ViewError:
		return "Esc: Close"
	default:
		return keyListHelpText
	}
}

func (m Model) passphraseFooterText() string {
	switch {
	case m.connectionState == ConnectionDisconnected:
		return "c: Retry | Esc: Quit"
	case m.connectionState == ConnectionConnecting || m.loggingIn:
		return "Esc: Quit"
	default:
		return "Enter: Submit | Tab: Toggle visibility | Esc: Quit"
	}
}

func (m Model) parameterModalFooterText(keyType, verb string) string {
	spec := getParamSpecForKeyType(keyType)
	if spec == nil {
		return "Esc: Back"
	}
	for _, param := range spec.Params {
		if isMultilineParamType(param.Type) {
			return ""
		}
	}
	return "Tab: Next | </> Switch mode | Enter: " + verb + " | Esc: Back"
}

func (m Model) policyASAFooterText() string {
	switch m.policyASAMode {
	case policyASAModeLimits:
		return "enter/e: edit ALGO | a: add ASA | d: delete ASA | s: save | esc: networks"
	case policyASAModeAddRef:
		return "enter: Search | esc: Back"
	case policyASAModeChoose:
		return "up/down: Select | enter: Continue | esc: Back"
	case policyASAModeAddAmount:
		return "tab: Switch field | enter: Save | esc: Back"
	case policyASAModeAlgoAmount:
		return "tab: Switch field | enter: Save | esc: Back"
	default:
		return "enter: Open network | esc: Back"
	}
}

func (m Model) policyLoadFooterText() string {
	switch m.policyLoadState {
	case policyLoadPath:
		return "Enter: Read file | Esc: Cancel"
	case policyLoadConfirm:
		return "y/Enter: Replace | n/Esc: Cancel"
	case policyLoadReading:
		return "Reading policy file..."
	case policyLoadReplacing:
		return "Replacing policy..."
	default:
		return m.policyViewerHelp()
	}
}

func (m Model) libraryTemplateDetailsFooterText() string {
	footer := "Esc/q close"
	if m.libraryDetailsContent != "" &&
		len(strings.Split(m.libraryDetailsContent, "\n")) > m.libraryTemplateDetailsVisibleLines() {
		footer += " | up/down/pgup/pgdown: Scroll"
	}
	return footer
}
