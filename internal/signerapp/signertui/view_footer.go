// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import "strings"

func (m Model) viewFooterText() string {
	switch m.viewState {
	case ViewAuth, ViewUnlock:
		return m.passphraseFooterText()
	case ViewKeyList:
		if m.keylist.filterActive {
			return "Enter: Apply | Esc: Clear"
		}
		return m.keyListFooterText()
	case ViewKeyDetails:
		parts := []string{"d=delete"}
		if m.details.teal != "" {
			parts = append(parts, "t=TEAL", "s=save")
		}
		parts = append(parts, "esc/q: Back")
		return strings.Join(parts, " | ")
	case ViewTEALFullDisplay:
		footer := "Esc/q close"
		if len(strings.Split(m.details.teal, "\n")) > m.tealFullDisplayVisibleLines() {
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
		if m.restore.previewing {
			return "Previewing backup archive"
		}
		return "Enter: Preview | Esc: Back"
	case ViewRestorePreview:
		return "Space: Toggle | a: Select all | o: Overwrite | Tab: Recover button | Enter: Activate | Esc: Back"
	case ViewRestoreReview:
		return "tab: Acknowledgement/Activate | space: Toggle | enter: Activate | esc: Leave inactive"
	case ViewRestoreDisplay:
		return "up/down: Select | Enter/Esc: Back"
	case ViewGenerateForm:
		return "up/down: Select | enter: Generate | t: Template | esc: Back"
	case ViewGenerateParams:
		return m.parameterModalFooterText(getKeyTypeByIndex(m.forms.generateKeyType), "Generate")
	case ViewImportForm:
		return "up/down: Select key type | tab: Next | enter: Import | esc: Back"
	case ViewImportParams:
		return m.parameterModalFooterText(getImportKeyTypeByIndex(m.forms.importKeyType), "Import")
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
	case ViewPolicyEditor:
		return m.policyEditorFooterText()
	case ViewTemplateLibrary:
		return "up/down: Select | enter: Toggle availability | t: Template | r: Refresh | esc: Back"
	case ViewTemplateInstallConfirm:
		return "left/right/tab: Focus | enter/space: Select | y: Confirm | n/esc: Cancel"
	case ViewLibraryTemplateDetails:
		return m.libraryTemplateDetailsFooterText()
	case ViewError:
		return "Esc: Close"
	default:
		return m.keyListFooterText()
	}
}

func (m Model) passphraseFooterText() string {
	switch {
	case m.connectionState == ConnectionDisconnected:
		return "c: Retry | Esc: Quit"
	case m.connectionState == ConnectionConnecting || m.auth.loggingIn:
		return "Esc: Quit"
	default:
		return "Enter: Submit | Tab: Toggle visibility | Esc: Quit"
	}
}

func (m Model) parameterModalFooterText(keyType, verb string) string {
	if m.forms.genericLSigPasteParam != "" {
		return "Paste key now | Esc: Cancel"
	}
	spec := getParamSpecForKeyType(keyType)
	if spec == nil {
		return "Esc: Back"
	}
	for _, param := range spec.Params {
		if isMultilineParamType(param.Type) {
			return ""
		}
		if isPasteOnlyParam(param) {
			return "Enter: Paste/Replace | Del: Clear | Tab: Next | Esc: Back"
		}
	}
	return "Tab: Next | </> Switch mode | Enter: " + verb + " | Esc: Back"
}

func (m Model) libraryTemplateDetailsFooterText() string {
	footer := "Esc/q close"
	if m.library.detailsContent != "" &&
		len(strings.Split(m.library.detailsContent, "\n")) > m.libraryTemplateDetailsVisibleLines() {
		footer += " | up/down/pgup/pgdown: Scroll"
	}
	return footer
}
