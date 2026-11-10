// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"strings"

	"github.com/aplane-algo/aplane/internal/witness"
)

func (m Model) viewFooterText() string {
	if m.fileBrowserOpen() {
		return m.fileBrowserFooterText()
	}
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
		if m.details.mnemonicExportable {
			parts = append(parts, "m=recovery phrase")
		}
		if m.isCosignerNode() && witness.IsKeyType(m.details.keyType) {
			parts = append(parts, "e=export cosigner key")
		}
		if m.details.teal != "" {
			parts = append(parts, "t=TEAL", "s=save")
		}
		parts = append(parts, "esc/q: Back")
		return strings.Join(parts, " | ")
	case ViewMnemonicExport:
		return "Esc: close recovery phrase"
	case ViewTEALFullDisplay:
		footer := "Esc/q close"
		if len(strings.Split(m.details.teal, "\n")) > m.tealFullDisplayVisibleLines() {
			footer += " | up/down/pgup/pgdown: Scroll"
		}
		return footer
	case ViewSigningPopup:
		return "left/right/tab: Focus | enter/space: Submit | y/a: Approve | n/r/esc: Reject"
	case ViewClientEnrollmentPopup:
		return "left/right/tab: Focus | enter/space: Submit | y/a: Approve | n/r: Reject | esc: Defer"
	case ViewBackupConfirm:
		return "Tab: Next | Enter: Create backup | Esc: Back"
	case ViewGenerateDisplay:
		if m.forms.generatedWarningsOpen {
			return "w/Esc: Back"
		}
		if len(m.forms.generatedWarnings) > 0 {
			if _, ok := m.generatedReceipt(); ok {
				return "w: Warnings in full | s: Save receipt | Enter/Esc: Back"
			}
			return "w: Warnings in full | Enter/Esc: Back"
		}
		if m.isCosignerNode() && witness.IsKeyType(m.forms.generatedKeyType) {
			return "e: Export setup file | Enter/Esc: Back"
		}
		if _, ok := m.generatedReceipt(); ok {
			return "s: Save receipt | Enter/Esc: Back"
		}
		return "Enter/Esc: Back"
	case ViewBoundaryPreset:
		if m.boundaryFileRowSelected() {
			return "Enter: Load | ctrl+o: Browse | Esc: Back"
		}
		return "Up/Down: Choose | Enter: Select | Esc: Back"
	case ViewGenerateReview:
		return "Tab: Focus | d: Details | Enter: Select | Esc: Back"
	case ViewGenerateReviewDetails:
		return "Ctrl+PgUp/PgDn: Scroll | Esc: Back"
	case ViewBackupDisplay, ViewImportDisplay:
		return "Enter/Esc: Back"
	case ViewBackups:
		return m.backupsFooterText()
	case ViewBackupDeleteConfirm:
		if m.backups.del.pendingID != "" {
			return ""
		}
		return "left/right/tab: Focus | enter/space: Select | y: Delete | n/esc: Cancel"
	case ViewBackupUndoConfirm:
		return "left/right/tab: Focus | enter/space: Select | y: Undo | n/esc: Cancel"
	case ViewBackupExport:
		return m.backupExportFooterText()
	case ViewBackupImport:
		return m.backupImportFooterText()
	case ViewRestorePassphrase:
		if m.restore.previewing {
			return "Previewing backup archive"
		}
		if m.restore.replaceExisting {
			return "Enter: Replace listed credentials | Esc: Back"
		}
		return "Enter: Preview | Esc: Back"
	case ViewRestorePreview:
		return "Space: Toggle | a: Select all | Tab: Restore button | Enter: Restore | Esc: Back"
	case ViewStoreRecovery:
		return "r: Reconcile | x: Roll back restore | b: Backups | l: Lock | q: Quit"
	case ViewRestoreDisplay:
		return "up/down: Select | Enter/Esc: Back"
	case ViewGenerateForm:
		return "up/down: Select | enter: Generate | t: Template | esc: Back"
	case ViewGenerateParams:
		return m.parameterModalFooterText(getKeyTypeByIndex(m.forms.generateKeyType), "Generate")
	case ViewCosignerPicker:
		return "up/down: Select | enter: Choose | esc: Back"
	case ViewCosignerImportForm:
		if m.cosigner.importPaste {
			return "Paste: Replace JSON | Tab: Next | Enter: Continue | Esc: Back"
		}
		return "Tab: Next | ctrl+o: Browse | Enter: Review | Esc: Back"
	case ViewCosignerImportReview:
		if len(m.cosigner.reuseAliases) > 0 {
			return "Enter/y: Use existing key | n/Esc: Back"
		}
		return "Enter/y: Enroll | n/Esc: Back"
	case ViewCosignerReferences:
		return "up/down: Select | enter: Details | i: Import file | p: Paste JSON | r: Refresh | esc/q: Back"
	case ViewCosignerReferenceDetails:
		return "g: Generate account | d: Remove alias | esc/q: Back"
	case ViewCosignerRemoveConfirm:
		return "left/right/tab: Focus | enter/space: Select | y: Remove | n/esc: Cancel"
	case ViewCosignerGenerateType:
		return "up/down: Select | enter: Continue | esc/q: Back"
	case ViewCosignerExportPath:
		return "Tab: Next | ctrl+o: Browse | Enter: Select | Esc: Back"
	case ViewCosignerExportResult:
		return "Enter/Esc: Back"
	case ViewCosignerExportJSON:
		return "Enter: Return to export"
	case ViewImportForm:
		return "up/down: Select key type | tab: Next | enter: Import | esc: Back"
	case ViewImportParams:
		return m.parameterModalFooterText(getImportKeyTypeByIndex(m.forms.importKeyType), "Import")
	case ViewGenerating, ViewImporting, ViewCosignerImporting, ViewCosignerRemoving, ViewCosignerExporting, ViewDeleting, ViewTemplateInstalling, ViewBackingUp, ViewRestoring:
		return "q: Quit"
	case ViewDeleteConfirm:
		return "left/right/tab: Focus | enter/space: Select | y: Delete | n/esc: Cancel"
	case ViewEnrolledClients:
		return "up/down: Select | r: Revoke selected | A: Revoke all | esc: Back"
	case ViewRevokeClientConfirm:
		return "left/right/tab: Focus | enter/space: Select | y: Revoke | n/esc: Cancel"
	case ViewImportClientKey:
		return "Tab: Next | ctrl+o: Browse | Enter: Continue | Esc: Cancel"
	case ViewLockConfirm:
		return "left/right/tab: Focus | enter/space: Select | y: Lock | n/esc: Cancel"
	case ViewDisplaceConfirm:
		return "left/right/tab: Focus | enter/space: Select | y: Proceed | n/esc: Cancel"
	case ViewAdminPanel:
		return "p: Policies | k: KeyTypes | l: Lock | esc: Back"
	case ViewPolicies, ViewPolicyDocument:
		return m.policiesFooterText()
	case ViewPolicyApplyForm, ViewPolicyApplyReview:
		return m.policyApplyFooterText()
	case ViewPolicyEdit:
		return m.policyEditFooterText()
	case ViewPolicyPresetPick:
		return "up/down: Select | enter: Open in editor | esc/q: Back"
	case ViewPolicyExportForm:
		if m.policies.export.busy != "" {
			return "esc: Cancel"
		}
		return "enter: Export | ctrl+o: Browse | esc: Cancel"
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
	spec := m.paramSpecFor(keyType)
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

func (m Model) libraryTemplateDetailsFooterText() string {
	footer := "Esc/q close"
	if m.library.detailsContent != "" &&
		len(strings.Split(m.library.detailsContent, "\n")) > m.libraryTemplateDetailsVisibleLines() {
		footer += " | up/down/pgup/pgdown: Scroll"
	}
	return footer
}
