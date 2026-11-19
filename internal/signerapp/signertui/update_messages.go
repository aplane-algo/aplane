// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/aplane-algo/aplane/internal/cosigner/cosignerrefs"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/theme"

	tea "github.com/charmbracelet/bubbletea"
)

// Handlers for the messages update dispatches whose handling is more than a
// few lines. Each is the body of its case in update.

func (m Model) handleKeyMsg(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.belowMinSize() {
		// The operator cannot see the screen a key would act on, so
		// only quitting is allowed, and nothing counts as activity.
		if msg.String() == "ctrl+c" {
			return m.handleKeyPress(msg)
		}
		return m, nil
	}
	var activityCmd tea.Cmd
	m, activityCmd = m.recordUserActivity(time.Now(), msg)
	next, cmd := m.handleKeyPress(msg)
	if got, ok := next.(Model); ok {
		return got, tea.Batch(activityCmd, cmd)
	}
	return next, tea.Batch(activityCmd, cmd)
}

func (m Model) handleWindowSizeMsg(msg tea.WindowSizeMsg) (tea.Model, tea.Cmd) {
	m.sizeKnown = true
	m.width = msg.Width
	m.height = msg.Height
	if m.standalone {
		m.height--
	}
	if m.signing.request != nil {
		m.resizeSigningViewport()
	}
	if m.browser.active() {
		m.browser.keepSelectionVisible(m.fileBrowserVisibleRows())
	}
	return m, nil
}

func (m Model) handleAuthResultMsg(msg AuthResultMsg) (tea.Model, tea.Cmd) {
	m.auth.loggingIn = false
	if msg.Success {
		// Server will send signer status next; key-type and template
		// information arrives via the admin protocol (ListKeyTypes).
		m.auth.passphraseError = ""
		m.auth.passphraseInput = ""
		m.resetActivityState()
		// The signer may have restarted since that result.
		m.admin.settingWarning = settingResultWarning{}
	} else if msg.Code == protocol.ErrCodeLoginTimeout {
		// The signer gave up on this login and closes the connection;
		// stay disconnected rather than retake its single login slot.
		m.endAdminSession()
		m.connectionState = ConnectionDisconnected
		m.auth.passphraseInput = ""
		m.auth.passphraseError = ""
		m.auth.endedReason = loginTimeoutReason
		return m, nil
	} else {
		// Authentication failed - show error and stay on auth screen
		m.auth.passphraseError = msg.Error
		if m.auth.passphraseError == "" {
			m.auth.passphraseError = "Authentication failed"
		}
		if isSeriousUnlockError(msg.Code) {
			m.showSeriousErrorPopup("Signer unlock failed", msg.Error, ViewAuth)
			m.auth.passphraseInput = ""
			m.auth.loggingIn = false
		}
	}
	return m, nil
}

func (m Model) handleLocalIdleDisconnectedMsg(msg localIdleDisconnectedMsg) (tea.Model, tea.Cmd) {
	// Stay disconnected: an automatic reconnect would sit at the login
	// screen holding the signer's single login slot, locking out every
	// other apadmin until someone found this terminal.
	m.endAdminSession()
	m.connectionState = ConnectionDisconnected
	m.signerStatusKnown = false
	m.viewState = ViewAuth
	m.auth.passphraseInput = ""
	m.auth.passphraseError = ""
	m.auth.loggingIn = false
	m.auth.endedReason = msg.Reason
	m.lastError = ""
	return m, nil
}

func (m Model) handleSignerStatusMsg(msg SignerStatusMsg) (tea.Model, tea.Cmd) {
	m.signerWarnings = msg.Warnings
	switch signerRuntimeStateFromWire(msg.State) {
	case signerRuntimeUnlocked:
		return m, m.enterUnlocked(msg.KeyCount)
	case signerRuntimeRecovery:
		// Signing is blocked by store damage or an unresolved generation
		// transition; open the general recovery screen.
		return m, m.enterRecovery()
	default:
		// Signer locked; show unlock screen immediately regardless of
		// current view. Any in-progress operation would fail anyway since
		// the keyring has been zeroed. Key types are not asked for: a
		// locked signer cannot list them, and enterUnlocked loads them.
		abort := m.interruptBackupTransfers(true)
		m.applySignerLockedState()
		return m, tea.Batch(m.sendGetAdminSettingsCmd(), abort)
	}
}

func (m Model) handleUnlockResultMsg(msg UnlockResultMsg) (tea.Model, tea.Cmd) {
	m.auth.loggingIn = false
	if msg.Success {
		m.auth.passphraseError = ""
		m.auth.passphraseInput = ""
		if msg.Code == protocol.ResultCodeRecoveryBlocked {
			// Unlock succeeded into recovery mode; signing stays blocked
			// until a strict reconcile/reload succeeds.
			return m, m.enterRecovery()
		}
		return m, m.enterUnlocked(msg.KeyCount)
	} else {
		m.auth.passphraseError = msg.Error
		if isSeriousUnlockError(msg.Code) {
			m.showSeriousErrorPopup("Signer unlock failed", msg.Error, ViewUnlock)
			m.auth.passphraseInput = ""
			m.auth.loggingIn = false
		}
	}
	return m, nil
}

func (m Model) handleKeysListMsg(msg KeysListMsg) (tea.Model, tea.Cmd) {
	// Sort keys alphabetically by address
	sort.Slice(msg.Keys, func(i, j int) bool {
		return msg.Keys[i].Address < msg.Keys[j].Address
	})
	m.keylist.keys = msg.Keys
	m.keyCount = len(msg.Keys)
	// Ensure selectedKey and scrollOffset are within bounds
	displayKeys := m.filteredKeys()
	if m.keylist.selectedKey >= len(displayKeys) {
		m.keylist.selectedKey = len(displayKeys) - 1
		if m.keylist.selectedKey < 0 {
			m.keylist.selectedKey = 0
		}
	}
	if m.keylist.scrollOffset > m.keylist.selectedKey {
		m.keylist.scrollOffset = m.keylist.selectedKey
	}
	return m, nil
}

// handleFailure routes an untyped failure, from the daemon (ErrorMsg) or from
// a send (sendFailedMsg), to the request id names.
func (m Model) handleFailure(id string, err error) (Model, tea.Cmd) {
	if m.mnemonicExport.pending && id == m.mnemonicExport.requestID {
		m.mnemonicExport.pending = false
		m.mnemonicExport.error = err.Error()
		return m, nil
	}
	if next, ok := m.failPendingPolicyExport(id, err); ok {
		return next, nil
	}
	if next, ok := m.failPendingBackupExport(id, err); ok {
		return next, nil
	}
	if next, cmd, ok := m.failPendingBackupImport(id, err); ok {
		return next, cmd
	}
	if next, ok := m.failPendingBackupDelete(id, err); ok {
		return next, nil
	}
	if next, ok := m.failPendingPolicyApply(id, err); ok {
		return next, nil
	}
	if next, ok := m.failOperationInProgress(id, err); ok {
		return next, nil
	}
	if id != "" && id == m.restore.pendingID {
		return m.failRestoreRequest(err), nil
	}
	m.lastError = err.Error()
	return m, nil
}

func (m Model) handleGenerateResultMsg(msg GenerateResultMsg) (tea.Model, tea.Cmd) {
	if !m.takeOperationReply(msg.ID) {
		return m, nil
	}
	m = m.settleGenerateReview(msg)
	if msg.Success {
		m.lastError = ""
		m.cosigner.generateFromManager = false
		m.forms.generatedAddress = msg.Address
		m.forms.generatedKeyType = msg.KeyType
		m.forms.generatedWarnings = msg.Warnings
		m.forms.generatedWarningsOpen = false
		m.viewState = ViewGenerateDisplay
		return m, m.sendListKeysCmd()
	} else {
		m.forms.generateError = msg.Error
		// Go back to params view for generic LogicSigs, otherwise form
		if m.forms.genericLSigParams != nil {
			m.viewState = ViewGenerateParams
		} else {
			m.viewState = ViewGenerateForm
		}
	}
	return m, nil
}

func (m Model) handleDeleteResultMsg(msg DeleteResultMsg) (tea.Model, tea.Cmd) {
	if !m.takeOperationReply(msg.ID) {
		return m, nil
	}
	if msg.Success {
		m.lastError = ""
		// Clear delete state and return to key list
		m.del.address = ""
		m.del.keyType = ""
		m.viewState = ViewKeyList
		// Request updated key list
		return m, m.sendListKeysCmd()
	} else {
		m.lastError = msg.Error
		// Return to confirm dialog on error
		m.viewState = ViewDeleteConfirm
	}
	return m, nil
}

func (m Model) handleRestorePreviewMsg(msg RestorePreviewMsg) (tea.Model, tea.Cmd) {
	m.restore.previewing = false
	if msg.Error != "" || (len(msg.Keys) == 0 && len(msg.Errors) > 0) {
		m.clearRestorePassphrase()
		m.restore.passphraseError = msg.Error
		if m.restore.passphraseError == "" {
			m.restore.passphraseError = firstRestoreError(msg.Errors)
		}
		if m.restore.passphraseError == "" {
			m.restore.passphraseError = "Restore preview failed"
		}
		m.viewState = ViewRestorePassphrase
		return m, nil
	}
	m.lastError = ""
	m.restore.archivePath = msg.ArchivePath
	m.restore.archiveCreatedAt = msg.ArchiveCreatedAt
	m.restore.previewKeys = msg.Keys
	m.restore.previewErrors = msg.Errors
	m.restore.passphraseError = ""
	m.restore.previewError = ""
	m.restore.selectedKey = 0
	m.restore.previewScrollOffset = 0
	m.restore.previewFocus = restoreFocusList
	m.initializeRestoreSelection()
	m.viewState = ViewRestorePreview
	return m, nil
}

func (m Model) handleRestoreBackupResultMsg(msg RestoreBackupResultMsg) (tea.Model, tea.Cmd) {
	if !msg.Result.Success && msg.Result.Code == protocol.ResultCodeRestoreConflict {
		m.clearRestorePassphrase()
		m.restore.replaceExisting = true
		m.restore.replaceConflicts = append([]RestoreConflict(nil), msg.Result.Conflicts...)
		m.restore.passphraseError = fmt.Sprintf(
			"%d credential conflict(s). Re-enter the export passphrase and press Enter to confirm replacement.",
			len(msg.Result.Conflicts),
		)
		m.viewState = ViewRestorePassphrase
		return m, nil
	}
	m.clearRestorePassphrase()
	m.restore.replaceExisting = false
	m.restore.replaceConflicts = nil
	withPolicy := make(map[string]bool, len(msg.Result.PoliciesRestored))
	for _, key := range msg.Result.PoliciesRestored {
		withPolicy[key] = true
	}
	restored := make([]RestoreKeyInfo, 0, len(msg.Result.Restored)+len(withPolicy))
	for _, entry := range msg.Result.Restored {
		restored = append(restored, RestoreKeyInfo{Address: entry.Selector, KeyType: entry.KeyType, HasPolicy: withPolicy[entry.Selector]})
		delete(withPolicy, entry.Selector)
	}
	for _, key := range msg.Result.PoliciesRestored {
		if withPolicy[key] {
			restored = append(restored, RestoreKeyInfo{Address: key, HasPolicy: true})
		}
	}
	m.restore.result = RestoreDisplayResult{
		ArchivePath: m.restore.archivePath,
		Success:     msg.Result.Success,
		Activated:   restored,
		KeyCount:    msg.Result.KeyCount,
		Error:       msg.Result.Error,
	}
	m.restore.displaySelectedKey = 0
	m.restore.displayScrollOffset = 0
	m.viewState = ViewRestoreDisplay
	var cmds []tea.Cmd
	if msg.Result.Success {
		cmds = append(cmds, m.sendListKeysCmd(), m.sendListKeyTypesCmd())
	} else if msg.Result.Code == protocol.ResultCodeRestoreRollbackFailed {
		m.signerState = signerRuntimeRecovery
	}
	return m, tea.Batch(cmds...)
}

func (m Model) handleRollbackRestoreResultMsg(msg RollbackRestoreResultMsg) (tea.Model, tea.Cmd) {
	if m.signerKnownLocked() {
		return m.recordLateRollback(msg.Result), nil
	}
	if !msg.Result.Success {
		if next, cmd, ok := m.handleRefusedBackupUndo(msg.Result); ok {
			return next, cmd
		}
		if msg.Result.Code == protocol.ResultCodeRestoreRollbackFailed {
			m.signerState = signerRuntimeRecovery
		}
		m.restore.recoveryError = msg.Result.Error
		if m.signerState == signerRuntimeRecovery {
			m.viewState = ViewStoreRecovery
		} else {
			m.lastError = msg.Result.Error
			m.viewState = ViewKeyList
		}
		return m, nil
	}
	m.backups.undoPending = false
	m.restore.recoveryError = "Restore rollback completed; reconciling current generation"
	m.viewState = ViewStoreRecovery
	return m, m.sendReconcileStoreCmd(m.beginRestoreRequest("reconcile-store"))
}

func (m Model) handleReconcileStoreResultMsg(msg ReconcileStoreResultMsg) (tea.Model, tea.Cmd) {
	if m.signerKnownLocked() {
		// The signer locked after the reconcile was sent; its state on
		// the next unlock says what is needed. (A reply from an ended
		// session is never delivered.)
		if !msg.Result.Success {
			m.restore.recoveryError = msg.Result.Error
		}
		return m, nil
	}
	if !msg.Result.Success {
		// The signer is recovery-blocked whichever screen the operator
		// moved to; the recovery screen is where that is handled.
		m.signerState = signerRuntimeRecovery
		m.restore.recoveryError = msg.Result.Error
		m.viewState = ViewStoreRecovery
		return m, nil
	}
	m.restore.recoveryError = ""
	if !m.restoreFlowWaiting() {
		// The operator moved on from the recovery screen meanwhile: the
		// signer is unlocked all the same, so enter that state, loading
		// what unlock loads, but keep their screen.
		view := m.viewState
		cmd := m.enterUnlocked(msg.Result.KeyCount)
		m.viewState = view
		m.restore.returnToRecovery = false
		return m, cmd
	}
	return m, m.enterUnlocked(msg.Result.KeyCount)
}

func (m Model) handleImportResultMsg(msg ImportResultMsg) (tea.Model, tea.Cmd) {
	if !m.takeOperationReply(msg.ID) {
		return m, nil
	}
	if msg.Success {
		m.lastError = ""
		m.forms.importMnemonicInput.SetValue("")
		m.forms.importMnemonicInput.Blur()
		m.forms.importError = ""
		// Store imported key info for display
		m.forms.importedAddress = msg.Address
		m.forms.importedKeyType = msg.KeyType
		m.viewState = ViewImportDisplay
		// Also refresh key list in background
		return m, m.sendListKeysCmd()
	} else {
		m.forms.importError = msg.Error
		// Return to the form the import was sent from to show the error.
		m.viewState = m.importErrorView()
	}
	return m, nil
}

// importErrorView is the form a failed import returns to: the parameter form
// for a key type that takes parameters, otherwise the import form.
func (m Model) importErrorView() ViewState {
	if getParamSpecForKeyType(getImportKeyTypeByIndex(m.forms.importKeyType)) != nil {
		return ViewImportParams
	}
	return ViewImportForm
}

func (m Model) handleAdminSettingsMsg(msg AdminSettingsMsg) (tea.Model, tea.Cmd) {
	// Detect theme change and re-init styles
	if m.admin.settings == nil || m.admin.settings.Theme != msg.Settings.Theme {
		theme.Init(msg.Settings.Theme)
		initStyles()
	}
	m.admin.settings = &msg.Settings
	if w := m.admin.settingWarning; w.key != "" && !slices.Contains(msg.Settings.UnsavedSettings, w.key) {
		// Saved since, perhaps by another admin client.
		m.admin.settingWarning = settingResultWarning{}
	}
	m.syncKeyListTabWithMode()
	timeoutCmd := m.applyAdminSettingsTimeout(msg.Settings)
	return m, timeoutCmd
}

func (m Model) handleAdminSettingUpdatedMsg(msg AdminSettingUpdatedMsg) (tea.Model, tea.Cmd) {
	// A value in effect but not saved is not a failure. The panel draws
	// its unsaved warning from the settings re-read below; the status
	// line gives the signer's reason.
	switch {
	case msg.Code == protocol.ResultCodeAppliedNotSaved:
		reason := msg.Error
		if reason == "" {
			reason = msg.Key + " is in effect but not saved"
		}
		text := "Warning: " + reason
		if m.settingUnsaved(msg.Key) {
			// A retry of a save that had failed failed again: the way
			// out goes ahead of the cause, so the line's cut keeps it.
			text = "restart apsigner for the saved value; " + msg.Key + " still not saved: " + reason
		}
		m.admin.settingWarning = settingResultWarning{key: msg.Key, text: text}
	case !msg.Success:
		m.lastError = "Setting update failed: " + msg.Error
	case msg.Key == m.admin.settingWarning.key:
		m.admin.settingWarning = settingResultWarning{}
	}
	// Re-read the settings either way: a failed update can still be in
	// effect (a restrictive value not saved), so the panel shows what the
	// signer holds rather than what it showed before.
	return m, m.sendGetAdminSettingsCmd()
}

func (m Model) handleKeyDetailsMsg(msg KeyDetailsMsg) (tea.Model, tea.Cmd) {
	if msg.Success {
		m.details.address = msg.Address
		m.details.keyType = msg.KeyType
		m.details.publicKeyHex = msg.PublicKeyHex
		m.details.parameters = msg.Parameters
		m.details.teal = msg.DisplayTEAL
		m.details.templateProvenanceStatus = msg.TemplateProvenanceStatus
		m.details.templateProvenanceNote = msg.TemplateProvenanceNote
		m.details.policyLabel = msg.PolicyLabel
		m.details.mnemonicExportable = msg.MnemonicExportable
		m.details.scrollOffset = 0 // Reset scroll on open
		m.viewState = ViewKeyDetails
	} else {
		m.lastError = msg.Error
	}
	return m, nil
}

func (m Model) handleLibraryTemplatesMsg(msg LibraryTemplatesMsg) (tea.Model, tea.Cmd) {
	if msg.Error != "" {
		m.library.installError = msg.Error
		m.library.installStatus = ""
	} else {
		m.library.templates = msg.Templates
		if m.library.selectedTemplate >= len(m.library.templates) {
			m.library.selectedTemplate = len(m.library.templates) - 1
		}
		if m.library.selectedTemplate < 0 {
			m.library.selectedTemplate = 0
		}
		m = m.ensureTemplateVisible()
	}
	return m, nil
}

func (m Model) handleShowLibraryTemplateResultMsg(msg ShowLibraryTemplateResultMsg) (tea.Model, tea.Cmd) {
	// Only adopt the result if we're still waiting for it; ignore late replies
	// after the user has navigated away.
	if m.viewState == ViewLibraryTemplateDetails &&
		m.library.detailsLoading &&
		msg.KeyType == m.library.detailsKeyType &&
		(m.library.detailsInstalled || msg.TemplateType == m.library.detailsTemplateType) {
		m.library.detailsLoading = false
		if msg.Success {
			m.library.detailsContent = string(msg.TemplateYAML)
			m.library.detailsSourcePath = msg.SourcePath
			m.library.detailsSourceSHA256 = msg.SourceSHA256
			m.library.detailsSourceModTime = msg.SourceModTime
			m.library.detailsError = ""
			m.library.detailsScrollOffset = 0
		} else {
			m.library.detailsContent = ""
			m.library.detailsSourceSHA256 = ""
			m.library.detailsSourceModTime = 0
			m.library.detailsError = msg.Error
			if m.library.detailsError == "" {
				m.library.detailsError = "Failed to load library YAML"
			}
		}
	}
	return m, nil
}

func (m Model) handleKeyTypesMsg(msg KeyTypesMsg) (tea.Model, tea.Cmd) {
	if msg.Error != "" {
		m.lastError = msg.Error
	} else {
		selectedGenerate := m.generateSelection()
		selectedImport := getImportKeyTypeByIndex(m.forms.importKeyType)
		m.serverKeyTypes = msg.KeyTypes
		setServerKeyTypes(msg.KeyTypes)
		m = m.reselectKeyTypes(selectedGenerate, selectedImport)
		resumeEnrollment := false
		for _, info := range msg.KeyTypes {
			if info.KeyType != m.cosigner.pendingKeyType {
				continue
			}
			// A per-key type does not advertise the selector, because its
			// cosigner is optional. The preset that asked for one is the field,
			// and so is the overlay form's cosigner control, preset or not.
			resumeEnrollment = m.forms.boundaryPreset != nil
			for _, param := range info.CreationParams {
				if param.Name == cosignerrefs.ParamCosignerName {
					resumeEnrollment = true
					break
				}
			}
			if spec := m.paramSpecFor(info.KeyType); spec != nil && spec.Overlay {
				resumeEnrollment = true
			}
			break
		}
		if m.cosigner.pendingWitnessID != "" && m.cosigner.pendingKeyType != "" && resumeEnrollment {
			m = m.resumeCosignerImport()
		}
	}
	return m, nil
}

func (m Model) handleCosignerRemoveResultMsg(msg CosignerRemoveResultMsg) (tea.Model, tea.Cmd) {
	if !m.takeOperationReply(msg.ID) {
		return m, nil
	}
	if !msg.Success {
		m.cosigner.importError = msg.Error
		if m.cosigner.importError == "" {
			m.cosigner.importError = "Cosigner reference removal failed"
		}
		m.viewState = ViewCosignerRemoveConfirm
		return m, nil
	}
	m.cosigner.importError = ""
	if msg.Removed {
		m.cosigner.managerStatus = "Removed " + msg.Name
	} else {
		m.cosigner.managerStatus = msg.Name + " was already absent"
	}
	m.viewState = ViewCosignerReferences
	return m, tea.Batch(
		m.sendListCosignerReferencesCmd(),
		m.sendListKeyTypesCmd(),
	)
}

func (m Model) handleCosignerExportResultMsg(msg CosignerExportResultMsg) (tea.Model, tea.Cmd) {
	if !m.takeOperationReply(msg.ID) {
		return m, nil
	}
	if !msg.Success {
		m.cosigner.exportError = msg.Error
		if m.cosigner.exportError == "" {
			m.cosigner.exportError = "Cosigner key export failed"
		}
		m.viewState = ViewCosignerExportPath
		return m, nil
	}
	if msg.WitnessKeyID != m.cosigner.exportWitnessID || msg.EnvelopeJSON == "" {
		m.cosigner.exportError = "Signer returned inconsistent cosigner key metadata"
		m.viewState = ViewCosignerExportPath
		return m, nil
	}
	artifactJSON, err := composeCosignerExportArtifact(msg.EnvelopeJSON)
	if err != nil {
		m.cosigner.exportError = "Cannot compose cosigner key JSON: " + err.Error()
		m.viewState = ViewCosignerExportPath
		return m, nil
	}
	if m.cosigner.exportShowJSON {
		m.cosigner.exportError = ""
		m.viewState = ViewCosignerExportJSON
		return m, tea.Exec(&cosignerJSONTerminalDisplay{document: artifactJSON}, func(err error) tea.Msg {
			return cosignerJSONTerminalClosedMsg{err: err}
		})
	}
	return m, writeCosignerPublicEnvelopeCmd(m.cosigner.exportPath, artifactJSON)
}
