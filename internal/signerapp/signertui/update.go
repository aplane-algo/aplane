// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

// Core update loop and message handling.
// View-specific handlers are in update_*.go files.

import (
	"sort"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/theme"

	tea "github.com/charmbracelet/bubbletea"
)

// adminRefreshInterval is how often the admin panel polls for updated settings.
const adminRefreshInterval = 2 * time.Second

const transientWarningDuration = 5 * time.Second

// adminRefreshTickCmd returns a tea.Cmd that fires after adminRefreshInterval.
func adminRefreshTickCmd() tea.Cmd {
	return tea.Tick(adminRefreshInterval, func(time.Time) tea.Msg {
		return adminRefreshTickMsg{}
	})
}

func clearWarningTickCmd(generation uint64) tea.Cmd {
	return tea.Tick(transientWarningDuration, func(time.Time) tea.Msg {
		return clearWarningMsg{Generation: generation}
	})
}

func (m *Model) setPersistentWarning(warning string) {
	m.lastWarningGeneration++
	m.lastWarning = warning
}

func (m *Model) clearWarning() {
	m.lastWarningGeneration++
	m.lastWarning = ""
}

func (m *Model) clearWarningIf(warning string) {
	if m.lastWarning == warning {
		m.clearWarning()
	}
}

func (m *Model) setTransientWarning(warning string) tea.Cmd {
	m.setPersistentWarning(warning)
	return clearWarningTickCmd(m.lastWarningGeneration)
}

// Update handles all TUI events and messages
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		var activityCmd tea.Cmd
		m, activityCmd = m.recordUserActivity(time.Now(), msg)
		next, cmd := m.handleKeyPress(msg)
		if got, ok := next.(Model); ok {
			return got, tea.Batch(activityCmd, cmd)
		}
		return next, tea.Batch(activityCmd, cmd)

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		if m.standalone {
			m.height--
		}
		if m.viewState == ViewSigningPopup {
			m.resizeSigningViewport()
		}
		if m.viewState == ViewPolicyEditor && m.policyEd.editor != nil {
			return m.forwardPolicyEditorMsg(tea.WindowSizeMsg{Width: m.width, Height: m.policyEditorHeight()})
		}
		return m, nil

	case ConnectedMsg:
		m.connectionState = ConnectionConnected
		if msg.Client != nil {
			m.adminClient = msg.Client
		}
		m.resetActivityState()
		// Start listening for messages - server will send auth_required first
		return m, m.waitForMessageCmd()

	case AuthRequiredMsg:
		// Server requires authentication - show auth screen
		m.clearRestorePassphrase()
		m.resetActivityState()
		m.viewState = ViewAuth
		m.auth.passphraseInput = ""
		m.auth.passphraseError = ""
		return m, m.waitForMessageCmd()

	case AuthResultMsg:
		m.auth.loggingIn = false
		if msg.Success {
			// Server will send signer status next; key-type and template
			// information arrives via the admin protocol (ListKeyTypes).
			m.auth.passphraseError = ""
			m.auth.passphraseInput = ""
			m.clearWarningIf(localIdleDisconnectReason)
			m.resetActivityState()
		} else {
			// Authentication failed - show error and stay on auth screen
			m.auth.passphraseError = msg.Error
			if m.auth.passphraseError == "" {
				m.auth.passphraseError = "Authentication failed"
			}
			if isSeriousUnlockError(msg.Code, msg.Error) {
				m.showSeriousErrorPopup("Signer unlock failed", msg.Error, ViewAuth)
				m.auth.passphraseInput = ""
				m.auth.loggingIn = false
			}
		}
		return m, m.waitForMessageCmd()

	case DisconnectedMsg:
		m.clearRestorePassphrase()
		m.resetActivityState()
		m.manualLock.pending = false
		m.connectionState = ConnectionDisconnected
		if msg.Error != nil {
			m.lastError = msg.Error.Error()
		}
		return m, nil

	case localIdleDisconnectedMsg:
		m.clearRestorePassphrase()
		m.resetActivityState()
		m.manualLock.pending = false
		m.connectionState = ConnectionConnecting
		m.signerStatusKnown = false
		m.viewState = ViewAuth
		m.auth.passphraseInput = ""
		m.auth.passphraseError = ""
		m.auth.loggingIn = false
		m.lastError = ""
		m.setPersistentWarning(msg.Reason)
		return m, m.reconnectCmd()

	case SignerStatusMsg:
		switch signerRuntimeStateFromWire(msg.State) {
		case signerRuntimeUnlocked:
			m.applySignerUnlockedState(msg.KeyCount)
			idleCmd := m.armLocalIdleTimer()
			// If signer is already unlocked, request key list
			return m, tea.Batch(m.waitForMessageCmd(), m.sendListKeysCmd(), m.sendListKeyTypesCmd(), m.sendGetAdminSettingsCmd(), idleCmd)
		case signerRuntimeRecovery:
			// Signing is blocked by an incomplete activation; open the
			// blocking recovery screen instead of normal navigation.
			m.applySignerRecoveryState()
			return m, tea.Batch(m.waitForMessageCmd(), m.sendListRecoveredCmd(), m.sendGetAdminSettingsCmd(), m.armLocalIdleTimer())
		default:
			// Signer locked; show unlock screen immediately regardless of
			// current view. Any in-progress operation would fail anyway since
			// the master key has been zeroed.
			m.applySignerLockedState()
			return m, tea.Batch(m.waitForMessageCmd(), m.sendListKeyTypesCmd(), m.sendGetAdminSettingsCmd())
		}

	case UnlockResultMsg:
		m.auth.loggingIn = false
		if msg.Success {
			m.auth.passphraseError = ""
			m.auth.passphraseInput = ""
			m.clearWarningIf(localIdleDisconnectReason)
			if msg.Code == protocol.ResultCodeActivationIncomplete {
				// Unlock succeeded into recovery mode: automatic
				// reconciliation could not resolve every incomplete
				// activation, so signing stays blocked.
				m.applySignerRecoveryState()
				return m, tea.Batch(m.waitForMessageCmd(), m.sendListRecoveredCmd(), m.sendGetAdminSettingsCmd(), m.armLocalIdleTimer())
			}
			m.applySignerUnlockedState(msg.KeyCount)
			idleCmd := m.armLocalIdleTimer()
			// Request the key list after unlocking
			return m, tea.Batch(m.waitForMessageCmd(), m.sendListKeysCmd(), m.sendListKeyTypesCmd(), m.sendGetAdminSettingsCmd(), idleCmd)
		} else {
			m.auth.passphraseError = msg.Error
			if isSeriousUnlockError(msg.Code, msg.Error) {
				m.showSeriousErrorPopup("Signer unlock failed", msg.Error, ViewUnlock)
				m.auth.passphraseInput = ""
				m.auth.loggingIn = false
			}
		}
		// Continue listening for messages
		return m, m.waitForMessageCmd()

	case LockIdentityResultMsg:
		if msg.Success {
			m.manualLock.pending = false
			m.applySignerLockedState()
			return m, tea.Batch(m.waitForMessageCmd(), m.sendListKeyTypesCmd())
		}
		if m.manualLock.pending {
			return m, tea.Batch(m.waitForMessageCmd(), m.handleManualLockFailed(msg.Error))
		}
		return m, tea.Batch(m.waitForMessageCmd(), m.handleManualLockFailed(msg.Error))

	case SignRequestReceivedMsg:
		m.signing.request = &msg.Request
		m.signing.focus = 1 // Default to reject button (safety-first)
		m.viewState = ViewSigningPopup
		// Initialize scrollable viewport with description + violations
		m.initSigningViewport(m.buildSigningViewportContent())
		// Continue listening for messages
		return m, m.waitForMessageCmd()

	case SignRequestCanceledMsg:
		var warningCmd tea.Cmd
		if m.signing.request != nil && m.signing.request.ID == msg.ID {
			m.signing.request = nil
			m.viewState = ViewKeyList
			warningCmd = m.setTransientWarning(signRequestCanceledWarning(msg.Reason))
		}
		return m, tea.Batch(m.waitForMessageCmd(), warningCmd)

	case TokenProvisioningRequestReceivedMsg:
		m.tokenApproval.request = &msg.Request
		m.tokenApproval.focus = 1 // Default to reject button (safety-first)
		m.viewState = ViewTokenProvisioningPopup
		// Continue listening for messages
		return m, m.waitForMessageCmd()

	case KeysListMsg:
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
		// Continue listening for messages
		return m, m.waitForMessageCmd()

	case ErrorMsg:
		if m.viewState == ViewRestorePassphrase || m.viewState == ViewRestorePreview || m.viewState == ViewRestoring {
			m.clearRestorePassphrase()
			m.restore.previewing = false
		}
		if m.viewState == ViewRestoring {
			// An untyped failure (authorization denial, service
			// unavailable, a send error) must not strand the operator on
			// the progress screen, where Esc refuses and only q quits.
			// Route the same way typed failures do.
			if m.signerState == signerRuntimeRecovery || m.restore.restoreID != "" {
				m.restore.recoveredError = msg.Error.Error()
				return m.openRecoveredList()
			}
			m.lastError = msg.Error.Error()
			m.viewState = ViewRestoreList
			return m, m.waitForMessageCmd()
		}
		m.lastError = msg.Error.Error()
		// Continue listening for messages
		return m, m.waitForMessageCmd()

	case KeysChangedMsg:
		// Server notified us that keys or key types changed - refresh both projections.
		return m, tea.Batch(m.waitForMessageCmd(), m.sendListKeysCmd(), m.sendListKeyTypesCmd())

	case ReconnectingMsg:
		m.clearRestorePassphrase()
		m.resetActivityState()
		m.connectionState = ConnectionConnecting
		// Continue listening for messages
		return m, m.waitForMessageCmd()

	case GenerateResultMsg:
		if msg.Success {
			m.lastError = ""
			m.forms.generatedAddress = msg.Address
			m.forms.generatedKeyType = msg.KeyType
			m.viewState = ViewGenerateDisplay
			return m, tea.Batch(m.waitForMessageCmd(), m.sendListKeysCmd())
		} else {
			m.forms.generateError = msg.Error
			// Go back to params view for generic LogicSigs, otherwise form
			if m.forms.genericLSigParams != nil {
				m.viewState = ViewGenerateParams
			} else {
				m.viewState = ViewGenerateForm
			}
		}
		return m, m.waitForMessageCmd()

	case RevokeTokenResultMsg:
		if msg.Success {
			m.lastError = ""
			warningCmd := m.setTransientWarning("Token revoked - clients must re-enroll")
			m.viewState = ViewAdminPanel
			return m, tea.Batch(m.waitForMessageCmd(), m.sendGetAdminSettingsCmd(), adminRefreshTickCmd(), warningCmd)
		} else {
			m.lastError = "Token revocation failed: " + msg.Error
		}
		m.viewState = ViewAdminPanel
		return m, tea.Batch(m.waitForMessageCmd(), m.sendGetAdminSettingsCmd(), adminRefreshTickCmd())

	case DeleteResultMsg:
		if msg.Success {
			m.lastError = ""
			// Clear delete state and return to key list
			m.del.address = ""
			m.del.keyType = ""
			m.viewState = ViewKeyList
			// Request updated key list
			return m, tea.Batch(m.waitForMessageCmd(), m.sendListKeysCmd())
		} else {
			m.lastError = msg.Error
			// Return to confirm dialog on error
			m.viewState = ViewDeleteConfirm
		}
		return m, m.waitForMessageCmd()

	case BackupResultMsg:
		if msg.Success {
			m.lastError = ""
			m.backup.archivePath = msg.ArchivePath
			m.backup.skippedKeys = msg.SkippedKeys
			m.backup.exportPassphrase = ""
			m.backup.confirmPassphrase = ""
			m.backup.confirmError = ""
			m.viewState = ViewBackupDisplay
		} else {
			m.backup.confirmError = msg.Error
			m.viewState = ViewBackupConfirm
		}
		return m, m.waitForMessageCmd()

	case BackupsListMsg:
		m.restore.backupsLoaded = true
		if msg.Error != "" {
			m.lastError = "Backup list failed: " + msg.Error
		} else {
			m.lastError = ""
			m.restore.backups = msg.Backups
			m.clampRestoreSelection()
			if m.viewState != ViewRestoreList {
				m.viewState = ViewRestoreList
			}
		}
		return m, m.waitForMessageCmd()

	case RestorePreviewMsg:
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
			return m, m.waitForMessageCmd()
		}
		m.lastError = ""
		m.restore.archivePath = msg.ArchivePath
		m.restore.previewKeys = msg.Keys
		m.restore.previewErrors = msg.Errors
		m.restore.passphraseError = ""
		m.restore.previewError = ""
		m.restore.selectedKey = 0
		m.restore.previewScrollOffset = 0
		m.restore.previewFocus = restoreFocusList
		m.initializeRestoreSelection()
		m.viewState = ViewRestorePreview
		return m, m.waitForMessageCmd()

	case RecoverBackupResultMsg:
		m.clearRestorePassphrase()
		if !msg.Success {
			m.restore.result = RestoreDisplayResult{
				ArchivePath: m.restore.archivePath,
				Success:     false,
				Error:       msg.Error,
			}
			m.viewState = ViewRestoreDisplay
			return m, m.waitForMessageCmd()
		}
		m.restore.restoreID = msg.RestoreID
		return m, tea.Batch(m.sendReviewRecoveredCmd(msg.RestoreID), m.waitForMessageCmd())

	case ReviewRecoveredResultMsg:
		if !msg.Result.Success {
			m.restore.result = RestoreDisplayResult{
				ArchivePath: m.restore.archivePath,
				Success:     false,
				Error:       msg.Result.Error,
			}
			m.viewState = ViewRestoreDisplay
			return m, m.waitForMessageCmd()
		}
		m.restore.review = msg.Result
		m.restore.restoreID = msg.Result.RestoreID
		// A freshly opened review always starts at the top: a stale scroll
		// position from a previous popup must not hide the credentials
		// list on the informed-consent screen.
		m.panelScrollView = ViewRestoreReview
		m.panelScrollPosition = 0
		if msg.Result.State == "activation_incomplete" {
			// Resume: the consent and acknowledgement are fixed to the
			// recorded activation intent the server will verify.
			m.restore.unattendedAcknowledged = msg.Result.AcknowledgeUnattendedSigning
			m.restore.replaceExisting = msg.Result.ReplaceExisting
		} else {
			m.restore.unattendedAcknowledged = false
			m.restore.replaceExisting = false
		}
		m.restore.reviewCursor = 0
		if len(m.reviewCheckboxes()) > 0 {
			m.restore.reviewFocus = restoreFocusList
		} else {
			m.restore.reviewFocus = restoreFocusAction
		}
		m.restore.previewError = ""
		m.viewState = ViewRestoreReview
		return m, m.waitForMessageCmd()

	case ActivateRecoveredResultMsg:
		restored := make([]RestoreKeyInfo, len(msg.Result.Activated))
		for i, entry := range msg.Result.Activated {
			restored[i] = RestoreKeyInfo{
				Address: entry.Selector,
				KeyType: entry.KeyType,
			}
		}
		m.restore.result = RestoreDisplayResult{
			ArchivePath: m.restore.archivePath,
			Success:     msg.Result.Success,
			Activated:   restored,
			Warnings:    append([]string(nil), msg.Result.Warnings...),
			KeyCount:    msg.Result.KeyCount,
			Error:       msg.Result.Error,
		}
		m.restore.displaySelectedKey = 0
		m.restore.displayScrollOffset = 0
		m.viewState = ViewRestoreDisplay
		cmds := []tea.Cmd{m.waitForMessageCmd()}
		if msg.Result.Success {
			if m.signerState == signerRuntimeRecovery {
				// The activation resolved recovery-blocking state; the
				// server pushes the unlocked status when its rescan is
				// clean, and the refreshed list covers the still-blocked
				// case.
				cmds = append(cmds, m.sendListRecoveredCmd())
			}
			cmds = append(cmds, m.sendListKeysCmd(), m.sendListKeyTypesCmd())
		} else if msg.Result.Code == protocol.ResultCodeRecoveredRollbackFailed {
			// A failed rollback blocks signing immediately server-side;
			// mirror it so the client does not pretend to be unlocked.
			m.signerState = signerRuntimeRecovery
		}
		return m, tea.Batch(cmds...)

	case RecoveredListMsg:
		m.restore.recoveredLoaded = true
		if msg.Error != "" {
			m.restore.recoveredError = msg.Error
		} else {
			m.restore.recoveredError = ""
			m.restore.recovered = msg.Batches
			m.clampRecoveredSelection()
		}
		return m, m.waitForMessageCmd()

	case RollbackRecoveredResultMsg:
		cmds := []tea.Cmd{m.waitForMessageCmd()}
		if msg.Result.Success {
			m.restore.recoveredError = ""
			if m.viewState == ViewRestoring {
				m.viewState = ViewRecoveredList
			}
			// The server pushes the unlocked status if its rescan is clean;
			// refresh the list either way.
			cmds = append(cmds, m.sendListRecoveredCmd())
		} else {
			// recovered_rollback_refused means the server refused before
			// mutating anything: no recovery was entered server-side and
			// no corrective status push will ever come, so mirroring
			// recovery here would lock the client into the blocking screen
			// until restart. Only a mutated-and-failed rollback mirrors.
			if msg.Result.Code == protocol.ResultCodeRecoveredRollbackFailed {
				m.signerState = signerRuntimeRecovery
			}
			m.restore.recoveredError = msg.Result.Error
			if m.viewState == ViewRestoring {
				m.viewState = ViewRecoveredList
			}
			cmds = append(cmds, m.sendListRecoveredCmd())
		}
		return m, tea.Batch(cmds...)

	case PurgeRecoveredResultMsg:
		if msg.Result.Success {
			m.restore.recoveredError = ""
		} else {
			m.restore.recoveredError = msg.Result.Error
		}
		if m.viewState == ViewRestoring {
			m.viewState = ViewRecoveredList
		}
		return m, tea.Batch(m.waitForMessageCmd(), m.sendListRecoveredCmd())

	case ImportResultMsg:
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
			return m, tea.Batch(m.waitForMessageCmd(), m.sendListKeysCmd())
		} else {
			m.forms.importError = msg.Error
			// Return to the appropriate form to show the error
			if m.viewState == ViewImportParams || m.viewState == ViewImporting {
				m.viewState = ViewImportParams
			}
		}
		return m, m.waitForMessageCmd()

	case ClientExistsMsg:
		// Server says another client is already connected - show confirmation modal
		m.viewState = ViewDisplaceConfirm
		m.displaceConfirmFocus = 0 // Default to Cancel
		return m, m.waitForMessageCmd()

	case DisplacedMsg:
		// We've been displaced by another apadmin client
		m.resetActivityState()
		m.connectionState = ConnectionDisconnected
		m.lastError = msg.Reason
		// Do NOT issue WaitForMessageCmd - no reconnect
		return m, nil

	case AdminSettingsMsg:
		// Detect theme change and re-init styles
		if m.admin.settings == nil || m.admin.settings.Theme != msg.Settings.Theme {
			theme.Init(msg.Settings.Theme)
			initStyles()
		}
		m.admin.settings = &msg.Settings
		m.syncKeyListTabWithMode()
		timeoutCmd := m.applyAdminSettingsTimeout(msg.Settings)
		return m, tea.Batch(m.waitForMessageCmd(), timeoutCmd)

	case AdminSettingUpdatedMsg:
		if msg.Success {
			// Refresh settings after successful update
			return m, tea.Batch(m.waitForMessageCmd(), m.sendGetAdminSettingsCmd())
		} else {
			m.lastError = "Setting update failed: " + msg.Error
		}
		return m, m.waitForMessageCmd()

	case policyEditorLoadedMsg:
		return m.handlePolicyEditorLoaded(msg)

	case policyEditorClosedMsg:
		return m.closePolicyEditor()

	case adminRefreshTickMsg:
		// Periodic admin panel refresh — only poll while admin panel is active
		if m.viewState == ViewAdminPanel {
			return m, tea.Batch(m.sendGetAdminSettingsCmd(), adminRefreshTickCmd())
		}
		// Not on admin panel — let the tick expire silently
		return m, nil

	case clearWarningMsg:
		if msg.Generation == m.lastWarningGeneration {
			m.lastWarning = ""
		}
		return m, nil

	case localIdleTickMsg:
		return m, m.handleLocalIdleTick(msg)

	case lockIdentitySendFailedMsg:
		errText := ""
		if msg.Error != nil {
			errText = msg.Error.Error()
		}
		if m.manualLock.pending {
			return m, m.handleManualLockFailed(errText)
		}
		return m, m.handleManualLockFailed(errText)

	case KeyDetailsMsg:
		if msg.Success {
			m.details.address = msg.Address
			m.details.keyType = msg.KeyType
			m.details.publicKeyHex = msg.PublicKeyHex
			m.details.parameters = msg.Parameters
			m.details.teal = msg.DisplayTEAL
			m.details.templateProvenanceStatus = msg.TemplateProvenanceStatus
			m.details.templateProvenanceNote = msg.TemplateProvenanceNote
			m.details.scrollOffset = 0 // Reset scroll on open
			m.viewState = ViewKeyDetails
		} else {
			m.lastError = msg.Error
		}
		return m, m.waitForMessageCmd()

	case LibraryTemplatesMsg:
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
		return m, m.waitForMessageCmd()

	case InstallLibraryTemplateResultMsg:
		if msg.Success {
			m.library.installError = ""
			if msg.AlreadyExists {
				m.library.installStatus = displayKeyType(msg.KeyType) + " was already " + libraryPastTense()
			} else {
				m.library.installStatus = displayKeyType(msg.KeyType) + " " + libraryPastTense()
			}
			m.library.pendingTemplate = nil
			m.viewState = ViewTemplateLibrary
			return m, tea.Batch(
				m.waitForMessageCmd(),
				m.sendListLibraryTemplatesCmd(),
				m.sendListKeyTypesCmd(),
				m.sendListKeysCmd(),
			)
		}
		m.library.installError = msg.Error
		if m.library.installError == "" {
			m.library.installError = "Key type enable failed"
		}
		m.viewState = ViewTemplateInstallConfirm
		return m, m.waitForMessageCmd()

	case ShowLibraryTemplateResultMsg:
		// Only adopt the result if we're still waiting for it; ignore late replies
		// after the user has navigated away.
		if m.viewState == ViewLibraryTemplateDetails &&
			m.library.detailsLoading &&
			msg.KeyType == m.library.detailsKeyType &&
			msg.TemplateType == m.library.detailsTemplateType {
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
		return m, m.waitForMessageCmd()

	case ActivateKeyTypeResultMsg:
		if msg.Success {
			m.library.installError = ""
			if msg.AlreadyExists {
				m.library.installStatus = displayKeyType(msg.KeyType) + " was already " + libraryPastTense()
			} else {
				m.library.installStatus = displayKeyType(msg.KeyType) + " " + libraryPastTense()
			}
			m.library.pendingTemplate = nil
			m.viewState = ViewTemplateLibrary
			return m, tea.Batch(
				m.waitForMessageCmd(),
				m.sendListLibraryTemplatesCmd(),
				m.sendListKeyTypesCmd(),
				m.sendListKeysCmd(),
			)
		}
		m.library.installError = msg.Error
		if m.library.installError == "" {
			m.library.installError = libraryActivateFailure()
		}
		m.viewState = ViewTemplateInstallConfirm
		return m, m.waitForMessageCmd()

	case DeactivateKeyTypeResultMsg:
		if msg.Success {
			m.library.installError = ""
			if msg.Removed {
				m.library.installStatus = displayKeyType(msg.KeyType) + " " + libraryDeactivatePastTense()
			} else {
				m.library.installStatus = displayKeyType(msg.KeyType) + " was already disabled"
			}
			m.library.pendingTemplate = nil
			m.viewState = ViewTemplateLibrary
			return m, tea.Batch(
				m.waitForMessageCmd(),
				m.sendListLibraryTemplatesCmd(),
				m.sendListKeyTypesCmd(),
				m.sendListKeysCmd(),
			)
		}
		m.library.installError = msg.Error
		if m.library.installError == "" {
			m.library.installError = libraryDeactivateFailure()
		}
		m.viewState = ViewTemplateInstallConfirm
		return m, m.waitForMessageCmd()

	case KeyTypesMsg:
		if msg.Error != "" {
			m.lastError = msg.Error
		} else {
			m.serverKeyTypes = msg.KeyTypes
			setServerKeyTypes(msg.KeyTypes)
			if m.forms.generateKeyType >= getKeyTypeCount() {
				m.forms.generateKeyType = getKeyTypeCount() - 1
			}
			if m.forms.importKeyType >= getImportKeyTypeCount() {
				m.forms.importKeyType = getImportKeyTypeCount() - 1
			}
			if m.forms.generateKeyType < 0 {
				m.forms.generateKeyType = 0
			}
			if m.forms.importKeyType < 0 {
				m.forms.importKeyType = 0
			}
		}
		return m, m.waitForMessageCmd()
	}

	if m.viewState == ViewPolicyEditor && m.policyEd.editor != nil {
		return m.forwardPolicyEditorMsg(msg)
	}

	return m, nil
}

// handleKeyPress handles keyboard input based on current view
func (m Model) handleKeyPress(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if msg.String() == "ctrl+c" || (msg.String() == "q" && (m.viewState == ViewGenerating || m.viewState == ViewImporting || m.viewState == ViewDeleting || m.viewState == ViewTemplateInstalling || m.viewState == ViewRestoring)) {
		return m, tea.Quit
	}
	if m.usesSharedPopupViewport() {
		switch msg.String() {
		case "ctrl+up":
			return m.scrollSharedPopup(-25), nil
		case "ctrl+down":
			return m.scrollSharedPopup(25), nil
		case "ctrl+pgup":
			return m.scrollSharedPopup(-200), nil
		case "ctrl+pgdown":
			return m.scrollSharedPopup(200), nil
		case "ctrl+home":
			return m.setSharedPopupPosition(0), nil
		case "ctrl+end":
			return m.setSharedPopupPosition(panelScrollScale), nil
		}
	}

	// Global reconnect handling when disconnected
	if m.connectionState == ConnectionDisconnected && msg.String() == "c" {
		m.connectionState = ConnectionConnecting
		m.lastError = ""
		if m.lastWarning == localIdleDisconnectReason {
			m.clearWarning()
		}
		return m, m.reconnectCmd()
	}

	// View-specific handling
	switch m.viewState {
	case ViewError:
		return m.handleErrorKeys(msg)
	case ViewAuth:
		return m.handleAuthKeys(msg)
	case ViewUnlock:
		return m.handleUnlockKeys(msg)
	case ViewKeyList:
		return m.handleKeyListKeys(msg)
	case ViewSigningPopup:
		return m.handleSigningPopupKeys(msg)
	case ViewTokenProvisioningPopup:
		return m.handleTokenProvisioningPopupKeys(msg)
	case ViewBackupConfirm:
		return m.handleBackupConfirmKeys(msg)
	case ViewBackupDisplay:
		return m.handleBackupDisplayKeys(msg)
	case ViewRestoreList:
		return m.handleRestoreListKeys(msg)
	case ViewRestorePassphrase:
		return m.handleRestorePassphraseKeys(msg)
	case ViewRestorePreview:
		return m.handleRestorePreviewKeys(msg)
	case ViewRestoreReview:
		return m.handleRestoreReviewKeys(msg)
	case ViewRestoreDisplay:
		return m.handleRestoreDisplayKeys(msg)
	case ViewRecoveredList:
		return m.handleRecoveredListKeys(msg)
	case ViewGenerateDisplay:
		return m.handleGenerateDisplayKeys(msg)
	case ViewImportDisplay:
		return m.handleImportDisplayKeys(msg)
	case ViewImportForm:
		return m.handleImportFormKeys(msg)
	case ViewGenerateForm:
		return m.handleGenerateFormKeys(msg)
	case ViewGenerateParams:
		return m.handleGenerateParamsKeys(msg)
	case ViewImportParams:
		return m.handleImportParamsKeys(msg)
	case ViewDeleteConfirm:
		return m.handleDeleteConfirmKeys(msg)
	case ViewRevokeTokenConfirm:
		return m.handleRevokeTokenConfirmKeys(msg)
	case ViewLockConfirm:
		return m.handleLockConfirmKeys(msg)
	case ViewDisplaceConfirm:
		return m.handleDisplaceConfirmKeys(msg)
	case ViewKeyDetails:
		return m.handleKeyDetailsKeys(msg)
	case ViewTEALFullDisplay:
		return m.handleTEALFullDisplayKeys(msg)
	case ViewAdminPanel:
		return m.handleAdminPanelKeys(msg)
	case ViewPolicyEditor:
		return m.handlePolicyEditorKeys(msg)
	case ViewTemplateLibrary:
		return m.handleTemplateLibraryKeys(msg)
	case ViewTemplateInstallConfirm:
		return m.handleTemplateInstallConfirmKeys(msg)
	case ViewLibraryTemplateDetails:
		return m.handleLibraryTemplateDetailsKeys(msg)
	case ViewGenerating, ViewImporting, ViewDeleting, ViewTemplateInstalling, ViewBackingUp, ViewRestoring:
		if msg.String() == "esc" {
			m.lastError = "Operation in progress; wait for completion or press q to quit"
		}
		return m, nil
	}

	return m, nil
}

func (m Model) usesSharedPopupViewport() bool {
	switch m.viewState {
	case ViewAuth,
		ViewUnlock,
		ViewTokenProvisioningPopup,
		ViewRestoreReview,
		ViewGenerateForm,
		ViewGenerateParams,
		ViewGenerating,
		ViewGenerateDisplay,
		ViewImportForm,
		ViewImportParams,
		ViewImporting,
		ViewImportDisplay,
		ViewBackupConfirm,
		ViewBackingUp,
		ViewBackupDisplay,
		ViewRestorePassphrase,
		ViewRestoring,
		ViewDeleteConfirm,
		ViewDeleting,
		ViewRevokeTokenConfirm,
		ViewLockConfirm,
		ViewDisplaceConfirm,
		ViewTemplateInstallConfirm,
		ViewTemplateInstalling,
		ViewError:
		return true
	default:
		return false
	}
}

func (m Model) scrollSharedPopup(delta int) Model {
	position := 0
	if m.panelScrollView == m.viewState {
		position = m.panelScrollPosition
	}
	return m.setSharedPopupPosition(position + delta)
}

func (m Model) setSharedPopupPosition(position int) Model {
	if position < 0 {
		position = 0
	}
	if position > panelScrollScale {
		position = panelScrollScale
	}
	m.panelScrollView = m.viewState
	m.panelScrollPosition = position
	return m
}

func (m *Model) showSeriousErrorPopup(title, message string, returnView ViewState) {
	m.errorPopup.title = title
	m.errorPopup.message = message
	m.errorPopup.returnView = returnView
	m.viewState = ViewError
	m.panelScrollView = ViewError
	m.panelScrollPosition = 0
}

func (m Model) handleErrorKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.viewState = m.errorPopup.returnView
		m.errorPopup.title = ""
		m.errorPopup.message = ""
		m.auth.passphraseError = ""
		return m, nil
	}
	return m, nil
}

// isSeriousUnlockError reports whether an auth/unlock failure is a server-side
// fault that deserves a popup rather than the inline "try again" treatment a
// wrong passphrase gets. The structured code from the IPC result is
// authoritative; the text heuristic remains only for older signers that do
// not send codes.
func isSeriousUnlockError(code, message string) bool {
	switch code {
	case protocol.ErrCodeUnlockFailed:
		return true
	case protocol.ErrCodeInvalidPassphrase, protocol.ErrCodeAuthenticationFailed:
		return false
	}
	text := strings.ToLower(strings.TrimSpace(message))
	if text == "" {
		return false
	}
	if strings.Contains(text, "invalid passphrase") || strings.Contains(text, "authentication failed") {
		return false
	}
	return strings.Contains(text, "auth ok but unlock failed") ||
		strings.Contains(text, "failed to load keys") ||
		strings.Contains(text, "reload pre-scan hook failed") ||
		strings.Contains(text, "policy integrity") ||
		strings.Contains(text, "hmac mismatch")
}
