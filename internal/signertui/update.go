// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

// Core update loop and message handling.
// View-specific handlers are in update_*.go files.

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/protocol"
	signertemplates "github.com/aplane-algo/aplane/internal/signerapp/templates"
	"github.com/aplane-algo/aplane/internal/storepaths"
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
		m.passphraseInput = ""
		m.passphraseError = ""
		return m, m.waitForMessageCmd()

	case AuthResultMsg:
		m.loggingIn = false
		if msg.Success {
			// Authentication successful - load runtime templates using master key
			if m.passphraseInput != "" && m.dataDir != "" {
				m.loadRuntimeTemplates([]byte(m.passphraseInput))
				m.setTemplateWarning()
			}
			// Server will send signer status next
			m.passphraseError = ""
			m.passphraseInput = ""
			m.resetActivityState()
		} else {
			// Authentication failed - show error and stay on auth screen
			m.passphraseError = msg.Error
			if m.passphraseError == "" {
				m.passphraseError = "Authentication failed"
			}
			if isSeriousUnlockError(msg.Error) {
				m.showSeriousErrorPopup("Signer unlock failed", msg.Error, ViewAuth)
				m.passphraseInput = ""
				m.loggingIn = false
			}
		}
		return m, m.waitForMessageCmd()

	case DisconnectedMsg:
		m.clearRestorePassphrase()
		m.resetActivityState()
		m.manualLockPending = false
		m.connectionState = ConnectionDisconnected
		if msg.Error != nil {
			m.lastError = msg.Error.Error()
		}
		return m, nil

	case localIdleDisconnectedMsg:
		m.clearRestorePassphrase()
		m.resetActivityState()
		m.manualLockPending = false
		m.connectionState = ConnectionDisconnected
		m.signerStatusKnown = false
		m.lastError = ""
		m.setPersistentWarning(msg.Reason)
		return m, nil

	case SignerStatusMsg:
		if msg.Locked {
			// Signer locked; show unlock screen immediately regardless of
			// current view. Any in-progress operation would fail anyway since
			// the master key has been zeroed.
			m.applySignerLockedState()
			return m, tea.Batch(m.waitForMessageCmd(), m.sendListKeyTypesCmd(), m.sendGetAdminSettingsCmd())
		} else {
			m.applySignerUnlockedState(msg.KeyCount)
			idleCmd := m.armLocalIdleTimer()
			// If signer is already unlocked, request key list
			return m, tea.Batch(m.waitForMessageCmd(), m.sendListKeysCmd(), m.sendListKeyTypesCmd(), m.sendGetAdminSettingsCmd(), idleCmd)
		}

	case UnlockResultMsg:
		m.loggingIn = false
		if msg.Success {
			// Load runtime templates using master key
			if m.passphraseInput != "" && m.dataDir != "" {
				m.loadRuntimeTemplates([]byte(m.passphraseInput))
				m.setTemplateWarning()
			}
			m.applySignerUnlockedState(msg.KeyCount)
			m.passphraseError = ""
			m.passphraseInput = ""
			idleCmd := m.armLocalIdleTimer()
			// Request the key list after unlocking
			return m, tea.Batch(m.waitForMessageCmd(), m.sendListKeysCmd(), m.sendListKeyTypesCmd(), m.sendGetAdminSettingsCmd(), idleCmd)
		} else {
			m.passphraseError = msg.Error
			if isSeriousUnlockError(msg.Error) {
				m.showSeriousErrorPopup("Signer unlock failed", msg.Error, ViewUnlock)
				m.passphraseInput = ""
				m.loggingIn = false
			}
		}
		// Continue listening for messages
		return m, m.waitForMessageCmd()

	case LockIdentityResultMsg:
		if msg.Success {
			m.manualLockPending = false
			m.applySignerLockedState()
			return m, tea.Batch(m.waitForMessageCmd(), m.sendListKeyTypesCmd())
		}
		if m.manualLockPending {
			return m, tea.Batch(m.waitForMessageCmd(), m.handleManualLockFailed(msg.Error))
		}
		return m, tea.Batch(m.waitForMessageCmd(), m.handleManualLockFailed(msg.Error))

	case SignRequestReceivedMsg:
		m.pendingSign = &msg.Request
		m.pendingSignFocus = 1 // Default to reject button (safety-first)
		m.viewState = ViewSigningPopup
		// Initialize scrollable viewport with description + violations
		m.initSigningViewport(m.buildSigningViewportContent())
		// Continue listening for messages
		return m, m.waitForMessageCmd()

	case SignRequestCanceledMsg:
		var warningCmd tea.Cmd
		if m.pendingSign != nil && m.pendingSign.ID == msg.ID {
			m.pendingSign = nil
			m.viewState = ViewKeyList
			warningCmd = m.setTransientWarning(signRequestCanceledWarning(msg.Reason))
		}
		return m, tea.Batch(m.waitForMessageCmd(), warningCmd)

	case TokenProvisioningRequestReceivedMsg:
		m.pendingTokenRequest = &msg.Request
		m.pendingTokenRequestFocus = 1 // Default to reject button (safety-first)
		m.viewState = ViewTokenProvisioningPopup
		// Continue listening for messages
		return m, m.waitForMessageCmd()

	case KeysListMsg:
		// Sort keys alphabetically by address
		sort.Slice(msg.Keys, func(i, j int) bool {
			return msg.Keys[i].Address < msg.Keys[j].Address
		})
		m.keys = msg.Keys
		m.keyCount = len(msg.Keys)
		// Ensure selectedKey and scrollOffset are within bounds
		displayKeys := m.filteredKeys()
		if m.selectedKey >= len(displayKeys) {
			m.selectedKey = len(displayKeys) - 1
			if m.selectedKey < 0 {
				m.selectedKey = 0
			}
		}
		if m.scrollOffset > m.selectedKey {
			m.scrollOffset = m.selectedKey
		}
		// Continue listening for messages
		return m, m.waitForMessageCmd()

	case ErrorMsg:
		if m.viewState == ViewRestorePassphrase || m.viewState == ViewRestorePreview || m.viewState == ViewRestoring {
			m.clearRestorePassphrase()
			m.restorePreviewing = false
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
			m.generatedAddress = msg.Address
			m.generatedKeyType = msg.KeyType
			m.viewState = ViewGenerateDisplay
			return m, tea.Batch(m.waitForMessageCmd(), m.sendListKeysCmd())
		} else {
			m.generateError = msg.Error
			// Go back to params view for generic LogicSigs, otherwise form
			if m.genericLSigParams != nil {
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
			m.deleteAddress = ""
			m.deleteKeyType = ""
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
			m.backupArchivePath = msg.ArchivePath
			m.backupExportPassphrase = ""
			m.backupConfirmPassphrase = ""
			m.backupConfirmError = ""
			m.viewState = ViewBackupDisplay
		} else {
			m.backupConfirmError = msg.Error
			m.viewState = ViewBackupConfirm
		}
		return m, m.waitForMessageCmd()

	case BackupsListMsg:
		m.restoreBackupsLoaded = true
		if msg.Error != "" {
			m.lastError = "Backup list failed: " + msg.Error
		} else {
			m.lastError = ""
			m.restoreBackups = msg.Backups
			m.clampRestoreSelection()
			if m.viewState != ViewRestoreList {
				m.viewState = ViewRestoreList
			}
		}
		return m, m.waitForMessageCmd()

	case RestorePreviewMsg:
		m.restorePreviewing = false
		if msg.Error != "" || (len(msg.Keys) == 0 && len(msg.Errors) > 0) {
			m.clearRestorePassphrase()
			m.restorePassphraseError = msg.Error
			if m.restorePassphraseError == "" {
				m.restorePassphraseError = firstRestoreError(msg.Errors)
			}
			if m.restorePassphraseError == "" {
				m.restorePassphraseError = "Restore preview failed"
			}
			m.viewState = ViewRestorePassphrase
			return m, m.waitForMessageCmd()
		}
		m.lastError = ""
		m.restoreArchivePath = msg.ArchivePath
		m.restorePreviewKeys = msg.Keys
		m.restorePreviewErrors = msg.Errors
		m.restorePassphraseError = ""
		m.restorePreviewError = ""
		m.restoreSelectedKey = 0
		m.restorePreviewScrollOffset = 0
		m.initializeRestoreSelection()
		m.viewState = ViewRestorePreview
		return m, m.waitForMessageCmd()

	case RestoreBackupResultMsg:
		m.clearRestorePassphrase()
		m.restoreResult = RestoreBackupResultMessage{
			ArchivePath: msg.ArchivePath,
			Success:     msg.Success,
			Restored:    msg.Restored,
			Skipped:     msg.Skipped,
			Errors:      msg.Errors,
			Warnings:    msg.Warnings,
			KeyCount:    msg.KeyCount,
			Error:       msg.Error,
		}
		m.restoreDisplaySelectedKey = 0
		m.restoreDisplayScrollOffset = 0
		m.viewState = ViewRestoreDisplay
		cmds := []tea.Cmd{m.waitForMessageCmd()}
		if msg.Success || len(msg.Restored) > 0 || msg.KeyCount > 0 {
			cmds = append(cmds, m.sendListKeysCmd(), m.sendListKeyTypesCmd())
		}
		return m, tea.Batch(cmds...)

	case ImportResultMsg:
		if msg.Success {
			m.lastError = ""
			m.importMnemonicInput.SetValue("")
			m.importMnemonicInput.Blur()
			m.importError = ""
			// Store imported key info for display
			m.importedAddress = msg.Address
			m.importedKeyType = msg.KeyType
			m.viewState = ViewImportDisplay
			// Also refresh key list in background
			return m, tea.Batch(m.waitForMessageCmd(), m.sendListKeysCmd())
		} else {
			m.importError = msg.Error
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
		if m.adminSettings == nil || m.adminSettings.Theme != msg.Settings.Theme {
			theme.Init(msg.Settings.Theme)
			initStyles()
		}
		m.adminSettings = &msg.Settings
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

	case PolicySettingsMsg:
		m.policySettings = &msg.Settings
		return m, m.waitForMessageCmd()

	case PolicySnapshotMsg:
		m = m.applyPolicySnapshot(msg.Snapshot, "Policy snapshot")
		return m, m.waitForMessageCmd()

	case PolicyLoadFileMsg:
		if msg.Error != nil {
			m.policyLoadState = policyLoadPath
			m.policyLoadError = "read failed: " + msg.Error.Error()
			return m, nil
		}
		m.policyLoadState = policyLoadConfirm
		m.policyLoadPath = msg.Path
		m.policyLoadYAML = msg.PolicyYAML
		m.policyLoadBytes = msg.Bytes
		m.policyLoadError = ""
		return m, nil

	case PolicyReplaceResultMsg:
		if !msg.Snapshot.Success {
			errText := msg.Snapshot.Error
			if errText == "" {
				errText = "request failed"
			}
			m.policyLoadState = policyLoadConfirm
			m.policyLoadError = "replace failed: " + errText
			m.lastError = "Policy replacement failed: " + errText
			return m, m.waitForMessageCmd()
		}
		replacedPath := m.policyLoadPath
		m = m.applyPolicySnapshot(msg.Snapshot, "Policy replacement")
		m.policyLoadState = policyLoadIdle
		m.policyLoadPath = ""
		m.policyLoadYAML = ""
		m.policyLoadBytes = 0
		m.policyLoadError = ""
		if replacedPath != "" && m.policyViewError == "" {
			m.policyLoadStatus = "Replaced policy from " + replacedPath
		}
		return m, m.waitForMessageCmd()

	case ASAMetadataResultsMsg:
		if msg.Error != "" {
			m.lastError = "ASA search failed: " + msg.Error
			return m, m.waitForMessageCmd()
		}
		switch len(msg.Results) {
		case 0:
			m.lastError = fmt.Sprintf("No cached ASA symbol match for %q on %s", msg.Query, msg.Network)
		case 1:
			selected := msg.Results[0]
			m.policyASASelectedAsset = &selected
			m.policyASAInput = fmt.Sprintf("%d", selected.AssetID)
			m.policyASAReviewInput = ""
			m.policyASADenyInput = ""
			m.policyASAAmountField = 0
			m.policyASAMode = policyASAModeAddAmount
		default:
			m.policyASAMatches = msg.Results
			m.policyASAFocus = 0
			m.policyASAMode = policyASAModeChoose
		}
		return m, m.waitForMessageCmd()

	case ASAMetadataResultMsg:
		if msg.Error != "" {
			m.lastError = "ASA resolve failed: " + msg.Error
			return m, m.waitForMessageCmd()
		}
		selected := msg.Asset
		m.policyASASelectedAsset = &selected
		m.policyASAInput = fmt.Sprintf("%d", selected.AssetID)
		m.policyASAReviewInput = ""
		m.policyASADenyInput = ""
		m.policyASAAmountField = 0
		m.policyASAMode = policyASAModeAddAmount
		return m, m.waitForMessageCmd()

	case PolicySettingUpdatedMsg:
		if msg.Key == policyPanelActionTransferGuards || msg.Key == policyPanelActionMaxASAAmounts {
			m.policyASAPending = false
			if msg.Success {
				m.applyPolicyASAAmountsSnapshot(m.policyASAPendingValues)
				m.applyPolicyASAReviewAmountsSnapshot(m.policyASAReviewPendingValues)
				m.applyPolicyAlgoPaymentsSnapshot(m.policyAlgoPendingValues)
				m.applyPolicyAlgoReviewPaymentsSnapshot(m.policyAlgoReviewPendingValues)
				m.policyASAPendingValues = nil
				m.policyASAReviewPendingValues = nil
				m.policyAlgoPendingValues = nil
				m.policyAlgoReviewPendingValues = nil
				m.viewState = ViewPolicyPanel
				return m, tea.Batch(m.waitForMessageCmd(), m.sendGetPolicySettingsCmd())
			}
			m.policyASAPendingValues = nil
			m.policyASAReviewPendingValues = nil
			m.policyAlgoPendingValues = nil
			m.policyAlgoReviewPendingValues = nil
			m.lastError = "Policy update failed: " + msg.Error
			return m, tea.Batch(m.waitForMessageCmd(), m.sendGetPolicySettingsCmd())
		}
		if msg.Success {
			return m, tea.Batch(m.waitForMessageCmd(), m.sendGetPolicySettingsCmd())
		}
		m.lastError = "Policy update failed: " + msg.Error
		return m, tea.Batch(m.waitForMessageCmd(), m.sendGetPolicySettingsCmd())

	case adminRefreshTickMsg:
		// Periodic admin panel refresh — only poll while admin panel is active
		if m.viewState == ViewAdminPanel {
			return m, tea.Batch(m.sendGetAdminSettingsCmd(), adminRefreshTickCmd())
		}
		if m.viewState == ViewPolicyPanel {
			return m, tea.Batch(m.sendGetPolicySettingsCmd(), adminRefreshTickCmd())
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
		if m.manualLockPending {
			return m, m.handleManualLockFailed(errText)
		}
		return m, m.handleManualLockFailed(errText)

	case KeyDetailsMsg:
		if msg.Success {
			m.detailsAddress = msg.Address
			m.detailsKeyType = msg.KeyType
			m.detailsPublicKeyHex = msg.PublicKeyHex
			m.detailsParameters = msg.Parameters
			m.detailsTEAL = msg.DisplayTEAL
			m.detailsTemplateProvenanceStatus = msg.TemplateProvenanceStatus
			m.detailsTemplateProvenanceNote = msg.TemplateProvenanceNote
			m.detailsScrollOffset = 0 // Reset scroll on open
			m.viewState = ViewKeyDetails
		} else {
			m.lastError = msg.Error
		}
		return m, m.waitForMessageCmd()

	case LibraryTemplatesMsg:
		if msg.Error != "" {
			m.templateInstallError = msg.Error
			m.templateInstallStatus = ""
		} else {
			m.libraryTemplates = msg.Templates
			if m.selectedTemplate >= len(m.libraryTemplates) {
				m.selectedTemplate = len(m.libraryTemplates) - 1
			}
			if m.selectedTemplate < 0 {
				m.selectedTemplate = 0
			}
			m = m.ensureTemplateVisible()
		}
		return m, m.waitForMessageCmd()

	case InstallLibraryTemplateResultMsg:
		if msg.Success {
			m.templateInstallError = ""
			tmpl := protocol.LibraryTemplateInfo{KeyType: msg.KeyType, TemplateType: msg.TemplateType}
			if msg.AlreadyExists {
				m.templateInstallStatus = displayKeyType(msg.KeyType) + " was already " + libraryPastTense(tmpl)
			} else {
				m.templateInstallStatus = displayKeyType(msg.KeyType) + " " + libraryPastTense(tmpl)
			}
			m.pendingTemplate = nil
			m.viewState = ViewTemplateLibrary
			return m, tea.Batch(
				m.waitForMessageCmd(),
				m.sendListLibraryTemplatesCmd(),
				m.sendListKeyTypesCmd(),
				m.sendListKeysCmd(),
			)
		}
		m.templateInstallError = msg.Error
		if m.templateInstallError == "" {
			if msg.TemplateType == libraryTypeCompiledProvider {
				m.templateInstallError = "Key type activation failed"
			} else {
				m.templateInstallError = "Template key type enable failed"
			}
		}
		m.viewState = ViewTemplateInstallConfirm
		return m, m.waitForMessageCmd()

	case ShowLibraryTemplateResultMsg:
		// Only adopt the result if we're still waiting for it; ignore late replies
		// after the user has navigated away.
		if m.viewState == ViewLibraryTemplateDetails &&
			m.libraryDetailsLoading &&
			msg.KeyType == m.libraryDetailsKeyType &&
			msg.TemplateType == m.libraryDetailsTemplateType {
			m.libraryDetailsLoading = false
			if msg.Success {
				m.libraryDetailsContent = string(msg.TemplateYAML)
				m.libraryDetailsSourcePath = msg.SourcePath
				m.libraryDetailsSourceSHA256 = msg.SourceSHA256
				m.libraryDetailsSourceModTime = msg.SourceModTime
				m.libraryDetailsError = ""
				m.libraryDetailsScrollOffset = 0
			} else {
				m.libraryDetailsContent = ""
				m.libraryDetailsSourceSHA256 = ""
				m.libraryDetailsSourceModTime = 0
				m.libraryDetailsError = msg.Error
				if m.libraryDetailsError == "" {
					m.libraryDetailsError = "Failed to load library YAML"
				}
			}
		}
		return m, m.waitForMessageCmd()

	case ActivateKeyTypeResultMsg:
		tmpl := m.libraryEntryForResult(msg.KeyType, libraryTypeCompiledProvider)
		if msg.Success {
			m.templateInstallError = ""
			if msg.AlreadyExists {
				m.templateInstallStatus = displayKeyType(msg.KeyType) + " was already " + libraryPastTense(tmpl)
			} else {
				m.templateInstallStatus = displayKeyType(msg.KeyType) + " " + libraryPastTense(tmpl)
			}
			m.pendingTemplate = nil
			m.viewState = ViewTemplateLibrary
			return m, tea.Batch(
				m.waitForMessageCmd(),
				m.sendListLibraryTemplatesCmd(),
				m.sendListKeyTypesCmd(),
				m.sendListKeysCmd(),
			)
		}
		m.templateInstallError = msg.Error
		if m.templateInstallError == "" {
			m.templateInstallError = libraryActivateFailure(tmpl)
		}
		m.viewState = ViewTemplateInstallConfirm
		return m, m.waitForMessageCmd()

	case DeactivateKeyTypeResultMsg:
		tmpl := m.libraryEntryForResult(msg.KeyType, libraryTypeCompiledProvider)
		if msg.Success {
			m.templateInstallError = ""
			if msg.Removed {
				m.templateInstallStatus = displayKeyType(msg.KeyType) + " " + libraryDeactivatePastTense()
			} else {
				m.templateInstallStatus = displayKeyType(msg.KeyType) + " was already disabled"
			}
			m.pendingTemplate = nil
			m.viewState = ViewTemplateLibrary
			return m, tea.Batch(
				m.waitForMessageCmd(),
				m.sendListLibraryTemplatesCmd(),
				m.sendListKeyTypesCmd(),
				m.sendListKeysCmd(),
			)
		}
		m.templateInstallError = msg.Error
		if m.templateInstallError == "" {
			m.templateInstallError = libraryDeactivateFailure(tmpl)
		}
		m.viewState = ViewTemplateInstallConfirm
		return m, m.waitForMessageCmd()

	case KeyTypesMsg:
		if msg.Error != "" {
			m.lastError = msg.Error
		} else {
			m.serverKeyTypes = msg.KeyTypes
			setServerKeyTypes(msg.KeyTypes)
			if m.generateKeyType >= getKeyTypeCount() {
				m.generateKeyType = getKeyTypeCount() - 1
			}
			if m.importKeyType >= getImportKeyTypeCount() {
				m.importKeyType = getImportKeyTypeCount() - 1
			}
			if m.generateKeyType < 0 {
				m.generateKeyType = 0
			}
			if m.importKeyType < 0 {
				m.importKeyType = 0
			}
		}
		return m, m.waitForMessageCmd()
	}

	return m, nil
}

// handleKeyPress handles keyboard input based on current view
func (m Model) handleKeyPress(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if msg.String() == "ctrl+c" || (msg.String() == "q" && (m.viewState == ViewGenerating || m.viewState == ViewImporting || m.viewState == ViewDeleting || m.viewState == ViewTemplateInstalling || m.viewState == ViewRestoring)) {
		return m, tea.Quit
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
	case ViewRestoreDisplay:
		return m.handleRestoreDisplayKeys(msg)
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
	case ViewPolicyViewer:
		return m.handlePolicyViewerKeys(msg)
	case ViewPolicyPanel:
		return m.handlePolicyPanelKeys(msg)
	case ViewPolicyASAModal:
		return m.handlePolicyASAModalKeys(msg)
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

func (m *Model) showSeriousErrorPopup(title, message string, returnView ViewState) {
	m.errorPopupTitle = title
	m.errorPopupMessage = message
	m.errorPopupReturnView = returnView
	m.viewState = ViewError
}

func (m Model) handleErrorKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.viewState = m.errorPopupReturnView
		m.errorPopupTitle = ""
		m.errorPopupMessage = ""
		m.passphraseError = ""
		return m, nil
	}
	return m, nil
}

func isSeriousUnlockError(message string) bool {
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

// loadRuntimeTemplates loads runtime templates from the keystore using the master key.
// This is needed to recognize generic LogicSig key types (e.g., htlc-v3, timelock-v3)
// and Falcon-1024 DSA composition templates (e.g., falcon1024-timedlock-v1).
func (m *Model) loadRuntimeTemplates(passphrase []byte) {
	// Reset template warnings for this load attempt
	m.templateLoadWarnings = nil
	m.clearWarning()

	// Create a keystore to derive the master key using configured keystore path
	paths := storepaths.NewPaths(m.dataDir)
	ks := keystore.NewFileKeyStoreForPaths(paths, auth.CurrentProductIdentityID())

	// Initialize master key (verifies passphrase and derives key from metadata salt)
	masterKey, err := ks.InitializeMasterKey(passphrase)
	if err != nil {
		// Can't load templates without master key - this is expected if keystore
		// metadata is missing or passphrase verification failed
		return
	}

	manager := signertemplates.NewManager(paths)
	report, err := manager.RegisterKeystoreTemplates(auth.CurrentProductIdentityID(), masterKey)
	if err != nil {
		m.templateLoadWarnings = append(m.templateLoadWarnings, fmt.Sprintf("Failed to load templates: %v", err))
		return
	}
	m.templateLoadWarnings = append(m.templateLoadWarnings, report.Warnings()...)
}

// setTemplateWarning sets lastWarning if any template load warnings were collected.
func (m *Model) setTemplateWarning() {
	if warning := templateLoadWarningSummary(m.templateLoadWarnings); warning != "" {
		m.setPersistentWarning(warning)
	}
}

func templateLoadWarningSummary(warnings []string) string {
	switch len(warnings) {
	case 0:
		return ""
	case 1:
		return warnings[0]
	default:
		return fmt.Sprintf("%d template(s) failed to load: %s (+%d more)", len(warnings), warnings[0], len(warnings)-1)
	}
}
