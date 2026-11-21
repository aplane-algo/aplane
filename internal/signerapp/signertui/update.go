// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

// Core update loop and message handling.
// View-specific handlers are in update_*.go files.

import (
	"fmt"
	"time"

	"github.com/aplane-algo/aplane/internal/keytypeux"
	"github.com/aplane-algo/aplane/internal/protocol"

	tea "github.com/charmbracelet/bubbletea"
)

// adminRefreshInterval is how often the admin panel polls for updated settings.
const adminRefreshInterval = 2 * time.Second

const transientStatusDuration = 5 * time.Second

// adminRefreshTickCmd returns a tea.Cmd that fires after adminRefreshInterval.
func adminRefreshTickCmd() tea.Cmd {
	return tea.Tick(adminRefreshInterval, func(time.Time) tea.Msg {
		return adminRefreshTickMsg{}
	})
}

func clearWarningTickCmd(generation uint64) tea.Cmd {
	return tea.Tick(transientStatusDuration, func(time.Time) tea.Msg {
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

func clearNoticeTickCmd(generation uint64) tea.Cmd {
	return tea.Tick(transientStatusDuration, func(time.Time) tea.Msg {
		return clearNoticeMsg{Generation: generation}
	})
}

func (m *Model) setTransientNotice(notice string) tea.Cmd {
	m.lastNoticeGeneration++
	m.lastNotice = notice
	m.lastNoticeArming = false
	return clearNoticeTickCmd(m.lastNoticeGeneration)
}

// setApprovalArmingNotice says why an approval key was not taken: the
// request came into view too recently. The approver acts on it, so the
// status bar ranks it above warnings.
func (m *Model) setApprovalArmingNotice() tea.Cmd {
	cmd := m.setTransientNotice("One moment...")
	m.lastNoticeArming = true
	return cmd
}

// Update handles all TUI events and messages. A pending approval popup stays
// in front of whatever screen a message selects.
//
// Update alone owns the listener: exactly one wait is in flight while a
// session lasts. ConnectCmd's ConnectedMsg starts it, and each message the
// wait delivers (a listenerMsg, a reconnect's ConnectedMsg among them) starts
// the next only once it has been handled, so the signer's messages are
// handled in the order it sent them. Handlers never start a wait.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case listenerMsg:
		next, cmd := m.updateOnTop(msg.msg)
		return next, tea.Batch(cmd, next.listenAgain())
	case ConnectedMsg:
		next, cmd := m.updateOnTop(msg)
		return next, tea.Batch(cmd, next.listen())
	}
	return m.updateOnTop(msg)
}

func (m Model) updateOnTop(msg tea.Msg) (Model, tea.Cmd) {
	preferred := m.viewState
	if _, isKey := msg.(tea.KeyMsg); !isKey && isApprovalView(m.viewState) {
		// Background messages apply to the screen under the popup, so
		// handlers that act on the current screen see the one the operator
		// left.
		m.viewState = m.screenUnderApproval()
	}
	next, cmd := m.update(msg)
	shown, heldCmd := next.(Model).showHeldResult()
	return shown.keepApprovalOnTop(preferred).fitPolicyEditor(), tea.Batch(cmd, heldCmd)
}

func (m Model) update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		return m.handleKeyMsg(msg)

	case tea.WindowSizeMsg:
		return m.handleWindowSizeMsg(msg)

	case ConnectedMsg:
		m.connectionState = ConnectionConnected
		m.auth.endedReason = ""
		if msg.Client != nil {
			m.adminClient = msg.Client
		}
		m.resetActivityState()
		// Update starts the listener; the server sends auth_required first.
		return m, nil

	case AuthRequiredMsg:
		// Server requires authentication - show auth screen
		m.endAdminSession()
		m.clearAuthPassphrase()
		m.auth.passphraseError = ""
		if m.viewState == ViewError {
			// A login the signer ended with a serious error closes the
			// connection, and the reconnect's auth_required follows at
			// once. The error stays up until the operator dismisses it,
			// which leads to this new login.
			m.errorPopup.returnView = ViewAuth
			return m, nil
		}
		m.viewState = ViewAuth
		return m, nil

	case AuthResultMsg:
		return m.handleAuthResultMsg(msg)

	case DisconnectedMsg:
		m.endAdminSession()
		m.connectionState = ConnectionDisconnected
		if msg.Error != nil {
			m.lastError = msg.Error.Error()
		}
		return m, nil

	case localIdleDisconnectedMsg:
		return m.handleLocalIdleDisconnectedMsg(msg)

	case SignerStatusMsg:
		return m.handleSignerStatusMsg(msg)

	case UnlockResultMsg:
		return m.handleUnlockResultMsg(msg)

	case LockIdentityResultMsg:
		if msg.Success {
			m.manualLock.pending = false
			abort := m.interruptBackupTransfers(true)
			m.applySignerLockedState()
			return m, abort
		}
		m.handleManualLockFailed(msg.Error)
		return m, nil

	case SignRequestReceivedMsg:
		m.signing.request = &msg.Request
		m.signing.shownAt = signingNow()
		m.signing.focus = 1 // Default to reject button (safety-first)
		m.signing.review = reviewState{}
		// Initialize scrollable viewport with description + violations
		m.initSigningViewport()
		return m, nil

	case SignRequestCanceledMsg:
		var warningCmd tea.Cmd
		if m.signing.request != nil && m.signing.request.ID == msg.ID {
			m.signing.request = nil
			warningCmd = m.setTransientWarning(signRequestCanceledWarning(msg.Reason))
		}
		return m, warningCmd

	case ClientEnrollmentRequestReceivedMsg:
		// Requests are announced when queued and again at login; one popup
		// per request, shown in turn.
		m.queueEnrollmentRequest(msg.Request)
		return m, nil

	case EnrollmentChangedMsg:
		return m.handleEnrollmentChanged()
	case PendingEnrollmentsListMsg:
		return m.handlePendingEnrollmentsList(msg)
	case ApproveEnrollmentResultMsg:
		return m.handleApproveEnrollmentResult(msg)
	case RejectEnrollmentResultMsg:
		return m.handleRejectEnrollmentResult(msg)
	case ImportClientKeyResultMsg:
		return m.handleImportClientKeyResult(msg)

	case KeysListMsg:
		return m.handleKeysListMsg(msg)

	case nativeMnemonicResultMsg:
		return m.handleNativeMnemonicResult(msg)
	case sourceTokenListMsg:
		return m.handleSourceTokenList(msg)
	case sourceTokenChangeMsg:
		return m.handleSourceTokenChange(msg)
	case mnemonicExpiredMsg:
		if msg.Serial == m.mnemonicExport.serial {
			m.clearMnemonicExport()
			if m.viewState == ViewMnemonicExport {
				m.viewState = ViewKeyDetails
			}
		}
		return m, nil
	case ErrorMsg:
		return m.handleFailure(msg.ID, msg.Error)

	case sendFailedMsg:
		return m.handleFailure(msg.ID, msg.Error)

	case NotificationsLostMsg:
		m.notificationsLost = max(m.notificationsLost, msg.Total)
		return m, nil

	case KeysChangedMsg:
		// Server notified us that keys or key types changed - refresh both projections.
		return m, tea.Batch(m.sendListKeysCmd(), m.sendListKeyTypesCmd())

	case ReconnectingMsg:
		m.endAdminSession()
		m.connectionState = ConnectionConnecting
		return m, nil

	case PrepareGenerateResultMsg:
		return m.handlePreparedGeneration(msg.Result)

	case GenerateResultMsg:
		return m.handleGenerateResultMsg(msg)

	case EnrolledKeysListMsg:
		return m.handleEnrolledKeysList(msg)

	case RevokeEnrolledKeyResultMsg:
		return m.handleRevokeEnrolledKeyResult(msg)

	case RevokeAllEnrolledKeysResultMsg:
		return m.handleRevokeAllEnrolledKeysResult(msg)

	case DeleteResultMsg:
		return m.handleDeleteResultMsg(msg)

	case BackupResultMsg:
		return m.handleBackupResultMsg(msg)

	case BackupsListMsg:
		return m.handleBackupsListed(msg), nil

	case BackupDeleteResultMsg:
		return m.handleBackupDeleteResult(msg)

	case BackupChunkMsg:
		return m.handleBackupChunk(msg)

	case BeginBackupImportResultMsg:
		return m.handleBeginBackupImportResult(msg)

	case AppendBackupImportResultMsg:
		return m.handleAppendBackupImportResult(msg)

	case CommitBackupImportResultMsg:
		return m.handleCommitBackupImportResult(msg)

	case backupImportPreparedMsg:
		return m.handleBackupImportPrepared(msg)

	case backupCommitTimeoutMsg:
		return m.handleBackupCommitTimeout(msg)

	case backupExportFinishedMsg:
		return m.handleBackupExportFinished(msg)

	case AbortBackupImportResultMsg:
		// Abort is best effort; the signer also removes abandoned uploads.
		return m, nil

	case RestorePreviewMsg:
		return m.handleRestorePreviewMsg(msg)

	case RestoreBackupResultMsg:
		return m.handleRestoreBackupResultMsg(msg)

	case RollbackRestoreResultMsg:
		return m.handleRollbackRestoreResultMsg(msg)

	case ReconcileStoreResultMsg:
		return m.handleReconcileStoreResultMsg(msg)

	case ImportResultMsg:
		return m.handleImportResultMsg(msg)

	case ClientExistsMsg:
		// Server says another client is already connected - show confirmation modal
		m.displaceConfirmFocus = 0 // Default to Cancel
		if m.viewState == ViewError {
			// As for auth_required: a serious error the last login ended
			// on stays up, and dismissing it leads to this prompt.
			m.errorPopup.returnView = ViewDisplaceConfirm
			return m, nil
		}
		m.viewState = ViewDisplaceConfirm
		return m, nil

	case DisplacedMsg:
		// We've been displaced by another apadmin client
		m.endAdminSession()
		m.connectionState = ConnectionDisconnected
		m.lastError = msg.Reason
		// Disconnected: Update starts no further wait, and nothing reconnects.
		return m, nil

	case AdminSettingsMsg:
		return m.handleAdminSettingsMsg(msg)

	case AdminSettingUpdatedMsg:
		return m.handleAdminSettingUpdatedMsg(msg)

	case PolicyLoadedMsg:
		return m.handlePolicyLoaded(msg)

	case PolicyContextLoadedMsg:
		return m.handlePolicyContextLoaded(msg)

	case PolicyDocumentLoadedMsg:
		return m.handlePolicyDocumentLoaded(msg)

	case PolicyCheckResultMsg:
		return m.handlePolicyCheckResult(msg)

	case PolicyApplyResultMsg:
		return m.handlePolicyApplyResult(msg)

	case PolicyExportWrittenMsg:
		return m.handlePolicyExportWritten(msg)

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

	case clearNoticeMsg:
		if msg.Generation == m.lastNoticeGeneration {
			m.lastNotice = ""
		}
		return m, nil

	case localIdleTickMsg:
		return m, m.handleLocalIdleTick(msg)

	case lockIdentitySendFailedMsg:
		errText := ""
		if msg.Error != nil {
			errText = msg.Error.Error()
		}
		m.handleManualLockFailed(errText)
		return m, nil

	case KeyDetailsMsg:
		return m.handleKeyDetailsMsg(msg)

	case LibraryTemplatesMsg:
		return m.handleLibraryTemplatesMsg(msg)

	case InstallLibraryTemplateResultMsg:
		return m.finishLibraryAction(msg.ID, msg.Success, libraryEnabledStatus(msg.KeyType, msg.AlreadyExists), msg.Error, libraryEnableFailure)

	case ShowLibraryTemplateResultMsg:
		return m.handleShowLibraryTemplateResultMsg(msg)

	case ActivateKeyTypeResultMsg:
		return m.finishLibraryAction(msg.ID, msg.Success, libraryEnabledStatus(msg.KeyType, msg.AlreadyExists), msg.Error, libraryEnableFailure)

	case DeactivateKeyTypeResultMsg:
		status := displayKeyType(msg.KeyType) + " was already disabled"
		if msg.Removed {
			status = displayKeyType(msg.KeyType) + " " + keytypeux.NotAvailableToCreate
		}
		return m.finishLibraryAction(msg.ID, msg.Success, status, msg.Error, libraryDisableFailure)

	case KeyTypesMsg:
		return m.handleKeyTypesMsg(msg)

	case CosignerReferencesMsg:
		m.cosigner.loaded = true
		if msg.Error != "" {
			m.cosigner.listErr = msg.Error
			// The status bar reports the failure on every other screen, such
			// as the key list, which loads the list at unlock, and the
			// Generate form, whose picker reads it; statusBarError leaves it
			// out on the manager, which shows listErr itself.
			m.lastError = msg.Error
			if m.cosigner.managerStatus == "Refreshing..." {
				m.cosigner.managerStatus = ""
			}
		} else {
			// The failure is over, in the status bar too; another error
			// there stays.
			if m.cosigner.listErr != "" && m.lastError == m.cosigner.listErr {
				m.lastError = ""
			}
			m.cosigner.listErr = ""
			m.cosigner.references = append([]CosignerReferenceInfo(nil), msg.References...)
			m.cosigner.invalid = append([]InvalidCosignerReferenceInfo(nil), msg.Invalid...)
			m.clampCosignerManagerScroll(m.cosignerManagerRows())
			// The delete hint is about the row it was given for, which the
			// list may have removed or moved from under the cursor.
			if bad, ok := m.selectedInvalidCosignerReference(); !ok || bad.Removable || bad.Path != m.cosigner.deleteHint {
				m.cosigner.deleteHint = ""
			}
			if m.viewState == ViewCosignerReferences && m.cosigner.managerStatus == "Refreshing..." {
				m.cosigner.managerStatus = ""
			}
		}
		return m, nil

	case CosignerImportResultMsg:
		if !m.takeOperationReply(msg.ID) {
			return m, nil
		}
		if !msg.Success {
			m.clearCosignerImportEnvelope()
			m.cosigner.importError = msg.Error
			if m.cosigner.importError == "" {
				m.cosigner.importError = "Cosigner key import failed"
			}
			m.viewState = ViewCosignerImportForm
			return m, nil
		}
		return m.completeCosignerImport(msg.Reference)

	case CosignerRemoveResultMsg:
		return m.handleCosignerRemoveResultMsg(msg)

	case CosignerExportResultMsg:
		return m.handleCosignerExportResultMsg(msg)

	case cosignerJSONTerminalClosedMsg:
		if m.viewState != ViewCosignerExportJSON {
			return m, nil
		}
		m.cosigner.exportShowJSON = false
		m.viewState = ViewCosignerExportPath
		if msg.err != nil {
			m.cosigner.exportError = fmt.Sprintf("Cannot display JSON in terminal: %v", msg.err)
		}
		return m, nil

	case CosignerExportWrittenMsg:
		if msg.Error != nil {
			m.cosigner.exportError = msg.Error.Error()
			m.viewState = ViewCosignerExportPath
			return m, nil
		}
		m.cosigner.exportError = ""
		m.cosigner.exportWrittenPath = msg.Path
		m.viewState = ViewCosignerExportResult
		return m, nil

	}

	return m, nil
}

// handleKeyPress handles keyboard input based on current view
func (m Model) handleKeyPress(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if msg.String() == "ctrl+c" || (msg.String() == "q" && isOperationInProgressView(m.viewState)) {
		m.clearMnemonicExport()
		m.clearSourceTokens()
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
		m.auth.endedReason = ""
		return m, m.reconnectCmd()
	}

	// A file browser belongs to the view it was opened from: it takes that
	// view's keys, waits under an approval popup, and closes when the view
	// changes for any other reason.
	if m.browser.active() {
		switch {
		case m.fileBrowserOpen():
			return m.handleFileBrowserKeys(msg)
		case !isApprovalView(m.viewState):
			m = m.closeFileBrowser()
		}
	}

	// View-specific handling
	switch m.viewState {
	case ViewMnemonicExport:
		return m.handleMnemonicExportKeys(msg)
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
	case ViewClientEnrollmentPopup:
		return m.handleClientEnrollmentPopupKeys(msg)
	case ViewBackupConfirm:
		return m.handleBackupConfirmKeys(msg)
	case ViewBackupDisplay:
		return m.handleBackupDisplayKeys(msg)
	case ViewBackups:
		return m.handleBackupsKeys(msg)
	case ViewBackupDeleteConfirm:
		return m.handleBackupDeleteConfirmKeys(msg)
	case ViewBackupUndoConfirm:
		return m.handleBackupUndoConfirmKeys(msg)
	case ViewBackupExport:
		return m.handleBackupExportKeys(msg)
	case ViewBackupImport:
		return m.handleBackupImportKeys(msg)
	case ViewRestorePassphrase:
		return m.handleRestorePassphraseKeys(msg)
	case ViewRestorePreview:
		return m.handleRestorePreviewKeys(msg)
	case ViewRestoreDisplay:
		return m.handleRestoreDisplayKeys(msg)
	case ViewStoreRecovery:
		return m.handleStoreRecoveryKeys(msg)
	case ViewGenerateDisplay:
		return m.handleGenerateDisplayKeys(msg)
	case ViewBoundaryPreset:
		return m.handleBoundaryPresetKeys(msg)
	case ViewGenerateReview:
		return m.handleGenerateReviewKeys(msg)
	case ViewGenerateReviewDetails:
		return m.handleGenerateReviewDetailsKeys(msg)
	case ViewImportDisplay:
		return m.handleImportDisplayKeys(msg)
	case ViewImportForm:
		return m.handleImportFormKeys(msg)
	case ViewGenerateForm:
		return m.handleGenerateFormKeys(msg)
	case ViewGenerateParams:
		return m.handleGenerateParamsKeys(msg)
	case ViewCosignerPicker:
		return m.handleCosignerPickerKeys(msg)
	case ViewCosignerImportForm:
		return m.handleCosignerImportFormKeys(msg)
	case ViewCosignerImportReview:
		return m.handleCosignerImportReviewKeys(msg)
	case ViewCosignerReferences:
		return m.handleCosignerReferencesKeys(msg)
	case ViewCosignerReferenceDetails:
		return m.handleCosignerReferenceDetailsKeys(msg)
	case ViewCosignerRemoveConfirm:
		return m.handleCosignerRemoveConfirmKeys(msg)
	case ViewCosignerGenerateType:
		return m.handleCosignerGenerateTypeKeys(msg)
	case ViewCosignerExportPath:
		return m.handleCosignerExportPathKeys(msg)
	case ViewCosignerExportResult:
		return m.handleCosignerExportResultKeys(msg)
	case ViewImportParams:
		return m.handleImportParamsKeys(msg)
	case ViewDeleteConfirm:
		return m.handleDeleteConfirmKeys(msg)
	case ViewEnrolledClients:
		return m.handleEnrolledClientsKeys(msg)
	case ViewRevokeClientConfirm:
		return m.handleRevokeClientConfirmKeys(msg)
	case ViewImportClientKey:
		return m.handleImportClientKeyKeys(msg)
	case ViewLockConfirm:
		return m.handleLockConfirmKeys(msg)
	case ViewDisplaceConfirm:
		return m.handleDisplaceConfirmKeys(msg)
	case ViewKeyDetails:
		return m.handleKeyDetailsKeys(msg)
	case ViewSourceTokens:
		return m.handleSourceTokensKeys(msg)
	case ViewTEALFullDisplay:
		return m.handleTEALFullDisplayKeys(msg)
	case ViewAdminPanel:
		return m.handleAdminPanelKeys(msg)
	case ViewPolicies:
		return m.handlePoliciesKeys(msg)
	case ViewPolicyDocument:
		return m.handlePolicyDocumentKeys(msg)
	case ViewPolicyApplyForm:
		return m.handlePolicyApplyFormKeys(msg)
	case ViewPolicyApplyReview:
		return m.handlePolicyApplyReviewKeys(msg)
	case ViewPolicyEdit:
		return m.handlePolicyEditKeys(msg)
	case ViewPolicyPresetPick:
		return m.handlePolicyPresetPickKeys(msg)
	case ViewPolicyExportForm:
		return m.handlePolicyExportFormKeys(msg)
	case ViewTemplateLibrary:
		return m.handleTemplateLibraryKeys(msg)
	case ViewTemplateInstallConfirm:
		return m.handleTemplateInstallConfirmKeys(msg)
	case ViewLibraryTemplateDetails:
		return m.handleLibraryTemplateDetailsKeys(msg)
	default:
		if isOperationInProgressView(m.viewState) && msg.String() == "esc" {
			m.lastError = "Operation in progress; wait for completion or press q to quit"
		}
	}

	return m, nil
}

// isOperationInProgressView reports whether view is a progress screen: it
// waits on one request, refuses Esc, and offers q to quit.
func isOperationInProgressView(view ViewState) bool {
	switch view {
	case ViewGenerating, ViewImporting, ViewCosignerImporting, ViewCosignerRemoving, ViewCosignerExporting,
		ViewDeleting, ViewTemplateInstalling, ViewBackingUp, ViewRestoring:
		return true
	}
	return false
}

func (m Model) usesSharedPopupViewport() bool {
	switch m.viewState {
	case ViewAuth,
		ViewUnlock,
		ViewClientEnrollmentPopup,
		ViewGenerateForm,
		ViewGenerateParams,
		ViewCosignerPicker,
		ViewRestorePreview,
		ViewCosignerImportForm,
		ViewCosignerImportReview,
		ViewCosignerImporting,
		ViewCosignerReferenceDetails,
		ViewCosignerRemoveConfirm,
		ViewCosignerRemoving,
		ViewCosignerGenerateType,
		ViewCosignerExportPath,
		ViewCosignerExporting,
		ViewCosignerExportResult,
		ViewGenerating,
		ViewGenerateDisplay,
		ViewBoundaryPreset,
		ViewGenerateReview,
		ViewGenerateReviewDetails,
		ViewMnemonicExport,
		ViewSourceTokens,
		ViewImportForm,
		ViewImportParams,
		ViewImporting,
		ViewImportDisplay,
		ViewBackupConfirm,
		ViewBackingUp,
		ViewBackupDisplay,
		ViewBackups,
		ViewBackupDeleteConfirm,
		ViewBackupUndoConfirm,
		ViewBackupExport,
		ViewBackupImport,
		ViewRestorePassphrase,
		ViewRestoring,
		ViewDeleteConfirm,
		ViewDeleting,
		ViewRevokeClientConfirm,
		ViewImportClientKey,
		ViewLockConfirm,
		ViewDisplaceConfirm,
		ViewPolicyApplyForm,
		ViewPolicyExportForm,
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
// wrong passphrase gets. apsigner codes every unlock failure: a wrong
// passphrase is invalid_passphrase and anything else is unlock_failed. A
// login the signer cannot check at all, such as one against a store root it
// cannot open, is authentication_failed, and the signer ends that login.
func isSeriousUnlockError(code string) bool {
	return code == protocol.ErrCodeUnlockFailed || code == protocol.ErrCodeAuthenticationFailed
}

// pendingOperation is the request an in-progress screen waits on.
type pendingOperation struct {
	id   string
	view ViewState
}

// beginOperation shows a progress screen for a new request and returns the
// request's ID, which the request must carry.
func (m *Model) beginOperation(view ViewState) string {
	prefix := map[ViewState]string{
		ViewGenerating: "gen", ViewImporting: "imp", ViewDeleting: "del",
		ViewTemplateInstalling: "keytype", ViewBackingUp: "backup",
		ViewCosignerImporting: "cosigner-import", ViewCosignerRemoving: "cosigner-remove",
		ViewCosignerExporting: "cosigner-export",
	}[view]
	id := newRequestID(prefix)
	m.operation = pendingOperation{id: id, view: view}
	m.viewState = view
	return id
}

// takeOperationReply reports whether id answers the operation the progress
// screen on show waits on, and if so ends that wait. A reply for any other
// request, or one that arrives after the screen moved on (a lock shows the
// unlock screen), is not that operation's result and changes no screen.
func (m *Model) takeOperationReply(id string) bool {
	if id == "" || id != m.operation.id || m.viewState != m.operation.view {
		return false
	}
	m.operation = pendingOperation{}
	return true
}

// failOperationInProgress returns an untyped failure (an authorization
// denial, an undecodable result, a send error) to the screen an in-progress
// operation started from, as that operation's own failure result would. A
// progress screen ignores Esc, so staying on it would strand the operator. id
// must name the operation's request: an error for any other request, such as
// a background refresh, leaves the operation waiting for its own result.
func (m Model) failOperationInProgress(id string, err error) (Model, bool) {
	if !m.takeOperationReply(id) {
		return m, false
	}
	switch m.viewState {
	case ViewGenerating:
		m.forms.generateError = err.Error()
		m.viewState = ViewGenerateForm
		if m.forms.genericLSigParams != nil {
			m.viewState = ViewGenerateParams
		}
	case ViewImporting:
		m.forms.importError = err.Error()
		m.viewState = m.importErrorView()
	case ViewDeleting:
		m.lastError = err.Error()
		m.viewState = ViewDeleteConfirm
	case ViewTemplateInstalling:
		m.library.installError = err.Error()
		m.viewState = ViewTemplateInstallConfirm
	case ViewBackingUp:
		m.backup.confirmError = err.Error()
		m.viewState = ViewBackupConfirm
	case ViewCosignerImporting:
		m.cosigner.importError = err.Error()
		m.viewState = ViewCosignerImportReview
	case ViewCosignerRemoving:
		m.cosigner.importError = err.Error()
		m.viewState = ViewCosignerRemoveConfirm
	case ViewCosignerExporting:
		m.cosigner.exportError = err.Error()
		m.viewState = ViewCosignerExportPath
	default:
		return m, false
	}
	return m, true
}
