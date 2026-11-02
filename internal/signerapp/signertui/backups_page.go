// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/apadminapp"
	"github.com/aplane-algo/aplane/internal/backup"
	"github.com/aplane-algo/aplane/internal/protocol"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// The Backups page is the operator's view of the signer's backup repository:
// it lists every managed backup and creates, views and restores, exports,
// imports, and deletes them, and undoes the latest restore. Listing,
// viewing, restoring, exporting, and importing work in recovery mode too;
// creating and deleting need the signer unlocked, and the page says so
// instead of sending a request the daemon would refuse.

// backupsPageState is the Backups page's own state. The view and restore
// screens keep theirs in restoreState.
type backupsPageState struct {
	// status is a one-shot message shown on the list: the outcome of the
	// last action.
	status    string
	statusErr bool
	// selectName is the archive to select when the next list arrives.
	selectName string

	del       backupDeleteState
	undoFocus int // 0 = cancel, 1 = undo
	// undoPending routes a refused undo back to this page; a completed one
	// follows the store reconcile to the key list.
	undoPending bool

	export backupExportState
	imp    backupImportState
}

type backupDeleteState struct {
	target    BackupInfo
	focus     int // 0 = cancel, 1 = delete
	pendingID string
	err       string
}

func (m *Model) setBackupsStatus(text string, isErr bool) {
	m.backups.status = text
	m.backups.statusErr = isErr
}

// backupsRecovery reports whether the signer is in recovery mode, where
// creating and deleting backups are unavailable.
func (m Model) backupsRecovery() bool {
	return m.signerState == signerRuntimeRecovery
}

// refreshBackups lists the repository again, keeping the page where it is.
func (m Model) refreshBackups() (Model, tea.Cmd) {
	m.restore.backupsLoaded = false
	return m, tea.Batch(m.sendListBackupsCmd(), m.waitForMessageCmd())
}

// returnToBackups shows the list and refreshes it, selecting name when given.
func (m Model) returnToBackups(selectName string) (Model, tea.Cmd) {
	m.viewState = ViewBackups
	m.backups.selectName = selectName
	return m.refreshBackups()
}

func (m Model) handleBackupsKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()
	switch key {
	case "q", "esc":
		m.setBackupsStatus("", false)
		if m.restore.returnToRecovery || m.backupsRecovery() {
			m.resetRestoreFlow(true)
			return m.openStoreRecovery()
		}
		m.resetRestoreFlow(true)
		m.viewState = ViewKeyList
		return m, nil
	case "up", "k":
		if m.restore.selectedBackup > 0 {
			m.restore.selectedBackup--
		}
		return m, nil
	case "down", "j":
		if m.restore.selectedBackup < len(m.restore.backups)-1 {
			m.restore.selectedBackup++
		}
		return m, nil
	case "home", "g":
		m.restore.selectedBackup = 0
		return m, nil
	case "end", "G":
		m.restore.selectedBackup = max(len(m.restore.backups)-1, 0)
		return m, nil
	}

	m.setBackupsStatus("", false)
	switch key {
	case "r", "R":
		return m.refreshBackups()
	case "n", "N":
		if m.backupsRecovery() {
			m.setBackupsStatus("Creating a backup needs the signer unlocked; it is in recovery mode.", true)
			return m, nil
		}
		return m.openBackupConfirm()
	case "i", "I":
		return m.openBackupImport()
	case "u", "U":
		m.backups.undoFocus = 0
		m.viewState = ViewBackupUndoConfirm
		return m, nil
	}

	info, ok := m.currentRestoreBackup()
	if !ok {
		return m, nil
	}
	switch key {
	case "enter":
		return m.openBackupView(info), nil
	case "x", "X":
		return m.openBackupExport(info), nil
	case "d", "D":
		if m.backupsRecovery() {
			m.setBackupsStatus("Deleting a backup needs the signer unlocked; it is in recovery mode.", true)
			return m, nil
		}
		m.backups.del = backupDeleteState{target: info}
		m.viewState = ViewBackupDeleteConfirm
		return m, nil
	}
	return m, nil
}

// openBackupView asks for the backup's passphrase, then shows what it holds;
// restoring is the view's last step.
func (m Model) openBackupView(info BackupInfo) Model {
	m.clearRestorePassphrase()
	m.restore.archivePath = info.Path
	m.restore.archiveCreatedAt = 0
	m.restore.passphraseError = ""
	m.restore.previewError = ""
	m.restore.previewKeys = nil
	m.restore.previewErrors = nil
	m.restore.selected = nil
	m.restore.selectedKey = 0
	m.restore.previewScrollOffset = 0
	m.restore.replaceExisting = false
	m.restore.replaceConflicts = nil
	m.viewState = ViewRestorePassphrase
	return m
}

// handleBackupsListed applies a fresh list: it keeps or moves the selection
// and settles an import whose outcome was unknown.
func (m Model) handleBackupsListed(msg BackupsListMsg) Model {
	m.restore.backupsLoaded = true
	if msg.Error != "" {
		m.lastError = "Backup list failed: " + msg.Error
		return m
	}
	m.lastError = ""
	previous, hadPrevious := m.currentRestoreBackup()
	m.restore.backups = msg.Backups
	want := m.backups.selectName
	if want == "" && hadPrevious {
		want = previous.FileName
	}
	m.backups.selectName = ""
	for i, item := range m.restore.backups {
		if item.FileName == want {
			m.restore.selectedBackup = i
		}
	}
	m.clampRestoreSelection()
	m = m.reconcileUnresolvedImport()
	return m
}

// --- delete ---

func (m Model) handleBackupDeleteConfirmKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	del := &m.backups.del
	if del.pendingID != "" {
		return m, nil
	}
	switch msg.String() {
	case "esc", "n", "N":
		m.backups.del = backupDeleteState{}
		m.viewState = ViewBackups
		return m, nil
	case "left", "right", "tab", "shift+tab", "h", "l":
		del.focus = 1 - del.focus
		return m, nil
	case "enter", " ":
		if del.focus == 0 {
			m.backups.del = backupDeleteState{}
			m.viewState = ViewBackups
			return m, nil
		}
		return m.sendBackupDelete()
	case "y", "Y":
		return m.sendBackupDelete()
	}
	return m, nil
}

func (m Model) sendBackupDelete() (tea.Model, tea.Cmd) {
	del := &m.backups.del
	del.err = ""
	del.pendingID = newRequestID("backup-delete")
	return m, tea.Batch(m.sendDeleteBackupCmd(del.pendingID, del.target.FileName), m.waitForMessageCmd())
}

func (m Model) handleBackupDeleteResult(msg BackupDeleteResultMsg) (tea.Model, tea.Cmd) {
	del := &m.backups.del
	if msg.Result.ID == "" || msg.Result.ID != del.pendingID {
		return m, m.waitForMessageCmd()
	}
	del.pendingID = ""
	if !msg.Result.Success {
		del.err = backupResultText(msg.Result.Error, "the backup could not be deleted")
		return m, m.waitForMessageCmd()
	}
	name := del.target.FileName
	m.backups.del = backupDeleteState{}
	m.setBackupsStatus("Deleted "+name+".", false)
	// A reply that arrives after the operator left the dialog (the signer
	// locked, say) is recorded, not shown by taking over the screen.
	if m.viewState != ViewBackupDeleteConfirm {
		return m, m.waitForMessageCmd()
	}
	next, cmd := m.returnToBackups("")
	return next, cmd
}

func (m Model) renderBackupDeleteConfirm() string {
	del := m.backups.del
	width := m.popupBodyWidth(80)
	var body strings.Builder
	body.WriteString(warningStyle.Render("DELETE BACKUP"))
	body.WriteString("\n\n")
	body.WriteString(wrapPlainText(terminalSafe(del.target.FileName), width))
	created, _ := apadminapp.BackupCreatedTime(del.target)
	body.WriteString("\n" + subtitleStyle.Render(fmt.Sprintf("Created %s   %s", formatBackupTime(created), backup.FormatFileSize(del.target.Size))))
	body.WriteString("\n\n")
	if len(m.restore.backups) == 1 {
		body.WriteString(warningStyle.Render("This is the only backup: the signer will have none."))
		body.WriteString("\n\n")
	} else if len(m.restore.backups) > 0 && m.restore.backups[0].FileName == del.target.FileName {
		body.WriteString(warningStyle.Render("This is the newest backup."))
		body.WriteString("\n\n")
	}
	body.WriteString("The archive is removed from the signer. Export it first to keep a copy.\n\n")
	body.WriteString(confirmButtons(del.focus, "DELETE") + "\n")
	if del.pendingID != "" {
		body.WriteString("\n" + subtitleStyle.Render("Deleting...") + "\n")
	}
	if del.err != "" {
		body.WriteString("\n" + errorStyle.Render(wrapPlainText(terminalSafeLines(del.err), width)) + "\n")
	}
	return m.renderPopup(80, body.String())
}

// --- undo the latest restore ---

func (m Model) handleBackupUndoConfirmKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "n", "N":
		m.viewState = ViewBackups
		return m, nil
	case "left", "right", "tab", "shift+tab", "h", "l":
		m.backups.undoFocus = 1 - m.backups.undoFocus
		return m, nil
	case "enter", " ":
		if m.backups.undoFocus == 0 {
			m.viewState = ViewBackups
			return m, nil
		}
		return m.sendBackupUndo()
	case "y", "Y":
		return m.sendBackupUndo()
	}
	return m, nil
}

// sendBackupUndo asks the daemon to roll back the latest restore. The daemon
// decides whether one can be undone; a refusal comes back to this page.
func (m Model) sendBackupUndo() (tea.Model, tea.Cmd) {
	m.backups.undoPending = true
	m.restore.recoveryError = ""
	m.restore.progressLabel = "Undoing Latest Restore"
	m.viewState = ViewRestoring
	return m, tea.Batch(m.sendRollbackRestoreCmd(), m.waitForMessageCmd())
}

// handleRefusedBackupUndo returns a refused undo to the Backups page. It
// reports false when no undo from this page is pending or the failure left
// the store in recovery, which the recovery screen handles.
func (m Model) handleRefusedBackupUndo(result protocol.RollbackRestoreResultMessage) (Model, tea.Cmd, bool) {
	if !m.backups.undoPending {
		return m, nil, false
	}
	m.backups.undoPending = false
	if result.Code == protocol.ResultCodeRestoreRollbackFailed || m.backupsRecovery() {
		return m, nil, false
	}
	m.setBackupsStatus("Undo refused: "+backupResultText(result.Error, "there is no restore to undo"), true)
	next, cmd := m.returnToBackups("")
	return next, cmd, true
}

func (m Model) renderBackupUndoConfirm() string {
	width := m.popupBodyWidth(80)
	var body strings.Builder
	body.WriteString(warningStyle.Render("UNDO LATEST RESTORE"))
	body.WriteString("\n\n")
	body.WriteString(wrapPlainText("Returns the signer's keys to how they were before the most recent restore. The signer refuses if its latest change was not a restore that can still be undone.", width))
	body.WriteString("\n\n")
	body.WriteString(confirmButtons(m.backups.undoFocus, "UNDO") + "\n")
	return m.renderPopup(80, body.String())
}

// --- the list ---

// backupTimeLayout is how the page shows times, in the local zone.
const backupTimeLayout = "2006-01-02 15:04:05"

func formatBackupTime(t time.Time) string {
	if t.IsZero() || t.Unix() <= 0 {
		return "unknown"
	}
	return t.Local().Format(backupTimeLayout)
}

func backupResultText(text, fallback string) string {
	if strings.TrimSpace(text) == "" {
		return fallback
	}
	return text
}

func (m Model) renderBackups() string {
	const popupWidth = 96
	width := m.popupBodyWidth(popupWidth)
	var header strings.Builder
	header.WriteString(titleStyle.Render("Backups"))
	header.WriteString("\n")

	if !m.restore.backupsLoaded && len(m.restore.backups) == 0 {
		header.WriteString(subtitleStyle.Render("Loading backups..."))
		return m.renderPopup(popupWidth, header.String())
	}
	node := "signer"
	if m.isCosignerNode() {
		node = "cosigner"
	}
	count := len(m.restore.backups)
	noun := "backups"
	if count == 1 {
		noun = "backup"
	}
	header.WriteString(subtitleStyle.Render(fmt.Sprintf("%d %s on this %s", count, noun, node)))
	header.WriteString("\n")
	if banner := m.unresolvedImportBanner(); banner != "" {
		header.WriteString("\n" + warningStyle.Render(wrapPlainText(banner, width)) + "\n")
	}
	if m.backups.status != "" {
		style := statusUnlockedStyle
		if m.backups.statusErr {
			style = errorStyle
		}
		header.WriteString("\n" + style.Render(wrapPlainText(terminalSafeLines(m.backups.status), width)) + "\n")
	}
	header.WriteString("\n")

	if count == 0 {
		header.WriteString(subtitleStyle.Render("No backups yet. n creates one; i imports one."))
		return m.renderPopup(popupWidth, header.String())
	}

	const timeWidth, sizeWidth = 21, 9
	nameWidth := max(width-2-timeWidth-2-sizeWidth-2, 12)
	zone := time.Now().Format("MST")
	header.WriteString(helpStyle.Render(fmt.Sprintf("  %-*s  %-*s  %*s", timeWidth, "Created ("+zone+")", nameWidth, "Name", sizeWidth, "Size")))
	header.WriteString("\n")

	rows := make([]string, count)
	fileTimes := false
	for i, item := range m.restore.backups {
		created, source := apadminapp.BackupCreatedTime(item)
		stamp := formatBackupTime(created)
		if source == apadminapp.BackupTimeFile {
			stamp += " *"
			fileTimes = true
		}
		name := ellipsizeMiddle(terminalSafe(item.FileName), nameWidth)
		line := fmt.Sprintf("%-*s  %-*s  %*s", timeWidth, stamp, nameWidth, name, sizeWidth, backup.FormatFileSize(item.Size))
		if i == m.restore.selectedBackup {
			rows[i] = selectedStyle.Render("> " + line)
		} else {
			rows[i] = normalStyle.Render("  " + line)
		}
	}
	footer := ""
	if fileTimes {
		footer = "\n" + helpStyle.Render("* file time: the name carries no creation time") + "\n"
	}
	return m.renderPopup(popupWidth, m.fitSelectionList(header.String(), rows, m.restore.selectedBackup, footer, popupWidth))
}

func (m Model) backupsFooterText() string {
	parts := []string{"enter: View/Restore", "x: Export", "i: Import"}
	if !m.backupsRecovery() {
		parts = append([]string{"n: New"}, parts...)
		parts = append(parts, "d: Delete")
	}
	parts = append(parts, "u: Undo restore", "r: Refresh", "esc: Back")
	return strings.Join(parts, " | ")
}

// failPendingBackupDelete routes an untyped failure for the delete request.
func (m Model) failPendingBackupDelete(id string, err error) (Model, bool) {
	if id == "" || id != m.backups.del.pendingID {
		return m, false
	}
	m.backups.del.pendingID = ""
	m.backups.del.err = err.Error()
	return m, true
}

// backupNameTimeTolerance is how far a backup's sealed creation time may be
// from the time in its name before the view says they disagree; the name is
// written just before the manifest is sealed.
const backupNameTimeTolerance = time.Minute

// renderBackupViewHeader names the backup being viewed: when it was made, as
// sealed inside it, and its size and checksum from the list. It warns when
// the sealed time disagrees with the time in the backup's name.
func (m Model) renderBackupViewHeader(popupWidth int) string {
	name := filepath.Base(m.restore.archivePath)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Archive:  %s\n", terminalSafe(name)))
	if sealed := m.restore.archiveCreatedAt; sealed > 0 {
		sb.WriteString(fmt.Sprintf("Created:  %s (sealed in the backup)\n", formatBackupTime(time.Unix(sealed, 0))))
		if named, ok := backup.ManagedArchiveNameTime(name); ok {
			if diff := named.Sub(time.Unix(sealed, 0)); diff > backupNameTimeTolerance || diff < -backupNameTimeTolerance {
				sb.WriteString(warningStyle.Render(wrapPlainText(fmt.Sprintf(
					"The name says %s; the backup was sealed at a different time. It may have been renamed.",
					formatBackupTime(named)), m.popupBodyWidth(popupWidth))))
				sb.WriteString("\n")
			}
		}
	}
	for _, item := range m.restore.backups {
		if item.FileName == name {
			sb.WriteString(fmt.Sprintf("Size:     %s   SHA-256 %s\n", backup.FormatFileSize(item.Size), item.Checksum))
			break
		}
	}
	return sb.String()
}

// confirmButtons lays out a CANCEL button and a destructive action button
// side by side, as the key delete dialog does; focus 0 is CANCEL.
func confirmButtons(focus int, action string) string {
	cancel := buttonInactiveStyle.Render("  CANCEL")
	act := buttonInactiveStyle.Render("  " + action)
	if focus == 0 {
		cancel = buttonActiveStyle.Render("> CANCEL")
	} else {
		act = buttonActiveStyle.BorderForeground(lipgloss.Color("196")).Foreground(lipgloss.Color("196")).Render("> " + action)
	}
	return lipgloss.JoinHorizontal(lipgloss.Center, cancel, "  ", act)
}

// Shutdown releases what the Backups page holds when the program exits: an
// export's staging file, an import's open archive and passphrase. An export
// already being verified and saved is left to finish; an upload in progress
// is left to the signer's cleanup of abandoned uploads. The apadmin and
// apconsole binaries call it on the final model, whatever ended the program.
func (m Model) Shutdown() {
	m = m.stopBackupExport()
	m.shutdownBackupImport()
}

// restoreFlowWaiting reports whether the operator is on a screen that waits
// for a rollback or reconcile reply: the progress screen that sent it, or
// the store recovery screen. A successful reconcile only takes over the
// screen from one of these.
func (m Model) restoreFlowWaiting() bool {
	return m.viewState == ViewRestoring || m.viewState == ViewStoreRecovery
}

// recordLateRollback records a rollback reply that arrived after the signer
// locked. It changes no screen and sends no reconcile: the signer's state on
// the next unlock says whether one is needed.
func (m Model) recordLateRollback(result protocol.RollbackRestoreResultMessage) Model {
	fromPage := m.backups.undoPending
	m.backups.undoPending = false
	if result.Success {
		m.restore.recoveryError = ""
		if fromPage {
			m.setBackupsStatus("The latest restore was undone.", false)
		}
		return m
	}
	m.restore.recoveryError = result.Error
	if fromPage {
		m.setBackupsStatus("Undo refused: "+backupResultText(result.Error, "there is no restore to undo"), true)
	}
	return m
}

// signerKnownLocked reports that the signer has said it is locked. Locked is
// also the state before any status arrives, which is not a lock.
func (m Model) signerKnownLocked() bool {
	return m.signerStatusKnown && m.signerState == signerRuntimeLocked
}
