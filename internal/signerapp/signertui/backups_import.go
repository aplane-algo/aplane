// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/apadminapp"
	"github.com/aplane-algo/aplane/internal/backup"
	tea "github.com/charmbracelet/bubbletea"
)

// Importing adds an archive from this machine to the signer's repository, as
// apadmin backup import does: begin an upload, append it in chunks, then
// commit with the backup passphrase, which the signer uses to check every
// key before publishing the archive. Import never changes keys.
//
// Two replies may arrive after the page has stopped waiting, and both are
// kept by request ID rather than ignored:
//   - a begin abandoned before its reply: the reply names an upload that is
//     then aborted;
//   - a commit whose outcome is unresolved: once sent, the signer finishes
//     validating and publishing whatever the client does, so its reply, when
//     it comes, settles the outcome. If the connection was lost, no reply
//     will come, and the next list settles it instead: listed with the same
//     checksum means it succeeded; absent means it may still be validating,
//     never that it failed.

type backupImportPhase int

const (
	importIdle backupImportPhase = iota
	// importPreparing checks and hashes the local archive off the event
	// loop; a large file on slow storage must not freeze the TUI.
	importPreparing
	importBeginning
	importUploading
	importCommitting
)

// Focus positions on the import form.
const (
	importFocusPath = iota
	importFocusPassphrase
	importFocusButton
)

type backupImportState struct {
	path       string
	passphrase []byte
	focus      int
	err        string

	phase     backupImportPhase
	source    apadminapp.BackupImportSource
	file      *os.File
	uploadID  string
	pendingID string
	offset    int64

	// canceledBegins are begin requests abandoned before their reply.
	canceledBegins map[string]bool
	// unresolved are committed imports whose outcome is not known yet. There
	// can be several: an import left unresolved by a lost connection is
	// still tracked while a later one is left by esc.
	unresolved []unresolvedBackupImport
}

// backupCommitWait is how long the page waits on a commit before leaving its
// outcome unresolved; the signer's validation has no such limit.
var backupCommitWait = apadminapp.BackupCommitTimeout

// backupImportPreparedMsg carries the local archive check, run off the event
// loop. token names the attempt; a stale result is ignored.
type backupImportPreparedMsg struct {
	token  string
	source apadminapp.BackupImportSource
	err    error
}

// backupCommitTimeoutMsg fires when the page stops waiting on a commit.
type backupCommitTimeoutMsg struct{ id string }

type unresolvedBackupImport struct {
	name     string
	checksum string
	size     int64
	// commitID names the commit whose reply would settle the outcome; it is
	// empty once the connection that sent it is gone.
	commitID string
}

func (m Model) openBackupImport() (tea.Model, tea.Cmd) {
	imp := &m.backups.imp
	zeroBytes(imp.passphrase)
	*imp = backupImportState{canceledBegins: imp.canceledBegins, unresolved: imp.unresolved}
	m.viewState = ViewBackupImport
	return m, nil
}

func (m Model) handleBackupImportKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	imp := &m.backups.imp
	if imp.phase != importIdle {
		if msg.String() == "esc" {
			return m.leaveBackupImport()
		}
		return m, nil
	}
	switch msg.String() {
	case "esc":
		m = m.closeBackupImportForm()
		m.viewState = ViewBackups
		return m, nil
	case fileBrowserKey:
		imp.focus = importFocusPath
		return m.openFileBrowser(browseBackupImportFile, imp.path, ""), nil
	case "tab", "down":
		imp.focus = (imp.focus + 1) % 3
		return m, nil
	case "shift+tab", "up":
		imp.focus = (imp.focus + 2) % 3
		return m, nil
	case "enter":
		if imp.focus < importFocusButton {
			imp.focus++
			return m, nil
		}
		return m.startBackupImport()
	case "backspace", "delete":
		switch imp.focus {
		case importFocusPath:
			imp.path = trimLastRune(imp.path)
		case importFocusPassphrase:
			if n := len(imp.passphrase); n > 0 {
				imp.passphrase[n-1] = 0
				imp.passphrase = imp.passphrase[:n-1]
			}
		}
		imp.err = ""
		return m, nil
	}
	if msg.Type == tea.KeyRunes {
		switch imp.focus {
		case importFocusPath:
			imp.path += string(msg.Runes)
		case importFocusPassphrase:
			imp.passphrase = append(imp.passphrase, string(msg.Runes)...)
		}
		imp.err = ""
	}
	return m, nil
}

// closeBackupImportForm forgets the form's input, zeroing the passphrase.
func (m Model) closeBackupImportForm() Model {
	imp := &m.backups.imp
	zeroBytes(imp.passphrase)
	imp.passphrase = nil
	imp.err = ""
	return m
}

func (m Model) startBackupImport() (tea.Model, tea.Cmd) {
	imp := &m.backups.imp
	path := strings.TrimSpace(imp.path)
	if path == "" {
		imp.err = "An archive file is required"
		imp.focus = importFocusPath
		return m, nil
	}
	if len(imp.passphrase) == 0 {
		imp.err = "The backup passphrase is required"
		imp.focus = importFocusPassphrase
		return m, nil
	}
	expanded, err := expandHomePath(path)
	if err != nil {
		imp.err = err.Error()
		return m, nil
	}
	imp.err = ""
	imp.phase = importPreparing
	imp.pendingID = newRequestID("backup-import-prepare")
	token := imp.pendingID
	return m, func() tea.Msg {
		source, err := apadminapp.PrepareBackupImportSource(expanded)
		return backupImportPreparedMsg{token: token, source: source, err: err}
	}
}

func (m Model) handleBackupImportPrepared(msg backupImportPreparedMsg) (tea.Model, tea.Cmd) {
	imp := &m.backups.imp
	if msg.token == "" || msg.token != imp.pendingID || imp.phase != importPreparing {
		return m, nil
	}
	imp.pendingID = ""
	if msg.err != nil {
		m = m.failBackupImport(msg.err)
		return m, nil
	}
	file, err := os.Open(msg.source.Path)
	if err != nil {
		m = m.failBackupImport(err)
		return m, nil
	}
	imp.source = msg.source
	imp.file = file
	imp.offset = 0
	imp.uploadID = ""
	imp.phase = importBeginning
	imp.pendingID = newRequestID("backup-import-begin")
	return m, tea.Batch(m.sendBeginBackupImportCmd(imp.pendingID, msg.source.Name), m.waitForMessageCmd())
}

func (m Model) handleBeginBackupImportResult(msg BeginBackupImportResultMsg) (tea.Model, tea.Cmd) {
	imp := &m.backups.imp
	id := msg.Result.ID
	if id != "" && imp.canceledBegins[id] {
		delete(imp.canceledBegins, id)
		if msg.Result.Success && msg.Result.UploadID != "" {
			return m, tea.Batch(m.sendAbortBackupImportCmd(msg.Result.UploadID), m.waitForMessageCmd())
		}
		return m, m.waitForMessageCmd()
	}
	if id == "" || id != imp.pendingID || imp.phase != importBeginning {
		return m, m.waitForMessageCmd()
	}
	imp.pendingID = ""
	if !msg.Result.Success {
		m = m.failBackupImport(errors.New(backupResultText(msg.Result.Error, "the upload could not start")))
		return m, m.waitForMessageCmd()
	}
	imp.uploadID = msg.Result.UploadID
	imp.phase = importUploading
	return m.sendNextBackupImportStep()
}

// sendNextBackupImportStep appends the next chunk, or commits once the whole
// file is uploaded.
func (m Model) sendNextBackupImportStep() (tea.Model, tea.Cmd) {
	imp := &m.backups.imp
	if imp.offset >= imp.source.Size {
		return m.commitBackupImport()
	}
	buffer := make([]byte, min(int64(adminproto.BackupTransferChunkBytes), imp.source.Size-imp.offset))
	n, err := imp.file.ReadAt(buffer, imp.offset)
	if n < len(buffer) {
		if err == nil || errors.Is(err, io.EOF) {
			err = errors.New("the archive file changed while it was being uploaded")
		}
		next, cmd := m.abortBackupImport(err)
		return next, cmd
	}
	imp.pendingID = newRequestID("backup-import-append")
	return m, tea.Batch(m.sendAppendBackupImportCmd(imp.pendingID, imp.uploadID, imp.offset, buffer), m.waitForMessageCmd())
}

func (m Model) handleAppendBackupImportResult(msg AppendBackupImportResultMsg) (tea.Model, tea.Cmd) {
	imp := &m.backups.imp
	if msg.Result.ID == "" || msg.Result.ID != imp.pendingID || imp.phase != importUploading {
		return m, m.waitForMessageCmd()
	}
	imp.pendingID = ""
	if !msg.Result.Success {
		next, cmd := m.abortBackupImport(errors.New(backupResultText(msg.Result.Error, "the upload failed")))
		return next, cmd
	}
	if msg.Result.NextOffset <= imp.offset || msg.Result.NextOffset > imp.source.Size {
		next, cmd := m.abortBackupImport(fmt.Errorf("the signer reported offset %d after %d", msg.Result.NextOffset, imp.offset))
		return next, cmd
	}
	imp.offset = msg.Result.NextOffset
	return m.sendNextBackupImportStep()
}

func (m Model) commitBackupImport() (tea.Model, tea.Cmd) {
	imp := &m.backups.imp
	m = m.closeBackupImportFile()
	imp.phase = importCommitting
	imp.pendingID = newRequestID("backup-import-commit")
	cmd := m.sendCommitBackupImportCmd(imp.pendingID, imp.uploadID, imp.source.Name, imp.source.Size, imp.source.Checksum, imp.passphrase)
	zeroBytes(imp.passphrase)
	imp.passphrase = nil
	id := imp.pendingID
	timeout := tea.Tick(backupCommitWait, func(time.Time) tea.Msg { return backupCommitTimeoutMsg{id: id} })
	return m, tea.Batch(cmd, timeout, m.waitForMessageCmd())
}

// handleBackupCommitTimeout stops waiting on a commit that has not replied.
// The outcome becomes unresolved, keeping the commit's ID for a late reply.
func (m Model) handleBackupCommitTimeout(msg backupCommitTimeoutMsg) (tea.Model, tea.Cmd) {
	imp := &m.backups.imp
	if msg.id == "" || msg.id != imp.pendingID || imp.phase != importCommitting {
		return m, nil
	}
	m.markBackupImportUnresolved(imp.pendingID)
	m = m.resetBackupImportTransfer()
	m = m.closeBackupImportForm()
	if m.viewState == ViewBackupImport {
		m.viewState = ViewBackups
	}
	return m, nil
}

func (m Model) handleCommitBackupImportResult(msg CommitBackupImportResultMsg) (tea.Model, tea.Cmd) {
	imp := &m.backups.imp
	id := msg.Result.ID
	if id == "" {
		return m, m.waitForMessageCmd()
	}
	if id == imp.pendingID && imp.phase == importCommitting {
		imp.pendingID = ""
		imp.phase = importIdle
		if !msg.Result.Success {
			imp.err = "Import failed: " + backupResultText(msg.Result.Error, "the signer refused the archive")
			return m, m.waitForMessageCmd()
		}
		m.setBackupsStatus(importedStatus(imp.source.Name, msg.Result.Warning), false)
		if m.viewState != ViewBackupImport {
			return m, m.waitForMessageCmd()
		}
		next, cmd := m.returnToBackups(imp.source.Name)
		return next, cmd
	}
	name := m.takeUnresolvedImport(id)
	if name == "" {
		return m, m.waitForMessageCmd()
	}
	if !msg.Result.Success {
		m.setBackupsStatus("Import of "+name+" failed: "+backupResultText(msg.Result.Error, "the signer refused the archive"), true)
	} else {
		m.setBackupsStatus(importedStatus(name, msg.Result.Warning), false)
	}
	if m.viewState == ViewBackups {
		next, cmd := m.refreshBackups()
		return next, cmd
	}
	return m, m.waitForMessageCmd()
}

func importedStatus(name, warning string) string {
	status := "Imported " + name + ". Restoring from it is a separate step."
	if warning != "" {
		status += "\nWarning: " + warning
	}
	return status
}

// leaveBackupImport handles esc while a transfer runs: before commit it
// cancels the upload; after commit it leaves the outcome unresolved.
func (m Model) leaveBackupImport() (tea.Model, tea.Cmd) {
	imp := &m.backups.imp
	var cmd tea.Cmd
	switch imp.phase {
	case importPreparing:
		m.setBackupsStatus("Import canceled.", false)
	case importBeginning:
		m.cancelBackupImportBegin()
		m.setBackupsStatus("Import canceled.", false)
	case importUploading:
		cmd = m.sendAbortBackupImportCmd(imp.uploadID)
		m.setBackupsStatus("Import canceled.", false)
	case importCommitting:
		m.markBackupImportUnresolved(imp.pendingID)
	}
	m = m.resetBackupImportTransfer()
	m = m.closeBackupImportForm()
	m.viewState = ViewBackups
	return m, cmd
}

func (m *Model) cancelBackupImportBegin() {
	imp := &m.backups.imp
	if imp.pendingID == "" {
		return
	}
	if imp.canceledBegins == nil {
		imp.canceledBegins = make(map[string]bool)
	}
	imp.canceledBegins[imp.pendingID] = true
}

func (m *Model) markBackupImportUnresolved(commitID string) {
	imp := &m.backups.imp
	imp.unresolved = append(imp.unresolved, unresolvedBackupImport{
		name: imp.source.Name, checksum: imp.source.Checksum, size: imp.source.Size, commitID: commitID,
	})
}

// takeUnresolvedImport removes the unresolved import whose commit is id and
// returns its name; "" when there is none.
func (m *Model) takeUnresolvedImport(id string) string {
	imp := &m.backups.imp
	for i, pending := range imp.unresolved {
		if pending.commitID != "" && pending.commitID == id {
			imp.unresolved = append(imp.unresolved[:i:i], imp.unresolved[i+1:]...)
			return pending.name
		}
	}
	return ""
}

// abortBackupImport ends an upload that began, telling the signer to remove
// it, and reports err on the form.
func (m Model) abortBackupImport(err error) (Model, tea.Cmd) {
	imp := &m.backups.imp
	var cmd tea.Cmd
	if imp.uploadID != "" {
		cmd = m.sendAbortBackupImportCmd(imp.uploadID)
	}
	m = m.failBackupImport(err)
	return m, tea.Batch(cmd, m.waitForMessageCmd())
}

func (m Model) failBackupImport(err error) Model {
	m = m.resetBackupImportTransfer()
	m.backups.imp.err = "Import failed: " + err.Error()
	return m
}

func (m Model) resetBackupImportTransfer() Model {
	m = m.closeBackupImportFile()
	imp := &m.backups.imp
	imp.phase = importIdle
	imp.pendingID = ""
	imp.uploadID = ""
	imp.offset = 0
	return m
}

func (m Model) closeBackupImportFile() Model {
	imp := &m.backups.imp
	if imp.file != nil {
		_ = imp.file.Close()
		imp.file = nil
	}
	return m
}

// failPendingBackupImport routes an untyped failure (a send error, an
// authorization denial) for the import's request or for an unresolved
// commit. It reports false for any other request.
func (m Model) failPendingBackupImport(id string, err error) (Model, tea.Cmd, bool) {
	imp := &m.backups.imp
	if id == "" {
		return m, nil, false
	}
	if name := m.takeUnresolvedImport(id); name != "" {
		m.setBackupsStatus("Import of "+name+" failed: "+err.Error(), true)
		return m, nil, true
	}
	if id != imp.pendingID {
		return m, nil, false
	}
	next, cmd := m.abortBackupImport(err)
	return next, cmd, true
}

// interruptBackupTransfers stops the page's transfers when the session can
// no longer continue them. With a live connection (the signer locked) an
// upload not yet committed is aborted now, which the signer allows while
// locked; a lost connection leaves that to the signer's own cleanup. A
// committed import's outcome becomes unresolved; its reply can still arrive
// only on a live connection.
func (m *Model) interruptBackupTransfers(connectionLive bool) tea.Cmd {
	if m.backups.export.writer != nil {
		*m = m.stopBackupExport()
		m.backups.export.err = "Export stopped: the signer session ended."
	}
	imp := &m.backups.imp
	var cmd tea.Cmd
	switch imp.phase {
	case importBeginning:
		if connectionLive {
			m.cancelBackupImportBegin()
		}
	case importUploading:
		if connectionLive && imp.uploadID != "" {
			cmd = m.sendAbortBackupImportCmd(imp.uploadID)
		}
	case importCommitting:
		commitID := imp.pendingID
		if !connectionLive {
			commitID = ""
		}
		m.markBackupImportUnresolved(commitID)
	}
	if !connectionLive {
		imp.canceledBegins = nil
		for i := range imp.unresolved {
			imp.unresolved[i].commitID = ""
		}
	}
	if imp.phase != importIdle {
		*m = m.resetBackupImportTransfer()
	}
	// The form's passphrase never outlives the session, entered or not.
	*m = m.closeBackupImportForm()
	return cmd
}

// reconcileUnresolvedImport settles an unresolved import from a fresh list,
// when it can: a listed backup with its name decides it; absence does not,
// since the signer may still be validating it.
func (m Model) reconcileUnresolvedImport() Model {
	imp := &m.backups.imp
	var still []unresolvedBackupImport
	var settled []string
	failed := false
	for _, pending := range imp.unresolved {
		listed := false
		for _, item := range m.restore.backups {
			if item.FileName != pending.name {
				continue
			}
			listed = true
			if item.Checksum == pending.checksum && item.Size == pending.size {
				settled = append(settled, "Imported "+pending.name+".")
			} else {
				settled = append(settled, "A different backup named "+pending.name+" is in the repository; the import did not publish.")
				failed = true
			}
			break
		}
		if !listed {
			still = append(still, pending)
		}
	}
	imp.unresolved = still
	if len(settled) > 0 {
		m.setBackupsStatus(strings.Join(settled, "\n"), failed)
	}
	return m
}

func (m Model) unresolvedImportBanner() string {
	var lines []string
	for _, pending := range m.backups.imp.unresolved {
		line := "Import of " + terminalSafe(pending.name) + ": outcome unknown. The signer may still be checking it."
		if pending.commitID != "" {
			line += " The result shows here when it replies; r checks the list."
		} else {
			line += " r checks again."
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

// shutdownBackupImport releases what an import holds when the program exits:
// the open archive file and the passphrase.
func (m *Model) shutdownBackupImport() {
	*m = m.closeBackupImportFile()
	*m = m.closeBackupImportForm()
}

func (m Model) renderBackupImport() string {
	imp := m.backups.imp
	width := m.popupBodyWidth(90)
	var body strings.Builder
	body.WriteString(titleStyle.Render("Import Backup"))
	body.WriteString("\n")
	body.WriteString(subtitleStyle.Render(wrapPlainText("Adds an archive to the signer's backups; keys change only on restore.", width)))
	body.WriteString("\n\n")

	pathStyle, passStyle := inputInactiveStyle, inputInactiveStyle
	switch imp.focus {
	case importFocusPath:
		pathStyle = inputActiveStyle
	case importFocusPassphrase:
		passStyle = inputActiveStyle
	}
	body.WriteString("Archive file (.tar.gz or .tgz)  " + helpStyle.Render("ctrl+o browses") + "\n")
	body.WriteString(pathStyle.Width(m.constrainParameterFieldWidth(60)).Render(terminalSafe(imp.path)))
	body.WriteString("\nBackup passphrase  " + helpStyle.Render("the signer checks every key with it; not stored") + "\n")
	body.WriteString(passStyle.Width(m.constrainParameterFieldWidth(44)).Render(strings.Repeat("*", len(imp.passphrase))))
	body.WriteString("\n\n")
	button := buttonInactiveStyle.Render("IMPORT")
	if imp.focus == importFocusButton {
		button = buttonActiveStyle.Render("IMPORT")
	}
	body.WriteString(button + "\n")

	switch imp.phase {
	case importPreparing:
		body.WriteString("\n" + subtitleStyle.Render("Checking the file...") + "\n")
	case importBeginning:
		body.WriteString("\n" + subtitleStyle.Render("Starting the upload...") + "\n")
	case importUploading:
		body.WriteString("\n" + subtitleStyle.Render(fmt.Sprintf("Uploading... %s of %s",
			backup.FormatFileSize(imp.offset), backup.FormatFileSize(imp.source.Size))) + "\n")
	case importCommitting:
		body.WriteString("\n" + subtitleStyle.Render(wrapPlainText("Checking the archive. This can take a while; esc leaves, and the result is reported on the Backups page.", width)) + "\n")
	}
	if imp.err != "" {
		body.WriteString("\n" + errorStyle.Render(wrapPlainText(terminalSafeLines(imp.err), width)) + "\n")
	}
	return m.renderPopup(90, body.String())
}

func (m Model) backupImportFooterText() string {
	switch m.backups.imp.phase {
	case importIdle:
		return "Tab: Next | ctrl+o: Browse | Enter: Import | Esc: Back"
	case importCommitting:
		return "esc: Leave (the result is reported later)"
	default:
		return "esc: Cancel"
	}
}
