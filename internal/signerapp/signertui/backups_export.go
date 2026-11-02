// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/apadminapp"
	"github.com/aplane-algo/aplane/internal/backup"
	tea "github.com/charmbracelet/bubbletea"
)

// Exporting copies one backup archive from the signer's repository into a
// directory on this machine, as apadmin backup export does: the bytes are
// read in chunks into a private staging file, checked against the listed
// size and SHA-256, and published under the archive's name without replacing
// anything. The archive stays encrypted under its backup passphrase.

type backupExportState struct {
	target BackupInfo
	// dir is the destination directory field; lastDir is reused for the
	// next export this session.
	dir     string
	lastDir string
	err     string
	// writer is the transfer in progress, nil when none; pendingID names the
	// chunk request it waits on.
	writer    *apadminapp.BackupExportWriter
	pendingID string
	// finishing is a transfer whose last chunk arrived: its sync, checksum,
	// and publication run off the event loop and cannot be canceled.
	finishing *apadminapp.BackupExportWriter
}

// backupExportFinishedMsg carries a finished export's verification and
// publication, run off the event loop.
type backupExportFinishedMsg struct {
	writer   *apadminapp.BackupExportWriter
	checksum string
	warnings []string
	err      error
}

func (m Model) openBackupExport(info BackupInfo) Model {
	export := &m.backups.export
	dir := export.lastDir
	if dir == "" {
		dir = "~"
	}
	*export = backupExportState{target: info, dir: dir, lastDir: export.lastDir, finishing: export.finishing}
	m.viewState = ViewBackupExport
	return m
}

func (m Model) handleBackupExportKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	export := &m.backups.export
	if export.finishing != nil {
		if msg.String() == "esc" {
			m.setBackupsStatus("Finishing the export; its result will show here.", false)
			m.viewState = ViewBackups
		}
		return m, nil
	}
	if export.writer != nil {
		if msg.String() == "esc" {
			m = m.stopBackupExport()
			m.setBackupsStatus("Export canceled.", false)
			m.viewState = ViewBackups
		}
		return m, nil
	}
	switch msg.String() {
	case "esc":
		m.viewState = ViewBackups
		return m, nil
	case "enter":
		return m.startBackupExport()
	case fileBrowserKey:
		return m.openFileBrowser(browseBackupExportDir, export.dir, "", export.target.FileName), nil
	case "backspace", "delete":
		export.dir = trimLastRune(export.dir)
		export.err = ""
		return m, nil
	}
	if msg.Type == tea.KeyRunes {
		export.dir += string(msg.Runes)
		export.err = ""
	}
	return m, nil
}

func (m Model) startBackupExport() (tea.Model, tea.Cmd) {
	export := &m.backups.export
	if export.finishing != nil {
		export.err = "The previous export is still being saved; try again when it finishes."
		return m, nil
	}
	dir := strings.TrimSpace(export.dir)
	if dir == "" {
		export.err = "A destination directory is required"
		return m, nil
	}
	expanded, err := expandHomePath(dir)
	if err != nil {
		export.err = err.Error()
		return m, nil
	}
	writer, err := apadminapp.BeginBackupExport(expanded, export.target)
	if err != nil {
		export.err = err.Error()
		return m, nil
	}
	export.err = ""
	export.lastDir = dir
	export.writer = writer
	return m.requestBackupExportChunk()
}

func (m Model) requestBackupExportChunk() (tea.Model, tea.Cmd) {
	export := &m.backups.export
	export.pendingID = newRequestID("backup-export-chunk")
	return m, tea.Batch(
		m.sendReadBackupChunkCmd(export.pendingID, export.target.FileName, export.writer.Written()),
		m.waitForMessageCmd(),
	)
}

func (m Model) handleBackupChunk(msg BackupChunkMsg) (tea.Model, tea.Cmd) {
	export := &m.backups.export
	if export.writer == nil || msg.Chunk.ID == "" || msg.Chunk.ID != export.pendingID {
		return m, m.waitForMessageCmd()
	}
	export.pendingID = ""
	done, err := export.writer.Write(msg.Chunk)
	if err != nil {
		return m.failBackupExport(err), m.waitForMessageCmd()
	}
	if !done {
		return m.requestBackupExportChunk()
	}
	writer := export.writer
	export.writer = nil
	export.finishing = writer
	finish := func() tea.Msg {
		checksum, warnings, err := writer.Finish()
		return backupExportFinishedMsg{writer: writer, checksum: checksum, warnings: warnings, err: err}
	}
	return m, tea.Batch(finish, m.waitForMessageCmd())
}

func (m Model) handleBackupExportFinished(msg backupExportFinishedMsg) (tea.Model, tea.Cmd) {
	export := &m.backups.export
	if msg.writer == nil || msg.writer != export.finishing {
		return m, nil
	}
	export.finishing = nil
	if msg.err != nil {
		if m.viewState == ViewBackupExport {
			export.err = "Export failed: " + msg.err.Error()
		} else {
			m.setBackupsStatus("Export failed: "+msg.err.Error(), true)
		}
		return m, nil
	}
	status := fmt.Sprintf("Exported to %s (SHA-256 %s).", msg.writer.Destination(), msg.checksum)
	for _, warning := range msg.warnings {
		status += "\nWarning: " + warning
	}
	m.setBackupsStatus(status, false)
	if m.viewState == ViewBackupExport {
		m.viewState = ViewBackups
	}
	return m, nil
}

// failBackupExport ends a transfer with err, removing its staging file.
func (m Model) failBackupExport(err error) Model {
	m = m.stopBackupExport()
	m.backups.export.err = "Export failed: " + err.Error()
	return m
}

// stopBackupExport abandons a transfer in progress, if any; a chunk still in
// flight is ignored when it arrives.
func (m Model) stopBackupExport() Model {
	export := &m.backups.export
	if export.writer != nil {
		export.writer.Abort()
	}
	export.writer = nil
	export.pendingID = ""
	return m
}

// failPendingBackupExport routes an untyped failure for the export's chunk
// request. It reports false for any other request.
func (m Model) failPendingBackupExport(id string, err error) (Model, bool) {
	if id == "" || id != m.backups.export.pendingID {
		return m, false
	}
	return m.failBackupExport(err), true
}

func (m Model) renderBackupExport() string {
	export := m.backups.export
	width := m.popupBodyWidth(90)
	var body strings.Builder
	body.WriteString(titleStyle.Render("Export Backup"))
	body.WriteString("\n")
	body.WriteString(wrapPlainText(terminalSafe(export.target.FileName), width))
	body.WriteString("\n" + subtitleStyle.Render(backup.FormatFileSize(export.target.Size)) + "\n\n")
	body.WriteString("Destination directory:\n")
	body.WriteString(inputActiveStyle.Width(m.constrainParameterFieldWidth(60)).Render(terminalSafe(export.dir)))
	body.WriteString("\n" + helpStyle.Render("ctrl+o browses. The archive keeps its name and stays encrypted under its backup passphrase."))
	body.WriteString("\n")
	if export.finishing != nil {
		body.WriteString("\n" + subtitleStyle.Render("Verifying and saving the copy...") + "\n")
	}
	if export.writer != nil {
		body.WriteString("\n" + subtitleStyle.Render(fmt.Sprintf("Exporting... %s of %s",
			backup.FormatFileSize(export.writer.Written()), backup.FormatFileSize(export.target.Size))) + "\n")
	}
	if export.err != "" {
		body.WriteString("\n" + errorStyle.Render(wrapPlainText(terminalSafeLines(export.err), width)) + "\n")
	}
	return m.renderPopup(90, body.String())
}

func (m Model) backupExportFooterText() string {
	if m.backups.export.finishing != nil {
		return "esc: Leave (the result is reported later)"
	}
	if m.backups.export.writer != nil {
		return "esc: Cancel"
	}
	return "enter: Export | ctrl+o: Browse | esc: Back"
}
