// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"github.com/aplane-algo/aplane/internal/protocol"
	tea "github.com/charmbracelet/bubbletea"
)

// Admin requests and replies for the Backups page: delete, export (chunk
// reads), and import (begin, append, commit, abort). Every request carries an
// ID the page chose, and every reply arrives as a message carrying that ID,
// so the page can tell its own replies from stale ones.

// BackupDeleteResultMsg is the reply to delete_backup.
type BackupDeleteResultMsg struct {
	Result protocol.DeleteBackupResultMessage
}

// BackupChunkMsg is the reply to read_backup_chunk.
type BackupChunkMsg struct{ Chunk protocol.BackupChunkMessage }

// BeginBackupImportResultMsg is the reply to begin_backup_import.
type BeginBackupImportResultMsg struct {
	Result protocol.BeginBackupImportResultMessage
}

// AppendBackupImportResultMsg is the reply to append_backup_import.
type AppendBackupImportResultMsg struct {
	Result protocol.AppendBackupImportResultMessage
}

// CommitBackupImportResultMsg is the reply to commit_backup_import.
type CommitBackupImportResultMsg struct {
	Result protocol.CommitBackupImportResultMessage
}

// AbortBackupImportResultMsg is the reply to abort_backup_import.
type AbortBackupImportResultMsg struct {
	Result protocol.AbortBackupImportResultMessage
}

func init() {
	signerMessageDecoders[protocol.MsgTypeDeleteBackupResult] = decodeAs(func(r protocol.DeleteBackupResultMessage) tea.Msg {
		return BackupDeleteResultMsg{Result: r}
	})
	signerMessageDecoders[protocol.MsgTypeBackupChunk] = decodeAs(func(r protocol.BackupChunkMessage) tea.Msg {
		return BackupChunkMsg{Chunk: r}
	})
	signerMessageDecoders[protocol.MsgTypeBeginBackupImportResult] = decodeAs(func(r protocol.BeginBackupImportResultMessage) tea.Msg {
		return BeginBackupImportResultMsg{Result: r}
	})
	signerMessageDecoders[protocol.MsgTypeAppendBackupImportResult] = decodeAs(func(r protocol.AppendBackupImportResultMessage) tea.Msg {
		return AppendBackupImportResultMsg{Result: r}
	})
	signerMessageDecoders[protocol.MsgTypeCommitBackupImportResult] = decodeAs(func(r protocol.CommitBackupImportResultMessage) tea.Msg {
		return CommitBackupImportResultMsg{Result: r}
	})
	signerMessageDecoders[protocol.MsgTypeAbortBackupImportResult] = decodeAs(func(r protocol.AbortBackupImportResultMessage) tea.Msg {
		return AbortBackupImportResultMsg{Result: r}
	})
}

func base(msgType, id string) protocol.BaseMessage {
	return protocol.BaseMessage{Type: msgType, ID: id}
}

// backupRequestCmd sends one Backups-page request. A send failure comes back
// as an ErrorMsg carrying id, like the daemon's error replies.
func (m Model) backupRequestCmd(id string, send func(*IPCClient) error) tea.Cmd {
	return operationCmd(m.adminClient, id, send)
}

func (m Model) sendDeleteBackupCmd(id, fileName string) tea.Cmd {
	return m.backupRequestCmd(id, func(c *IPCClient) error {
		return c.sendMessage(protocol.DeleteBackupMessage{BaseMessage: base(protocol.MsgTypeDeleteBackup, id), ArchivePath: fileName})
	})
}

func (m Model) sendReadBackupChunkCmd(id, fileName string, offset int64) tea.Cmd {
	return m.backupRequestCmd(id, func(c *IPCClient) error {
		return c.sendMessage(protocol.ReadBackupChunkMessage{BaseMessage: base(protocol.MsgTypeReadBackupChunk, id), FileName: fileName, Offset: offset})
	})
}

func (m Model) sendBeginBackupImportCmd(id, fileName string) tea.Cmd {
	return m.backupRequestCmd(id, func(c *IPCClient) error {
		return c.sendMessage(protocol.BeginBackupImportMessage{BaseMessage: base(protocol.MsgTypeBeginBackupImport, id), FileName: fileName})
	})
}

func (m Model) sendAppendBackupImportCmd(id, uploadID string, offset int64, data []byte) tea.Cmd {
	return m.backupRequestCmd(id, func(c *IPCClient) error {
		return c.sendMessage(protocol.AppendBackupImportMessage{
			BaseMessage: base(protocol.MsgTypeAppendBackupImport, id), UploadID: uploadID, Offset: offset, Data: data,
		})
	})
}

// sendCommitBackupImportCmd sends the commit. It takes its own copy of the
// passphrase and zeroes that copy after sending; the caller zeroes its own.
func (m Model) sendCommitBackupImportCmd(id, uploadID, fileName string, size int64, checksum string, passphrase []byte) tea.Cmd {
	secret := protocol.SensitiveBytes(append([]byte(nil), passphrase...))
	return m.backupRequestCmd(id, func(c *IPCClient) error {
		defer secret.Zero()
		return c.sendMessage(protocol.CommitBackupImportMessage{
			BaseMessage: base(protocol.MsgTypeCommitBackupImport, id), UploadID: uploadID, FileName: fileName,
			ExpectedSize: size, ExpectedSHA256: checksum, ExportPassphrase: secret,
		})
	})
}

func (m Model) sendAbortBackupImportCmd(uploadID string) tea.Cmd {
	id := newRequestID("backup-import-abort")
	return m.backupRequestCmd(id, func(c *IPCClient) error {
		return c.sendMessage(protocol.AbortBackupImportMessage{BaseMessage: base(protocol.MsgTypeAbortBackupImport, id), UploadID: uploadID})
	})
}
