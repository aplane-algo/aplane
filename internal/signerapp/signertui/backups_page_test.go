// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/protocol"
	tea "github.com/charmbracelet/bubbletea"
)

// sentRequestIDs runs cmd and returns the IDs of the requests it sent. With
// no admin client every send fails at once with an ErrorMsg carrying its
// request ID, whose prefix names the request.
func sentRequestIDs(cmd tea.Cmd) []string {
	if cmd == nil {
		return nil
	}
	switch msg := cmd().(type) {
	case tea.BatchMsg:
		var ids []string
		for _, c := range msg {
			ids = append(ids, sentRequestIDs(c)...)
		}
		return ids
	case ErrorMsg:
		if msg.ID != "" {
			return []string{msg.ID}
		}
	}
	return nil
}

func sentRequest(cmd tea.Cmd, prefix string) string {
	for _, id := range sentRequestIDs(cmd) {
		if strings.HasPrefix(id, prefix+"-") {
			return id
		}
	}
	return ""
}

func backupsModel(backups ...BackupInfo) Model {
	return Model{
		viewState:   ViewBackups,
		signerState: signerRuntimeUnlocked,
		width:       100,
		height:      40,
		restore:     restoreState{backupsLoaded: true, backups: backups},
	}
}

func pressKey(t *testing.T, m Model, keys ...string) (Model, tea.Cmd) {
	t.Helper()
	var cmd tea.Cmd
	for _, k := range keys {
		var next tea.Model
		next, cmd = m.handleKeyPress(browserKey(k))
		m = next.(Model)
	}
	return m, cmd
}

func update(t *testing.T, m Model, msg tea.Msg) (Model, tea.Cmd) {
	t.Helper()
	next, cmd := m.Update(msg)
	return next.(Model), cmd
}

func TestBackupsListShowsNameTimeAndSize(t *testing.T) {
	m := backupsModel(
		BackupInfo{FileName: "aplane-backup-20261102-070725.677012380.tar.gz", Path: "aplane-backup-20261102-070725.677012380.tar.gz", Size: 13861},
		BackupInfo{FileName: "lab-signer.tar.gz", Path: "lab-signer.tar.gz", Size: 100, CreatedAt: time.Date(2026, 10, 30, 18, 2, 11, 0, time.UTC).Unix()},
	)
	view := stripANSI(m.View())
	named := time.Date(2026, 11, 2, 7, 7, 25, 0, time.UTC).Local().Format(backupTimeLayout)
	filed := time.Date(2026, 10, 30, 18, 2, 11, 0, time.UTC).Local().Format(backupTimeLayout)
	for _, want := range []string{
		"2 backups on this signer", named, filed + " *", "lab-signer.tar.gz", "13.5 KB",
		"* file time: the name carries no creation time",
	} {
		if !strings.Contains(view, want) {
			t.Fatalf("list is missing %q:\n%s", want, view)
		}
	}
	if footer := m.viewFooterText(); !strings.Contains(footer, "n: New") || !strings.Contains(footer, "d: Delete") {
		t.Fatalf("footer = %q", footer)
	}
}

func TestBackupsPageGatesCreateAndDeleteInRecovery(t *testing.T) {
	m := backupsModel(BackupInfo{FileName: "a.tar.gz", Path: "a.tar.gz"})
	m.signerState = signerRuntimeRecovery
	if footer := m.viewFooterText(); strings.Contains(footer, "n: New") || strings.Contains(footer, "d: Delete") {
		t.Fatalf("recovery footer offers create or delete: %q", footer)
	}
	for _, key := range []string{"n", "d"} {
		got, _ := pressKey(t, m, key)
		if got.viewState != ViewBackups || !got.backups.statusErr || !strings.Contains(got.backups.status, "needs the signer unlocked") {
			t.Fatalf("%s in recovery: view %v status %q", key, got.viewState, got.backups.status)
		}
	}
	// Viewing, exporting, and importing still work.
	if got, _ := pressKey(t, m, "x"); got.viewState != ViewBackupExport {
		t.Fatalf("x in recovery: view %v, want export", got.viewState)
	}
}

func TestBackupsListKeepsSelectionAcrossRefresh(t *testing.T) {
	a := BackupInfo{FileName: "a.tar.gz", Path: "a.tar.gz"}
	b := BackupInfo{FileName: "b.tar.gz", Path: "b.tar.gz"}
	m := backupsModel(a, b)
	m.restore.selectedBackup = 1
	m, _ = update(t, m, BackupsListMsg{Backups: []BackupInfo{{FileName: "new.tar.gz"}, a, b}})
	if got, _ := m.currentRestoreBackup(); got.FileName != "b.tar.gz" {
		t.Fatalf("selection moved to %s, want b.tar.gz", got.FileName)
	}
	m.backups.selectName = "new.tar.gz"
	m, _ = update(t, m, BackupsListMsg{Backups: []BackupInfo{{FileName: "new.tar.gz"}, a, b}})
	if got, _ := m.currentRestoreBackup(); got.FileName != "new.tar.gz" {
		t.Fatalf("selectName did not select the new backup: %s", got.FileName)
	}
}

func TestBackupDeleteConfirmsThenDeletes(t *testing.T) {
	m := backupsModel(BackupInfo{FileName: "only.tar.gz", Path: "only.tar.gz"})
	m, _ = pressKey(t, m, "d")
	if m.viewState != ViewBackupDeleteConfirm || m.backups.del.focus != 0 {
		t.Fatalf("d: view %v focus %d, want the confirm with focus on cancel", m.viewState, m.backups.del.focus)
	}
	if view := stripANSI(m.View()); !strings.Contains(view, "only backup") {
		t.Fatalf("deleting the only backup does not warn:\n%s", view)
	}
	if got, _ := pressKey(t, m, "enter"); got.viewState != ViewBackups || got.backups.del.pendingID != "" {
		t.Fatal("enter on the default focus did not cancel")
	}

	m, cmd := pressKey(t, m, "y")
	id := sentRequest(cmd, "backup-delete")
	if id == "" || m.backups.del.pendingID != id {
		t.Fatalf("y sent %v, want a delete request", sentRequestIDs(cmd))
	}
	failed, _ := update(t, m, BackupDeleteResultMsg{Result: protocol.DeleteBackupResultMessage{BaseMessage: protocol.BaseMessage{ID: id}, Error: "busy"}})
	if failed.viewState != ViewBackupDeleteConfirm || failed.backups.del.err != "busy" {
		t.Fatalf("failed delete: view %v err %q", failed.viewState, failed.backups.del.err)
	}
	done, _ := update(t, m, BackupDeleteResultMsg{Result: protocol.DeleteBackupResultMessage{BaseMessage: protocol.BaseMessage{ID: id}, Success: true}})
	if done.viewState != ViewBackups || !strings.Contains(done.backups.status, "Deleted only.tar.gz") || done.restore.backupsLoaded {
		t.Fatalf("deleted: view %v status %q loaded %v, want the list refreshing", done.viewState, done.backups.status, done.restore.backupsLoaded)
	}
}

func TestBackupUndoRefusalReturnsToBackups(t *testing.T) {
	m := backupsModel()
	m, _ = pressKey(t, m, "u", "y")
	if m.viewState != ViewRestoring || !m.backups.undoPending {
		t.Fatalf("undo: view %v pending %v", m.viewState, m.backups.undoPending)
	}
	m, _ = update(t, m, RollbackRestoreResultMsg{Result: protocol.RollbackRestoreResultMessage{Error: "no restore to roll back"}})
	if m.viewState != ViewBackups || !m.backups.statusErr || !strings.Contains(m.backups.status, "no restore to roll back") || m.backups.undoPending {
		t.Fatalf("refused undo: view %v status %q pending %v", m.viewState, m.backups.status, m.backups.undoPending)
	}
}

// --- export ---

func exportFixture(t *testing.T) (Model, []byte, string) {
	t.Helper()
	payload := []byte(strings.Repeat("backup bytes ", 100))
	sum := sha256.Sum256(payload)
	info := BackupInfo{FileName: "aplane-backup-20261102-070725.tar.gz", Path: "aplane-backup-20261102-070725.tar.gz", Size: int64(len(payload)), Checksum: hex.EncodeToString(sum[:])}
	dest := filepath.Join(t.TempDir(), "usb")
	m := backupsModel(info)
	m, _ = pressKey(t, m, "x")
	m.backups.export.dir = dest
	return m, payload, dest
}

func TestBackupExportStreamsVerifiesAndPublishes(t *testing.T) {
	m, payload, dest := exportFixture(t)
	m, cmd := pressKey(t, m, "enter")
	id := sentRequest(cmd, "backup-export-chunk")
	if id == "" || m.backups.export.writer == nil {
		t.Fatalf("enter sent %v, want a chunk read", sentRequestIDs(cmd))
	}
	half := len(payload) / 2
	m, cmd = update(t, m, BackupChunkMsg{Chunk: protocol.BackupChunkMessage{BaseMessage: protocol.BaseMessage{ID: id}, Success: true, Data: payload[:half]}})
	next := sentRequest(cmd, "backup-export-chunk")
	if next == "" || next == id {
		t.Fatalf("first chunk did not request the next: %v", sentRequestIDs(cmd))
	}
	// A late reply to the earlier request is ignored.
	m, _ = update(t, m, BackupChunkMsg{Chunk: protocol.BackupChunkMessage{BaseMessage: protocol.BaseMessage{ID: id}, Success: true, Data: []byte("stale")}})
	m, _ = update(t, m, BackupChunkMsg{Chunk: protocol.BackupChunkMessage{BaseMessage: protocol.BaseMessage{ID: next}, Success: true, Offset: int64(half), Data: payload[half:], EOF: true}})
	if m.viewState != ViewBackups || !strings.Contains(m.backups.status, "Exported to "+filepath.Join(dest, "aplane-backup-20261102-070725.tar.gz")) {
		t.Fatalf("export done: view %v status %q", m.viewState, m.backups.status)
	}
	got, err := os.ReadFile(filepath.Join(dest, "aplane-backup-20261102-070725.tar.gz"))
	if err != nil || string(got) != string(payload) {
		t.Fatalf("exported file = %d bytes, err %v", len(got), err)
	}
	assertNoExportStaging(t, dest)
}

func TestBackupExportRejectsChecksumMismatchAndCleansUp(t *testing.T) {
	m, payload, dest := exportFixture(t)
	m, cmd := pressKey(t, m, "enter")
	id := sentRequest(cmd, "backup-export-chunk")
	tampered := append([]byte(nil), payload...)
	tampered[0] ^= 1
	m, _ = update(t, m, BackupChunkMsg{Chunk: protocol.BackupChunkMessage{BaseMessage: protocol.BaseMessage{ID: id}, Success: true, Data: tampered, EOF: true}})
	if m.viewState != ViewBackupExport || !strings.Contains(m.backups.export.err, "checksum mismatch") {
		t.Fatalf("mismatch: view %v err %q", m.viewState, m.backups.export.err)
	}
	if _, err := os.Stat(filepath.Join(dest, "aplane-backup-20261102-070725.tar.gz")); !os.IsNotExist(err) {
		t.Fatalf("a mismatched export was published: %v", err)
	}
	assertNoExportStaging(t, dest)
}

func TestBackupExportEscCancelsAndRemovesStaging(t *testing.T) {
	m, _, dest := exportFixture(t)
	m, cmd := pressKey(t, m, "enter")
	id := sentRequest(cmd, "backup-export-chunk")
	m, _ = pressKey(t, m, "esc")
	if m.viewState != ViewBackups || m.backups.export.writer != nil || !strings.Contains(m.backups.status, "canceled") {
		t.Fatalf("esc: view %v writer %v status %q", m.viewState, m.backups.export.writer, m.backups.status)
	}
	assertNoExportStaging(t, dest)
	// The chunk in flight is ignored when it arrives.
	m, _ = update(t, m, BackupChunkMsg{Chunk: protocol.BackupChunkMessage{BaseMessage: protocol.BaseMessage{ID: id}, Success: true, Data: []byte("x"), EOF: true}})
	if entries, _ := os.ReadDir(dest); len(entries) != 0 {
		t.Fatalf("a canceled export wrote %d file(s)", len(entries))
	}
}

func TestBackupExportRefusesExistingDestination(t *testing.T) {
	m, _, dest := exportFixture(t)
	if err := os.MkdirAll(dest, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dest, "aplane-backup-20261102-070725.tar.gz"), []byte("mine"), 0o600); err != nil {
		t.Fatal(err)
	}
	m, cmd := pressKey(t, m, "enter")
	if sentRequest(cmd, "backup-export-chunk") != "" || !strings.Contains(m.backups.export.err, "already exists") {
		t.Fatalf("existing destination: sent %v err %q", sentRequestIDs(cmd), m.backups.export.err)
	}
}

func assertNoExportStaging(t *testing.T, dir string) {
	t.Helper()
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".part") {
			t.Fatalf("staging file %s left behind", e.Name())
		}
	}
}

// --- import ---

// importFixture opens the import form with a real archive file and a
// passphrase entered.
func importFixture(t *testing.T) (Model, string, int64) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "lab.tar.gz")
	data := []byte(strings.Repeat("archive ", 64))
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	m := backupsModel()
	m, _ = pressKey(t, m, "i")
	m.backups.imp.path = path
	m.backups.imp.passphrase = []byte("secret")
	m.backups.imp.focus = importFocusButton
	sum := sha256.Sum256(data)
	return m, hex.EncodeToString(sum[:]), int64(len(data))
}

func beginReply(id, uploadID string) BeginBackupImportResultMsg {
	return BeginBackupImportResultMsg{Result: protocol.BeginBackupImportResultMessage{BaseMessage: protocol.BaseMessage{ID: id}, Success: true, UploadID: uploadID}}
}

func appendReply(id string, next int64) AppendBackupImportResultMsg {
	return AppendBackupImportResultMsg{Result: protocol.AppendBackupImportResultMessage{BaseMessage: protocol.BaseMessage{ID: id}, Success: true, NextOffset: next}}
}

func commitReply(id string, ok bool, warning, errText string) CommitBackupImportResultMsg {
	return CommitBackupImportResultMsg{Result: protocol.CommitBackupImportResultMessage{
		BaseMessage: protocol.BaseMessage{ID: id}, Success: ok, Warning: warning, Error: errText,
	}}
}

// importToCommit runs an import through begin and upload, returning the
// model waiting on the commit and the commit's request ID.
func importToCommit(t *testing.T) (Model, string) {
	t.Helper()
	m, _, size := importFixture(t)
	m, cmd := pressKey(t, m, "enter")
	begin := sentRequest(cmd, "backup-import-begin")
	m, cmd = update(t, m, beginReply(begin, "upload-1"))
	appendID := sentRequest(cmd, "backup-import-append")
	m, cmd = update(t, m, appendReply(appendID, size))
	commit := sentRequest(cmd, "backup-import-commit")
	if commit == "" || m.backups.imp.phase != importCommitting {
		t.Fatalf("upload did not commit: sent %v phase %v", sentRequestIDs(cmd), m.backups.imp.phase)
	}
	if m.backups.imp.passphrase != nil {
		t.Fatal("the passphrase was kept after commit was sent")
	}
	return m, commit
}

func TestBackupImportUploadsAndCommits(t *testing.T) {
	m, commit := importToCommit(t)
	m, _ = update(t, m, commitReply(commit, true, "", ""))
	if m.viewState != ViewBackups || m.backups.selectName != "lab.tar.gz" || !strings.Contains(m.backups.status, "Imported lab.tar.gz") {
		t.Fatalf("committed: view %v select %q status %q", m.viewState, m.backups.selectName, m.backups.status)
	}
}

func TestBackupImportCommitFailureStaysOnForm(t *testing.T) {
	m, commit := importToCommit(t)
	m, _ = update(t, m, commitReply(commit, false, "", "wrong passphrase"))
	if m.viewState != ViewBackupImport || m.backups.imp.phase != importIdle || !strings.Contains(m.backups.imp.err, "wrong passphrase") {
		t.Fatalf("failed commit: view %v phase %v err %q", m.viewState, m.backups.imp.phase, m.backups.imp.err)
	}
}

func TestBackupImportEscBeforeBeginReplyAbortsTheLateUpload(t *testing.T) {
	m, _, _ := importFixture(t)
	m, cmd := pressKey(t, m, "enter")
	begin := sentRequest(cmd, "backup-import-begin")
	m, _ = pressKey(t, m, "esc")
	if m.viewState != ViewBackups || m.backups.imp.phase != importIdle {
		t.Fatalf("esc: view %v phase %v", m.viewState, m.backups.imp.phase)
	}
	m, cmd = update(t, m, beginReply(begin, "upload-late"))
	if sentRequest(cmd, "backup-import-abort") == "" {
		t.Fatalf("the late begin reply was not aborted: %v", sentRequestIDs(cmd))
	}
	if m.viewState != ViewBackups || m.backups.imp.phase != importIdle || len(m.backups.imp.canceledBegins) != 0 {
		t.Fatalf("late begin reopened the import: view %v phase %v", m.viewState, m.backups.imp.phase)
	}
}

func TestBackupImportEscDuringUploadAborts(t *testing.T) {
	m, _, _ := importFixture(t)
	m, cmd := pressKey(t, m, "enter")
	m, _ = update(t, m, beginReply(sentRequest(cmd, "backup-import-begin"), "upload-1"))
	m, cmd = pressKey(t, m, "esc")
	if sentRequest(cmd, "backup-import-abort") == "" || m.viewState != ViewBackups {
		t.Fatalf("esc during upload: sent %v view %v", sentRequestIDs(cmd), m.viewState)
	}
}

func TestBackupImportLateCommitReplySettlesUnresolvedOutcome(t *testing.T) {
	for _, tc := range []struct {
		name, warning, errText string
		ok                     bool
		want                   string
		isErr                  bool
	}{
		{"late failure", "", "invalid backup contents", false, "Import of lab.tar.gz failed: invalid backup contents", true},
		{"late success with warning", "directory durability could not be confirmed", "", true, "Warning: directory durability could not be confirmed", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, commit := importToCommit(t)
			m, _ = pressKey(t, m, "esc")
			if m.viewState != ViewBackups || m.backups.imp.unresolved == nil || m.backups.imp.unresolved.commitID != commit {
				t.Fatalf("esc while checking: view %v unresolved %+v", m.viewState, m.backups.imp.unresolved)
			}
			if banner := stripANSI(m.View()); !strings.Contains(banner, "outcome unknown") {
				t.Fatalf("no unresolved banner:\n%s", banner)
			}
			m.viewState = ViewKeyList
			m, _ = update(t, m, commitReply(commit, tc.ok, tc.warning, tc.errText))
			if m.viewState != ViewKeyList || m.backups.imp.unresolved != nil {
				t.Fatalf("late reply: view %v unresolved %+v, want settled without reopening", m.viewState, m.backups.imp.unresolved)
			}
			if !strings.Contains(m.backups.status, tc.want) || m.backups.statusErr != tc.isErr {
				t.Fatalf("status %q (err %v), want %q", m.backups.status, m.backups.statusErr, tc.want)
			}
		})
	}
}

func TestBackupImportAfterLostConnectionSettlesOnlyByListing(t *testing.T) {
	m, commit := importToCommit(t)
	m, _ = update(t, m, DisconnectedMsg{})
	pending := m.backups.imp.unresolved
	if pending == nil || pending.commitID != "" || m.backups.imp.phase != importIdle {
		t.Fatalf("disconnect while checking: unresolved %+v phase %v", pending, m.backups.imp.phase)
	}
	// No reply can come on a lost connection; a stray one is not trusted.
	m, _ = update(t, m, commitReply(commit, false, "", "x"))
	if m.backups.imp.unresolved == nil {
		t.Fatal("a reply for the lost connection's commit settled the import")
	}

	m.viewState = ViewBackups
	// Validation can still be running: absence keeps the outcome unknown.
	m, _ = update(t, m, BackupsListMsg{Backups: []BackupInfo{{FileName: "other.tar.gz"}}})
	if m.backups.imp.unresolved == nil || m.backups.statusErr {
		t.Fatalf("an absent import was settled: status %q", m.backups.status)
	}
	// The archive appears on a later check.
	m, _ = update(t, m, BackupsListMsg{Backups: []BackupInfo{{FileName: "lab.tar.gz", Checksum: pending.checksum, Size: pending.size}}})
	if m.backups.imp.unresolved != nil || !strings.Contains(m.backups.status, "Imported lab.tar.gz") {
		t.Fatalf("listed import: unresolved %+v status %q", m.backups.imp.unresolved, m.backups.status)
	}
}

func TestBackupImportListedWithAnotherChecksumIsANameConflict(t *testing.T) {
	m, _ := importToCommit(t)
	m, _ = update(t, m, DisconnectedMsg{})
	m, _ = update(t, m, BackupsListMsg{Backups: []BackupInfo{{FileName: "lab.tar.gz", Checksum: "other", Size: 1}}})
	if m.backups.imp.unresolved != nil || !m.backups.statusErr || !strings.Contains(m.backups.status, "different backup named lab.tar.gz") {
		t.Fatalf("name conflict: unresolved %+v status %q", m.backups.imp.unresolved, m.backups.status)
	}
}

func TestBackupImportLockAbortsUploadOrLeavesCommitUnresolved(t *testing.T) {
	m, _, _ := importFixture(t)
	m, cmd := pressKey(t, m, "enter")
	m, _ = update(t, m, beginReply(sentRequest(cmd, "backup-import-begin"), "upload-1"))
	m, cmd = update(t, m, LockIdentityResultMsg{Success: true})
	if sentRequest(cmd, "backup-import-abort") == "" || m.backups.imp.phase != importIdle {
		t.Fatalf("lock during upload: sent %v phase %v", sentRequestIDs(cmd), m.backups.imp.phase)
	}

	m, commit := importToCommit(t)
	m, _ = update(t, m, LockIdentityResultMsg{Success: true})
	if m.backups.imp.unresolved == nil || m.backups.imp.unresolved.commitID != commit {
		t.Fatalf("lock while checking: unresolved %+v, want the commit kept for its reply", m.backups.imp.unresolved)
	}
	m, _ = update(t, m, commitReply(commit, true, "", ""))
	if m.backups.imp.unresolved != nil || !strings.Contains(m.backups.status, "Imported lab.tar.gz") {
		t.Fatalf("reply after lock: unresolved %+v status %q", m.backups.imp.unresolved, m.backups.status)
	}
}

func TestBackupViewHeaderShowsSealedTimeAndWarnsOnMismatch(t *testing.T) {
	name := "aplane-backup-20261102-070725.tar.gz"
	m := backupsModel(BackupInfo{FileName: name, Path: name, Size: 13861, Checksum: "abcd"})
	m.restore.archivePath = name
	m.restore.archiveCreatedAt = time.Date(2026, 11, 2, 7, 7, 25, 0, time.UTC).Unix()
	header := stripANSI(m.renderBackupViewHeader(110))
	if !strings.Contains(header, "(sealed in the backup)") || !strings.Contains(header, "SHA-256 abcd") || strings.Contains(header, "renamed") {
		t.Fatalf("header:\n%s", header)
	}
	m.restore.archiveCreatedAt = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
	if header := stripANSI(m.renderBackupViewHeader(110)); !strings.Contains(header, "renamed") {
		t.Fatalf("no mismatch warning:\n%s", header)
	}
}
