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

// findMsg runs cmd and returns the first message it produces that match
// accepts, looking inside batches.
func findMsg(cmd tea.Cmd, match func(tea.Msg) bool) tea.Msg {
	if cmd == nil {
		return nil
	}
	msg := cmd()
	if batch, ok := msg.(tea.BatchMsg); ok {
		for _, c := range batch {
			if found := findMsg(c, match); found != nil {
				return found
			}
		}
		return nil
	}
	if msg != nil && match(msg) {
		return msg
	}
	return nil
}

func isMsg[T any](msg tea.Msg) bool { _, ok := msg.(T); return ok }

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
	m, cmd = update(t, m, BackupChunkMsg{Chunk: protocol.BackupChunkMessage{BaseMessage: protocol.BaseMessage{ID: next}, Success: true, Offset: int64(half), Data: payload[half:], EOF: true}})
	m = finishExport(t, m, cmd)
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
	m, cmd = update(t, m, BackupChunkMsg{Chunk: protocol.BackupChunkMessage{BaseMessage: protocol.BaseMessage{ID: id}, Success: true, Data: tampered, EOF: true}})
	m = finishExport(t, m, cmd)
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

// finishExport runs the off-loop verification and publication the last chunk
// started and delivers its result.
func finishExport(t *testing.T, m Model, cmd tea.Cmd) Model {
	t.Helper()
	if m.backups.export.finishing == nil {
		t.Fatal("the last chunk did not start finishing the export")
	}
	done := findMsg(cmd, isMsg[backupExportFinishedMsg])
	if done == nil {
		t.Fatal("no finish result")
	}
	m, _ = update(t, m, done)
	return m
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
	// Commands are run to completion to see what they send; the commit's
	// timer must not hold a test for half an hour.
	saved := backupCommitWait
	backupCommitWait = time.Millisecond
	t.Cleanup(func() { backupCommitWait = saved })
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

// startImport presses enter on the import form and delivers the off-loop
// archive check, returning the begin request's ID.
func startImport(t *testing.T, m Model) (Model, string) {
	t.Helper()
	m, cmd := pressKey(t, m, "enter")
	if m.backups.imp.phase != importPreparing {
		t.Fatalf("enter: phase %v, want preparing", m.backups.imp.phase)
	}
	prepared := findMsg(cmd, isMsg[backupImportPreparedMsg])
	if prepared == nil {
		t.Fatal("enter did not start the archive check")
	}
	m, cmd = update(t, m, prepared)
	begin := sentRequest(cmd, "backup-import-begin")
	if begin == "" {
		t.Fatalf("the checked archive did not begin an upload: %v", sentRequestIDs(cmd))
	}
	return m, begin
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
	m, begin := startImport(t, m)
	m, cmd := update(t, m, beginReply(begin, "upload-1"))
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
	m, begin := startImport(t, m)
	m, _ = pressKey(t, m, "esc")
	if m.viewState != ViewBackups || m.backups.imp.phase != importIdle {
		t.Fatalf("esc: view %v phase %v", m.viewState, m.backups.imp.phase)
	}
	m, cmd := update(t, m, beginReply(begin, "upload-late"))
	if sentRequest(cmd, "backup-import-abort") == "" {
		t.Fatalf("the late begin reply was not aborted: %v", sentRequestIDs(cmd))
	}
	if m.viewState != ViewBackups || m.backups.imp.phase != importIdle || len(m.backups.imp.canceledBegins) != 0 {
		t.Fatalf("late begin reopened the import: view %v phase %v", m.viewState, m.backups.imp.phase)
	}
}

func TestBackupImportEscDuringUploadAborts(t *testing.T) {
	m, _, _ := importFixture(t)
	m, begin := startImport(t, m)
	m, _ = update(t, m, beginReply(begin, "upload-1"))
	m, cmd := pressKey(t, m, "esc")
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
			if m.viewState != ViewBackups || len(m.backups.imp.unresolved) != 1 || m.backups.imp.unresolved[0].commitID != commit {
				t.Fatalf("esc while checking: view %v unresolved %+v", m.viewState, m.backups.imp.unresolved)
			}
			if banner := stripANSI(m.View()); !strings.Contains(banner, "outcome unknown") {
				t.Fatalf("no unresolved banner:\n%s", banner)
			}
			m.viewState = ViewKeyList
			m, _ = update(t, m, commitReply(commit, tc.ok, tc.warning, tc.errText))
			if m.viewState != ViewKeyList || len(m.backups.imp.unresolved) != 0 {
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
	if len(m.backups.imp.unresolved) != 1 || m.backups.imp.unresolved[0].commitID != "" || m.backups.imp.phase != importIdle {
		t.Fatalf("disconnect while checking: unresolved %+v phase %v", m.backups.imp.unresolved, m.backups.imp.phase)
	}
	pending := m.backups.imp.unresolved[0]
	// No reply can come on a lost connection; a stray one is not trusted.
	m, _ = update(t, m, commitReply(commit, false, "", "x"))
	if len(m.backups.imp.unresolved) != 1 {
		t.Fatal("a reply for the lost connection's commit settled the import")
	}

	m.viewState = ViewBackups
	// Validation can still be running: absence keeps the outcome unknown.
	m, _ = update(t, m, BackupsListMsg{Backups: []BackupInfo{{FileName: "other.tar.gz"}}})
	if len(m.backups.imp.unresolved) != 1 || m.backups.statusErr {
		t.Fatalf("an absent import was settled: status %q", m.backups.status)
	}
	// The archive appears on a later check.
	m, _ = update(t, m, BackupsListMsg{Backups: []BackupInfo{{FileName: "lab.tar.gz", Checksum: pending.checksum, Size: pending.size}}})
	if len(m.backups.imp.unresolved) != 0 || !strings.Contains(m.backups.status, "Imported lab.tar.gz") {
		t.Fatalf("listed import: unresolved %+v status %q", m.backups.imp.unresolved, m.backups.status)
	}
}

func TestBackupImportListedWithAnotherChecksumIsANameConflict(t *testing.T) {
	m, _ := importToCommit(t)
	m, _ = update(t, m, DisconnectedMsg{})
	m, _ = update(t, m, BackupsListMsg{Backups: []BackupInfo{{FileName: "lab.tar.gz", Checksum: "other", Size: 1}}})
	if len(m.backups.imp.unresolved) != 0 || !m.backups.statusErr || !strings.Contains(m.backups.status, "different backup named lab.tar.gz") {
		t.Fatalf("name conflict: unresolved %+v status %q", m.backups.imp.unresolved, m.backups.status)
	}
}

func TestBackupImportLockAbortsUploadOrLeavesCommitUnresolved(t *testing.T) {
	m, _, _ := importFixture(t)
	m, begin := startImport(t, m)
	m, _ = update(t, m, beginReply(begin, "upload-1"))
	m, cmd := update(t, m, LockIdentityResultMsg{Success: true})
	if sentRequest(cmd, "backup-import-abort") == "" || m.backups.imp.phase != importIdle {
		t.Fatalf("lock during upload: sent %v phase %v", sentRequestIDs(cmd), m.backups.imp.phase)
	}

	m, commit := importToCommit(t)
	m, _ = update(t, m, LockIdentityResultMsg{Success: true})
	if len(m.backups.imp.unresolved) != 1 || m.backups.imp.unresolved[0].commitID != commit {
		t.Fatalf("lock while checking: unresolved %+v, want the commit kept for its reply", m.backups.imp.unresolved)
	}
	m, _ = update(t, m, commitReply(commit, true, "", ""))
	if len(m.backups.imp.unresolved) != 0 || !strings.Contains(m.backups.status, "Imported lab.tar.gz") {
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

// --- regressions from review ---

func TestBackupImportPassphraseIsZeroedWhenTheSessionEnds(t *testing.T) {
	for name, end := range map[string]tea.Msg{
		"lock":       LockIdentityResultMsg{Success: true},
		"disconnect": DisconnectedMsg{},
	} {
		t.Run(name, func(t *testing.T) {
			m, _, _ := importFixture(t)
			secret := m.backups.imp.passphrase
			m, _ = update(t, m, end)
			if m.backups.imp.passphrase != nil || string(secret) != "\x00\x00\x00\x00\x00\x00" {
				t.Fatalf("passphrase after %s: kept %q, buffer %q", name, m.backups.imp.passphrase, secret)
			}
		})
	}
}

func TestBackupImportCommitTimeoutLeavesTheOutcomeUnresolved(t *testing.T) {
	m, commit := importToCommit(t)
	m, _ = update(t, m, backupCommitTimeoutMsg{id: "another"})
	if m.backups.imp.phase != importCommitting {
		t.Fatal("a timeout for another commit stopped this one")
	}
	m, _ = update(t, m, backupCommitTimeoutMsg{id: commit})
	if m.viewState != ViewBackups || m.backups.imp.phase != importIdle ||
		len(m.backups.imp.unresolved) != 1 || m.backups.imp.unresolved[0].commitID != commit {
		t.Fatalf("timeout: view %v phase %v unresolved %+v", m.viewState, m.backups.imp.phase, m.backups.imp.unresolved)
	}
	m, _ = update(t, m, commitReply(commit, true, "", ""))
	if len(m.backups.imp.unresolved) != 0 || !strings.Contains(m.backups.status, "Imported lab.tar.gz") {
		t.Fatalf("late reply after timeout: unresolved %+v status %q", m.backups.imp.unresolved, m.backups.status)
	}
}

func TestBackupImportKeepsEveryUnresolvedImport(t *testing.T) {
	// Import A is left unresolved by a lost connection.
	m, _ := importToCommit(t)
	m, _ = update(t, m, DisconnectedMsg{})
	a := m.backups.imp.unresolved[0]
	// Import B is left by esc while the signer checks it.
	m.viewState = ViewBackups
	m, _ = pressKey(t, m, "i")
	other := filepath.Join(t.TempDir(), "other.tar.gz")
	if err := os.WriteFile(other, []byte("other archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	m.backups.imp.path, m.backups.imp.passphrase, m.backups.imp.focus = other, []byte("secret"), importFocusButton
	m, begin := startImport(t, m)
	m, cmd := update(t, m, beginReply(begin, "upload-2"))
	m, cmd = update(t, m, appendReply(sentRequest(cmd, "backup-import-append"), int64(len("other archive"))))
	commitB := sentRequest(cmd, "backup-import-commit")
	m, _ = pressKey(t, m, "esc")
	if len(m.backups.imp.unresolved) != 2 {
		t.Fatalf("unresolved = %+v, want both imports", m.backups.imp.unresolved)
	}
	if banner := stripANSI(m.View()); !strings.Contains(banner, "lab.tar.gz") || !strings.Contains(banner, "other.tar.gz") {
		t.Fatalf("banner does not name both imports:\n%s", banner)
	}
	// B's reply settles B only; A settles when it is listed.
	m, _ = update(t, m, commitReply(commitB, true, "", ""))
	if len(m.backups.imp.unresolved) != 1 || m.backups.imp.unresolved[0].name != "lab.tar.gz" {
		t.Fatalf("after B's reply: %+v", m.backups.imp.unresolved)
	}
	m, _ = update(t, m, BackupsListMsg{Backups: []BackupInfo{{FileName: "lab.tar.gz", Checksum: a.checksum, Size: a.size}}})
	if len(m.backups.imp.unresolved) != 0 || !strings.Contains(m.backups.status, "Imported lab.tar.gz") {
		t.Fatalf("after listing A: unresolved %+v status %q", m.backups.imp.unresolved, m.backups.status)
	}
}

func TestBackupImportCheckRunsOffTheEventLoopAndCanBeCanceled(t *testing.T) {
	m, _, _ := importFixture(t)
	m, cmd := pressKey(t, m, "enter")
	if m.backups.imp.phase != importPreparing || sentRequest(cmd, "backup-import-begin") != "" {
		t.Fatalf("enter: phase %v; the archive must be checked before any request", m.backups.imp.phase)
	}
	prepared := findMsg(cmd, isMsg[backupImportPreparedMsg])
	m, _ = pressKey(t, m, "esc")
	if m.viewState != ViewBackups || m.backups.imp.phase != importIdle {
		t.Fatalf("esc while checking: view %v phase %v", m.viewState, m.backups.imp.phase)
	}
	m, cmd = update(t, m, prepared)
	if sentRequest(cmd, "backup-import-begin") != "" || m.backups.imp.phase != importIdle {
		t.Fatal("a canceled check's result started an upload")
	}
}

func TestBackupExportFinishRunsOffTheEventLoopAndReportsAfterLeaving(t *testing.T) {
	m, payload, dest := exportFixture(t)
	m, cmd := pressKey(t, m, "enter")
	id := sentRequest(cmd, "backup-export-chunk")
	m, cmd = update(t, m, BackupChunkMsg{Chunk: protocol.BackupChunkMessage{BaseMessage: protocol.BaseMessage{ID: id}, Success: true, Data: payload, EOF: true}})
	if m.backups.export.finishing == nil || m.backups.export.writer != nil {
		t.Fatal("the last chunk did not hand the export to the off-loop finish")
	}
	done := findMsg(cmd, isMsg[backupExportFinishedMsg])
	m, _ = pressKey(t, m, "esc")
	if m.viewState != ViewBackups {
		t.Fatalf("esc while finishing: view %v", m.viewState)
	}
	m.viewState = ViewKeyList
	m, _ = update(t, m, done)
	if m.viewState != ViewKeyList || !strings.Contains(m.backups.status, "Exported to "+dest) || m.backups.export.finishing != nil {
		t.Fatalf("finished after leaving: view %v status %q", m.viewState, m.backups.status)
	}
}

func TestBackupDeleteReplyAfterLockKeepsTheUnlockScreen(t *testing.T) {
	m := backupsModel(BackupInfo{FileName: "a.tar.gz", Path: "a.tar.gz"}, BackupInfo{FileName: "b.tar.gz", Path: "b.tar.gz"})
	m, _ = pressKey(t, m, "d")
	m, cmd := pressKey(t, m, "y")
	id := sentRequest(cmd, "backup-delete")
	m, _ = update(t, m, LockIdentityResultMsg{Success: true})
	if m.viewState != ViewUnlock {
		t.Fatalf("lock: view %v", m.viewState)
	}
	m, _ = update(t, m, BackupDeleteResultMsg{Result: protocol.DeleteBackupResultMessage{BaseMessage: protocol.BaseMessage{ID: id}, Success: true}})
	if m.viewState != ViewUnlock || !strings.Contains(m.backups.status, "Deleted a.tar.gz") {
		t.Fatalf("late delete reply: view %v status %q, want the unlock screen kept", m.viewState, m.backups.status)
	}
}

func TestShutdownRemovesExportStagingAndReleasesImport(t *testing.T) {
	m, _, dest := exportFixture(t)
	m, _ = pressKey(t, m, "enter")
	if entries, _ := os.ReadDir(dest); len(entries) != 1 {
		t.Fatalf("expected one staging file, found %d", len(entries))
	}
	m.Shutdown()
	assertNoExportStaging(t, dest)

	im, _, _ := importFixture(t)
	im, _ = startImport(t, im)
	secret := im.backups.imp.passphrase
	file := im.backups.imp.file
	im.Shutdown()
	if string(secret) != "\x00\x00\x00\x00\x00\x00" {
		t.Fatalf("Shutdown left the passphrase: %q", secret)
	}
	if _, err := file.Stat(); err == nil {
		t.Fatal("Shutdown left the archive file open")
	}
}

func TestBackupUndoRepliesAfterLockKeepTheUnlockScreen(t *testing.T) {
	m := backupsModel()
	m, _ = pressKey(t, m, "u", "y")
	m, _ = update(t, m, LockIdentityResultMsg{Success: true})
	if m.viewState != ViewUnlock {
		t.Fatalf("lock: view %v", m.viewState)
	}
	m, _ = update(t, m, RollbackRestoreResultMsg{Result: protocol.RollbackRestoreResultMessage{Success: true}})
	if m.viewState != ViewUnlock || m.backups.undoPending || !strings.Contains(m.backups.status, "latest restore was undone") {
		t.Fatalf("late undo success: view %v pending %v status %q", m.viewState, m.backups.undoPending, m.backups.status)
	}
	if strings.Contains(m.restore.recoveryError, "reconciling") {
		t.Fatal("a late undo success started a reconcile")
	}

	// A reconcile already sent before the lock does not unlock the screen
	// either way when its reply arrives.
	for _, result := range []protocol.ReconcileStoreResultMessage{{Success: true, KeyCount: 3}, {Error: "store damaged"}} {
		got, _ := update(t, m, ReconcileStoreResultMsg{Result: result})
		if got.viewState != ViewUnlock || got.signerState != signerRuntimeLocked {
			t.Fatalf("late reconcile %+v: view %v state %v, want the unlock screen and locked state kept", result, got.viewState, got.signerState)
		}
	}
}

func TestBackupUndoSuccessStillReconcilesWhileWaiting(t *testing.T) {
	m := backupsModel()
	m, _ = pressKey(t, m, "u", "y")
	m, _ = update(t, m, RollbackRestoreResultMsg{Result: protocol.RollbackRestoreResultMessage{Success: true}})
	if m.viewState != ViewStoreRecovery || !strings.Contains(m.restore.recoveryError, "reconciling") {
		t.Fatalf("undo success: view %v recovery %q, want the reconcile started", m.viewState, m.restore.recoveryError)
	}
	m, _ = update(t, m, ReconcileStoreResultMsg{Result: protocol.ReconcileStoreResultMessage{Success: true, KeyCount: 2}})
	if m.viewState != ViewKeyList {
		t.Fatalf("reconciled: view %v, want the key list", m.viewState)
	}
}

func TestReconcileFailureAfterLeavingRecoveryStillBlocks(t *testing.T) {
	m := backupsModel()
	m, _ = pressKey(t, m, "u", "y")
	m, _ = update(t, m, RollbackRestoreResultMsg{Result: protocol.RollbackRestoreResultMessage{Success: true}})
	if m.viewState != ViewStoreRecovery {
		t.Fatalf("undo success: view %v", m.viewState)
	}
	// The signer is unlocked, so the recovery screen is not blocking: the
	// operator leaves it while the reconcile runs.
	m, _ = pressKey(t, m, "esc")
	if m.viewState == ViewStoreRecovery {
		t.Fatal("esc did not leave the non-blocking recovery screen")
	}
	left := m.viewState

	failed, _ := update(t, m, ReconcileStoreResultMsg{Result: protocol.ReconcileStoreResultMessage{Error: "store damaged"}})
	if failed.signerState != signerRuntimeRecovery || failed.viewState != ViewStoreRecovery {
		t.Fatalf("reconcile failure after leaving: state %v view %v, want recovery shown", failed.signerState, failed.viewState)
	}
	ok, _ := update(t, m, ReconcileStoreResultMsg{Result: protocol.ReconcileStoreResultMessage{Success: true, KeyCount: 4}})
	if ok.viewState != left || ok.keyCount != 4 {
		t.Fatalf("reconcile success after leaving: view %v keys %d, want the operator's screen kept", ok.viewState, ok.keyCount)
	}
}

func TestReconcileSuccessAfterLeavingRecoveryUnlocksInPlace(t *testing.T) {
	m := backupsModel(BackupInfo{FileName: "a.tar.gz", Path: "a.tar.gz"})
	m.signerState, m.signerStatusKnown = signerRuntimeRecovery, true
	m.viewState = ViewStoreRecovery
	// From the recovery screen the operator opens Backups before the
	// reconcile's reply arrives.
	m, _ = pressKey(t, m, "b")
	if m.viewState != ViewBackups || !m.restore.returnToRecovery {
		t.Fatalf("b: view %v returnToRecovery %v", m.viewState, m.restore.returnToRecovery)
	}
	m.restore.backupsLoaded, m.restore.backups = true, []BackupInfo{{FileName: "a.tar.gz", Path: "a.tar.gz"}}
	m, cmd := update(t, m, ReconcileStoreResultMsg{Result: protocol.ReconcileStoreResultMessage{Success: true, KeyCount: 5}})
	if m.signerState != signerRuntimeUnlocked || m.viewState != ViewBackups || m.keyCount != 5 || m.restore.returnToRecovery {
		t.Fatalf("reconcile success: state %v view %v keys %d returnToRecovery %v, want unlocked on the same screen",
			m.signerState, m.viewState, m.keyCount, m.restore.returnToRecovery)
	}
	if footer := m.viewFooterText(); !strings.Contains(footer, "n: New") || !strings.Contains(footer, "d: Delete") {
		t.Fatalf("create and delete still hidden: %q", footer)
	}
	_, unlockCmd := approvalTestModel(ViewUnlock).Update(UnlockResultMsg{Success: true, KeyCount: 1})
	if want, got := batchSize(t, unlockCmd), batchSize(t, cmd); got != want {
		t.Fatalf("in-place unlock issues %d commands, unlock issues %d", got, want)
	}
	if got, _ := pressKey(t, m, "esc"); got.viewState != ViewKeyList {
		t.Fatalf("esc from Backups after unlocking: view %v, want the key list", got.viewState)
	}
}
