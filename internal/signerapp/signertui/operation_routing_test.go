// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/aplane-algo/aplane/internal/protocol"
)

// startedCosignerOperation is a cosigner import, removal or export just
// started from its own screen.
type startedCosignerOperation struct {
	name     string
	progress ViewState
	back     ViewState
	prefix   string
	start    func(t *testing.T) (Model, tea.Cmd)
	errText  func(Model) string
}

func cosignerOperations() []startedCosignerOperation {
	return []startedCosignerOperation{
		{
			name: "import", progress: ViewCosignerImporting, back: ViewCosignerImportReview, prefix: "cosigner-import",
			start: func(t *testing.T) (Model, tea.Cmd) {
				m := Model{viewState: ViewCosignerImportReview, connectionState: ConnectionConnected,
					cosigner: cosignerState{importName: "west", envelopeJSON: "{}"}}
				next, cmd := m.handleCosignerImportReviewKeys(tea.KeyMsg{Type: tea.KeyEnter})
				return next.(Model), cmd
			},
			errText: func(m Model) string { return m.cosigner.importError },
		},
		{
			name: "remove", progress: ViewCosignerRemoving, back: ViewCosignerRemoveConfirm, prefix: "cosigner-remove",
			start: func(t *testing.T) (Model, tea.Cmd) {
				m := Model{viewState: ViewCosignerRemoveConfirm, connectionState: ConnectionConnected,
					cosigner: cosignerState{references: testCosignerReferences(), managerSelected: 2}}
				next, cmd := m.handleCosignerRemoveConfirmKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'y'}})
				return next.(Model), cmd
			},
			errText: func(m Model) string { return m.cosigner.importError },
		},
		{
			name: "export", progress: ViewCosignerExporting, back: ViewCosignerExportPath, prefix: "cosigner-export",
			start: func(t *testing.T) (Model, tea.Cmd) {
				m := Model{viewState: ViewCosignerExportPath, connectionState: ConnectionConnected,
					cosigner: cosignerState{exportWitnessID: testWitnessID1}}
				m.cosigner.exportFocus = m.cosignerExportJSONButtonFocus()
				next, cmd := m.handleCosignerExportPathKeys(tea.KeyMsg{Type: tea.KeyEnter})
				return next.(Model), cmd
			},
			errText: func(m Model) string { return m.cosigner.exportError },
		},
	}
}

// An error ends a cosigner operation only when it names the operation's
// request. One for anything else, such as a background refresh, leaves the
// progress screen waiting for the operation's own result.
func TestCosignerOperationsFailOnlyOnTheirOwnRequest(t *testing.T) {
	for _, op := range cosignerOperations() {
		t.Run(op.name, func(t *testing.T) {
			m, cmd := op.start(t)
			if m.viewState != op.progress {
				t.Fatalf("started on view %v, want %v", m.viewState, op.progress)
			}
			for _, unrelated := range []ErrorMsg{{Error: errors.New("list failed")}, {ID: "list-keys-1", Error: errors.New("list failed")}} {
				next, _ := m.Update(unrelated)
				if got := next.(Model); got.viewState != op.progress || op.errText(got) != "" {
					t.Fatalf("unrelated error %+v ended the %s: view %v error %q", unrelated, op.name, got.viewState, op.errText(got))
				}
			}
			id := sentRequest(cmd, op.prefix)
			if id == "" {
				t.Fatalf("the %s request carries no ID of its own: sent %v", op.name, sentRequestIDs(cmd))
			}
			next, _ := m.Update(ErrorMsg{ID: id, Error: errors.New("authorization denied")})
			if got := next.(Model); got.viewState != op.back || op.errText(got) != "authorization denied" {
				t.Fatalf("its own error: view %v error %q, want %v with the error", got.viewState, op.errText(got), op.back)
			}
		})
	}
}

// A cosigner reply that arrives after a lock moved the TUI to the unlock
// screen is not shown over it.
func TestLateCosignerReplyAfterLockKeepsTheUnlockScreen(t *testing.T) {
	replies := map[string]func(base protocol.BaseMessage) any{
		"import": func(base protocol.BaseMessage) any {
			base.Type = protocol.MsgTypeImportCosignerReferenceResult
			return protocol.ImportCosignerReferenceResultMessage{BaseMessage: base, Success: true,
				Reference: protocol.CosignerReferenceInfo{Name: "west", ComponentKey: testWitnessKeyID}}
		},
		"remove": func(base protocol.BaseMessage) any {
			base.Type = protocol.MsgTypeRemoveCosignerReferenceResult
			return protocol.RemoveCosignerReferenceResultMessage{BaseMessage: base, Success: true, Name: "west", Removed: true}
		},
		"export": func(base protocol.BaseMessage) any {
			base.Type = protocol.MsgTypeExportCosignerPublicResult
			return protocol.ExportCosignerPublicResultMessage{BaseMessage: base, Success: true, WitnessKeyID: testWitnessID1, EnvelopeJSON: "{}"}
		},
	}
	for _, op := range cosignerOperations() {
		t.Run(op.name, func(t *testing.T) {
			m, cmd := op.start(t)
			id := sentRequest(cmd, op.prefix)
			m = updateModel(t, m, SignerStatusMsg{State: "locked"})
			if m.viewState != ViewUnlock {
				t.Fatalf("lock: view %v", m.viewState)
			}
			reply := decodeSignerReply(t, replies[op.name](protocol.BaseMessage{ID: id}))
			m = updateModel(t, m, reply)
			if m.viewState != ViewUnlock {
				t.Fatalf("late %s reply %T moved the unlock screen to view %v", op.name, reply, m.viewState)
			}
		})
	}
}

// decodeSignerReply passes msg through the TUI's decoder for its type, as the
// listener would deliver it.
func decodeSignerReply(t *testing.T, msg any) tea.Msg {
	t.Helper()
	raw, err := protocol.MarshalAdminMessage(msg)
	if err != nil {
		t.Fatalf("MarshalAdminMessage: %v", err)
	}
	var base protocol.BaseMessage
	if err := json.Unmarshal(raw, &base); err != nil {
		t.Fatalf("read the message type: %v", err)
	}
	decode, ok := signerMessageDecoders[base.Type]
	if !ok {
		t.Fatalf("no decoder for %s", base.Type)
	}
	decoded, err := decode(raw)
	if err != nil {
		t.Fatalf("decode %s: %v", base.Type, err)
	}
	return decoded
}

// An error ends the restore flow's wait only when it names the restore's own
// request. One for anything else must neither zero the passphrase the
// preview step still needs nor move the operator off the progress screen.
func TestRestoreFailuresNameTheirOwnRequest(t *testing.T) {
	m := Model{viewState: ViewRestorePreview, connectionState: ConnectionConnected, signerState: signerRuntimeUnlocked, restore: restoreState{
		archivePath: "aplane-backup.tar.gz", passphrase: []byte("export passphrase"),
		previewKeys: []RestoreKeyInfo{{Address: "ADDR", KeyType: "ed25519"}}, selected: map[string]bool{"ADDR": true},
		previewFocus: restoreFocusAction,
	}}
	unrelated := []ErrorMsg{{Error: errors.New("list failed")}, {ID: "list-keys-1", Error: errors.New("list failed")}}
	for _, msg := range unrelated {
		next, _ := m.Update(msg)
		if got := next.(Model); string(got.restore.passphrase) != "export passphrase" || got.viewState != ViewRestorePreview {
			t.Fatalf("unrelated error %+v on the preview: view %v passphrase %q", msg, got.viewState, got.restore.passphrase)
		}
	}

	next, cmd := m.handleRestorePreviewKeys(tea.KeyMsg{Type: tea.KeyEnter})
	restoring := next.(Model)
	id := sentRequest(cmd, "restore-backup")
	if restoring.viewState != ViewRestoring || id == "" {
		t.Fatalf("restore: view %v sent %v, want the progress screen and a restore request", restoring.viewState, sentRequestIDs(cmd))
	}
	for _, msg := range unrelated {
		next, _ := restoring.Update(msg)
		if got := next.(Model); got.viewState != ViewRestoring {
			t.Fatalf("unrelated error %+v ended the restore: view %v", msg, got.viewState)
		}
	}
	next, _ = restoring.Update(ErrorMsg{ID: id, Error: errors.New("authorization denied")})
	if got := next.(Model); got.viewState != ViewBackups || !strings.Contains(got.lastError, "authorization denied") {
		t.Fatalf("its own error: view %v lastError %q, want the Backups page with the error", got.viewState, got.lastError)
	}
}

// An import for a key type without parameters waits on the import progress
// screen like every other operation: Enter cannot send it a second time, and
// its failure, untyped or typed, returns to the import form it came from.
func TestPlainImportRunsAsAnOperation(t *testing.T) {
	setServerKeyTypes([]protocol.KeyTypeInfo{{KeyType: "ed25519", DisplayName: "Ed25519", MnemonicImport: true, MnemonicWordCount: 25}})
	t.Cleanup(func() { setServerKeyTypes(nil) })
	words := make([]string, 25)
	for i := range words {
		words[i] = fmt.Sprintf("w%02d", i)
	}
	input := newImportMnemonicInput()
	input.SetValue(strings.Join(words, " "))
	m := Model{viewState: ViewImportForm, connectionState: ConnectionConnected, forms: formsState{importFocus: 2, importMnemonicInput: input}}
	next, cmd := m.handleImportFormKeys(tea.KeyMsg{Type: tea.KeyEnter})
	importing := next.(Model)
	id := sentRequest(cmd, "imp")
	if importing.viewState != ViewImporting || id == "" || id != importing.operation.id {
		t.Fatalf("import: view %v sent %v error %q, want the progress screen and the operation's request", importing.viewState, sentRequestIDs(cmd), importing.forms.importError)
	}
	again, cmd := importing.handleKeyPress(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd != nil || again.(Model).viewState != ViewImporting {
		t.Fatalf("a second Enter: view %v cmd %v, want nothing sent", again.(Model).viewState, cmd != nil)
	}

	next, _ = importing.Update(ErrorMsg{ID: id, Error: errors.New("authorization denied")})
	if got := next.(Model); got.viewState != ViewImportForm || got.forms.importError != "authorization denied" {
		t.Fatalf("untyped failure: view %v error %q, want the import form", got.viewState, got.forms.importError)
	}
	next, _ = importing.Update(ImportResultMsg{ID: id, Error: "invalid recovery phrase"})
	if got := next.(Model); got.viewState != ViewImportForm || got.forms.importError != "invalid recovery phrase" {
		t.Fatalf("typed failure: view %v error %q, want the import form", got.viewState, got.forms.importError)
	}
}

// An operation's result changes the screen only while its progress screen
// still waits on it. A result arriving after a lock showed the unlock screen
// leaves that screen in place; the operation's own result, decoded from the
// wire with its request ID, still ends the wait.
func TestOperationResultsApplyOnlyToTheirOwnProgressScreen(t *testing.T) {
	for _, op := range []struct {
		name     string
		start    ViewState
		progress ViewState
		done     ViewState
		reply    func(base protocol.BaseMessage) any
	}{
		{"generate", ViewGenerateForm, ViewGenerating, ViewGenerateDisplay, func(base protocol.BaseMessage) any {
			base.Type = protocol.MsgTypeGenerateResult
			return protocol.GenerateResultMessage{BaseMessage: base, Success: true, Address: "ADDR", KeyType: "ed25519"}
		}},
		{"import", ViewImportForm, ViewImporting, ViewImportDisplay, func(base protocol.BaseMessage) any {
			base.Type = protocol.MsgTypeImportResult
			return protocol.ImportResultMessage{BaseMessage: base, Success: true, Address: "ADDR", KeyType: "ed25519"}
		}},
		{"delete", ViewDeleteConfirm, ViewDeleting, ViewKeyList, func(base protocol.BaseMessage) any {
			base.Type = protocol.MsgTypeDeleteResult
			return protocol.DeleteResultMessage{BaseMessage: base, Success: true}
		}},
		{"backup", ViewBackupConfirm, ViewBackingUp, ViewBackupDisplay, func(base protocol.BaseMessage) any {
			base.Type = protocol.MsgTypeBackupResult
			return protocol.BackupResultMessage{BaseMessage: base, Success: true, ArchivePath: "aplane-backup.tar.gz"}
		}},
		{"key type install", ViewTemplateInstallConfirm, ViewTemplateInstalling, ViewTemplateLibrary, func(base protocol.BaseMessage) any {
			base.Type = protocol.MsgTypeInstallLibraryTemplateResult
			return protocol.InstallLibraryTemplateResultMessage{BaseMessage: base, Success: true, KeyType: "test.timed-policy.v1"}
		}},
		{"key type enable", ViewTemplateInstallConfirm, ViewTemplateInstalling, ViewTemplateLibrary, func(base protocol.BaseMessage) any {
			base.Type = protocol.MsgTypeActivateKeyTypeResult
			return protocol.ActivateKeyTypeResultMessage{BaseMessage: base, Success: true, KeyType: "aplane.ed25519.v1"}
		}},
		{"key type disable", ViewTemplateInstallConfirm, ViewTemplateInstalling, ViewTemplateLibrary, func(base protocol.BaseMessage) any {
			base.Type = protocol.MsgTypeDeactivateKeyTypeResult
			return protocol.DeactivateKeyTypeResultMessage{BaseMessage: base, Success: true, KeyType: "aplane.ed25519.v1", Removed: true}
		}},
	} {
		t.Run(op.name, func(t *testing.T) {
			m := Model{viewState: op.start, connectionState: ConnectionConnected, signerState: signerRuntimeUnlocked,
				forms: formsState{importMnemonicInput: newImportMnemonicInput()}}
			id := m.beginOperation(op.progress)
			base := protocol.BaseMessage{ID: id}

			locked := updateModel(t, m, SignerStatusMsg{State: "locked"})
			if late := updateModel(t, locked, decodeSignerReply(t, op.reply(base))); late.viewState != ViewUnlock {
				t.Fatalf("late %s result after a lock moved the unlock screen to view %v", op.name, late.viewState)
			}

			other := base
			other.ID = id + "-other"
			if stray := updateModel(t, m, decodeSignerReply(t, op.reply(other))); stray.viewState != op.progress {
				t.Fatalf("a result for another request moved the %s progress screen to view %v", op.name, stray.viewState)
			}

			own := updateModel(t, m, decodeSignerReply(t, op.reply(base)))
			if own.viewState != op.done || own.operation != (pendingOperation{}) {
				t.Fatalf("its own result: view %v operation %+v, want view %v and the wait ended", own.viewState, own.operation, op.done)
			}
		})
	}
}

// A preview reply is applied only while the passphrase screen still waits on
// that preview. One arriving after a lock showed the unlock screen, where
// previewing is still set, leaves that screen in place, and so does a reply
// that names another request.
func TestRestorePreviewReplyAppliesOnlyToItsOwnRequest(t *testing.T) {
	m := Model{viewState: ViewRestorePassphrase, connectionState: ConnectionConnected, signerState: signerRuntimeUnlocked,
		restore: restoreState{archivePath: "aplane-backup.tar.gz", passphrase: []byte("export passphrase")}}
	next, cmd := m.handleRestorePassphraseKeys(tea.KeyMsg{Type: tea.KeyEnter})
	previewing := next.(Model)
	id := sentRequest(cmd, "preview-restore")
	if !previewing.restore.previewing || id == "" {
		t.Fatalf("preview: previewing %v sent %v", previewing.restore.previewing, sentRequestIDs(cmd))
	}
	reply := func(id string) tea.Msg {
		return decodeSignerReply(t, protocol.RestorePreviewMessage{
			BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeRestorePreview, ID: id}, ArchivePath: "aplane-backup.tar.gz",
			Keys: []protocol.RestoreKeyInfo{{Address: "ADDR", KeyType: "ed25519"}},
		})
	}

	locked := updateModel(t, previewing, SignerStatusMsg{State: "locked"})
	if late := updateModel(t, locked, reply(id)); late.viewState != ViewUnlock {
		t.Fatalf("late preview after a lock moved the unlock screen to view %v", late.viewState)
	}
	if stray := updateModel(t, previewing, reply("preview-restore-other")); stray.viewState != ViewRestorePassphrase || !stray.restore.previewing {
		t.Fatalf("a preview for another request: view %v previewing %v", stray.viewState, stray.restore.previewing)
	}
	if own := updateModel(t, previewing, reply(id)); own.viewState != ViewRestorePreview || own.restore.previewing {
		t.Fatalf("its own preview: view %v previewing %v, want the preview shown", own.viewState, own.restore.previewing)
	}
}
