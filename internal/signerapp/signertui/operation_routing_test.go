// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"encoding/json"
	"errors"
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
