// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"errors"
	"os"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/aplane-algo/aplane/internal/boundary"
	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/protocol"
)

// lockedDuring locks m, as the signer reports a lock while an operation runs.
func lockedDuring(t *testing.T, m Model) Model {
	t.Helper()
	m = updateModel(t, m, fromListener(SignerStatusMsg{State: "locked"}))
	if m.viewState != ViewUnlock {
		t.Fatalf("lock: view %v", m.viewState)
	}
	return m
}

func unlocked(t *testing.T, m Model) Model {
	t.Helper()
	return updateModel(t, m, fromListener(UnlockResultMsg{Success: true, KeyCount: 1}))
}

// A bounded account generated while the signer locked still exists. Its
// result is not shown over the unlock screen but held, and shown once the
// operator unlocks, so its receipt can still be saved.
func TestLateBoundedGenerateResultIsShownAfterUnlock(t *testing.T) {
	t.Chdir(t.TempDir())
	prepared := preparedAccount(boundedmeta.Layer3PolicyFixedAllowlist, boundary.RekeyRefused, true, 2)
	m, result := reviewedResult("ADDRESS", prepared)
	m.connectionState, m.signerState = ConnectionConnected, signerRuntimeUnlocked

	m = lockedDuring(t, m)
	m = updateModel(t, m, fromListener(decodeSignerReply(t, protocol.GenerateResultMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeGenerateResult, ID: result.ID},
		Success:     true, Address: result.Address, KeyType: result.KeyType,
	})))
	if m.viewState != ViewUnlock {
		t.Fatalf("the late result moved the unlock screen to view %v", m.viewState)
	}

	m = unlocked(t, m)
	if m.viewState != ViewGenerateDisplay || m.forms.generatedAddress != "ADDRESS" {
		t.Fatalf("after unlocking: view %v address %q, want the generated account", m.viewState, m.forms.generatedAddress)
	}
	if _, ok := m.generatedReceipt(); !ok {
		t.Fatal("the generated account's receipt is not offered after unlocking")
	}
	next, _ := m.handleKeyPress(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})
	m = next.(Model)
	if m.forms.receiptError != "" {
		t.Fatalf("save receipt: %s", m.forms.receiptError)
	}
	if _, err := os.Stat("ADDRESS.receipt.json"); err != nil {
		t.Fatalf("the receipt was not saved: %v", err)
	}
	if m.heldResult != nil {
		t.Fatal("the shown result is still held")
	}
}

// Late successes of an import or a backup are held and shown after unlocking
// too; a late failure changed nothing and is dropped.
func TestLateImportAndBackupSuccessesAreShownAfterUnlock(t *testing.T) {
	for _, op := range []struct {
		name     string
		start    ViewState
		progress ViewState
		done     ViewState
		reply    func(id string, success bool) tea.Msg
	}{
		{"import", ViewImportForm, ViewImporting, ViewImportDisplay, func(id string, success bool) tea.Msg {
			return ImportResultMsg{ID: id, Success: success, Address: "ADDR", KeyType: "ed25519", Error: errorIf(!success)}
		}},
		{"backup", ViewBackupConfirm, ViewBackingUp, ViewBackupDisplay, func(id string, success bool) tea.Msg {
			return BackupResultMsg{ID: id, Success: success, ArchivePath: "aplane-backup.tar.gz", Error: errorIf(!success)}
		}},
	} {
		for _, success := range []bool{true, false} {
			m := Model{viewState: op.start, connectionState: ConnectionConnected, signerState: signerRuntimeUnlocked,
				forms: formsState{importMnemonicInput: newImportMnemonicInput()}}
			id := m.beginOperation(op.progress)
			m = lockedDuring(t, m)
			m = updateModel(t, m, fromListener(op.reply(id, success)))
			m = unlocked(t, m)
			want := op.done
			if !success {
				want = ViewKeyList
			}
			if m.viewState != want || m.heldResult != nil {
				t.Fatalf("%s success=%v: view %v held %v after unlocking, want view %v", op.name, success, m.viewState, m.heldResult != nil, want)
			}
		}
	}
}

func errorIf(failed bool) string {
	if failed {
		return "refused"
	}
	return ""
}

// A held result outlives a reconnect and re-authentication, but a
// displacement ends the session for good, and it is discarded with the
// import form it left filled.
func TestHeldResultIsDiscardedOnDisplacement(t *testing.T) {
	input := newImportMnemonicInput()
	input.SetValue("w01 w02 w03")
	m := Model{viewState: ViewImportForm, connectionState: ConnectionConnected, signerState: signerRuntimeUnlocked,
		forms: formsState{importMnemonicInput: input}}
	id := m.beginOperation(ViewImporting)
	m = lockedDuring(t, m)
	m = updateModel(t, m, fromListener(ImportResultMsg{ID: id, Success: true, Address: "ADDR", KeyType: "ed25519"}))

	reconnected := updateModel(t, m, fromListener(ErrorMsg{Error: errors.New("connection reset")}))
	reconnected = updateModel(t, reconnected, fromListener(ReconnectingMsg{}))
	reconnected = updateModel(t, reconnected, fromListener(AuthRequiredMsg{}))
	reconnected = updateModel(t, reconnected, fromListener(AuthResultMsg{Success: true}))
	reconnected = updateModel(t, reconnected, fromListener(SignerStatusMsg{State: "unlocked", KeyCount: 1}))
	if reconnected.viewState != ViewImportDisplay {
		t.Fatalf("after reconnecting and unlocking: view %v, want the held import shown", reconnected.viewState)
	}

	displaced := updateModel(t, m, fromListener(DisplacedMsg{Reason: "replaced"}))
	if displaced.heldResult != nil || displaced.forms.importMnemonicInput.Value() != "" {
		t.Fatalf("displaced: held %v form %q, want both cleared", displaced.heldResult != nil, displaced.forms.importMnemonicInput.Value())
	}
}
