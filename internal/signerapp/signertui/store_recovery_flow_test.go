// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/aplane-algo/aplane/internal/protocol"
)

func TestSignerStatusPreservesAllThreeRuntimeStates(t *testing.T) {
	m := Model{viewState: ViewKeyList}
	got, _ := updateForTest(t, m, SignerStatusMsg{State: "locked"})
	if got.signerState != signerRuntimeLocked || got.viewState != ViewUnlock {
		t.Fatalf("locked status = state %v view %v", got.signerState, got.viewState)
	}
	got, _ = updateForTest(t, m, SignerStatusMsg{State: "unlocked", KeyCount: 4})
	if got.signerState != signerRuntimeUnlocked || got.viewState != ViewKeyList || got.keyCount != 4 {
		t.Fatalf("unlocked status = state %v view %v keys %d", got.signerState, got.viewState, got.keyCount)
	}
	got, _ = updateForTest(t, m, SignerStatusMsg{State: "recovery"})
	if got.signerState != signerRuntimeRecovery || got.viewState != ViewStoreRecovery {
		t.Fatalf("recovery status = state %v view %v", got.signerState, got.viewState)
	}
}

func TestUnlockIntoRecoveryOpensStoreRecoveryScreen(t *testing.T) {
	m := Model{viewState: ViewUnlock}
	got, _ := updateForTest(t, m, UnlockResultMsg{Success: true, Code: protocol.ResultCodeRecoveryBlocked})
	if got.signerState != signerRuntimeRecovery || got.viewState != ViewStoreRecovery {
		t.Fatalf("unlock recovery = state %v view %v", got.signerState, got.viewState)
	}
}

func TestStoreRecoveryScreenBlocksEscapeWhileRecoveryBlocked(t *testing.T) {
	m := Model{viewState: ViewStoreRecovery, signerState: signerRuntimeRecovery}
	next, _ := m.handleStoreRecoveryKeys(tea.KeyMsg{Type: tea.KeyEsc})
	got := next.(Model)
	if got.viewState != ViewStoreRecovery {
		t.Fatalf("escape left recovery screen: %v", got.viewState)
	}
	if !strings.Contains(got.restore.recoveryError, "Signing remains disabled") {
		t.Fatalf("blocking message = %q", got.restore.recoveryError)
	}
}

func TestStoreRecoveryViewOffersReconcileRollbackAndRestore(t *testing.T) {
	view := stripANSI((Model{viewState: ViewStoreRecovery, signerState: signerRuntimeRecovery}).renderStoreRecovery())
	for _, text := range []string{
		"Reconcile and validate", "Roll back the latest clean credential restore", "Restore credentials from a backup archive",
	} {
		if !strings.Contains(view, text) {
			t.Fatalf("recovery view missing %q:\n%s", text, view)
		}
	}
}

func TestStoreRecoveryQQuitsAsAdvertised(t *testing.T) {
	m := Model{viewState: ViewStoreRecovery, signerState: signerRuntimeRecovery}
	_, cmd := m.handleStoreRecoveryKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	if cmd == nil {
		t.Fatal("q did not return a quit command")
	}
}

func TestStoreRecoveryRestoreShortcutPreservesRecoveryReturn(t *testing.T) {
	m := Model{viewState: ViewStoreRecovery, signerState: signerRuntimeRecovery}
	next, cmd := m.handleStoreRecoveryKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'b'}})
	got := next.(Model)
	if got.viewState != ViewBackups || !got.restore.returnToRecovery {
		t.Fatalf("recovery restore shortcut = view %v returnToRecovery %v", got.viewState, got.restore.returnToRecovery)
	}
	if cmd == nil {
		t.Fatal("recovery restore shortcut did not request the backup list")
	}
}

func TestUntypedRecoveryRestoreFailureRemainsVisible(t *testing.T) {
	m := Model{viewState: ViewRestoring, signerState: signerRuntimeRecovery, restore: restoreState{pendingID: "reconcile-store-1"}}
	got, _ := updateForTest(t, m, ErrorMsg{ID: "reconcile-store-1", Error: errors.New("authorization denied")})
	if got.viewState != ViewStoreRecovery || got.signerState != signerRuntimeRecovery {
		t.Fatalf("untyped recovery failure = state %v view %v", got.signerState, got.viewState)
	}
	if got.restore.recoveryError != "authorization denied" {
		t.Fatalf("recovery error = %q, want authorization denial", got.restore.recoveryError)
	}
}

func TestRestoreListEscapeReturnsToBlockingRecoveryScreen(t *testing.T) {
	m := Model{
		viewState:   ViewBackups,
		signerState: signerRuntimeRecovery,
		restore: restoreState{
			returnToRecovery: true,
			backupsLoaded:    true,
		},
	}
	next, _ := m.handleBackupsKeys(tea.KeyMsg{Type: tea.KeyEsc})
	got := next.(Model)
	if got.viewState != ViewStoreRecovery || got.signerState != signerRuntimeRecovery {
		t.Fatalf("escape from recovery restore list = state %v view %v", got.signerState, got.viewState)
	}
}

func TestRollbackRefusalDoesNotInventRecoveryState(t *testing.T) {
	m := Model{viewState: ViewRestoring, signerState: signerRuntimeUnlocked}
	got, _ := updateForTest(t, m, RollbackRestoreResultMsg{Result: RollbackRestoreResultMessage{
		Success: false,
		Code:    protocol.ResultCodeRestoreRollbackRefused,
		Error:   "current generation is not rollback eligible",
	}})
	if got.signerState != signerRuntimeUnlocked || got.viewState != ViewKeyList {
		t.Fatalf("rollback refusal = state %v view %v, want unlocked key list", got.signerState, got.viewState)
	}
}

// A key or key type change whose reload found a content defect, the review's
// trigger: the signer wrote the change, entered recovery and pushed a status
// naming it while the reload ran, and the change's reply, recovery_blocked
// with the defect, came after. The status opens the recovery screen, which offers the
// reconcile, and the reply, by then a late failure, puts its cause there
// instead of being dropped. A reply with no status before it opens the
// screen itself.
func TestAKeyChangeThatEnteredRecoveryEndsOnTheRecoveryScreen(t *testing.T) {
	const cause = "the change was written, but the reload after it found a content defect in the selected generation, and the signer entered recovery: generation validation failed: keys/junk.txt"
	base := func(msgType, id string) protocol.BaseMessage {
		return protocol.BaseMessage{Kind: protocol.MessageKindResponse, Type: msgType, ID: id}
	}
	for _, op := range []struct {
		name            string
		start, progress ViewState
		reply           func(id string) any
		prefix          string
	}{
		// The key a generation or import wrote is named with the cause.
		{"generate", ViewGenerateForm, ViewGenerating, func(id string) any {
			return protocol.GenerateResultMessage{BaseMessage: base(protocol.MsgTypeGenerateResult, id), Address: "ADDRWRITTEN", Code: protocol.ResultCodeRecoveryBlocked, Error: cause}
		}, "Key generation of ADDRWRITTEN: "},
		{"delete", ViewDeleteConfirm, ViewDeleting, func(id string) any {
			return protocol.DeleteResultMessage{BaseMessage: base(protocol.MsgTypeDeleteResult, id), Code: protocol.ResultCodeRecoveryBlocked, Error: cause}
		}, "Key deletion: "},
		{"import", ViewImportForm, ViewImporting, func(id string) any {
			return protocol.ImportResultMessage{BaseMessage: base(protocol.MsgTypeImportResult, id), Address: "ADDRWRITTEN", Code: protocol.ResultCodeRecoveryBlocked, Error: cause}
		}, "Key import of ADDRWRITTEN: "},
		// The KeyType Library's actions, the review's probe: their replies
		// went through finishLibraryAction, which dropped a late one.
		{"template install", ViewTemplateInstallConfirm, ViewTemplateInstalling, func(id string) any {
			return protocol.InstallLibraryTemplateResultMessage{BaseMessage: base(protocol.MsgTypeInstallLibraryTemplateResult, id), Code: protocol.ResultCodeRecoveryBlocked, Error: cause}
		}, "KeyType Library: "},
		{"key type enable", ViewTemplateInstallConfirm, ViewTemplateInstalling, func(id string) any {
			return protocol.ActivateKeyTypeResultMessage{BaseMessage: base(protocol.MsgTypeActivateKeyTypeResult, id), Code: protocol.ResultCodeRecoveryBlocked, Error: cause}
		}, "KeyType Library: "},
		{"key type disable", ViewTemplateInstallConfirm, ViewTemplateInstalling, func(id string) any {
			return protocol.DeactivateKeyTypeResultMessage{BaseMessage: base(protocol.MsgTypeDeactivateKeyTypeResult, id), Code: protocol.ResultCodeRecoveryBlocked, Error: cause}
		}, "KeyType Library: "},
	} {
		for _, pushed := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s pushed=%v", op.name, pushed), func(t *testing.T) {
				input := newImportMnemonicInput()
				input.SetValue("w01 w02 w03")
				m := Model{viewState: op.start, connectionState: ConnectionConnected, signerState: signerRuntimeUnlocked,
					forms: formsState{importMnemonicInput: input}}
				id := m.beginOperation(op.progress)
				if pushed {
					m = updateModel(t, m, fromListener(decodeSignerReply(t, protocol.StatusMessage{
						BaseMessage: protocol.BaseMessage{Kind: protocol.MessageKindNotification, Type: protocol.MsgTypeStatus},
						State:       "recovery",
					})))
					if m.viewState != ViewStoreRecovery {
						t.Fatalf("the pushed status left view %v, want the recovery screen", m.viewState)
					}
				}
				m = updateModel(t, m, fromListener(decodeSignerReply(t, op.reply(id))))
				if m.viewState != ViewStoreRecovery || m.signerState != signerRuntimeRecovery {
					t.Fatalf("view %v state %v, want the recovery screen in recovery", m.viewState, m.signerState)
				}
				if m.restore.recoveryError != op.prefix+cause {
					t.Fatalf("recovery screen error = %q, want the reply's cause", m.restore.recoveryError)
				}
				if m.operation != (pendingOperation{}) || m.heldResult != nil {
					t.Fatalf("operation %+v held %v, want the operation ended", m.operation, m.heldResult != nil)
				}
				if m.forms.importMnemonicInput.Value() != "" && op.name == "import" {
					t.Fatal("the imported key's recovery phrase stayed in the form")
				}
			})
		}
	}
}

// A lock that lands after a key change's reload entered recovery and before
// its reply arrives stands: the reply ends the operation and leaves the
// unlock screen, as a reconcile's or a rollback's late reply does, and the
// next unlock finds the recovery. The reply once reopened the recovery
// screen on a locked signer. The review's probe.
func TestARecoveryBlockedReplyAfterALockLeavesTheSignerLocked(t *testing.T) {
	m := Model{viewState: ViewGenerateForm, connectionState: ConnectionConnected, signerState: signerRuntimeUnlocked,
		forms: formsState{importMnemonicInput: newImportMnemonicInput()}}
	id := m.beginOperation(ViewGenerating)
	m = updateModel(t, m, fromListener(decodeSignerReply(t, protocol.StatusMessage{
		BaseMessage: protocol.BaseMessage{Kind: protocol.MessageKindNotification, Type: protocol.MsgTypeStatus},
		State:       "recovery",
	})))
	m = updateModel(t, m, SignerStatusMsg{State: "locked"})
	m = updateModel(t, m, fromListener(decodeSignerReply(t, protocol.GenerateResultMessage{
		BaseMessage: protocol.BaseMessage{Kind: protocol.MessageKindResponse, Type: protocol.MsgTypeGenerateResult, ID: id},
		Code:        protocol.ResultCodeRecoveryBlocked, Error: "the cause",
	})))
	if m.viewState != ViewUnlock || m.signerState != signerRuntimeLocked {
		t.Fatalf("view %v state %v after the late reply, want the unlock screen of a locked signer", m.viewState, m.signerState)
	}
	if m.operation != (pendingOperation{}) {
		t.Fatalf("operation %+v, want it ended", m.operation)
	}
}
