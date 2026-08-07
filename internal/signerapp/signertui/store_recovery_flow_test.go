// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"errors"
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
	if got.viewState != ViewRestoreList || !got.restore.returnToRecovery {
		t.Fatalf("recovery restore shortcut = view %v returnToRecovery %v", got.viewState, got.restore.returnToRecovery)
	}
	if cmd == nil {
		t.Fatal("recovery restore shortcut did not request the backup list")
	}
}

func TestUntypedRecoveryRestoreFailureRemainsVisible(t *testing.T) {
	m := Model{viewState: ViewRestoring, signerState: signerRuntimeRecovery}
	got, _ := updateForTest(t, m, ErrorMsg{Error: errors.New("authorization denied")})
	if got.viewState != ViewStoreRecovery || got.signerState != signerRuntimeRecovery {
		t.Fatalf("untyped recovery failure = state %v view %v", got.signerState, got.viewState)
	}
	if got.restore.recoveryError != "authorization denied" {
		t.Fatalf("recovery error = %q, want authorization denial", got.restore.recoveryError)
	}
}

func TestRestoreListEscapeReturnsToBlockingRecoveryScreen(t *testing.T) {
	m := Model{
		viewState:   ViewRestoreList,
		signerState: signerRuntimeRecovery,
		restore: restoreState{
			returnToRecovery: true,
			backupsLoaded:    true,
		},
	}
	next, _ := m.handleRestoreListKeys(tea.KeyMsg{Type: tea.KeyEsc})
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
