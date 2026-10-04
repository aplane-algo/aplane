// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/protocol"
	tea "github.com/charmbracelet/bubbletea"
)

// Every way an admin session ends clears the same state. Displacement once
// kept the restore passphrase in memory.
func TestEverySessionEndClearsSessionState(t *testing.T) {
	for name, msg := range map[string]tea.Msg{
		"auth required": AuthRequiredMsg{},
		"disconnected":  DisconnectedMsg{},
		"idle":          localIdleDisconnectedMsg{Reason: "idle"},
		"reconnecting":  ReconnectingMsg{},
		"displaced":     DisplacedMsg{Reason: "replaced"},
	} {
		m := approvalTestModel(ViewRestorePassphrase)
		passphrase := []byte("export-passphrase")
		m.restore.passphrase = passphrase
		m.manualLock.pending = true
		m.cosigner.loaded = true
		m = updateModel(t, m, msg)
		if m.restore.passphrase != nil || string(passphrase) == "export-passphrase" {
			t.Errorf("%s kept the restore passphrase", name)
		}
		if m.manualLock.pending || m.cosigner.loaded {
			t.Errorf("%s kept session state: manual lock pending %v, cosigner references loaded %v",
				name, m.manualLock.pending, m.cosigner.loaded)
		}
	}
}

func batchSize(t *testing.T, cmd tea.Cmd) int {
	t.Helper()
	if cmd == nil {
		return 0
	}
	if batch, ok := cmd().(tea.BatchMsg); ok {
		return len(batch)
	}
	return 1
}

// Finishing a recovery loads what unlocking loads; it once skipped cosigner
// references and settings.
func TestRecoveryReconcileLoadsWhatUnlockLoads(t *testing.T) {
	_, unlockCmd := approvalTestModel(ViewUnlock).Update(UnlockResultMsg{Success: true, KeyCount: 1})
	next, reconcileCmd := approvalTestModel(ViewStoreRecovery).Update(ReconcileStoreResultMsg{
		Result: protocol.ReconcileStoreResultMessage{Success: true, KeyCount: 1},
	})
	if got := next.(Model).viewState; got != ViewKeyList {
		t.Fatalf("view after reconcile = %v, want the key list", got)
	}
	if want, got := batchSize(t, unlockCmd), batchSize(t, reconcileCmd); got != want || want == 0 {
		t.Fatalf("reconcile issues %d commands, unlock issues %d", got, want)
	}
}

// Notifications arrive unprompted, so every one must decode; responses only
// matter for requests the TUI sends.
func TestEveryNotificationTypeIsDecoded(t *testing.T) {
	for _, msgType := range []string{
		protocol.MsgTypeAuthRequired, protocol.MsgTypeStatus, protocol.MsgTypeSignRequest,
		protocol.MsgTypeSignRequestCanceled, protocol.MsgTypeTokenProvisioningRequest,
		protocol.MsgTypeKeysChanged, protocol.MsgTypeSignerLocked, protocol.MsgTypeClientExists,
	} {
		if kind, ok := protocol.InferMessageKind(msgType); !ok || kind != protocol.MessageKindNotification {
			t.Fatalf("%s is not a notification type", msgType)
		}
		if _, ok := signerMessageDecoders[msgType]; !ok {
			t.Errorf("notification %s has no decoder", msgType)
		}
	}
}
