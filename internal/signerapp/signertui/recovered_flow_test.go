// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
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
		t.Fatalf("locked status = state %v view %v, want locked/unlock", got.signerState, got.viewState)
	}

	got, _ = updateForTest(t, m, SignerStatusMsg{State: "unlocked", KeyCount: 4})
	if got.signerState != signerRuntimeUnlocked || got.viewState != ViewKeyList || got.keyCount != 4 {
		t.Fatalf("unlocked status = state %v view %v keys %d", got.signerState, got.viewState, got.keyCount)
	}

	got, cmd := updateForTest(t, m, SignerStatusMsg{State: "recovery"})
	if got.signerState != signerRuntimeRecovery {
		t.Fatalf("recovery status = state %v, want recovery (never collapsed into unlocked)", got.signerState)
	}
	if got.viewState != ViewRecoveredList {
		t.Fatalf("recovery status view = %v, want the blocking recovered list", got.viewState)
	}
	if cmd == nil {
		t.Fatal("recovery status issued no command; expected a recovered-list request")
	}
}

func TestUnlockIntoRecoveryOpensBlockingScreen(t *testing.T) {
	m := Model{viewState: ViewUnlock}

	got, cmd := updateForTest(t, m, UnlockResultMsg{
		Success: true,
		Code:    protocol.ResultCodeActivationIncomplete,
	})
	if got.signerState != signerRuntimeRecovery || got.viewState != ViewRecoveredList {
		t.Fatalf("unlock-into-recovery = state %v view %v, want recovery/recovered list", got.signerState, got.viewState)
	}
	if cmd == nil {
		t.Fatal("no command issued after entering recovery")
	}
}

func TestRecoveredListBlocksEscapeWhileInRecovery(t *testing.T) {
	m := Model{
		viewState:   ViewRecoveredList,
		signerState: signerRuntimeRecovery,
	}

	next, _ := m.handleRecoveredListKeys(tea.KeyMsg{Type: tea.KeyEsc})
	got := next.(Model)
	if got.viewState != ViewRecoveredList {
		t.Fatalf("esc left the blocking recovery screen: view %v", got.viewState)
	}
	if !strings.Contains(got.restore.recoveredError, "Signing is disabled") {
		t.Fatalf("blocking message missing: %q", got.restore.recoveredError)
	}
}

func TestRecoveredListActionSetsFollowBatchState(t *testing.T) {
	batches := []RecoveredBatchInfo{
		{RestoreID: "00000000000000000000000000000001"},
		{RestoreID: "00000000000000000000000000000002", ActivationState: "applying"},
		{RestoreID: "00000000000000000000000000000003", ActivationState: "completed"},
	}
	base := Model{
		viewState:   ViewRecoveredList,
		signerState: signerRuntimeUnlocked,
		restore:     restoreState{recovered: batches, recoveredLoaded: true},
	}

	// Inactive: rollback refused, purge arms then commits on y.
	m := base
	m.restore.selectedRecovered = 0
	next, _ := m.handleRecoveredListKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'x'}})
	got := next.(Model)
	if !strings.Contains(got.restore.recoveredError, "nothing to roll back") {
		t.Fatalf("inactive rollback error = %q", got.restore.recoveredError)
	}
	next, _ = m.handleRecoveredListKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'p'}})
	got = next.(Model)
	if got.restore.purgeArmedID != batches[0].RestoreID {
		t.Fatalf("purge not armed: %q", got.restore.purgeArmedID)
	}
	next, cmd := got.handleRecoveredListKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'y'}})
	got = next.(Model)
	if got.viewState != ViewRestoring || cmd == nil {
		t.Fatalf("confirmed purge = view %v cmd %v", got.viewState, cmd != nil)
	}
	if got.restore.progressLabel != "Purging Recovered Batch" {
		t.Fatalf("purge progress label = %q", got.restore.progressLabel)
	}

	// Incomplete (applying): rollback proceeds, purge refused.
	m = base
	m.restore.selectedRecovered = 1
	next, cmd = m.handleRecoveredListKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'x'}})
	got = next.(Model)
	if got.viewState != ViewRestoring || cmd == nil {
		t.Fatalf("incomplete rollback = view %v cmd %v", got.viewState, cmd != nil)
	}
	if got.restore.progressLabel != "Rolling Back Incomplete Activation" {
		t.Fatalf("rollback progress label = %q", got.restore.progressLabel)
	}
	next, _ = m.handleRecoveredListKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'p'}})
	got = next.(Model)
	if !strings.Contains(got.restore.recoveredError, "Cannot purge") {
		t.Fatalf("incomplete purge error = %q", got.restore.recoveredError)
	}

	// Completed: rollback redirected to cleanup via activation retry.
	m = base
	m.restore.selectedRecovered = 2
	next, _ = m.handleRecoveredListKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'x'}})
	got = next.(Model)
	if !strings.Contains(got.restore.recoveredError, "finish its cleanup") {
		t.Fatalf("completed rollback error = %q", got.restore.recoveredError)
	}

	// Review needs no passphrase: enter goes straight to the review fetch.
	m = base
	m.restore.selectedRecovered = 1
	next, cmd = m.handleRecoveredListKeys(tea.KeyMsg{Type: tea.KeyEnter})
	got = next.(Model)
	if got.viewState != ViewRestoring || cmd == nil {
		t.Fatalf("review reopen = view %v cmd %v", got.viewState, cmd != nil)
	}
	if got.restore.progressLabel != "Loading Activation Review" {
		t.Fatalf("review progress label = %q", got.restore.progressLabel)
	}
	if len(got.restore.passphrase) != 0 {
		t.Fatal("reopening a recovered batch must not involve a passphrase")
	}
}

func TestReviewEscapeReturnsToRecoveredListWithoutStranding(t *testing.T) {
	m := Model{
		viewState:   ViewRestoreReview,
		signerState: signerRuntimeUnlocked,
		restore: restoreState{
			restoreID: "00000000000000000000000000000001",
		},
	}

	next, cmd := m.handleRestoreReviewKeys(tea.KeyMsg{Type: tea.KeyEsc})
	got := next.(Model)
	if got.viewState != ViewRecoveredList {
		t.Fatalf("esc from review = view %v, want recovered list", got.viewState)
	}
	if !strings.Contains(got.restore.recoveredError, "remains inactive") {
		t.Fatalf("esc message = %q", got.restore.recoveredError)
	}
	if cmd == nil {
		t.Fatal("esc from review did not refresh the recovered list")
	}
}

func TestReviewCollectsReplaceConsentBesideConflicts(t *testing.T) {
	m := Model{
		viewState:   ViewRestoreReview,
		signerState: signerRuntimeUnlocked,
		restore: restoreState{
			restoreID: "00000000000000000000000000000001",
			review: ReviewRecoveredResultMessage{
				Success:     true,
				RestoreID:   "00000000000000000000000000000001",
				ReviewToken: "token",
				ActiveConflicts: []protocol.RecoveredActiveConflict{
					{Selector: "CONFLICTADDR", Category: "account", KeyType: "ed25519"},
				},
			},
			reviewFocus: restoreFocusAction,
		},
	}

	// Activation without consent is refused with remediation.
	next, _ := m.handleRestoreReviewKeys(tea.KeyMsg{Type: tea.KeyEnter})
	got := next.(Model)
	if got.viewState == ViewRestoring {
		t.Fatal("activation started without replace-existing consent")
	}
	if !strings.Contains(got.restore.previewError, "replace-existing") {
		t.Fatalf("consent error = %q", got.restore.previewError)
	}

	// The consent is a checkbox on the review, beside the conflicts.
	view := stripANSI(m.renderRestoreReview())
	conflictAt := strings.Index(view, "Active credential conflicts")
	consentAt := strings.Index(view, "Replace the 1 existing active credential(s)")
	if conflictAt < 0 || consentAt < 0 || consentAt < conflictAt {
		t.Fatalf("consent not rendered beside conflicts (conflict %d, consent %d):\n%s", conflictAt, consentAt, view)
	}

	// Toggle it, then activate from the focused button.
	m.restore.reviewFocus = restoreFocusList
	next, _ = m.handleRestoreReviewKeys(tea.KeyMsg{Type: tea.KeySpace})
	got = next.(Model)
	if !got.restore.replaceExisting {
		t.Fatal("space did not toggle the replace-existing consent")
	}
	next, _ = got.handleRestoreReviewKeys(tea.KeyMsg{Type: tea.KeyTab})
	got = next.(Model)
	next, cmd := got.handleRestoreReviewKeys(tea.KeyMsg{Type: tea.KeyEnter})
	got = next.(Model)
	if got.viewState != ViewRestoring || cmd == nil {
		t.Fatalf("consented activation = view %v cmd %v", got.viewState, cmd != nil)
	}
	if got.restore.progressLabel != "Activating Recovered Credentials" {
		t.Fatalf("activation progress label = %q", got.restore.progressLabel)
	}
}

func TestResumeReviewUsesRecordedIntentVerbatim(t *testing.T) {
	m := Model{viewState: ViewRestoring}
	got, _ := updateForTest(t, m, ReviewRecoveredResultMsg{Result: ReviewRecoveredResultMessage{
		Success:                      true,
		RestoreID:                    "00000000000000000000000000000002",
		State:                        "activation_incomplete",
		ReviewToken:                  "recorded-token",
		AcknowledgeUnattendedSigning: true,
		ReplaceExisting:              true,
		ActiveConflicts: []protocol.RecoveredActiveConflict{
			{Selector: "CONFLICTADDR", Category: "account", KeyType: "ed25519"},
		},
	}})
	if got.viewState != ViewRestoreReview {
		t.Fatalf("view = %v, want review", got.viewState)
	}
	if !got.restore.replaceExisting || !got.restore.unattendedAcknowledged {
		t.Fatal("recorded consent was not adopted for the resume")
	}
	if boxes := got.reviewCheckboxes(); len(boxes) != 0 {
		t.Fatalf("resume review offers %d checkboxes, want none (consent is fixed to the recorded intent)", len(boxes))
	}
	view := stripANSI(got.renderRestoreReview())
	if !strings.Contains(view, "resumes the exact recorded intent") {
		t.Fatalf("resume review does not state the recorded-intent semantics:\n%s", view)
	}

	next, cmd := got.handleRestoreReviewKeys(tea.KeyMsg{Type: tea.KeyEnter})
	final := next.(Model)
	if final.viewState != ViewRestoring || cmd == nil {
		t.Fatalf("resume activation = view %v cmd %v", final.viewState, cmd != nil)
	}
}

func TestFailedActivationResultRoutesBackToRecoveredList(t *testing.T) {
	m := Model{
		viewState:   ViewRestoreDisplay,
		signerState: signerRuntimeUnlocked,
		restore: restoreState{
			restoreID: "00000000000000000000000000000001",
			result:    RestoreDisplayResult{Success: false, Error: "activation failed"},
		},
	}

	next, cmd := m.handleRestoreDisplayKeys(tea.KeyMsg{Type: tea.KeyEsc})
	got := next.(Model)
	if got.viewState != ViewRecoveredList {
		t.Fatalf("failed result dismissal = view %v, want recovered list", got.viewState)
	}
	if cmd == nil {
		t.Fatal("failed result dismissal did not refresh the recovered list")
	}
}

func TestStatusBarAndProgressLabelsDistinguishStates(t *testing.T) {
	m := Model{
		width:             120,
		height:            40,
		signerStatusKnown: true,
		signerState:       signerRuntimeRecovery,
		viewState:         ViewRecoveredList,
	}
	view := stripANSI(m.View())
	if !strings.Contains(view, "Signer Recovery (signing disabled)") {
		t.Fatalf("status bar does not surface recovery:\n%s", view)
	}

	m.viewState = ViewRestoring
	m.restore.progressLabel = "Recovering Into Inactive Batch"
	view = stripANSI(m.renderRestoring())
	if !strings.Contains(view, "Recovering Into Inactive Batch") {
		t.Fatalf("recovering label missing:\n%s", view)
	}
	m.restore.progressLabel = "Activating Recovered Credentials"
	view = stripANSI(m.renderRestoring())
	if !strings.Contains(view, "Activating Recovered Credentials") {
		t.Fatalf("activating label missing:\n%s", view)
	}
}

func TestBackupConfirmStatesScopeAndCredentialCount(t *testing.T) {
	m := Model{
		viewState: ViewBackupConfirm,
		keyCount:  3,
		width:     100,
		height:    40,
	}
	view := stripANSI(m.renderBackupConfirm())
	if !strings.Contains(view, "all active credentials of this identity (3 keys)") {
		t.Fatalf("backup scope label missing:\n%s", view)
	}
}

func TestRecoveredListMsgPopulatesInventory(t *testing.T) {
	m := Model{viewState: ViewRecoveredList}
	got, _ := updateForTest(t, m, RecoveredListMsg{Batches: []RecoveredBatchInfo{
		{RestoreID: "00000000000000000000000000000001", ActivationState: "applying", EntryCount: 2},
	}})
	if !got.restore.recoveredLoaded || len(got.restore.recovered) != 1 {
		t.Fatalf("recovered list not populated: loaded %v n %d", got.restore.recoveredLoaded, len(got.restore.recovered))
	}
	view := stripANSI(got.renderRecoveredList())
	if !strings.Contains(view, "INCOMPLETE (applying)") {
		t.Fatalf("batch lifecycle state not rendered:\n%s", view)
	}
}

func TestFailedRollbackResultMirrorsRecoveryState(t *testing.T) {
	m := Model{viewState: ViewRestoring, signerState: signerRuntimeUnlocked}
	got, _ := updateForTest(t, m, RollbackRecoveredResultMsg{Result: RollbackRecoveredResultMessage{
		Success: false,
		Code:    protocol.ResultCodeRecoveredRollbackFailed,
		Error:   "rollback incomplete",
	}})
	if got.signerState != signerRuntimeRecovery {
		t.Fatalf("signer state = %v after failed rollback, want recovery", got.signerState)
	}
	if got.viewState != ViewRecoveredList {
		t.Fatalf("view = %v after failed rollback, want recovered list", got.viewState)
	}
	if !strings.Contains(got.restore.recoveredError, "rollback incomplete") {
		t.Fatalf("failure details missing: %q", got.restore.recoveredError)
	}
}

func TestReviewRendersEntriesAndArchiveIdentity(t *testing.T) {
	m := Model{
		viewState:   ViewRestoreReview,
		signerState: signerRuntimeUnlocked,
		restore: restoreState{
			restoreID: "00000000000000000000000000000001",
			review: ReviewRecoveredResultMessage{
				Success:         true,
				RestoreID:       "00000000000000000000000000000001",
				ArchiveChecksum: "abcdef0123456789",
				SourceNodeRole:  "signer",
				Entries: []protocol.RecoveredReviewEntry{
					{Selector: "ENTRYADDRONE", Category: "account", KeyType: "ed25519"},
					{Selector: "ENTRYADDRTWO", Category: "witness", KeyType: "aplane.witness-falcon1024.v1"},
				},
			},
		},
	}
	view := stripANSI(m.renderRestoreReview())
	// The operator commits ACTIVATE for exactly these credentials; via the
	// passphrase-free reopen path this screen is the only place they can
	// ever be seen.
	for _, want := range []string{
		"Credentials to activate (2)",
		"ENTRYADDRONE (account, ed25519)",
		"ENTRYADDRTWO (witness, aplane.witness-falcon1024.v1)",
		"Source archive: abcdef0123456789 (signer)",
	} {
		if !strings.Contains(view, want) {
			t.Fatalf("review view missing %q:\n%s", want, view)
		}
	}
}

func TestReviewScrollsInsteadOfTruncating(t *testing.T) {
	changes := make([]protocol.RecoveryPolicyChange, 20)
	for i := range changes {
		changes[i] = protocol.RecoveryPolicyChange{Category: "routing", Path: fmt.Sprintf("field-%02d", i)}
	}
	m := Model{
		viewState:   ViewRestoreReview,
		signerState: signerRuntimeUnlocked,
		width:       120,
		height:      24,
		restore: restoreState{
			restoreID: "00000000000000000000000000000001",
			review: ReviewRecoveredResultMessage{
				Success:         true,
				RestoreID:       "00000000000000000000000000000001",
				SecurityChanges: changes,
			},
		},
	}
	if !m.usesSharedPopupViewport() {
		t.Fatal("ViewRestoreReview is not registered for the shared popup viewport; overflow would be truncated with controls still operable")
	}
	top := stripANSI(m.renderRestoreReview())
	if !strings.Contains(top, "Panel lines") {
		t.Fatalf("overflowing review has no scroll indicator:\n%s", top)
	}
	// Scrolling to the bottom reveals the ACTIVATE control that plain
	// truncation used to drop while leaving it operable.
	scrolled := m.setSharedPopupPosition(panelScrollScale)
	bottom := stripANSI(scrolled.renderRestoreReview())
	if !strings.Contains(bottom, "ACTIVATE") {
		t.Fatalf("scrolled-to-bottom review does not reveal ACTIVATE:\n%s", bottom)
	}
	if strings.Contains(top, "ACTIVATE") {
		t.Skip("terminal budget fits ACTIVATE at top; scroll assertion not meaningful at this size")
	}
}
