// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/protocol"
	tea "github.com/charmbracelet/bubbletea"
)

func TestRestoreFlowUpdateSmoke(t *testing.T) {
	backupFileName := "backup.tar.gz"
	archivePath := filepath.Join(t.TempDir(), "backups", "default", backupFileName)
	m := Model{
		viewState: ViewKeyList,
		keylist: keyListState{keys: []KeyInfo{{
			Address: "CURRENTADDR",
			KeyType: "ed25519",
		}}},
	}

	m, cmd := updateForTest(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}})
	if m.viewState != ViewRestoreList {
		t.Fatalf("after restore key viewState = %v, want ViewRestoreList", m.viewState)
	}
	if m.restore.backupsLoaded {
		t.Fatal("restoreBackupsLoaded = true, want false while list request is in flight")
	}
	if cmd == nil {
		t.Fatal("restore shortcut cmd = nil, want list backups command")
	}

	m, _ = updateForTest(t, m, BackupsListMsg{
		Backups: []BackupInfo{{
			Path:     archivePath,
			FileName: backupFileName,
			Size:     4096,
		}},
	})
	if m.viewState != ViewRestoreList {
		t.Fatalf("after backups list viewState = %v, want ViewRestoreList", m.viewState)
	}
	if len(m.restore.backups) != 1 {
		t.Fatalf("restoreBackups len = %d, want 1", len(m.restore.backups))
	}

	m, _ = updateForTest(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.viewState != ViewRestorePassphrase {
		t.Fatalf("after backup selection viewState = %v, want ViewRestorePassphrase", m.viewState)
	}
	if m.restore.archivePath == "" {
		t.Fatal("restoreArchivePath is empty")
	}

	m = updateTextForTest(t, m, "export-passphrase")
	m, cmd = updateForTest(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.viewState != ViewRestorePassphrase {
		t.Fatalf("after preview submit viewState = %v, want ViewRestorePassphrase", m.viewState)
	}
	if !m.restore.previewing {
		t.Fatal("restorePreviewing = false, want true")
	}
	if string(m.restore.passphrase) != "export-passphrase" {
		t.Fatalf("restorePassphrase = %q, want retained passphrase for restore", string(m.restore.passphrase))
	}
	if cmd == nil {
		t.Fatal("preview submit cmd = nil, want preview command")
	}

	m, _ = updateForTest(t, m, RestorePreviewMsg{
		ArchivePath: m.restore.archivePath,
		Keys: []RestoreKeyInfo{
			{Address: "NEWADDR", KeyType: "ed25519"},
			{Address: "EXISTINGADDR", KeyType: "ed25519", AlreadyExists: true},
		},
	})
	if m.viewState != ViewRestorePreview {
		t.Fatalf("after preview response viewState = %v, want ViewRestorePreview", m.viewState)
	}
	if !m.restore.selected["NEWADDR"] {
		t.Fatal("new key was not preselected")
	}
	if m.restore.selected["EXISTINGADDR"] {
		t.Fatal("existing key was preselected without overwrite")
	}

	passphrase := m.restore.passphrase
	// Enter on the key list must not commit; only the Recover button does.
	m, _ = updateForTest(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.viewState != ViewRestorePreview {
		t.Fatalf("enter on the key list started a recovery: viewState = %v", m.viewState)
	}
	m, _ = updateForTest(t, m, tea.KeyMsg{Type: tea.KeyTab})
	m, cmd = updateForTest(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.viewState != ViewRestoring {
		t.Fatalf("after restore submit viewState = %v, want ViewRestoring", m.viewState)
	}
	if len(m.restore.passphrase) != 0 {
		t.Fatalf("restorePassphrase length = %d, want 0", len(m.restore.passphrase))
	}
	for i, b := range passphrase {
		if b != 0 {
			t.Fatalf("passphrase byte %d = %d, want zero", i, b)
		}
	}
	if cmd == nil {
		t.Fatal("restore submit cmd = nil, want restore command")
	}

	restoreID := "0123456789abcdef0123456789abcdef"
	m, cmd = updateForTest(t, m, RecoverBackupResultMsg{
		Success:   true,
		RestoreID: restoreID,
	})
	if m.viewState != ViewRestoring || cmd == nil {
		t.Fatalf("after recovery result viewState=%v cmd=%v", m.viewState, cmd)
	}
	m, _ = updateForTest(t, m, ReviewRecoveredResultMsg{Result: ReviewRecoveredResultMessage{
		Success:                 true,
		RestoreID:               restoreID,
		DestinationApprovalMode: "manual_default",
		PolicyComparison:        "different",
		ReviewToken:             strings.Repeat("a", 64),
	}})
	if m.viewState != ViewRestoreReview {
		t.Fatalf("after review viewState = %v, want ViewRestoreReview", m.viewState)
	}
	m, cmd = updateForTest(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.viewState != ViewRestoring || cmd == nil {
		t.Fatalf("after activation submit viewState=%v cmd=%v", m.viewState, cmd)
	}
	m, _ = updateForTest(t, m, ActivateRecoveredResultMsg{Result: ActivateRecoveredResultMessage{
		Success: true,
		Activated: []RecoveredReviewEntry{{
			Selector: "NEWADDR",
			KeyType:  "ed25519",
		}},
		Warnings: []string{"skipped bundled template for test.v1: conflict"},
		KeyCount: 1,
	}})
	if m.viewState != ViewRestoreDisplay {
		t.Fatalf("after activation result viewState = %v, want ViewRestoreDisplay", m.viewState)
	}
	if !m.restore.result.Success || len(m.restore.result.Activated) != 1 {
		t.Fatalf("restoreResult = %+v, want successful one-key result", m.restore.result)
	}
	if view := m.renderRestoreDisplay(); !strings.Contains(view, "skipped bundled template") {
		t.Fatalf("restore display omitted activation warning:\n%s", view)
	}

	m, _ = updateForTest(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.viewState != ViewKeyList {
		t.Fatalf("after closing result viewState = %v, want ViewKeyList", m.viewState)
	}
}

func TestRestoreReviewForegroundsAutoApproveBeforeAcknowledgement(t *testing.T) {
	unattendedAckRequired := true
	m := Model{
		viewState: ViewRestoring,
		restore: restoreState{
			restoreID: "0123456789abcdef0123456789abcdef",
		},
	}
	m, _ = updateForTest(t, m, ReviewRecoveredResultMsg{Result: ReviewRecoveredResultMessage{
		Success:                      true,
		RestoreID:                    m.restore.restoreID,
		DestinationApprovalMode:      "auto_approve_fallback",
		UnattendedSigningWarning:     "you are activating into an auto-approving identity",
		PolicyComparison:             "different",
		ReviewToken:                  strings.Repeat("b", 64),
		UnattendedSigningAckRequired: &unattendedAckRequired,
		SecurityChanges: []RecoveryPolicyChange{{
			Category:    "hard_rejects",
			Path:        "reject_rekey",
			Source:      "true",
			Destination: "false",
		}},
	}})
	rendered := m.renderRestoreReview()
	warningIndex := strings.Index(rendered, "auto-approving identity")
	changeIndex := strings.Index(rendered, "reject_rekey")
	ackIndex := strings.Index(rendered, "Required acknowledgement")
	if warningIndex < 0 || changeIndex < 0 || ackIndex < 0 ||
		warningIndex > ackIndex || changeIndex > ackIndex {
		t.Fatalf("security review order is wrong:\n%s", rendered)
	}
	if strings.Contains(stripANSI(rendered), "downgrade") {
		t.Fatalf("security review rendered a downgrade verdict:\n%s", rendered)
	}

	// Activating without the acknowledgement is refused from the button.
	m, _ = updateForTest(t, m, tea.KeyMsg{Type: tea.KeyTab})
	m, _ = updateForTest(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.viewState != ViewRestoreReview ||
		!strings.Contains(m.restore.previewError, "Acknowledge unattended signing") {
		t.Fatalf("enter without unattended ack state=%v error=%q", m.viewState, m.restore.previewError)
	}
	m, _ = updateForTest(t, m, tea.KeyMsg{Type: tea.KeyTab})
	m, _ = updateForTest(t, m, tea.KeyMsg{Type: tea.KeySpace})
	m, _ = updateForTest(t, m, tea.KeyMsg{Type: tea.KeyTab})
	m, cmd := updateForTest(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.viewState != ViewRestoring || cmd == nil {
		t.Fatalf("acknowledged activation state=%v cmd=%v", m.viewState, cmd)
	}
}

func TestRestoreReviewSeparatesSourceMetadataFromPolicyDifferences(t *testing.T) {
	autoApprove := false
	review := ReviewRecoveredResultMessage{
		Success:                 true,
		RestoreID:               "0123456789abcdef0123456789abcdef",
		DestinationApprovalMode: "manual_default",
		PolicyComparison:        "identical",
		UnknownSourceSettings: []string{
			"source.user_auto_approve",
			"source.genesis_hash_mappings",
			"source.node_role",
			"source.future_setting",
		},
		SourceSettingsStatus:  protocol.RecoverySourceSettingsStatusUnverified,
		SourceUserAutoApprove: &autoApprove,
		SourceGenesisHashMappings: []protocol.RecoveryGenesisHashMapping{{
			GenesisHash: "REREREREREREREREREREREREREREREREREREREREREQ=",
			Network:     "private-network",
		}},
		ReviewToken: strings.Repeat("c", 64),
	}
	m := Model{
		viewState: ViewRestoreReview,
		restore: restoreState{
			restoreID: review.RestoreID,
			review:    review,
		},
	}

	rendered := stripANSI(m.renderRestoreReview())
	policyHeadingIndex := strings.Index(rendered, "Policy differences (informational)")
	metadataHeadingIndex := strings.Index(rendered, "Source metadata unavailable for this archive")
	contextHeadingIndex := strings.Index(rendered, "Reported by the backup archive")
	if policyHeadingIndex < 0 || metadataHeadingIndex < policyHeadingIndex ||
		contextHeadingIndex < metadataHeadingIndex {
		t.Fatalf("review sections are out of order:\n%s", rendered)
	}
	differences := rendered[policyHeadingIndex:metadataHeadingIndex]
	if !strings.Contains(differences, "none") {
		t.Fatalf("review omitted the empty policy-difference result:\n%s", rendered)
	}
	// Constant archive limitations belong to the format note, not the bullets.
	for _, constant := range []string{"source.user_auto_approve", "source.genesis_hash_mappings"} {
		if strings.Contains(rendered, "[unknown source] "+constant) {
			t.Fatalf("review rendered constant limitation %q as a finding:\n%s", constant, rendered)
		}
	}
	metadata := rendered[metadataHeadingIndex:contextHeadingIndex]
	if !strings.Contains(metadata, "source.node_role") ||
		!strings.Contains(metadata, "source.future_setting") {
		t.Fatalf("review dropped batch-specific source metadata:\n%s", rendered)
	}
	if !strings.Contains(rendered, "approval default: manual review") ||
		!strings.Contains(rendered, "private-network") {
		t.Fatalf("review omitted typed source context:\n%s", rendered)
	}
	// Invariant prose belongs in the documentation, not on every review.
	for _, constant := range []string{
		"Backup archives do not record",
		"cannot be authenticated",
		"Unverified",
	} {
		if strings.Contains(rendered, constant) {
			t.Fatalf("review repeated invariant prose %q:\n%s", constant, rendered)
		}
	}
	if strings.Contains(rendered, "Required acknowledgement") {
		t.Fatalf("manual-default review rendered an acknowledgement:\n%s", rendered)
	}
}

func TestRestoreReviewIdenticalPolicyActivatesWithoutAcknowledgement(t *testing.T) {
	m := Model{
		viewState: ViewRestoring,
		restore: restoreState{
			restoreID: "0123456789abcdef0123456789abcdef",
		},
	}
	m, _ = updateForTest(t, m, ReviewRecoveredResultMsg{Result: ReviewRecoveredResultMessage{
		Success:                 true,
		RestoreID:               m.restore.restoreID,
		DestinationApprovalMode: "manual_default",
		PolicyComparison:        "identical",
		ReviewToken:             strings.Repeat("f", 64),
	}})
	rendered := stripANSI(m.renderRestoreReview())
	if strings.Contains(rendered, "Required acknowledgements") ||
		strings.Contains(rendered, "I acknowledge the destination policy downgrade") {
		t.Fatalf("identical policy review rendered an acknowledgement:\n%s", rendered)
	}

	m, cmd := updateForTest(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.viewState != ViewRestoring || cmd == nil {
		t.Fatalf("activation without acknowledgement state=%v cmd=%v", m.viewState, cmd)
	}
}

func TestRestoreReviewAutoApproveRequiresUnattendedAcknowledgement(t *testing.T) {
	unattendedAckRequired := true
	m := Model{
		viewState: ViewRestoring,
		restore: restoreState{
			restoreID: "0123456789abcdef0123456789abcdef",
		},
	}
	m, _ = updateForTest(t, m, ReviewRecoveredResultMsg{Result: ReviewRecoveredResultMessage{
		Success:                      true,
		RestoreID:                    m.restore.restoreID,
		DestinationApprovalMode:      "auto_approve_fallback",
		UnattendedSigningWarning:     "you are activating into an auto-approving identity",
		PolicyComparison:             "identical",
		ReviewToken:                  strings.Repeat("1", 64),
		UnattendedSigningAckRequired: &unattendedAckRequired,
	}})
	rendered := stripANSI(m.renderRestoreReview())
	if !strings.Contains(rendered, "I acknowledge this identity auto-approves unmatched signing requests") {
		t.Fatalf("auto-approve review omitted its acknowledgement:\n%s", rendered)
	}

	m, _ = updateForTest(t, m, tea.KeyMsg{Type: tea.KeySpace})
	m, _ = updateForTest(t, m, tea.KeyMsg{Type: tea.KeyTab})
	m, cmd := updateForTest(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.viewState != ViewRestoring || cmd == nil {
		t.Fatalf("unattended-only acknowledgement state=%v cmd=%v", m.viewState, cmd)
	}
}

// Committing is a deliberate act on a focused button on both restore screens,
// so Enter while navigating cannot start a recovery or an activation.
func TestRestoreScreensCommitOnlyFromTheirButton(t *testing.T) {
	preview := Model{
		viewState: ViewRestorePreview,
		restore: restoreState{
			archivePath: "aplane-backup.tar.gz",
			passphrase:  []byte("export"),
			previewKeys: []RestoreKeyInfo{{Address: "NEWADDR", KeyType: "ed25519"}},
			selected:    map[string]bool{"NEWADDR": true},
		},
	}
	next, cmd := preview.handleRestorePreviewKeys(tea.KeyMsg{Type: tea.KeyEnter})
	if got := next.(Model); got.viewState != ViewRestorePreview || cmd != nil {
		t.Fatalf("enter on the key list started a recovery: viewState=%v cmd=%v", got.viewState, cmd)
	}
	if len(preview.restore.passphrase) == 0 {
		t.Fatal("enter on the key list cleared the export passphrase")
	}

	review := Model{
		viewState: ViewRestoreReview,
		restore: restoreState{
			restoreID: "0123456789abcdef0123456789abcdef",
			review: ReviewRecoveredResultMessage{
				Success:                 true,
				RestoreID:               "0123456789abcdef0123456789abcdef",
				DestinationApprovalMode: "manual_default",
				ReviewToken:             strings.Repeat("a", 64),
			},
			reviewFocus: restoreFocusList,
		},
	}
	next, cmd = review.handleRestoreReviewKeys(tea.KeyMsg{Type: tea.KeyEnter})
	if got := next.(Model); got.viewState != ViewRestoreReview || cmd != nil {
		t.Fatalf("enter off the button started an activation: viewState=%v cmd=%v", got.viewState, cmd)
	}
}

func TestRestoreReviewWithoutAcknowledgementActivatesDirectly(t *testing.T) {
	unattendedAckRequired := false
	m := Model{
		viewState: ViewRestoring,
		restore: restoreState{
			restoreID: "0123456789abcdef0123456789abcdef",
		},
	}
	m, _ = updateForTest(t, m, ReviewRecoveredResultMsg{Result: ReviewRecoveredResultMessage{
		Success:                      true,
		RestoreID:                    m.restore.restoreID,
		DestinationApprovalMode:      "auto_approve_fallback",
		PolicyComparison:             "identical",
		ReviewToken:                  strings.Repeat("2", 64),
		UnattendedSigningAckRequired: &unattendedAckRequired,
	}})
	rendered := stripANSI(m.renderRestoreReview())
	if strings.Contains(rendered, "Required acknowledgements") ||
		strings.Contains(rendered, "I acknowledge") {
		t.Fatalf("same-auto-approve review rendered an acknowledgement:\n%s", rendered)
	}

	m, cmd := updateForTest(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.viewState != ViewRestoring || cmd == nil {
		t.Fatalf("same-auto-approve activation state=%v cmd=%v", m.viewState, cmd)
	}
}

func TestKeyListRestoreShortcutOpensRestoreList(t *testing.T) {
	m := Model{
		viewState: ViewKeyList,
	}

	next, cmd := m.handleKeyListKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}})
	got := next.(Model)
	if got.viewState != ViewRestoreList {
		t.Fatalf("viewState = %v, want ViewRestoreList", got.viewState)
	}
	if got.restore.backupsLoaded {
		t.Fatal("restoreBackupsLoaded = true, want false while list request is in flight")
	}
	if cmd == nil {
		t.Fatal("cmd = nil, want backup list command")
	}
}

func TestRestoreListCancelReturnsToKeyList(t *testing.T) {
	archivePath := filepath.Join(t.TempDir(), "backups", "default", "aplane-backup.tar.gz")
	m := Model{
		viewState: ViewRestoreList,
		restore: restoreState{backupsLoaded: true, backups: []BackupInfo{{
			Path:     archivePath,
			FileName: "aplane-backup.tar.gz",
		}}, selectedBackup: 0},
	}

	next, cmd := m.handleRestoreListKeys(tea.KeyMsg{Type: tea.KeyEsc})
	got := next.(Model)
	if got.viewState != ViewKeyList {
		t.Fatalf("viewState = %v, want ViewKeyList", got.viewState)
	}
	if got.restore.backupsLoaded || len(got.restore.backups) != 0 {
		t.Fatalf("restore list state was not reset: %+v", got)
	}
	if cmd != nil {
		t.Fatalf("cmd = %v, want nil", cmd)
	}
}

func TestRenderRestoreListShowsBackupDirectory(t *testing.T) {
	dataDir := t.TempDir()
	m := Model{
		width:     120,
		height:    30,
		dataDir:   dataDir,
		viewState: ViewRestoreList,
		restore: restoreState{backupsLoaded: true, backups: []BackupInfo{{
			Path:     filepath.Join(dataDir, "backups", "default", "aplane-backup.tar.gz"),
			FileName: "aplane-backup.tar.gz",
			Size:     4096,
		}}},
	}

	view := stripANSI(m.renderRestoreList())
	wantPath := filepath.Join(dataDir, "backups") + string(filepath.Separator)
	if !strings.Contains(view, "Backup Directory:") || !strings.Contains(view, wantPath) {
		t.Fatalf("restore list missing backup directory:\n%s", view)
	}
}

func TestBackupsListResponsePopulatesRestoreBrowser(t *testing.T) {
	m := Model{viewState: ViewRestoreList}
	archivePath := filepath.Join(t.TempDir(), "backups", "default", "backup.tar.gz")

	next, _ := m.Update(BackupsListMsg{
		Backups: []BackupInfo{{
			Path:     archivePath,
			FileName: "backup.tar.gz",
			Size:     4096,
		}},
	})
	got := next.(Model)
	if got.viewState != ViewRestoreList {
		t.Fatalf("viewState = %v, want ViewRestoreList", got.viewState)
	}
	if !got.restore.backupsLoaded {
		t.Fatal("restoreBackupsLoaded = false, want true")
	}
	if len(got.restore.backups) != 1 || got.restore.backups[0].FileName != "backup.tar.gz" {
		t.Fatalf("restoreBackups = %+v, want backup.tar.gz", got.restore.backups)
	}
}

func TestRestorePreviewPreselectsOnlyNewKeysAndKeepsPassphrase(t *testing.T) {
	archivePath := filepath.Join(t.TempDir(), "aplane-backup.tar.gz")
	m := Model{
		viewState: ViewRestorePassphrase,
		restore:   restoreState{archivePath: archivePath, passphrase: []byte("export-passphrase"), previewing: true},
	}

	next, _ := m.Update(RestorePreviewMsg{
		ArchivePath: archivePath,
		Keys: []RestoreKeyInfo{
			{Address: "NEWADDR", KeyType: "ed25519"},
			{Address: "EXISTINGADDR", KeyType: "ed25519", AlreadyExists: true},
		},
	})
	got := next.(Model)
	if got.viewState != ViewRestorePreview {
		t.Fatalf("viewState = %v, want ViewRestorePreview", got.viewState)
	}
	if got.restore.previewing {
		t.Fatal("restorePreviewing = true, want false")
	}
	if string(got.restore.passphrase) != "export-passphrase" {
		t.Fatalf("restorePassphrase = %q, want retained passphrase for restore", string(got.restore.passphrase))
	}
	if !got.restore.selected["NEWADDR"] {
		t.Fatal("new key was not preselected")
	}
	if got.restore.selected["EXISTINGADDR"] {
		t.Fatal("existing key was preselected without overwrite")
	}
}

func TestRestorePreviewFailureClearsPassphrase(t *testing.T) {
	archivePath := filepath.Join(t.TempDir(), "aplane-backup.tar.gz")
	passphrase := []byte("export-passphrase")
	m := Model{
		viewState: ViewRestorePassphrase,
		restore:   restoreState{archivePath: archivePath, passphrase: passphrase, previewing: true},
	}

	next, _ := m.Update(RestorePreviewMsg{
		Errors: []RestoreError{{Error: "invalid backup export passphrase"}},
	})
	got := next.(Model)
	if got.viewState != ViewRestorePassphrase {
		t.Fatalf("viewState = %v, want ViewRestorePassphrase", got.viewState)
	}
	if got.restore.previewing {
		t.Fatal("restorePreviewing = true, want false")
	}
	if len(got.restore.passphrase) != 0 {
		t.Fatalf("restorePassphrase length = %d, want 0", len(got.restore.passphrase))
	}
	for i, b := range passphrase {
		if b != 0 {
			t.Fatalf("passphrase byte %d = %d, want zero", i, b)
		}
	}
	if got.restore.passphraseError == "" {
		t.Fatal("restorePassphraseError is empty")
	}
}

func TestRestorePreviewSelectsExistingKeysFreely(t *testing.T) {
	// Recovery is inactive and never overwrites anything: conflict rows are
	// informational, and the replace-existing consent lives on the
	// activation review beside the exact conflicts it authorizes.
	m := Model{
		viewState: ViewRestorePreview,
		restore: restoreState{previewKeys: []RestoreKeyInfo{
			{Address: "EXISTINGADDR", KeyType: "ed25519", AlreadyExists: true},
		}, selected: make(map[string]bool)},
	}

	next, _ := m.handleRestorePreviewKeys(tea.KeyMsg{Type: tea.KeySpace})
	got := next.(Model)
	if !got.restore.selected["EXISTINGADDR"] {
		t.Fatal("existing key was not freely selectable on the preview")
	}
	if got.restore.previewError != "" {
		t.Fatalf("previewError = %q, want none for an informational conflict", got.restore.previewError)
	}

	view := got.renderRestorePreview()
	plain := stripANSI(view)
	if !strings.Contains(plain, "exists") {
		t.Fatalf("preview does not mark the conflicting key informationally:\n%s", plain)
	}
	if strings.Contains(plain, "Overwrite:") {
		t.Fatalf("preview still renders the removed overwrite toggle:\n%s", plain)
	}
}

func TestRestorePreviewRendersScrollableKeyWindowLikeKeyList(t *testing.T) {
	keys := make([]RestoreKeyInfo, 0, 6)
	for i := 0; i < 6; i++ {
		keys = append(keys, RestoreKeyInfo{
			Address: fmt.Sprintf("RESTOREADDR%02d", i),
			KeyType: "ed25519",
		})
	}
	m := Model{
		viewState: ViewRestorePreview,
		height:    16,
		restore:   restoreState{previewKeys: keys, selected: map[string]bool{"RESTOREADDR00": true}},
	}

	view := m.renderRestorePreview()
	if !strings.Contains(view, "> ") || !strings.Contains(view, "RESTOREADDR00") {
		t.Fatalf("rendered restore key list does not show selected key like main key list:\n%s", view)
	}
	if !strings.Contains(view, "▼ 4 more below") {
		t.Fatalf("rendered restore key list missing scroll-down indicator:\n%s", view)
	}
	if !strings.Contains(view, "Total: 6 keys") {
		t.Fatalf("rendered restore key list missing total count:\n%s", view)
	}
	if strings.Contains(view, "RESTOREADDR05") {
		t.Fatalf("rendered restore key list shows item outside visible window:\n%s", view)
	}

	for range 4 {
		next, _ := m.Update(tea.KeyMsg{Type: tea.KeyDown})
		m = next.(Model)
	}
	if m.restore.previewScrollOffset == 0 {
		t.Fatal("restorePreviewScrollOffset = 0, want scrolled window")
	}

	view = m.renderRestorePreview()
	if !strings.Contains(view, "▲ 3 more above") {
		t.Fatalf("rendered restore key list missing scroll-up indicator:\n%s", view)
	}
	if !strings.Contains(view, "> ") || !strings.Contains(view, "RESTOREADDR04") {
		t.Fatalf("rendered restore key list does not keep selected key visible:\n%s", view)
	}
}

func TestRestorePreviewPopupFitsTerminalHeight(t *testing.T) {
	keys := make([]RestoreKeyInfo, 0, 8)
	selected := make(map[string]bool)
	for i := 0; i < 8; i++ {
		address := fmt.Sprintf("RESTOREADDR%02d", i)
		keys = append(keys, RestoreKeyInfo{
			Address: address,
			KeyType: "ed25519",
		})
		selected[address] = true
	}
	m := Model{
		viewState: ViewRestorePreview,
		width:     90,
		height:    16,
		restore:   restoreState{previewKeys: keys, selected: selected, selectedKey: 4, previewScrollOffset: 3},
	}

	view := m.renderRestorePreview()
	if lines := visibleLineCount(view); lines > m.height {
		t.Fatalf("restore preview line count = %d, want <= %d\n%s", lines, m.height, stripANSI(view))
	}
	if !strings.Contains(stripANSI(view), "▲ 3 more above") || !strings.Contains(stripANSI(view), "▼ 3 more below") {
		t.Fatalf("height-constrained restore preview missing scroll indicators:\n%s", stripANSI(view))
	}
}

func TestRestorePreviewReservesContinuationRows(t *testing.T) {
	noContinuation := Model{
		viewState: ViewRestorePreview,
		width:     90,
		height:    16,
		restore: restoreState{previewKeys: []RestoreKeyInfo{
			{Address: "RESTOREADDR00", KeyType: "ed25519"},
			{Address: "RESTOREADDR01", KeyType: "ed25519"},
		}, selected: map[string]bool{"RESTOREADDR00": true}},
	}

	keys := make([]RestoreKeyInfo, 0, 8)
	selected := make(map[string]bool)
	for i := 0; i < 8; i++ {
		address := fmt.Sprintf("RESTOREADDR%02d", i)
		keys = append(keys, RestoreKeyInfo{
			Address: address,
			KeyType: "ed25519",
		})
		selected[address] = true
	}
	withContinuation := Model{
		viewState: ViewRestorePreview,
		width:     90,
		height:    16,
		restore:   restoreState{previewKeys: keys, selected: selected, selectedKey: 4, previewScrollOffset: 3},
	}

	noContinuationView := noContinuation.renderRestorePreview()
	withContinuationView := withContinuation.renderRestorePreview()
	if strings.Contains(stripANSI(noContinuationView), "more above") || strings.Contains(stripANSI(noContinuationView), "more below") {
		t.Fatalf("restore preview without continuation unexpectedly rendered indicator text:\n%s", stripANSI(noContinuationView))
	}
	if got, want := visibleLineCount(noContinuationView), visibleLineCount(withContinuationView); got != want {
		t.Fatalf("restore preview line count without continuation = %d, with continuation = %d\nwithout:\n%s\nwith:\n%s",
			got, want, stripANSI(noContinuationView), stripANSI(withContinuationView))
	}
}

func TestRestoreDisplayPopupFitsTerminalHeightAndScrollsRestoredKeys(t *testing.T) {
	archivePath := filepath.Join(t.TempDir(), "backups", "default", "aplane-backup.tar.gz")
	restored := make([]RestoreKeyInfo, 0, 8)
	for i := 0; i < 8; i++ {
		restored = append(restored, RestoreKeyInfo{
			Address: fmt.Sprintf("RESTOREDADDR%02d", i),
			KeyType: "ed25519",
		})
	}
	m := Model{
		viewState: ViewRestoreDisplay,
		width:     90,
		height:    21,
		restore: restoreState{result: RestoreDisplayResult{
			ArchivePath: archivePath,
			Activated:   restored,
			Success:     true,
		}},
	}

	view := m.renderRestoreDisplay()
	clean := stripANSI(view)
	if lines := visibleLineCount(view); lines > m.height {
		t.Fatalf("restore display line count = %d, want <= %d\n%s", lines, m.height, clean)
	}
	if !strings.Contains(clean, "▼") || !strings.Contains(clean, "more below") {
		t.Fatalf("restore display missing scroll-down indicator:\n%s", clean)
	}
	if strings.Contains(clean, "RESTOREDADDR07") {
		t.Fatalf("restore display shows key outside initial window:\n%s", clean)
	}
	if !strings.Contains(clean, "> RESTOREDADDR00  [ed25519]") {
		t.Fatalf("restore display missing selected cursor on first row:\n%s", clean)
	}

	for range 5 {
		next, _ := m.Update(tea.KeyMsg{Type: tea.KeyDown})
		m = next.(Model)
	}
	view = m.renderRestoreDisplay()
	clean = stripANSI(view)
	if lines := visibleLineCount(view); lines > m.height {
		t.Fatalf("scrolled restore display line count = %d, want <= %d\n%s", lines, m.height, clean)
	}
	if !strings.Contains(clean, "▲") || !strings.Contains(clean, "more above") {
		t.Fatalf("scrolled restore display missing scroll-up indicator:\n%s", clean)
	}
	if !strings.Contains(clean, "RESTOREDADDR05") {
		t.Fatalf("scrolled restore display missing later restored key:\n%s", clean)
	}
	if !strings.Contains(clean, "> RESTOREDADDR05  [ed25519]") {
		t.Fatalf("scrolled restore display did not move cursor to later key:\n%s", clean)
	}
}

func TestRestoreSubmitClearsPassphrase(t *testing.T) {
	archivePath := filepath.Join(t.TempDir(), "aplane-backup.tar.gz")
	passphrase := []byte("export-passphrase")
	m := Model{
		viewState: ViewRestorePreview,
		restore: restoreState{archivePath: archivePath, passphrase: passphrase, previewKeys: []RestoreKeyInfo{
			{Address: "NEWADDR", KeyType: "ed25519"},
		}, selected: map[string]bool{"NEWADDR": true}, previewFocus: restoreFocusAction},
	}

	next, cmd := m.handleRestorePreviewKeys(tea.KeyMsg{Type: tea.KeyEnter})
	got := next.(Model)
	if got.viewState != ViewRestoring {
		t.Fatalf("viewState = %v, want ViewRestoring", got.viewState)
	}
	if len(got.restore.passphrase) != 0 {
		t.Fatalf("restorePassphrase length = %d, want 0", len(got.restore.passphrase))
	}
	for i, b := range passphrase {
		if b != 0 {
			t.Fatalf("passphrase byte %d = %d, want zero", i, b)
		}
	}
	if cmd == nil {
		t.Fatal("cmd = nil, want restore command")
	}
}

var ansiRE = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func stripANSI(s string) string {
	return ansiRE.ReplaceAllString(s, "")
}

func visibleWidth(s string) int {
	return len([]rune(stripANSI(s)))
}

func visibleLineCount(s string) int {
	return len(strings.Split(strings.TrimRight(stripANSI(s), "\n"), "\n"))
}

func updateForTest(t *testing.T, m Model, msg tea.Msg) (Model, tea.Cmd) {
	t.Helper()

	next, cmd := m.Update(msg)
	got, ok := next.(Model)
	if !ok {
		t.Fatalf("Update(%T) returned %T, want Model", msg, next)
	}
	return got, cmd
}

func updateTextForTest(t *testing.T, m Model, text string) Model {
	t.Helper()

	for _, r := range text {
		var msg tea.KeyMsg
		if r == ' ' {
			msg = tea.KeyMsg{Type: tea.KeySpace}
		} else {
			msg = tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}}
		}
		var cmd tea.Cmd
		m, cmd = updateForTest(t, m, msg)
		if cmd != nil {
			t.Fatalf("text key %q returned unexpected cmd", string(r))
		}
	}
	return m
}
