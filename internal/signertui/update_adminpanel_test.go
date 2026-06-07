// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/adminproto"
	tea "github.com/charmbracelet/bubbletea"
)

func TestValidateAdminSettingValuePassphraseTimeout(t *testing.T) {
	if err := validateAdminSettingValue(adminproto.AdminSettingPassphraseTimeout, "15m"); err != nil {
		t.Fatalf("validateAdminSettingValue(valid) error = %v", err)
	}
	if err := validateAdminSettingValue(adminproto.AdminSettingPassphraseTimeout, "nope"); err == nil {
		t.Fatal("validateAdminSettingValue(invalid) error = nil, want parse rejection")
	}
}

func TestAdminRowsGroupEditableSettingsFirst(t *testing.T) {
	m := Model{
		transportLabel: "IPC",
		adminSettings: &AdminSettings{
			UserAutoApprove:   false,
			LockOnDisconnect:  false,
			PassphraseTimeout: "15m0s",
			PassphraseMethod:  "none",
			Theme:             "dark",
			SignerPort:        4010,
			TEALCompileNet:    "testnet",
		},
	}

	rows := m.adminRows()
	wantLabels := []string{
		"User Auto-Approve",
		"Lock-on-disconnect",
		"Passphrase timeout",
		"Color theme",
	}
	for i, want := range wantLabels {
		if rows[i].label != want {
			t.Fatalf("row %d label = %q, want %q", i, rows[i].label, want)
		}
		if rows[i].section != "User-Editable" {
			t.Fatalf("row %d section = %q, want User-Editable", i, rows[i].section)
		}
		if !rows[i].editable {
			t.Fatalf("row %d editable = false, want true", i)
		}
	}
	if rows[4].section != "Runtime" || rows[4].label != "Admin transport" {
		t.Fatalf("row 4 = %q/%q, want Runtime/Admin transport", rows[4].section, rows[4].label)
	}
	if rows[5].section != "Runtime" || rows[5].label != "Node role" || rows[5].value != "signer" {
		t.Fatalf("row 5 = %q/%q/%q, want Runtime/Node role/signer", rows[5].section, rows[5].label, rows[5].value)
	}
	if rows[0].key != adminproto.AdminSettingUserAutoApprove || rows[0].value != "false" {
		t.Fatalf("user auto-approve row = key %q value %q, want user_auto_approve/false", rows[0].key, rows[0].value)
	}

	rendered := stripANSI(m.renderAdminPanel())
	editable := strings.Index(rendered, "User-Editable")
	runtime := strings.Index(rendered, "Runtime")
	userAutoApprove := strings.Index(rendered, "User Auto-Approve")
	adminTransport := strings.Index(rendered, "Admin transport")
	if editable < 0 || runtime < 0 || userAutoApprove < 0 || adminTransport < 0 {
		t.Fatalf("renderAdminPanel() missing expected settings sections:\n%s", rendered)
	}
	if editable >= userAutoApprove || userAutoApprove >= runtime || runtime >= adminTransport {
		t.Fatalf("settings section order is wrong:\n%s", rendered)
	}
}

func TestAdminPanelKShortcutOpensKeyTypes(t *testing.T) {
	m := Model{
		viewState:       ViewAdminPanel,
		adminEditingRow: -1,
		adminSettings: &AdminSettings{
			PassphraseMethod: "none",
			Theme:            "auto",
		},
	}

	next, cmd := m.handleAdminPanelKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'k'}})
	got := next.(Model)
	if got.viewState != ViewTemplateLibrary {
		t.Fatalf("viewState = %v, want ViewTemplateLibrary", got.viewState)
	}
	if cmd == nil {
		t.Fatal("cmd = nil, want list templates command")
	}
}

func TestAdminPanelPolicyShortcutOpensReadOnlyViewer(t *testing.T) {
	m := Model{
		viewState:       ViewAdminPanel,
		adminEditingRow: -1,
		adminSettings: &AdminSettings{
			PassphraseMethod: "none",
			Theme:            "auto",
		},
	}

	next, cmd := m.handleAdminPanelKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'p'}})
	got := next.(Model)
	if got.viewState != ViewPolicyViewer {
		t.Fatalf("viewState = %v, want ViewPolicyViewer", got.viewState)
	}
	if !got.policyViewLoading {
		t.Fatal("policyViewLoading = false, want true")
	}
	if cmd == nil {
		t.Fatal("cmd = nil, want policy snapshot request command")
	}

	rendered := stripANSI(m.View())
	if !strings.Contains(rendered, "p: Policy") {
		t.Fatalf("View() does not advertise policy shortcut:\n%s", rendered)
	}
}

func TestAdminPanelPolicyRowOpensReadOnlyViewer(t *testing.T) {
	m := Model{
		viewState:       ViewAdminPanel,
		adminEditingRow: -1,
		adminSettings: &AdminSettings{
			PassphraseMethod: "none",
			Theme:            "auto",
		},
	}
	found := false
	for i, row := range m.adminRows() {
		if row.action == "open_policy" {
			m.adminSelectedRow = i
			found = true
			break
		}
	}
	if !found {
		t.Fatal("adminRows() missing open_policy row")
	}

	next, cmd := m.handleAdminPanelKeys(tea.KeyMsg{Type: tea.KeyEnter})
	got := next.(Model)
	if got.viewState != ViewPolicyViewer {
		t.Fatalf("viewState = %v, want ViewPolicyViewer", got.viewState)
	}
	if cmd == nil {
		t.Fatal("cmd = nil, want policy snapshot request command")
	}
}

func TestAdminPanelTShortcutOpensRevokeTokenConfirm(t *testing.T) {
	m := Model{
		viewState:       ViewAdminPanel,
		adminEditingRow: -1,
		adminSettings: &AdminSettings{
			PassphraseMethod: "none",
			Theme:            "auto",
		},
	}

	next, cmd := m.handleAdminPanelKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'t'}})
	got := next.(Model)
	if got.viewState != ViewRevokeTokenConfirm {
		t.Fatalf("viewState = %v, want ViewRevokeTokenConfirm", got.viewState)
	}
	if cmd != nil {
		t.Fatalf("cmd = %v, want nil", cmd)
	}
}

func TestAdminPanelLockShortcutOpensLockConfirm(t *testing.T) {
	m := Model{
		viewState:       ViewAdminPanel,
		adminEditingRow: -1,
		adminSettings: &AdminSettings{
			PassphraseMethod: "none",
			Theme:            "auto",
		},
	}

	next, cmd := m.handleAdminPanelKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'l'}})
	got := next.(Model)
	if got.viewState != ViewLockConfirm {
		t.Fatalf("viewState = %v, want ViewLockConfirm", got.viewState)
	}
	if got.manualLockReturnView != ViewAdminPanel {
		t.Fatalf("manualLockReturnView = %v, want ViewAdminPanel", got.manualLockReturnView)
	}
	if cmd != nil {
		t.Fatalf("cmd = %v, want nil", cmd)
	}
}
