// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/protocol"
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
		admin: adminPanelState{settings: &AdminSettings{
			UserAutoApprove:   false,
			LockOnDisconnect:  false,
			PassphraseTimeout: "15m0s",
			PassphraseMethod:  "none",
			Theme:             "dark",
			SignerPort:        4010,
			TEALCompileNet:    "testnet",
		}},
	}

	rows := m.adminRows()
	wantLabels := []string{
		"User Auto-Approve",
		"Lock-on-disconnect",
		"Passphrase timeout",
		"Color theme",
		"Require contained accounts",
		"Require cosigned accounts",
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
	if rows[6].section != "Runtime" || rows[6].label != "Admin transport" {
		t.Fatalf("row 6 = %q/%q, want Runtime/Admin transport", rows[6].section, rows[6].label)
	}
	if rows[7].section != "Runtime" || rows[7].label != "Node role" || rows[7].value != "signer" {
		t.Fatalf("row 7 = %q/%q/%q, want Runtime/Node role/signer", rows[7].section, rows[7].label, rows[7].value)
	}
	if rows[9].section != "Runtime" || rows[9].label != "Signer Port" || rows[9].value != "4010" {
		t.Fatalf("row 9 = %q/%q/%q, want Runtime/Signer Port/4010", rows[9].section, rows[9].label, rows[9].value)
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

func TestAdminRowsUseCosignerPortLabelForCosignerNodes(t *testing.T) {
	m := Model{admin: adminPanelState{settings: &AdminSettings{
		NodeRole:         "cosigner",
		PassphraseMethod: "none",
		SignerPort:       11270,
	}},
	}

	rows := m.adminRows()
	if rows[7].label != "Cosigner Port" || rows[7].value != "11270" {
		t.Fatalf("port row = %q/%q, want Cosigner Port/11270", rows[7].label, rows[7].value)
	}
}

func TestAdminPanelKShortcutOpensKeyTypes(t *testing.T) {
	m := Model{
		viewState: ViewAdminPanel,
		admin: adminPanelState{editingRow: -1, settings: &AdminSettings{
			PassphraseMethod: "none",
			Theme:            "auto",
		}},
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

func TestAdminPanelLockShortcutOpensLockConfirm(t *testing.T) {
	m := Model{
		viewState: ViewAdminPanel,
		admin: adminPanelState{editingRow: -1, settings: &AdminSettings{
			PassphraseMethod: "none",
			Theme:            "auto",
		}},
	}

	next, cmd := m.handleAdminPanelKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'l'}})
	got := next.(Model)
	if got.viewState != ViewLockConfirm {
		t.Fatalf("viewState = %v, want ViewLockConfirm", got.viewState)
	}
	if got.manualLock.returnView != ViewAdminPanel {
		t.Fatalf("manualLockReturnView = %v, want ViewAdminPanel", got.manualLock.returnView)
	}
	if cmd != nil {
		t.Fatalf("cmd = %v, want nil", cmd)
	}
}

func TestBoundedSettingsAreHiddenOnCosignerNodes(t *testing.T) {
	m := Model{admin: adminPanelState{settings: &AdminSettings{NodeRole: "cosigner"}}}
	for _, row := range m.adminRows() {
		if strings.HasPrefix(row.label, "Bounded:") {
			t.Fatalf("a cosigner node offers %q", row.label)
		}
	}
}

// A failed setting update can still be in effect (saved, its durability
// unconfirmed), so the panel re-reads the settings after a failure as after a
// success, instead of keeping the value it showed before. That result is
// coded applied_not_durable and shown as a warning; it once read "Setting
// update failed" like a refused change.
func TestFailedSettingUpdateRereadsTheSettings(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer func() { _ = serverConn.Close() }()
	client := NewAdminClient(&queueConnector{conns: []io.ReadWriteCloser{clientConn}})
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer client.Disconnect()

	sent := make(chan string, 4)
	go func() {
		reader := bufio.NewReader(serverConn)
		for {
			line, err := reader.ReadBytes('\n')
			if err != nil {
				return
			}
			var base protocol.BaseMessage
			if json.Unmarshal(line, &base) == nil {
				sent <- base.Type
			}
		}
	}()

	m := approvalTestModel(ViewAdminPanel)
	m.adminClient = client
	m.admin.settings = &AdminSettings{UserAutoApprove: false}
	inEffect := "user_auto_approve is set to true and in effect, but its durability is not confirmed: injected"
	next, cmd := m.Update(AdminSettingUpdatedMsg{
		Success: false, Key: adminproto.AdminSettingUserAutoApprove, Value: "true",
		Code: protocol.ResultCodeAppliedNotDurable, Error: inEffect,
	})
	if got := next.(Model); got.lastError != "" || got.lastWarning != inEffect {
		t.Fatalf("lastError = %q, lastWarning = %q; want no error and the signer's message as a warning", got.lastError, got.lastWarning)
	}
	// A lone listener wait blocks until the client disconnects.
	produced := make(chan tea.Msg, 1)
	go func() { produced <- cmd() }()
	var batch tea.BatchMsg
	select {
	case msg := <-produced:
		var ok bool
		if batch, ok = msg.(tea.BatchMsg); !ok {
			t.Fatalf("command after a failed update = %T, want a batch that re-reads the settings", msg)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the command after a failed update only waits for messages; it does not re-read the settings")
	}
	for _, c := range batch {
		go c()
	}
	select {
	case msgType := <-sent:
		if msgType != protocol.MsgTypeGetAdminSettings {
			t.Fatalf("sent %q after a failed update, want %q", msgType, protocol.MsgTypeGetAdminSettings)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no get_admin_settings sent after a failed update")
	}
}

// A refused or unsaved setting change is shown as a failure.
func TestUnappliedSettingUpdateIsShownAsAFailure(t *testing.T) {
	m := approvalTestModel(ViewAdminPanel)
	next, _ := m.Update(AdminSettingUpdatedMsg{
		Success: false, Key: adminproto.AdminSettingUserAutoApprove, Value: "true",
		Code: protocol.ErrCodeInternal, Error: "failed to save config.yaml; user_auto_approve is unchanged: injected",
	})
	if got := next.(Model); got.lastError != "Setting update failed: failed to save config.yaml; user_auto_approve is unchanged: injected" || got.lastWarning != "" {
		t.Fatalf("lastError = %q, lastWarning = %q; want the failure as an error", got.lastError, got.lastWarning)
	}
}
