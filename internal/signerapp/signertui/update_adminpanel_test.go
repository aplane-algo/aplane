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
// coded applied_not_durable and shown as a warning that does not say
// "failed"; it once read "Setting update failed" like a refused change.
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
	next, cmd := m.Update(AdminSettingUpdatedMsg{
		Success: false, Key: adminproto.AdminSettingUserAutoApprove, Value: "true", Code: protocol.ResultCodeAppliedNotDurable,
		Error: "user_auto_approve is set to true and in effect, but its durability is not confirmed: file replaced, but its directory sync failed: injected",
	})
	want := "Setting in effect, durability not confirmed: user_auto_approve"
	if got := next.(Model); got.lastError != "" || got.lastWarning != want {
		t.Fatalf("lastError = %q, lastWarning = %q; want no error and the warning %q", got.lastError, got.lastWarning, want)
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

// The applied_not_durable warning stays on screen, as a failure would, until
// the next key on the admin panel. It once cleared itself after 5s.
func TestSettingNotDurableWarningStaysUntilTheNextAdminPanelKey(t *testing.T) {
	m := approvalTestModel(ViewAdminPanel)
	m.admin.settings = &AdminSettings{}
	next, cmd := m.Update(AdminSettingUpdatedMsg{
		Success: false, Key: adminproto.AdminSettingUserAutoApprove, Value: "true", Code: protocol.ResultCodeAppliedNotDurable,
	})
	if next.(Model).lastWarning == "" {
		t.Fatal("no warning shown for a setting in effect with its durability unconfirmed")
	}
	// Nothing is scheduled to clear it: with no client, every command the
	// update returns completes at once, and a clearing timer would not.
	ran := make(chan struct{})
	go func() {
		defer close(ran)
		if batch, ok := cmd().(tea.BatchMsg); ok {
			for _, c := range batch {
				c()
			}
		}
	}()
	select {
	case <-ran:
	case <-time.After(2 * time.Second):
		t.Fatal("the update scheduled a command that clears the warning later")
	}
	next, _ = next.(Model).Update(tea.KeyMsg{Type: tea.KeyDown})
	if got := next.(Model).lastWarning; got != "" {
		t.Fatalf("warning after the next admin panel key = %q, want it cleared", got)
	}
}

// The durability warning names the setting, not the echoed request value,
// which can differ from what the signer stored (a theme is lower-cased), and
// it shows only on the admin panel, not in the status line of a view the
// operator moved to before the result arrived.
func TestSettingNotDurableWarningShowsOnlyOnTheAdminPanel(t *testing.T) {
	m := approvalTestModel(ViewKeyList)
	next, _ := m.Update(AdminSettingUpdatedMsg{
		Success: false, Key: adminproto.AdminSettingTheme, Value: "Dark", Code: protocol.ResultCodeAppliedNotDurable,
	})
	m = next.(Model)
	if strings.Contains(m.lastWarning, "Dark") {
		t.Fatalf("warning = %q, want it without the echoed value", m.lastWarning)
	}
	if bar := m.renderStatusBar(); strings.Contains(bar, "durability not confirmed") {
		t.Fatalf("status bar on the key list = %q, want no durability warning there", bar)
	}
	m.viewState = ViewAdminPanel
	if bar := m.renderStatusBar(); !strings.Contains(bar, "durability not confirmed: theme") {
		t.Fatalf("status bar on the admin panel = %q, want the durability warning", bar)
	}
}
