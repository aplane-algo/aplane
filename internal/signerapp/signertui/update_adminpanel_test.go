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
	"github.com/charmbracelet/lipgloss"
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

// A failed setting update can still be in effect (saved with its durability
// unconfirmed, or a restrictive change not saved at all), so the panel
// re-reads the settings after a failure as after a success, instead of
// keeping the value it showed before. A saved value whose durability is
// unconfirmed (applied_not_durable) is warned of in words that do not say
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
	want := "user_auto_approve is in effect; its durability is not confirmed"
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

// A refused change, or a permissive one that was not saved, is not in effect
// and is shown as a failure.
func TestUnappliedSettingUpdateIsShownAsAFailure(t *testing.T) {
	m := approvalTestModel(ViewAdminPanel)
	next, _ := m.Update(AdminSettingUpdatedMsg{
		Success: false, Key: adminproto.AdminSettingUserAutoApprove, Value: "true",
		Code: protocol.ErrCodeInternal, Error: "failed to save config.yaml; user_auto_approve is unchanged: injected",
	})
	if got := next.(Model); got.lastError != "Setting update failed: failed to save config.yaml; user_auto_approve is unchanged: injected" ||
		got.lastWarning != "" {
		t.Fatalf("lastError = %q, lastWarning = %q; want the failure as an error", got.lastError, got.lastWarning)
	}
}

// The Settings panel's unsaved-setting warning is drawn from the settings the
// signer reports, so a new login or a second apadmin shows it and nothing the
// TUI receives clears it but settings without the setting: not a key, a
// timer, another warning or error, nor a refusal or other result for the
// setting. It names the setting and says it is in effect, never "failed".
// The warning was once the TUI's own, lost to a login, a second apadmin, or
// the next result for the setting.
func TestUnsavedSettingWarningComesFromTheSigner(t *testing.T) {
	want := "Warning: user_auto_approve is in effect but not saved; a restart reverts it"
	unsaved := AdminSettings{PassphraseMethod: "none", Theme: "auto", UnsavedSettings: []string{adminproto.AdminSettingUserAutoApprove}}

	// A fresh TUI, as after a login or in a second apadmin.
	m := approvalTestModel(ViewAdminPanel)
	next, _ := m.Update(AdminSettingsMsg{Settings: unsaved})
	m = next.(Model)
	panel := stripANSI(m.renderAdminPanel())
	if !strings.Contains(panel, want) || strings.Contains(strings.ToLower(panel), "failed") {
		t.Fatalf("panel from the signer's settings:\n%s\nwant %q and no failure", panel, want)
	}

	for _, msg := range []tea.Msg{
		tea.KeyMsg{Type: tea.KeyDown},
		AdminSettingUpdatedMsg{Success: false, Key: adminproto.AdminSettingUserAutoApprove, Value: "maybe", Code: protocol.ErrCodeInvalidRequest, Error: "refused"},
		AdminSettingUpdatedMsg{Success: true, Key: adminproto.AdminSettingUserAutoApprove, Value: "false"},
		AdminSettingUpdatedMsg{Success: true, Key: adminproto.AdminSettingTheme, Value: "dark"},
	} {
		next, _ = m.Update(msg)
		m = next.(Model)
	}
	m.setTransientWarning("another warning")
	if panel := stripANSI(m.renderAdminPanel()); !strings.Contains(panel, want) {
		t.Fatalf("panel after a key, results for the setting and another warning:\n%s\nwant %q", panel, want)
	}
	if bar := stripANSI(m.renderStatusBar()); strings.Contains(bar, "not saved") {
		t.Fatalf("status bar = %q, want the unsaved warning on the panel only", bar)
	}

	saved := unsaved
	saved.UnsavedSettings = nil
	next, _ = m.Update(AdminSettingsMsg{Settings: saved})
	if panel := stripANSI(next.(Model).renderAdminPanel()); strings.Contains(panel, "not saved") {
		t.Fatalf("panel after the signer reports the setting saved:\n%s\nwant no warning", panel)
	}
}

// Several unsaved settings share the panel's one warning line, which names
// them in key order.
func TestSeveralUnsavedSettingsShareOneWarningLine(t *testing.T) {
	settings := &AdminSettings{PassphraseMethod: "none", Theme: "auto",
		UnsavedSettings: []string{adminproto.AdminSettingUserAutoApprove, adminproto.AdminSettingLockOnDisconnect}}
	m := Model{viewState: ViewAdminPanel, admin: adminPanelState{editingRow: -1, settings: settings}}
	want := "Warning: in effect but not saved: lock_on_disconnect, user_auto_approve"
	if got := m.unsavedSettingsWarning(); got != want {
		t.Fatalf("warning = %q, want %q", got, want)
	}
}

// The panel fits 80x24 with the warning as it does without it: the warning
// takes the title's margin line and is cut to the panel's width, so it adds
// no row, a line naming every restrictive setting included, and is on screen
// whatever the panel shows below it. apadmin is never narrower than MinWidth
// (below it shows only the resize screen, and apconsole's signer pane is
// exactly MinWidth), so that is the width tested.
func TestUnsavedSettingWarningAddsNoRowAtMinSize(t *testing.T) {
	base := AdminSettings{
		PassphraseMethod: "none", Theme: "auto", NodeRole: "signer", SSHEnabled: true, SSHPort: 2222,
		SSHFingerprint: "SHA256:Abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
	}
	plain := base
	for _, standalone := range []bool{false, true} {
		for _, keys := range [][]string{
			{adminproto.AdminSettingLockOnDisconnect},
			{adminproto.AdminSettingUserAutoApprove, adminproto.AdminSettingRequireContained,
				adminproto.AdminSettingRequireCosigner, adminproto.AdminSettingLockOnDisconnect},
		} {
			warnedSettings := base
			warnedSettings.UnsavedSettings = keys
			without := sizedForTest(t, Model{viewState: ViewAdminPanel, standalone: standalone,
				admin: adminPanelState{editingRow: -1, settings: &plain}}, MinWidth, MinHeight)
			warned := without
			warned.admin.settings = &warnedSettings
			warning := warned.unsavedSettingsWarning()
			panel := stripANSI(warned.renderAdminPanel())
			if got, want := renderedBlockHeight(panel), renderedBlockHeight(without.renderAdminPanel()); got != want {
				t.Fatalf("%v: panel is %d rows with the warning, %d without", keys, got, want)
			}
			for _, line := range strings.Split(panel, "\n") {
				if lipgloss.Width(line) > MinWidth {
					t.Fatalf("%v: line wider than the %d-column window: %q", keys, MinWidth, line)
				}
			}
			shown := ellipsize(warning, MinWidth)
			if view := stripANSI(warned.View()); !strings.Contains(view, shown) {
				t.Fatalf("standalone %v, %v: warning %q not on screen at %dx%d:\n%s", standalone, keys, shown, MinWidth, MinHeight, view)
			}
			if len(keys) > 1 && (lipgloss.Width(warning) <= MinWidth || !strings.HasSuffix(shown, "...")) {
				t.Fatalf("warning %q is not long enough to be cut at %d columns; the test needs a longer one", warning, MinWidth)
			}
		}
	}
}

// The settings message carries the signer's unsaved settings to the panel.
func TestAdminSettingsMessageCarriesUnsavedSettings(t *testing.T) {
	decoded, err := signerMessageDecoders[MsgTypeAdminSettings]([]byte(
		`{"type":"admin_settings","id":"1","theme":"auto","unsaved_settings":["user_auto_approve"]}`))
	if err != nil {
		t.Fatal(err)
	}
	msg, ok := decoded.(AdminSettingsMsg)
	if !ok || len(msg.Settings.UnsavedSettings) != 1 || msg.Settings.UnsavedSettings[0] != adminproto.AdminSettingUserAutoApprove {
		t.Fatalf("decoded = %#v, want unsaved_settings [user_auto_approve]", decoded)
	}
}
