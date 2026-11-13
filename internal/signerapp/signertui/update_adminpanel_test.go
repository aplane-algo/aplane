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
// keeping the value it showed before. That result is coded
// applied_not_durable or applied_not_saved and shown as a warning on the
// panel that does not say "failed"; it once read "Setting update failed" like
// a refused change.
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
	if got := next.(Model); got.lastError != "" || got.lastWarning != "" || got.admin.unsavedWarning != want {
		t.Fatalf("lastError = %q, lastWarning = %q, panel warning = %q; want no error and the panel warning %q",
			got.lastError, got.lastWarning, got.admin.unsavedWarning, want)
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
		got.lastWarning != "" || got.admin.unsavedWarning != "" {
		t.Fatalf("lastError = %q, lastWarning = %q, panel warning = %q; want the failure as an error", got.lastError, got.lastWarning, got.admin.unsavedWarning)
	}
}

// A setting in effect without a completed save is warned of on the admin
// panel itself, for each of the two outcomes, in words that say it is in
// effect and never "failed". The warning is the panel's own: no other warning
// or error replaces it, no key or timer clears it, and it stays until the next
// setting update result, which replaces it or, for any other outcome, clears
// it. It once shared the status line's single warning slot, shown only on the
// panel and lost to the first key there or to any other warning.
func TestSettingInEffectWarningStaysOnThePanelUntilTheNextResult(t *testing.T) {
	for _, tc := range []struct {
		code, want string
	}{
		{protocol.ResultCodeAppliedNotDurable, "Warning: user_auto_approve is in effect; its durability is not confirmed"},
		{protocol.ResultCodeAppliedNotSaved, "Warning: user_auto_approve is in effect but not saved; a restart reverts it"},
	} {
		t.Run(tc.code, func(t *testing.T) {
			m := approvalTestModel(ViewAdminPanel)
			m.admin.settings = &AdminSettings{PassphraseMethod: "none", Theme: "auto"}
			next, cmd := m.Update(AdminSettingUpdatedMsg{
				Success: false, Key: adminproto.AdminSettingUserAutoApprove, Value: "false", Code: tc.code,
				Error: "user_auto_approve is set to false and in effect: injected",
			})
			m = next.(Model)
			panel := stripANSI(m.renderAdminPanel())
			if !strings.Contains(panel, tc.want) || strings.Contains(strings.ToLower(panel), "failed") || m.lastError != "" {
				t.Fatalf("panel after %s (error %q):\n%s\nwant %q and no failure", tc.code, m.lastError, panel, tc.want)
			}
			// Nothing is scheduled to clear it: with no client, every command
			// the update returns completes at once, and a clearing timer would
			// not.
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
			next, _ = m.Update(tea.KeyMsg{Type: tea.KeyDown})
			m = next.(Model)
			m.setTransientWarning("another warning")
			m.lastError = "another error"
			if panel := stripANSI(m.renderAdminPanel()); !strings.Contains(panel, tc.want) {
				t.Fatalf("panel after a key, another warning and an error:\n%s\nwant %q", panel, tc.want)
			}
			if bar := stripANSI(m.renderStatusBar()); strings.Contains(bar, "in effect") {
				t.Fatalf("status bar = %q, want the setting warning on the panel only", bar)
			}

			next, _ = m.Update(AdminSettingUpdatedMsg{Success: true, Key: adminproto.AdminSettingTheme, Value: "dark"})
			if panel := stripANSI(next.(Model).renderAdminPanel()); strings.Contains(panel, "in effect") {
				t.Fatalf("panel after the next result succeeded:\n%s\nwant the warning cleared", panel)
			}
		})
	}
}

// The warning names the setting, not the echoed request value, which can
// differ from what the signer holds (a theme is lower-cased).
func TestSettingInEffectWarningNamesTheSettingNotTheValue(t *testing.T) {
	m := approvalTestModel(ViewKeyList)
	next, _ := m.Update(AdminSettingUpdatedMsg{
		Success: false, Key: adminproto.AdminSettingTheme, Value: "Dark", Code: protocol.ResultCodeAppliedNotDurable,
	})
	if got := next.(Model).admin.unsavedWarning; got != "theme is in effect; its durability is not confirmed" {
		t.Fatalf("warning = %q, want it naming the setting without the echoed value", got)
	}
}

// The panel fits 80x24 with the warning as it does without it: the warning
// takes the title's margin line, adds no row, fits the width, and is on
// screen whatever the panel shows below it.
func TestSettingInEffectWarningAddsNoRowAtMinSize(t *testing.T) {
	settings := &AdminSettings{
		PassphraseMethod: "none", Theme: "auto", NodeRole: "signer", SSHEnabled: true, SSHPort: 2222,
		SSHFingerprint: "SHA256:Abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
	}
	for _, standalone := range []bool{false, true} {
		for _, key := range []string{adminproto.AdminSettingLockOnDisconnect, adminproto.AdminSettingPassphraseTimeout} {
			for _, code := range []string{protocol.ResultCodeAppliedNotDurable, protocol.ResultCodeAppliedNotSaved} {
				plain := sizedForTest(t, Model{viewState: ViewAdminPanel, standalone: standalone,
					admin: adminPanelState{editingRow: -1, settings: settings}}, MinWidth, MinHeight)
				next, _ := plain.Update(AdminSettingUpdatedMsg{Key: key, Code: code})
				warned := next.(Model)
				warning := "Warning: " + warned.admin.unsavedWarning
				if warned.admin.unsavedWarning == "" {
					t.Fatalf("%s: no warning", code)
				}
				if lipgloss.Width(warning) > MinWidth {
					t.Fatalf("%s for %s: warning is %d wide, the window %d: %q", code, key, lipgloss.Width(warning), MinWidth, warning)
				}
				if got, want := renderedBlockHeight(warned.renderAdminPanel()), renderedBlockHeight(plain.renderAdminPanel()); got != want {
					t.Fatalf("%s: panel is %d rows with the warning, %d without", code, got, want)
				}
				if view := stripANSI(warned.View()); !strings.Contains(view, warning) {
					t.Fatalf("standalone %v, %s for %s: warning not on screen at %dx%d:\n%s", standalone, code, key, MinWidth, MinHeight, view)
				}
			}
		}
	}
}
