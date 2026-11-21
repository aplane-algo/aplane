// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"bufio"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/protocol"

	tea "github.com/charmbracelet/bubbletea"
)

func TestAuthResultSeriousUnlockErrorShowsBlockingPopup(t *testing.T) {
	msg := "auth ok but unlock failed: failed to load keys: reload pre-scan hook failed: " +
		"policy verification failed for identity \"default\": policy integrity check failed: " +
		"policy integrity mismatch: hmac mismatch"
	m := Model{
		viewState:       ViewAuth,
		connectionState: ConnectionConnected,
		auth:            authState{passphraseInput: SensitiveBytes("secret"), passphraseError: "old error", passphraseMasked: true}, width: 80,
		height: MinHeight,
	}

	next, _ := m.Update(AuthResultMsg{Success: false, Code: protocol.ErrCodeUnlockFailed, Error: msg})
	got := next.(Model)
	if got.viewState != ViewError {
		t.Fatalf("viewState = %v, want ViewError", got.viewState)
	}
	if got.errorPopup.returnView != ViewAuth {
		t.Fatalf("errorPopupReturnView = %v, want ViewAuth", got.errorPopup.returnView)
	}
	if len(got.auth.passphraseInput) != 0 {
		t.Fatal("passphraseInput retained after serious auth error")
	}

	view := stripANSI(got.View())
	if !strings.Contains(view, "Signer unlock failed") {
		t.Fatalf("popup missing title:\n%s", view)
	}
	if !strings.Contains(view, "policy integrity mismatch") || !strings.Contains(view, "hmac mismatch") {
		t.Fatalf("popup missing policy integrity details:\n%s", view)
	}
	if !strings.Contains(view, "Esc: Close") {
		t.Fatalf("popup missing dismissal hint:\n%s", view)
	}
}

// A login the signer could not check, because it cannot open its store root,
// is a fault to report, not a passphrase to type again.
func TestAuthResultStoreRootFailureShowsBlockingPopup(t *testing.T) {
	m := Model{
		viewState:       ViewAuth,
		connectionState: ConnectionConnected,
		auth:            authState{passphraseInput: SensitiveBytes("secret"), passphraseMasked: true},
		width:           80,
		height:          MinHeight,
	}

	msg := "the signer cannot open its store root; see the signer log"
	next, _ := m.Update(AuthResultMsg{Success: false, Code: protocol.ErrCodeAuthenticationFailed, Error: msg})
	got := next.(Model)
	if got.viewState != ViewError || got.errorPopup.returnView != ViewAuth {
		t.Fatalf("viewState = %v (return %v), want the error popup over ViewAuth", got.viewState, got.errorPopup.returnView)
	}
	if len(got.auth.passphraseInput) != 0 {
		t.Fatal("passphraseInput retained after a store-root failure")
	}
	if view := stripANSI(got.View()); !strings.Contains(view, "cannot open its store root") {
		t.Fatalf("popup missing the failure:\n%s", view)
	}
}

// A login the signer ends with a serious error closes the connection, and
// the client reconnects to a fresh login at once. The error stays up through
// that reconnect, and dismissing it leads to the new login. When another
// session owns the signer, the reconnect is offered displacement first: the
// error stays up over that prompt too, and dismissing it leads to the prompt.
func TestSeriousAuthErrorPopupSurvivesTheReconnect(t *testing.T) {
	for _, tc := range []struct {
		name, code, message string
		ownerActive         bool
	}{
		{"authentication_failed", protocol.ErrCodeAuthenticationFailed, "the signer cannot open its store root; see the signer log", false},
		{"unlock_failed", protocol.ErrCodeUnlockFailed, "auth ok but unlock failed: failed to load keys", false},
		{"authentication_failed with an owner", protocol.ErrCodeAuthenticationFailed, "the signer cannot open its store root; see the signer log", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			firstClient, firstServer := net.Pipe()
			secondClient, secondServer := net.Pipe()
			defer func() { _ = secondServer.Close() }()
			connector := &queueConnector{conns: []io.ReadWriteCloser{firstClient, secondClient}}
			client := NewAdminClient(connector)
			client.reconnectDelay = 10 * time.Millisecond
			client.maxDelay = 20 * time.Millisecond
			if err := client.Connect(); err != nil {
				t.Fatal(err)
			}
			defer client.Disconnect()

			send := func(conn net.Conn, msg any) {
				line, err := protocol.MarshalAdminMessage(msg)
				if err != nil {
					t.Error(err)
					return
				}
				if _, err := conn.Write(append(line, '\n')); err != nil {
					t.Error(err)
				}
			}
			m := Model{
				adminClient:     client,
				viewState:       ViewAuth,
				connectionState: ConnectionConnected,
				auth:            authState{passphraseInput: SensitiveBytes("secret"), passphraseMasked: true},
				width:           80,
				height:          MinHeight,
			}
			apply := func(msg tea.Msg) tea.Cmd {
				next, cmd := m.Update(msg)
				m = next.(Model)
				return cmd
			}
			applyUntil := func(done func(tea.Msg) bool) {
				for {
					msg := waitForClientMsg(t, client, 2*time.Second)
					apply(msg)
					if done(msg) {
						return
					}
				}
			}
			isAuthRequired := func(msg tea.Msg) bool { _, ok := msg.(AuthRequiredMsg); return ok }
			wantPopupReturningTo := func(when string, view ViewState) {
				t.Helper()
				if m.viewState != ViewError || m.errorPopup.message != tc.message || m.errorPopup.returnView != view {
					t.Fatalf("%s: viewState = %v, popup = %q returning to %v; want the error kept, returning to %v",
						when, m.viewState, m.errorPopup.message, m.errorPopup.returnView, view)
				}
			}

			go send(firstServer, AuthResultMessage{BaseMessage: BaseMessage{Type: MsgTypeAuthResult}, Code: tc.code, Error: tc.message})
			apply(waitForClientMsg(t, client, 2*time.Second))
			if m.viewState != ViewError {
				t.Fatalf("viewState after the auth result = %v, want the error popup", m.viewState)
			}
			// The signer ends the login and closes the connection; its next
			// connection opens with auth_required, or with client_exists
			// while another session owns the signer.
			_ = firstServer.Close()
			if tc.ownerActive {
				go send(secondServer, ClientExistsMessage{BaseMessage: BaseMessage{Type: MsgTypeClientExists}})
				applyUntil(func(msg tea.Msg) bool { _, ok := msg.(ClientExistsMsg); return ok })
				wantPopupReturningTo("after client_exists", ViewDisplaceConfirm)
				apply(tea.KeyMsg{Type: tea.KeyEsc})
				if m.viewState != ViewDisplaceConfirm || m.displaceConfirmFocus != 0 {
					t.Fatalf("after dismissal: viewState = %v focus = %d, want the displacement prompt on Cancel", m.viewState, m.displaceConfirmFocus)
				}
				// Confirming displacement makes the signer start the login.
				go func() {
					line, err := bufio.NewReader(secondServer).ReadBytes('\n')
					if err != nil {
						t.Error(err)
						return
					}
					if base, err := protocol.ParseAdminBaseMessage(line); err != nil || base.Type != MsgTypeDisplaceConfirm {
						t.Errorf("client sent %q (%v), want displace_confirm", line, err)
						return
					}
					send(secondServer, AuthRequiredMessage{BaseMessage: BaseMessage{Type: MsgTypeAuthRequired}})
				}()
				if cmd := apply(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("y")}); cmd != nil {
					cmd()
				}
				applyUntil(isAuthRequired)
				if m.viewState != ViewAuth {
					t.Fatalf("after confirming displacement: viewState = %v, want the new login", m.viewState)
				}
				return
			}

			go send(secondServer, AuthRequiredMessage{BaseMessage: BaseMessage{Type: MsgTypeAuthRequired}})
			applyUntil(isAuthRequired)
			if connector.connectCount() != 2 {
				t.Fatalf("connections = %d, want the reconnect", connector.connectCount())
			}
			wantPopupReturningTo("after the reconnect", ViewAuth)
			if len(m.auth.passphraseInput) != 0 {
				t.Fatal("passphrase retained across the reconnect")
			}

			apply(tea.KeyMsg{Type: tea.KeyEsc})
			if m.viewState != ViewAuth || m.errorPopup.message != "" {
				t.Fatalf("after dismissal: viewState = %v, popup = %q; want the new login", m.viewState, m.errorPopup.message)
			}
		})
	}
}

func TestSeriousErrorPopupEscReturnsToPassphraseView(t *testing.T) {
	m := Model{
		viewState:       ViewError,
		connectionState: ConnectionConnected,
		errorPopup:      errorPopupState{title: "Signer unlock failed", message: "failed to load keys", returnView: ViewAuth},
		auth:            authState{passphraseError: "failed to load keys"},
	}

	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	got := next.(Model)
	if got.viewState != ViewAuth {
		t.Fatalf("viewState = %v, want ViewAuth", got.viewState)
	}
	if got.errorPopup.message != "" || got.auth.passphraseError != "" {
		t.Fatalf("popup/passphrase error not cleared: popup=%q passphrase=%q",
			got.errorPopup.message, got.auth.passphraseError)
	}
}

func TestInvalidPassphraseStaysInlineOnAuthView(t *testing.T) {
	m := Model{viewState: ViewAuth, connectionState: ConnectionConnected}

	next, _ := m.Update(AuthResultMsg{Success: false, Error: "invalid passphrase"})
	got := next.(Model)
	if got.viewState != ViewAuth {
		t.Fatalf("viewState = %v, want ViewAuth", got.viewState)
	}
	if got.auth.passphraseError != "invalid passphrase" {
		t.Fatalf("passphraseError = %q, want invalid passphrase", got.auth.passphraseError)
	}
	if got.errorPopup.message != "" {
		t.Fatalf("errorPopupMessage = %q, want empty", got.errorPopup.message)
	}
}

// A failed login or unlock ends the wait once and always says it failed, even
// when the signer gives no reason.
func TestFailedLoginOrUnlockWithoutAReasonSaysItFailed(t *testing.T) {
	for _, tc := range []struct {
		view ViewState
		msg  tea.Msg
		want string
	}{
		{ViewAuth, AuthResultMsg{Success: false}, "Authentication failed"},
		{ViewUnlock, UnlockResultMsg{Success: false}, "Unlock failed"},
	} {
		m := sizedForTest(t, Model{viewState: tc.view, connectionState: ConnectionConnected, auth: authState{loggingIn: true, passphraseMasked: true}}, MinWidth, MinHeight)
		got := updateModel(t, m, tc.msg)
		if got.auth.loggingIn || got.auth.passphraseError != tc.want {
			t.Fatalf("%T: loggingIn %v error %q, want false and %q", tc.msg, got.auth.loggingIn, got.auth.passphraseError, tc.want)
		}
		view := stripANSI(got.View())
		checkFitsMinSize(t, view)
		if !strings.Contains(view, tc.want) {
			t.Fatalf("%T: %q missing from:\n%s", tc.msg, tc.want, view)
		}
	}
}
