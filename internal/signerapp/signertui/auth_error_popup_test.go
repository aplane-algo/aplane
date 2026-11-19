// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
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
// that reconnect, and dismissing it leads to the new login.
func TestSeriousAuthErrorPopupSurvivesTheReconnect(t *testing.T) {
	for _, tc := range []struct{ code, message string }{
		{protocol.ErrCodeAuthenticationFailed, "the signer cannot open its store root; see the signer log"},
		{protocol.ErrCodeUnlockFailed, "auth ok but unlock failed: failed to load keys"},
	} {
		t.Run(tc.code, func(t *testing.T) {
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
				viewState:       ViewAuth,
				connectionState: ConnectionConnected,
				auth:            authState{passphraseInput: SensitiveBytes("secret"), passphraseMasked: true},
				width:           80,
				height:          MinHeight,
			}
			apply := func(msg tea.Msg) {
				next, _ := m.Update(msg)
				m = next.(Model)
			}

			go send(firstServer, AuthResultMessage{BaseMessage: BaseMessage{Type: MsgTypeAuthResult}, Code: tc.code, Error: tc.message})
			apply(waitForClientMsg(t, client, 2*time.Second))
			if m.viewState != ViewError {
				t.Fatalf("viewState after the auth result = %v, want the error popup", m.viewState)
			}
			// The signer ends the login and closes the connection; its next
			// connection opens with auth_required.
			_ = firstServer.Close()
			go send(secondServer, AuthRequiredMessage{BaseMessage: BaseMessage{Type: MsgTypeAuthRequired}})
			for {
				msg := waitForClientMsg(t, client, 2*time.Second)
				apply(msg)
				if _, ok := msg.(AuthRequiredMsg); ok {
					break
				}
			}
			if connector.connectCount() != 2 {
				t.Fatalf("connections = %d, want the reconnect", connector.connectCount())
			}
			if m.viewState != ViewError || m.errorPopup.message != tc.message || m.errorPopup.returnView != ViewAuth {
				t.Fatalf("after the reconnect: viewState = %v, popup = %q returning to %v; want the error kept over the new login",
					m.viewState, m.errorPopup.message, m.errorPopup.returnView)
			}
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
