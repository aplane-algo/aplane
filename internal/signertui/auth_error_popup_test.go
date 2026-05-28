// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestAuthResultSeriousUnlockErrorShowsBlockingPopup(t *testing.T) {
	msg := "auth ok but unlock failed: failed to load keys: reload pre-scan hook failed: " +
		"policy verification failed for identity \"default\": policy integrity check failed: " +
		"policy integrity mismatch: hmac mismatch"
	m := Model{
		viewState:        ViewAuth,
		connectionState:  ConnectionConnected,
		passphraseInput:  "secret",
		passphraseError:  "old error",
		passphraseMasked: true,
		width:            80,
		height:           20,
	}

	next, _ := m.Update(AuthResultMsg{Success: false, Error: msg})
	got := next.(Model)
	if got.viewState != ViewError {
		t.Fatalf("viewState = %v, want ViewError", got.viewState)
	}
	if got.errorPopupReturnView != ViewAuth {
		t.Fatalf("errorPopupReturnView = %v, want ViewAuth", got.errorPopupReturnView)
	}
	if got.passphraseInput != "" {
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

func TestSeriousErrorPopupEscReturnsToPassphraseView(t *testing.T) {
	m := Model{
		viewState:            ViewError,
		connectionState:      ConnectionConnected,
		errorPopupTitle:      "Signer unlock failed",
		errorPopupMessage:    "failed to load keys",
		errorPopupReturnView: ViewAuth,
		passphraseError:      "failed to load keys",
	}

	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	got := next.(Model)
	if got.viewState != ViewAuth {
		t.Fatalf("viewState = %v, want ViewAuth", got.viewState)
	}
	if got.errorPopupMessage != "" || got.passphraseError != "" {
		t.Fatalf("popup/passphrase error not cleared: popup=%q passphrase=%q",
			got.errorPopupMessage, got.passphraseError)
	}
}

func TestInvalidPassphraseStaysInlineOnAuthView(t *testing.T) {
	m := Model{viewState: ViewAuth, connectionState: ConnectionConnected}

	next, _ := m.Update(AuthResultMsg{Success: false, Error: "invalid passphrase"})
	got := next.(Model)
	if got.viewState != ViewAuth {
		t.Fatalf("viewState = %v, want ViewAuth", got.viewState)
	}
	if got.passphraseError != "invalid passphrase" {
		t.Fatalf("passphraseError = %q, want invalid passphrase", got.passphraseError)
	}
	if got.errorPopupMessage != "" {
		t.Fatalf("errorPopupMessage = %q, want empty", got.errorPopupMessage)
	}
}
