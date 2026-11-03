// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/protocol"
	tea "github.com/charmbracelet/bubbletea"
)

func mnemonicTestModel() Model {
	m := activityReadyModel()
	m.viewState = ViewMnemonicExport
	m.mnemonicExport = mnemonicExportState{address: "ACCOUNT", keyType: "ed25519", requestID: "export-1", pending: true, serial: 1}
	return m
}

func mnemonicTestReply(id string) nativeMnemonicResultMsg {
	return nativeMnemonicResultMsg{BaseMessage: protocol.BaseMessage{ID: id}, Success: true, Address: "ACCOUNT", KeyType: "ed25519", WordCount: 25, Mnemonic: protocol.NewSensitiveBytes(strings.TrimSpace(strings.Repeat("word ", 25)))}
}

func TestMnemonicDisplayAndDismissal(t *testing.T) {
	m := mnemonicTestModel()
	msg := mnemonicTestReply("export-1")
	next, _ := m.Update(msg)
	m = next.(Model)
	if len(m.mnemonicExport.words) == 0 || m.mnemonicExport.pending {
		t.Fatal("phrase not displayed")
	}
	if !bytes.Equal(msg.Mnemonic, make([]byte, len(msg.Mnemonic))) {
		t.Fatal("response buffer not cleared")
	}
	words := m.mnemonicExport.words
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = next.(Model)
	if m.viewState != ViewKeyDetails || len(m.mnemonicExport.words) != 0 || !bytes.Equal(words, make([]byte, len(words))) {
		t.Fatal("dismissal retained phrase")
	}
	late := mnemonicTestReply("export-1")
	next, _ = m.Update(late)
	if len(next.(Model).mnemonicExport.words) != 0 || !bytes.Equal(late.Mnemonic, make([]byte, len(late.Mnemonic))) {
		t.Fatal("late response retained phrase")
	}
}

func TestMnemonicClearedOnSessionTransitions(t *testing.T) {
	for _, event := range []tea.Msg{DisconnectedMsg{}, SignerStatusMsg{State: "locked"}, SignerStatusMsg{State: "recovery"}, mnemonicExpiredMsg{Serial: 1}, tea.KeyMsg{Type: tea.KeyCtrlC}} {
		m := mnemonicTestModel()
		m.mnemonicExport.words = protocol.NewSensitiveBytes("secret phrase")
		m.mnemonicExport.passphrase = protocol.NewSensitiveBytes("secret passphrase")
		words, pass := m.mnemonicExport.words, m.mnemonicExport.passphrase
		next, _ := m.Update(event)
		if len(next.(Model).mnemonicExport.words) != 0 || !bytes.Equal(words, make([]byte, len(words))) || !bytes.Equal(pass, make([]byte, len(pass))) {
			t.Fatalf("%T retained material", event)
		}
	}
}

func TestMnemonicRejectsStaleAndMismatchedResponses(t *testing.T) {
	for _, mismatch := range []string{"id", "address", "type", "words"} {
		m := mnemonicTestModel()
		msg := mnemonicTestReply("export-1")
		switch mismatch {
		case "id":
			msg.ID = "old"
		case "address":
			msg.Address = "OTHER"
		case "type":
			msg.KeyType = "falcon1024"
		case "words":
			msg.WordCount = 24
		}
		next, _ := m.Update(msg)
		if len(next.(Model).mnemonicExport.words) != 0 {
			t.Fatalf("accepted mismatched %s", mismatch)
		}
		if !bytes.Equal(msg.Mnemonic, make([]byte, len(msg.Mnemonic))) {
			t.Fatal("rejected response not cleared")
		}
	}
}

func TestMnemonicPassphraseGrowthClearsPreviousBuffer(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  tea.KeyMsg
		text string
	}{
		{"ASCII", tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'x'}}, "x"},
		{"Unicode", tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'界'}}, "界"},
		{"space", tea.KeyMsg{Type: tea.KeySpace}, " "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := mnemonicTestModel()
			m.mnemonicExport.pending = false
			m.mnemonicExport.passphrase = make(protocol.SensitiveBytes, 8)
			copy(m.mnemonicExport.passphrase, "testpass")
			old := m.mnemonicExport.passphrase
			next, _ := m.Update(tc.key)
			m = next.(Model)
			if string(m.mnemonicExport.passphrase) != "testpass"+tc.text {
				t.Fatal("growth changed passphrase input")
			}
			if !bytes.Equal(old, make([]byte, len(old))) {
				t.Fatal("growth retained previous passphrase allocation")
			}
			current := m.mnemonicExport.passphrase
			next, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
			if len(next.(Model).mnemonicExport.passphrase) != 0 || !bytes.Equal(current, make([]byte, len(current))) {
				t.Fatal("dismissal retained current passphrase allocation")
			}
		})
	}
}

func TestMnemonicExportOpensOnlyForSignerMarkedKeys(t *testing.T) {
	for _, exportable := range []bool{false, true} {
		m := activityReadyModel()
		m.viewState = ViewKeyDetails
		m.details.address, m.details.keyType = "ACCOUNT", "falcon1024"
		m.details.mnemonicExportable = exportable
		next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'m'}})
		if got := next.(Model).viewState == ViewMnemonicExport; got != exportable {
			t.Fatalf("exportable=%v opened export screen=%v", exportable, got)
		}
	}
}

func TestMnemonicRevealRestartsExpiry(t *testing.T) {
	m := mnemonicTestModel()
	promptSerial := m.mnemonicExport.serial
	next, _ := m.Update(mnemonicTestReply("export-1"))
	m = next.(Model)
	// The prompt's tick must not hide a phrase revealed just before it fires.
	next, _ = m.Update(mnemonicExpiredMsg{Serial: promptSerial})
	m = next.(Model)
	if len(m.mnemonicExport.words) == 0 || m.viewState != ViewMnemonicExport {
		t.Fatal("prompt timeout cut the revealed phrase short")
	}
	next, _ = m.Update(mnemonicExpiredMsg{Serial: m.mnemonicExport.serial})
	m = next.(Model)
	if len(m.mnemonicExport.words) != 0 || m.viewState != ViewKeyDetails {
		t.Fatal("reveal timeout did not hide the phrase")
	}
}

func connectedTestClient() *IPCClient {
	c := NewAdminClient(nil)
	c.connected, c.sessionID = true, 1
	return c
}

func TestDisconnectClearsQueuedMnemonicReplies(t *testing.T) {
	c := connectedTestClient()
	reply := mnemonicTestReply("export-1")
	if !c.emit(1, reply) {
		t.Fatal("reply not queued")
	}
	c.Disconnect()
	if len(c.msgChan) != 0 {
		t.Fatal("stale reply left queued after disconnect")
	}
	if !bytes.Equal(reply.Mnemonic, make([]byte, len(reply.Mnemonic))) {
		t.Fatal("queued reply retained its phrase after disconnect")
	}
}

func TestDisconnectClearsReplyFromBlockedProducer(t *testing.T) {
	c := connectedTestClient()
	for i := 0; i < cap(c.msgChan); i++ {
		c.emit(1, KeysListMsg{})
	}
	reply := mnemonicTestReply("export-1")
	emitted := make(chan bool, 1)
	go func() { emitted <- c.emit(1, reply) }()
	// Give the producer time to block on the full queue; the outcome is the
	// same either way (dropped by emit or drained by Disconnect).
	time.Sleep(20 * time.Millisecond)
	c.Disconnect()
	<-emitted
	if len(c.msgChan) != 0 || !bytes.Equal(reply.Mnemonic, make([]byte, len(reply.Mnemonic))) {
		t.Fatal("reply from a producer racing disconnect stayed resident")
	}
}

func TestDiscardStaleQueuedKeepsCurrentSession(t *testing.T) {
	c := NewAdminClient(nil)
	c.sessionID = 2
	stale := mnemonicTestReply("old")
	c.msgChan <- queuedMsg{sessionID: 1, msg: stale}
	c.msgChan <- queuedMsg{sessionID: 2, msg: KeysListMsg{}}
	c.discardStaleQueued()
	if len(c.msgChan) != 1 || (<-c.msgChan).sessionID != 2 {
		t.Fatal("current-session message not preserved")
	}
	if !bytes.Equal(stale.Mnemonic, make([]byte, len(stale.Mnemonic))) {
		t.Fatal("stale reply not cleared")
	}
}

func TestShutdownClearsMnemonicExport(t *testing.T) {
	m := mnemonicTestModel()
	m.mnemonicExport.words = protocol.NewSensitiveBytes("secret phrase")
	m.mnemonicExport.passphrase = protocol.NewSensitiveBytes("secret passphrase")
	words, pass := m.mnemonicExport.words, m.mnemonicExport.passphrase
	m.Shutdown()
	if !bytes.Equal(words, make([]byte, len(words))) || !bytes.Equal(pass, make([]byte, len(pass))) {
		t.Fatal("shutdown retained recovery phrase or passphrase")
	}
}

func TestMnemonicPhraseRendersInThreeColumns(t *testing.T) {
	words := make([][]byte, 25)
	for i := range words {
		words[i] = []byte(fmt.Sprintf("w%02d", i+1))
	}
	var b strings.Builder
	writeMnemonicColumns(&b, words)
	lines := strings.Split(strings.TrimSuffix(b.String(), "\n"), "\n")
	if len(lines) != 9 {
		t.Fatalf("rendered %d rows, want 9:\n%s", len(lines), b.String())
	}
	for row, line := range lines {
		want := []string{fmt.Sprintf("w%02d", row+1), fmt.Sprintf("w%02d", row+10)}
		if row < 7 {
			want = append(want, fmt.Sprintf("w%02d", row+19))
		}
		if got := strings.Fields(line); len(got) != 2*len(want) {
			t.Fatalf("row %d = %q, want %d columns", row+1, line, len(want))
		}
		for _, word := range want {
			if !strings.Contains(line, word) {
				t.Fatalf("row %d = %q, missing %s", row+1, line, word)
			}
		}
	}
	// Columns line up: every entry in a column starts at the same offset.
	if strings.Index(lines[0], "10.") != strings.Index(lines[8], "18.") || strings.Index(lines[0], "19.") != strings.Index(lines[6], "25.") {
		t.Fatalf("columns are not aligned:\n%s", b.String())
	}
}
