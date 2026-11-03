// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"bytes"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/aplane-algo/aplane/internal/protocol"
	tea "github.com/charmbracelet/bubbletea"
)

type mnemonicExportState struct {
	address, keyType, requestID, error string
	passphrase, words                  protocol.SensitiveBytes
	serial                             uint64
	pending                            bool
}

type nativeMnemonicResultMsg protocol.ExportResultMessage
type mnemonicExpiredMsg struct{ Serial uint64 }

// appendPassphraseRune owns growth so an abandoned allocation never retains
// the previously typed passphrase.
func (e *mnemonicExportState) appendPassphraseRune(r rune) {
	n := utf8.RuneLen(r)
	if n < 0 {
		r = utf8.RuneError
		n = utf8.RuneLen(r)
	}
	if len(e.passphrase)+n > cap(e.passphrase) {
		grown := make(protocol.SensitiveBytes, len(e.passphrase), max(2*cap(e.passphrase), len(e.passphrase)+n))
		copy(grown, e.passphrase)
		e.passphrase[:cap(e.passphrase)].Zero()
		e.passphrase = grown
	}
	e.passphrase = utf8.AppendRune(e.passphrase, r)
}

// mnemonicDisplayTimeout bounds both the passphrase prompt and, restarted at
// reveal, how long a revealed phrase stays on screen.
const mnemonicDisplayTimeout = 2 * time.Minute

func mnemonicExpiryCmd(serial uint64) tea.Cmd {
	return tea.Tick(mnemonicDisplayTimeout, func(time.Time) tea.Msg { return mnemonicExpiredMsg{serial} })
}

func (m *Model) clearMnemonicExport() {
	m.mnemonicExport.passphrase.Zero()
	m.mnemonicExport.words.Zero()
	m.mnemonicExport = mnemonicExportState{serial: m.mnemonicExport.serial + 1}
}

func (m Model) openMnemonicExport() (tea.Model, tea.Cmd) {
	// The signer decides eligibility (key details' mnemonic_exportable).
	if !m.details.mnemonicExportable || m.signerState != signerRuntimeUnlocked {
		return m, nil
	}
	m.clearMnemonicExport()
	m.mnemonicExport.address = m.details.address
	m.mnemonicExport.keyType = m.details.keyType
	m.viewState = ViewMnemonicExport
	return m, mnemonicExpiryCmd(m.mnemonicExport.serial)
}

func (m Model) handleMnemonicExportKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	e := &m.mnemonicExport
	if msg.String() == "esc" || (len(e.words) > 0 && (msg.String() == "enter" || msg.String() == "q")) {
		m.clearMnemonicExport()
		m.viewState = ViewKeyDetails
		return m, nil
	}
	if e.pending || len(e.words) > 0 {
		return m, nil
	}
	switch msg.Type {
	case tea.KeyEnter:
		if len(e.passphrase) == 0 {
			e.error = "Enter your signer passphrase"
			return m, nil
		}
		e.requestID = fmt.Sprintf("mnemonic-export-%d", time.Now().UnixNano())
		e.pending, e.error = true, ""
		request := protocol.ExportKeyMessage{
			BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeExportKey, ID: e.requestID},
			Address:     e.address, Passphrase: protocol.SensitiveBytes(e.passphrase.Clone()),
		}
		e.passphrase.Zero()
		e.passphrase = nil
		send := operationCmd(m.adminClient, request.ID, func(c *IPCClient) error { return c.sendMessage(request) })
		return m, tea.Batch(func() tea.Msg {
			defer request.Passphrase.Zero()
			return send()
		}, m.waitForMessageCmd())
	case tea.KeyBackspace, tea.KeyCtrlH:
		if len(e.passphrase) > 0 {
			_, n := utf8.DecodeLastRune(e.passphrase)
			end := len(e.passphrase) - n
			protocol.SensitiveBytes(e.passphrase[end:]).Zero()
			e.passphrase = e.passphrase[:end]
		}
	case tea.KeyRunes:
		for _, r := range msg.Runes {
			e.appendPassphraseRune(r)
		}
	case tea.KeySpace:
		e.appendPassphraseRune(' ')
	}
	return m, nil
}

func (m Model) handleNativeMnemonicResult(msg nativeMnemonicResultMsg) (tea.Model, tea.Cmd) {
	defer msg.Mnemonic.Zero()
	e := &m.mnemonicExport
	if !e.pending || msg.ID != e.requestID || m.viewState != ViewMnemonicExport || m.signerState != signerRuntimeUnlocked {
		return m, m.waitForMessageCmd()
	}
	e.pending = false
	if !msg.Success {
		e.error = msg.Error
		return m, m.waitForMessageCmd()
	}
	if msg.Address != e.address || msg.KeyType != e.keyType || msg.WordCount != 25 || len(bytes.Fields(msg.Mnemonic)) != 25 {
		e.error = "Invalid recovery phrase response"
		return m, m.waitForMessageCmd()
	}
	e.words = protocol.SensitiveBytes(msg.Mnemonic.Clone())
	// Restart the timeout at reveal: a slow passphrase entry must not shorten
	// how long the phrase is readable. The new serial retires the prompt's tick.
	e.serial++
	return m, tea.Batch(m.waitForMessageCmd(), mnemonicExpiryCmd(e.serial))
}

func (m Model) renderMnemonicExport() string {
	e := &m.mnemonicExport
	var b strings.Builder
	b.WriteString(titleStyle.Render("Recovery phrase") + "\n\n")
	fmt.Fprintf(&b, "Type: %s\nAddress: %s\n\n", e.keyType, e.address)
	b.WriteString("Anyone with this phrase can control this key.\nThe phrase is hidden again after two minutes.\n\n")
	switch {
	case len(e.words) > 0:
		writeMnemonicColumns(&b, bytes.Fields(e.words))
		b.WriteString("\nEnter / Esc: close")
	case e.pending:
		b.WriteString("Verifying passphrase…\n\nEsc: cancel")
	default:
		b.WriteString("Signer passphrase: " + strings.Repeat("*", utf8.RuneCount(e.passphrase)))
		b.WriteString("\n\nEnter: reveal phrase | Esc: cancel")
	}
	if e.error != "" {
		b.WriteString("\n\n" + e.error)
	}
	return m.renderPopup(66, b.String())
}

// mnemonicColumns is how many columns the revealed phrase is laid out in.
const mnemonicColumns = 3

// writeMnemonicColumns lays the phrase out top to bottom, then left to right,
// so it reads in recovery order: a 25-word phrase fills columns of 9, 9 and 7.
func writeMnemonicColumns(b *strings.Builder, words [][]byte) {
	rows := (len(words) + mnemonicColumns - 1) / mnemonicColumns
	width := 0
	for _, word := range words {
		width = max(width, utf8.RuneCount(word))
	}
	for row := 0; row < rows; row++ {
		for col := 0; col < mnemonicColumns; col++ {
			i := col*rows + row
			if i >= len(words) {
				break
			}
			if col > 0 {
				b.WriteString("    ")
			}
			fmt.Fprintf(b, "%2d. %s", i+1, words[i])
			// Pad to the column width unless this is the row's last entry.
			if col < mnemonicColumns-1 && (col+1)*rows+row < len(words) {
				b.WriteString(strings.Repeat(" ", width-utf8.RuneCount(words[i])))
			}
		}
		b.WriteString("\n")
	}
}
