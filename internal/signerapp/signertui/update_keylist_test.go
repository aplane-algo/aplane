// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/aplane-algo/aplane/internal/protocol"
)

func TestSaveTEALToFileRequiresCanonicalAddressFilename(t *testing.T) {
	dataDir := t.TempDir()
	address := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"
	path, err := saveTEALToFile(dataDir, strings.ToLower(address), "int 1\n")
	if err != nil {
		t.Fatalf("saveTEALToFile() error = %v", err)
	}
	want := filepath.Join(dataDir, address+".teal")
	if path != want {
		t.Fatalf("saveTEALToFile() path = %q, want %q", path, want)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "int 1\n" {
		t.Fatalf("saved TEAL = %q, err = %v", data, err)
	}

	if _, err := saveTEALToFile(dataDir, "../../outside", "int 0\n"); err == nil || !strings.Contains(err.Error(), "invalid account address") {
		t.Fatalf("saveTEALToFile(path traversal) error = %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dataDir, "outside.teal")); !os.IsNotExist(err) {
		t.Fatalf("invalid address created an outside file: %v", err)
	}
}

// sentKeyDetailsReads connects m to a pipe and returns the ID of each key
// details read it sends.
func sentKeyDetailsReads(t *testing.T, m *Model) <-chan string {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() { _ = serverConn.Close() })
	client := NewAdminClient(&queueConnector{conns: []io.ReadWriteCloser{clientConn}})
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	t.Cleanup(client.Disconnect)
	m.adminClient = client
	sent := make(chan string, 8)
	go func() {
		reader := bufio.NewReader(serverConn)
		for {
			line, err := reader.ReadBytes('\n')
			if err != nil {
				return
			}
			var msg protocol.BaseMessage
			if json.Unmarshal(line, &msg) == nil && msg.Type == protocol.MsgTypeGetKeyDetails {
				sent <- msg.ID
			}
		}
	}()
	return sent
}

// A key's details open only on the reply to the read the key list is waiting
// on: a reply to an earlier read, or one that arrives after the operator has
// moved to another screen, leaves the screen as it is.
func TestKeyDetailsOpenOnlyOnTheirOwnReply(t *testing.T) {
	const addressA = "SGCU7MLRXQ4H227YCRTTT6MHL2N64WGJPHH3OTPID2CK4JNGJU6DITLIUQ"
	const addressB = "LPB4KVPDCWWU6RHQARBAVVFCZRQKV7BXTKDGRZAPRS7STX6DQMPQKMWALQ"
	model := func(t *testing.T) (Model, <-chan string) {
		m := sizedForTest(t, Model{viewState: ViewKeyList, connectionState: ConnectionConnected, signerState: signerRuntimeUnlocked,
			keylist: keyListState{keys: []KeyInfo{{Address: addressA, KeyType: "ed25519"}, {Address: addressB, KeyType: "ed25519"}}}}, MinWidth, MinHeight)
		reads := sentKeyDetailsReads(t, &m)
		return m, reads
	}
	read := func(t *testing.T, m Model, reads <-chan string, keys ...string) (Model, string) {
		t.Helper()
		var cmd tea.Cmd
		for _, key := range keys {
			var next tea.Model
			next, cmd = m.handleKeyPress(browserKey(key))
			m = next.(Model)
		}
		runSends(cmd)
		select {
		case id := <-reads:
			return m, id
		case <-time.After(5 * time.Second):
			t.Fatal("no key details read was sent")
		}
		return m, ""
	}
	reply := func(t *testing.T, id, address string) tea.Msg {
		return decodeSignerReply(t, protocol.KeyDetailsMessage{
			BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeKeyDetails, ID: id},
			Success:     true, Address: address, KeyType: "ed25519",
		})
	}

	t.Run("own reply", func(t *testing.T) {
		m, reads := model(t)
		m, id := read(t, m, reads, "enter")
		if m = updateModel(t, m, reply(t, id, addressA)); m.viewState != ViewKeyDetails || m.details.address != addressA {
			t.Fatalf("view %v address %q, want %s's details", m.viewState, m.details.address, addressA)
		}
	})
	t.Run("after moving on", func(t *testing.T) {
		m, reads := model(t)
		m, id := read(t, m, reads, "enter")
		m = press(t, m, "g")
		if m = updateModel(t, m, reply(t, id, addressA)); m.viewState != ViewGenerateForm {
			t.Fatalf("view %v, want the generate form the operator moved to", m.viewState)
		}
	})
	t.Run("earlier read", func(t *testing.T) {
		m, reads := model(t)
		m, first := read(t, m, reads, "enter")
		m, second := read(t, m, reads, "down", "enter")
		if m = updateModel(t, m, reply(t, first, addressA)); m.viewState != ViewKeyList {
			t.Fatalf("the earlier read's reply opened view %v", m.viewState)
		}
		if m = updateModel(t, m, reply(t, second, addressB)); m.viewState != ViewKeyDetails || m.details.address != addressB {
			t.Fatalf("view %v address %q, want %s's details", m.viewState, m.details.address, addressB)
		}
	})
}
