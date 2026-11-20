// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// Every pager can show the last line of what it pages: scrolled as far as its
// keys allow, the whole screen (header, the pager, its footer and the status
// bar) holds that line. A pager that reserves too few lines for its own
// header leaves its end below the bottom of the terminal.
func TestPagersReachTheirLastLine(t *testing.T) {
	numbered := func(n int) []string {
		lines := make([]string, n)
		for i := range lines {
			lines[i] = fmt.Sprintf("line-%03d", i+1)
		}
		return lines
	}
	pagers := []struct {
		name  string
		setup func(m *Model, lines []string)
		last  string
		// popup: the pager is a popup, whose bottom border must be drawn;
		// a popup too tall for the screen is cut from the bottom, its
		// border first.
		popup bool
	}{
		{"library YAML", func(m *Model, lines []string) {
			m.viewState = ViewLibraryTemplateDetails
			m.library.detailsKeyType = "publisher.family.v1"
			m.library.detailsSourcePath = "/data/templates/publisher.family.v1.yaml"
			m.library.detailsSourceModTime = 1_700_000_000
			m.library.detailsSourceSHA256 = strings.Repeat("ab", 32)
			m.library.detailsContent = strings.Join(lines, "\n")
		}, "line-080", false},
		{"TEAL source", func(m *Model, lines []string) {
			m.viewState = ViewTEALFullDisplay
			m.details.address = strings.Repeat("A", 58)
			m.details.teal = strings.Join(lines, "\n")
		}, "line-080", false},
		{"key details", func(m *Model, lines []string) {
			m.viewState = ViewKeyDetails
			m.details.address = strings.Repeat("A", 58)
			// A native key type, so the recovery phrase line is drawn too.
			m.details.keyType = "falcon1024"
			m.details.publicKeyHex = strings.Repeat("cd", 32)
			m.details.policyLabel = "per-key policy"
			m.details.templateProvenanceNote = "the installed template differs from the one this key was made with"
			m.details.saveStatus = "Saved."
			m.details.parameters = map[string]string{}
			for _, line := range lines[:30] {
				m.details.parameters["p"+line] = "value"
			}
		}, "pline-030: value", true},
		{"key details with wrapped values", func(m *Model, lines []string) {
			m.viewState = ViewKeyDetails
			m.details.address = strings.Repeat("A", 58)
			m.details.keyType = "publisher.family.v1"
			m.details.parameters = map[string]string{}
			// "parameter-line-NNN: <58 characters>" is wider than the popup
			// at 80 columns, so each one takes two rows.
			for i, line := range lines[:30] {
				m.details.parameters["parameter-"+line] = strings.Repeat("R", 55) + fmt.Sprintf("%03d", i+1)
			}
		}, strings.Repeat("R", 55) + "030", true},
	}
	for _, p := range pagers {
		for _, size := range []struct {
			width, height int
			standalone    bool
		}{
			{MinWidth, MinHeight, false}, {MinWidth, MinHeight, true}, {100, 28, true}, {100, 31, false}, {100, 31, true}, {133, 39, true}, {100, 40, false},
		} {
			width, height := size.width, size.height
			t.Run(fmt.Sprintf("%s at %dx%d standalone %v", p.name, width, height, size.standalone), func(t *testing.T) {
				m := Model{width: width, height: height, standalone: size.standalone, connectionState: ConnectionConnected}
				p.setup(&m, numbered(80))
				for i := 0; i < 200; i++ {
					m = updateModel(t, m, tea.KeyMsg{Type: tea.KeyDown})
				}
				screen := stripANSI(m.View())
				if rows := strings.Count(screen, "\n") + 1; rows > height {
					t.Fatalf("the screen is %d rows on a %d-row terminal", rows, height)
				}
				if !strings.Contains(screen, p.last) {
					t.Fatalf("scrolled to the end, the screen does not show %q:\n%s", p.last, screen)
				}
				if p.popup && !strings.Contains(screen, "╚") {
					t.Fatalf("the popup is cut off at the bottom:\n%s", screen)
				}
			})
		}
	}
}

// Key Details' rows depend on the terminal width, so an offset scrolled to
// the end at one width can be past the end at a wider one. The pager still
// shows its last rows there, and the first press of up scrolls.
func TestKeyDetailsScrolledThenWidenedStillShowsParameters(t *testing.T) {
	m := Model{width: MinWidth, height: MinHeight, connectionState: ConnectionConnected}
	m.viewState = ViewKeyDetails
	m.details.address = strings.Repeat("A", 58)
	m.details.keyType = "publisher.family.v1"
	m.details.parameters = map[string]string{}
	for i := 1; i <= 30; i++ {
		m.details.parameters[fmt.Sprintf("parameter-line-%03d", i)] = strings.Repeat("R", 55) + fmt.Sprintf("%03d", i)
	}
	for i := 0; i < 200; i++ {
		m = updateModel(t, m, tea.KeyMsg{Type: tea.KeyDown})
	}
	m = updateModel(t, m, tea.WindowSizeMsg{Width: 160, Height: MinHeight})
	last := strings.Repeat("R", 55) + "030"
	if screen := stripANSI(m.View()); !strings.Contains(screen, last) {
		t.Fatalf("widened after scrolling, the screen does not show the last parameter:\n%s", screen)
	}
	before := stripANSI(m.View())
	m = updateModel(t, m, tea.KeyMsg{Type: tea.KeyUp})
	if stripANSI(m.View()) == before {
		t.Fatal("the first press of up after widening did not scroll")
	}
}

type refusingConnector struct{ attempts atomic.Int32 }

func (c *refusingConnector) Connect() (io.ReadWriteCloser, error) {
	c.attempts.Add(1)
	return nil, errors.New("connection refused")
}
func (c *refusingConnector) Label() string { return "test" }

// A reconnect keeps trying while the signer is unreachable. A failed attempt
// once began a new session, which the loop then took for a newer connection
// and stopped for, with nothing left trying and the TUI told nothing.
func TestReconnectKeepsTryingWhileTheSignerIsUnreachable(t *testing.T) {
	conn := &refusingConnector{}
	c := NewAdminClient(conn)
	c.reconnectDelay, c.maxDelay = time.Millisecond, 2*time.Millisecond
	c.mu.Lock()
	sessionID := c.sessionID
	c.mu.Unlock()

	done := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		c.reconnect(sessionID, done)
		close(finished)
	}()
	deadline := time.After(2 * time.Second)
	for conn.attempts.Load() < 5 {
		select {
		case <-finished:
			t.Fatalf("the reconnect loop gave up after %d attempt(s) while the signer was unreachable", conn.attempts.Load())
		case <-deadline:
			t.Fatalf("only %d attempt(s) in 2s", conn.attempts.Load())
		case <-time.After(time.Millisecond):
		}
	}
	// Disconnecting stops it.
	c.Disconnect()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("the reconnect loop did not stop on Disconnect")
	}
}
