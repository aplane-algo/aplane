// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/aplane-algo/aplane/internal/protocol"
)

// textPagers are the four full-screen text pagers, each set up to page
// lines, with what each keeps as its offset and how many lines it shows.
func textPagers() []struct {
	name    string
	setup   func(m *Model, lines []string)
	offset  func(m *Model) *int
	visible func(m Model) int
} {
	return []struct {
		name    string
		setup   func(m *Model, lines []string)
		offset  func(m *Model) *int
		visible func(m Model) int
	}{
		{"TEAL source", func(m *Model, lines []string) {
			m.viewState = ViewTEALFullDisplay
			m.details.address = strings.Repeat("A", 58)
			m.details.teal = strings.Join(lines, "\n")
		}, func(m *Model) *int { return &m.details.scrollOffset }, Model.tealFullDisplayVisibleLines},
		{"library YAML", func(m *Model, lines []string) {
			m.viewState = ViewLibraryTemplateDetails
			m.library.detailsKeyType = "publisher.family.v1"
			m.library.detailsContent = strings.Join(lines, "\n")
		}, func(m *Model) *int { return &m.library.detailsScrollOffset }, Model.libraryTemplateDetailsVisibleLines},
		{"policy document", func(m *Model, lines []string) {
			m.viewState = ViewPolicyDocument
			m.policies.document = protocol.PolicyDocumentMessage{Success: true, Key: "default", Document: strings.Join(lines, "\n")}
		}, func(m *Model) *int { return &m.policies.scrollOffset }, Model.policyDocumentVisibleLines},
		{"policy apply review", func(m *Model, lines []string) {
			m.viewState = ViewPolicyApplyReview
			m.policies.apply.file = "default.json"
			m.policies.apply.diffLines = lines
		}, func(m *Model) *int { return &m.policies.apply.scrollOffset }, Model.policyApplyVisibleLines},
	}
}

var pagerLineRE = regexp.MustCompile(`line-(\d{3})`)

// shownLines is the first and last numbered line on the screen, and whether
// the screen marks lines above and below them.
func shownLines(t *testing.T, screen string) (first, last int, above, below bool) {
	t.Helper()
	first = -1
	for _, match := range pagerLineRE.FindAllStringSubmatch(screen, -1) {
		n, err := strconv.Atoi(match[1])
		if err != nil {
			t.Fatal(err)
		}
		if first < 0 {
			first = n
		}
		last = n
	}
	return first, last, strings.Contains(screen, "▲"), strings.Contains(screen, "▼")
}

// Every text pager scrolls the same way: up/down and k/j move a line,
// pgup/pgdown a page, never before the first line or past the point where
// the last line is at the bottom, and the screen shows the lines from the
// offset with a marker for those above and below.
func TestTextPagersScrollAlike(t *testing.T) {
	const total = 40
	lines := make([]string, total)
	for i := range lines {
		lines[i] = fmt.Sprintf("line-%03d", i+1)
	}
	keys := []struct {
		msg  tea.KeyMsg
		step func(visible int) int
	}{
		{tea.KeyMsg{Type: tea.KeyDown}, func(int) int { return 1 }},
		{tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'j'}}, func(int) int { return 1 }},
		{tea.KeyMsg{Type: tea.KeyDown}, func(int) int { return 1 }},
		{tea.KeyMsg{Type: tea.KeyPgDown}, func(v int) int { return v }},
		{tea.KeyMsg{Type: tea.KeyUp}, func(int) int { return -1 }},
		{tea.KeyMsg{Type: tea.KeyPgDown}, func(v int) int { return v }},
		{tea.KeyMsg{Type: tea.KeyPgDown}, func(v int) int { return v }},
		{tea.KeyMsg{Type: tea.KeyPgDown}, func(v int) int { return v }},
		{tea.KeyMsg{Type: tea.KeyDown}, func(int) int { return 1 }},
		{tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'k'}}, func(int) int { return -1 }},
		{tea.KeyMsg{Type: tea.KeyPgUp}, func(v int) int { return -v }},
		{tea.KeyMsg{Type: tea.KeyUp}, func(int) int { return -1 }},
		{tea.KeyMsg{Type: tea.KeyPgUp}, func(v int) int { return -v }},
		{tea.KeyMsg{Type: tea.KeyPgUp}, func(v int) int { return -v }},
		{tea.KeyMsg{Type: tea.KeyUp}, func(int) int { return -1 }},
	}
	for _, p := range textPagers() {
		for _, size := range []struct{ width, height int }{{MinWidth, MinHeight}, {100, 31}} {
			t.Run(fmt.Sprintf("%s at %dx%d", p.name, size.width, size.height), func(t *testing.T) {
				m := Model{width: size.width, height: size.height, connectionState: ConnectionConnected}
				p.setup(&m, lines)
				visible := p.visible(m)
				maxOffset := total - visible
				want := 0
				for i, key := range keys {
					m = updateModel(t, m, key.msg)
					want = max(0, min(want+key.step(visible), maxOffset))
					if got := *p.offset(&m); got != want {
						t.Fatalf("after key %d (%s): offset %d, want %d", i, key.msg, got, want)
					}
					first, last, above, below := shownLines(t, stripANSI(m.View()))
					end := min(want+visible, total)
					if first != want+1 || last != end || above != (want > 0) || below != (end < total) {
						t.Fatalf("after key %d at offset %d: shows lines %d-%d (above %v, below %v), want %d-%d (above %v, below %v)",
							i, want, first, last, above, below, want+1, end, want > 0, end < total)
					}
				}
			})
		}
	}
}

// An offset past the last full window, left by a taller window or shorter
// text, draws the last full window, and the first press of up scrolls up
// from it. Before the pagers were one, the TEAL and library pagers restarted
// from the top for an offset past the text and drew a short window for one
// past the last full window, and the policy pagers drew nothing but a marker
// for an offset past the text.
func TestTextPagersHoldAnOffsetPastTheEnd(t *testing.T) {
	const total = 40
	lines := make([]string, total)
	for i := range lines {
		lines[i] = fmt.Sprintf("line-%03d", i+1)
	}
	for _, p := range textPagers() {
		for _, past := range []int{35, total, 100} {
			t.Run(fmt.Sprintf("%s at offset %d", p.name, past), func(t *testing.T) {
				m := Model{width: MinWidth, height: MinHeight, connectionState: ConnectionConnected}
				p.setup(&m, lines)
				*p.offset(&m) = past
				maxOffset := total - p.visible(m)
				first, last, above, below := shownLines(t, stripANSI(m.View()))
				if first != maxOffset+1 || last != total || !above || below {
					t.Fatalf("shows lines %d-%d (above %v, below %v), want %d-%d with only lines above", first, last, above, below, maxOffset+1, total)
				}
				m = updateModel(t, m, tea.KeyMsg{Type: tea.KeyUp})
				if got := *p.offset(&m); got != maxOffset-1 {
					t.Fatalf("up from offset %d: offset %d, want %d", past, got, maxOffset-1)
				}
			})
		}
	}
}
