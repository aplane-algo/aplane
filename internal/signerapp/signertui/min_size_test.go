// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// sizedForTest delivers a terminal or pane size the way Bubble Tea does.
func sizedForTest(t *testing.T, m Model, width, height int) Model {
	t.Helper()
	next, _ := m.Update(tea.WindowSizeMsg{Width: width, Height: height})
	return next.(Model)
}

func TestBelowMinSizeShowsOnlyTheResizeScreen(t *testing.T) {
	for _, standalone := range []bool{false, true} {
		for _, size := range [][2]int{{MinWidth - 1, MinHeight}, {MinWidth, MinHeight - 1}, {30, 8}} {
			m := sizedForTest(t, Model{viewState: ViewKeyList, standalone: standalone}, size[0], size[1])
			view := stripANSI(m.View())
			want := fmt.Sprintf("this window is %d×%d", size[0], size[1])
			if !strings.Contains(view, "Window too small") || !strings.Contains(strings.Join(strings.Fields(view), " "), want) {
				t.Fatalf("standalone %v, %dx%d: no resize screen:\n%s", standalone, size[0], size[1], view)
			}
			if strings.Contains(view, "g: Generate") {
				t.Fatalf("standalone %v, %dx%d: the key list shows through:\n%s", standalone, size[0], size[1], view)
			}
			for _, line := range strings.Split(view, "\n") {
				if lipgloss.Width(line) > size[0] {
					t.Fatalf("standalone %v, %dx%d: line wider than the window: %q", standalone, size[0], size[1], line)
				}
			}
		}
		m := sizedForTest(t, Model{viewState: ViewKeyList, standalone: standalone}, MinWidth, MinHeight)
		if view := stripANSI(m.View()); strings.Contains(view, "Window too small") {
			t.Fatalf("standalone %v: the floor itself is treated as too small:\n%s", standalone, view)
		}
	}
}

func TestBelowMinSizeIgnoresKeysButQuit(t *testing.T) {
	m := sizedForTest(t, Model{viewState: ViewKeyList, connectionState: ConnectionConnected}, MinWidth-1, MinHeight)
	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("g")})
	if got := next.(Model); got.viewState != ViewKeyList || cmd != nil {
		t.Fatalf("a key acted on the hidden key list: view %v, cmd %v", got.viewState, cmd != nil)
	}

	pending := &PendingSignRequest{ID: "sign-1"}
	m = sizedForTest(t, Model{viewState: ViewSigningPopup, signing: signingState{request: pending}}, MinWidth-1, MinHeight)
	if view := stripANSI(m.View()); !strings.Contains(view, "An approval request is waiting.") {
		t.Fatalf("the resize screen hides a waiting approval:\n%s", view)
	}
	for _, key := range []tea.KeyMsg{{Type: tea.KeyRunes, Runes: []rune("y")}, {Type: tea.KeyEnter}, {Type: tea.KeyRunes, Runes: []rune("n")}} {
		next, cmd := m.Update(key)
		got := next.(Model)
		if got.viewState != ViewSigningPopup || got.signing.request != pending || cmd != nil {
			t.Fatalf("%q answered an approval the operator cannot see", key.String())
		}
	}

	_, cmd = m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	if cmd == nil {
		t.Fatal("ctrl+c does not quit below the minimum size")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Fatal("ctrl+c below the minimum size does not quit")
	}
}

// At the minimum size every view fits its window without falling back to the
// panel scroller and without cutting content off. The views are rendered with
// no data; views whose data can be arbitrarily long (key lists, transaction
// details, policy documents) scroll that data by their own controls.
func TestEveryViewFitsAtMinSize(t *testing.T) {
	skipped := map[ViewState]string{
		ViewPolicyEdit: "renders an open editor, which only exists with a loaded document",
	}
	for _, standalone := range []bool{false, true} {
		for v := ViewAuth; v <= ViewStoreRecovery; v++ {
			if _, skip := skipped[v]; skip {
				continue
			}
			base := Model{viewState: v, standalone: standalone, auth: authState{passphraseMasked: true},
				forms: formsState{importMnemonicInput: newImportMnemonicInput()}}
			m := sizedForTest(t, base, MinWidth, MinHeight)
			view := stripANSI(m.View())
			lines := strings.Split(view, "\n")
			if len(lines) > MinHeight {
				t.Errorf("standalone %v, view %d: %d lines in a %d-line window", standalone, v, len(lines), MinHeight)
			}
			for _, line := range lines {
				if lipgloss.Width(line) > MinWidth {
					t.Errorf("standalone %v, view %d: line wider than the window: %q", standalone, v, line)
					break
				}
			}
			if strings.Contains(view, "Panel lines") {
				t.Errorf("standalone %v, view %d: falls back to the panel scroller:\n%s", standalone, v, view)
				continue
			}
			tall := sizedForTest(t, base, MinWidth, 400)
			need := strings.Count(strings.TrimRight(stripANSI(tall.renderViewContent()), "\n"), "\n") + 1
			if need > m.windowBodyHeight() {
				t.Errorf("standalone %v, view %d: needs %d rows, has %d, so content is cut off:\n%s",
					standalone, v, need, m.windowBodyHeight(), view)
			}
		}
	}
}
