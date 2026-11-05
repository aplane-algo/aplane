// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/aplane-algo/aplane/internal/protocol"
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

// A standalone terminal one row tall leaves the model a height of zero, which
// is still a known, too-small window, not an unknown one.
func TestOneRowStandaloneTerminalIsBelowMinSize(t *testing.T) {
	for _, size := range [][2]int{{MinWidth, 1}, {0, MinHeight}} {
		m := sizedForTest(t, Model{viewState: ViewKeyList, standalone: true, connectionState: ConnectionConnected}, size[0], size[1])
		if !m.belowMinSize() {
			t.Fatalf("%dx%d: not treated as below the minimum size", size[0], size[1])
		}
		next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("g")})
		if got := next.(Model); got.viewState != ViewKeyList || cmd != nil {
			t.Fatalf("%dx%d: g acted on the hidden key list: view %v", size[0], size[1], got.viewState)
		}
		if view := stripANSI(m.View()); strings.Contains(view, "Generate") {
			t.Fatalf("%dx%d: the key list shows through: %q", size[0], size[1], view)
		}
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

// TestListsKeepTheirContentAtMinSize renders lists with realistic rows, which
// TestEveryViewFitsAtMinSize cannot: a row wider than the window is clipped
// without any error, so what matters is that the text is still on screen.
func TestListsKeepTheirContentAtMinSize(t *testing.T) {
	const (
		address     = "SGCU7MLRXQ4H227YCRTTT6MHL2N64WGJPHH3OTPID2CK4JNGJU6DITLIUQ"
		fingerprint = "SHA256:Abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"
		witnessKey  = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
		longType    = "aplane.falcon1024-allowlist-lock.v1"
	)
	requestedAt := int64(1790000000)
	clients := clientsState{
		pending: []protocol.PendingEnrollmentInfo{{
			Fingerprint: fingerprint, Label: "a-very-long-label-from-a-laptop", KeyType: "ssh-ed25519",
			RemoteAddr: "192.168.100.250:51234", RequestedAt: requestedAt,
		}},
		keys: []protocol.EnrolledKeyInfo{
			{Fingerprint: fingerprint, Label: "a-very-long-label-on-ops", KeyType: "ssh-rsa", Connected: true},
			{Fingerprint: fingerprint, KeyType: "ssh-ed25519"},
		},
	}
	enrolledSelected := clients
	enrolledSelected.selected = 1
	hint := uint64(1234567)
	tests := []struct {
		name  string
		model Model
		want  []string
	}{
		{"pending client selected", Model{viewState: ViewEnrolledClients, clients: clients}, []string{
			"> " + fingerprint, "  connected", "a-very-long-label-from-a-laptop", "192.168.100.250:51234",
			time.Unix(requestedAt, 0).Local().Format("2006-01-02 15:04"), "closes its connections",
		}},
		{"enrolled client selected", Model{viewState: ViewEnrolledClients, clients: enrolledSelected}, []string{
			"> " + fingerprint, "  connected", "a-very-long-label-on-ops", "ssh-rsa",
		}},
		{"restore flags", Model{viewState: ViewRestorePreview, restore: restoreState{previewKeys: []RestoreKeyInfo{
			{Address: address, KeyType: "ed25519"},
			{Address: address, KeyType: longType, AlreadyExists: true, HasPolicy: true},
			{Address: address, KeyType: "aplane.rotating-triple-slhdsa.v1", StageHint: &hint, AlreadyExists: true, HasPolicy: true},
		}}}, []string{
			"lock.v1]  present  +policy", "hint 1234567  present  +policy", "[ed25519]",
		}},
		{"restore row error", Model{viewState: ViewRestorePreview, restore: restoreState{previewKeys: []RestoreKeyInfo{
			{Address: address, KeyType: longType, AlreadyExists: true, Error: "archive entry failed its integrity check"},
		}}}, []string{"present  archive entry"}},
		{"cosigner references", Model{viewState: ViewCosignerReferences, cosigner: cosignerState{loaded: true, references: []CosignerReferenceInfo{
			{Name: "a-reference-name-that-is-longer-than-any-window-has-room-for", ComponentKey: witnessKey, KeyType: "aplane.falcon1024.v1"},
			{Name: "ops", ComponentKey: witnessKey, KeyType: "ed25519"},
		}}}, []string{"abcdef0123...0123456789  aplane.falcon1024.v1", "abcdef0123...0123456789  ed25519"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			m := sizedForTest(t, test.model, MinWidth, MinHeight)
			view := stripANSI(m.View())
			for _, line := range strings.Split(view, "\n") {
				if lipgloss.Width(line) > MinWidth {
					t.Errorf("line wider than the window: %q", line)
				}
			}
			for _, want := range test.want {
				if !strings.Contains(view, want) {
					t.Errorf("%q missing from:\n%s", want, view)
				}
			}
		})
	}
}

func TestCosignerReferenceColumnsAlign(t *testing.T) {
	const witnessKey = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	m := sizedForTest(t, Model{viewState: ViewCosignerReferences, cosigner: cosignerState{loaded: true, references: []CosignerReferenceInfo{
		{Name: "a-reference-name-that-is-longer-than-any-window-has-room-for", ComponentKey: witnessKey, KeyType: "aplane.falcon1024.v1"},
		{Name: "backup-site", ComponentKey: witnessKey, KeyType: "ed25519"},
		{Name: "ops", ComponentKey: witnessKey, KeyType: "ed25519"},
	}}}, MinWidth, MinHeight)

	column := -1
	rows := 0
	for _, line := range strings.Split(stripANSI(m.View()), "\n") {
		index := strings.Index(line, "abcdef0123...")
		if index < 0 {
			continue
		}
		rows++
		if column < 0 {
			column = index
		}
		if index != column {
			t.Errorf("witness ID at %d, want %d: %q", index, column, line)
		}
	}
	if rows != 3 {
		t.Fatalf("found %d rows, want 3", rows)
	}
}
