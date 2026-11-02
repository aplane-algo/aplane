// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/protocol"
	tea "github.com/charmbracelet/bubbletea"
)

func TestSelectionWindow(t *testing.T) {
	for _, tc := range []struct{ selected, total, visible, start, end int }{
		{0, 5, 10, 0, 5},
		{0, 20, 5, 0, 5},
		{10, 20, 5, 8, 13},
		{19, 20, 5, 15, 20},
		{-3, 20, 5, 0, 5},
		{99, 20, 5, 15, 20},
	} {
		start, end := selectionWindow(tc.selected, tc.total, tc.visible)
		if start != tc.start || end != tc.end {
			t.Errorf("selectionWindow(%d, %d, %d) = %d, %d; want %d, %d",
				tc.selected, tc.total, tc.visible, start, end, tc.start, tc.end)
		}
	}
}

// manyServerKeyTypes registers n key types, each importable from a mnemonic.
func manyServerKeyTypes(t *testing.T, n int) []string {
	t.Helper()
	var names []string
	var infos []protocol.KeyTypeInfo
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("test.keytype-%02d.v1", i)
		names = append(names, name)
		infos = append(infos, protocol.KeyTypeInfo{KeyType: name, DisplayName: name, MnemonicImport: true, MnemonicWordCount: 25})
	}
	setServerKeyTypes(infos)
	t.Cleanup(func() { setServerKeyTypes(nil) })
	return names
}

// assertFitsWindow fails when the rendered view is taller than the window.
func assertFitsWindow(t *testing.T, m Model) string {
	t.Helper()
	view := m.View()
	if lines := strings.Count(view, "\n") + 1; lines > m.height {
		t.Fatalf("view is %d lines in a %d-line window:\n%s", lines, m.height, view)
	}
	return view
}

func TestGenerateFormKeepsSelectionAndDescriptionVisible(t *testing.T) {
	names := manyServerKeyTypes(t, 20)
	m := Model{viewState: ViewGenerateForm, width: 90, height: 22, standalone: true}

	view := assertFitsWindow(t, m)
	if !strings.Contains(view, "> "+names[0]) || !strings.Contains(view, "more below") || strings.Contains(view, names[19]) {
		t.Fatalf("the first screen should show the top of the list and how much is below:\n%s", view)
	}
	if strings.Contains(view, "Select Key Type") {
		t.Fatal("the generate form still shows the list heading")
	}

	for i := 0; i < 19; i++ {
		next, _ := m.handleKeyPress(tea.KeyMsg{Type: tea.KeyDown})
		m = next.(Model)
	}
	view = assertFitsWindow(t, m)
	if !strings.Contains(view, "> "+names[19]) || !strings.Contains(view, "more above") || strings.Contains(view, "more below") {
		t.Fatalf("the last key type is not shown selected at the end of the list:\n%s", view)
	}
	// The description of the selection sits below the list, after a blank line.
	if strings.Count(view, names[19]) < 2 {
		t.Fatalf("the selected key type's description is not shown:\n%s", view)
	}

	m.height = 60
	if view := assertFitsWindow(t, m); strings.Contains(view, "more above") || !strings.Contains(view, names[0]) {
		t.Fatalf("a tall window should show the whole list:\n%s", view)
	}
}

func TestImportFormKeepsButtonVisible(t *testing.T) {
	names := manyServerKeyTypes(t, 20)
	m := Model{viewState: ViewImportForm, width: 90, height: 26, standalone: true,
		forms: formsState{importMnemonicInput: newImportMnemonicInput(), importKeyType: 6}}
	view := assertFitsWindow(t, m)
	if !strings.Contains(view, "IMPORT KEY") {
		t.Fatalf("the import button is off screen:\n%s", view)
	}
	if !strings.Contains(view, "> "+names[6]) {
		t.Fatalf("the selected key type is off screen:\n%s", view)
	}
}
