// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
)

func TestLayoutSplitAndZoom(t *testing.T) {
	m := model{width: splitMinWidth, height: splitMinHeight}
	if got := m.layout(); !got.split {
		t.Fatalf("layout().split = false, want true for large terminal")
	}

	m.zoomed = true
	if got := m.layout(); got.split {
		t.Fatalf("layout().split = true, want false when zoomed")
	}
}

func TestLayoutSmallTerminalFallsBackToFocusedPane(t *testing.T) {
	m := model{width: splitMinWidth - 1, height: splitMinHeight}
	if got := m.layout(); got.split {
		t.Fatalf("layout().split = true, want false below split width")
	}

	m = model{width: splitMinWidth, height: splitMinHeight - 1}
	if got := m.layout(); got.split {
		t.Fatalf("layout().split = true, want false below split height")
	}
}

func TestSplitLayoutCompactsExternallyManagedDaemon(t *testing.T) {
	m := model{
		daemon: newDaemonModel(daemonInfo{
			Status:  daemonStatusAttached,
			DataDir: "/tmp/apsigner",
			IPCPath: "/tmp/apsigner/apsigner.sock",
			Detail:  "attached to existing apsigner",
		}, nil),
		width:  splitMinWidth,
		height: splitMinHeight,
	}

	l := m.layout()
	wantDaemonHeight := m.daemon.preferredCompactHeight()
	if l.daemon.height != wantDaemonHeight {
		t.Fatalf("daemon height = %d, want compact height %d", l.daemon.height, wantDaemonHeight)
	}
	if l.signer.height != l.contentHeight-wantDaemonHeight {
		t.Fatalf("top pane height = %d, want %d", l.signer.height, l.contentHeight-wantDaemonHeight)
	}
}

func TestSplitLayoutKeepsOwnedDaemonLogArea(t *testing.T) {
	m := model{
		daemon: newDaemonModel(daemonInfo{
			Status:  daemonStatusStarting,
			Owned:   true,
			DataDir: "/tmp/apsigner",
			IPCPath: "/tmp/apsigner/apsigner.sock",
			Detail:  "started apsigner; waiting for IPC",
		}, make(chan daemonEvent)),
		width:  splitMinWidth,
		height: splitMinHeight + 4,
	}

	l := m.layout()
	compactHeight := paneBorderSize + 1 + compactDaemonMaxBodyRows
	if l.daemon.height <= compactHeight {
		t.Fatalf("daemon height = %d, want larger log area than compact height %d", l.daemon.height, compactHeight)
	}
}

func TestSplitLayoutUsesSignerShellFortyFiveFiftyFiveRatio(t *testing.T) {
	m := model{
		width:  201, // 200 top-pane columns after the one-column pane gap.
		height: splitMinHeight,
	}

	l := m.layout()
	if !l.split {
		t.Fatal("layout().split = false, want split layout")
	}
	if l.signer.width != 90 || l.shell.width != 110 {
		t.Fatalf("pane widths = signer %d shell %d, want 90/110", l.signer.width, l.shell.width)
	}
}

func TestNewModelStartsWithSignerFocused(t *testing.T) {
	m := newModel(testConnector{}, "/tmp/apsigner", nil, nil, newDaemonModel(daemonInfo{Status: daemonStatusAttached}, nil))
	if m.focus != paneSigner {
		t.Fatalf("focus = %v, want signer", m.focus)
	}
}

func TestTerminalSizeRejectsNilFile(t *testing.T) {
	width, height, ok := terminalSize(nil)
	if ok || width != 0 || height != 0 {
		t.Fatalf("terminalSize(nil) = (%d, %d, %v), want zero false", width, height, ok)
	}
}

func TestSplitLayoutRendersSignerBeforeShell(t *testing.T) {
	m := model{
		focus:  paneSigner,
		shell:  newShellModel(nil, []string{"shell ready"}),
		signer: stubTeaModel{},
		daemon: newDaemonModel(daemonInfo{Status: daemonStatusAttached, Detail: "attached"}, nil),
		width:  splitMinWidth,
		height: splitMinHeight,
	}

	got := m.renderBody(m.layout())
	signerPos := strings.Index(got, "Signer")
	shellPos := strings.Index(got, "Shell")
	if signerPos < 0 || shellPos < 0 {
		t.Fatalf("rendered view missing pane headers: signer=%d shell=%d\n%s", signerPos, shellPos, got)
	}
	if signerPos > shellPos {
		t.Fatalf("signer pane rendered after shell pane: signer=%d shell=%d", signerPos, shellPos)
	}
}

func TestSplitLayoutSeparatesTopPaneBorders(t *testing.T) {
	m := model{
		focus:  paneShell,
		shell:  newShellModel(nil, []string{"shell ready"}),
		signer: stubTeaModel{},
		daemon: newDaemonModel(daemonInfo{Status: daemonStatusAttached, Detail: "attached"}, nil),
		width:  splitMinWidth,
		height: splitMinHeight,
	}

	l := m.layout()
	if got := l.signer.width + topPaneGap + l.shell.width; got != l.contentWidth {
		t.Fatalf("top pane widths = %d + %d + %d = %d, want content width %d",
			l.signer.width, topPaneGap, l.shell.width, got, l.contentWidth)
	}

	got := m.renderBody(l)
	if strings.Contains(got, "││") {
		t.Fatalf("top pane seam rendered as doubled vertical border:\n%s", got)
	}
}

func TestBubbleTeaProgramSmoke(t *testing.T) {
	var input bytes.Buffer
	input.WriteByte(0x03) // Ctrl+C opens the quit-confirm overlay.
	input.WriteByte('\r') // Enter confirms.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	m := model{
		focus:  paneShell,
		shell:  newShellModel(nil, []string{"shell ready"}),
		signer: stubTeaModel{},
		daemon: newDaemonModel(daemonInfo{Status: daemonStatusAttached, Detail: "attached"}, nil),
		width:  100,
		height: 28,
	}
	p := tea.NewProgram(m,
		tea.WithInput(&input),
		tea.WithOutput(io.Discard),
		tea.WithContext(ctx),
		tea.WithoutRenderer(),
	)
	if _, err := p.Run(); err != nil {
		t.Fatalf("program run failed: %v", err)
	}
}

func TestPaneNavigationCyclesShellSignerAndDaemon(t *testing.T) {
	if got := nextPane(paneSigner, true); got != paneShell {
		t.Fatalf("nextPane(signer) = %v, want shell", got)
	}
	if got := nextPane(paneShell, true); got != paneDaemon {
		t.Fatalf("nextPane(shell) = %v, want daemon", got)
	}
	if got := nextPane(paneDaemon, true); got != paneSigner {
		t.Fatalf("nextPane(daemon) = %v, want signer", got)
	}
	if got := prevPane(paneDaemon, true); got != paneShell {
		t.Fatalf("prevPane(daemon) = %v, want shell", got)
	}
	if got := prevPane(paneShell, true); got != paneSigner {
		t.Fatalf("prevPane(shell) = %v, want signer", got)
	}
}

func TestPaneNavigationSkipsDaemonWithoutLog(t *testing.T) {
	if got := nextPane(paneShell, false); got != paneSigner {
		t.Fatalf("nextPane(shell, false) = %v, want signer", got)
	}
	if got := prevPane(paneSigner, false); got != paneShell {
		t.Fatalf("prevPane(signer, false) = %v, want shell", got)
	}
}

func TestF3IgnoresDaemonWithoutLog(t *testing.T) {
	m := model{
		focus:  paneSigner,
		daemon: newDaemonModel(daemonInfo{Status: daemonStatusAttached}, nil),
	}

	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyF3})
	if cmd != nil {
		t.Fatalf("cmd = %v, want nil", cmd)
	}
	got := next.(model)
	if got.focus != paneSigner {
		t.Fatalf("focus = %v, want signer", got.focus)
	}
}

func TestF3FocusesDaemonWithLog(t *testing.T) {
	m := model{
		focus:  paneSigner,
		daemon: newDaemonModel(daemonInfo{Status: daemonStatusStarting, Owned: true}, make(chan daemonEvent)),
	}

	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyF3})
	if cmd != nil {
		t.Fatalf("cmd = %v, want nil", cmd)
	}
	got := next.(model)
	if got.focus != paneDaemon {
		t.Fatalf("focus = %v, want daemon", got.focus)
	}
}

func TestF1FocusesSignerAndF2FocusesShell(t *testing.T) {
	m := model{focus: paneShell}

	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyF1})
	if cmd != nil {
		t.Fatalf("F1 cmd = %v, want nil", cmd)
	}
	got := next.(model)
	if got.focus != paneSigner {
		t.Fatalf("F1 focus = %v, want signer", got.focus)
	}

	next, cmd = got.Update(tea.KeyMsg{Type: tea.KeyF2})
	if cmd != nil {
		t.Fatalf("F2 cmd = %v, want nil", cmd)
	}
	got = next.(model)
	if got.focus != paneShell {
		t.Fatalf("F2 focus = %v, want shell", got.focus)
	}
}

func TestMouseEventsDoNotChangePaneFocus(t *testing.T) {
	m := model{
		focus:  paneSigner,
		signer: recordingTeaModel{},
		daemon: newDaemonModel(daemonInfo{Status: daemonStatusStarting, Owned: true}, make(chan daemonEvent)),
		width:  splitMinWidth,
		height: splitMinHeight,
	}
	l := m.layout()

	next, cmd := m.Update(leftMousePress(l.signer.width+topPaneGap+1, headerHeight+1))
	if cmd != nil {
		t.Fatalf("mouse cmd = %v, want nil", cmd)
	}
	got := next.(model)
	if got.focus != paneSigner {
		t.Fatalf("mouse focus = %v, want signer", got.focus)
	}
	if signer := got.signer.(recordingTeaModel); signer.updates != 0 {
		t.Fatalf("mouse event forwarded to signer %d times, want 0", signer.updates)
	}
}

func TestShellInputIsRoutedWhenShellFocused(t *testing.T) {
	m := model{focus: paneShell, shell: newShellModel(nil, nil)}
	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s', 't', 'a', 't', 'u', 's'}})
	if cmd != nil {
		t.Fatalf("Update(shell key) cmd = %v, want nil", cmd)
	}
	got := next.(model)
	if got.shell.input != "status" {
		t.Fatalf("shell input = %q, want status", got.shell.input)
	}
}

func TestShellEnterAppendsTranscript(t *testing.T) {
	m := newShellModel(nil, nil)
	m.input = "status"
	var cmd tea.Cmd
	m, cmd = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd != nil {
		t.Fatalf("Update(enter) cmd = %v, want nil without executor", cmd)
	}
	if m.input != "" {
		t.Fatalf("input after enter = %q, want empty", m.input)
	}
	if len(m.lines) < 2 || m.lines[len(m.lines)-2] != "> status" {
		t.Fatalf("transcript tail = %#v, want command echo", m.lines)
	}
}

func TestShellCompletionCandidatesRenderAbovePrompt(t *testing.T) {
	exec := &fakeShellExecutor{
		offset:     1,
		completion: []string{"end ", "weep "},
	}
	m := newShellModel(exec, nil)
	m.startupRunning = false
	m.input = "s"
	m.inputCursor = len(m.input)
	m.lines = []string{"old-1", "old-2"}

	var cmd tea.Cmd
	m, cmd = m.Update(tea.KeyMsg{Type: tea.KeyTab})
	if cmd != nil {
		t.Fatalf("tab cmd = %v, want nil", cmd)
	}
	if len(m.completionLines) != 1 || m.completionLines[0] != "send  sweep" {
		t.Fatalf("completionLines = %#v, want send/sweep prompt display", m.completionLines)
	}
	if len(m.lines) != 2 {
		t.Fatalf("transcript lines = %#v, want unchanged transcript", m.lines)
	}

	rows := visibleRows(m.View(30, 6))
	if len(rows) != 6 {
		t.Fatalf("view rows = %d, want 6:\n%s", len(rows), strings.Join(rows, "\n"))
	}
	if got := strings.TrimSpace(rows[len(rows)-3]); got != "send  sweep" {
		t.Fatalf("row above prompt gutter = %q, want completion candidates\nview:\n%s", got, strings.Join(rows, "\n"))
	}
	if got := strings.TrimSpace(rows[len(rows)-2]); got != "" {
		t.Fatalf("gutter row = %q, want blank\nview:\n%s", got, strings.Join(rows, "\n"))
	}
	if got := strings.TrimSpace(rows[len(rows)-1]); got != "> s" {
		t.Fatalf("prompt row = %q, want prompt at bottom\nview:\n%s", got, strings.Join(rows, "\n"))
	}
}

func TestShellCompletionCandidatesClearOnInputEdit(t *testing.T) {
	exec := &fakeShellExecutor{
		offset:     1,
		completion: []string{"end ", "weep "},
	}
	m := newShellModel(exec, nil)
	m.startupRunning = false
	m.input = "s"
	m.inputCursor = len(m.input)

	var cmd tea.Cmd
	m, cmd = m.Update(tea.KeyMsg{Type: tea.KeyTab})
	if cmd != nil {
		t.Fatalf("tab cmd = %v, want nil", cmd)
	}
	if len(m.completionLines) == 0 {
		t.Fatal("completionLines empty after tab, want candidates")
	}

	m, cmd = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'e'}})
	if cmd != nil {
		t.Fatalf("edit cmd = %v, want nil", cmd)
	}
	if len(m.completionLines) != 0 {
		t.Fatalf("completionLines after edit = %#v, want cleared", m.completionLines)
	}
}

func TestShellViewWrapsTranscriptAtRenderTime(t *testing.T) {
	const longLine = "alpha bravo charlie delta echo foxtrot"
	m := shellModel{lines: []string{longLine}}

	view := m.View(12, 6)
	rows := visibleRows(view)
	if len(rows) != 6 {
		t.Fatalf("view rows = %d, want 6:\n%s", len(rows), view)
	}
	for _, row := range rows {
		if len(row) > 12 {
			t.Fatalf("row length = %d, want <= 12: %q\nview:\n%s", len(row), row, view)
		}
	}
	if !strings.Contains(view, "alpha bravo") || !strings.Contains(view, "charlie") {
		t.Fatalf("wrapped transcript missing expected text:\n%s", view)
	}
	if len(m.lines) != 1 || m.lines[0] != longLine {
		t.Fatalf("transcript storage changed: %#v", m.lines)
	}
}

func TestWrapShellRowsDoesNotBreakAtHyphen(t *testing.T) {
	line := "SX2EACRCOIUDIJPKZMTRGKRNPRR4C5OVJ6IMGY2V3UNDRZIIU5447XRTGY [aplane.falcon1024.v1]"
	rows := wrapShellRows([]string{line}, 70)

	if len(rows) < 2 {
		t.Fatalf("wrapShellRows() rows = %d, want wrapped output", len(rows))
	}
	for _, row := range rows {
		visible := strings.TrimRight(ansi.Strip(row), " ")
		if strings.HasSuffix(visible, "falcon1024-") {
			t.Fatalf("wrapped row breaks at hyphen: %q\nrows=%q", visible, rows)
		}
	}
	if !strings.Contains(strings.Join(rows, "\n"), "[aplane.falcon1024.v1]") {
		t.Fatalf("wrapped rows split key type label:\n%q", rows)
	}
}

func TestWrapShellRowsKeepsBracketedContentTogether(t *testing.T) {
	line := "ADDRADDRAA [falcon 1024-v1]"
	rows := wrapShellRows([]string{line}, 24)

	if len(rows) < 2 {
		t.Fatalf("wrapShellRows() rows = %d, want wrapped output", len(rows))
	}
	for _, row := range rows {
		visible := strings.TrimRight(ansi.Strip(row), " ")
		if strings.Contains(visible, "[falcon") && !strings.Contains(visible, "]") {
			t.Fatalf("wrapped row splits bracketed content: %q\nrows=%q", visible, rows)
		}
	}
	if !strings.Contains(strings.Join(rows, "\n"), "[falcon 1024-v1]") {
		t.Fatalf("wrapped rows split bracketed label:\n%q", rows)
	}
}

func TestShellViewWrapsPromptInputAtRenderTime(t *testing.T) {
	const input = "one two three four five"
	m := shellModel{input: input}

	view := m.View(12, 5)
	rows := visibleRows(view)
	if len(rows) != 5 {
		t.Fatalf("view rows = %d, want 5:\n%s", len(rows), view)
	}
	for _, row := range rows {
		if len(row) > 12 {
			t.Fatalf("row length = %d, want <= 12: %q\nview:\n%s", len(row), row, view)
		}
	}
	if !strings.Contains(view, "> one two") || !strings.Contains(view, "three four") || !strings.Contains(view, "five") {
		t.Fatalf("wrapped prompt missing expected text:\n%s", view)
	}
	if m.input != input {
		t.Fatalf("input changed after render: %q", m.input)
	}
}

func TestShellSpinnerTickAdvancesOnlyWhileBusy(t *testing.T) {
	m := shellModel{running: true}

	next, cmd := m.Update(shellSpinnerTickMsg{})
	if next.spinnerIndex != 1 {
		t.Fatalf("spinnerIndex = %d, want 1", next.spinnerIndex)
	}
	if cmd == nil {
		t.Fatal("cmd = nil, want next spinner tick while busy")
	}

	next.running = false
	next, cmd = next.Update(shellSpinnerTickMsg{})
	if next.spinnerIndex != 1 {
		t.Fatalf("idle spinnerIndex = %d, want unchanged 1", next.spinnerIndex)
	}
	if cmd != nil {
		t.Fatalf("idle cmd = %v, want nil", cmd)
	}
}

func TestShellInputCursorEditsInPlace(t *testing.T) {
	m := newShellModel(nil, nil)
	m.startupRunning = false
	for _, r := range "abc" {
		var cmd tea.Cmd
		m, cmd = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
		if cmd != nil {
			t.Fatalf("rune cmd = %v, want nil", cmd)
		}
	}
	m, _ = m.Update(tea.KeyMsg{Type: tea.KeyLeft})
	m, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'X'}})
	if m.input != "abXc" {
		t.Fatalf("input = %q, want abXc", m.input)
	}
	if m.inputCursor != len("abX") {
		t.Fatalf("cursor = %d, want %d", m.inputCursor, len("abX"))
	}

	m, _ = m.Update(tea.KeyMsg{Type: tea.KeyBackspace})
	if m.input != "abc" || m.inputCursor != len("ab") {
		t.Fatalf("after backspace input/cursor = %q/%d, want abc/%d", m.input, m.inputCursor, len("ab"))
	}
	m, _ = m.Update(tea.KeyMsg{Type: tea.KeyDelete})
	if m.input != "ab" || m.inputCursor != len("ab") {
		t.Fatalf("after delete input/cursor = %q/%d, want ab/%d", m.input, m.inputCursor, len("ab"))
	}
}

func TestShellEscClearsInputLine(t *testing.T) {
	m := newShellModel(nil, nil)
	m.startupRunning = false
	m.input = "status"
	m.inputCursor = len("sta")
	m.completionLines = []string{"status"}

	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if cmd != nil {
		t.Fatalf("esc cmd = %v, want nil", cmd)
	}
	if next.input != "" || next.inputCursor != 0 {
		t.Fatalf("after esc input/cursor = %q/%d, want empty/0", next.input, next.inputCursor)
	}
	if len(next.completionLines) != 0 {
		t.Fatalf("after esc completionLines = %#v, want cleared", next.completionLines)
	}
}

func TestPendingLinePromptCursorEditsInPlace(t *testing.T) {
	resp := make(chan string, 1)
	m := newShellModel(nil, nil)
	m.pendingLinePrompt = &shellLinePromptMsg{prompt: "Proceed? ", response: resp}
	m, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'n'}})
	m, _ = m.Update(tea.KeyMsg{Type: tea.KeyLeft})
	m, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'y'}})
	m, _ = m.Update(tea.KeyMsg{Type: tea.KeyDelete})
	m, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})

	select {
	case got := <-resp:
		if got != "y" {
			t.Fatalf("prompt response = %q, want y", got)
		}
	default:
		t.Fatal("prompt response was not sent")
	}
}

func TestPendingLinePromptEscClearsInputLine(t *testing.T) {
	resp := make(chan string, 1)
	m := newShellModel(nil, nil)
	m.pendingLinePrompt = &shellLinePromptMsg{
		prompt:   "Proceed? ",
		input:    "yes",
		cursor:   len("ye"),
		response: resp,
	}

	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if cmd != nil {
		t.Fatalf("esc cmd = %v, want nil", cmd)
	}
	if next.pendingLinePrompt == nil {
		t.Fatal("pendingLinePrompt cleared, want prompt still active")
	}
	if next.pendingLinePrompt.input != "" || next.pendingLinePrompt.cursor != 0 {
		t.Fatalf("after esc prompt input/cursor = %q/%d, want empty/0",
			next.pendingLinePrompt.input, next.pendingLinePrompt.cursor)
	}
	select {
	case got := <-resp:
		t.Fatalf("unexpected prompt response after esc: %q", got)
	default:
	}
}

func TestPromptColorCodeForLipglossPreservesANSISGRColors(t *testing.T) {
	if got := promptColorCodeForLipgloss("32"); got != "2" {
		t.Fatalf("promptColorCodeForLipgloss(32) = %q, want 2", got)
	}
	if got := promptColorCodeForLipgloss("92"); got != "10" {
		t.Fatalf("promptColorCodeForLipgloss(92) = %q, want 10", got)
	}
	if got := promptColorCodeForLipgloss("28"); got != "28" {
		t.Fatalf("promptColorCodeForLipgloss(28) = %q, want unchanged 28", got)
	}
}

func TestShellCommandHistoryNavigatesWithArrows(t *testing.T) {
	m := newShellModel(nil, nil)
	m.input = "status"
	var cmd tea.Cmd
	m, cmd = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd != nil {
		t.Fatalf("first enter cmd = %v, want nil", cmd)
	}
	m.input = "network mainnet"
	m, cmd = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd != nil {
		t.Fatalf("second enter cmd = %v, want nil", cmd)
	}

	m, cmd = m.Update(tea.KeyMsg{Type: tea.KeyUp})
	if cmd != nil {
		t.Fatalf("up cmd = %v, want nil", cmd)
	}
	if m.input != "network mainnet" {
		t.Fatalf("input after first up = %q, want latest command", m.input)
	}

	m, cmd = m.Update(tea.KeyMsg{Type: tea.KeyUp})
	if cmd != nil {
		t.Fatalf("second up cmd = %v, want nil", cmd)
	}
	if m.input != "status" {
		t.Fatalf("input after second up = %q, want previous command", m.input)
	}

	m, cmd = m.Update(tea.KeyMsg{Type: tea.KeyDown})
	if cmd != nil {
		t.Fatalf("down cmd = %v, want nil", cmd)
	}
	if m.input != "network mainnet" {
		t.Fatalf("input after down = %q, want newer command", m.input)
	}

	m, cmd = m.Update(tea.KeyMsg{Type: tea.KeyDown})
	if cmd != nil {
		t.Fatalf("second down cmd = %v, want nil", cmd)
	}
	if m.input != "" {
		t.Fatalf("input after second down = %q, want draft input", m.input)
	}
}

func visibleRows(view string) []string {
	rows := strings.Split(view, "\n")
	for i, row := range rows {
		rows[i] = ansi.Strip(row)
	}
	return rows
}

func TestShellCommandHistoryPreservesDraftAndSupportsCtrlKeys(t *testing.T) {
	m := newShellModel(nil, nil)
	m.input = "status"
	var cmd tea.Cmd
	m, cmd = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd != nil {
		t.Fatalf("enter cmd = %v, want nil", cmd)
	}
	m.input = "bal"

	m, cmd = m.Update(tea.KeyMsg{Type: tea.KeyCtrlP})
	if cmd != nil {
		t.Fatalf("ctrl-p cmd = %v, want nil", cmd)
	}
	if m.input != "status" {
		t.Fatalf("input after ctrl-p = %q, want history command", m.input)
	}

	m, cmd = m.Update(tea.KeyMsg{Type: tea.KeyCtrlN})
	if cmd != nil {
		t.Fatalf("ctrl-n cmd = %v, want nil", cmd)
	}
	if m.input != "bal" {
		t.Fatalf("input after ctrl-n = %q, want restored draft", m.input)
	}
}

func TestShellCommandHistoryLoadsAndPersistsThroughExecutor(t *testing.T) {
	exec := &fakeShellExecutor{history: []string{"status"}}
	m := newShellModel(exec, nil)
	m.startupRunning = false
	var cmd tea.Cmd

	m, cmd = m.Update(tea.KeyMsg{Type: tea.KeyUp})
	if cmd != nil {
		t.Fatalf("up cmd = %v, want nil", cmd)
	}
	if m.input != "status" {
		t.Fatalf("input after up = %q, want persisted history entry", m.input)
	}

	m.input = "network testnet"
	m, cmd = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd == nil {
		t.Fatal("enter cmd = nil, want shell execution command")
	}
	if len(exec.recordedHistory) != 1 || exec.recordedHistory[0] != "network testnet" {
		t.Fatalf("recordedHistory = %#v, want network testnet", exec.recordedHistory)
	}
}

func TestShellPageScrollsTranscript(t *testing.T) {
	m := newShellModel(nil, nil)
	m.lines = numberedLines("shell", 20)

	if view := m.View(20, 6); !strings.Contains(view, "shell-20") {
		t.Fatalf("initial view missing tail line:\n%s", view)
	}

	m.scrollPage(1, 4)
	view := m.View(20, 6)
	if !strings.Contains(view, "shell-13") || strings.Contains(view, "shell-20") {
		t.Fatalf("page-up view =\n%s\nwant older page without tail", view)
	}

	m.scrollPage(-1, 4)
	if view := m.View(20, 6); !strings.Contains(view, "shell-20") {
		t.Fatalf("page-down view missing tail line:\n%s", view)
	}
}

func TestDaemonPageScrollsLog(t *testing.T) {
	m := newDaemonModel(daemonInfo{Status: daemonStatusAttached}, nil)
	m.lines = numberedLines("daemon", 20)

	if view := m.View(20, 4); !strings.Contains(view, "daemon-20") {
		t.Fatalf("initial view missing tail line:\n%s", view)
	}

	m.scrollPage(1, 4)
	view := m.View(20, 4)
	if !strings.Contains(view, "daemon-13") || strings.Contains(view, "daemon-20") {
		t.Fatalf("page-up view =\n%s\nwant older page without tail", view)
	}

	m.scrollPage(-1, 4)
	if view := m.View(20, 4); !strings.Contains(view, "daemon-20") {
		t.Fatalf("page-down view missing tail line:\n%s", view)
	}
}

func TestFocusedDaemonReceivesPageScrollKey(t *testing.T) {
	m := model{
		focus:  paneDaemon,
		daemon: newDaemonModel(daemonInfo{Status: daemonStatusAttached}, nil),
		width:  100,
		height: 10,
	}
	m.daemon.lines = numberedLines("daemon", 20)

	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyPgUp})
	if cmd != nil {
		t.Fatalf("cmd = %v, want nil", cmd)
	}
	got := next.(model)
	if got.daemon.scrollOffset == 0 {
		t.Fatal("daemon scrollOffset = 0, want scrolled back")
	}
}

func TestShellCtrlCCancelsRunningCommand(t *testing.T) {
	exec := &fakeShellExecutor{}
	m := newShellModel(exec, nil)
	m.running = true

	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	if cmd != nil {
		t.Fatalf("cmd = %v, want nil", cmd)
	}
	if !exec.cancelled {
		t.Fatal("executor was not cancelled")
	}
	if !next.cancelRequested {
		t.Fatal("cancelRequested = false, want true")
	}
	if got := next.lines[len(next.lines)-1]; got != "cancel requested" {
		t.Fatalf("last line = %q, want cancel requested", got)
	}
}

func TestShellCanceledExecRendersInterrupted(t *testing.T) {
	m := newShellModel(&fakeShellExecutor{}, nil)
	m.running = true
	m.cancelRequested = true

	m = m.updateExec(shellExecMsg{err: context.Canceled})
	if m.running {
		t.Fatal("running = true, want false")
	}
	if m.cancelRequested {
		t.Fatal("cancelRequested = true, want false")
	}
	if got := m.lines[len(m.lines)-1]; got != "Interrupted" {
		t.Fatalf("last line = %q, want Interrupted", got)
	}
}

func TestShellErrorExecClearsRunningAndRendersError(t *testing.T) {
	exec := &fakeShellExecutor{execErr: fmt.Errorf("approval timed out")}
	msg, ok := executeShellLine(exec, "sign")().(shellExecMsg)
	if !ok {
		t.Fatalf("executeShellLine returned %T, want shellExecMsg", msg)
	}

	m := newShellModel(exec, nil)
	m.running = true
	m = m.updateExec(msg)

	if m.running {
		t.Fatal("running = true, want false")
	}
	if got := m.lines[len(m.lines)-1]; got != "Error: approval timed out" {
		t.Fatalf("last line = %q, want Error: approval timed out", got)
	}
}

func TestRootCtrlCCancelsFocusedRunningShell(t *testing.T) {
	exec := &fakeShellExecutor{}
	m := model{
		focus: paneShell,
		shell: newShellModel(exec, nil),
	}
	m.shell.running = true

	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	if cmd != nil {
		t.Fatalf("cmd = %v, want nil", cmd)
	}
	got := next.(model)
	if !exec.cancelled {
		t.Fatal("executor was not cancelled")
	}
	if !got.shell.cancelRequested {
		t.Fatal("cancelRequested = false, want true")
	}
}

func TestSignerCtrlCOpensQuitConfirmation(t *testing.T) {
	m := model{focus: paneSigner}

	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	if cmd != nil {
		t.Fatalf("ctrl+c cmd = %v, want nil", cmd)
	}
	got := next.(model)
	if !got.quitConfirm {
		t.Fatal("quitConfirm = false, want true")
	}

	next, cmd = got.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'n'}})
	if cmd != nil {
		t.Fatalf("cancel cmd = %v, want nil", cmd)
	}
	got = next.(model)
	if got.quitConfirm {
		t.Fatal("quitConfirm = true after cancel, want false")
	}
}

func TestSignerQuitCommandOpensQuitConfirmation(t *testing.T) {
	m := model{
		focus:  paneSigner,
		signer: quitOnKeyTeaModel{},
	}

	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	if cmd == nil {
		t.Fatal("signer q cmd = nil, want wrapped quit request")
	}
	got := next.(model)
	if got.quitConfirm {
		t.Fatal("quitConfirm set before wrapped command result, want false")
	}

	msg := cmd()
	if _, ok := msg.(signerQuitRequestMsg); !ok {
		t.Fatalf("wrapped signer quit msg = %T, want signerQuitRequestMsg", msg)
	}
	next, cmd = got.Update(msg)
	if cmd != nil {
		t.Fatalf("quit request update cmd = %v, want nil", cmd)
	}
	got = next.(model)
	if !got.quitConfirm {
		t.Fatal("quitConfirm = false, want true")
	}
	if signer := got.signer.(quitOnKeyTeaModel); signer.quitting {
		t.Fatal("signer model kept its internal quitting state after intercepted quit")
	}

	_, cmd = got.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd == nil {
		t.Fatal("confirm enter cmd = nil, want tea.Quit")
	}
	quitMsg := cmd()
	if _, ok := quitMsg.(tea.QuitMsg); !ok {
		t.Fatalf("confirm enter msg = %T, want tea.QuitMsg", quitMsg)
	}
}

func TestRootRoutesPendingHostKeyPromptRegardlessOfFocus(t *testing.T) {
	resp := make(chan bool, 1)
	m := model{
		focus: paneSigner,
		shell: newShellModel(nil, nil),
	}
	m.shell.pendingHostKey = &shellHostKeyApprovalMsg{
		host:        "signer.example",
		fingerprint: "SHA256:test",
		response:    resp,
	}

	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'y'}})
	if cmd != nil {
		t.Fatalf("cmd = %v, want nil", cmd)
	}
	got := next.(model)
	if got.focus != paneSigner {
		t.Fatalf("focus = %v, want signer", got.focus)
	}
	if got.shell.pendingHostKey != nil {
		t.Fatal("pendingHostKey still set after response")
	}
	select {
	case approved := <-resp:
		if !approved {
			t.Fatal("approved = false, want true")
		}
	default:
		t.Fatal("host key response was not sent")
	}
	if gotLine := got.shell.lines[len(got.shell.lines)-1]; gotLine != "y" {
		t.Fatalf("last line = %q, want y", gotLine)
	}
	for _, line := range got.shell.lines {
		if strings.Contains(line, "Waiting for operator approval") {
			t.Fatalf("unexpected operator-approval status after host-key approval: %q", line)
		}
	}
}

func TestRootRoutesPendingLinePromptRegardlessOfFocus(t *testing.T) {
	resp := make(chan string, 1)
	m := model{
		focus: paneSigner,
		shell: newShellModel(nil, nil),
	}
	m.shell.running = true
	m.shell.pendingLinePrompt = &shellLinePromptMsg{
		prompt:   "Proceed with signing and submission? [y/N]: ",
		response: resp,
	}

	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'y'}})
	if cmd != nil {
		t.Fatalf("cmd after rune = %v, want nil", cmd)
	}
	got := next.(model)
	next, cmd = got.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd != nil {
		t.Fatalf("cmd after enter = %v, want nil", cmd)
	}
	got = next.(model)

	if got.focus != paneSigner {
		t.Fatalf("focus = %v, want signer", got.focus)
	}
	if got.shell.pendingLinePrompt != nil {
		t.Fatal("pendingLinePrompt still set after response")
	}
	select {
	case line := <-resp:
		if line != "y" {
			t.Fatalf("line response = %q, want y", line)
		}
	default:
		t.Fatal("line response was not sent")
	}
	if gotLine := got.shell.lines[len(got.shell.lines)-1]; gotLine != "Proceed with signing and submission? [y/N]: y" {
		t.Fatalf("last line = %q, want echoed approval", gotLine)
	}
}

func TestViewRendersHostKeyOverlayWhenPending(t *testing.T) {
	m := model{
		focus:  paneSigner,
		shell:  newShellModel(nil, nil),
		signer: stubTeaModel{},
		daemon: newDaemonModel(daemonInfo{Status: daemonStatusAttached}, nil),
		width:  splitMinWidth,
		height: splitMinHeight,
	}
	m.shell.pendingHostKey = &shellHostKeyApprovalMsg{
		host:        "signer.example",
		fingerprint: "SHA256:abc123",
		response:    make(chan bool, 1),
	}

	view := m.View()
	for _, want := range []string{
		"Unknown SSH host",
		"signer.example",
		"SHA256:abc123",
		"Trust this server? [y/N]",
		"Trust SSH host:",
	} {
		if !strings.Contains(view, want) {
			t.Fatalf("view missing %q\n%s", want, view)
		}
	}
	// Modal should suppress the normal pane layout (no pane headers visible).
	for _, paneTitle := range []string{"▸ Signer", "▸ Shell", "▸ Daemon"} {
		if strings.Contains(view, paneTitle) {
			t.Fatalf("view shows pane header %q while host-key overlay is pending\n%s", paneTitle, view)
		}
	}
}

func TestShellStartupBlocksInputUntilComplete(t *testing.T) {
	m := newShellModel(&fakeShellExecutor{}, nil)
	if !m.startupRunning {
		t.Fatal("startupRunning = false, want true")
	}

	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})
	if cmd != nil {
		t.Fatalf("cmd = %v, want nil", cmd)
	}
	if next.input != "" {
		t.Fatalf("input while startup running = %q, want empty", next.input)
	}

	next, cmd = next.Update(shellStartupConnectMsg{output: "connected"})
	if cmd != nil {
		t.Fatalf("startup complete cmd = %v, want nil", cmd)
	}
	if next.startupRunning {
		t.Fatal("startupRunning = true, want false")
	}
	if got := next.lines[len(next.lines)-1]; got != "connected" {
		t.Fatalf("last line = %q, want connected", got)
	}

	next, cmd = next.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})
	if cmd != nil {
		t.Fatalf("post-startup key cmd = %v, want nil", cmd)
	}
	if next.input != "s" {
		t.Fatalf("input after startup = %q, want s", next.input)
	}
}

func TestHelpToggleAndDismiss(t *testing.T) {
	m := model{focus: paneShell}

	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'?'}})
	if cmd != nil {
		t.Fatalf("help open cmd = %v, want nil", cmd)
	}
	got := next.(model)
	if !got.help {
		t.Fatal("help = false, want true")
	}

	next, cmd = got.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if cmd != nil {
		t.Fatalf("help close cmd = %v, want nil", cmd)
	}
	got = next.(model)
	if got.help {
		t.Fatal("help = true, want false")
	}
}

func TestHelpSwallowsPaneKeys(t *testing.T) {
	m := model{focus: paneShell, help: true}

	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyF2})
	if cmd != nil {
		t.Fatalf("cmd = %v, want nil", cmd)
	}
	got := next.(model)
	if got.focus != paneShell {
		t.Fatalf("focus = %v, want shell while help is open", got.focus)
	}
	if !got.help {
		t.Fatal("help = false, want true")
	}
}

func TestShellExitClosesShellPaneOnly(t *testing.T) {
	m := newShellModel(&fakeShellExecutor{}, nil)

	m = m.updateExec(shellExecMsg{exit: true})
	if !m.exited {
		t.Fatal("exited = false, want true")
	}
	if got := m.lines[len(m.lines)-1]; got != "apshell session closed" {
		t.Fatalf("last line = %q, want apshell session closed", got)
	}

	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})
	if cmd != nil {
		t.Fatalf("cmd = %v, want nil", cmd)
	}
	if next.input != "" {
		t.Fatalf("input = %q, want empty after shell closed", next.input)
	}
}

func TestShellRestartReopensClosedShellPane(t *testing.T) {
	exec := &fakeShellExecutor{startupOutput: "connected"}
	m := newShellModel(exec, nil)
	m.exited = true
	m.startupRunning = false
	m.input = "ignored"
	m.inputCursor = len(m.input)
	m.completionLines = []string{"candidate"}

	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}})
	if cmd == nil {
		t.Fatal("cmd = nil, want startup reconnect command")
	}
	if next.exited {
		t.Fatal("exited = true after restart, want false")
	}
	if !next.startupRunning {
		t.Fatal("startupRunning = false after restart, want true")
	}
	if next.input != "" || next.inputCursor != 0 {
		t.Fatalf("input/cursor = %q/%d, want empty/0", next.input, next.inputCursor)
	}
	if len(next.completionLines) != 0 {
		t.Fatalf("completionLines = %#v, want cleared", next.completionLines)
	}
	if got := next.lines[len(next.lines)-1]; got != "apshell session restarted" {
		t.Fatalf("last line = %q, want restart notice", got)
	}

	msg := cmd()
	batch, ok := msg.(tea.BatchMsg)
	if !ok {
		t.Fatalf("restart cmd msg = %T, want tea.BatchMsg", msg)
	}
	if len(batch) != 2 {
		t.Fatalf("restart batch length = %d, want startup connect and spinner", len(batch))
	}
	firstMsg := batch[0]()
	startupMsg, ok := firstMsg.(shellStartupConnectMsg)
	if !ok {
		t.Fatalf("restart first batch msg = %T, want shellStartupConnectMsg", firstMsg)
	}
	if exec.startupCalls != 1 {
		t.Fatalf("StartupConnect calls = %d, want 1", exec.startupCalls)
	}
	next, cmd = next.Update(startupMsg)
	if cmd != nil {
		t.Fatalf("startup complete cmd = %v, want nil", cmd)
	}
	if next.startupRunning {
		t.Fatal("startupRunning = true after startup complete, want false")
	}
	if got := next.lines[len(next.lines)-1]; got != "connected" {
		t.Fatalf("last line after startup = %q, want connected", got)
	}

	next, cmd = next.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})
	if cmd != nil {
		t.Fatalf("post-restart key cmd = %v, want nil", cmd)
	}
	if next.input != "s" {
		t.Fatalf("input after restart = %q, want s", next.input)
	}
}

type fakeShellExecutor struct {
	cancelled       bool
	completion      []string
	offset          int
	history         []string
	recordedHistory []string
	startupOutput   string
	startupErr      error
	startupCalls    int
	execOutput      string
	execExit        bool
	execErr         error
}

func (f *fakeShellExecutor) ExecuteLineCaptured(string) (string, bool, error) {
	return f.execOutput, f.execExit, f.execErr
}

func (f *fakeShellExecutor) Cancel() bool {
	f.cancelled = true
	return true
}

func (f *fakeShellExecutor) Complete(string, int) (int, []string) {
	return f.offset, f.completion
}

func (f *fakeShellExecutor) Prompt() string {
	return "> "
}

func (f *fakeShellExecutor) StartupConnect() (string, error) {
	f.startupCalls++
	return f.startupOutput, f.startupErr
}

func (f *fakeShellExecutor) History() []string {
	return append([]string(nil), f.history...)
}

func (f *fakeShellExecutor) RecordHistory(line string) {
	f.recordedHistory = append(f.recordedHistory, line)
}

func numberedLines(prefix string, n int) []string {
	lines := make([]string, 0, n)
	for i := 1; i <= n; i++ {
		lines = append(lines, fmt.Sprintf("%s-%02d", prefix, i))
	}
	return lines
}

func leftMousePress(x, y int) tea.MouseMsg {
	return tea.MouseMsg{
		X:      x,
		Y:      y,
		Action: tea.MouseActionPress,
		Button: tea.MouseButtonLeft,
	}
}

type stubTeaModel struct{}

type recordingTeaModel struct {
	updates int
}

type quitOnKeyTeaModel struct {
	quitting bool
}

type testConnector struct{}

func (testConnector) Connect() (io.ReadWriteCloser, error) {
	return nil, io.EOF
}

func (testConnector) Label() string {
	return "test"
}

func (stubTeaModel) Init() tea.Cmd {
	return nil
}

func (stubTeaModel) Update(tea.Msg) (tea.Model, tea.Cmd) {
	return stubTeaModel{}, nil
}

func (stubTeaModel) View() string {
	return "signer"
}

func (m recordingTeaModel) Init() tea.Cmd {
	return nil
}

func (m recordingTeaModel) Update(tea.Msg) (tea.Model, tea.Cmd) {
	m.updates++
	return m, nil
}

func (m recordingTeaModel) View() string {
	return "signer"
}

func (quitOnKeyTeaModel) Init() tea.Cmd {
	return nil
}

func (quitOnKeyTeaModel) Update(tea.Msg) (tea.Model, tea.Cmd) {
	return quitOnKeyTeaModel{quitting: true}, tea.Quit
}

func (m quitOnKeyTeaModel) View() string {
	if m.quitting {
		return "Goodbye!"
	}
	return "signer"
}
