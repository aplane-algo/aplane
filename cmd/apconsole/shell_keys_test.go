// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"reflect"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

// shellMaxLines is how many transcript lines the pane keeps.
const shellMaxLines = 200

// keyTestExecutor is a shell executor that only answers Cancel.
type keyTestExecutor struct {
	shellExecutor
	cancels    int
	canceled   bool
	candidates []string // what Complete offers
}

func (e *keyTestExecutor) Cancel() bool {
	e.cancels++
	return e.canceled
}

func (e *keyTestExecutor) Complete(string, int) (int, []string) { return 0, e.candidates }

// keyState is the part of the shell pane a key can change.
type keyState struct {
	Input           string
	Cursor          int
	Running         bool
	Exited          bool
	StartupRunning  bool
	CancelRequested bool
	ScrollOffset    int
	Lines           []string
	Completions     []string
	History         []string
	HostKeyPending  bool
	PromptInput     string
	PromptPending   bool
}

func stateOf(m shellModel) keyState {
	s := keyState{
		Input: m.input, Cursor: m.inputCursor, Running: m.running, Exited: m.exited, StartupRunning: m.startupRunning,
		CancelRequested: m.cancelRequested, ScrollOffset: m.scrollOffset, Lines: m.lines, Completions: m.completionLines,
		History: m.history, HostKeyPending: m.pendingHostKey != nil, PromptPending: m.pendingLinePrompt != nil,
	}
	if m.pendingLinePrompt != nil {
		s.PromptInput = m.pendingLinePrompt.input
	}
	return s
}

func runes(text string) tea.KeyMsg { return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(text)} }
func key(t tea.KeyType) tea.KeyMsg { return tea.KeyMsg{Type: t} }

// Each row is one key in one state: what the pane looks like after, and
// whether a command was started.
func TestShellPaneKeys(t *testing.T) {
	typed := func(input string, cursor int) shellModel { return shellModel{input: input, inputCursor: cursor} }
	tests := []struct {
		name     string
		model    func(exec *keyTestExecutor) shellModel
		exec     *keyTestExecutor // nil: the pane has no executor
		key      tea.KeyMsg
		want     keyState
		wantCmd  bool
		wantStop int // times the executor was asked to cancel
	}{
		// Keys that edit the command line.
		{name: "a character is inserted at the cursor", model: func(*keyTestExecutor) shellModel { return typed("ac", 1) },
			key: runes("b"), want: keyState{Input: "abc", Cursor: 2}},
		{name: "a paste of several lines becomes one line", model: func(*keyTestExecutor) shellModel { return typed("", 0) },
			key: tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("one\ntwo"), Paste: true}, want: keyState{Input: "one two", Cursor: 7}},
		{name: "space inserts a space", model: func(*keyTestExecutor) shellModel { return typed("ab", 1) },
			key: key(tea.KeySpace), want: keyState{Input: "a b", Cursor: 2}},
		{name: "backspace deletes before the cursor", model: func(*keyTestExecutor) shellModel { return typed("abc", 2) },
			key: key(tea.KeyBackspace), want: keyState{Input: "ac", Cursor: 1}},
		{name: "ctrl+h deletes before the cursor", model: func(*keyTestExecutor) shellModel { return typed("abc", 3) },
			key: key(tea.KeyCtrlH), want: keyState{Input: "ab", Cursor: 2}},
		{name: "backspace at the start does nothing", model: func(*keyTestExecutor) shellModel { return typed("abc", 0) },
			key: key(tea.KeyBackspace), want: keyState{Input: "abc", Cursor: 0}},
		{name: "delete removes at the cursor", model: func(*keyTestExecutor) shellModel { return typed("abc", 1) },
			key: key(tea.KeyDelete), want: keyState{Input: "ac", Cursor: 1}},
		{name: "delete at the end does nothing", model: func(*keyTestExecutor) shellModel { return typed("abc", 3) },
			key: key(tea.KeyDelete), want: keyState{Input: "abc", Cursor: 3}},
		{name: "ctrl+u clears the line", model: func(*keyTestExecutor) shellModel { return typed("abc", 2) },
			key: key(tea.KeyCtrlU), want: keyState{}},
		{name: "esc clears the line", model: func(*keyTestExecutor) shellModel { return typed("abc", 2) },
			key: key(tea.KeyEsc), want: keyState{}},
		{name: "left moves the cursor back", model: func(*keyTestExecutor) shellModel { return typed("abc", 2) },
			key: key(tea.KeyLeft), want: keyState{Input: "abc", Cursor: 1}},
		{name: "right moves the cursor forward", model: func(*keyTestExecutor) shellModel { return typed("abc", 1) },
			key: key(tea.KeyRight), want: keyState{Input: "abc", Cursor: 2}},
		{name: "home moves to the start", model: func(*keyTestExecutor) shellModel { return typed("abc", 2) },
			key: key(tea.KeyHome), want: keyState{Input: "abc", Cursor: 0}},
		{name: "end moves to the end", model: func(*keyTestExecutor) shellModel { return typed("abc", 1) },
			key: key(tea.KeyEnd), want: keyState{Input: "abc", Cursor: 3}},
		{name: "an editing key drops the completions shown", model: func(*keyTestExecutor) shellModel {
			m := typed("a", 1)
			m.completionLines = []string{"alpha", "apple"}
			return m
		}, key: runes("b"), want: keyState{Input: "ab", Cursor: 2}},
		{name: "a cursor key keeps the completions shown", model: func(*keyTestExecutor) shellModel {
			m := typed("a", 1)
			m.completionLines = []string{"alpha"}
			return m
		}, key: key(tea.KeyLeft), want: keyState{Input: "a", Completions: []string{"alpha"}}},
		{name: "tab without an executor does nothing", model: func(*keyTestExecutor) shellModel { return typed("ba", 2) },
			key: key(tea.KeyTab), want: keyState{Input: "ba", Cursor: 2}},

		// While a command runs, the command line is frozen.
		{name: "a character while a command runs is dropped", model: func(*keyTestExecutor) shellModel {
			m := typed("abc", 3)
			m.running = true
			return m
		}, key: runes("d"), want: keyState{Input: "abc", Cursor: 3, Running: true}},
		{name: "ctrl+u while a command runs is dropped", model: func(*keyTestExecutor) shellModel {
			m := typed("abc", 3)
			m.running = true
			return m
		}, key: key(tea.KeyCtrlU), want: keyState{Input: "abc", Cursor: 3, Running: true}},
		{name: "ctrl+c while a command runs asks the executor to cancel", exec: &keyTestExecutor{canceled: true},
			model: func(*keyTestExecutor) shellModel { return shellModel{running: true} },
			key:   key(tea.KeyCtrlC), want: keyState{Running: true, CancelRequested: true, Lines: []string{"cancel requested"}}, wantStop: 1},
		{name: "ctrl+c that the executor does not take says nothing", exec: &keyTestExecutor{},
			model: func(*keyTestExecutor) shellModel { return shellModel{running: true} },
			key:   key(tea.KeyCtrlC), want: keyState{Running: true}, wantStop: 1},
		{name: "ctrl+c while a command runs without an executor does nothing",
			model: func(*keyTestExecutor) shellModel { return shellModel{running: true} },
			key:   key(tea.KeyCtrlC), want: keyState{Running: true}},

		// Enter.
		{name: "enter on an empty line does nothing", model: func(*keyTestExecutor) shellModel { return typed("   ", 3) },
			key: key(tea.KeyEnter), want: keyState{Input: "   ", Cursor: 3}},
		{name: "enter runs the line", exec: &keyTestExecutor{},
			model: func(*keyTestExecutor) shellModel {
				m := typed(" balance ", 9)
				m.cancelRequested = true
				return m
			},
			key: key(tea.KeyEnter), want: keyState{Running: true, Lines: []string{"> balance"}, History: []string{"balance"}}, wantCmd: true},
		{name: "enter without an executor says the session is unavailable",
			model: func(*keyTestExecutor) shellModel { return typed("balance", 7) },
			key:   key(tea.KeyEnter), want: keyState{Lines: []string{"> balance", "shell session unavailable"}, History: []string{"balance"}}},
		{name: "clear empties the pane and runs nothing", exec: &keyTestExecutor{},
			model: func(*keyTestExecutor) shellModel {
				m := typed("CLEAR", 5)
				m.lines, m.scrollOffset = []string{"old output"}, 3
				return m
			},
			key: key(tea.KeyEnter), want: keyState{History: []string{"CLEAR"}}},

		// States that take the key before the command line does.
		{name: "a key while the session starts is dropped", model: func(*keyTestExecutor) shellModel {
			m := typed("a", 1)
			m.startupRunning = true
			return m
		}, key: runes("b"), want: keyState{Input: "a", Cursor: 1, StartupRunning: true}},
		{name: "r restarts an exited session", exec: &keyTestExecutor{},
			model: func(*keyTestExecutor) shellModel {
				m := typed("left over", 4)
				m.exited = true
				m.completionLines = []string{"x"}
				return m
			},
			key: runes("r"), want: keyState{StartupRunning: true, Lines: []string{"apshell session restarted"}}, wantCmd: true},
		{name: "R restarts an exited session with nothing to start",
			model: func(*keyTestExecutor) shellModel { return shellModel{exited: true} },
			key:   runes("R"), want: keyState{Lines: []string{"apshell session restarted"}}},
		{name: "another key leaves an exited session exited", exec: &keyTestExecutor{},
			model: func(*keyTestExecutor) shellModel { return shellModel{exited: true, input: "a", inputCursor: 1} },
			key:   runes("x"), want: keyState{Exited: true, Input: "a", Cursor: 1}},
		{name: "a key during a line prompt goes to the prompt", exec: &keyTestExecutor{},
			model: func(*keyTestExecutor) shellModel {
				return shellModel{running: true, input: "cmd", pendingLinePrompt: &shellLinePromptMsg{prompt: "? ", response: make(chan string, 1)}}
			},
			key: runes("y"), want: keyState{Running: true, Input: "cmd", PromptPending: true, PromptInput: "y"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := tt.model(tt.exec)
			if tt.exec != nil {
				m.executor = tt.exec
			}
			got, cmd := m.updateKey(tt.key)
			if state := stateOf(got); !reflect.DeepEqual(state, tt.want) {
				t.Fatalf("after the key:\n got %+v\nwant %+v", state, tt.want)
			}
			if (cmd != nil) != tt.wantCmd {
				t.Fatalf("command started = %v, want %v", cmd != nil, tt.wantCmd)
			}
			if tt.exec != nil && tt.exec.cancels != tt.wantStop {
				t.Fatalf("executor asked to cancel %d times, want %d", tt.exec.cancels, tt.wantStop)
			}
		})
	}
}

// A host key question takes the next key as its answer: y trusts the host,
// anything else does not, and ctrl+c cancels the command when it can.
func TestShellPaneHostKeyAnswer(t *testing.T) {
	tests := []struct {
		name       string
		exec       *keyTestExecutor
		key        tea.KeyMsg
		wantAnswer []bool // what the waiting command is sent, if anything
		wantLine   string
		wantCancel bool
	}{
		{"y trusts", nil, runes("y"), []bool{true}, "y", false},
		{"Y trusts", nil, runes("Y"), []bool{true}, "y", false},
		{"n declines", nil, runes("n"), []bool{false}, "N", false},
		{"enter declines", nil, key(tea.KeyEnter), []bool{false}, "N", false},
		{"ctrl+c cancels the command and sends no answer", &keyTestExecutor{canceled: true}, key(tea.KeyCtrlC), nil, "cancel requested", true},
		{"ctrl+c the executor does not take declines", &keyTestExecutor{}, key(tea.KeyCtrlC), []bool{false}, "N", false},
		{"ctrl+c without an executor declines", nil, key(tea.KeyCtrlC), []bool{false}, "N", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			answer := make(chan bool, 1)
			m := shellModel{running: true, input: "cmd", pendingHostKey: &shellHostKeyApprovalMsg{response: answer}}
			if tt.exec != nil {
				m.executor = tt.exec
			}
			got, cmd := m.updateKey(tt.key)
			var answers []bool
			select {
			case a := <-answer:
				answers = append(answers, a)
			default:
			}
			want := keyState{Running: true, Input: "cmd", Lines: []string{tt.wantLine}, CancelRequested: tt.wantCancel}
			if state := stateOf(got); !reflect.DeepEqual(state, want) || cmd != nil || !reflect.DeepEqual(answers, tt.wantAnswer) {
				t.Fatalf("state %+v, command %v, answers %v\nwant state %+v, no command, answers %v", state, cmd != nil, answers, want, tt.wantAnswer)
			}
		})
	}
}

// Keys that hand off to another method of the pane do what that method does.
func TestShellPaneKeysThatDelegate(t *testing.T) {
	base := func() shellModel {
		m := shellModel{input: "ba", inputCursor: 2, history: []string{"one", "two"}, completionLines: []string{"x"}}
		for i := 0; i < 200; i++ {
			m.lines = append(m.lines, "line")
		}
		// Scrolled back, so paging can move either way.
		m.scrollOffset = 20
		return m
	}
	tests := []struct {
		name string
		key  tea.KeyMsg
		want func(m shellModel) shellModel
	}{
		{"page up scrolls back", key(tea.KeyPgUp), func(m shellModel) shellModel { m.scrollPage(1, shellTranscriptHeight(10)); return m }},
		{"page down scrolls forward", key(tea.KeyPgDown), func(m shellModel) shellModel { m.scrollPage(-1, shellTranscriptHeight(10)); return m }},
		{"up recalls history", key(tea.KeyUp), func(m shellModel) shellModel { m.clearCompletions(); m.previousHistory(); return m }},
		{"ctrl+p recalls history", key(tea.KeyCtrlP), func(m shellModel) shellModel { m.clearCompletions(); m.previousHistory(); return m }},
		{"down moves forward in history", key(tea.KeyDown), func(m shellModel) shellModel { m.clearCompletions(); m.nextHistory(); return m }},
		{"ctrl+n moves forward in history", key(tea.KeyCtrlN), func(m shellModel) shellModel { m.clearCompletions(); m.nextHistory(); return m }},
		{"tab completes", key(tea.KeyTab), func(m shellModel) shellModel { return m.completeInput() }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := base()
			m.executor = &keyTestExecutor{candidates: []string{"balance"}}
			want := base()
			want.executor = &keyTestExecutor{candidates: []string{"balance"}}
			want = tt.want(want)
			want.trim()
			got, cmd := m.updateKey(tt.key)
			if cmd != nil || !reflect.DeepEqual(stateOf(got), stateOf(want)) {
				t.Fatalf("after the key:\n got %+v\nwant %+v", stateOf(got), stateOf(want))
			}
			if reflect.DeepEqual(stateOf(got), stateOf(base())) {
				t.Fatal("the key changed nothing: the case tests nothing")
			}

			// While a command runs, history and completion keys are dropped;
			// scrolling still works.
			running := base()
			running.running = true
			running.executor = &keyTestExecutor{}
			frozen := stateOf(running)
			after, _ := running.updateKey(tt.key)
			scrolls := tt.key.Type == tea.KeyPgUp || tt.key.Type == tea.KeyPgDown
			if changed := !reflect.DeepEqual(stateOf(after), frozen); changed != scrolls {
				t.Fatalf("while a command runs, the key changed the pane = %v, want %v", changed, scrolls)
			}
		})
	}
}

// Enter has no check that a command is running: a line left in the input
// runs. An empty line does nothing either way.
func TestShellPaneEnterWhileACommandRuns(t *testing.T) {
	exec := &keyTestExecutor{}
	m := shellModel{running: true, input: "status", inputCursor: 6, executor: exec, historyBrowsing: true, historyDraft: "draft"}
	got, cmd := m.updateKey(key(tea.KeyEnter))
	want := keyState{Running: true, Lines: []string{"> status"}, History: []string{"status"}}
	if state := stateOf(got); !reflect.DeepEqual(state, want) || cmd == nil {
		t.Fatalf("state %+v, command %v; want %+v and a command", state, cmd != nil, want)
	}
	// Submitting a line ends history browsing.
	if got.historyBrowsing || got.historyDraft != "" || got.historyIndex != len(got.history) {
		t.Fatalf("history after a submit: browsing %v, draft %q, index %d", got.historyBrowsing, got.historyDraft, got.historyIndex)
	}

	idle := shellModel{running: true, executor: exec}
	got, cmd = idle.updateKey(key(tea.KeyEnter))
	if state := stateOf(got); !reflect.DeepEqual(state, keyState{Running: true}) || cmd != nil {
		t.Fatalf("enter on an empty line while running: state %+v, command %v", state, cmd != nil)
	}
}

// Keys with nothing to do change nothing and cancel nothing.
func TestShellPaneKeysWithNoEffect(t *testing.T) {
	for _, k := range []tea.KeyMsg{key(tea.KeyCtrlC), key(tea.KeyF1), key(tea.KeyCtrlA)} {
		exec := &keyTestExecutor{canceled: true}
		m := shellModel{input: "abc", inputCursor: 2, executor: exec, completionLines: []string{"x"}}
		got, cmd := m.updateKey(k)
		want := keyState{Input: "abc", Cursor: 2, Completions: []string{"x"}}
		if state := stateOf(got); !reflect.DeepEqual(state, want) || cmd != nil || exec.cancels != 0 {
			t.Fatalf("%s: state %+v, command %v, cancels %d; want nothing to change", k, state, cmd != nil, exec.cancels)
		}
	}
}

// The transcript is cut back to its limit after a key that edits the line,
// and left alone by a key a state swallows.
func TestShellPaneTrimsTheTranscriptAfterEditingKeys(t *testing.T) {
	long := func() shellModel {
		m := shellModel{}
		for i := 0; i <= shellMaxLines; i++ {
			m.lines = append(m.lines, "line")
		}
		return m
	}
	if got, _ := long().updateKey(runes("a")); len(got.lines) != shellMaxLines {
		t.Fatalf("lines after an editing key = %d, want %d", len(got.lines), shellMaxLines)
	}
	if got, _ := long().updateKey(key(tea.KeyEnter)); len(got.lines) != shellMaxLines {
		t.Fatalf("lines after enter on an empty line = %d, want %d", len(got.lines), shellMaxLines)
	}
	starting := long()
	starting.startupRunning = true
	if got, _ := starting.updateKey(runes("a")); len(got.lines) != shellMaxLines+1 {
		t.Fatalf("lines after a key during startup = %d, want them untouched at %d", len(got.lines), shellMaxLines+1)
	}
	exited := long()
	exited.exited = true
	if got, _ := exited.updateKey(runes("x")); len(got.lines) != shellMaxLines+1 {
		t.Fatalf("lines after a key on an exited session = %d, want them untouched at %d", len(got.lines), shellMaxLines+1)
	}
}

// When two states could take a key, the earlier one does.
func TestShellPaneStatePrecedence(t *testing.T) {
	t.Run("a host key question before a line prompt", func(t *testing.T) {
		answer := make(chan bool, 1)
		m := shellModel{
			pendingHostKey:    &shellHostKeyApprovalMsg{response: answer},
			pendingLinePrompt: &shellLinePromptMsg{prompt: "? ", response: make(chan string, 1)},
		}
		got, _ := m.updateKey(runes("y"))
		if got.pendingHostKey != nil || got.pendingLinePrompt == nil || got.pendingLinePrompt.input != "" || len(answer) != 1 {
			t.Fatalf("the host key question did not take the key: %+v", stateOf(got))
		}
	})
	t.Run("ctrl+c for a running command before an exited session", func(t *testing.T) {
		exec := &keyTestExecutor{canceled: true}
		m := shellModel{running: true, exited: true, executor: exec}
		got, _ := m.updateKey(key(tea.KeyCtrlC))
		if exec.cancels != 1 || !got.cancelRequested || !got.exited {
			t.Fatalf("cancels %d, state %+v; want the command cancelled", exec.cancels, stateOf(got))
		}
	})
	t.Run("an exited session before a starting one", func(t *testing.T) {
		m := shellModel{exited: true, startupRunning: true}
		got, _ := m.updateKey(runes("r"))
		if got.exited {
			t.Fatalf("r did not restart the exited session: %+v", stateOf(got))
		}
	})
}

// Only a single r restarts an exited session.
func TestShellPaneExitedSessionIgnoresOtherInput(t *testing.T) {
	for _, k := range []tea.KeyMsg{runes("rr"), key(tea.KeyEnter), key(tea.KeySpace)} {
		exec := &keyTestExecutor{}
		m := shellModel{exited: true, input: "left over", inputCursor: 4, executor: exec}
		got, cmd := m.updateKey(k)
		want := keyState{Exited: true, Input: "left over", Cursor: 4}
		if state := stateOf(got); !reflect.DeepEqual(state, want) || cmd != nil {
			t.Fatalf("%s: state %+v, command %v; want the session left exited", k, state, cmd != nil)
		}
	}
}
