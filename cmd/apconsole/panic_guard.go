// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"runtime/debug"
	"sync"

	tea "github.com/charmbracelet/bubbletea"
)

// consolePanic is a panic the console caught, with the stack of the goroutine
// it happened on.
type consolePanic struct {
	value any
	stack []byte
}

// panicGuard records the first panic in the console model's Init, Update or
// View, or in any Cmd they return, with its stack. Bubble Tea prints its own
// report to the redirected stdout, where nobody sees it, so the console
// reports the recorded panic once the program has ended.
//
// A panic in a model method panics again after it is recorded, and Bubble
// Tea's recover in Run restores the terminal before Run returns. A panic in a
// Cmd ends the program with a QuitMsg instead: Bubble Tea's recover in a Cmd
// goroutine would still be printing its report after Run returned, while the
// console restores stdio. Either way the console leaves through its normal
// exit path.
type panicGuard struct {
	mu     sync.Mutex
	caught *consolePanic

	// last is the model the last completed Update returned. Run returns no
	// model when Update or View panics. Update runs on the goroutine that
	// calls Run, so last is read only after Run returns.
	last tea.Model
}

func newPanicGuard(model tea.Model) (*panicGuard, tea.Model) {
	g := &panicGuard{last: model}
	return g, guardedModel{inner: model, guard: g}
}

func (g *panicGuard) record(value any, stack []byte) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.caught == nil {
		g.caught = &consolePanic{value: value, stack: stack}
	}
}

// recordAndRepanic must be deferred directly, so that its recover stops the
// panic.
func (g *panicGuard) recordAndRepanic() {
	if r := recover(); r != nil {
		g.record(r, debug.Stack())
		panic(r)
	}
}

// recorded returns the first panic the guard saw, or nil.
func (g *panicGuard) recorded() *consolePanic {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.caught
}

// finalModel returns the console model Run ended with, or the last one an
// Update returned when Run returned none.
func (g *panicGuard) finalModel(final tea.Model) tea.Model {
	if m, ok := final.(guardedModel); ok {
		return m.inner
	}
	return g.last
}

// guardCmd wraps cmd, and the commands of a batch it returns, which Bubble Tea
// runs in goroutines of their own. A panic in one is recorded and quits the
// program. The commands of a tea.Sequence cannot be reached (its message type
// is unexported): Bubble Tea still catches a panic in one and the console
// still exits 2 through its cleanup, but no stack is recorded. Nothing in the
// console uses tea.Sequence; use tea.Batch, or extend this, before adding one.
func (g *panicGuard) guardCmd(cmd tea.Cmd) tea.Cmd {
	if cmd == nil {
		return nil
	}
	return func() (msg tea.Msg) {
		defer func() {
			if r := recover(); r != nil {
				g.record(r, debug.Stack())
				msg = tea.QuitMsg{}
			}
		}()
		msg = cmd()
		if batch, ok := msg.(tea.BatchMsg); ok {
			guarded := make(tea.BatchMsg, len(batch))
			for i, c := range batch {
				guarded[i] = g.guardCmd(c)
			}
			return guarded
		}
		return msg
	}
}

type guardedModel struct {
	inner tea.Model
	guard *panicGuard
}

func (m guardedModel) Init() tea.Cmd {
	defer m.guard.recordAndRepanic()
	return m.guard.guardCmd(m.inner.Init())
}

func (m guardedModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	defer m.guard.recordAndRepanic()
	next, cmd := m.inner.Update(msg)
	m.inner = next
	m.guard.last = next
	return m, m.guard.guardCmd(cmd)
}

func (m guardedModel) View() string {
	defer m.guard.recordAndRepanic()
	return m.inner.View()
}
