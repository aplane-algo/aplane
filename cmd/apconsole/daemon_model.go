// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

type daemonModel struct {
	status       daemonStatus
	owned        bool
	detail       string
	lines        []string
	events       <-chan daemonEvent
	scrollOffset int
}

type daemonLogMsg struct {
	event daemonEvent
}

func newDaemonModel(info daemonInfo, events <-chan daemonEvent) daemonModel {
	lines := info.Lines()
	if len(lines) == 0 {
		lines = []string{"status: unknown"}
	}
	return daemonModel{
		status: info.Status,
		owned:  info.Owned,
		detail: info.Detail,
		lines:  append([]string(nil), lines...),
		events: events,
	}
}

func (m daemonModel) Init() tea.Cmd {
	return waitDaemonLog(m.events)
}

func (m daemonModel) hasLogNavigation() bool {
	return m.events != nil
}

func (m daemonModel) preferredCompactHeight() int {
	bodyRows := len(m.lines)
	if bodyRows < compactDaemonMinBodyRows {
		bodyRows = compactDaemonMinBodyRows
	}
	if bodyRows > compactDaemonMaxBodyRows {
		bodyRows = compactDaemonMaxBodyRows
	}
	return paneBorderSize + 1 + bodyRows
}

func (m daemonModel) Update(msg tea.Msg) (daemonModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyPgUp:
			m.scrollPage(1, 10)
		case tea.KeyPgDown:
			m.scrollPage(-1, 10)
		}
		return m, nil
	case daemonLogMsg:
		if msg.event.Status != "" {
			m.status = msg.event.Status
			m.detail = msg.event.Detail
			m.appendLine("status: " + string(msg.event.Status))
			if msg.event.Detail != "" {
				m.appendLine(msg.event.Detail)
			}
		}
		if msg.event.Line != "" {
			m.appendLine(msg.event.Line)
		}
		if len(m.lines) > 200 {
			m.lines = append([]string(nil), m.lines[len(m.lines)-200:]...)
		}
		m.clampScrollOffset(10)
		return m, waitDaemonLog(m.events)
	default:
		return m, nil
	}
}

// appendLine stores one entry per visual row so View's height accounting
// matches what actually renders. apsigner may emit multi-line records
// (transaction descriptions, etc.) in a single event line.
func (m *daemonModel) appendLine(line string) {
	if strings.IndexByte(line, '\n') >= 0 {
		m.lines = append(m.lines, strings.Split(line, "\n")...)
		return
	}
	m.lines = append(m.lines, line)
}

func (m *daemonModel) scrollPage(direction, visible int) {
	if visible < 1 {
		visible = 1
	}
	m.scrollOffset += direction * visible
	m.clampScrollOffset(visible)
}

func (m *daemonModel) clampScrollOffset(visible int) {
	maxScroll := maxDaemonScroll(len(m.lines), visible)
	if m.scrollOffset < 0 {
		m.scrollOffset = 0
	}
	if m.scrollOffset > maxScroll {
		m.scrollOffset = maxScroll
	}
}

func maxDaemonScroll(lineCount, visible int) int {
	if visible < 1 {
		visible = 1
	}
	if lineCount <= visible {
		return 0
	}
	return lineCount - visible
}

func (m daemonModel) View(width, height int) string {
	if width < 1 {
		width = 1
	}
	if height < 1 {
		height = 1
	}
	start := 0
	end := len(m.lines)
	if len(m.lines) > height {
		offset := m.scrollOffset
		maxScroll := maxDaemonScroll(len(m.lines), height)
		if offset > maxScroll {
			offset = maxScroll
		}
		start = len(m.lines) - height - offset
		end = start + height
	}
	out := make([]string, 0, height)
	for _, line := range m.lines[start:end] {
		out = append(out, fitLine(line, width))
	}
	for len(out) < height {
		out = append(out, strings.Repeat(" ", width))
	}
	return strings.Join(out, "\n")
}

func waitDaemonLog(events <-chan daemonEvent) tea.Cmd {
	if events == nil {
		return nil
	}
	return func() tea.Msg {
		event, ok := <-events
		if !ok {
			return nil
		}
		return daemonLogMsg{event: event}
	}
}
