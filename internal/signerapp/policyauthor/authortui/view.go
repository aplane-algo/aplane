// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package authortui

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/aplane-algo/aplane/internal/signerapp/policyauthor"
	"github.com/aplane-algo/aplane/internal/theme"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

type styles struct {
	title, subtle, selected, err, warn, label, pane, paneFocused lipgloss.Style
}

func newStyles() styles {
	p := theme.Current()
	border := lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(0, 1)
	return styles{
		title:       lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(p.Title)),
		subtle:      lipgloss.NewStyle().Foreground(lipgloss.Color(p.Subtitle)),
		selected:    lipgloss.NewStyle().Background(lipgloss.Color(p.Selected)).Foreground(lipgloss.Color(p.SelectedFg)),
		err:         lipgloss.NewStyle().Foreground(lipgloss.Color(p.Error)).Bold(true),
		warn:        lipgloss.NewStyle().Foreground(lipgloss.Color(p.Warning)),
		label:       lipgloss.NewStyle().Bold(true),
		pane:        border.BorderForeground(lipgloss.Color(p.InputInactive)),
		paneFocused: border.BorderForeground(lipgloss.Color(p.InputActive)),
	}
}

func (m Model) View() string {
	var body string
	switch m.screen {
	case screenFiles:
		body = m.filesView()
	case screenProblems:
		body = m.problemsView()
	case screenComparePick:
		body = m.comparePickView()
	case screenExplain, screenCompare, screenHelp, screenField, screenSave, screenOverwrite:
		body = m.pageView()
	case screenConflict:
		body = m.conflictView()
	default:
		body = m.documentView()
	}
	footer := m.styles.subtle.Render(ansi.Truncate(m.footer(), m.width, "…"))
	status := ""
	if s := m.statusText(); s != "" {
		status = ansi.Truncate(s, m.width, "…") + "\n"
	}
	return body + "\n" + status + footer
}

func (m Model) statusText() string {
	if m.status != "" {
		return m.status
	}
	if len(*m.diagnostics) > 0 {
		return m.styles.warn.Render((*m.diagnostics)[0])
	}
	return ""
}

func (m Model) footer() string {
	if m.quitConfirm {
		return fmt.Sprintf("%d file(s) have unsaved edits. Quit and discard them? y: quit · any other key: stay", m.unsavedCount())
	}
	switch m.screen {
	case screenSave:
		return "y: Write the file | n/esc: Back | up/down: Scroll"
	case screenOverwrite:
		return "y: Overwrite | n/esc: Back | up/down: Scroll"
	case screenConflict:
		if m.save.saveAs {
			return "enter: Save as | esc: Back"
		}
		return "r: Reload | a: Save as | o: Overwrite | esc: Back"
	case screenFiles:
		return "up/down: Select | enter: Open | r: Reload | q: Quit"
	case screenProblems:
		return "up/down: Select | enter: Go to | esc: Back | q: Quit"
	case screenComparePick:
		return "up/down: Select | enter: Compare | esc: Back | q: Quit"
	case screenCompare:
		return "up/down/pgup/pgdown: Scroll | o: Other file | esc: Back | q: Quit"
	case screenExplain, screenHelp, screenField:
		return "up/down/pgup/pgdown: Scroll | esc: Back | q: Quit"
	}
	back := "esc: Files"
	if len(m.ws.Files) == 1 {
		back = "esc: Quit"
	}
	if m.prompt.kind != promptNone {
		return ""
	}
	return "up/down: Move | tab: Pane | enter: Edit | space: Toggle | a: Add | d: Remove | s: Save | u: Undo | ]/[: Problem | p: Problems | x: Explain | c: Compare | ?: Help | " + back + " | q: Quit"
}

func countLabel(errors, warnings int) string {
	var parts []string
	if errors > 0 {
		parts = append(parts, fmt.Sprintf("%d error(s)", errors))
	}
	if warnings > 0 {
		parts = append(parts, fmt.Sprintf("%d warning(s)", warnings))
	}
	if len(parts) == 0 {
		return "no problems"
	}
	return strings.Join(parts, " · ")
}

func (m Model) counts(i int) (errors, warnings int) {
	for _, p := range m.problemsFor(i, m.shownFile(i)) {
		if p.Severity == policyauthor.SeverityError {
			errors++
		} else {
			warnings++
		}
	}
	return errors, warnings
}

func (m Model) filesView() string {
	var b strings.Builder
	b.WriteString(m.styles.title.Render("appolicy") + "  " + m.styles.subtle.Render(fmt.Sprintf("%d file(s), %s documents", len(m.ws.Files), roleOrUnknown(m.ws))) + "\n\n")
	if len(m.ws.Files) == 0 {
		b.WriteString("No policy files.\n")
	}
	var lines []string
	for i, f := range m.ws.Files {
		key := f.Key
		if key == "" {
			key = "(no key)"
		}
		e, w := m.counts(i)
		if s, ok := m.sessions[f.Path]; ok && s.Modified() {
			key += "  (modified)"
		}
		line := fmt.Sprintf("%-28s %-10s %-30s %s", ansi.Truncate(filepath.Base(f.Path), 28, "…"), f.State, countLabel(e, w), key)
		line = ansi.Truncate(line, m.width-2, "…")
		if i == m.fileCursor {
			line = m.styles.selected.Render("> " + line)
		} else {
			line = "  " + line
		}
		lines = append(lines, line)
	}
	b.WriteString(strings.Join(window(lines, m.fileCursor, m.listHeight()), "\n"))
	return b.String()
}

// listHeight is the rows a list screen has below its title and blank line,
// above the status and footer lines.
func (m Model) listHeight() int { return max(1, m.height-5) }

func roleOrUnknown(ws *policyauthor.Workspace) string {
	if ws.Role == "" {
		return "no valid role"
	}
	return string(ws.Role)
}

func (m Model) documentView() string {
	f := m.shown()
	e, w := m.counts(m.current)
	key := f.Key
	if key == "" {
		key = "(no key)"
	}
	role := string(f.Role)
	if role == "" {
		role = "(no role)"
	}
	header := m.styles.title.Render(filepath.Base(f.Path)) + "  "
	switch s := m.session(); {
	case s == nil:
		header += m.styles.warn.Render("read-only") + "  "
	case s.Modified():
		header += m.styles.warn.Render("modified") + "  "
	}
	header += m.styles.subtle.Render(fmt.Sprintf("%s  %s  %s  ", role, key, f.State))
	if e > 0 {
		header += m.styles.err.Render(countLabel(e, w))
	} else if w > 0 {
		header += m.styles.warn.Render(countLabel(e, w))
	} else {
		header += m.styles.subtle.Render(countLabel(e, w))
	}

	// A pane's style width includes its padding (one column each side); its
	// border adds one more each side and a row above and below. Content is
	// laid out at the inner width and cut to it, so lipgloss never wraps it.
	var bar []string
	if m.prompt.kind != promptNone {
		bar = m.promptLines()
	}
	inner := max(3, m.height-5-len(bar))
	leftW := max(20, min(40, m.width/3))
	rightW := max(20, m.width-leftW-4)
	outline := m.paneStyle(paneOutline).Width(leftW).Height(inner).Render(fit(window(m.outlineLines(leftW-2), m.sectionCursor, inner), leftW-2))
	formLines, selected := m.formLines(rightW - 2)
	form := m.paneStyle(paneForm).Width(rightW).Height(inner).Render(fit(window(formLines, selected, inner), rightW-2))
	out := ansi.Truncate(header, m.width, "…") + "\n" + lipgloss.JoinHorizontal(lipgloss.Top, outline, form)
	if len(bar) > 0 {
		out += "\n" + strings.Join(bar, "\n")
	}
	return out
}

func (m Model) paneStyle(p pane) lipgloss.Style {
	if m.focus == p {
		return m.styles.paneFocused
	}
	return m.styles.pane
}

func (m Model) outlineLines(width int) []string {
	lines := make([]string, 0, len(m.sections))
	for i, s := range m.sections {
		all, errs := s.ProblemCount()
		mark := ""
		switch {
		case errs > 0:
			mark = m.styles.err.Render(fmt.Sprintf(" ✗%d", errs))
		case all > 0:
			mark = m.styles.warn.Render(fmt.Sprintf(" ⚠%d", all))
		}
		text := ansi.Truncate(strings.Repeat("  ", s.Depth)+s.Title, width-lipgloss.Width(mark), "…")
		if i == m.sectionCursor {
			text = m.styles.selected.Render(text)
		}
		lines = append(lines, text+mark)
	}
	return lines
}

// formLines renders the selected section's fields and returns the index of
// the selected field's first line.
func (m Model) formLines(width int) ([]string, int) {
	s := m.sections[m.sectionCursor]
	lines := []string{m.styles.title.Render(ansi.Truncate(s.Title, width, "…")), ""}
	for _, p := range s.Problems {
		lines = append(lines, m.problemLines(p, width)...)
	}
	selected := 0
	labelW := 0
	for _, f := range s.Fields {
		labelW = max(labelW, lipgloss.Width(f.Label))
	}
	labelW = min(labelW, width/2)
	for i, f := range s.Fields {
		if i == m.fieldCursor {
			selected = len(lines)
		}
		label := ansi.Truncate(f.Label, labelW, "…")
		label += strings.Repeat(" ", labelW-lipgloss.Width(label))
		value := f.Value
		switch {
		case f.Missing:
			value = m.styles.err.Render(value)
		case f.Unknown:
			value = m.styles.warn.Render(value)
		}
		valueLines := wrap(f.Value, max(10, width-labelW-2))
		first := m.styles.label.Render(label) + "  "
		if len(valueLines) > 0 {
			if f.Missing || f.Unknown {
				first += value
				valueLines = nil
			} else {
				first += valueLines[0]
				valueLines = valueLines[1:]
			}
		}
		if i == m.fieldCursor && m.focus == paneForm {
			first = m.styles.selected.Render(ansi.Strip(first))
		}
		lines = append(lines, first)
		for _, more := range valueLines {
			lines = append(lines, strings.Repeat(" ", labelW+2)+more)
		}
		if f.Note != "" {
			lines = append(lines, strings.Repeat(" ", labelW+2)+m.styles.subtle.Render(ansi.Truncate(f.Note, max(10, width-labelW-2), "…")))
		}
		for _, p := range f.Problems {
			lines = append(lines, m.problemLines(p, width)...)
		}
	}
	if len(s.Fields) == 0 && len(s.Problems) == 0 {
		lines = append(lines, m.styles.subtle.Render("(nothing to show)"))
	}
	return lines, selected
}

func (m Model) problemLines(p policyauthor.Problem, width int) []string {
	mark, style := "⚠ ", m.styles.warn
	if p.Severity == policyauthor.SeverityError {
		mark, style = "✗ ", m.styles.err
	}
	text := p.Message
	if p.Pointer != "" {
		text = p.Pointer + ": " + text
	}
	var out []string
	for i, line := range wrap(text, max(10, width-2)) {
		if i == 0 {
			out = append(out, style.Render(mark+line))
		} else {
			out = append(out, style.Render("  "+line))
		}
	}
	return out
}

// fit joins lines, each cut to width cells.
func fit(lines []string, width int) string {
	out := make([]string, len(lines))
	for i, line := range lines {
		out[i] = ansi.Truncate(line, width, "…")
	}
	return strings.Join(out, "\n")
}

// window returns the lines that fit in height, scrolled so line focus shows.
func window(lines []string, focus, height int) []string {
	if len(lines) <= height {
		return lines
	}
	start := max(0, min(focus-height/2, len(lines)-height))
	return lines[start : start+height]
}

// wrap breaks text into lines of at most width cells: at spaces and commas
// when it can, and inside a word longer than a line, such as an address,
// when it must, so no part of a value is cut off.
func wrap(text string, width int) []string {
	if text == "" {
		return []string{""}
	}
	return strings.Split(ansi.Hardwrap(ansi.Wrap(text, width, " ,"), width, true), "\n")
}
