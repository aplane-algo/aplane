// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

type shellExecutor interface {
	ExecuteLineCaptured(raw string) (output string, exit bool, err error)
	Cancel() bool
	Complete(line string, pos int) (offset int, candidates []string)
	Prompt() string
	StartupConnect() (output string, err error)
}

type shellHistoryStore interface {
	History() []string
	RecordHistory(line string)
}

type shellModel struct {
	lines           []string
	input           string
	inputCursor     int
	completionLines []string
	history         []string
	historyIndex    int
	historyDraft    string
	historyBrowsing bool
	historyStore    shellHistoryStore
	executor        shellExecutor
	running         bool
	startupRunning  bool
	cancelRequested bool
	spinnerIndex    int
	exited          bool
	scrollOffset    int

	// pending host key approval (non-nil while waiting for user to trust a host)
	pendingHostKey *shellHostKeyApprovalMsg

	// pending line prompt (non-nil while a running shell command needs one
	// line of user input, such as plugin transaction approval).
	pendingLinePrompt *shellLinePromptMsg
}

type shellExecMsg struct {
	command string
	output  string
	exit    bool
	err     error
}

// shellHostKeyApprovalMsg is sent by the SSH host key approval handler when
// the server's key is unknown and the user must decide whether to trust it.
type shellHostKeyApprovalMsg struct {
	host        string
	fingerprint string
	response    chan<- bool
}

type shellLinePromptMsg struct {
	prompt   string
	input    string
	cursor   int
	response chan<- string
}

// shellStartupConnectMsg delivers the result of the deferred startup connect
// (see shellModel.Init). Running the connect as a tea.Cmd lets TOFU prompts
// route through shellHostKeyApprovalMsg now that the TUI is live.
type shellStartupConnectMsg struct {
	output string
	err    error
}

// shellProgressLineMsg is a live status line emitted by a blocking command
// (e.g. request-token) that would otherwise be trapped in the captured output
// buffer until the command returns.
type shellProgressLineMsg struct {
	text string
}

type shellSpinnerTickMsg struct{}

const shellSpinnerInterval = 120 * time.Millisecond

var shellSpinnerFrames = [...]string{"-", "\\", "|", "/"}

func newShellModel(executor shellExecutor, startupLines []string) shellModel {
	var lines []string
	if len(startupLines) > 0 {
		lines = append(lines, startupLines...)
	} else if executor == nil {
		lines = append(lines, "Shell session unavailable: APCLIENT_DATA/config.yaml is required.")
	} else {
		lines = append(lines, "Ready.")
	}
	historyStore, _ := executor.(shellHistoryStore)
	var history []string
	if historyStore != nil {
		history = historyStore.History()
	}
	return shellModel{
		executor:       executor,
		lines:          lines,
		history:        history,
		historyIndex:   len(history),
		historyStore:   historyStore,
		startupRunning: executor != nil,
	}
}

// Init kicks off the deferred signer connect once bubbletea is running so any
// SSH host key approval routes through the TUI instead of blocking on stdin.
func (m shellModel) Init() tea.Cmd {
	if m.executor == nil {
		return nil
	}
	return tea.Batch(
		startupConnectShell(m.executor),
		shellSpinnerTick(),
	)
}

func (m shellModel) Update(msg tea.Msg) (shellModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		return m.updateKey(msg)
	case shellExecMsg:
		return m.updateExec(msg), nil
	case shellHostKeyApprovalMsg:
		m.clearCompletions()
		m.pendingHostKey = &msg
		m.appendLines(
			"[SSH] Unknown host: "+msg.host,
			"[SSH] Fingerprint:  "+msg.fingerprint,
			"Trust this server? [y/N]: ",
		)
		return m, nil
	case shellLinePromptMsg:
		m.clearCompletions()
		m.pendingLinePrompt = &msg
		return m, nil
	case shellStartupConnectMsg:
		m.clearCompletions()
		m.startupRunning = false
		if msg.output != "" {
			m.appendLines(strings.Split(msg.output, "\n")...)
		}
		return m, nil
	case shellProgressLineMsg:
		m.clearCompletions()
		if msg.text != "" {
			m.appendLines(strings.Split(msg.text, "\n")...)
		}
		return m, nil
	case shellSpinnerTickMsg:
		if !m.busy() {
			return m, nil
		}
		m.spinnerIndex++
		return m, shellSpinnerTick()
	default:
		return m, nil
	}
}

func (m shellModel) updateKey(msg tea.KeyMsg) (shellModel, tea.Cmd) {
	if m.pendingHostKey != nil {
		ch := m.pendingHostKey.response
		m.pendingHostKey = nil
		approved := msg.String() == "y" || msg.String() == "Y"
		if approved {
			m.appendLines("y")
		} else {
			m.appendLines("N")
		}
		ch <- approved
		return m, nil
	}
	if m.pendingLinePrompt != nil {
		return m.updateLinePromptKey(msg)
	}
	if msg.Type == tea.KeyCtrlC && m.running {
		if m.executor != nil && m.executor.Cancel() {
			m.cancelRequested = true
			m.appendLines("cancel requested")
		}
		return m, nil
	}
	if m.exited {
		if msg.Type == tea.KeyRunes && len(msg.Runes) == 1 && (msg.Runes[0] == 'r' || msg.Runes[0] == 'R') {
			m.exited = false
			m.input = ""
			m.inputCursor = 0
			m.clearCompletions()
			m.appendLines("apshell session restarted")
			if m.executor != nil {
				m.startupRunning = true
				return m, tea.Batch(startupConnectShell(m.executor), shellSpinnerTick())
			}
		}
		return m, nil
	}
	if m.startupRunning {
		return m, nil
	}

	switch msg.Type {
	case tea.KeyPgUp:
		m.scrollPage(1, shellTranscriptHeight(10))
	case tea.KeyPgDown:
		m.scrollPage(-1, shellTranscriptHeight(10))
	case tea.KeyUp, tea.KeyCtrlP:
		if !m.running {
			m.clearCompletions()
			m.previousHistory()
		}
	case tea.KeyDown, tea.KeyCtrlN:
		if !m.running {
			m.clearCompletions()
			m.nextHistory()
		}
	case tea.KeyRunes:
		if !m.running {
			m.clearCompletions()
			m.input, m.inputCursor = insertAtCursor(m.input, m.inputCursor, string(msg.Runes))
		}
	case tea.KeySpace:
		if !m.running {
			m.clearCompletions()
			m.input, m.inputCursor = insertAtCursor(m.input, m.inputCursor, " ")
		}
	case tea.KeyBackspace, tea.KeyCtrlH:
		if !m.running && m.inputCursor > 0 {
			m.clearCompletions()
			m.input, m.inputCursor = deleteBeforeCursor(m.input, m.inputCursor)
		}
	case tea.KeyDelete:
		if !m.running && m.inputCursor < len(m.input) {
			m.clearCompletions()
			m.input = deleteAtCursor(m.input, m.inputCursor)
		}
	case tea.KeyCtrlU, tea.KeyEsc:
		if !m.running {
			m.clearCompletions()
			m.input = ""
			m.inputCursor = 0
		}
	case tea.KeyLeft:
		if !m.running {
			m.inputCursor = previousCursor(m.input, m.inputCursor)
		}
	case tea.KeyRight:
		if !m.running {
			m.inputCursor = nextCursor(m.input, m.inputCursor)
		}
	case tea.KeyHome:
		if !m.running {
			m.inputCursor = 0
		}
	case tea.KeyEnd:
		if !m.running {
			m.inputCursor = len(m.input)
		}
	case tea.KeyTab:
		if !m.running && m.executor != nil {
			m = m.completeInput()
		}
	case tea.KeyEnter:
		line := strings.TrimSpace(m.input)
		if line != "" {
			m.clearCompletions()
			m.input = ""
			m.inputCursor = 0
			m.recordHistory(line)
			if isPaneClearCommand(line) {
				m.lines = nil
				m.scrollOffset = 0
				return m, nil
			}
			m.appendLines("> " + line)
			if m.executor == nil {
				m.appendLines("shell session unavailable")
				return m, nil
			}
			m.running = true
			m.cancelRequested = false
			return m, tea.Batch(executeShellLine(m.executor, line), shellSpinnerTick())
		}
	}
	m.trim()
	return m, nil
}

func (m shellModel) updateLinePromptKey(msg tea.KeyMsg) (shellModel, tea.Cmd) {
	pending := m.pendingLinePrompt
	switch msg.Type {
	case tea.KeyEnter:
		line := pending.input
		m.appendLines(pending.prompt + line)
		pending.response <- line
		m.pendingLinePrompt = nil
	case tea.KeyCtrlC:
		m.appendLines(pending.prompt)
		pending.response <- ""
		m.pendingLinePrompt = nil
		if m.executor != nil {
			_ = m.executor.Cancel()
		}
	case tea.KeyBackspace, tea.KeyCtrlH:
		if pending.cursor > 0 {
			pending.input, pending.cursor = deleteBeforeCursor(pending.input, pending.cursor)
		}
	case tea.KeyDelete:
		if pending.cursor < len(pending.input) {
			pending.input = deleteAtCursor(pending.input, pending.cursor)
		}
	case tea.KeyCtrlU, tea.KeyEsc:
		pending.input = ""
		pending.cursor = 0
	case tea.KeyLeft:
		pending.cursor = previousCursor(pending.input, pending.cursor)
	case tea.KeyRight:
		pending.cursor = nextCursor(pending.input, pending.cursor)
	case tea.KeyHome:
		pending.cursor = 0
	case tea.KeyEnd:
		pending.cursor = len(pending.input)
	case tea.KeySpace:
		pending.input, pending.cursor = insertAtCursor(pending.input, pending.cursor, " ")
	case tea.KeyRunes:
		pending.input, pending.cursor = insertAtCursor(pending.input, pending.cursor, string(msg.Runes))
	}
	return m, nil
}

func (m shellModel) busy() bool {
	return m.running || m.startupRunning
}

func (m shellModel) spinnerFrame() string {
	return shellSpinnerFrames[m.spinnerIndex%len(shellSpinnerFrames)]
}

func shellSpinnerTick() tea.Cmd {
	return tea.Tick(shellSpinnerInterval, func(time.Time) tea.Msg {
		return shellSpinnerTickMsg{}
	})
}

func startupConnectShell(executor shellExecutor) tea.Cmd {
	return func() tea.Msg {
		output, err := executor.StartupConnect()
		return shellStartupConnectMsg{output: output, err: err}
	}
}

// isPaneClearCommand reports whether the input is apshell's "clear"/"cls" with
// no arguments. The standalone command emits raw ANSI screen-clear codes that
// would corrupt the bubbletea-managed apconsole layout, so we handle it locally
// by clearing the pane's transcript instead.
func isPaneClearCommand(line string) bool {
	switch strings.ToLower(line) {
	case "clear", "cls":
		return true
	}
	return false
}

// completeInput asks the executor for completions at the current cursor position
// (end of input) and applies them: exactly one candidate is appended in full;
// multiple candidates advance by their longest common prefix, or are displayed
// directly above the prompt if they share no prefix.
func (m shellModel) completeInput() shellModel {
	m.clearCompletions()
	m.inputCursor = clampCursor(m.input, m.inputCursor)
	offset, candidates := m.executor.Complete(m.input, m.inputCursor)
	switch len(candidates) {
	case 0:
		return m
	case 1:
		m.input, m.inputCursor = insertAtCursor(m.input, m.inputCursor, candidates[0])
	default:
		prefix := longestCommonPrefix(candidates)
		if prefix != "" {
			m.input, m.inputCursor = insertAtCursor(m.input, m.inputCursor, prefix)
			return m
		}
		partial := ""
		if offset > 0 && offset <= m.inputCursor {
			partial = m.input[m.inputCursor-offset : m.inputCursor]
		}
		display := make([]string, 0, len(candidates))
		for _, c := range candidates {
			full := strings.TrimRight(partial+c, " ")
			if full != "" {
				display = append(display, full)
			}
		}
		if len(display) > 0 {
			m.completionLines = []string{strings.Join(display, "  ")}
		}
	}
	return m
}

func (m *shellModel) clearCompletions() {
	m.completionLines = nil
}

const shellHistoryLimit = 1000

func (m *shellModel) recordHistory(line string) {
	if line == "" {
		m.resetHistoryNavigation()
		return
	}
	recorded := false
	if len(m.history) == 0 || m.history[len(m.history)-1] != line {
		m.history = append(m.history, line)
		recorded = true
		if len(m.history) > shellHistoryLimit {
			m.history = append([]string(nil), m.history[len(m.history)-shellHistoryLimit:]...)
		}
	}
	if recorded && m.historyStore != nil {
		m.historyStore.RecordHistory(line)
	}
	m.resetHistoryNavigation()
}

func (m *shellModel) previousHistory() {
	if len(m.history) == 0 {
		return
	}
	if !m.historyBrowsing {
		m.historyDraft = m.input
		m.historyIndex = len(m.history) - 1
		m.historyBrowsing = true
	} else if m.historyIndex > 0 {
		m.historyIndex--
	}
	m.input = m.history[m.historyIndex]
	m.inputCursor = len(m.input)
}

func (m *shellModel) nextHistory() {
	if !m.historyBrowsing {
		return
	}
	if m.historyIndex < len(m.history)-1 {
		m.historyIndex++
		m.input = m.history[m.historyIndex]
		m.inputCursor = len(m.input)
		return
	}
	m.input = m.historyDraft
	m.inputCursor = len(m.input)
	m.resetHistoryNavigation()
}

func (m *shellModel) resetHistoryNavigation() {
	m.historyIndex = len(m.history)
	m.historyDraft = ""
	m.historyBrowsing = false
}

func clampCursor(s string, cursor int) int {
	if cursor < 0 {
		return 0
	}
	if cursor > len(s) {
		return len(s)
	}
	if cursor == len(s) {
		return cursor
	}
	for cursor > 0 && !utf8.RuneStart(s[cursor]) {
		cursor--
	}
	return cursor
}

func previousCursor(s string, cursor int) int {
	cursor = clampCursor(s, cursor)
	if cursor <= 0 {
		return 0
	}
	_, size := utf8.DecodeLastRuneInString(s[:cursor])
	if size <= 0 {
		return 0
	}
	return cursor - size
}

func nextCursor(s string, cursor int) int {
	cursor = clampCursor(s, cursor)
	if cursor >= len(s) {
		return len(s)
	}
	_, size := utf8.DecodeRuneInString(s[cursor:])
	if size <= 0 {
		return len(s)
	}
	return cursor + size
}

func insertAtCursor(s string, cursor int, text string) (string, int) {
	cursor = clampCursor(s, cursor)
	return s[:cursor] + text + s[cursor:], cursor + len(text)
}

func deleteBeforeCursor(s string, cursor int) (string, int) {
	cursor = clampCursor(s, cursor)
	prev := previousCursor(s, cursor)
	return s[:prev] + s[cursor:], prev
}

func deleteAtCursor(s string, cursor int) string {
	cursor = clampCursor(s, cursor)
	next := nextCursor(s, cursor)
	return s[:cursor] + s[next:]
}

func longestCommonPrefix(strs []string) string {
	if len(strs) == 0 {
		return ""
	}
	prefix := strs[0]
	for _, s := range strs[1:] {
		for !strings.HasPrefix(s, prefix) {
			prefix = prefix[:len(prefix)-1]
			if prefix == "" {
				return ""
			}
		}
	}
	return prefix
}

func executeShellLine(executor shellExecutor, line string) tea.Cmd {
	return func() tea.Msg {
		output, exit, err := executor.ExecuteLineCaptured(line)
		return shellExecMsg{command: line, output: output, exit: exit, err: err}
	}
}

func (m shellModel) updateExec(msg shellExecMsg) shellModel {
	m.running = false
	m.clearCompletions()
	wasCancelRequested := m.cancelRequested
	m.cancelRequested = false
	if msg.output != "" {
		m.appendLines(strings.Split(msg.output, "\n")...)
	}
	if msg.err != nil {
		if errors.Is(msg.err, context.Canceled) || wasCancelRequested {
			m.appendLines("Interrupted")
		} else {
			m.appendLines("Error: " + msg.err.Error())
		}
	}
	if msg.exit {
		m.exited = true
		m.appendLines("apshell session closed")
	}
	m.trim()
	return m
}

func (m *shellModel) appendLines(lines ...string) {
	for _, line := range lines {
		// Callers may pass multi-line strings (e.g. multi-line error messages).
		// Store one entry per visual row so View's height accounting matches
		// what actually renders — otherwise embedded \n overflows the pane box.
		if strings.IndexByte(line, '\n') >= 0 {
			m.lines = append(m.lines, strings.Split(line, "\n")...)
		} else {
			m.lines = append(m.lines, line)
		}
	}
	m.trim()
}

func (m *shellModel) trim() {
	if len(m.lines) > 200 {
		m.lines = append([]string(nil), m.lines[len(m.lines)-200:]...)
	}
}

func (m *shellModel) scrollPage(direction, visible int) {
	if visible < 1 {
		visible = 1
	}
	m.scrollOffset += direction * visible
	if m.scrollOffset < 0 {
		m.scrollOffset = 0
	}
}

func maxShellScroll(lineCount, visible int) int {
	if visible < 1 {
		visible = 1
	}
	if lineCount <= visible {
		return 0
	}
	return lineCount - visible
}

func shellTranscriptHeight(totalHeight int) int {
	const gutterRows = 1
	bodyHeight := totalHeight - 1 - gutterRows
	if bodyHeight < 0 {
		return 0
	}
	return bodyHeight
}

func (m shellModel) View(width, height int) string {
	if width < 1 {
		width = 1
	}
	if height < 1 {
		height = 1
	}
	prefix := "> "
	input := m.input
	cursor := m.inputCursor
	if m.executor != nil {
		prefix = m.executor.Prompt()
	}
	if m.pendingLinePrompt != nil {
		prefix = m.pendingLinePrompt.prompt
		input = m.pendingLinePrompt.input
		cursor = m.pendingLinePrompt.cursor
	} else if m.busy() {
		prefix = m.spinnerFrame() + " " + prefix
	} else if m.exited {
		prefix = "[closed - press r to restart] " + prefix
	}
	promptRows := styledShellPromptRows(prefix, input, cursor, width)
	if len(promptRows) > height {
		promptRows = promptRows[len(promptRows)-height:]
	}

	completionVisualRows := wrapShellRows(m.completionLines, width)

	// Reserve the wrapped prompt rows, then place completions and a small gutter
	// directly above them. Transcript rows use whatever space remains.
	const preferredGutterRows = 1
	availableAbovePrompt := height - len(promptRows)
	if availableAbovePrompt < 0 {
		availableAbovePrompt = 0
	}
	gutter := preferredGutterRows
	if gutter > availableAbovePrompt {
		gutter = availableAbovePrompt
	}
	completionRows := len(completionVisualRows)
	maxCompletionRows := availableAbovePrompt - gutter
	if maxCompletionRows < 0 {
		maxCompletionRows = 0
	}
	if completionRows > maxCompletionRows {
		completionRows = maxCompletionRows
	}
	bodyHeight := height - len(promptRows) - gutter - completionRows
	if bodyHeight < 0 {
		bodyHeight = 0
	}

	transcriptRows := wrapShellRows(m.lines, width)
	start := 0
	end := len(transcriptRows)
	if len(transcriptRows) > bodyHeight {
		offset := m.scrollOffset
		maxScroll := maxShellScroll(len(transcriptRows), bodyHeight)
		if offset > maxScroll {
			offset = maxScroll
		}
		start = len(transcriptRows) - bodyHeight - offset
		end = start + bodyHeight
	}
	out := make([]string, 0, height)
	out = append(out, transcriptRows[start:end]...)
	for len(out) < bodyHeight {
		out = append(out, strings.Repeat(" ", width))
	}
	if completionRows > 0 {
		start := len(completionVisualRows) - completionRows
		out = append(out, completionVisualRows[start:]...)
	}
	for i := 0; i < gutter; i++ {
		out = append(out, strings.Repeat(" ", width))
	}
	out = append(out, promptRows...)
	return strings.Join(out, "\n")
}

func styledShellPromptRows(prefix, input string, cursor int, width int) []string {
	if width < 1 {
		width = 1
	}
	visiblePrefix := ansi.Strip(prefix)
	cursor = clampCursor(input, cursor)
	renderText := visiblePrefix + input
	cursorOffset := len(visiblePrefix) + cursor
	if cursorOffset == len(renderText) {
		renderText += " "
	}
	wrapped := ansi.Wrap(renderText, width, "")
	rows := strings.Split(wrapped, "\n")
	if len(rows) == 0 {
		rows = []string{""}
	}

	promptStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color(apconsoleShellPromptColor)).
		Background(lipgloss.Color("240"))
	inputStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("255")).
		Background(lipgloss.Color("240"))
	fillStyle := lipgloss.NewStyle().
		Background(lipgloss.Color("240"))
	cursorStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("0")).
		Background(lipgloss.Color(apconsoleShellPromptColor))

	offset := 0
	for i, row := range rows {
		rendered := renderShellPromptRow(row, offset, len(visiblePrefix), cursorOffset, promptStyle, inputStyle, cursorStyle)
		if pad := width - lipgloss.Width(rendered); pad > 0 {
			rendered += fillStyle.Render(strings.Repeat(" ", pad))
		}
		rows[i] = rendered
		offset += len(row)
	}
	return rows
}

const apconsoleShellPromptColor = "11"

func renderShellPromptRow(row string, rowOffset, promptLen, cursorOffset int, promptStyle, inputStyle, cursorStyle lipgloss.Style) string {
	var b strings.Builder
	for i := 0; i < len(row); {
		r, size := utf8.DecodeRuneInString(row[i:])
		if r == utf8.RuneError && size == 0 {
			break
		}
		cell := row[i : i+size]
		global := rowOffset + i
		switch {
		case global == cursorOffset:
			b.WriteString(cursorStyle.Render(cell))
		case global < promptLen:
			b.WriteString(promptStyle.Render(cell))
		default:
			b.WriteString(inputStyle.Render(cell))
		}
		i += size
	}
	return b.String()
}

func promptColorCodeForLipgloss(code string) string {
	n, err := strconv.Atoi(code)
	if err != nil {
		return code
	}
	if n >= 30 && n <= 37 {
		return strconv.Itoa(n - 30)
	}
	if n >= 90 && n <= 97 {
		return strconv.Itoa(n - 90 + 8)
	}
	return code
}

func wrapShellRows(lines []string, width int) []string {
	if width < 1 {
		width = 1
	}
	rows := make([]string, 0, len(lines))
	for _, line := range lines {
		wrapped := wrapShellLine(line, width)
		parts := strings.Split(wrapped, "\n")
		if len(parts) == 0 {
			parts = []string{""}
		}
		for _, part := range parts {
			rows = append(rows, fitLine(styleShellTranscriptRow(line, part), width))
		}
	}
	return rows
}

func wrapShellLine(line string, width int) string {
	const (
		nonBreakingHyphen = "\u2011"
		nonBreakingSpace  = "\u00a0"
	)
	protected := protectShellWrapBreaks(line, nonBreakingHyphen, nonBreakingSpace)
	wrapped := ansi.Wrap(protected, width, "")
	wrapped = strings.ReplaceAll(wrapped, nonBreakingHyphen, "-")
	return strings.ReplaceAll(wrapped, nonBreakingSpace, " ")
}

func protectShellWrapBreaks(line, nonBreakingHyphen, nonBreakingSpace string) string {
	var b strings.Builder
	b.Grow(len(line))
	inBracket := false

	for i := 0; i < len(line); {
		if line[i] == '\x1b' && i+1 < len(line) && line[i+1] == '[' {
			end := i + 2
			for end < len(line) {
				c := line[end]
				end++
				if c >= 0x40 && c <= 0x7e {
					break
				}
			}
			b.WriteString(line[i:end])
			i = end
			continue
		}

		r, size := utf8.DecodeRuneInString(line[i:])
		switch r {
		case '[':
			inBracket = true
			b.WriteRune(r)
		case ']':
			b.WriteRune(r)
			inBracket = false
		case '-':
			b.WriteString(nonBreakingHyphen)
		case ' ':
			if inBracket {
				b.WriteString(nonBreakingSpace)
			} else {
				b.WriteRune(r)
			}
		default:
			b.WriteRune(r)
		}
		i += size
	}

	return b.String()
}

const (
	apconsoleMissingTokenNotice    = "No aplane token found. Run 'request-token' to obtain token from the signer."
	apconsoleMissingTokenPinkColor = "205"
)

func styleShellTranscriptRow(line, row string) string {
	if line != apconsoleMissingTokenNotice {
		return row
	}
	return "\x1b[38;5;" + apconsoleMissingTokenPinkColor + "m" + row + "\x1b[0m"
}
