// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"

	tui "github.com/aplane-algo/aplane/internal/signertui"
	"github.com/aplane-algo/aplane/internal/theme"
)

type pane int

const (
	paneShell pane = iota
	paneSigner
	paneDaemon
)

const (
	splitMinWidth  = 100
	splitMinHeight = 28
	headerHeight   = 2 // title row + tab row
	footerHeight   = 1
	paneBorderSize = 2  // rounded border: 1 char each side (also 1 row top + 1 row bottom)
	topPaneGap     = 1  // visual gutter between the signer and shell panes
	signerPaneCols = 45 // signer:shell split is 45:55 in split mode
	shellPaneCols  = 55

	compactDaemonMinBodyRows = 5
	compactDaemonMaxBodyRows = 6
)

type model struct {
	focus         pane
	zoomed        bool
	help          bool
	quitConfirm   bool
	shellDisabled bool

	shell  shellModel
	signer tea.Model
	daemon daemonModel

	width  int
	height int
}

type rect struct {
	width  int
	height int
}

type layout struct {
	split         bool
	contentWidth  int
	contentHeight int
	shell         rect
	signer        rect
	daemon        rect
}

func newModel(connector tui.AdminConnector, dataDir string, shell shellExecutor, shellStartup []string, daemon daemonModel) model {
	return newModelWithShell(connector, dataDir, shell, shellStartup, daemon, true)
}

func newModelWithShell(connector tui.AdminConnector, dataDir string, shell shellExecutor, shellStartup []string, daemon daemonModel, shellEnabled bool) model {
	return model{
		focus:         paneSigner,
		shellDisabled: !shellEnabled,
		shell:         newShellModel(shell, shellStartup),
		signer:        tui.NewModel(connector, dataDir),
		daemon:        daemon,
	}
}

func (m model) Init() tea.Cmd {
	cmds := []tea.Cmd{
		tea.EnterAltScreen,
		m.signer.Init(),
		m.daemon.Init(),
	}
	if m.shellEnabled() {
		cmds = append(cmds, m.shell.Init())
	}
	return tea.Batch(cmds...)
}

func (m model) shellEnabled() bool {
	return !m.shellDisabled
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m.resyncSignerSize()
	case signerQuitRequestMsg:
		if msg.signer != nil {
			m.signer = msg.signer
		}
		m.quitConfirm = true
		return m, nil
	case tea.MouseMsg:
		// Mouse reporting is intentionally disabled in main.go so terminal text
		// selection works normally. Ignore synthetic mouse messages in tests.
		return m, nil
	case tea.KeyMsg:
		if m.quitConfirm {
			return m.handleQuitConfirmKey(msg)
		}
		if m.shellEnabled() && (m.shell.pendingHostKey != nil || m.shell.pendingLinePrompt != nil) {
			shell, cmd := m.shell.Update(msg)
			m.shell = shell
			return m, cmd
		}
		if m.help {
			switch msg.String() {
			case "?", "esc", "f5", "q":
				m.help = false
				return m, nil
			case "ctrl+c":
				return m, tea.Quit
			default:
				return m, nil
			}
		}
		if m.shellEnabled() && msg.Type == tea.KeyCtrlC && m.focus == paneShell && m.shell.running {
			shell, cmd := m.shell.Update(msg)
			m.shell = shell
			return m, cmd
		}
		switch msg.String() {
		case "ctrl+c":
			m.quitConfirm = true
			return m, nil
		case "?", "f5":
			m.help = true
			return m, nil
		case "shift+left":
			m.focus = m.prevPane()
			return m.resyncSignerSize()
		case "shift+right", "shift+tab":
			m.focus = m.nextPane()
			return m.resyncSignerSize()
		case "shift+up":
			m.focus = m.paneAbove()
			return m.resyncSignerSize()
		case "shift+down":
			m.focus = m.paneBelow()
			return m.resyncSignerSize()
		case "f1":
			m.focus = paneSigner
			return m, nil
		case "f2":
			if m.shellEnabled() {
				m.focus = paneShell
			} else if m.daemon.hasLogNavigation() {
				m.focus = paneDaemon
			}
			return m, nil
		case "f3":
			if !m.shellEnabled() || !m.daemon.hasLogNavigation() {
				return m, nil
			}
			m.focus = paneDaemon
			return m, nil
		case "f4":
			m.zoomed = !m.zoomed
			return m.resyncSignerSize()
		}
		if m.shellEnabled() && m.focus == paneShell && isScrollKey(msg) {
			m.shell.scrollPage(scrollDirection(msg), m.shellVisibleRows())
			return m, nil
		}
		if m.focus == paneDaemon && isScrollKey(msg) {
			m.daemon.scrollPage(scrollDirection(msg), m.daemonVisibleRows())
			return m, nil
		}
		if m.shellEnabled() && m.focus == paneShell {
			shell, cmd := m.shell.Update(msg)
			m.shell = shell
			return m, cmd
		}
	case shellExecMsg:
		if !m.shellEnabled() {
			return m, nil
		}
		shell, cmd := m.shell.Update(msg)
		m.shell = shell
		return m, cmd
	case shellHostKeyApprovalMsg:
		if !m.shellEnabled() {
			return m, nil
		}
		shell, cmd := m.shell.Update(msg)
		m.shell = shell
		return m, cmd
	case shellLinePromptMsg:
		if !m.shellEnabled() {
			return m, nil
		}
		shell, cmd := m.shell.Update(msg)
		m.shell = shell
		return m, cmd
	case shellStartupConnectMsg:
		if !m.shellEnabled() {
			return m, nil
		}
		shell, cmd := m.shell.Update(msg)
		m.shell = shell
		return m, cmd
	case shellProgressLineMsg:
		if !m.shellEnabled() {
			return m, nil
		}
		shell, cmd := m.shell.Update(msg)
		m.shell = shell
		return m, cmd
	case shellSpinnerTickMsg:
		if !m.shellEnabled() {
			return m, nil
		}
		shell, cmd := m.shell.Update(msg)
		m.shell = shell
		return m, cmd
	case daemonLogMsg:
		daemon, cmd := m.daemon.Update(msg)
		m.daemon = daemon
		return m, cmd
	}

	if m.focus == paneSigner || shouldForwardToSigner(msg) {
		return m.forwardToSigner(msg)
	}
	return m, nil
}

// resyncSignerSize forwards a synthetic WindowSizeMsg sized to the signer pane so
// the embedded Bubble Tea UI renders inside its box rather than the whole terminal.
func (m model) resyncSignerSize() (tea.Model, tea.Cmd) {
	l := m.layout()
	w := l.signer.width - paneBorderSize
	h := l.signer.height - paneBorderSize - 1 // minus header row
	if w < 1 {
		w = 1
	}
	if h < 1 {
		h = 1
	}
	return m.forwardToSigner(tea.WindowSizeMsg{Width: w, Height: h})
}

func (m model) forwardToSigner(msg tea.Msg) (tea.Model, tea.Cmd) {
	prev := m.signer
	next, cmd := m.signer.Update(msg)
	m.signer = next
	return m, confirmSignerQuitCmd(cmd, prev)
}

type signerQuitRequestMsg struct {
	signer tea.Model
}

func confirmSignerQuitCmd(cmd tea.Cmd, signer tea.Model) tea.Cmd {
	if cmd == nil {
		return nil
	}
	return func() tea.Msg {
		msg := cmd()
		switch msg := msg.(type) {
		case tea.QuitMsg:
			return signerQuitRequestMsg{signer: signer}
		case tea.BatchMsg:
			wrapped := make(tea.BatchMsg, 0, len(msg))
			for _, cmd := range msg {
				wrapped = append(wrapped, confirmSignerQuitCmd(cmd, signer))
			}
			return wrapped
		default:
			return msg
		}
	}
}

func (m model) handleQuitConfirmKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "y", "Y", "enter":
		return m, tea.Quit
	case "n", "N", "esc", "q", "ctrl+c":
		m.quitConfirm = false
		return m, nil
	default:
		return m, nil
	}
}

func shouldForwardToSigner(msg tea.Msg) bool {
	switch msg.(type) {
	case tea.KeyMsg:
		return false
	default:
		return true
	}
}

func (m model) View() string {
	l := m.layout()
	if l.contentWidth <= 0 || l.contentHeight <= 0 {
		return "APlane Console"
	}

	var body string
	switch {
	case m.shellEnabled() && m.shell.pendingHostKey != nil:
		body = lipgloss.Place(
			l.contentWidth, l.contentHeight,
			lipgloss.Center, lipgloss.Center,
			m.renderHostKeyOverlay(),
		)
	case m.quitConfirm:
		body = lipgloss.Place(
			l.contentWidth, l.contentHeight,
			lipgloss.Center, lipgloss.Center,
			m.renderQuitConfirmOverlay(),
		)
	case m.help:
		body = lipgloss.Place(
			l.contentWidth, l.contentHeight,
			lipgloss.Center, lipgloss.Center,
			m.renderHelpOverlay(),
		)
	default:
		body = m.renderBody(l)
	}
	frame := lipgloss.JoinVertical(
		lipgloss.Left,
		m.renderTitle(l.contentWidth),
		m.renderTabs(l.contentWidth),
		body,
		m.renderFooter(l.contentWidth),
	)
	// Belt-and-suspenders: never let the rendered frame exceed the terminal
	// dimensions. Any pane that misreports its height (or content that wraps
	// in lipgloss past our internal clamp) would otherwise push the bottom
	// of the layout past the screen and scramble the boundary rows.
	if m.width > 0 && m.height > 0 {
		frame = clampBlock(frame, m.width, m.height)
	}
	return frame
}

func (m model) layout() layout {
	width := m.width
	height := m.height
	if width <= 0 {
		width = 100
	}
	if height <= 0 {
		height = 28
	}

	contentWidth := max(20, width)
	contentHeight := max(1, height-headerHeight-footerHeight)
	split := !m.zoomed && width >= splitMinWidth && height >= splitMinHeight
	if !split {
		r := rect{width: contentWidth, height: contentHeight}
		return layout{
			split:         false,
			contentWidth:  contentWidth,
			contentHeight: contentHeight,
			shell:         r,
			signer:        r,
			daemon:        r,
		}
	}

	topHeight := max(8, (contentHeight*2)/3)
	daemonHeight := max(5, contentHeight-topHeight)
	if !m.daemon.owned {
		daemonHeight = m.daemon.preferredCompactHeight()
	}
	if contentHeight-daemonHeight < 8 {
		daemonHeight = max(5, contentHeight-8)
	}
	topHeight = contentHeight - daemonHeight
	if !m.shellEnabled() {
		return layout{
			split:         true,
			contentWidth:  contentWidth,
			contentHeight: contentHeight,
			shell:         rect{},
			signer:        rect{width: contentWidth, height: topHeight},
			daemon:        rect{width: contentWidth, height: daemonHeight},
		}
	}

	topWidth := contentWidth - topPaneGap
	signerWidth := (topWidth*signerPaneCols + (signerPaneCols+shellPaneCols)/2) / (signerPaneCols + shellPaneCols)
	shellWidth := topWidth - signerWidth

	return layout{
		split:         true,
		contentWidth:  contentWidth,
		contentHeight: contentHeight,
		shell:         rect{width: shellWidth, height: topHeight},
		signer:        rect{width: signerWidth, height: topHeight},
		daemon:        rect{width: contentWidth, height: daemonHeight},
	}
}

func (m model) renderBody(l layout) string {
	paneBody := func(r rect, render func(w, h int) string) string {
		innerW := r.width - paneBorderSize
		bodyH := r.height - paneBorderSize - 1 // reserve header row
		if innerW < 1 {
			innerW = 1
		}
		if bodyH < 1 {
			bodyH = 1
		}
		return render(innerW, bodyH)
	}

	daemonBody := paneBody(l.daemon, m.daemon.View)

	if !l.split {
		switch m.focus {
		case paneSigner:
			return renderPane(m.signerPaneTitle(), true, m.signer.View(), l.signer.width, l.signer.height)
		case paneDaemon:
			return renderPane("Daemon", true, daemonBody, l.daemon.width, l.daemon.height)
		default:
			if !m.shellEnabled() {
				return renderPane(m.signerPaneTitle(), true, m.signer.View(), l.signer.width, l.signer.height)
			}
			shellBody := paneBody(l.shell, m.shell.View)
			return renderPane("Shell", true, shellBody, l.shell.width, l.shell.height)
		}
	}

	signerBox := renderPane(m.signerPaneTitle(), m.focus == paneSigner, m.signer.View(), l.signer.width, l.signer.height)
	daemonBox := renderPane("Daemon", m.focus == paneDaemon, daemonBody, l.daemon.width, l.daemon.height)
	if !m.shellEnabled() {
		return lipgloss.JoinVertical(lipgloss.Left, signerBox, daemonBox)
	}
	shellBody := paneBody(l.shell, m.shell.View)
	shellBox := renderPane("Shell", m.focus == paneShell, shellBody, l.shell.width, l.shell.height)
	top := lipgloss.JoinHorizontal(lipgloss.Top, signerBox, strings.Repeat(" ", topPaneGap), shellBox)
	return lipgloss.JoinVertical(lipgloss.Left, top, daemonBox)
}

func (m model) signerPaneTitle() string {
	type adminTitleProvider interface {
		AdminTitle() string
	}
	if titled, ok := m.signer.(adminTitleProvider); ok {
		return titled.AdminTitle()
	}
	if !m.shellEnabled() {
		return "Attestor Admin"
	}
	return "Signer Admin"
}

func renderPane(title string, focused bool, body string, width, height int) string {
	innerW := width - paneBorderSize
	innerH := height - paneBorderSize
	if innerW < 4 {
		innerW = 4
	}
	if innerH < 2 {
		innerH = 2
	}

	p := theme.Current()
	borderColor := p.InputInactive
	headerColor := p.Subtitle
	if focused {
		borderColor = p.Button
		headerColor = p.Button
	}

	marker := "  "
	if focused {
		marker = "▸ "
	}
	header := lipgloss.NewStyle().
		Bold(focused).
		Foreground(lipgloss.Color(headerColor)).
		Width(innerW).
		Render(marker + title)

	bodyH := innerH - 1
	if bodyH < 1 {
		bodyH = 1
	}
	body = clampBlock(body, innerW, bodyH)

	stacked := lipgloss.JoinVertical(lipgloss.Left, header, body)

	rendered := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(borderColor)).
		Width(innerW).
		Height(innerH).
		Render(stacked)
	// lipgloss .Height pads up but does not truncate. Embedded children
	// (notably the signer Bubble Tea view) can render taller than we asked,
	// which would make JoinHorizontal/JoinVertical inflate the layout and
	// overrun the footer. Force the final shape to exactly width x height.
	return clampBlock(rendered, width, height)
}

// clampBlock ANSI-safely truncates each line to width and clips the block to
// at most height rows. The outer lipgloss frame handles right/bottom padding.
// A trailing reset is appended whenever a line contains any escape so a stray
// or truncation-orphaned style cannot bleed past the line.
func clampBlock(s string, width, height int) string {
	if width < 1 {
		width = 1
	}
	if height < 1 {
		height = 1
	}
	lines := strings.Split(s, "\n")
	if len(lines) > height {
		lines = lines[:height]
	}
	for i, line := range lines {
		if lipgloss.Width(line) > width {
			line = ansi.Truncate(line, width, "")
		}
		if strings.IndexByte(line, 0x1b) >= 0 {
			line += "\x1b[0m"
		}
		lines[i] = line
	}
	return strings.Join(lines, "\n")
}

func (m model) renderTitle(width int) string {
	p := theme.Current()
	title := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color(p.Title)).
		Render("APlane Console")

	mode := "split"
	if m.zoomed {
		mode = "zoom"
	} else if m.width < splitMinWidth || m.height < splitMinHeight {
		mode = "focus"
	}

	statusItems := []string{
		statusPill("daemon", string(m.daemon.status), daemonStatusColor(m.daemon.status)),
	}
	if m.shellEnabled() {
		statusItems = append(statusItems, statusPill("shell", m.shellState(), shellStatusColor(m.shell)))
	}
	statusItems = append(statusItems, statusPill("mode", mode, p.Subtitle))
	status := lipgloss.JoinHorizontal(lipgloss.Top, joinStatusItems(statusItems)...)
	return padBetween(title, status, width)
}

func joinStatusItems(items []string) []string {
	if len(items) <= 1 {
		return items
	}
	out := make([]string, 0, len(items)*2-1)
	for i, item := range items {
		if i > 0 {
			out = append(out, "  ")
		}
		out = append(out, item)
	}
	return out
}

func (m model) shellState() string {
	switch {
	case m.shell.busy():
		return "running"
	case m.shell.exited:
		return "closed"
	default:
		return "ready"
	}
}

func statusPill(key, value, valueColor string) string {
	p := theme.Current()
	label := lipgloss.NewStyle().Foreground(lipgloss.Color(p.Subtitle)).Render(key + ": ")
	val := lipgloss.NewStyle().Foreground(lipgloss.Color(valueColor)).Render(value)
	return label + val
}

func daemonStatusColor(s daemonStatus) string {
	p := theme.Current()
	switch s {
	case daemonStatusReady, daemonStatusAttached:
		return p.StatusConnected
	case daemonStatusStarting:
		return p.StatusLocked
	case daemonStatusFailed, daemonStatusExited:
		return p.StatusDisconnected
	default:
		return p.Subtitle
	}
}

func shellStatusColor(s shellModel) string {
	p := theme.Current()
	switch {
	case s.busy():
		return p.StatusLocked
	case s.exited:
		return p.StatusDisconnected
	default:
		return p.StatusConnected
	}
}

func (m model) renderTabs(width int) string {
	p := theme.Current()
	tab := func(key, name string, target pane) string {
		keyStyle := lipgloss.NewStyle().Foreground(lipgloss.Color(p.Help))
		nameStyle := lipgloss.NewStyle().Foreground(lipgloss.Color(p.Subtitle))
		if m.focus == target {
			nameStyle = lipgloss.NewStyle().Foreground(lipgloss.Color(p.Button)).Bold(true)
		}
		return lipgloss.NewStyle().Padding(0, 1).Render(keyStyle.Render(key) + " " + nameStyle.Render(name))
	}
	tabItems := []string{
		tab("F1", m.signerPaneTitle(), paneSigner),
	}
	if m.shellEnabled() {
		tabItems = append(tabItems, tab("F2", "Shell", paneShell))
	}
	if m.daemon.hasLogNavigation() {
		if !m.shellEnabled() {
			tabItems = append(tabItems, tab("F2", "Daemon", paneDaemon))
		} else {
			tabItems = append(tabItems, tab("F3", "Daemon", paneDaemon))
		}
	}
	tabs := lipgloss.JoinHorizontal(lipgloss.Top, tabItems...)
	hint := lipgloss.NewStyle().Foreground(lipgloss.Color(p.Help)).Render("F4 zoom · " + m.navigationHint() + " navigate")
	return padBetween(tabs, hint, width)
}

func (m model) renderFooter(width int) string {
	p := theme.Current()
	return lipgloss.NewStyle().
		Foreground(lipgloss.Color(p.Help)).
		Width(width).
		Render(m.footerText())
}

func (m model) footerText() string {
	if m.shellEnabled() && m.shell.pendingHostKey != nil {
		return "Trust SSH host: press y to accept · any other key to deny"
	}
	if m.shellEnabled() && m.shell.pendingLinePrompt != nil {
		return "Enter response · Ctrl+C cancel prompt"
	}
	if m.quitConfirm {
		return "Confirm quit: y/Enter quit · n/Esc cancel"
	}
	if m.help {
		return "?/Esc/F5/q close help · Ctrl+C quit"
	}
	if m.shellEnabled() && m.focus == paneShell && m.shell.startupRunning {
		return "Shell startup in progress · PgUp/PgDn scroll · " + m.focusHint() + " · F4 zoom"
	}
	if m.shellEnabled() && m.focus == paneShell && m.shell.running {
		return "Ctrl+C cancel shell command · PgUp/PgDn scroll · " + m.focusHint() + " · F4 zoom"
	}
	if m.shellEnabled() && m.focus == paneShell && m.shell.exited {
		return "Shell closed · r restart · PgUp/PgDn scroll · " + m.focusHint() + " · F4 zoom · Ctrl+C quit"
	}
	if m.shellEnabled() && m.focus == paneShell {
		return "←/→ edit · Up/Down history · PgUp/PgDn scroll · " + m.focusHint() + " · F4 zoom · ? help"
	}
	if m.focus == paneDaemon {
		return "PgUp/PgDn scroll · " + m.focusHint() + " · F4 zoom · " + m.navigationHint() + " navigate · ? help"
	}
	return m.focusHint() + " · F4 zoom · " + m.navigationHint() + " navigate · ? help · Ctrl+C confirm quit"
}

func (m model) navigationHint() string {
	if !m.shellEnabled() {
		return "Shift ↑ ↓"
	}
	return "Shift ← →"
}

func (m model) focusHint() string {
	if !m.shellEnabled() {
		if m.daemon.hasLogNavigation() {
			return "F1 signer · F2 daemon"
		}
		return "F1 signer"
	}
	if m.daemon.hasLogNavigation() {
		return "F1 signer · F2 shell · F3 daemon"
	}
	return "F1 signer · F2 shell"
}

func (m model) renderHostKeyOverlay() string {
	pending := m.shell.pendingHostKey
	if pending == nil {
		return ""
	}
	p := theme.Current()
	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(p.Title)).Render("Unknown SSH host")
	kv := func(k, v string) string {
		key := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(p.Button)).Width(14).Render(k)
		val := lipgloss.NewStyle().Foreground(lipgloss.Color(p.Subtitle)).Render(v)
		return lipgloss.JoinHorizontal(lipgloss.Top, key, val)
	}
	prompt := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(p.Button)).Render("Trust this server? [y/N]")
	hint := lipgloss.NewStyle().Foreground(lipgloss.Color(p.Help)).Render("y to trust and continue · any other key to deny")
	lines := []string{
		title,
		"",
		kv("Host", pending.host),
		kv("Fingerprint", pending.fingerprint),
		"",
		prompt,
		hint,
	}
	content := lipgloss.JoinVertical(lipgloss.Left, lines...)
	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(p.Popup)).
		Padding(1, 2).
		Render(content)
}

func (m model) renderQuitConfirmOverlay() string {
	p := theme.Current()
	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(p.Title)).Render("Quit APlane Console?")
	message := lipgloss.NewStyle().Foreground(lipgloss.Color(p.Subtitle)).Render("The signer admin pane requested exit.")
	prompt := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(p.Button)).Render("Quit? [y/N]")
	hint := lipgloss.NewStyle().Foreground(lipgloss.Color(p.Help)).Render("Enter/y to quit · Esc/n to cancel")
	content := lipgloss.JoinVertical(
		lipgloss.Left,
		title,
		"",
		message,
		"",
		prompt,
		hint,
	)
	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(p.Popup)).
		Padding(1, 2).
		Render(content)
}

func (m model) renderHelpOverlay() string {
	p := theme.Current()
	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(p.Title)).Render("APlane Console help")
	kv := func(k, v string) string {
		key := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(p.Button)).Width(16).Render(k)
		val := lipgloss.NewStyle().Foreground(lipgloss.Color(p.Subtitle)).Render(v)
		return lipgloss.JoinHorizontal(lipgloss.Top, key, val)
	}
	lines := []string{
		title,
		"",
		kv(m.helpFocusKeys(), m.helpFocusText()),
		kv(m.helpCycleKeys(), m.helpCycleText()),
		kv("F4", "toggle split/focused layout"),
		kv("? F5", "toggle this help"),
		kv("Esc / q", "close this help"),
		kv("PgUp/PgDn", m.helpScrollText()),
	}
	if m.shellEnabled() {
		lines = append(lines,
			kv("Up/Down", "browse shell command history when shell pane is focused"),
			kv("Ctrl+P/Ctrl+N", "previous or next shell history entry"),
			kv("Tab", "complete apshell command (when shell pane is focused)"),
			kv("Ctrl+C", "quit (or cancel running shell command when shell is focused)"),
		)
	} else {
		lines = append(lines, kv("Ctrl+C", "quit"))
	}
	lines = append(lines,
		"",
		kv("Signer pane", "apadmin Bubble Tea UI over local IPC or SSH admin"),
		kv("Daemon pane", "local apsigner status and owned-daemon logs"),
		"",
		kv("focus", m.focus.String()),
		kv("daemon", string(m.daemon.status)),
	)
	if m.shellEnabled() {
		lines = append(lines,
			kv("Shell pane", "embedded apshell command session"),
			kv("shell", m.shellState()),
		)
	}
	content := lipgloss.JoinVertical(lipgloss.Left, lines...)
	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(p.Popup)).
		Padding(1, 2).
		Render(content)
}

func (m model) helpFocusText() string {
	if !m.shellEnabled() {
		if m.daemon.hasLogNavigation() {
			return "focus signer or daemon"
		}
		return "focus signer"
	}
	if m.daemon.hasLogNavigation() {
		return "focus shell, signer, or daemon"
	}
	return "focus shell or signer"
}

func (m model) helpFocusKeys() string {
	if !m.shellEnabled() {
		if m.daemon.hasLogNavigation() {
			return "F1 F2"
		}
		return "F1"
	}
	if m.daemon.hasLogNavigation() {
		return "F1 F2 F3"
	}
	return "F1 F2"
}

func (m model) helpCycleKeys() string {
	if !m.shellEnabled() {
		return "Shift+↑ ↓"
	}
	return "Shift+← →"
}

func (m model) helpCycleText() string {
	if !m.shellEnabled() {
		if m.daemon.hasLogNavigation() {
			return "cycle signer and daemon panes"
		}
		return "signer pane only"
	}
	if m.daemon.hasLogNavigation() {
		return "cycle shell, signer, and daemon panes"
	}
	return "cycle shell and signer panes"
}

func (m model) helpScrollText() string {
	if !m.shellEnabled() {
		if m.daemon.hasLogNavigation() {
			return "scroll daemon log when focused"
		}
		return "no scrollable pane"
	}
	if m.daemon.hasLogNavigation() {
		return "scroll shell transcript or daemon log when focused"
	}
	return "scroll shell transcript when shell pane is focused"
}

// padBetween joins left and right with spaces so the combined visual width equals target.
func padBetween(left, right string, target int) string {
	lw := lipgloss.Width(left)
	rw := lipgloss.Width(right)
	gap := target - lw - rw
	if gap < 1 {
		if lw >= target {
			return ansi.Truncate(left, target, "")
		}
		return left + strings.Repeat(" ", target-lw)
	}
	return left + strings.Repeat(" ", gap) + right
}

// fitLine pads or truncates a line so its *visual* width equals width. Lines
// may contain ANSI escapes (e.g. apshell's colored address output), so visual
// width is measured via lipgloss.Width and truncation goes through ansi.Truncate.
// A trailing "\033[0m" is appended whenever the line contains any escape so an
// unterminated style (or one chopped off by truncation) can't bleed into the
// next row. Used by shell/daemon pane models.
func fitLine(s string, width int) string {
	if width < 0 {
		width = 0
	}
	visual := lipgloss.Width(s)
	if visual > width {
		s = ansi.Truncate(s, width, "")
		visual = lipgloss.Width(s)
	}
	if strings.IndexByte(s, 0x1b) >= 0 {
		s += "\x1b[0m"
	}
	if visual < width {
		s += strings.Repeat(" ", width-visual)
	}
	return s
}

func (m model) shellVisibleRows() int {
	l := m.layout()
	h := l.shell.height - paneBorderSize - 1
	if h < 1 {
		h = 1
	}
	return shellTranscriptHeight(h)
}

func (m model) daemonVisibleRows() int {
	l := m.layout()
	h := l.daemon.height - paneBorderSize - 1
	if h < 1 {
		h = 1
	}
	return h
}

func isScrollKey(msg tea.KeyMsg) bool {
	return msg.Type == tea.KeyPgUp || msg.Type == tea.KeyPgDown
}

func scrollDirection(msg tea.KeyMsg) int {
	if msg.Type == tea.KeyPgUp {
		return 1
	}
	return -1
}

func (m model) nextPane() pane {
	return nextPaneAvailable(m.focus, m.shellEnabled(), m.daemon.hasLogNavigation())
}

func (m model) prevPane() pane {
	return prevPaneAvailable(m.focus, m.shellEnabled(), m.daemon.hasLogNavigation())
}

func (m model) paneAbove() pane {
	if !m.shellEnabled() {
		return paneSigner
	}
	if m.focus == paneDaemon {
		return paneSigner
	}
	return m.focus
}

func (m model) paneBelow() pane {
	if !m.daemon.hasLogNavigation() {
		return m.focus
	}
	if !m.shellEnabled() {
		return paneDaemon
	}
	switch m.focus {
	case paneSigner, paneShell:
		return paneDaemon
	default:
		return m.focus
	}
}

func nextPaneAvailable(p pane, includeShell, includeDaemon bool) pane {
	if !includeShell {
		if includeDaemon {
			if p == paneSigner {
				return paneDaemon
			}
			return paneSigner
		}
		return paneSigner
	}
	return nextPane(p, includeDaemon)
}

func prevPaneAvailable(p pane, includeShell, includeDaemon bool) pane {
	if !includeShell {
		if includeDaemon {
			if p == paneSigner {
				return paneDaemon
			}
			return paneSigner
		}
		return paneSigner
	}
	return prevPane(p, includeDaemon)
}

func nextPane(p pane, includeDaemon bool) pane {
	switch p {
	case paneSigner:
		return paneShell
	case paneShell:
		if !includeDaemon {
			return paneSigner
		}
		return paneDaemon
	default:
		return paneSigner
	}
}

func prevPane(p pane, includeDaemon bool) pane {
	switch p {
	case paneShell:
		return paneSigner
	case paneDaemon:
		return paneShell
	default:
		if !includeDaemon {
			return paneShell
		}
		return paneDaemon
	}
}

func (p pane) String() string {
	switch p {
	case paneShell:
		return "shell"
	case paneSigner:
		return "signer"
	case paneDaemon:
		return "daemon"
	default:
		return "unknown"
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
