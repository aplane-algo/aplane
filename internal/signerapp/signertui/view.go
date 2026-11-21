// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

// Core view rendering and styles.
// View-specific renderers are in view_*.go files.

import (
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/charmbracelet/lipgloss"

	"github.com/aplane-algo/aplane/internal/algorithm"
	"github.com/aplane-algo/aplane/internal/theme"
)

// Styles — initialized from theme palette via initStyles()
var (
	titleStyle              lipgloss.Style
	subtitleStyle           lipgloss.Style
	statusConnectedStyle    lipgloss.Style
	statusDisconnectedStyle lipgloss.Style
	statusLockedStyle       lipgloss.Style
	statusUnlockedStyle     lipgloss.Style
	inputStyle              lipgloss.Style
	inputActiveStyle        lipgloss.Style
	inputInactiveStyle      lipgloss.Style
	errorStyle              lipgloss.Style
	warningStyle            lipgloss.Style
	helpStyle               lipgloss.Style
	selectedStyle           lipgloss.Style
	selectedRowBackground   lipgloss.Color
	normalStyle             lipgloss.Style
	buttonStyle             lipgloss.Style
	buttonActiveStyle       lipgloss.Style
	buttonInactiveStyle     lipgloss.Style
	popupStyle              lipgloss.Style
	keyTypeStyle            lipgloss.Style
)

func init() {
	initStyles()
}

// initStyles builds all lipgloss styles from the current theme palette.
func initStyles() {
	p := theme.Current()

	titleStyle = lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color(p.Title)).
		MarginBottom(1)

	subtitleStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color(p.Subtitle))

	statusConnectedStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color(p.StatusConnected))

	statusDisconnectedStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color(p.StatusDisconnected))

	statusLockedStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color(p.StatusLocked))

	statusUnlockedStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color(p.StatusConnected))

	inputStyle = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(p.InputBorder)).
		Padding(0, 1)

	inputActiveStyle = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(p.InputActive)).
		Padding(0, 1)

	inputInactiveStyle = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(p.InputInactive)).
		Padding(0, 1)

	errorStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color(p.Error)).
		Bold(true)

	warningStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color(p.Warning)).
		Bold(true)

	helpStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color(p.Help))

	selectedStyle = lipgloss.NewStyle().
		Background(lipgloss.Color(p.Selected)).
		Foreground(lipgloss.Color(p.SelectedFg)).
		Bold(true)

	// A selected row of a drawn review keeps its own colours, so a red
	// arrow stays red while it is looked at; only this tint marks it.
	selectedRowBackground = lipgloss.Color(p.SelectedRow)

	normalStyle = lipgloss.NewStyle()

	buttonStyle = lipgloss.NewStyle().
		Padding(0, 2).
		Border(lipgloss.RoundedBorder())

	buttonActiveStyle = buttonStyle.
		BorderForeground(lipgloss.Color(p.Button)).
		Foreground(lipgloss.Color(p.Button))

	buttonInactiveStyle = buttonStyle.
		BorderForeground(lipgloss.Color(p.ButtonInactive)).
		Foreground(lipgloss.Color(p.ButtonInactive))

	popupStyle = lipgloss.NewStyle().
		Border(lipgloss.DoubleBorder()).
		BorderForeground(lipgloss.Color(p.Popup)).
		Padding(1, 2).
		Width(80)

	keyTypeStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color(p.KeyType))
}

// popupWidth returns the width to pass to popupStyle. Lipgloss adds the border
// around that width, so once the terminal or panel reports its size this uses
// width-2 to make the rendered box fill the panel without overflowing it. max
// is only used as a fallback before sizing information arrives.
func (m Model) popupWidth(max int) int {
	if m.width <= 0 {
		return max
	}
	w := m.width - 2
	if w < 1 {
		return 1
	}
	return w
}

// popupBodyWidth returns the horizontal space available to body content after
// popupStyle's padding is applied.
func (m Model) popupBodyWidth(max int) int {
	w := m.popupWidth(max) - popupStyle.GetHorizontalPadding()
	if w < 1 {
		return 1
	}
	return w
}

func (m Model) popupContentHeight() int {
	return popupContentHeightForRenderedHeight(m.windowBodyHeight())
}

func popupContentHeightForRenderedHeight(renderedHeight int) int {
	if renderedHeight <= 0 {
		return 0
	}
	// popupStyle adds four chrome rows: two border rows plus one padding row
	// above and below the body.
	const popupVerticalChrome = 4
	h := renderedHeight - popupVerticalChrome
	if h < 1 {
		return 1
	}
	return h
}

func (m Model) renderPopup(maxWidth int, body string) string {
	return m.renderPopupWithinHeight(maxWidth, body, m.windowBodyHeight())
}

func (m Model) renderPopupWithinHeight(maxWidth int, body string, maxHeight int) string {
	contentHeight := popupContentHeightForRenderedHeight(maxHeight)
	bodyWidth := m.popupBodyWidth(maxWidth)
	return popupStyle.Width(m.popupWidth(maxWidth)).Render(
		m.renderScrollablePopupBody(body, contentHeight, bodyWidth),
	)
}

const panelScrollScale = 1000

func (m Model) renderScrollablePopupBody(body string, maxLines, maxWidth int) string {
	if maxLines <= 0 {
		return body
	}
	// Counted as the popup draws them: a line wider than the body wraps.
	lines := strings.Split(lipgloss.NewStyle().Width(maxWidth).Render(strings.TrimRight(body, "\n")), "\n")
	if len(lines) <= maxLines {
		return strings.Join(lines, "\n")
	}
	if !m.usesSharedPopupViewport() {
		return strings.Join(lines[:maxLines], "\n")
	}
	if maxLines == 1 {
		return fixedWidthFieldLine(lines[0], maxWidth)
	}

	viewportHeight := maxLines - 1 // reserve one row for position and controls
	maxOffset := len(lines) - viewportHeight
	position := 0
	if m.panelScrollView == m.viewState {
		position = m.panelScrollPosition
	}
	if position < 0 {
		position = 0
	}
	if position > panelScrollScale {
		position = panelScrollScale
	}
	offset := maxOffset * position / panelScrollScale
	end := offset + viewportHeight
	if end > len(lines) {
		end = len(lines)
	}

	visible := append([]string(nil), lines[offset:end]...)
	status := fmt.Sprintf("Panel lines %d-%d / %d  Ctrl+PgUp/PgDn", offset+1, end, len(lines))
	if maxWidth > 0 {
		status = ellipsize(status, maxWidth)
	}
	visible = append(visible, subtitleStyle.Render(status))
	return strings.Join(visible, "\n")
}

// algorithmColor returns the theme-aware ANSI color code for a given key type.
// Falls back to the theme's default color if no algorithm-specific color is defined.
func algorithmColor(keyType string) string {
	p := theme.Current()
	color := algorithm.GetDisplayColor(keyType)
	if color == "" {
		return p.DefaultColor
	}
	// Map algorithm colors to theme-appropriate variants
	if !theme.IsDark() {
		switch color {
		case "36": // Cyan → dark cyan for light backgrounds
			return p.Ed25519Color
		case "33": // Yellow → dark yellow for light backgrounds
			return p.FalconColor
		}
	}
	return color
}

// styledKeyType returns a key type string styled with the algorithm's display color
// Uses raw ANSI codes for consistent behavior with apshell
func styledKeyType(keyType string) string {
	return fmt.Sprintf("\033[%sm[%s]\033[0m", algorithmColor(keyType), displayKeyType(keyType))
}

// styledAddress returns an address string styled with the algorithm's display color
func styledAddress(address, keyType string) string {
	return fmt.Sprintf("\033[%sm%s\033[0m", algorithmColor(keyType), address)
}

// View renders the TUI
func (m Model) View() string {
	if m.quitting {
		return "Goodbye!\n"
	}
	if m.belowMinSize() {
		return m.renderTooSmall()
	}

	content := m.renderViewContent()
	footer := m.renderWindowFooter()
	statusBar := m.renderStatusBar()
	header := ""
	if m.standalone {
		header = m.renderAdminHeader()
	}

	return terminalSafeScreen(m.renderWindowLayout(header, content, footer, statusBar))
}

// AdminTitle returns the role-specific operator-facing title for this admin UI.
func (m Model) AdminTitle() string {
	if m.isCosignerNode() {
		return "Cosigner Admin"
	}
	return "Signer Admin"
}

func (m Model) renderAdminHeader() string {
	p := theme.Current()
	title := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color(p.Button)).
		Render(m.AdminTitle())

	meta := m.AdminHeaderMeta()
	if meta == "" {
		return title
	}
	metaStyle := lipgloss.NewStyle().Foreground(lipgloss.Color(p.Subtitle))
	if m.width <= 0 {
		return title + "  " + metaStyle.Render(meta)
	}

	const minGap = 2
	titleWidth := lipgloss.Width(title)
	available := m.width - titleWidth - minGap
	if available <= 0 {
		return title
	}
	meta = ellipsizeMiddle(meta, available)
	renderedMeta := metaStyle.Render(meta)
	spaces := m.width - titleWidth - lipgloss.Width(renderedMeta)
	if spaces < minGap {
		spaces = minGap
	}
	return title + strings.Repeat(" ", spaces) + renderedMeta
}

// AdminHeaderMeta returns the unstyled role-specific endpoint summary for the
// admin header and for pane chrome owned by apconsole.
func (m Model) AdminHeaderMeta() string {
	// The REST port is a loopback detail behind the SSH endpoint; the header
	// shows only what a client needs.
	if endpoint := m.adminEndpointDisplayURL(); endpoint != "" {
		return "Endpoint: " + terminalSafe(endpoint)
	}
	return ""
}

func (m Model) adminEndpointDisplayURL() string {
	if m.admin.settings == nil {
		return ""
	}
	if endpoint := strings.TrimSpace(m.admin.settings.EndpointDisplayURL); endpoint != "" {
		return endpoint
	}
	if endpoint := strings.TrimSpace(m.admin.settings.EndpointAdvertiseURL); endpoint != "" {
		return endpoint
	}
	if m.admin.settings.SSHPort <= 0 {
		return ""
	}
	host := strings.TrimSpace(m.admin.settings.SSHListenAddress)
	if host == "" {
		host = "127.0.0.1"
	}
	if host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	return "ssh://" + net.JoinHostPort(host, strconv.Itoa(m.admin.settings.SSHPort))
}

func (m Model) renderViewContent() string {
	if m.fileBrowserOpen() {
		return m.renderFileBrowser()
	}
	var content string

	switch m.viewState {
	case ViewAuth:
		content = m.renderAuthView()
	case ViewUnlock:
		content = m.renderUnlockView()
	case ViewKeyList:
		content = m.renderKeyListView()
	case ViewKeyDetails:
		content = m.renderKeyDetails()
	case ViewSourceTokens:
		content = m.renderSourceTokens()
	case ViewTEALFullDisplay:
		content = m.renderTEALFullDisplay()
	case ViewSigningPopup:
		content = m.renderSigningPopup()
	case ViewClientEnrollmentPopup:
		content = m.renderClientEnrollmentPopup()
	case ViewBackupConfirm:
		content = m.renderBackupConfirm()
	case ViewBackingUp:
		content = m.renderBackingUp()
	case ViewBackupDisplay:
		content = m.renderBackupDisplay()
	case ViewBackups:
		content = m.renderBackups()
	case ViewRestorePassphrase:
		content = m.renderRestorePassphrase()
	case ViewRestorePreview:
		content = m.renderRestorePreview()
	case ViewRestoring:
		content = m.renderRestoring()
	case ViewRestoreDisplay:
		content = m.renderRestoreDisplay()
	case ViewStoreRecovery:
		content = m.renderStoreRecovery()
	case ViewImportForm:
		content = m.renderImportForm()
	case ViewImportParams:
		content = m.renderImportParams()
	case ViewImporting:
		content = m.renderImporting()
	case ViewImportDisplay:
		content = m.renderImportDisplay()
	case ViewGenerateForm:
		content = m.renderGenerateForm()
	case ViewGenerateParams:
		content = m.renderGenerateParams()
	case ViewCosignerPicker:
		content = m.renderCosignerPicker()
	case ViewCosignerImportForm:
		content = m.renderCosignerImportForm()
	case ViewCosignerImportReview:
		content = m.renderCosignerImportReview()
	case ViewCosignerImporting:
		content = m.renderCosignerImporting()
	case ViewCosignerReferences:
		content = m.renderCosignerReferences()
	case ViewCosignerReferenceDetails:
		content = m.renderCosignerReferenceDetails()
	case ViewCosignerRemoveConfirm:
		content = m.renderCosignerRemoveConfirm()
	case ViewCosignerRemoving:
		content = m.renderCosignerRemoving()
	case ViewCosignerGenerateType:
		content = m.renderCosignerGenerateType()
	case ViewCosignerExportPath:
		content = m.renderCosignerExportPath()
	case ViewCosignerExporting:
		content = m.renderCosignerExporting()
	case ViewCosignerExportResult:
		content = m.renderCosignerExportResult()
	case ViewCosignerExportJSON:
		content = "Displaying JSON in the terminal..."
	case ViewGenerating:
		content = m.renderGenerating()
	case ViewMnemonicExport:
		content = m.renderMnemonicExport()
	case ViewBoundaryPreset:
		content = m.renderBoundaryPreset()
	case ViewGenerateReview:
		content = m.renderGenerateReview()
	case ViewGenerateReviewDetails:
		content = m.renderGenerateReviewDetails()
	case ViewGenerateDisplay:
		content = m.renderGenerateDisplay()
	case ViewDeleteConfirm:
		content = m.renderDeleteConfirm()
	case ViewEnrolledClients:
		content = m.renderEnrolledClients()
	case ViewRevokeClientConfirm:
		content = m.renderRevokeClientConfirm()
	case ViewImportClientKey:
		content = m.renderImportClientKey()
	case ViewLockConfirm:
		content = m.renderLockConfirm()
	case ViewDeleting:
		content = m.renderDeleting()
	case ViewDisplaceConfirm:
		content = m.renderDisplaceConfirm()
	case ViewAdminPanel:
		content = m.renderAdminPanel()
	case ViewPolicies:
		content = m.renderPolicies()
	case ViewPolicyDocument:
		content = m.renderPolicyDocument()
	case ViewPolicyApplyForm:
		content = m.renderPolicyApplyForm()
	case ViewPolicyApplyReview:
		content = m.renderPolicyApplyReview()
	case ViewPolicyEdit:
		content = m.renderPolicyEdit()
	case ViewPolicyPresetPick:
		content = m.renderPolicyPresetPick()
	case ViewPolicyExportForm:
		content = m.renderPolicyExportForm()
	case ViewBackupDeleteConfirm:
		content = m.renderBackupDeleteConfirm()
	case ViewBackupUndoConfirm:
		content = m.renderBackupUndoConfirm()
	case ViewBackupExport:
		content = m.renderBackupExport()
	case ViewBackupImport:
		content = m.renderBackupImport()
	case ViewTemplateLibrary:
		content = m.renderTemplateLibrary()
	case ViewTemplateInstallConfirm:
		content = m.renderTemplateInstallConfirm()
	case ViewTemplateInstalling:
		content = m.renderTemplateInstalling()
	case ViewLibraryTemplateDetails:
		content = m.renderLibraryTemplateDetails()
	case ViewError:
		content = m.renderErrorView()
	default:
		content = m.renderKeyListView()
	}

	return content
}

func (m Model) renderWindowLayout(header, content, footer, statusBar string) string {
	header = strings.TrimRight(header, "\n")
	content = strings.TrimRight(content, "\n")
	footer = strings.TrimRight(footer, "\n")
	statusBar = strings.TrimRight(statusBar, "\n")

	if m.height <= 0 {
		return joinRenderedBlocks(header, content, footer, statusBar)
	}

	headerHeight := renderedBlockHeight(header)
	footerHeight := renderedBlockHeight(footer)
	statusHeight := renderedBlockHeight(statusBar)
	bodyMaxHeight := m.height - headerHeight - footerHeight - statusHeight
	if bodyMaxHeight < 0 {
		bodyMaxHeight = 0
	}
	content = m.constrainWindowBlock(content, bodyMaxHeight)

	contentHeight := renderedBlockHeight(content)
	padding := m.height - headerHeight - contentHeight - footerHeight - statusHeight
	if padding < 0 {
		padding = 0
	}

	out := joinRenderedBlocks(header, content)
	if padding > 0 {
		if out != "" {
			out += strings.Repeat("\n", padding+1)
		} else {
			out += strings.Repeat("\n", padding)
		}
	}
	out = appendRenderedBlock(out, footer)
	out = appendRenderedBlock(out, statusBar)
	return lipgloss.NewStyle().MaxHeight(m.height).Render(out)
}

func (m Model) constrainWindowBlock(body string, maxHeight int) string {
	if maxHeight <= 0 {
		return ""
	}
	style := lipgloss.NewStyle()
	if m.width > 0 {
		style = style.MaxWidth(m.width)
	}
	return style.MaxHeight(maxHeight).Render(strings.TrimRight(body, "\n"))
}

func (m Model) windowBodyHeight() int {
	return m.windowBodyHeightUnder(renderedBlockHeight(m.renderWindowFooter()))
}

// windowBodyHeightUnder is the window body's height under a footer of
// footerRows rows.
func (m Model) windowBodyHeightUnder(footerRows int) int {
	if m.height <= 0 {
		return 0
	}
	headerHeight := 0
	if m.standalone {
		headerHeight = 1
	}
	h := m.height - headerHeight - footerRows - renderedBlockHeight(m.renderStatusBar())
	if h < 1 {
		return 1
	}
	return h
}

func (m Model) renderWindowFooter() string {
	return m.renderFooterText(m.viewFooterText())
}

// renderFooterText draws footer text as the window footer does.
func (m Model) renderFooterText(text string) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}
	width := m.width
	if width <= 0 {
		width = 96
	}
	return helpStyle.Render(wrapShortcutHint(text, width))
}

func joinRenderedBlocks(blocks ...string) string {
	out := ""
	for _, block := range blocks {
		out = appendRenderedBlock(out, block)
	}
	return out
}

func appendRenderedBlock(out, block string) string {
	block = strings.TrimRight(block, "\n")
	if block == "" {
		return out
	}
	if out != "" && !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	return out + block
}

func renderedBlockHeight(s string) int {
	s = strings.TrimRight(s, "\n")
	if s == "" {
		return 0
	}
	return strings.Count(s, "\n") + 1
}

// minSettingWarningWidth is the least room the status line's setting warning
// is shown in: "Warning: ", the longest setting name (18 columns) and "...".
const minSettingWarningWidth = len("Warning: ") + 18 + len("...")

// statusRank orders the status bar's parts for the rows under its line: a
// lower rank gets its rows first.
type statusRank int

const (
	rankLine statusRank = iota // connection and signer state, always on the line
	rankAlert
	rankError
	rankArming // why an approval key was not taken yet
	rankWarning
	rankNotice
)

// statusPart is one part of the status bar: its terminal-safe text, the
// style it is drawn in, its rank, and the kind the count of parts left out
// names it by.
type statusPart struct {
	text  string
	style lipgloss.Style
	rank  statusRank
	kind  string
}

// statusParts is the status bar's parts in the order its line shows them,
// and the place among them of the admin panel's setting warning.
func (m Model) statusParts() (parts []statusPart, settingAt int) {
	switch m.connectionState {
	case ConnectionConnected:
		parts = append(parts, statusPart{"Connected", statusConnectedStyle, rankLine, ""})
	case ConnectionConnecting:
		parts = append(parts, statusPart{"Connecting...", subtitleStyle, rankLine, ""})
	case ConnectionDisconnected:
		parts = append(parts, statusPart{"Disconnected (press 'c' to reconnect)", statusDisconnectedStyle, rankLine, ""})
	}

	// Signer status (only show once we've heard from apsigner)
	if m.signerStatusKnown {
		switch m.signerState {
		case signerRuntimeUnlocked:
			parts = append(parts, statusPart{fmt.Sprintf("Signer Unlocked (%d keys)", m.keyCount), statusUnlockedStyle, rankLine, ""})
		case signerRuntimeRecovery:
			parts = append(parts, statusPart{"Signer Recovery (signing disabled)", statusLockedStyle, rankLine, ""})
		default:
			parts = append(parts, statusPart{"Signer Locked", statusLockedStyle, rankLine, ""})
		}
	}

	// A lost notification can be an approval request, so this stays for the
	// session and ranks with the signer's alerts, ahead of them as it is
	// always short.
	if m.notificationsLost > 0 {
		noun := "notifications"
		if m.notificationsLost == 1 {
			noun = "notification"
		}
		parts = append(parts, statusPart{fmt.Sprintf("Warning: %d signer %s lost", m.notificationsLost, noun), warningStyle, rankAlert, "notifications lost"})
	}
	// Signer-raised alerts stay until the signer clears them.
	for _, warning := range m.signerWarnings {
		parts = append(parts, statusPart{"ALERT: " + terminalSafe(warning), errorStyle, rankAlert, "alert"})
	}
	if m.lastNotice != "" {
		rank := rankNotice
		if m.lastNoticeArming {
			rank = rankArming
		}
		parts = append(parts, statusPart{terminalSafe(m.lastNotice), statusConnectedStyle, rank, "notice"})
	}
	if m.lastWarning != "" {
		parts = append(parts, statusPart{"Warning: " + terminalSafe(m.lastWarning), warningStyle, rankWarning, "warning"})
	}
	settingAt = len(parts)
	if errorText := m.statusBarError(); errorText != "" {
		parts = append(parts, statusPart{"Error: " + terminalSafe(errorText), errorStyle, rankError, "error"})
	}
	return parts, settingAt
}

// statusLayout is where the status bar draws each part: on the line, in the
// rows under it, or left out.
type statusLayout struct {
	onLine  []bool
	rows    map[int][]string
	dropped []int // the parts left out, by rank
	used    int   // the columns the line's parts take
}

// statusCountRoom is the room the line keeps for the count of the parts left
// out when there are any: " | +" and the digits of the most there can be.
// The connection and signer state stay on the line whatever room is kept,
// and where they leave too little for " | " the count follows a space
// (statusCount): beside the widest of them, 74 columns, it fits for up to
// 9999 parts.
func statusCountRoom(parts int) int {
	return len(" | +") + len(strconv.Itoa(parts))
}

// layoutStatusParts places parts on a line of lineWidth columns while they
// fit, by rank, the connection and signer state always, and the rest in at
// most maxErrorLines rows of width columns under it, wrapped and cut in the
// middle (wrapCutLines). The rows go by rank, a row kept for each later
// part while rows last, and one always for the error, which answers what
// the operator just did.
func layoutStatusParts(parts []statusPart, width, lineWidth int) statusLayout {
	byRank := make([]int, len(parts))
	for i := range byRank {
		byRank[i] = i
	}
	slices.SortStableFunc(byRank, func(a, b int) int { return int(parts[a].rank) - int(parts[b].rank) })

	layout := statusLayout{onLine: make([]bool, len(parts)), rows: map[int][]string{}}
	var under []int
	for _, i := range byRank {
		w := lipgloss.Width(parts[i].text)
		if layout.used > 0 {
			w += len(" | ")
		}
		if parts[i].rank == rankLine || layout.used+w <= lineWidth {
			layout.onLine[i] = true
			layout.used += w
		} else {
			under = append(under, i)
		}
	}

	held, later := 0, len(under) // the error's row, and the other parts still to place
	for _, i := range under {
		if parts[i].rank == rankError {
			held, later = 1, later-1
		}
	}
	budget := maxErrorLines
	for _, i := range under {
		if parts[i].rank == rankError {
			held = 0
		} else {
			later--
		}
		avail := budget - held
		if avail <= 0 {
			layout.dropped = append(layout.dropped, i)
			continue
		}
		layout.rows[i] = wrapCutLines(parts[i].text, width, max(1, avail-later))
		budget -= len(layout.rows[i])
	}
	return layout
}

// statusCount is the line's count of the parts left out, and the separator
// before it, in room columns: after " | " as a part, with their kinds named
// when room allows, or, when nothing else fits, "+N" after a space.
func statusCount(parts []statusPart, dropped []int, room int) (sep, count string) {
	var kinds []string
	for _, i := range dropped {
		if !slices.Contains(kinds, parts[i].kind) {
			kinds = append(kinds, parts[i].kind)
		}
	}
	short := fmt.Sprintf("+%d", len(dropped))
	for _, text := range []string{short + " more: " + strings.Join(kinds, ", "), short + " more", short} {
		if len(" | ")+lipgloss.Width(text) <= room {
			return " | ", text
		}
	}
	return " ", short
}

// renderStatusBar renders the bottom status bar (layoutStatusParts), so no
// screen grows wider than the window. When parts are left out, the line
// keeps room for a count of them.
func (m Model) renderStatusBar() string {
	width := m.tableWidth()
	parts, settingAt := m.statusParts()
	layout := layoutStatusParts(parts, width, width)
	if len(layout.dropped) > 0 {
		layout = layoutStatusParts(parts, width, width-statusCountRoom(len(parts)))
	}

	var line, blocks []string
	settingSlot := 0
	for i, part := range parts {
		switch {
		case layout.onLine[i]:
			line = append(line, part.style.Render(part.text))
			if i < settingAt {
				settingSlot++
			}
		case layout.rows[i] != nil:
			blocks = append(blocks, part.style.Render(strings.Join(layout.rows[i], "\n")))
		}
	}
	used, count := layout.used, ""
	if len(layout.dropped) > 0 {
		style := warningStyle
		if parts[layout.dropped[0]].rank <= rankError {
			style = errorStyle
		}
		sep, text := statusCount(parts, layout.dropped, width-used)
		if used == 0 {
			sep = ""
		}
		count = sep + style.Render(text)
		used += lipgloss.Width(count)
	}
	if setting := m.settingWarningPart(width, used); setting != "" {
		line = slices.Insert(line, settingSlot, setting)
	}
	if text := strings.Join(line, " | ") + count; text != "" {
		// The line's own parts always fit at the minimum width; in a
		// narrower window, which shows no status bar, they are cut.
		blocks = append([]string{ellipsize(text, width)}, blocks...)
	}
	return helpStyle.Render(strings.Join(blocks, "\n"))
}

// settingWarningPart is the status line's part for a setting update's
// in-effect warning, which belongs to the admin panel, on a line of width
// whose other parts take used columns. It is cut to the room they leave, so
// the line stays one row and takes none from the panel, and dropped when
// that room cannot hold even the setting's name; the panel's own unsaved
// warning still shows.
func (m Model) settingWarningPart(width, used int) string {
	w := m.admin.settingWarning.text
	if m.viewState != ViewAdminPanel || w == "" {
		return ""
	}
	room := width - used
	if used > 0 {
		room -= len(" | ")
	}
	if room < minSettingWarningWidth {
		return ""
	}
	return warningStyle.Render(ellipsize(terminalSafe(w), room))
}

// statusBarError is the error the status bar shows: the last error, but not
// on the cosigner manager or the Backups page while it is the failed list
// the screen shows itself, so the error is on screen once.
func (m Model) statusBarError() string {
	switch {
	case m.viewState == ViewCosignerReferences && m.lastError == m.cosigner.listErr,
		m.viewState == ViewBackups && m.lastError == backupListFailure(m.restore.backupsListErr):
		return ""
	}
	return m.lastError
}

// maxErrorLines bounds a daemon error a screen shows, and the rows the
// status bar takes under its line, so a long message leaves the rest of the
// window its room.
const maxErrorLines = 3

// wrapCutLines wraps text to width, breaking a word wider than a line, such
// as a path. Text longer than maxLines lines is cut in the middle, since a
// Go error ends in its cause ("no space left on device"): its first lines,
// the last of them ending in "..." where the text is cut, then as much of
// its end as one line holds; on a single line, its start, "...", and its
// end.
func wrapCutLines(text string, width, maxLines int) []string {
	width = max(width, 1)
	words := breakWideWords(strings.Fields(text), width)
	lines := strings.Split(wrapPlainText(strings.Join(words, " "), width), "\n")
	if len(lines) <= maxLines {
		return lines
	}
	if maxLines <= 1 {
		return []string{ellipsizeMiddle(strings.Join(strings.Fields(text), " "), width)}
	}
	// The end: the most of the last words one line holds. The wrap fills
	// each line before the next, so if the rest fit in fewer lines than are
	// kept for it, the whole text would have fit, and some of it is cut.
	tail := len(words) - 1
	for tail > 0 && lipgloss.Width(strings.Join(words[tail-1:], " ")) <= width {
		tail--
	}
	head := strings.Split(wrapPlainText(strings.Join(words[:tail], " "), width), "\n")[:maxLines-1]
	head[len(head)-1] = ellipsize(head[len(head)-1]+"...", width)
	return append(head, strings.Join(words[tail:], " "))
}

// breakWideWords breaks each word wider than width into pieces that fit. A
// piece takes at least one character, so a character wider than width, such
// as a two-column one at width 1, is a piece of its own.
func breakWideWords(words []string, width int) []string {
	var out []string
	for _, word := range words {
		for lipgloss.Width(word) > width {
			cut := 0
			for i := range word {
				if lipgloss.Width(word[:i]) > width {
					break
				}
				cut = i
			}
			if cut == 0 {
				_, cut = utf8.DecodeRuneInString(word)
			}
			out = append(out, word[:cut])
			word = word[cut:]
		}
		if word != "" {
			out = append(out, word)
		}
	}
	return out
}
