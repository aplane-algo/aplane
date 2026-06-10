// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

// Core view rendering and styles.
// View-specific renderers are in view_*.go files.

import (
	"fmt"
	"net"
	"strconv"
	"strings"

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
	return popupStyle.Width(m.popupWidth(maxWidth)).Render(
		constrainPopupBody(body, popupContentHeightForRenderedHeight(maxHeight)),
	)
}

func constrainPopupBody(body string, maxLines int) string {
	if maxLines <= 0 {
		return body
	}
	lines := strings.Split(strings.TrimRight(body, "\n"), "\n")
	if len(lines) <= maxLines {
		return strings.Join(lines, "\n")
	}
	return strings.Join(lines[:maxLines], "\n")
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

	content := m.renderViewContent()
	footer := m.renderWindowFooter()
	statusBar := m.renderStatusBar()
	header := ""
	if m.standalone {
		header = m.renderAdminHeader()
	}

	return m.renderWindowLayout(header, content, footer, statusBar)
}

// AdminTitle returns the role-specific operator-facing title for this admin UI.
func (m Model) AdminTitle() string {
	if m.isSentryNode() {
		return "Sentry Admin"
	}
	return "Signer Admin"
}

// AdminHeaderMeta returns the unstyled role-specific endpoint summary for pane
// chrome owned by apconsole.
func (m Model) AdminHeaderMeta() string {
	return m.adminHeaderMeta()
}

func (m Model) renderAdminHeader() string {
	p := theme.Current()
	title := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color(p.Button)).
		Render(m.AdminTitle())

	meta := m.adminHeaderMeta()
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

func (m Model) adminHeaderMeta() string {
	if m.adminSettings == nil {
		return ""
	}
	var parts []string
	if m.adminSettings.SignerPort != 0 {
		parts = append(parts, fmt.Sprintf("%s: %d", m.rolePortLabel(), m.adminSettings.SignerPort))
	}
	if endpoint := m.adminEndpointDisplayURL(); endpoint != "" {
		parts = append(parts, "Endpoint: "+endpoint)
	}
	return strings.Join(parts, "  ")
}

func (m Model) adminEndpointDisplayURL() string {
	if m.adminSettings == nil {
		return ""
	}
	if endpoint := strings.TrimSpace(m.adminSettings.EndpointDisplayURL); endpoint != "" {
		return endpoint
	}
	if endpoint := strings.TrimSpace(m.adminSettings.EndpointAdvertiseURL); endpoint != "" {
		return endpoint
	}
	if !m.adminSettings.SSHEnabled || m.adminSettings.SSHPort <= 0 {
		return ""
	}
	host := strings.TrimSpace(m.adminSettings.SSHListenAddress)
	if host == "" {
		host = "127.0.0.1"
	}
	if host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	return "ssh://" + net.JoinHostPort(host, strconv.Itoa(m.adminSettings.SSHPort))
}

func (m Model) renderViewContent() string {
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
	case ViewTEALFullDisplay:
		content = m.renderTEALFullDisplay()
	case ViewSigningPopup:
		content = m.renderSigningPopup()
	case ViewTokenProvisioningPopup:
		content = m.renderTokenProvisioningPopup()
	case ViewBackupConfirm:
		content = m.renderBackupConfirm()
	case ViewBackingUp:
		content = m.renderBackingUp()
	case ViewBackupDisplay:
		content = m.renderBackupDisplay()
	case ViewRestoreList:
		content = m.renderRestoreList()
	case ViewRestorePassphrase:
		content = m.renderRestorePassphrase()
	case ViewRestorePreview:
		content = m.renderRestorePreview()
	case ViewRestoring:
		content = m.renderRestoring()
	case ViewRestoreDisplay:
		content = m.renderRestoreDisplay()
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
	case ViewGenerating:
		content = m.renderGenerating()
	case ViewGenerateDisplay:
		content = m.renderGenerateDisplay()
	case ViewDeleteConfirm:
		content = m.renderDeleteConfirm()
	case ViewRevokeTokenConfirm:
		content = m.renderRevokeTokenConfirm()
	case ViewLockConfirm:
		content = m.renderLockConfirm()
	case ViewDeleting:
		content = m.renderDeleting()
	case ViewDisplaceConfirm:
		content = m.renderDisplaceConfirm()
	case ViewAdminPanel:
		content = m.renderAdminPanel()
	case ViewPolicyEditor:
		content = m.renderPolicyEditor()
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
	if m.height <= 0 {
		return 0
	}
	headerHeight := 0
	if m.standalone {
		headerHeight = 1
	}
	h := m.height - headerHeight - renderedBlockHeight(m.renderWindowFooter()) - renderedBlockHeight(m.renderStatusBar())
	if h < 1 {
		return 1
	}
	return h
}

func (m Model) renderWindowFooter() string {
	text := strings.TrimSpace(m.viewFooterText())
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

// renderStatusBar renders the bottom status bar
func (m Model) renderStatusBar() string {
	var parts []string

	// Connection status
	switch m.connectionState {
	case ConnectionConnected:
		parts = append(parts, statusConnectedStyle.Render("Connected"))
	case ConnectionConnecting:
		parts = append(parts, subtitleStyle.Render("Connecting..."))
	case ConnectionDisconnected:
		parts = append(parts, statusDisconnectedStyle.Render("Disconnected (press 'c' to reconnect)"))
	}

	// Signer status (only show once we've heard from apsigner)
	if m.signerStatusKnown {
		if m.signerLocked {
			parts = append(parts, statusLockedStyle.Render("Signer Locked"))
		} else {
			parts = append(parts, statusUnlockedStyle.Render(fmt.Sprintf("Signer Unlocked (%d keys)", m.keyCount)))
		}
	}

	// Warning if any
	if m.lastWarning != "" {
		parts = append(parts, warningStyle.Render("Warning: "+m.lastWarning))
	}

	// Error if any
	if m.lastError != "" {
		parts = append(parts, errorStyle.Render("Error: "+m.lastError))
	}

	return helpStyle.Render(strings.Join(parts, " | "))
}
