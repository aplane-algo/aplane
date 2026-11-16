// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

// The signing review drawn from a sign request's review: a list of the
// request's transactions, and under it the selected one in full. When the
// operator asks for the text, the lower pane holds the request's description
// instead. A request without a review is shown as its description alone
// (view_signing.go).

import (
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/aplane-algo/aplane/internal/protocol"
)

// reviewState is what the operator has selected in a drawn review.
type reviewState struct {
	// text shows the request's description in place of the drawn review.
	text bool
	// row is the selected row of a group's list: 0 is the overview, and i is
	// the group's transaction i.
	row int
	// top is the first line of the upper pane's rows that is shown.
	top int
	// picture is how the upper pane draws a group; left alone, the shape of
	// the request decides.
	picture reviewPicture
}

// reviewLine is one line of the detail pane before it is wrapped.
type reviewLine struct {
	text  string
	style lipgloss.Style
	// fixed is a line already rendered, which is never wrapped.
	fixed string
}

// reviewOf is the request's review when the screen draws it.
func (m Model) reviewOf() *protocol.Review {
	request := m.signing.request
	if request == nil || request.Review == nil || len(request.Review.Items) == 0 || m.signing.review.text {
		return nil
	}
	return request.Review
}

// reviewAvailable reports whether the request can be drawn at all.
func (m Model) reviewAvailable() bool {
	request := m.signing.request
	return request != nil && request.Review != nil && len(request.Review.Items) > 0
}

// reviewRows is the number of rows in a group's list: the overview and each
// transaction. A lone transaction has no list.
func reviewRows(review *protocol.Review) int {
	if !review.Group {
		return 0
	}
	return len(review.Items) + 1
}

// reviewWidth is the width the review is drawn in: the whole window, with no
// popup frame, so the lanes and the fields have every column there is.
func (m Model) reviewWidth() int {
	if m.width <= 0 {
		return 78
	}
	return m.width
}

// reviewLayout is the width of the review and the heights of its upper pane
// and its detail pane. The review fills the window between the admin header
// and the status bar; it draws its own keys line, so the window has no
// footer under it.
func (m Model) reviewLayout(review *protocol.Review) (width, paneHeight, detailHeight int) {
	width = m.reviewWidth()
	inner := m.windowBodyHeight()
	if inner <= 0 {
		inner = 30
	}
	// Title, the scroll hint and the keys line are always there.
	fixed := 3
	if m.reviewValidityLine() != "" {
		fixed++
	}
	if m.reviewRiskLine(review) != "" {
		fixed++
	}
	rest := inner - fixed
	if pane, ok := m.reviewUpperPane(review, width); ok {
		// A list leaves most of the room to the detail pane; a picture
		// takes what it needs and leaves the detail pane a few lines. One
		// more line rules the two panes apart.
		limit := max(3, rest/3)
		if len(pane.header) > 0 {
			limit = max(len(pane.header)+3, rest-5)
		}
		paneHeight = min(len(pane.header)+len(pane.lines), limit)
		rest -= paneHeight + 1
	}
	return width, paneHeight, max(3, rest)
}

// refreshReview sizes the detail pane and fills it for the selected row, and
// scrolls the upper pane to keep that row in view.
func (m *Model) refreshReview() {
	if !m.reviewAvailable() {
		return
	}
	review := m.signing.request.Review
	rows := reviewRows(review)
	m.signing.review.row = max(0, min(max(0, rows-1), m.signing.review.row))
	width, paneHeight, detailHeight := m.reviewLayout(review)
	if pane, ok := m.reviewUpperPane(review, width); ok && review.Group {
		visible := max(1, paneHeight-len(pane.header))
		first, last := -1, 0
		for i, line := range pane.lines {
			if line.row == m.signing.review.row {
				if first < 0 {
					first = i
				}
				last = i
			}
		}
		top := m.signing.review.top
		if last >= top+visible {
			top = last - visible + 1
		}
		if first >= 0 && first < top {
			top = first
		}
		m.signing.review.top = max(0, min(max(0, len(pane.lines)-visible), top))
	}

	detail := m.reviewDetail(review)
	if m.signing.review.text {
		// The request's description, as apapprover prints it, then its
		// warnings.
		detail = nil
		for _, line := range strings.Split(m.buildSigningViewportContent(), "\n") {
			detail = append(detail, reviewLine{text: line, style: normalStyle})
		}
	}
	var out []string
	for _, line := range detail {
		if line.fixed != "" {
			out = append(out, line.fixed)
			continue
		}
		for _, part := range strings.Split(wrapText(line.text, width), "\n") {
			out = append(out, line.style.Render(part))
		}
	}
	m.signing.viewport = viewport.New(width, detailHeight)
	m.signing.viewport.SetContent(strings.Join(out, "\n"))
}

// handleReviewKeys handles the keys a drawn review adds to the approval
// keys. It reports whether it handled the key.
func (m Model) handleReviewKeys(msg tea.KeyMsg) (Model, bool) {
	if !m.reviewAvailable() {
		return m, false
	}
	if msg.String() == "t" {
		m.signing.review.text = !m.signing.review.text
		m.refreshReview()
		return m, true
	}
	review := m.reviewOf()
	if review == nil || !review.Group {
		return m, false
	}
	switch msg.String() {
	case "up", "k":
		m.signing.review.row--
	case "down", "j":
		m.signing.review.row++
	case "v":
		m.signing.review.picture = m.nextPicture(review, m.reviewWidth())
		m.signing.review.top = 0
	default:
		return m, false
	}
	m.refreshReview()
	return m, true
}

func (m Model) reviewValidityLine() string {
	if m.signing.request == nil {
		return ""
	}
	return protocol.ValidityWindowLine(m.signing.request.FirstValid, m.signing.request.LastValid)
}

// reviewPositionWords says how the request treats a transaction.
func reviewPositionWords(position string) string {
	switch position {
	case protocol.ReviewPositionSign:
		return "signed here"
	case protocol.ReviewPositionPassthrough:
		return "already signed"
	default:
		return "not signed here"
	}
}

// reviewSummary says how the request is made up, in one line.
func reviewSummary(review *protocol.Review) string {
	if !review.Group {
		return "Single transaction"
	}
	counts := map[string]int{}
	var order []string
	for _, item := range review.Items {
		words := reviewPositionWords(item.Position)
		if counts[words] == 0 {
			order = append(order, words)
		}
		counts[words]++
	}
	parts := []string{fmt.Sprintf("Group of %d", len(review.Items))}
	for _, words := range order {
		parts = append(parts, fmt.Sprintf("%d %s", counts[words], words))
	}
	return strings.Join(parts, " · ")
}

// reviewHasCritical reports whether any warning of the request is critical.
func (m Model) reviewHasCritical() bool {
	for _, v := range m.signing.request.Violations {
		if v.Severity == "critical" {
			return true
		}
	}
	return false
}

// reviewRiskLine counts the request's warnings and names the effects among
// them that hand over control or funds. It is empty when there are none.
func (m Model) reviewRiskLine(review *protocol.Review) string {
	count := len(m.signing.request.Violations)
	if count == 0 {
		return ""
	}
	line := fmt.Sprintf("⚠ %d warning", count)
	if count > 1 {
		line += "s"
	}
	for i, item := range review.Items {
		for _, effect := range item.Effects {
			if effect.Severity != protocol.ReviewSeverityDanger {
				continue
			}
			name := strings.ToUpper(strings.ReplaceAll(effect.Kind, "_", " "))
			if review.Group {
				name += fmt.Sprintf(" in %d", i+1)
			}
			line += " · " + name
		}
	}
	return line
}

// reviewWarningStyle is the style of a warning of the given severity.
func reviewWarningStyle(severity string) lipgloss.Style {
	if severity == "critical" {
		return errorStyle
	}
	return warningStyle
}

// reviewItemSeverity is the gravest severity among a transaction's findings,
// or empty when it has none.
func reviewItemSeverity(item protocol.ReviewItem) string {
	severity := ""
	for _, finding := range item.Findings {
		if finding.Severity == "critical" {
			return "critical"
		}
		severity = finding.Severity
	}
	return severity
}

// reviewPaneLines draws the visible part of the upper pane: its header, then
// its rows from the first one shown, the selected row marked.
func (m Model) reviewPaneLines(pane reviewPane, width, height int) []string {
	lines := append([]string{}, pane.header...)
	clip := lipgloss.NewStyle().MaxWidth(width)
	for i := m.signing.review.top; i < len(pane.lines) && len(lines) < height; i++ {
		line := pane.lines[i]
		if line.row == m.signing.review.row {
			// The mark is on the row's first line; its other lines are lit.
			mark := "> "
			if i > 0 && pane.lines[i-1].row == line.row {
				mark = "  "
			}
			lines = append(lines, selectedStyle.Render(mark+fixedWidthFieldLine(line.plain, width-2)))
		} else {
			lines = append(lines, clip.Render("  "+line.styled))
		}
	}
	for i, line := range lines {
		lines[i] = clip.Render(line)
	}
	return lines
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// reviewDetail is the detail pane for the selected row: the overview or one
// transaction. A lone transaction has no rows: its pane holds the warnings
// about the request, the transaction, then the rest of the overview.
func (m Model) reviewDetail(review *protocol.Review) []reviewLine {
	join := func(sections ...[]reviewLine) []reviewLine {
		var lines []reviewLine
		for _, section := range sections {
			if len(section) == 0 {
				continue
			}
			if len(lines) > 0 {
				lines = append(lines, reviewLine{})
			}
			lines = append(lines, section...)
		}
		return lines
	}
	if !review.Group {
		return join(reviewWarnings(review.Findings), reviewTransaction(review, 0), reviewAccounts(review), reviewRequest(review))
	}
	if m.signing.review.row == 0 {
		lines := join(reviewWarnings(m.signing.request.Violations), reviewAccounts(review), reviewRequest(review))
		if len(lines) == 0 {
			lines = append(lines, reviewLine{text: "No warnings. The signer changed nothing.", style: helpStyle})
		}
		return lines
	}
	return reviewTransaction(review, m.signing.review.row-1)
}

// reviewWarning draws one warning: what it is about, then its message.
func reviewWarning(v protocol.PolicyViolation) []reviewLine {
	style := reviewWarningStyle(v.Severity)
	head := "⚠ WARNING: " + v.Field
	if v.Severity == "critical" {
		head = "⚠ CRITICAL: " + v.Field
	}
	lines := []reviewLine{{text: head, style: style}}
	for _, part := range strings.Split(v.Message, "\n") {
		lines = append(lines, reviewLine{text: "   " + strings.TrimLeft(part, " "), style: normalStyle})
	}
	return lines
}

func reviewSection(title string) reviewLine {
	return reviewLine{text: title, style: subtitleStyle.Bold(true)}
}

// reviewWarnings lists warnings in full.
func reviewWarnings(warnings []protocol.PolicyViolation) []reviewLine {
	if len(warnings) == 0 {
		return nil
	}
	lines := []reviewLine{reviewSection("Warnings")}
	for _, v := range warnings {
		lines = append(lines, reviewWarning(v)...)
	}
	return lines
}

// reviewAccounts lists the accounts the request touches, each address in
// full, and says which of them are the signer's own.
func reviewAccounts(review *protocol.Review) []reviewLine {
	if len(review.Parties) == 0 {
		return nil
	}
	lines := []reviewLine{reviewSection("Accounts")}
	for _, party := range review.Parties {
		style := normalStyle
		if party.Signs || party.Held {
			style = statusConnectedStyle
		}
		lines = append(lines, reviewLine{fixed: "  " + addressChip(party.Address) + " " + style.Render(party.Address)})
		switch {
		case party.Signs && party.KeyType != "":
			lines = append(lines, reviewLine{text: "       this request signs for it, with a " + party.KeyType + " key", style: helpStyle})
		case party.Signs:
			lines = append(lines, reviewLine{text: "       this request signs for it", style: helpStyle})
		case party.Held:
			lines = append(lines, reviewLine{text: "       this signer holds its key; this request does not sign for it", style: helpStyle})
		}
	}
	return lines
}

// reviewRequest says how the request is made up and what planning did to it.
func reviewRequest(review *protocol.Review) []reviewLine {
	if len(review.Banners) == 0 && review.Changes.Heading == "" && len(review.Changes.Lines) == 0 {
		return nil
	}
	lines := []reviewLine{reviewSection("Request")}
	for _, banner := range review.Banners {
		lines = append(lines, reviewLine{text: banner, style: normalStyle})
	}
	if review.Changes.Heading != "" {
		lines = append(lines, reviewLine{text: review.Changes.Heading, style: warningStyle})
	}
	for _, line := range review.Changes.Lines {
		lines = append(lines, reviewLine{text: "  • " + line, style: normalStyle})
	}
	return lines
}

// reviewFieldLine prints a field as the description prints it.
func reviewFieldLine(f protocol.ReviewField) string {
	line := strings.Repeat("  ", 1+f.Depth)
	if f.Alert {
		line += "⚠ "
	}
	if f.Label != "" {
		line += f.Label + ": "
	}
	return line + f.Value
}

// reviewTransaction is one transaction in full: how the request treats it,
// its warnings, then every field.
func reviewTransaction(review *protocol.Review, index int) []reviewLine {
	item := review.Items[index]
	head := reviewPositionWords(item.Position)
	if review.Group {
		head = fmt.Sprintf("Transaction %d of %d · %s", index+1, len(review.Items), head)
	} else {
		head = "Transaction · " + head
	}
	lines := []reviewLine{{text: head, style: subtitleStyle.Bold(true)}}
	if item.Label != "" {
		lines = append(lines, reviewLine{text: "  " + item.Label, style: helpStyle})
	}
	for _, note := range item.Notes {
		lines = append(lines, reviewLine{text: reviewFieldLine(note), style: helpStyle})
	}
	for _, finding := range item.Findings {
		lines = append(lines, reviewWarning(finding)...)
	}
	lines = append(lines, reviewLine{text: item.Title, style: normalStyle.Bold(true)})
	for _, claim := range item.Claims {
		lines = append(lines, reviewLine{text: claim, style: helpStyle})
	}
	for _, field := range item.Fields {
		style := normalStyle
		if field.Alert {
			style = errorStyle
		}
		lines = append(lines, reviewLine{text: reviewFieldLine(field), style: style})
	}
	return lines
}

// chipPalette holds colours that stay distinct from each other.
var chipPalette = []lipgloss.Color{"196", "208", "226", "40", "51", "33", "129", "201", "255", "137"}

// addressChip is a two-cell colour mark worked out from the whole address, so
// two addresses that share their ends still get different marks. It sits
// beside a full address and never stands in for one.
func addressChip(address string) string {
	sum := chipDigest(address)
	colour := func(i int) lipgloss.Color { return chipPalette[int(sum[i])%len(chipPalette)] }
	return lipgloss.NewStyle().Foreground(colour(0)).Background(colour(1)).Render("▌") +
		lipgloss.NewStyle().Foreground(colour(2)).Background(colour(3)).Render("▌")
}

func chipDigest(address string) [sha256.Size]byte { return sha256.Sum256([]byte(address)) }

// renderReviewScreen draws the signing request from its review.
func (m Model) renderReviewScreen(review *protocol.Review) string {
	width, paneHeight, _ := m.reviewLayout(review)
	var lines []string

	title := titleStyle.UnsetMargins().Render("Signing Request")
	lines = append(lines, title+"  "+fixedWidthFieldLine(reviewSummary(review), max(1, width-lipgloss.Width(title)-2)))
	if validity := m.reviewValidityLine(); validity != "" {
		lines = append(lines, helpStyle.Render(fixedWidthFieldLine(validity, width)))
	}
	if risk := m.reviewRiskLine(review); risk != "" {
		style := warningStyle
		if m.reviewHasCritical() {
			style = errorStyle
		}
		lines = append(lines, style.Render(fixedWidthFieldLine(risk, width)))
	}
	if pane, ok := m.reviewUpperPane(review, width); ok {
		lines = append(lines, m.reviewPaneLines(pane, width, paneHeight)...)
		rule := strings.Repeat("─", width)
		if m.signing.review.top+paneHeight-len(pane.header) < len(pane.lines) {
			label := "── more below "
			rule = label + strings.Repeat("─", max(0, width-lipgloss.Width(label)))
		}
		lines = append(lines, helpStyle.Render(rule))
	}
	lines = append(lines, strings.Split(m.signing.viewport.View(), "\n")...)

	hint := ""
	if more := m.signing.viewport.TotalLineCount() - m.signing.viewport.Height; more > 0 {
		hint = fmt.Sprintf("pgup/pgdown: scroll (%.0f%% of %d lines)", m.signing.viewport.ScrollPercent()*100, m.signing.viewport.TotalLineCount())
	}
	lines = append(lines, helpStyle.Render(hint))

	lines = append(lines, m.reviewKeysLine(width))

	clip := lipgloss.NewStyle().MaxWidth(width)
	for i, line := range lines {
		lines[i] = clip.Render(line)
	}
	return strings.Join(lines, "\n")
}

// reviewKeysLine is the review's last line: the two buttons, the focused one
// marked, then the keys the review adds to them.
func (m Model) reviewKeysLine(width int) string {
	approve, reject := "  APPROVE (y)", "  REJECT (n)"
	if m.signing.focus == 0 {
		approve, reject = selectedStyle.Render("> APPROVE (y)"), helpStyle.Render(reject)
	} else {
		approve, reject = helpStyle.Render(approve), selectedStyle.Render("> REJECT (n)")
	}
	buttons := approve + "  " + reject

	var keys string
	switch review := m.reviewOf(); {
	case review == nil:
		keys = "↑↓: Scroll | t: Review"
	case review.Group:
		keys = "↑↓: Select | PgUp/PgDn: Scroll | v: View | t: Text"
	default:
		keys = "↑↓: Scroll | t: Text"
	}
	room := width - lipgloss.Width(buttons) - 2
	if room <= 0 {
		return buttons
	}
	keys = strings.TrimRight(fixedWidthFieldLine(keys, min(room, lipgloss.Width(keys))), " ")
	gap := width - lipgloss.Width(buttons) - lipgloss.Width(keys)
	return buttons + strings.Repeat(" ", gap) + helpStyle.Render(keys)
}
