// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

// The signing review drawn from a sign request's review: a list of the
// request's transactions, and under it the selected one in full. A request
// without a review, and any request once the operator asks for the text, is
// shown as its description instead (view_signing.go).

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
	// top is the first list row shown.
	top int
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

// reviewLayout is the width of the review and the heights of its list and
// its detail pane.
func (m Model) reviewLayout(review *protocol.Review) (width, listHeight, detailHeight int) {
	width = m.popupBodyWidth(78)
	inner := m.popupContentHeight()
	if inner <= 0 {
		inner = 30
	}
	// Title, the scroll hint and the buttons are always there.
	fixed := 3
	if m.reviewValidityLine() != "" {
		fixed++
	}
	if m.reviewRiskLine(review) != "" {
		fixed++
	}
	rest := inner - fixed
	if rows := reviewRows(review); rows > 0 {
		// One more line rules the list off from the detail pane.
		listHeight = min(rows, max(3, rest/3))
		rest -= listHeight + 1
	}
	return width, listHeight, max(3, rest)
}

// refreshReview sizes the detail pane and fills it for the selected row.
func (m *Model) refreshReview() {
	review := m.reviewOf()
	if review == nil {
		return
	}
	rows := reviewRows(review)
	m.signing.review.row = max(0, min(max(0, rows-1), m.signing.review.row))
	width, listHeight, detailHeight := m.reviewLayout(review)
	if m.signing.review.row < m.signing.review.top {
		m.signing.review.top = m.signing.review.row
	}
	if listHeight > 0 && m.signing.review.row >= m.signing.review.top+listHeight {
		m.signing.review.top = m.signing.review.row - listHeight + 1
	}
	m.signing.review.top = max(0, min(max(0, rows-listHeight), m.signing.review.top))

	var out []string
	for _, line := range m.reviewDetail(review) {
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
		if m.signing.review.text {
			m.initSigningViewport(m.buildSigningViewportContent())
		} else {
			m.refreshReview()
		}
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

// reviewList draws the visible rows of a group's list.
func (m Model) reviewList(review *protocol.Review, width, height int) []string {
	var lines []string
	for row := m.signing.review.top; row < m.signing.review.top+height && row < reviewRows(review); row++ {
		text, style := "    Overview: warnings, accounts and what the signer changed", normalStyle
		if row > 0 {
			item := review.Items[row-1]
			mark := " "
			if severity := reviewItemSeverity(item); severity != "" {
				mark, style = "⚠", reviewWarningStyle(severity)
			} else if item.Position != protocol.ReviewPositionSign {
				style = helpStyle
			}
			text = fmt.Sprintf("%2d %s %-15s  %s", row, mark, reviewPositionWords(item.Position), firstLine(item.Title))
		}
		text = fixedWidthFieldLine(text, width-2)
		if row == m.signing.review.row {
			lines = append(lines, selectedStyle.Render("> "+text))
		} else {
			lines = append(lines, style.Render("  "+text))
		}
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
	width, listHeight, _ := m.reviewLayout(review)
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
	if listHeight > 0 {
		lines = append(lines, m.reviewList(review, width, listHeight)...)
		rule := strings.Repeat("─", width)
		if below := reviewRows(review) - m.signing.review.top - listHeight; below > 0 {
			rule = fixedWidthFieldLine(fmt.Sprintf("── %d more below ", below)+rule, width)
		}
		lines = append(lines, helpStyle.Render(rule))
	}
	lines = append(lines, strings.Split(m.signing.viewport.View(), "\n")...)

	hint := ""
	if more := m.signing.viewport.TotalLineCount() - m.signing.viewport.Height; more > 0 {
		hint = fmt.Sprintf("pgup/pgdown: scroll (%.0f%% of %d lines)", m.signing.viewport.ScrollPercent()*100, m.signing.viewport.TotalLineCount())
	}
	lines = append(lines, helpStyle.Render(hint))

	approve, reject := "  APPROVE  ", "  REJECT  "
	if m.signing.focus == 0 {
		approve, reject = selectedStyle.Render("> APPROVE  "), helpStyle.Render(reject)
	} else {
		approve, reject = helpStyle.Render(approve), selectedStyle.Render("> REJECT  ")
	}
	lines = append(lines, approve+"  "+reject)

	return m.renderPopup(78, strings.Join(lines, "\n"))
}
