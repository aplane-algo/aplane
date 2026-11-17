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

	"github.com/aplane-algo/aplane/internal/asaset"
	"github.com/aplane-algo/aplane/internal/protocol"
)

// reviewState is what the operator has selected in a drawn review.
type reviewState struct {
	// text shows the request's description in place of the drawn review.
	text bool
	// row is the selected transaction of a group's list, from 0.
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

// reviewRows is the number of rows in a group's list, one per transaction. A
// lone transaction has no list.
func reviewRows(review *protocol.Review) int {
	if !review.Group {
		return 0
	}
	return len(review.Items)
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
	// The header lines, the rule over the detail pane and the keys line are
	// always there.
	rest := inner - len(m.reviewHeader(review, width)) - 2
	if pane, ok := m.reviewUpperPane(review, width); ok {
		// A list leaves most of the room to the detail pane; a picture
		// takes what it needs and leaves the detail pane a few lines.
		limit := max(3, rest/3)
		if len(pane.header) > 0 {
			limit = max(len(pane.header)+3, rest-5)
		}
		paneHeight = min(len(pane.header)+len(pane.lines), limit)
		rest -= paneHeight
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

// reviewValidity is the request's validity window: the line apapprover
// prints, and the short form that shares a line, which leaves out the
// window's length but never that a window is empty.
func (m Model) reviewValidity() (full, short string) {
	if m.signing.request == nil {
		return "", ""
	}
	first, last := m.signing.request.FirstValid, m.signing.request.LastValid
	full = protocol.ValidityWindowLine(first, last)
	short = full
	if full != "" && last >= first {
		short = fmt.Sprintf("Valid Rounds: %d - %d", first, last)
	}
	return full, short
}

// reviewHeader is the lines above the upper pane: a blank line under the
// admin header, then the title lines.
func (m Model) reviewHeader(review *protocol.Review, width int) []string {
	return append([]string{""}, m.reviewTitleLines(review, width)...)
}

// reviewTitleLines are the title and summary, and the risk line when there
// are warnings. The validity window goes at the right of the first of them
// with room for it, or on a line of its own.
func (m Model) reviewTitleLines(review *protocol.Review, width int) []string {
	title := titleStyle.UnsetMargins().Render("Signing Request")
	summary := reviewSummary(review)
	if room := width - lipgloss.Width(title) - 2; lipgloss.Width(summary) > room {
		summary = fixedWidthFieldLine(summary, max(0, room))
	}
	lines := []string{title + "  " + summary}
	if risk := m.reviewRiskLine(review); risk != "" {
		style := warningStyle
		if m.reviewHasCritical() {
			style = errorStyle
		}
		lines = append(lines, style.Render(fixedWidthFieldLine(risk, min(width, lipgloss.Width(risk)))))
	}
	full, short := m.reviewValidity()
	if full == "" {
		return lines
	}
	for i, line := range lines {
		if gap := width - lipgloss.Width(line) - lipgloss.Width(short); gap >= 2 {
			lines[i] = line + strings.Repeat(" ", gap) + helpStyle.Render(short)
			return lines
		}
	}
	return append(lines[:1], append([]string{helpStyle.Render(fixedWidthFieldLine(full, width))}, lines[1:]...)...)
}

// reviewRule parts the detail pane from what is above it. It counts the rows
// of the upper pane hidden below it, and says which lines of the detail pane
// show when they do not all fit.
func (m Model) reviewRule(width, hiddenRows int) string {
	left := "──"
	if hiddenRows > 0 {
		left = fmt.Sprintf("── ▼ %d more below ", hiddenRows)
	}
	right := "──"
	viewport := m.signing.viewport
	if total := viewport.TotalLineCount(); total > viewport.Height {
		last := min(total, viewport.YOffset+viewport.Height)
		right = fmt.Sprintf(" details: lines %d-%d of %d ──", viewport.YOffset+1, last, total)
	}
	fill := max(0, width-lipgloss.Width(left)-lipgloss.Width(right))
	return helpStyle.Render(left + strings.Repeat("─", fill) + right)
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
		if v.Severity == protocol.ViolationSeverityCritical {
			return true
		}
	}
	return false
}

// reviewRiskLine counts the request's warnings and names the effects among
// them that hand over control or funds. It is empty when there are none;
// notices are not warnings here.
func (m Model) reviewRiskLine(review *protocol.Review) string {
	count := 0
	for _, v := range m.signing.request.Violations {
		if v.Severity != protocol.ViolationSeverityNotice {
			count++
		}
	}
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
	if severity == protocol.ViolationSeverityCritical {
		return errorStyle
	}
	return warningStyle
}

// reviewItemSeverity is the gravest severity among a transaction's findings,
// or empty when it has none but notices.
func reviewItemSeverity(item protocol.ReviewItem) string {
	severity := ""
	for _, finding := range item.Findings {
		switch finding.Severity {
		case protocol.ViolationSeverityCritical:
			return finding.Severity
		case protocol.ViolationSeverityNotice:
		default:
			severity = finding.Severity
		}
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
			// The mark is on the row's first line; all its lines are tinted
			// across the width, each in its own colours.
			mark := "> "
			if i > 0 && pane.lines[i-1].row == line.row {
				mark = "  "
			}
			tint := lipgloss.NewStyle().Background(selectedRowBackground)
			pad := strings.Repeat(" ", max(0, width-2-lipgloss.Width(line.plain)))
			lines = append(lines, tint.Bold(true).Render(mark)+line.render(true)+tint.Render(pad))
		} else {
			lines = append(lines, clip.Render("  "+line.render(false)))
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

// reviewDetail is the detail pane: the selected transaction (a lone
// transaction's only one) in full, then what is about the request as a whole:
// its warnings and notes, each account's whole address, and what the signer
// changed.
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
	row := 0
	if review.Group {
		row = m.signing.review.row
	}
	return join(reviewTransaction(review, row), reviewWarnings(review.Findings), reviewNotes(review.Findings), reviewAccounts(review), reviewRequest(review))
}

// reviewWarning draws one warning: what it is about and the first line of
// its message on one line, then the rest of the message. A notice is drawn
// as a note, in the ordinary colour and with no warning sign.
func reviewWarning(v protocol.PolicyViolation) []reviewLine {
	style := reviewWarningStyle(v.Severity)
	head := "⚠ WARNING: " + v.Field
	switch v.Severity {
	case protocol.ViolationSeverityCritical:
		head = "⚠ CRITICAL: " + v.Field
	case protocol.ViolationSeverityNotice:
		head, style = "Note: "+v.Field, normalStyle
	}
	parts := strings.Split(v.Message, "\n")
	if first := strings.TrimSpace(parts[0]); first != "" {
		head += " · " + first
	}
	lines := []reviewLine{{text: head, style: style}}
	for _, part := range parts[1:] {
		lines = append(lines, reviewLine{text: "   " + strings.TrimLeft(part, " "), style: normalStyle})
	}
	return lines
}

func reviewSection(title string) reviewLine {
	return reviewLine{text: title, style: subtitleStyle.Bold(true)}
}

// reviewWarnings lists the warnings in full, and reviewNotes the notices,
// each under its own heading.
func reviewWarnings(violations []protocol.PolicyViolation) []reviewLine {
	return reviewViolations("Warnings", violations, false)
}

func reviewNotes(violations []protocol.PolicyViolation) []reviewLine {
	return reviewViolations("Notes", violations, true)
}

func reviewViolations(title string, violations []protocol.PolicyViolation, notices bool) []reviewLine {
	var lines []reviewLine
	for _, v := range violations {
		if (v.Severity == protocol.ViolationSeverityNotice) == notices {
			lines = append(lines, reviewWarning(v)...)
		}
	}
	if len(lines) == 0 {
		return nil
	}
	return append([]reviewLine{reviewSection(title)}, lines...)
}

// reviewAccounts lists the accounts the request touches, each address in
// full, and says which the signer can sign for. Once the signer has read them from its node, each says
// its balance too.
func reviewAccounts(review *protocol.Review) []reviewLine {
	if len(review.Parties) == 0 {
		return nil
	}
	chain := review.Chain
	read := chain != nil && chain.Unavailable == ""
	heading := "Accounts"
	if read {
		heading = fmt.Sprintf("Accounts · round %d", chain.Round)
	}
	lines := []reviewLine{reviewSection(heading)}
	if chain != nil && chain.Unavailable != "" {
		lines = append(lines, reviewLine{text: "  Balances unavailable: " + chain.Unavailable, style: helpStyle})
	}
	for _, party := range review.Parties {
		style := normalStyle
		if party.Signable {
			style = statusConnectedStyle
		}
		lines = append(lines, reviewLine{fixed: "  " + addressChip(party.Address) + " " + style.Render(party.Address)})
		if !read {
			lines = append(lines, reviewLine{text: "       " + partyStanding(party), style: helpStyle})
			continue
		}
		balance := "balance unavailable"
		if party.MicroAlgos != nil {
			balance = asaset.FormatFixed(*party.MicroAlgos, 6) + " ALGO"
		}
		lines = append(lines, reviewLine{text: "       " + balance + " · " + partyStanding(party), style: normalStyle})
	}
	return lines
}

// partyStanding says whether the signer can sign for the account.
func partyStanding(party protocol.ReviewParty) string {
	if party.Signable {
		return "signable"
	}
	return "not signable"
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
// every field, then its warnings. The fields come first because they say
// where value goes; the risk line and the row marks already say there are
// warnings. The signing key is left out when it is the sender, which From
// already shows, and kept when it is not: a rekeyed account's key.
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
		if note.Label == protocol.ReviewNoteSigningKey && note.Value == item.Sender {
			continue
		}
		lines = append(lines, reviewLine{text: reviewFieldLine(note), style: helpStyle})
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
	for _, finding := range item.Findings {
		lines = append(lines, reviewWarning(finding)...)
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
	lines := m.reviewHeader(review, width)
	hidden := 0
	if pane, ok := m.reviewUpperPane(review, width); ok {
		lines = append(lines, m.reviewPaneLines(pane, width, paneHeight)...)
		rows := map[int]bool{}
		for _, line := range pane.lines[min(len(pane.lines), m.signing.review.top+paneHeight-len(pane.header)):] {
			rows[line.row] = true
		}
		hidden = len(rows)
	}
	lines = append(lines, m.reviewRule(width, hidden))
	lines = append(lines, strings.Split(m.signing.viewport.View(), "\n")...)
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
