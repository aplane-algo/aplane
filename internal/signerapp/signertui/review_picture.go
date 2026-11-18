// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

// The upper pane of a group's review: its transactions as a list, as lanes
// (one column per account or app, an arrow for each movement between them),
// or as a table of movements. All three are drawn from the review's items and
// effects and select the same rows.

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/aplane-algo/aplane/internal/protocol"
)

// reviewPicture is how the upper pane draws a group.
type reviewPicture int

const (
	// pictureAuto picks by the shape of the request.
	pictureAuto reviewPicture = iota
	pictureList
	pictureLanes
	pictureTable
)

const (
	// reviewRowPrefix is the width of a row's number and warning mark.
	reviewRowPrefix = 5
	// An address in a picture shows as many characters of each end as its
	// column has room for: four at least, and at most ten, as the key list
	// shows.
	minAddressEnds = 4
	maxAddressEnds = 10
	minLaneWidth   = 2*minAddressEnds + 3
	// maxLaneWidth holds the longest short address and a space.
	maxLaneWidth  = 2*maxAddressEnds + 2
	maxEffectText = 26
	// maxTableText is the widest What the table keeps room for: the widest
	// effect the lanes show, and the words that mark a lookalike.
	maxTableText = maxEffectText + len(lookalikeWords)
)

// lookalikeWords mark a table row that moves from or to a lookalike.
const lookalikeWords = " (looks alike)"

// paneLine is one line of the upper pane: its spans, and the same text with
// no styles.
type paneLine struct {
	row   int
	plain string
	spans []paneSpan
}

// paneSpan is a run of a pane line drawn in one style.
type paneSpan struct {
	text  string
	style lipgloss.Style
}

// render draws the line in its own colours, over the selected-row tint when
// selected.
func (l paneLine) render(selected bool) string {
	var b strings.Builder
	for _, span := range l.spans {
		style := span.style
		if selected {
			style = style.Background(selectedRowBackground)
		}
		b.WriteString(style.Render(span.text))
	}
	return b.String()
}

// reviewPane is the upper pane: lines that stay in place, then one or more
// lines for each row.
type reviewPane struct {
	header []string
	lines  []paneLine
}

// shortAddress is an address cut to its ends to fit width: as many
// characters of each end as fit, from minAddressEnds to maxAddressEnds.
func shortAddress(address string, width int) string {
	ends := min(maxAddressEnds, max(minAddressEnds, (width-1)/2))
	if len(address) <= 2*ends+1 {
		return address
	}
	return address[:ends] + "…" + address[len(address)-ends:]
}

// reviewLane is one column of the lanes picture: an account or an app.
type reviewLane struct {
	address string // an account
	app     uint64 // a called app
	newApp  int    // 1 + the index of the transaction that creates the app
	own     bool   // this request signs for the account, or the signer can
	role    string
}

// name is the lane's name in a lane width wide, a space left between it and
// the next lane's.
func (l reviewLane) name(width int) string {
	switch {
	case l.newApp != 0:
		return "new app"
	case l.app != 0:
		return fmt.Sprintf("app %d", l.app)
	}
	return shortAddress(l.address, width-1)
}

// reviewLookalikes are the addresses the signer says look like another
// account in the request.
func reviewLookalikes(review *protocol.Review) map[string]bool {
	out := map[string]bool{}
	for _, party := range review.Parties {
		if party.Lookalike {
			out[party.Address] = true
		}
	}
	return out
}

// reviewLanes lists the lanes of a review: the accounts this request signs
// for or the signer can sign for first, then the other accounts, then the
// apps, each in order of first appearance.
func reviewLanes(review *protocol.Review) []reviewLane {
	lookalikes := reviewLookalikes(review)
	var own, other, apps []reviewLane
	for _, party := range review.Parties {
		lane := reviewLane{address: party.Address, own: party.Signs || party.Signable}
		switch {
		case lookalikes[party.Address]:
			lane.role = "lookalike"
		case party.Signs:
			lane.role = "signs"
		case party.Signable:
			lane.role = "signable"
		}
		if lane.own {
			own = append(own, lane)
		} else {
			other = append(other, lane)
		}
	}
	seen := map[uint64]bool{}
	for i, item := range review.Items {
		for _, effect := range item.Effects {
			switch {
			case effect.NewApp:
				apps = append(apps, reviewLane{newApp: i + 1, role: "app"})
			case effect.App != 0 && !seen[effect.App]:
				seen[effect.App] = true
				apps = append(apps, reviewLane{app: effect.App, role: "app"})
			}
		}
	}
	return append(append(own, other...), apps...)
}

// effectTarget is the lane an effect points at, or -1 when it stays on the
// lane it starts from.
func effectTarget(lanes []reviewLane, item int, effect protocol.ReviewEffect) int {
	for i, lane := range lanes {
		switch {
		case effect.NewApp && lane.newApp == item+1,
			!effect.NewApp && effect.App != 0 && lane.app == effect.App,
			effect.App == 0 && !effect.NewApp && effect.To != "" && effect.To != effect.From && lane.address == effect.To && lane.newApp == 0 && lane.app == 0:
			return i
		}
	}
	return -1
}

func laneOf(lanes []reviewLane, address string) int {
	for i, lane := range lanes {
		if lane.address == address && address != "" {
			return i
		}
	}
	return -1
}

// reviewEffectWidth is the width of the widest effect text, up to a limit.
func reviewEffectWidth(review *protocol.Review) int {
	width := 0
	for _, item := range review.Items {
		for _, effect := range item.Effects {
			width = max(width, lipgloss.Width(effect.Text))
		}
	}
	return min(width, maxEffectText)
}

// lanesShown is how many lanes fit the width, and how wide each is.
func lanesShown(review *protocol.Review, lanes []reviewLane, width int) (shown, laneWidth int) {
	available := width - 2 - reviewRowPrefix - 2 - reviewEffectWidth(review)
	shown = min(len(lanes), available/minLaneWidth)
	if shown < 1 {
		return 0, 0
	}
	return shown, min(maxLaneWidth, available/shown)
}

// pictureFor is how the upper pane draws the review: what the operator chose,
// or, left to itself, a table for one account paying several others, lanes
// when every lane fits, a table when they do not, and a plain list when
// nothing moves between two parties.
func (m Model) pictureFor(review *protocol.Review, width int) reviewPicture {
	if m.signing.review.picture != pictureAuto {
		return m.signing.review.picture
	}
	lanes := reviewLanes(review)
	arrows, transfersOnly := 0, true
	senders, receivers := map[string]bool{}, map[string]bool{}
	for i, item := range review.Items {
		for _, effect := range item.Effects {
			if effectTarget(lanes, i, effect) < 0 {
				continue
			}
			arrows++
			senders[effect.From] = true
			receivers[effect.To] = true
			if effect.Kind != "transfer" {
				transfersOnly = false
			}
		}
	}
	switch shown, _ := lanesShown(review, lanes, width); {
	case arrows == 0:
		return pictureList
	case transfersOnly && len(senders) == 1 && len(receivers) >= 3:
		return pictureTable
	case shown == len(lanes):
		return pictureLanes
	}
	return pictureTable
}

// nextPicture is the picture after the one showing.
func (m Model) nextPicture(review *protocol.Review, width int) reviewPicture {
	switch m.pictureFor(review, width) {
	case pictureList:
		return pictureLanes
	case pictureLanes:
		return pictureTable
	}
	return pictureList
}

// reviewEffectStyle is the style an effect is drawn in.
func reviewEffectStyle(effect protocol.ReviewEffect) lipgloss.Style {
	switch effect.Severity {
	case protocol.ReviewSeverityDanger:
		return errorStyle
	case protocol.ReviewSeverityCaution:
		return warningStyle
	}
	if effect.Kind == "app_call" {
		return subtitleStyle
	}
	return normalStyle
}

// reviewRowLead is a row's number and warning mark.
func reviewRowLead(row int, item protocol.ReviewItem, first bool) string {
	if !first {
		return strings.Repeat(" ", reviewRowPrefix)
	}
	mark := " "
	if reviewItemSeverity(item) != "" {
		mark = "⚠"
	}
	return fmt.Sprintf("%2d %s ", row, mark)
}

// reviewUpperPane is the pane above the detail pane: a group's rows, or a
// lone transaction's picture. It reports false when there is none: the text
// is showing, or a lone transaction touches one account alone.
func (m Model) reviewUpperPane(review *protocol.Review, width int) (reviewPane, bool) {
	switch {
	case m.signing.review.text:
		return reviewPane{}, false
	case review.Group:
		return m.reviewPaneFor(review, width), true
	}
	return singlePicture(review, width)
}

// reviewPaneFor draws the whole upper pane of a group, every row of it.
func (m Model) reviewPaneFor(review *protocol.Review, width int) reviewPane {
	switch m.pictureFor(review, width) {
	case pictureLanes:
		return lanesPane(review, width)
	case pictureTable:
		return tablePane(review, width)
	}
	return listPane(review)
}

// listPane is one line for each transaction: how the request treats it, and
// its title.
func listPane(review *protocol.Review) reviewPane {
	var pane reviewPane
	for i, item := range review.Items {
		style := normalStyle
		if severity := reviewItemSeverity(item); severity != "" {
			style = reviewWarningStyle(severity)
		} else if item.Position != protocol.ReviewPositionSign {
			style = helpStyle
		}
		text := fmt.Sprintf("%s%-15s  %s", reviewRowLead(i+1, item, true), reviewPositionWords(item.Position), firstLine(item.Title))
		pane.lines = append(pane.lines, paneLine{row: i, plain: text, spans: []paneSpan{{text, style}}})
	}
	return pane
}

// centre puts text in the middle of a lane.
func centre(text string, width int) string {
	text = fixedWidthFieldLine(text, min(lipgloss.Width(text), width-1))
	left := max(0, (width-lipgloss.Width(text))/2)
	return strings.Repeat(" ", left) + text + strings.Repeat(" ", max(0, width-left-lipgloss.Width(text)))
}

// laneStroke is the line an effect's arrow is drawn with.
func laneStroke(kind string) rune {
	switch kind {
	case "close":
		return '═'
	case "rekey":
		return '╌'
	case "freeze":
		return '┈'
	}
	return '─'
}

// laneMark is the mark of an effect that stays on its own lane.
func laneMark(kind string) rune {
	switch kind {
	case "opt_in":
		return '◎'
	case "keyreg":
		return '◆'
	case "asset_create":
		return '+'
	case "asset_destroy":
		return '×'
	case "asset_config":
		return '◇'
	}
	return '↺'
}

// lanesPane draws each account and app as a column and each effect as an
// arrow between two of them, or a mark on one. A filled dot starts an arrow
// from a transaction this request signs, a hollow one from any other. When
// not every lane fits, the arrows that leave the lanes shown end in "»".
func lanesPane(review *protocol.Review, width int) reviewPane {
	return drawLanes(review, width, true)
}

// singlePicture is the lanes of a lone transaction that moves something
// between two parties: the same columns and arrows, with no rows to select.
// A transaction that touches one account alone has no picture.
func singlePicture(review *protocol.Review, width int) (reviewPane, bool) {
	if review.Group || len(review.Items) != 1 {
		return reviewPane{}, false
	}
	lanes := reviewLanes(review)
	arrows := false
	for _, effect := range review.Items[0].Effects {
		arrows = arrows || effectTarget(lanes, 0, effect) >= 0
	}
	if shown, _ := lanesShown(review, lanes, width); !arrows || shown == 0 {
		return reviewPane{}, false
	}
	return drawLanes(review, width, false), true
}

// drawLanes draws the lanes. rows is set for a group, whose lines are
// numbered rows to select; a lone transaction's lines are neither numbered
// nor selectable.
func drawLanes(review *protocol.Review, width int, rows bool) reviewPane { //nolint:gocognit // complexity backlog
	lanes := reviewLanes(review)
	shown, laneWidth := lanesShown(review, lanes, width)
	if shown == 0 {
		return listPane(review)
	}
	effectWidth := reviewEffectWidth(review)
	lead := strings.Repeat(" ", 2+reviewRowPrefix)

	var names, roles strings.Builder
	names.WriteString(lead)
	roles.WriteString(lead)
	for _, lane := range lanes[:shown] {
		nameStyle, roleStyle := normalStyle.Bold(true), helpStyle
		switch {
		case lane.role == "lookalike":
			roleStyle = errorStyle
		case lane.own:
			nameStyle, roleStyle = statusConnectedStyle.Bold(true), statusConnectedStyle
		case lane.role == "app":
			nameStyle = subtitleStyle.Bold(true)
		}
		names.WriteString(nameStyle.Render(centre(lane.name(laneWidth), laneWidth)))
		roles.WriteString(roleStyle.Render(centre(lane.role, laneWidth)))
	}
	if hidden := len(lanes) - shown; hidden > 0 {
		names.WriteString(helpStyle.Render(fmt.Sprintf(" +%d", hidden)))
	}
	pane := reviewPane{header: []string{names.String(), roles.String()}}

	centreOf := func(lane int) int { return lane*laneWidth + laneWidth/2 }
	edge := shown*laneWidth - 1
	for i, item := range review.Items {
		effects := item.Effects
		if len(effects) == 0 {
			effects = []protocol.ReviewEffect{{Text: firstLine(item.Title)}}
		}
		for j, effect := range effects {
			cells := []rune(strings.Repeat(" ", shown*laneWidth))
			drawn := make([]bool, len(cells))
			for lane := 0; lane < shown; lane++ {
				cells[centreOf(lane)] = '│'
			}
			put := func(x int, r rune) {
				if x >= 0 && x < len(cells) {
					cells[x], drawn[x] = r, true
				}
			}
			column := func(lane int) (int, bool) {
				if lane >= shown {
					return edge, true
				}
				return centreOf(lane), false
			}
			leaves := false
			from, to := laneOf(lanes, effect.From), effectTarget(lanes, i, effect)
			switch {
			case from < 0:
				// A transaction with nothing to draw: its title stands alone.
			case to < 0:
				x, off := column(from)
				leaves = off
				if !off {
					put(x, laneMark(effect.Kind))
				}
			default:
				a, offA := column(from)
				b, offB := column(to)
				leaves = offA || offB
				origin := '○'
				if item.Position == protocol.ReviewPositionSign && effect.From == item.Sender {
					origin = '●'
				}
				step, head := 1, '►'
				if b < a {
					step, head = -1, '◄'
				}
				for x := a; x != b; x += step {
					put(x, laneStroke(effect.Kind))
				}
				if !offA {
					put(a, origin)
				}
				if !offB {
					put(b, head)
				}
				if authority := laneOf(lanes, effect.Authority); authority >= 0 && authority < shown {
					if x := centreOf(authority); x != a && x != b {
						put(x, '◆')
					}
				}
			}

			gap := " "
			if leaves {
				gap = "»"
			}
			text := fixedWidthFieldLine(effect.Text, effectWidth)
			number := reviewRowLead(i+1, item, j == 0)
			if !rows {
				number = strings.Repeat(" ", reviewRowPrefix)
			}
			style := reviewEffectStyle(effect)

			numberStyle := normalStyle
			if severity := reviewItemSeverity(item); severity != "" {
				numberStyle = reviewWarningStyle(severity)
			}
			spans := []paneSpan{{number, numberStyle}}
			for x := 0; x < len(cells); {
				y := x
				for y < len(cells) && drawn[y] == drawn[x] {
					y++
				}
				if drawn[x] {
					spans = append(spans, paneSpan{string(cells[x:y]), style})
				} else {
					spans = append(spans, paneSpan{string(cells[x:y]), helpStyle})
				}
				x = y
			}
			spans = append(spans, paneSpan{gap + " " + text, style})
			row := i
			if !rows {
				row = -1
			}
			pane.lines = append(pane.lines, paneLine{row: row, plain: number + string(cells) + gap + " " + text, spans: spans})
		}
	}
	return pane
}

// tableRow is one line of the table: an effect of a row, and what the
// What column says of it.
type tableRow struct {
	item, effect int
	movement     protocol.ReviewEffect
	text         string
}

// tableRows are the table's lines, one for each effect, or for a transaction
// with none, its title.
func tableRows(review *protocol.Review) []tableRow {
	lookalikes := reviewLookalikes(review)
	var rows []tableRow
	for i, item := range review.Items {
		effects := item.Effects
		if len(effects) == 0 {
			effects = []protocol.ReviewEffect{{From: item.Sender, Text: firstLine(item.Title)}}
		}
		for j, effect := range effects {
			text := effect.Text
			if lookalikes[effect.To] || lookalikes[effect.From] {
				text += lookalikeWords
			}
			rows = append(rows, tableRow{item: i, effect: j, movement: effect, text: text})
		}
	}
	return rows
}

// tableNameWidth is the width of the From and To columns: what is left of the
// width once the widest What fits, between a short address of four characters
// at each end and one of ten.
func tableNameWidth(rows []tableRow, width int) int {
	text := 0
	for _, row := range rows {
		text = max(text, lipgloss.Width(row.text))
	}
	room := (width - 2 - reviewRowPrefix - 3 - 2 - min(text, maxTableText)) / 2
	return min(2*maxAddressEnds+1, max(2*minAddressEnds+1, room))
}

// tablePane is one line for each effect: who it moves from, who to, and what.
// It suits one account paying many, which lanes would draw as a fan of
// arrows.
func tablePane(review *protocol.Review, width int) reviewPane {
	own := map[string]bool{}
	for _, party := range review.Parties {
		own[party.Address] = party.Signs || party.Signable
	}
	rows := tableRows(review)
	nameWidth := tableNameWidth(rows, width)
	head := strings.Repeat(" ", 2+reviewRowPrefix) + fixedWidthFieldLine("From", nameWidth) + "   " + fixedWidthFieldLine("To", nameWidth) + "  What"
	pane := reviewPane{header: []string{helpStyle.Render(head)}}

	name := func(address string) (string, lipgloss.Style) {
		style := normalStyle
		if own[address] {
			style = statusConnectedStyle
		}
		return fixedWidthFieldLine(shortAddress(address, nameWidth), nameWidth), style
	}
	for _, row := range rows {
		item, effect := review.Items[row.item], row.movement
		number := reviewRowLead(row.item+1, item, row.effect == 0)
		from, fromStyle := name(effect.From)
		arrow, to, toStyle := "   ", strings.Repeat(" ", nameWidth), normalStyle
		switch {
		case effect.NewApp:
			arrow, to, toStyle = " → ", fixedWidthFieldLine("new app", nameWidth), subtitleStyle
		case effect.App != 0:
			arrow, to, toStyle = " → ", fixedWidthFieldLine(fmt.Sprintf("app %d", effect.App), nameWidth), subtitleStyle
		case effect.To != "" && effect.To != effect.From:
			arrow = " → "
			to, toStyle = name(effect.To)
		}
		style := reviewEffectStyle(effect)
		leadStyle := normalStyle
		if severity := reviewItemSeverity(item); severity != "" {
			leadStyle = reviewWarningStyle(severity)
		}
		pane.lines = append(pane.lines, paneLine{
			row:   row.item,
			plain: number + from + arrow + to + "  " + row.text,
			spans: []paneSpan{{number, leadStyle}, {from, fromStyle}, {arrow, style}, {to, toStyle}, {"  ", normalStyle}, {row.text, style}},
		})
	}
	return pane
}
