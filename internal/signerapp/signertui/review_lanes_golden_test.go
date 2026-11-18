// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"

	"github.com/aplane-algo/aplane/internal/protocol"
)

var updateLanesGolden = flag.Bool("update-lanes-golden", false, "rewrite testdata/review_lanes.golden")

// lanesReview is a review that reaches every way the lanes draw an effect.
func lanesReview() *protocol.Review {
	const (
		own      = reviewOwn
		signable = "SIGNABLE7777777777777777777777777777777777777777777777SIGN"
		other    = reviewOther
		alike    = reviewThird
		last     = "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
		stranger = "NOTAPARTYNOTAPARTYNOTAPARTYNOTAPARTYNOTAPARTYNOTAPARTYNOPE"
	)
	signed := func(title string, findings []protocol.PolicyViolation, effects ...protocol.ReviewEffect) protocol.ReviewItem {
		return protocol.ReviewItem{Position: protocol.ReviewPositionSign, Title: title, Sender: own, Effects: effects, Findings: findings}
	}
	critical := []protocol.PolicyViolation{{Field: "RekeyTo", Severity: protocol.ViolationSeverityCritical, Message: "rekey"}}
	warning := []protocol.PolicyViolation{{Field: "Amount", Severity: "warning", Message: "large"}}
	notice := []protocol.PolicyViolation{{Field: "Note", Severity: protocol.ViolationSeverityNotice, Message: "note"}}
	return &protocol.Review{
		Version: protocol.ReviewVersion, Group: true,
		Parties: []protocol.ReviewParty{
			{Address: other},
			{Address: own, Held: true, Signs: true, Signable: true},
			{Address: alike, Lookalike: true},
			{Address: signable, Signable: true},
			{Address: last},
		},
		Items: []protocol.ReviewItem{
			// Left to right, signed by its sender.
			signed("Payment", nil, protocol.ReviewEffect{Kind: "transfer", From: own, To: other, Text: "5000.000000 ALGO"}),
			// Right to left, from an account that is not the sender, with
			// the account that authorises it between the two.
			signed("Clawback", warning, protocol.ReviewEffect{Kind: "transfer", From: last, To: own, Authority: other, Text: "clawback 12 USDC", Severity: protocol.ReviewSeverityCaution}),
			// Two effects, the second a rekey; the authority is an end of the arrow.
			signed("Payment and rekey", critical,
				protocol.ReviewEffect{Kind: "transfer", From: own, To: alike, Authority: own, Text: "1.000000 ALGO"},
				protocol.ReviewEffect{Kind: "rekey", From: own, To: alike, Text: "REKEY: control moves", Severity: protocol.ReviewSeverityDanger}),
			signed("Close", notice, protocol.ReviewEffect{Kind: "close", From: own, To: last, Authority: stranger, Text: "CLOSE: all remaining ALGO to an account with a very long description"}),
			signed("Freeze", nil, protocol.ReviewEffect{Kind: "freeze", From: signable, To: other, Authority: last, Text: "freeze USDC"}),
			// Effects that stay on their own lane, one of each mark.
			signed("Opt in", nil, protocol.ReviewEffect{Kind: "opt_in", From: own, Text: "opt in to USDC"}),
			signed("Key registration", nil, protocol.ReviewEffect{Kind: "keyreg", From: signable, Text: "go online"}),
			signed("Asset create", nil, protocol.ReviewEffect{Kind: "asset_create", From: other, Text: "create asset"}),
			signed("Asset destroy", nil, protocol.ReviewEffect{Kind: "asset_destroy", From: alike, Text: "destroy asset"}),
			signed("Asset config", nil, protocol.ReviewEffect{Kind: "asset_config", From: last, Text: "configure asset"}),
			signed("Self payment", nil, protocol.ReviewEffect{Kind: "transfer", From: own, To: own, Text: "to itself"}),
			// Apps: a call, a second call of the same app, and a new app.
			{Position: protocol.ReviewPositionForeign, Title: "App call", Sender: other,
				Effects: []protocol.ReviewEffect{{Kind: "app_call", From: other, App: 1002, Text: "call"}}},
			signed("App call again", nil, protocol.ReviewEffect{Kind: "app_call", From: own, App: 1002, Text: "call"}),
			signed("App create", nil, protocol.ReviewEffect{Kind: "app_call", From: own, NewApp: true, Text: "create app"}),
			// Nothing to draw: no effects, and an effect from no party.
			{Position: protocol.ReviewPositionPassthrough, Title: "Dummy transaction\nsecond line", Sender: stranger},
			signed("From a stranger", nil, protocol.ReviewEffect{Kind: "transfer", From: stranger, To: own, Text: "from no party"}),
			signed("To a stranger", nil, protocol.ReviewEffect{Kind: "transfer", From: own, To: stranger, Text: "to no party"}),
		},
	}
}

// arrowsReview is seven accounts and every way an arrow can lie among them:
// rightward and leftward, with the account that authorises it nowhere, at
// either end, between the ends, outside them, or far to the right. At a
// narrow width the far lanes are the ones that do not fit.
func arrowsReview() *protocol.Review {
	lane := func(i int) string { return strings.Repeat(string(rune('A'+i)), 58) }
	review := &protocol.Review{Version: protocol.ReviewVersion, Group: true}
	for i := 0; i < 7; i++ {
		review.Parties = append(review.Parties, protocol.ReviewParty{Address: lane(i), Signs: i == 0})
	}
	for _, arrow := range []struct {
		text            string
		from, to, authz int // lanes; -1 for no authority
	}{
		{"R none", 0, 2, -1}, {"R between", 0, 3, 1}, {"R at head", 0, 2, 2}, {"R at origin", 1, 3, 1}, {"R outside", 1, 2, 4},
		{"L none", 3, 1, -1}, {"L at origin", 3, 1, 3}, {"L at head", 3, 1, 1}, {"L outside", 3, 1, 0}, {"L between", 4, 0, 2},
		{"to far, between", 0, 6, 3}, {"to far, none", 1, 6, -1},
		{"from far, none", 6, 0, -1}, {"from far, at head", 6, 1, 1}, {"from far, outside", 6, 2, 0}, {"from far, between", 6, 0, 1},
		{"far to far", 5, 6, -1}, {"far to far, near", 5, 6, 0}, {"far back, near", 6, 5, 1},
		{"far authority", 0, 1, 6},
	} {
		effect := protocol.ReviewEffect{Kind: "transfer", From: lane(arrow.from), To: lane(arrow.to), Text: arrow.text}
		if arrow.authz >= 0 {
			effect.Authority = lane(arrow.authz)
		}
		review.Items = append(review.Items, protocol.ReviewItem{Position: protocol.ReviewPositionSign, Title: arrow.text, Sender: lane(0), Effects: []protocol.ReviewEffect{effect}})
	}
	review.Items = append(review.Items, protocol.ReviewItem{Position: protocol.ReviewPositionSign, Title: "far mark", Sender: lane(6),
		Effects: []protocol.ReviewEffect{{Kind: "opt_in", From: lane(6), Text: "far mark"}}})
	return review
}

// dumpPane writes a pane as text: each header line as drawn, then each line's
// row, its plain text, and each span with the colours it is drawn in.
func dumpPane(pane reviewPane) string {
	var b strings.Builder
	for _, line := range pane.header {
		fmt.Fprintf(&b, "header %q\n", line)
	}
	for _, line := range pane.lines {
		fmt.Fprintf(&b, "row %d %q\n", line.row, line.plain)
		for _, span := range line.spans {
			fmt.Fprintf(&b, "  %q as %q\n", span.text, span.style.Render("x"))
		}
	}
	return b.String()
}

// arrowWidths are the narrowest width at which each number of the arrows
// review's lanes fits, and the width one narrower. A number below one gives
// that width itself.
func arrowWidths(lanes ...int) []int {
	room := 2 + reviewRowPrefix + 2 + reviewEffectWidth(arrowsReview())
	var widths []int
	for _, n := range lanes {
		if n < 1 {
			widths = append(widths, n)
			continue
		}
		widths = append(widths, room+n*minLaneWidth-1, room+n*minLaneWidth)
	}
	return widths
}

// The lanes of each review, at each width, are exactly the recorded ones:
// every character, and the colours of every part of every line.
func TestReviewLanesAreDrawnAsRecorded(t *testing.T) {
	// The colours only show under a colour profile, which is the whole
	// process's: no test in this package may run in parallel with this one.
	profile := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.TrueColor)
	defer lipgloss.SetColorProfile(profile)

	noParties := lanesReview()
	noParties.Parties = nil
	cases := []struct {
		name   string
		review *protocol.Review
		widths []int
		rows   bool
	}{
		{"every kind of effect", lanesReview(), []int{20, 40, 61, 80, 100, 133, 250}, true},
		{"every kind of effect, not selectable", lanesReview(), []int{80, 133}, false},
		{"only apps as lanes", noParties, []int{80}, true},
		{"a group", groupReviewRequest().Review, []int{80, 133}, true},
		{"a lone transaction", singleReviewRequest().Review, []int{80, 133}, false},
		{"more accounts than fit", payrollReviewRequest(9).Review, []int{80, 133}, true},
		{"no transactions", &protocol.Review{Parties: []protocol.ReviewParty{{Address: reviewOwn, Signs: true}}}, []int{80}, true},
		// The widths on each side of one, three, six and seven lanes fitting,
		// and widths with no room at all.
		{"every arrow", arrowsReview(), arrowWidths(-1, 0, 1, 3, 6, 7), true},
		{"every arrow, not selectable", arrowsReview(), arrowWidths(2, 7), false},
	}
	var b strings.Builder
	for _, tc := range cases {
		for _, width := range tc.widths {
			fmt.Fprintf(&b, "== %s, width %d\n%s\n", tc.name, width, dumpPane(drawLanes(tc.review, width, tc.rows)))
		}
	}
	got := b.String()

	path := filepath.Join("testdata", "review_lanes.golden")
	if *updateLanesGolden {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the recorded lanes (run with -update-lanes-golden to record them): %v", err)
	}
	if got == string(want) {
		return
	}
	gotLines, wantLines := strings.Split(got, "\n"), strings.Split(string(want), "\n")
	section := ""
	for i := 0; i < len(gotLines) || i < len(wantLines); i++ {
		g, w := "", ""
		if i < len(gotLines) {
			g = gotLines[i]
		}
		if i < len(wantLines) {
			w = wantLines[i]
		}
		if strings.HasPrefix(w, "== ") {
			section = w
		}
		if g != w {
			t.Fatalf("the lanes differ from the recorded ones at line %d (%s):\n got %s\nwant %s", i+1, section, g, w)
		}
	}
}
