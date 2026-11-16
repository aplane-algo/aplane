// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"regexp"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/aplane-algo/aplane/internal/protocol"
)

const (
	reviewOwn   = "M35J7HJRQ244COTGWACPZC5V6M2ZYTPLC4MXEZUJL64NHRT4HMLROFEZ6A"
	reviewOther = "Q25WCGRVJQEW5Z6HQ44EFQ6MJ2AJY3WSOJGL3NXEHONO5VRO5P7SML3JAE"
	reviewThird = "Q25WAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAL3JAE"
)

func reviewPayment(to string, extra ...protocol.ReviewField) protocol.ReviewItem {
	fields := []protocol.ReviewField{
		{Label: "From", Value: reviewOwn, Party: reviewOwn},
		{Label: "To", Value: to, Party: to},
	}
	fields = append(fields, extra...)
	fields = append(fields, protocol.ReviewField{Label: "Fee", Value: "0.001000 ALGO"}, protocol.ReviewField{Label: "Network", Value: "testnet"})
	return protocol.ReviewItem{
		Position: protocol.ReviewPositionSign,
		Notes:    []protocol.ReviewField{{Label: "Signing key", Value: reviewOwn}},
		Title:    "Payment: 5000.000000 ALGO",
		Sender:   reviewOwn,
		Fields:   fields,
		Effects:  []protocol.ReviewEffect{{Kind: "transfer", From: reviewOwn, To: to, Text: "5000.000000 ALGO"}},
	}
}

// groupReviewRequest is a group of three: a payment, a payment that also
// rekeys, and a transaction this request does not sign.
func groupReviewRequest() *PendingSignRequest {
	rekey := protocol.PolicyViolation{Field: "RekeyTo", Value: reviewThird, Severity: "critical",
		Message: "This transaction will REKEY the account.\n   You will lose control of this account."}
	lookalike := protocol.PolicyViolation{Field: "Lookalike accounts", Severity: "warning",
		Message: "Two different accounts in this request look alike: both start with Q25W and end with L3JAE. Compare the full addresses.\n   " + reviewOther + "\n   " + reviewThird}
	second := reviewPayment(reviewThird, protocol.ReviewField{Label: "REKEY TO", Value: reviewThird, Party: reviewThird, Alert: true})
	second.Effects = append(second.Effects, protocol.ReviewEffect{Kind: "rekey", From: reviewOwn, To: reviewThird, Text: "REKEY: control moves", Severity: protocol.ReviewSeverityDanger})
	second.Findings = []protocol.PolicyViolation{rekey}
	foreign := protocol.ReviewItem{
		Position: protocol.ReviewPositionForeign, Label: "FOREIGN - not signing",
		Title: "App Call: #1002 (NoOp)", Sender: reviewOther,
		Fields:  []protocol.ReviewField{{Label: "From", Value: reviewOther, Party: reviewOther}, {Label: "Args", Value: "1 argument(s)"}, {Label: "[0]", Value: "0xdeadbeef", Depth: 1}},
		Effects: []protocol.ReviewEffect{{Kind: "app_call", From: reviewOther, App: 1002, Text: "call"}},
	}
	groupRekey := rekey
	groupRekey.Field = "Tx 2/3: RekeyTo"
	return &PendingSignRequest{
		ID: "apv-1", Address: reviewOwn, TxnSender: "GROUP(3 txns)",
		Description: "[GROUP APPROVAL]\n=== TRANSACTION GROUP (3 transactions) ===\nraw text of the request",
		FirstValid:  100, LastValid: 1100,
		Violations: []protocol.PolicyViolation{groupRekey, lookalike},
		Review: &protocol.Review{
			Version: protocol.ReviewVersion, Group: true,
			Banners: []string{"[MULTI-PARTY: 2 to sign, 1 foreign (not signing)]"},
			Changes: protocol.ReviewChanges{Heading: "[MODIFIED BY SERVER]", Lines: []string{"Added 1 dummy transaction(s) for LogicSig arguments/opcode budget", "Group ID recomputed"}, Dummies: 1},
			Items:   []protocol.ReviewItem{reviewPayment(reviewOther), second, foreign},
			Parties: []protocol.ReviewParty{
				{Address: reviewOwn, Held: true, Signs: true, KeyType: "falcon1024"},
				{Address: reviewOther, Lookalike: true}, {Address: reviewThird, Lookalike: true},
			},
			Findings: []protocol.PolicyViolation{lookalike},
		},
	}
}

func singleReviewRequest() *PendingSignRequest {
	closing := protocol.PolicyViolation{Field: "CloseRemainderTo", Value: reviewOther, Severity: "critical",
		Message: "This transaction will close your account and send ALL remaining ALGO to another address."}
	item := reviewPayment(reviewOther, protocol.ReviewField{Label: "Close remainder to", Value: reviewOther, Party: reviewOther})
	item.Findings = []protocol.PolicyViolation{closing}
	item.Effects = append(item.Effects, protocol.ReviewEffect{Kind: "close", From: reviewOwn, To: reviewOther, Text: "CLOSE: all remaining ALGO", Severity: protocol.ReviewSeverityDanger})
	return &PendingSignRequest{
		ID: "apv-2", Address: reviewOwn, TxnSender: reviewOwn,
		Description: "[TXN APPROVAL]\nPayment: 5000.000000 ALGO\n  raw text",
		FirstValid:  100, LastValid: 1100,
		Violations: []protocol.PolicyViolation{closing},
		Review: &protocol.Review{
			Version: protocol.ReviewVersion,
			Items:   []protocol.ReviewItem{item},
			Parties: []protocol.ReviewParty{{Address: reviewOwn, Held: true, Signs: true, KeyType: "falcon1024"}, {Address: reviewOther}},
		},
	}
}

// reviewModelForTest is a model showing request at the given window size.
func reviewModelForTest(t *testing.T, request *PendingSignRequest, standalone bool, width, height int) Model {
	t.Helper()
	m := sizedForTest(t, Model{viewState: ViewKeyList, standalone: standalone}, width, height)
	m, _ = updateForTest(t, m, SignRequestReceivedMsg{Request: *request})
	if m.viewState != ViewSigningPopup {
		t.Fatalf("view = %v, want the signing popup", m.viewState)
	}
	return m
}

func reviewKey(t *testing.T, m Model, key string) Model {
	t.Helper()
	msg := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(key)}
	switch key {
	case "up":
		msg = tea.KeyMsg{Type: tea.KeyUp}
	case "down":
		msg = tea.KeyMsg{Type: tea.KeyDown}
	case "pgdown":
		msg = tea.KeyMsg{Type: tea.KeyPgDown}
	}
	m, _ = updateForTest(t, m, msg)
	return m
}

// requireFits fails unless the whole screen fits the window.
func requireFits(t *testing.T, m Model, width, height int) string {
	t.Helper()
	view := stripANSI(m.View())
	lines := strings.Split(strings.TrimRight(view, "\n"), "\n")
	if len(lines) > height {
		t.Fatalf("screen is %d lines, window has %d:\n%s", len(lines), height, view)
	}
	for _, line := range lines {
		if got := len([]rune(line)); got > width {
			t.Fatalf("line is %d wide, window is %d: %q\n%s", got, width, line, view)
		}
	}
	return view
}

// allDetail scrolls the detail pane to its end and returns everything it
// showed.
func allDetail(t *testing.T, m Model) string {
	t.Helper()
	var seen []string
	for i := 0; i < 200; i++ {
		seen = append(seen, stripANSI(m.signing.viewport.View()))
		if m.signing.viewport.AtBottom() {
			break
		}
		m = reviewKey(t, m, "pgdown")
	}
	return strings.Join(seen, "\n")
}

// The drawn review fits the smallest window apadmin lays out for, and a
// larger one, on every row of a group and for a lone transaction.
func TestReviewScreenFitsTheWindow(t *testing.T) {
	for _, size := range [][2]int{{MinWidth, MinHeight}, {133, 39}} {
		for _, standalone := range []bool{true, false} {
			m := reviewModelForTest(t, groupReviewRequest(), standalone, size[0], size[1])
			for row := 0; row < 12; row++ {
				if row%4 == 0 && row > 0 {
					m = reviewKey(t, m, "v")
					for i := 0; i < 4; i++ {
						m = reviewKey(t, m, "up")
					}
				}
				view := requireFits(t, m, size[0], size[1])
				if strings.ContainsAny(view, "╔║╚") {
					t.Fatalf("%dx%d: the review is drawn in a popup frame:\n%s", size[0], size[1], view)
				}
				for _, want := range []string{"Signing Request", "Group of 3 · 2 signed here · 1 not signed here", "⚠ 2 warnings · REKEY in 2", "APPROVE (y)", "> REJECT (n)"} {
					if !strings.Contains(view, want) {
						t.Fatalf("%dx%d row %d: screen lacks %q:\n%s", size[0], size[1], row, want, view)
					}
				}
				m = reviewKey(t, m, "down")
			}
			single := reviewModelForTest(t, singleReviewRequest(), standalone, size[0], size[1])
			view := requireFits(t, single, size[0], size[1])
			for _, want := range []string{"Single transaction", "⚠ 1 warning · CLOSE", "Valid Rounds: 100 - 1100"} {
				if !strings.Contains(view, want) {
					t.Fatalf("%dx%d: single screen lacks %q:\n%s", size[0], size[1], want, view)
				}
			}
		}
	}
}

// The overview holds every warning of the request, each account's whole
// address with what the signer holds, and what planning changed.
func TestReviewOverviewShowsWarningsAccountsAndChanges(t *testing.T) {
	m := reviewModelForTest(t, groupReviewRequest(), true, MinWidth, MinHeight)
	detail := allDetail(t, m)
	for _, want := range []string{
		"⚠ CRITICAL: Tx 2/3: RekeyTo",
		"⚠ WARNING: Lookalike accounts",
		reviewOwn, reviewOther, reviewThird,
		"this request signs for it, with a falcon1024 key",
		"[MULTI-PARTY: 2 to sign, 1 foreign (not signing)]",
		"[MODIFIED BY SERVER]",
		"• Group ID recomputed",
	} {
		if !strings.Contains(detail, want) {
			t.Errorf("overview lacks %q:\n%s", want, detail)
		}
	}
}

// Selecting a transaction shows it in full: how the request treats it, its
// own warnings, and every field, reached by scrolling where the pane is
// short.
func TestReviewShowsTheSelectedTransactionInFull(t *testing.T) {
	request := groupReviewRequest()
	m := reviewModelForTest(t, request, true, MinWidth, MinHeight)
	for index, item := range request.Review.Items {
		m = reviewKey(t, m, "down")
		if m.signing.review.row != index+1 {
			t.Fatalf("row = %d after %d presses", m.signing.review.row, index+1)
		}
		requireFits(t, m, MinWidth, MinHeight)
		detail := allDetail(t, m)
		wants := []string{item.Title}
		for _, field := range append(append([]protocol.ReviewField{}, item.Notes...), item.Fields...) {
			wants = append(wants, field.Value)
		}
		for _, finding := range item.Findings {
			wants = append(wants, "⚠ CRITICAL: "+finding.Field)
		}
		for _, want := range wants {
			if !strings.Contains(detail, want) {
				t.Errorf("transaction %d lacks %q:\n%s", index+1, want, detail)
			}
		}
	}
	if !strings.Contains(allDetail(t, m), "FOREIGN - not signing") {
		t.Error("a transaction the request does not sign lacks its label")
	}
	// The selection stops at the ends of the list.
	m = reviewKey(t, m, "down")
	if m.signing.review.row != 3 {
		t.Fatalf("row = %d past the last transaction", m.signing.review.row)
	}
	for i := 0; i < 5; i++ {
		m = reviewKey(t, m, "up")
	}
	if m.signing.review.row != 0 {
		t.Fatalf("row = %d past the overview", m.signing.review.row)
	}
}

// A lone transaction's pane holds everything: the transaction first, then
// the accounts. A field too long for the pane wraps with its address whole.
func TestReviewOfALoneTransactionShowsEverythingInOnePane(t *testing.T) {
	request := singleReviewRequest()
	m := reviewModelForTest(t, request, true, MinWidth, MinHeight)
	detail := allDetail(t, m)
	for _, want := range []string{"⚠ CRITICAL: CloseRemainderTo", "Close remainder to:", "Fee: 0.001000 ALGO", "Accounts", reviewOwn} {
		if !strings.Contains(detail, want) {
			t.Errorf("pane lacks %q:\n%s", want, detail)
		}
	}
	// Whether or not the field wraps, its address is never split.
	if !regexp.MustCompile(`Close remainder to:\s+` + reviewOther).MatchString(detail) {
		t.Errorf("the close-to address is not whole after its label:\n%s", detail)
	}
	if strings.Index(detail, "Payment: 5000.000000 ALGO") > strings.Index(detail, "Accounts") {
		t.Errorf("the transaction is not shown before the accounts:\n%s", detail)
	}
	// With no list, up and down scroll the pane.
	before := m.signing.viewport.YOffset
	m = reviewKey(t, m, "down")
	if m.signing.viewport.YOffset == before {
		t.Error("down did not scroll a lone transaction's pane")
	}
}

// "t" shows the request's description and brings the drawn review back, and
// a request that arrives next starts on the drawn review.
func TestReviewTextToggle(t *testing.T) {
	m := reviewModelForTest(t, groupReviewRequest(), true, MinWidth, MinHeight)
	m = reviewKey(t, m, "down")
	m = reviewKey(t, m, "t")
	view := requireFits(t, m, MinWidth, MinHeight)
	if !strings.Contains(view, "=== TRANSACTION GROUP (3 transactions) ===") || !strings.Contains(view, "t: Review") {
		t.Fatalf("text view:\n%s", view)
	}
	// The text keeps the frame: the warning count above it, the buttons
	// under it, and the warnings in full after the description.
	for _, want := range []string{"⚠ 2 warnings · REKEY in 2", "> REJECT", "APPROVE"} {
		if !strings.Contains(view, want) {
			t.Fatalf("text view lacks %q:\n%s", want, view)
		}
	}
	if text := allDetail(t, m); !strings.Contains(text, "raw text of the request") || !strings.Contains(text, "⚠ CRITICAL: Tx 2/3: RekeyTo") {
		t.Fatalf("text pane:\n%s", text)
	}
	m = reviewKey(t, m, "t")
	view = requireFits(t, m, MinWidth, MinHeight)
	if !strings.Contains(view, "Transaction 1 of 3 · signed here") || !strings.Contains(view, "t: Text") {
		t.Fatalf("drawn review after the toggle:\n%s", view)
	}

	m = reviewKey(t, m, "t")
	m, _ = updateForTest(t, m, SignRequestCanceledMsg{ID: "apv-1"})
	m, _ = updateForTest(t, m, SignRequestReceivedMsg{Request: *singleReviewRequest()})
	if m.signing.review != (reviewState{}) || !strings.Contains(stripANSI(m.View()), "Single transaction") {
		t.Fatalf("a new request did not start on the drawn review: %+v", m.signing.review)
	}
}

// A request without a review is shown as its description, as before.
func TestRequestWithoutAReviewShowsItsDescription(t *testing.T) {
	request := groupReviewRequest()
	request.Review = nil
	m := reviewModelForTest(t, request, true, MinWidth, MinHeight)
	view := stripANSI(m.View())
	if !strings.Contains(view, "Transaction Details") || strings.Contains(view, "t: ") {
		t.Fatalf("view:\n%s", view)
	}
	if m, handled := m.handleReviewKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("t")}); handled || m.signing.review.text {
		t.Fatal("t was handled with no review to draw")
	}
}

// The approval keys answer a drawn review as they answer the text.
func TestReviewAnswersWithTheApprovalKeys(t *testing.T) {
	m := reviewModelForTest(t, groupReviewRequest(), true, MinWidth, MinHeight)
	m, cmd := updateForTest(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("n")})
	if m.signing.request != nil || cmd == nil {
		t.Fatalf("n did not reject: request = %v, cmd = %v", m.signing.request, cmd)
	}
}

// Two addresses that share their ends get different marks.
func TestAddressChipDiffersForLookalikes(t *testing.T) {
	sum := func(address string) [4]int {
		var out [4]int
		digest := chipDigest(address)
		for i := range out {
			out[i] = int(digest[i]) % len(chipPalette)
		}
		return out
	}
	if sum(reviewOther) == sum(reviewThird) {
		t.Fatalf("lookalike addresses got the same mark: %v", sum(reviewOther))
	}
}

// payrollReviewRequest is one account paying n others.
func payrollReviewRequest(n int) *PendingSignRequest {
	request := groupReviewRequest()
	review := request.Review
	review.Items, review.Findings, review.Banners = nil, nil, nil
	review.Parties = []protocol.ReviewParty{{Address: reviewOwn, Held: true, Signs: true}}
	request.Violations = nil
	for i := 0; i < n; i++ {
		to := strings.Repeat(string(rune('B'+i)), 58)
		review.Items = append(review.Items, reviewPayment(to))
		review.Parties = append(review.Parties, protocol.ReviewParty{Address: to})
	}
	return request
}

func pictureOf(t *testing.T, m Model) reviewPicture {
	t.Helper()
	return m.pictureFor(m.reviewOf(), m.reviewWidth())
}

// Left to itself the upper pane draws lanes where every lane fits, a table
// for one account paying several others or where the lanes do not fit, and a
// plain list where nothing moves between two parties.
func TestReviewPictureFollowsTheShapeOfTheRequest(t *testing.T) {
	optIns := groupReviewRequest()
	for i := range optIns.Review.Items {
		optIns.Review.Items[i].Effects = []protocol.ReviewEffect{{Kind: "opt_in", From: reviewOwn, Text: "opt in to USDC"}}
	}
	wide := groupReviewRequest()
	for i := 0; i < 8; i++ {
		address := strings.Repeat(string(rune('C'+i)), 58)
		wide.Review.Parties = append(wide.Review.Parties, protocol.ReviewParty{Address: address})
	}
	for _, tc := range []struct {
		name    string
		request *PendingSignRequest
		width   int
		want    reviewPicture
	}{
		{"a few parties", groupReviewRequest(), MinWidth, pictureLanes},
		{"one account paying three", payrollReviewRequest(3), 133, pictureTable},
		{"one account paying two", payrollReviewRequest(2), MinWidth, pictureLanes},
		{"opt-ins only", optIns, MinWidth, pictureList},
		{"more lanes than fit", wide, MinWidth, pictureTable},
	} {
		m := reviewModelForTest(t, tc.request, true, tc.width, MinHeight)
		if got := pictureOf(t, m); got != tc.want {
			t.Errorf("%s: picture = %d, want %d", tc.name, got, tc.want)
		}
		requireFits(t, m, tc.width, MinHeight)
	}
}

// Lanes draw each account and app as a column and each effect as an arrow:
// filled where this request signs, dashed for a rekey, with a lookalike's
// column saying so.
func TestReviewLanes(t *testing.T) {
	m := reviewModelForTest(t, groupReviewRequest(), true, 133, 39)
	if pictureOf(t, m) != pictureLanes {
		t.Fatal("the group is not drawn as lanes")
	}
	view := requireFits(t, m, 133, 39)
	for _, want := range []string{"M35J…EZ6A", "Q25W…3JAE", "app 1002", "signs", "lookalike", "5000.000000 ALGO", "REKEY: control moves", "call"} {
		if !strings.Contains(view, want) {
			t.Errorf("lanes lack %q:\n%s", want, view)
		}
	}
	var payment, rekey, call string
	for _, line := range strings.Split(view, "\n") {
		switch {
		case strings.Contains(line, "REKEY: control moves"):
			rekey = line
		case strings.Contains(line, " call"):
			call = line
		case strings.Contains(line, " 1 ") && strings.Contains(line, "5000.000000 ALGO"):
			payment = line
		}
	}
	if !strings.Contains(payment, "●─") || !strings.Contains(payment, "─►") {
		t.Errorf("a payment this request signs is not a solid arrow from a filled dot: %q", payment)
	}
	if !strings.Contains(rekey, "●╌") || !strings.Contains(rekey, "╌►") {
		t.Errorf("a rekey is not a dashed arrow: %q", rekey)
	}
	if !strings.Contains(call, "○─") || strings.Contains(call, "●") {
		t.Errorf("a transaction this request does not sign does not start from a hollow dot: %q", call)
	}

	// Selecting a transaction with two effects keeps both of its lines.
	small := reviewModelForTest(t, groupReviewRequest(), true, MinWidth, MinHeight)
	small = reviewKey(t, small, "down")
	small = reviewKey(t, small, "down")
	smallView := requireFits(t, small, MinWidth, MinHeight)
	if !strings.Contains(smallView, "REKEY: control moves") || !strings.Contains(smallView, "Transaction 2 of 3 · signed here") {
		t.Errorf("the selected transaction's second effect is out of view:\n%s", smallView)
	}
}

// "v" goes round the three pictures, and a table names each movement with a
// lookalike marked in words.
func TestReviewPictureKeyAndTable(t *testing.T) {
	m := reviewModelForTest(t, groupReviewRequest(), true, 133, 39)
	var seen []reviewPicture
	for i := 0; i < 3; i++ {
		seen = append(seen, pictureOf(t, m))
		m = reviewKey(t, m, "v")
	}
	if seen[0] != pictureLanes || seen[1] != pictureTable || seen[2] != pictureList || pictureOf(t, m) != pictureLanes {
		t.Fatalf("pictures = %v, then %d", seen, pictureOf(t, m))
	}
	m = reviewKey(t, m, "v")
	view := requireFits(t, m, 133, 39)
	for _, want := range []string{"From", "What", "M35J…EZ6A    → Q25W…3JAE", "REKEY: control moves (looks alike)", "→ app 1002"} {
		if !strings.Contains(view, want) {
			t.Errorf("table lacks %q:\n%s", want, view)
		}
	}
}

// Lanes asked for where they do not all fit show the lanes that do, count
// the rest, and end an arrow that leaves them in "»".
func TestReviewLanesThatDoNotFit(t *testing.T) {
	m := reviewModelForTest(t, payrollReviewRequest(9), true, MinWidth, MinHeight)
	if pictureOf(t, m) != pictureTable {
		t.Fatal("a payroll is not drawn as a table")
	}
	m = reviewKey(t, m, "v") // list
	m = reviewKey(t, m, "v") // lanes
	if pictureOf(t, m) != pictureLanes {
		t.Fatalf("picture = %d, want lanes", pictureOf(t, m))
	}
	for i := 0; i < 9; i++ {
		m = reviewKey(t, m, "down")
	}
	view := requireFits(t, m, MinWidth, MinHeight)
	if !strings.Contains(view, "»") || !strings.Contains(view, " +") {
		t.Fatalf("lanes that do not fit are not marked:\n%s", view)
	}
	if !strings.Contains(view, "Transaction 9 of 9") {
		t.Fatalf("the last transaction is not selected:\n%s", view)
	}
}

// A lone transaction that moves something between two parties is drawn as
// lanes too, above its fields, with nothing to select. One that touches a
// single account has no picture, and the text view has none either.
func TestLoneTransactionIsDrawnAsLanes(t *testing.T) {
	for _, size := range [][2]int{{MinWidth, MinHeight}, {133, 39}} {
		m := reviewModelForTest(t, singleReviewRequest(), true, size[0], size[1])
		view := requireFits(t, m, size[0], size[1])
		for _, want := range []string{"M35J…EZ6A", "Q25W…3JAE", "signs", "5000.000000 ALGO", "CLOSE: all remaining ALGO", "●─", "─►", "●═", "═►", "Transaction · signed here", "> REJECT"} {
			if !strings.Contains(view, want) {
				t.Fatalf("%dx%d: screen lacks %q:\n%s", size[0], size[1], want, view)
			}
		}
		if strings.Contains(view, "Overview:") {
			t.Fatalf("a lone transaction has rows to select:\n%s", view)
		}
		// Up and down still scroll the fields.
		before := m.signing.viewport.YOffset
		m = reviewKey(t, m, "down")
		if size[1] == MinHeight && m.signing.viewport.YOffset == before {
			t.Error("down did not scroll a lone transaction's fields")
		}
		m = reviewKey(t, m, "t")
		if text := requireFits(t, m, size[0], size[1]); strings.Contains(text, "●") {
			t.Fatalf("the text view draws the picture:\n%s", text)
		}
	}

	optIn := singleReviewRequest()
	optIn.Review.Items[0].Effects = []protocol.ReviewEffect{{Kind: "opt_in", From: reviewOwn, Text: "opt in to USDC"}}
	m := reviewModelForTest(t, optIn, true, MinWidth, MinHeight)
	if view := requireFits(t, m, MinWidth, MinHeight); strings.Contains(view, "M35J…EZ6A") || strings.Contains(view, "◎") {
		t.Fatalf("a transaction on one account alone is drawn as lanes:\n%s", view)
	}
}

// A transaction's detail shows its fields before its warnings, each warning
// starting on one line with its message, and names the signing key only
// where it is not the sender.
func TestReviewTransactionShowsFieldsBeforeWarnings(t *testing.T) {
	m := reviewModelForTest(t, groupReviewRequest(), true, MinWidth, MinHeight)
	m = reviewKey(t, reviewKey(t, m, "down"), "down")
	detail := allDetail(t, m)
	to := strings.Index(detail, "REKEY TO: "+reviewThird)
	warning := strings.Index(detail, "⚠ CRITICAL: RekeyTo · This transaction will REKEY the account.")
	if to < 0 || warning < 0 || to > warning {
		t.Fatalf("the rekey field (at %d) does not come before its warning (at %d):\n%s", to, warning, detail)
	}
	if !strings.Contains(stripANSI(m.signing.viewport.View()), "To: "+reviewThird) {
		t.Errorf("the first page of the detail lacks the receiver:\n%s", m.signing.viewport.View())
	}
	if strings.Contains(detail, protocol.ReviewNoteSigningKey) {
		t.Errorf("the signing key is shown though it is the sender:\n%s", detail)
	}

	// A rekeyed account signs with another account's key: that stays.
	rekeyed := groupReviewRequest()
	rekeyed.Review.Items[0].Notes = []protocol.ReviewField{{Label: protocol.ReviewNoteSigningKey, Value: reviewThird}}
	m = reviewKey(t, reviewModelForTest(t, rekeyed, true, MinWidth, MinHeight), "down")
	if !strings.Contains(allDetail(t, m), protocol.ReviewNoteSigningKey+": "+reviewThird) {
		t.Errorf("a signing key other than the sender is not shown:\n%s", allDetail(t, m))
	}
}

// A selected row is drawn from its spans over a tint, not as plain text, so
// a rekey's arrow keeps its danger colour while the operator looks at it.
func TestReviewSelectedRowKeepsItsColours(t *testing.T) {
	m := reviewModelForTest(t, groupReviewRequest(), true, MinWidth, MinHeight)
	m = reviewKey(t, reviewKey(t, m, "down"), "down")
	pane, ok := m.reviewUpperPane(m.reviewOf(), m.reviewWidth())
	if !ok {
		t.Fatal("the group has no upper pane")
	}
	var rekey *paneLine
	for i, line := range pane.lines {
		if line.row == m.signing.review.row && strings.Contains(line.plain, "REKEY") {
			rekey = &pane.lines[i]
		}
	}
	if rekey == nil {
		t.Fatalf("the selected row has no rekey line: %+v", pane.lines)
	}
	danger := false
	for _, span := range rekey.spans {
		if strings.Contains(span.text, "╌") && span.style.GetForeground() == errorStyle.GetForeground() {
			danger = true
		}
	}
	if !danger {
		t.Fatalf("the rekey arrow is not drawn in the danger style: %+v", rekey.spans)
	}
	if got := stripANSI(rekey.render(true)); got != rekey.plain {
		t.Fatalf("the spans say %q, the plain text %q", got, rekey.plain)
	}
}

// The validity window shares the first header line with room for it, keeps
// saying when a window is empty, and the rule over the detail pane counts
// the rows below the upper pane and says which detail lines show.
func TestReviewHeaderAndRuleShareLines(t *testing.T) {
	lineWith := func(view, text string) string {
		for _, line := range strings.Split(view, "\n") {
			if strings.Contains(line, text) {
				return line
			}
		}
		return ""
	}

	wide := requireFits(t, reviewModelForTest(t, groupReviewRequest(), true, 133, 39), 133, 39)
	if line := lineWith(wide, "Valid Rounds: 100 - 1100"); !strings.Contains(line, "Group of 3") {
		t.Errorf("at 133 columns the validity window is not on the summary line: %q", line)
	}
	narrow := requireFits(t, reviewModelForTest(t, groupReviewRequest(), true, MinWidth, MinHeight), MinWidth, MinHeight)
	if line := lineWith(narrow, "Valid Rounds: 100 - 1100"); !strings.Contains(line, "⚠ 2 warnings") {
		t.Errorf("at 80 columns the validity window is not on the risk line: %q", line)
	}
	if strings.Contains(narrow, "pgup/pgdown: scroll") {
		t.Errorf("the detail scroll hint still has a line of its own:\n%s", narrow)
	}
	if line := lineWith(narrow, "details: lines 1-"); !strings.HasPrefix(strings.TrimSpace(line), "──") {
		t.Errorf("the rule does not say which detail lines show:\n%s", narrow)
	}

	empty := singleReviewRequest()
	empty.FirstValid, empty.LastValid = 20, 10
	view := requireFits(t, reviewModelForTest(t, empty, true, MinWidth, MinHeight), MinWidth, MinHeight)
	if !strings.Contains(view, "Valid Rounds: 20 - 10 (empty: no round is valid)") {
		t.Errorf("an empty validity window is not called empty:\n%s", view)
	}

	payroll := requireFits(t, reviewModelForTest(t, payrollReviewRequest(12), true, MinWidth, MinHeight), MinWidth, MinHeight)
	if !regexp.MustCompile(`── ▼ \d+ more below ─`).MatchString(payroll) {
		t.Errorf("the rule does not count the rows below:\n%s", payroll)
	}
}

// heldRekeyRequest is the group with its rekey made to an account this
// signer holds: the finding is a notice, the field and arrow ordinary, and
// no lookalike.
func heldRekeyRequest() *PendingSignRequest {
	request := groupReviewRequest()
	notice := protocol.PolicyViolation{Field: "RekeyTo", Value: reviewThird, Severity: protocol.ViolationSeverityNotice,
		Message: "This transaction will transfer signing authority to another address.\n   This signer holds the aplane key for the new address."}
	item := &request.Review.Items[1]
	item.Findings = []protocol.PolicyViolation{notice}
	for i := range item.Fields {
		if item.Fields[i].Party == reviewThird && item.Fields[i].Alert {
			item.Fields[i].Label, item.Fields[i].Alert = "Rekey to", false
		}
	}
	for i := range item.Effects {
		if item.Effects[i].Kind == "rekey" {
			item.Effects[i].Text, item.Effects[i].Severity = "rekey: control moves", ""
		}
	}
	groupNotice := notice
	groupNotice.Field = "Tx 2/3: RekeyTo"
	request.Violations = []protocol.PolicyViolation{groupNotice}
	request.Review.Findings = nil
	request.Review.Parties = []protocol.ReviewParty{
		{Address: reviewOwn, Held: true, Signs: true, KeyType: "falcon1024"},
		{Address: reviewOther}, {Address: reviewThird, Held: true},
	}
	return request
}

// A rekey to an account this signer holds is a notice: no risk line, no
// warning mark on its row, an arrow in the ordinary colour, and a note, not
// a warning, in its detail and in the overview.
func TestReviewShowsAHeldRekeyAsANotice(t *testing.T) {
	m := reviewModelForTest(t, heldRekeyRequest(), true, MinWidth, MinHeight)
	view := requireFits(t, m, MinWidth, MinHeight)
	if strings.Contains(view, "⚠") || strings.Contains(view, "REKEY") {
		t.Fatalf("a held rekey is shown with alarm:\n%s", view)
	}
	overview := allDetail(t, m)
	if !strings.Contains(overview, "Notes") || !strings.Contains(overview, "Note: Tx 2/3: RekeyTo · This transaction will transfer signing authority") || strings.Contains(overview, "Warnings") {
		t.Fatalf("the overview does not list the rekey as a note:\n%s", overview)
	}

	m = reviewKey(t, reviewKey(t, m, "down"), "down")
	detail := allDetail(t, m)
	if !strings.Contains(detail, "Rekey to: "+reviewThird) || !strings.Contains(detail, "Note: RekeyTo") || strings.Contains(detail, "CRITICAL") {
		t.Fatalf("the transaction's detail does not show the rekey as a note:\n%s", detail)
	}
	pane, _ := m.reviewUpperPane(m.reviewOf(), m.reviewWidth())
	for _, line := range pane.lines {
		for _, span := range line.spans {
			if strings.Contains(span.text, "╌") && span.style.GetForeground() == errorStyle.GetForeground() {
				t.Fatalf("the held rekey's arrow is drawn in the danger style: %q", line.plain)
			}
		}
	}

	m = reviewKey(t, m, "t")
	if text := allDetail(t, m); !strings.Contains(text, "Note: Tx 2/3: RekeyTo") || strings.Contains(text, "⚠") {
		t.Fatalf("the text view shows the notice as a warning:\n%s", text)
	}
}
