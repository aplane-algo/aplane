// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
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
				{Address: reviewOther}, {Address: reviewThird},
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
			for row := 0; row < 4; row++ {
				view := requireFits(t, m, size[0], size[1])
				for _, want := range []string{"Signing Request", "Group of 3 · 2 signed here · 1 not signed here", "⚠ 2 warnings · REKEY in 2", "APPROVE", "> REJECT"} {
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
	for _, want := range []string{"⚠ CRITICAL: CloseRemainderTo", "Close remainder to:", "\n    " + reviewOther, "Fee: 0.001000 ALGO", "Accounts", reviewOwn} {
		if !strings.Contains(detail, want) {
			t.Errorf("pane lacks %q:\n%s", want, detail)
		}
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
