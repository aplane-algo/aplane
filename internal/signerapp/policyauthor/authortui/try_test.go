// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package authortui

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/signerapp/policyauthor"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
)

const (
	treasuryAddr = "CEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEI7JH2AYM"
	opsMainnet   = "EIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRDOHSEZI"
)

func ctrl(t *testing.T, m Model, key tea.KeyType) Model {
	t.Helper()
	next, _ := m.Update(tea.KeyMsg{Type: key})
	return next.(Model)
}

// tryTopUp fills the try form with a 150 ALGO mainnet top-up from treasury
// to ops, the From field already holding the document's key.
func tryTopUp(t *testing.T, m Model) Model {
	t.Helper()
	m, _ = press(t, m, "t")
	if m.screen != screenTry || m.try.inputs[tryFrom].Value() != treasuryAddr {
		t.Fatalf("t: screen %d, from %q; want the try form with the key as sender", m.screen, m.try.inputs[tryFrom].Value())
	}
	m, _ = press(t, m, "up")
	m = ctrl(t, m, tea.KeyCtrlU)
	m, _ = press(t, m, "mainnet", "down", "down", opsMainnet, "down", "150000000", "enter")
	return m
}

func TestTryFormAsksTheDocument(t *testing.T) {
	ws, _ := workspace(t, map[string][]byte{"treasury.json": fixture(t, "signer_key_full.json")})
	m := tryTopUp(t, New(ws, nil, nil))
	if m.try.err != "" || m.try.result == nil {
		t.Fatalf("try: err %q, result %+v", m.try.err, m.try.result)
	}
	if got := m.try.result.RuleID; got != "review_algo_payment_exceeded" {
		t.Fatalf("rule = %q", got)
	}
	out := view(m)
	for _, want := range []string{"Try a transaction", "this document requires review (rule review_algo_payment_exceeded)", "assumed:", "built-in networks only"} {
		if !strings.Contains(out, want) {
			t.Fatalf("view lacks %q:\n%s", want, out)
		}
	}

	// A bad amount is reported, not tried.
	m, _ = press(t, m, "x", "enter")
	if !strings.Contains(m.try.err, "is not a whole number") || m.try.result != nil {
		t.Fatalf("bad amount: err %q, result %+v", m.try.err, m.try.result)
	}
	m, _ = press(t, m, "esc")
	if m.screen != screenDocument {
		t.Fatalf("esc: screen %d, want the document", m.screen)
	}
}

func TestTryKeepsAnAnswerAsACaseThatRunsAfterEdits(t *testing.T) {
	ws, dir := workspace(t, map[string][]byte{"treasury.json": fixture(t, "signer_key_full.json")})
	m := New(ws, nil, nil)
	if strings.Contains(view(m), "cases:") {
		t.Fatal("a workspace with no saved cases shows a cases count")
	}
	m, _ = press(t, m, "t")
	m = ctrl(t, m, tea.KeyCtrlS)
	if !strings.Contains(m.try.err, "Try the transaction first") || m.try.naming {
		t.Fatalf("ctrl+s before a try: err %q naming %v", m.try.err, m.try.naming)
	}
	m, _ = press(t, m, "esc")

	m = tryTopUp(t, m)
	m = ctrl(t, m, tea.KeyCtrlS)
	m, _ = press(t, m, "large top-up needs review", "enter")
	if m.try.naming || !strings.Contains(m.status, "Saved case") {
		t.Fatalf("saving the case: naming %v status %q err %q", m.try.naming, m.status, m.try.err)
	}
	cases, err := policyauthor.LoadCases(dir)
	if err != nil || len(cases.Cases) != 1 {
		t.Fatalf("LoadCases() = %+v, %v", cases, err)
	}
	c := cases.Cases[0]
	if c.Document != "treasury.json" || c.Expect.Outcome != "review" || c.Expect.RuleID != "review_algo_payment_exceeded" || c.Txn.Network != "mainnet" || c.Txn.Amount != 150000000 {
		t.Fatalf("saved case = %+v", c)
	}
	// The cases file is not a document of the workspace.
	if reopened, err := policyauthor.Open(dir); err != nil || len(reopened.Files) != 1 {
		t.Fatalf("reopened workspace: %v files, %v", len(reopened.Files), err)
	}

	m, _ = press(t, m, "esc")
	if !strings.Contains(view(m), "cases: 1 pass (T)") {
		t.Fatalf("header lacks the passing case:\n%s", view(m))
	}

	// An unsaved edit that raises the review limit changes the answer: the
	// case fails at once, before anything is saved.
	if err := m.session().Apply(func(d *policy.Draft) (*policy.Draft, error) {
		return d.Set("/limits/mainnet/algo/review_above", []byte(`"200000000"`))
	}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(view(m), "cases: 1 of 1 failing (T)") {
		t.Fatalf("header lacks the failing case:\n%s", view(m))
	}
	m, _ = press(t, m, "T")
	out := view(m)
	if m.screen != screenCases || !strings.Contains(out, "FAIL  large top-up needs review") || !strings.Contains(out, "got default, want review (rule review_algo_payment_exceeded)") {
		t.Fatalf("cases screen:\n%s", out)
	}

	// A second case with the same name is refused.
	m, _ = press(t, m, "esc")
	m = tryTopUp(t, m)
	m = ctrl(t, m, tea.KeyCtrlS)
	m, _ = press(t, m, "large top-up needs review", "enter")
	if !strings.Contains(m.try.err, "two cases are named") {
		t.Fatalf("duplicate name: err %q", m.try.err)
	}
}

func TestTryCosignerDocumentAndBadCasesFile(t *testing.T) {
	ws, dir := workspace(t, map[string][]byte{"cosigner.json": fixture(t, "cosigner_default.json")})
	if err := os.MkdirAll(policyauthor.CasesPath(dir)[:len(policyauthor.CasesPath(dir))-len("/cases.json")], 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policyauthor.CasesPath(dir), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := New(ws, nil, nil)
	if !strings.Contains(view(m), "cases file unreadable") {
		t.Fatalf("header lacks the unreadable cases file:\n%s", view(m))
	}
	m, _ = press(t, m, "t", treasuryAddr, "down", opsMainnet, "down", "1", "enter")
	if m.try.result == nil || !strings.Contains(m.try.result.Summary, "this cosigner policy document rejects the supplied transaction") {
		t.Fatalf("cosigner try: %+v err %q", m.try.result, m.try.err)
	}
	if !strings.Contains(view(m), "the cosigner holds the cosigner key") {
		t.Fatalf("view lacks the cosigner assumption:\n%s", view(m))
	}
}

func TestTryEditsDropTheAnswer(t *testing.T) {
	ws, dir := workspace(t, map[string][]byte{"treasury.json": fixture(t, "signer_key_full.json")})
	m := tryTopUp(t, New(ws, nil, nil))
	if m.try.result == nil {
		t.Fatal("no answer to begin with")
	}
	// Change the amount the screen shows: the old answer goes.
	m = ctrl(t, m, tea.KeyCtrlU)
	m, _ = press(t, m, "1")
	if m.try.result != nil {
		t.Fatal("an edited amount kept the answer for the old one")
	}
	m = ctrl(t, m, tea.KeyCtrlS)
	if m.try.naming || !strings.Contains(m.try.err, "Try the transaction first") {
		t.Fatalf("ctrl+s after an edit: naming %v err %q", m.try.naming, m.try.err)
	}
	// Tried again, the case is the transaction on screen.
	m, _ = press(t, m, "enter")
	m = ctrl(t, m, tea.KeyCtrlS)
	m, _ = press(t, m, "small top-up", "enter")
	cases, err := policyauthor.LoadCases(dir)
	if err != nil || len(cases.Cases) != 1 || cases.Cases[0].Txn.Amount != 1 || cases.Cases[0].Expect.Outcome != "default" {
		t.Fatalf("saved = %+v, %v; want the 1 microAlgo transaction and its answer", cases, err)
	}

	// The held-key toggle is an edit too.
	m, _ = press(t, m, "enter")
	for m.try.cursor != tryRekeyHeld {
		m, _ = press(t, m, "down")
	}
	m, _ = press(t, m, " ")
	if !m.try.held || m.try.result != nil {
		t.Fatalf("toggle: held %v, result %+v", m.try.held, m.try.result)
	}
	// Moving between fields is not.
	m, _ = press(t, m, "enter", "up")
	if m.try.result == nil {
		t.Fatal("moving the cursor dropped the answer")
	}
}

// pageThrough pages the try screen from the top to the end and back,
// returning every body line it showed, without styling.
func pageThrough(t *testing.T, m Model) map[string]bool {
	t.Helper()
	seen := map[string]bool{}
	record := func() {
		for _, l := range strings.Split(view(m), "\n") {
			seen[strings.TrimRight(l, " ")] = true
		}
	}
	m.try.offset = 0
	record()
	for i := 0; i < 50; i++ {
		before := m.try.offset
		m, _ = press(t, m, "pgdown")
		record()
		if m.try.offset == before {
			break
		}
	}
	for i := 0; i < 50 && m.try.offset > 0; i++ {
		m, _ = press(t, m, "pgup")
		record()
	}
	if m.try.offset != 0 {
		t.Fatalf("pgup did not return to the top: offset %d", m.try.offset)
	}
	return seen
}

func TestTryScreenPagingReachesEveryLine(t *testing.T) {
	ws, _ := workspace(t, map[string][]byte{"treasury.json": fixture(t, "signer_key_full.json")})
	// Heights where the form is pinned and the answer scrolls, and where the
	// form itself does not fit and everything scrolls.
	for _, height := range []int{14, 15, 16, 18, 19, 20, 21, 24} {
		t.Run(fmt.Sprint(height), func(t *testing.T) {
			m := New(ws, nil, nil)
			m.width, m.height = 80, height
			// A testnet transfer to ops misses every route: a rejection with
			// its violation, the summary and the assumptions.
			m, _ = press(t, m, "t", "down", opsMainnet, "down", "1", "enter")
			if m.try.result == nil {
				t.Fatalf("no answer: %q", m.try.err)
			}
			// The status line and footer take the last two rows.
			if lines := strings.Count(m.tryView(), "\n") + 1; lines > height-2 {
				t.Fatalf("try body is %d lines, over %d", lines, height-2)
			}
			seen := pageThrough(t, m)
			vp := m.tryViewport()
			for _, l := range append(append([]string(nil), vp.pinned...), vp.body...) {
				want := strings.TrimRight(ansi.Strip(ansi.Truncate(l, m.width, "…")), " ")
				if !seen[want] {
					t.Fatalf("paging never showed %q", want)
				}
			}
		})
	}
}

func TestTryShortTerminalKeepsTheFocusedFieldInView(t *testing.T) {
	ws, _ := workspace(t, map[string][]byte{"treasury.json": fixture(t, "signer_key_full.json")})
	m := New(ws, nil, nil)
	m.width, m.height = 80, 10
	m, _ = press(t, m, "t")
	for i := 0; i < tryFieldCount; i++ {
		m, _ = press(t, m, "down")
		label := tryLabels[m.try.cursor]
		if !strings.Contains(view(m), label) {
			t.Fatalf("focused field %q is not shown:\n%s", label, view(m))
		}
	}
	// Typing in a field low in the form keeps it in view.
	for m.try.cursor != tryRekeyTo {
		m, _ = press(t, m, "down")
	}
	m, _ = press(t, m, "x")
	if !strings.Contains(view(m), tryLabels[tryRekeyTo]) {
		t.Fatalf("the field being typed in scrolled away:\n%s", view(m))
	}
}
