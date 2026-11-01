// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package authortui

import (
	"os"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/signerapp/policyauthor"
	tea "github.com/charmbracelet/bubbletea"
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
	if !strings.Contains(view(m), "the cosigner holds the witness key") {
		t.Fatalf("view lacks the cosigner assumption:\n%s", view(m))
	}
}
