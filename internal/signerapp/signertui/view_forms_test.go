// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/aplane-algo/aplane/internal/boundary"
	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/witness"
)

func TestRenderGenerateDisplayLabelsCosignerKey(t *testing.T) {
	rendered := stripANSI(Model{
		initialNodeRole: "cosigner",
		forms:           formsState{generatedAddress: "COSIGNERKEY", generatedKeyType: witness.Falcon1024V1},
	}.renderGenerateDisplay())
	if !strings.Contains(rendered, "Cosigner Key: COSIGNERKEY") {
		t.Fatalf("renderGenerateDisplay() missing cosigner key label:\n%s", rendered)
	}
	if strings.Contains(rendered, "Address: COSIGNERKEY") {
		t.Fatalf("renderGenerateDisplay() used address label in cosigner mode:\n%s", rendered)
	}
}

func TestRenderGenerateDisplayLabelsSignerAddress(t *testing.T) {
	rendered := stripANSI(Model{forms: formsState{generatedAddress: "ADDR", generatedKeyType: "ed25519"}}.renderGenerateDisplay())
	if !strings.Contains(rendered, "Address: ADDR") {
		t.Fatalf("renderGenerateDisplay() missing address label:\n%s", rendered)
	}
}

// The generated-account screen names the signer's warnings by their first
// sentences, each under its own "Warning:" label and in the signer's order: one
// can be new since the review, whose single line showed a first sentence or a
// count. The full text is behind w. An account without warnings shows no label.
func TestGeneratedScreenNamesEachWarning(t *testing.T) {
	fee := feeLimitWarning(0, "spend (at least 4000), spending_rekey (at least 3060), listed_rekey (at least 2160)")
	held := cosignerHeldWarning(testAddress(9))
	for _, test := range []struct {
		name     string
		warnings []string
	}{
		{"none", nil},
		{"empty", []string{}},
		{"fee limit", []string{fee}},
		{"cosigner held", []string{held}},
		{"both", []string{fee, held}},
		{"both, the other order", []string{held, fee}},
	} {
		t.Run(test.name, func(t *testing.T) {
			m := Model{width: 80, height: 400, standalone: true, forms: formsState{
				generatedAddress: testAddress(3), generatedKeyType: boundedHostKeyType, generatedWarnings: test.warnings,
			}}
			rendered := m.renderGenerateDisplay()
			for _, line := range strings.Split(stripANSI(rendered), "\n") {
				if lipgloss.Width(line) > MinWidth {
					t.Errorf("line wider than the smallest window: %q", line)
				}
			}
			view := flatReview(rendered)
			if got := strings.Count(view, "Warning:"); got != len(test.warnings) {
				t.Fatalf("%d warnings shown, want %d:\n%s", got, len(test.warnings), view)
			}
			// Each warning is named by its first sentence, which stands alone, in
			// order. The full text doesn't fit the smallest window here.
			at := 0
			for _, warning := range test.warnings {
				line := "Warning: " + firstSentence(warning)
				next := strings.Index(view[at:], line)
				if next < 0 {
					t.Fatalf("the screen lacks %q, or shows it out of order:\n%s", line, view)
				}
				at += next + len(line)
			}
			// No sentence is cut, and nothing points at a details view this screen
			// doesn't have.
			if strings.Contains(view, "See details") || strings.Contains(view, "things to read") || strings.Contains(view, "…") {
				t.Fatalf("the screen cuts a warning or points elsewhere:\n%s", view)
			}
			// The account and what follows the warnings are still there, after them.
			for _, want := range []string{"Address: " + testAddress(3), "Recovery material is stored encrypted"} {
				if !strings.Contains(view, want) {
					t.Fatalf("the screen lacks %q:\n%s", want, view)
				}
			}
			if strings.Index(view, "Recovery material") < at || strings.Index(view, "Address:") > strings.Index(view+"Warning:", "Warning:") {
				t.Fatalf("the warnings are not between the account and the recovery note:\n%s", view)
			}
		})
	}
}

// The signer's generate_result carries warnings, and the decoder copies them
// into the message the model takes them from.
func TestGenerateResultDecoderCopiesWarnings(t *testing.T) {
	warnings := []string{feeLimitWarning(0, "spend (at least 2000)"), cosignerHeldWarning(testAddress(9))}
	decode := func(t *testing.T, msg GenerateResultMessage) GenerateResultMsg {
		t.Helper()
		raw, err := protocol.MarshalAdminMessage(msg)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := signerMessageDecoders[MsgTypeGenerateResult](raw)
		if err != nil {
			t.Fatalf("decode %s: %v", raw, err)
		}
		result, ok := decoded.(GenerateResultMsg)
		if !ok {
			t.Fatalf("decoded %T, want GenerateResultMsg", decoded)
		}
		return result
	}
	base := BaseMessage{Type: MsgTypeGenerateResult, ID: "gen-1"}
	got := decode(t, GenerateResultMessage{BaseMessage: base, Success: true, Address: "ADDR", KeyType: boundedHostKeyType, Warnings: warnings})
	if got.ID != "gen-1" || !got.Success || got.Address != "ADDR" || got.KeyType != boundedHostKeyType || !slices.Equal(got.Warnings, warnings) {
		t.Fatalf("decoded = %+v, want warnings %q", got, warnings)
	}
	if quiet := decode(t, GenerateResultMessage{BaseMessage: base, Success: true, Address: "ADDR", KeyType: "ed25519"}); len(quiet.Warnings) != 0 {
		t.Fatalf("a result without warnings decodes %q", quiet.Warnings)
	}
	// From the wire as a signer writes it, field name and all.
	decoded, err := signerMessageDecoders[MsgTypeGenerateResult]([]byte(
		`{"type":"generate_result","id":"gen-2","success":true,"address":"ADDR","key_type":"ed25519","warnings":["one","two"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if result := decoded.(GenerateResultMsg); !slices.Equal(result.Warnings, []string{"one", "two"}) {
		t.Fatalf("decoded = %+v", result)
	}
}

// A generation result's warnings reach the generated-account screen through the
// model, whether or not the account was reviewed, and a later generation
// without warnings shows none of the earlier account's.
func TestGeneratedWarningsFollowTheGenerationResult(t *testing.T) {
	warnings := []string{cosignerHeldWarning(testAddress(9))}
	prepared := preparedAccount(boundedmeta.Layer3PolicyFixedAllowlist, boundary.RekeySpendingKey, true, 2)
	// The review showed no warning: this one is new since.
	m, result := reviewedResult(testAddress(3), prepared)
	result.Warnings = warnings
	next, _ := m.Update(result)
	m = next.(Model)
	if m.viewState != ViewGenerateDisplay || !slices.Equal(m.forms.generatedWarnings, warnings) {
		t.Fatalf("view = %v, warnings = %q", m.viewState, m.forms.generatedWarnings)
	}
	if view := flatReview(m.renderGenerateDisplay()); !strings.Contains(view, "Warning: "+firstSentence(warnings[0])) {
		t.Fatalf("the screen lacks the warning:\n%s", view)
	}

	// A failed generation shows no account, so no warnings either.
	failed, _ := m.Update(GenerateResultMsg{ID: "gen-2", Success: false, Error: "signer refused", Warnings: []string{"not shown"}})
	if got := failed.(Model); got.viewState == ViewGenerateDisplay || strings.Contains(flatReview(got.View()), "not shown") {
		t.Fatalf("a failed generation shows a warning: view %v", got.viewState)
	}

	next, _ = m.Update(GenerateResultMsg{ID: "gen-3", Success: true, Address: "NATIVE", KeyType: "ed25519"})
	m = next.(Model)
	if len(m.forms.generatedWarnings) != 0 {
		t.Fatalf("a later account kept the earlier one's warnings: %q", m.forms.generatedWarnings)
	}
	if view := flatReview(m.renderGenerateDisplay()); strings.Contains(view, "Warning:") || !strings.Contains(view, "Address: NATIVE") {
		t.Fatalf("the later account's screen:\n%s", view)
	}
}

// Leaving the generated-account screen clears what it showed, the warnings
// with the address and key type, so nothing of one account is left for another
// screen to find.
func TestLeavingTheGeneratedScreenClearsItsWarnings(t *testing.T) {
	for _, key := range []tea.KeyMsg{{Type: tea.KeyEnter}, {Type: tea.KeyEsc}, {Type: tea.KeyRunes, Runes: []rune("q")}, {Type: tea.KeyRunes, Runes: []rune(" ")}} {
		m := Model{viewState: ViewGenerateDisplay, forms: formsState{
			generatedAddress: testAddress(3), generatedKeyType: boundedHostKeyType,
			generatedWarnings: []string{cosignerHeldWarning(testAddress(9))},
		}}
		next, _ := m.handleGenerateDisplayKeys(key)
		got := next.(Model)
		if got.viewState != ViewKeyList || got.forms.generatedAddress != "" || got.forms.generatedKeyType != "" {
			t.Fatalf("%q: view = %v, address = %q, key type = %q", key.String(), got.viewState, got.forms.generatedAddress, got.forms.generatedKeyType)
		}
		if len(got.forms.generatedWarnings) != 0 {
			t.Errorf("%q: the warnings outlived the screen: %q", key.String(), got.forms.generatedWarnings)
		}
	}
}

// The generated-account screen with the signer's warnings in full still fits
// the smallest window, every line of it, without the panel scroller. Both
// warnings can come together, and an account that has either was reviewed, so
// the screen also offers its receipt.
func TestGeneratedScreenWithWarningsFitsAt80x24(t *testing.T) {
	held := cosignerHeldWarning(testAddress(9))
	onePath := feeLimitWarning(0, "spend (at least 2000)")
	everyPath := feeLimitWarning(1999, "spend (at least 4000), spending_rekey (at least 3060), listed_rekey (at least 2160)")
	prepared := preparedAccount(boundedmeta.Layer3PolicyFixedAllowlist, boundary.RekeySpendingKey, true, 2)
	for _, test := range []struct {
		name     string
		warnings []string
	}{
		{"no warnings", nil},
		{"cosigner held", []string{held}},
		{"fee limit, one path", []string{onePath}},
		{"fee limit, every path", []string{everyPath}},
		{"fee limit and cosigner held", []string{onePath, held}},
		{"fee limit on every path and cosigner held", []string{everyPath, held}},
	} {
		for _, standalone := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/standalone=%v", test.name, standalone), func(t *testing.T) {
				base, result := reviewedResult(testAddress(3), prepared)
				base.standalone, base.connectionState = standalone, ConnectionConnected
				result.Warnings = test.warnings
				next, _ := base.Update(result)
				base = next.(Model)
				if base.viewState != ViewGenerateDisplay {
					t.Fatalf("view = %v", base.viewState)
				}
				if _, ok := base.generatedReceipt(); !ok {
					t.Fatal("the reviewed account has no receipt to offer")
				}
				m := sizedForTest(t, base, MinWidth, MinHeight)
				view := stripANSI(m.View())
				lines := strings.Split(view, "\n")
				if len(lines) > MinHeight {
					t.Errorf("%d lines in a %d-line window", len(lines), MinHeight)
				}
				for _, line := range lines {
					if lipgloss.Width(line) > MinWidth {
						t.Errorf("line wider than the window: %q", line)
					}
				}
				tall := sizedForTest(t, base, MinWidth, 400)
				need := strings.Count(strings.TrimRight(stripANSI(tall.renderViewContent()), "\n"), "\n") + 1
				if strings.Contains(view, "Panel lines") || need > m.windowBodyHeight() {
					t.Fatalf("the screen needs %d rows and has %d, so it scrolls or is cut off:\n%s", need, m.windowBodyHeight(), view)
				}
				flat := flatReview(view)
				for _, warning := range test.warnings {
					if line := "Warning: " + firstSentence(warning); !strings.Contains(flat, line) {
						t.Errorf("the screen lacks %q:\n%s", line, view)
					}
				}
				for _, want := range []string{"Address: " + testAddress(3), "Use encrypted backups for recovery.", "save a resolved receipt"} {
					if !strings.Contains(flat, want) {
						t.Errorf("the screen lacks %q:\n%s", want, view)
					}
				}
			})
		}
	}
}

// More warnings than the generated-account screen has rows for become one count
// line, so the screen's height doesn't grow with them; w still shows each one.
func TestGeneratedScreenCountsWarningsItHasNoRowsFor(t *testing.T) {
	warnings := []string{
		feeLimitWarning(0, "spend (at least 2000)"),
		cosignerHeldWarning(testAddress(9)),
		"A third thing. With more to say about it.",
		"A fourth thing. With more to say about it.",
	}
	if len(warnings) <= generatedWarningRows {
		t.Fatalf("the test needs more than %d warnings", generatedWarningRows)
	}
	base, result := reviewedResult(testAddress(3), preparedAccount(boundedmeta.Layer3PolicyFixedAllowlist, boundary.RekeySpendingKey, true, 2))
	base.standalone, base.connectionState = true, ConnectionConnected
	result.Warnings = warnings
	next, _ := base.Update(result)
	base = next.(Model)
	m := sizedForTest(t, base, MinWidth, MinHeight)
	view := stripANSI(m.View())
	tall := sizedForTest(t, base, MinWidth, 400)
	need := strings.Count(strings.TrimRight(stripANSI(tall.renderViewContent()), "\n"), "\n") + 1
	if strings.Contains(view, "Panel lines") || need > m.windowBodyHeight() {
		t.Fatalf("the screen needs %d rows and has %d:\n%s", need, m.windowBodyHeight(), view)
	}
	flat := flatReview(view)
	if got := strings.Count(flat, "Warning:"); got != 1 {
		t.Fatalf("%d warning lines, want one count:\n%s", got, view)
	}
	if want := fmt.Sprintf("Warning: %d things to read about this account. Press w.", len(warnings)); !strings.Contains(flat, want) {
		t.Fatalf("the screen lacks %q:\n%s", want, view)
	}
	if !strings.Contains(flat, "save a resolved receipt") || !strings.Contains(m.viewFooterText(), "w: Warnings in full") {
		t.Fatalf("the receipt prompt or the footer's w is missing:\n%s\nfooter: %s", view, m.viewFooterText())
	}
}

// w on the generated-account screen shows each warning in full, in the signer's
// order, in the smallest window. That is the only place the whole text of a
// warning new since the review can be read. Leaving it goes back to the
// account, not to the key list, and w does nothing on an account without
// warnings.
func TestGeneratedScreenShowsWarningsInFull(t *testing.T) {
	fee := feeLimitWarning(1999, "spend (at least 4000), spending_rekey (at least 3060), listed_rekey (at least 2160)")
	held := cosignerHeldWarning(testAddress(9))
	w := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("w")}
	base, result := reviewedResult(testAddress(3), preparedAccount(boundedmeta.Layer3PolicyFixedAllowlist, boundary.RekeySpendingKey, true, 2))
	base.standalone, base.connectionState = true, ConnectionConnected
	result.Warnings = []string{fee, held}
	next, _ := base.Update(result)
	base = next.(Model)
	if base.forms.generatedWarningsOpen {
		t.Fatal("the warnings open by themselves")
	}

	next, _ = base.handleGenerateDisplayKeys(w)
	open := next.(Model)
	if !open.forms.generatedWarningsOpen || open.viewState != ViewGenerateDisplay {
		t.Fatalf("after w: open = %v, view = %v", open.forms.generatedWarningsOpen, open.viewState)
	}
	m := sizedForTest(t, open, MinWidth, MinHeight)
	view := stripANSI(m.View())
	lines := strings.Split(view, "\n")
	if len(lines) > MinHeight {
		t.Errorf("%d lines in a %d-line window", len(lines), MinHeight)
	}
	for _, line := range lines {
		if lipgloss.Width(line) > MinWidth {
			t.Errorf("line wider than the window: %q", line)
		}
	}
	tall := sizedForTest(t, open, MinWidth, 400)
	need := strings.Count(strings.TrimRight(stripANSI(tall.renderViewContent()), "\n"), "\n") + 1
	if strings.Contains(view, "Panel lines") || need > m.windowBodyHeight() {
		t.Fatalf("the warnings need %d rows and have %d:\n%s", need, m.windowBodyHeight(), view)
	}
	flat := flatReview(view)
	at := 0
	for _, warning := range []string{fee, held} {
		next := strings.Index(flat[at:], warning)
		if next < 0 {
			t.Fatalf("the full text of %q is missing or out of order:\n%s", warning, view)
		}
		at += next + len(warning)
	}
	if !strings.Contains(flat, "Address: "+testAddress(3)) || strings.Contains(flat, "…") {
		t.Fatalf("the account is missing or a warning is cut:\n%s", view)
	}
	if got := m.viewFooterText(); got != "w/Esc: Back" {
		t.Fatalf("footer = %q", got)
	}

	for _, key := range []tea.KeyMsg{w, {Type: tea.KeyEsc}, {Type: tea.KeyEnter}, {Type: tea.KeyRunes, Runes: []rune("q")}} {
		next, _ := open.handleGenerateDisplayKeys(key)
		back := next.(Model)
		if back.forms.generatedWarningsOpen || back.viewState != ViewGenerateDisplay || back.forms.generatedAddress != testAddress(3) || len(back.forms.generatedWarnings) != 2 {
			t.Fatalf("%q left the account: open = %v, view = %v", key.String(), back.forms.generatedWarningsOpen, back.viewState)
		}
	}
	// s is the summary's key; here it saves nothing.
	next, _ = open.handleGenerateDisplayKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("s")})
	if got := next.(Model); got.forms.receiptPath != "" || got.forms.receiptError != "" || !got.forms.generatedWarningsOpen {
		t.Fatalf("s acted behind the warnings: path %q, error %q", got.forms.receiptPath, got.forms.receiptError)
	}

	none := base
	none.forms.generatedWarnings = nil
	next, _ = none.handleGenerateDisplayKeys(w)
	if got := next.(Model); got.forms.generatedWarningsOpen {
		t.Fatal("w opened warnings an account doesn't have")
	}
	if strings.Contains(none.viewFooterText(), "Warnings") {
		t.Fatalf("footer offers warnings an account doesn't have: %q", none.viewFooterText())
	}
}
