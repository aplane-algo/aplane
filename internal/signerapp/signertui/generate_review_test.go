// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/boundary"
	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/lsig/boundedaccount"
	tea "github.com/charmbracelet/bubbletea"
)

// preparedAccount is a prepared bounded generation with the given rekey setting.
func preparedAccount(policy, rekey string, cosigner bool, recipients int) PrepareGenerateResultMessage {
	list := make([]string, recipients)
	for i := range list {
		list[i] = fmt.Sprintf("RECIPIENT%048d", i)
	}
	prepared := PrepareGenerateResultMessage{
		Success:           true,
		KeyType:           boundary.KeyTypeV1,
		Parameters:        map[string]string{recipientsParameter: strings.Join(list, ",")},
		Fingerprint:       "1:" + strings.Repeat("c", 64),
		ReviewFingerprint: "1:" + strings.Repeat("d", 64),
		BoundaryDigest:    strings.Repeat("e", 64),
		Bounded: &protocol.PreparedBoundedProfile{
			SpendEffects:     []string{"pay", "axfer", "asset_opt_in"},
			MaxFee:           10_000,
			Rekey:            rekey,
			Layer3Policy:     policy,
			CosignerRequired: cosigner,
		},
	}
	if cosigner {
		prepared.CosignerKeyID = strings.Repeat("c3d4", 16)
	}
	return prepared
}

func TestReviewKeepsItsButtonsAt80x24(t *testing.T) {
	for _, test := range []struct {
		name          string
		policy, rekey string
		cosigner      bool
		recipients    int
	}{
		{"inline spending", boundedmeta.Layer3PolicyFixedAllowlist, boundary.RekeySpendingKey, false, 2},
		{"merkle spending", boundedmeta.Layer3PolicyMerkleAllowlist, boundary.RekeySpendingKey, false, 500},
		{"inline refused", boundedmeta.Layer3PolicyFixedAllowlist, boundary.RekeyRefused, false, 2},
		{"merkle refused", boundedmeta.Layer3PolicyMerkleAllowlist, boundary.RekeyRefused, false, 11},
		{"inline cosigner", boundedmeta.Layer3PolicyFixedAllowlist, boundary.RekeyRefused, true, 2},
		{"merkle cosigner", boundedmeta.Layer3PolicyMerkleAllowlist, boundary.RekeyRefused, true, 11},
		{"custom merkle cosigner", boundedmeta.Layer3PolicyMerkleAllowlistCustom, boundary.RekeyRefused, true, 11},
	} {
		t.Run(test.name, func(t *testing.T) {
			prepared := preparedAccount(test.policy, test.rekey, test.cosigner, test.recipients)
			m := Model{viewState: ViewGenerateReview, width: 80, height: 23, standalone: true, forms: formsState{review: &prepared}}
			view := m.renderGenerateReview()
			for _, want := range []string{"CANCEL", "DETAILS", "GENERATE", "pay, axfer, asset opt-in", "fee limit 10000", fmt.Sprintf("Recipients: %d", test.recipients)} {
				if !strings.Contains(view, want) {
					t.Errorf("review lacks %q:\n%s", want, view)
				}
			}
			if strings.Contains(view, "Panel lines") {
				t.Errorf("review scrolls at 80x24:\n%s", view)
			}
		})
	}
}

// The main review stays plain. A fingerprint there would invite an operator to
// treat it as the thing being approved.
func TestReviewKeepsDigestsInDetails(t *testing.T) {
	prepared := preparedAccount(boundedmeta.Layer3PolicyMerkleAllowlist, boundary.RekeyRefused, true, 11)
	m := Model{viewState: ViewGenerateReview, width: 80, height: 23, standalone: true, forms: formsState{review: &prepared}}
	main := m.renderGenerateReview()
	for _, hidden := range []string{prepared.Fingerprint, prepared.ReviewFingerprint, prepared.BoundaryDigest} {
		if strings.Contains(main, hidden) {
			t.Errorf("main review shows %q", hidden)
		}
	}
	if !strings.Contains(main, "partly hidden") {
		t.Errorf("Merkle exposure is not stated:\n%s", main)
	}

	m.viewState = ViewGenerateReviewDetails
	m.height = 400
	details := m.renderGenerateReviewDetails()
	for _, want := range []string{prepared.Fingerprint, prepared.ReviewFingerprint, prepared.BoundaryDigest, prepared.CosignerKeyID, "RECIPIENT" + strings.Repeat("0", 47) + "9"} {
		if !strings.Contains(details, want) {
			t.Errorf("details lack %q:\n%s", want, details)
		}
	}
}

func TestTimelockPoliciesReviewHonestly(t *testing.T) {
	for _, test := range []struct {
		policy, encoding, note string
	}{
		{boundedmeta.Layer3PolicyFixedAllowlistTimelock, "inline", "whole list is public"},
		{boundedmeta.Layer3PolicyMerkleAllowlistTimelock, "Merkle", "partly hidden"},
	} {
		prepared := preparedAccount(test.policy, boundary.RekeyRefused, true, 11)
		prepared.Parameters[unlockRoundParameter] = "50000000"
		m := Model{viewState: ViewGenerateReview, width: 80, height: 23, standalone: true, forms: formsState{review: &prepared}}
		view := m.renderGenerateReview()
		for _, want := range []string{"11, " + test.encoding, test.note, "round 50000000", "GENERATE"} {
			if !strings.Contains(view, want) {
				t.Errorf("%s review lacks %q:\n%s", test.policy, want, view)
			}
		}
		if strings.Contains(view, "Panel lines") {
			t.Errorf("%s review scrolls at 80x24:\n%s", test.policy, view)
		}
	}
}

func TestTimelockReviewStatesWhatTheLockDoesNot(t *testing.T) {
	prepared := preparedAccount(boundedmeta.Layer3PolicyTimelock, boundary.RekeyRefused, false, 0)
	prepared.Parameters = map[string]string{unlockRoundParameter: "50000000"}
	m := Model{viewState: ViewGenerateReview, width: 80, height: 23, standalone: true, forms: formsState{review: &prepared}}
	view := strings.Join(strings.Fields(strings.ReplaceAll(m.renderGenerateReview(), "║", " ")), " ")
	for _, want := range []string{"any, once unlocked", "None", "No rekey path", "round 50000000", "GENERATE"} {
		if !strings.Contains(view, want) {
			t.Errorf("review lacks %q:\n%s", want, view)
		}
	}
	if strings.Contains(view, "Panel lines") {
		t.Errorf("review scrolls at 80x24:\n%s", view)
	}
}

// Codex's reproduction: an imported template names its list beneficiaries. An
// account with a list must never be described as able to pay anyone.
func TestRestrictedAccountsNeverReadAsUnrestricted(t *testing.T) {
	for _, policy := range []string{
		boundedmeta.Layer3PolicyFixedAllowlist, boundedmeta.Layer3PolicyMerkleAllowlist,
		boundedmeta.Layer3PolicyFixedAllowlistCustom, boundedmeta.Layer3PolicyMerkleAllowlistCustom,
		boundedmeta.Layer3PolicyFixedAllowlistTimelock, boundedmeta.Layer3PolicyMerkleAllowlistTimelock,
		"a_policy_added_later",
	} {
		t.Run(policy, func(t *testing.T) {
			prepared := preparedAccount(policy, boundary.RekeyRefused, false, 0)
			prepared.Parameters = map[string]string{"beneficiaries": "A,B", unlockRoundParameter: "50"}
			m := Model{viewState: ViewGenerateReview, width: 80, height: 23, standalone: true, forms: formsState{review: &prepared}}
			view := m.renderGenerateReview()
			if strings.Contains(view, "any, once unlocked") {
				t.Fatalf("a restricted account reads as unrestricted:\n%s", view)
			}
			// A policy this client does not know may pay anyone, so it is named
			// rather than called restricted.
			want := "restricted"
			if !boundedmeta.IsRecipientListPolicy(policy) {
				want = policy
			}
			if !strings.Contains(view, want) || !strings.Contains(view, "see details") {
				t.Fatalf("review does not point to the details:\n%s", view)
			}
			if strings.Contains(view, "Panel lines") {
				t.Fatalf("review scrolls at 80x24:\n%s", view)
			}
			m.viewState = ViewGenerateReviewDetails
			m.height = 400
			if details := m.renderGenerateReviewDetails(); !strings.Contains(details, "beneficiaries") {
				t.Fatalf("details do not show the list:\n%s", details)
			}
		})
	}
}

func TestParameterNamesDoNotInventAList(t *testing.T) {
	row, note := reviewRecipients(boundedmeta.Layer3PolicyCustom, []string{"A", "B"})
	if !strings.Contains(row, "Custom policy") || strings.Contains(row, "inline") || note != "" {
		t.Fatalf("row = %q, note = %q", row, note)
	}
	row, _ = reviewRecipients(boundedmeta.Layer3PolicyTimelock, nil)
	if !strings.Contains(row, "any, once unlocked") {
		t.Fatalf("row = %q", row)
	}
}

// A limits-only account pays anyone, and the review says what still bounds it.
func TestLimitsOnlyReviewSaysAnyRecipient(t *testing.T) {
	for _, cosigner := range []bool{false, true} {
		rekey := boundary.RekeySpendingKey
		if cosigner {
			rekey = boundary.RekeyRefused
		}
		prepared := preparedAccount(boundedmeta.Layer3PolicyNone, rekey, cosigner, 0)
		prepared.Parameters = map[string]string{boundary.ParameterRecipientScope: boundary.RecipientScopeAny}
		m := Model{viewState: ViewGenerateReview, width: 80, height: 23, standalone: true, forms: formsState{review: &prepared}}
		view := m.renderGenerateReview()
		for _, want := range []string{"Recipients: any; only the fee limit and transfer kinds apply", "fee limit 10000", "GENERATE"} {
			if !strings.Contains(view, want) {
				t.Errorf("review lacks %q:\n%s", want, view)
			}
		}
		if strings.Contains(view, "once unlocked") || strings.Contains(view, "Unlocks at") || strings.Contains(view, "Panel lines") {
			t.Errorf("limits-only review is wrong or scrolls at 80x24:\n%s", view)
		}
	}
}

func TestCustomPolicyIsLabelledAsCustom(t *testing.T) {
	prepared := preparedAccount(boundedmeta.Layer3PolicyCustom, boundary.RekeySpendingKey, false, 0)
	m := Model{viewState: ViewGenerateReview, width: 80, height: 23, standalone: true, forms: formsState{review: &prepared}}
	if view := m.renderGenerateReview(); !strings.Contains(view, "Custom policy") {
		t.Fatalf("review does not label custom code:\n%s", view)
	}
}

// A reference edited after review must not change what is generated, so the
// request carries the resolved values, and the comparison values go with it.
func TestReviewedRequestCarriesTheResolvedValues(t *testing.T) {
	prepared := preparedAccount(boundedmeta.Layer3PolicyMerkleAllowlist, boundary.RekeyRefused, true, 2)
	prepared.Parameters[boundedmeta.CosignerPublicKeyParameter] = "resolved"
	message := reviewedGenerateMessage(prepared, "id")
	if message.Parameters[boundedmeta.CosignerPublicKeyParameter] != "resolved" {
		t.Fatalf("parameters = %v", message.Parameters)
	}
	if message.ExpectedFingerprint != prepared.ReviewFingerprint || message.ExpectedBoundaryDigest != prepared.BoundaryDigest {
		t.Fatalf("expected values = %q, %q", message.ExpectedFingerprint, message.ExpectedBoundaryDigest)
	}
	if message.KeyType != prepared.KeyType || message.Type != MsgTypeGenerateKey {
		t.Fatalf("message = %+v", message)
	}
}

func TestNonBoundedRequestSkipsReview(t *testing.T) {
	m := Model{viewState: ViewGenerating, forms: formsState{pendingGenerateParams: map[string]string{"a": "b"}}}
	next, cmd := m.handlePreparedGeneration(PrepareGenerateResultMessage{Success: true, KeyType: "aplane.htlc.v1"})
	got := next.(Model)
	if got.viewState != ViewGenerating || got.forms.review != nil || cmd == nil {
		t.Fatalf("view = %v, review = %v", got.viewState, got.forms.review)
	}
}

func TestPreparationFailureReturnsToTheForm(t *testing.T) {
	m := Model{viewState: ViewGenerating, forms: formsState{genericLSigParams: map[string]string{}}}
	next, _ := m.handlePreparedGeneration(PrepareGenerateResultMessage{Error: "needs approval"})
	got := next.(Model)
	if got.viewState != ViewGenerateParams || got.forms.generateError != "needs approval" {
		t.Fatalf("view = %v, error = %q", got.viewState, got.forms.generateError)
	}
}

func TestReviewStartsOnCancelAndGeneratesOnlyFromGenerate(t *testing.T) {
	m := Model{viewState: ViewGenerating}
	next, _ := m.handlePreparedGeneration(preparedAccount(boundedmeta.Layer3PolicyFixedAllowlist, boundary.RekeySpendingKey, false, 2))
	got := next.(Model)
	if got.viewState != ViewGenerateReview || got.forms.reviewFocus != reviewFocusCancel {
		t.Fatalf("view = %v, focus = %d", got.viewState, got.forms.reviewFocus)
	}
	cancelled, _ := got.handleGenerateReviewKeys(tea.KeyMsg{Type: tea.KeyEnter})
	if view := cancelled.(Model); view.viewState == ViewGenerating || view.forms.review != nil {
		t.Fatalf("Enter on Cancel: view = %v", view.viewState)
	}

	got.forms.reviewFocus = reviewFocusGenerate
	generating, cmd := got.handleGenerateReviewKeys(tea.KeyMsg{Type: tea.KeyEnter})
	if view := generating.(Model); view.viewState != ViewGenerating || cmd == nil {
		t.Fatalf("Enter on Generate: view = %v", view.viewState)
	}
}

func reviewedResult(address string, prepared PrepareGenerateResultMessage) (Model, GenerateResultMsg) {
	m := Model{viewState: ViewGenerating, width: 80, height: 23, standalone: true}
	m.forms.review = &prepared
	m.forms.reviewedRequestID = "reviewed"
	return m, GenerateResultMsg{ID: "reviewed", Success: true, Address: address, KeyType: prepared.KeyType}
}

func TestReceiptNamesTheSavedAccountAndNeverOverwrites(t *testing.T) {
	t.Chdir(t.TempDir())
	prepared := preparedAccount(boundedmeta.Layer3PolicyFixedAllowlist, boundary.RekeyRefused, true, 2)
	m, result := reviewedResult("ADDRESS", prepared)
	m = m.settleGenerateReview(result)
	m.forms.generatedAddress = result.Address
	m = m.saveGeneratedReceipt()
	if m.forms.receiptError != "" {
		t.Fatal(m.forms.receiptError)
	}
	data, err := os.ReadFile(filepath.Base(m.forms.receiptPath))
	if err != nil {
		t.Fatal(err)
	}
	var receipt boundary.Receipt
	if err := json.Unmarshal(data, &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.Schema != boundary.ReceiptSchemaV1 || receipt.Address != "ADDRESS" || receipt.KeyType != boundary.KeyTypeV1 ||
		receipt.GrammarFingerprint != prepared.ReviewFingerprint || receipt.ShapeFingerprint != prepared.Fingerprint ||
		receipt.BoundaryDigest != prepared.BoundaryDigest || receipt.CosignerKeyID != prepared.CosignerKeyID {
		t.Fatalf("receipt = %+v", receipt)
	}
	info, err := os.Stat(filepath.Base(m.forms.receiptPath))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("receipt mode = %v", info.Mode().Perm())
	}
	if again := m.saveGeneratedReceipt(); again.forms.receiptError == "" {
		t.Fatal("a second save overwrote the receipt")
	}
}

// Every way a review can fail to produce an account must leave nothing behind
// for a later account to inherit.
func TestReceiptNeverCrossesAccounts(t *testing.T) {
	prepared := preparedAccount(boundedmeta.Layer3PolicyFixedAllowlist, boundary.RekeySpendingKey, false, 2)
	for _, test := range []struct {
		name   string
		mutate func(*GenerateResultMsg)
	}{
		{"failed generation", func(r *GenerateResultMsg) { r.Success = false }},
		{"another request", func(r *GenerateResultMsg) { r.ID = "other" }},
		{"another key type", func(r *GenerateResultMsg) { r.KeyType = "ed25519" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			m, result := reviewedResult("ADDRESS", prepared)
			test.mutate(&result)
			m = m.settleGenerateReview(result)
			if m.forms.review != nil || m.forms.reviewedRequestID != "" {
				t.Fatal("the review outlived its generation")
			}
			m.forms.generatedAddress = result.Address
			if _, ok := m.generatedReceipt(); ok {
				t.Fatal("a receipt survived")
			}
		})
	}
}

// Codex's reproduction: a bounded generation fails, the operator backs out and
// generates a native account, and the save must offer nothing.
func TestFailedReviewCannotLabelALaterNativeAccount(t *testing.T) {
	prepared := preparedAccount(boundedmeta.Layer3PolicyFixedAllowlist, boundary.RekeySpendingKey, false, 2)
	m, failed := reviewedResult("", prepared)
	failed.Success, failed.Error = false, "signer refused"
	next, _ := m.Update(failed)
	m = next.(Model)
	next, _ = m.Update(GenerateResultMsg{ID: "gen-2", Success: true, Address: "NATIVE", KeyType: "ed25519"})
	m = next.(Model)
	if m.forms.generatedAddress != "NATIVE" {
		t.Fatalf("address = %q", m.forms.generatedAddress)
	}
	if _, ok := m.generatedReceipt(); ok {
		t.Fatal("a native account inherited the failed review")
	}
	if footer := m.renderGenerateDisplay(); strings.Contains(footer, "save a resolved receipt") {
		t.Fatalf("the screen offers a receipt:\n%s", footer)
	}
}

// The whole path, through the same entry points the running program uses: the id
// the request goes out with is the one its result must come back with.
func TestReviewedGenerationEarnsAReceipt(t *testing.T) {
	prepared := preparedAccount(boundedmeta.Layer3PolicyFixedAllowlist, boundary.RekeySpendingKey, false, 2)
	m := Model{viewState: ViewGenerateReview, forms: formsState{review: &prepared, reviewFocus: reviewFocusGenerate}}
	next, _ := m.handleGenerateReviewKeys(tea.KeyMsg{Type: tea.KeyEnter})
	sent := next.(Model)
	if sent.forms.reviewedRequestID == "" || sent.forms.reviewedRequestID != sent.operation.id {
		t.Fatalf("request id = %q, operation = %q", sent.forms.reviewedRequestID, sent.operation.id)
	}
	done, _ := sent.Update(GenerateResultMsg{ID: sent.operation.id, Success: true, Address: "ADDRESS", KeyType: prepared.KeyType})
	got := done.(Model)
	receipt, ok := got.generatedReceipt()
	if !ok || receipt.Address != "ADDRESS" || receipt.BoundaryDigest != prepared.BoundaryDigest {
		t.Fatalf("receipt = %+v, %v", receipt, ok)
	}
	if got.forms.review != nil {
		t.Fatal("the review outlived its generation")
	}
}

func TestReceiptMustMatchTheAccountOnScreen(t *testing.T) {
	prepared := preparedAccount(boundedmeta.Layer3PolicyFixedAllowlist, boundary.RekeySpendingKey, false, 2)
	m, result := reviewedResult("ADDRESS", prepared)
	m = m.settleGenerateReview(result)
	m.forms.generatedAddress = "OTHER"
	if _, ok := m.generatedReceipt(); ok {
		t.Fatal("a receipt for ADDRESS applied to OTHER")
	}
}

func TestDetailsShowEveryResolvedParameter(t *testing.T) {
	prepared := preparedAccount(boundedmeta.Layer3PolicyCustom, boundary.RekeySpendingKey, false, 2)
	prepared.Parameters["unlock_round"] = "50000000"
	prepared.Parameters["author_hash"] = strings.Repeat("ab", 64)
	prepared.Parameters[boundedmeta.CosignerPublicKeyParameter] = strings.Repeat("cd", 900)
	m := Model{viewState: ViewGenerateReviewDetails, width: 80, height: 400, forms: formsState{review: &prepared}}
	details := m.renderGenerateReviewDetails()
	for _, want := range []string{"unlock_round", "50000000", "author_hash"} {
		if !strings.Contains(details, want) {
			t.Errorf("details lack %q:\n%s", want, details)
		}
	}
	joined := strings.NewReplacer("\n", "", " ", "", "║", "").Replace(details)
	if !strings.Contains(joined, prepared.Parameters["author_hash"]) {
		t.Errorf("a long value was cut:\n%s", details)
	}
	if strings.Contains(details, "cdcdcdcd") {
		t.Error("an authority key repeats what its Witness Key ID says")
	}
}

func TestCustomTimelockShowsItsUnlockRound(t *testing.T) {
	prepared := preparedAccount(boundedmeta.Layer3PolicyCustom, boundary.RekeySpendingKey, false, 0)
	prepared.Parameters[unlockRoundParameter] = "50000000"
	m := Model{viewState: ViewGenerateReview, width: 80, height: 23, standalone: true, forms: formsState{review: &prepared}}
	view := m.renderGenerateReview()
	if !strings.Contains(view, "round 50000000") {
		t.Fatalf("review lacks the unlock round:\n%s", view)
	}
	if strings.Contains(view, "Panel lines") {
		t.Fatalf("review scrolls at 80x24:\n%s", view)
	}
}

// No host rule gates a rekey, so a spending-key rekey is stated as the key alone,
// whatever the account's policy.
func TestRekeySummaryStatesTheSpendingKeyAlone(t *testing.T) {
	for _, policy := range []string{boundedmeta.Layer3PolicyCustom, boundedmeta.Layer3PolicyFixedAllowlist, boundedmeta.Layer3PolicyMerkleAllowlist} {
		prepared := preparedAccount(policy, boundary.RekeySpendingKey, false, 0)
		label, note := reviewRekey(prepared)
		if label != "Spending key alone" || !strings.Contains(note, "out of this boundary") {
			t.Fatalf("%s: spending-key rekey = %q, %q", policy, label, note)
		}
		m := Model{viewState: ViewGenerateReview, width: 80, height: 23, standalone: true, forms: formsState{review: &prepared}}
		if view := m.renderGenerateReview(); !strings.Contains(view, "Spending key alone") || strings.Contains(view, "Panel lines") {
			t.Fatalf("%s review:\n%s", policy, view)
		}
	}
}

// A cosigned account's rekey row says who is asked: both keys for a declared
// rekey, the spending key alone for a listed one. Each still fits at 80x24.
func TestCosignedRekeySummariesFitAt80x24(t *testing.T) {
	targets := []string{fmt.Sprintf("TARGET%052d", 1), fmt.Sprintf("TARGET%052d", 2)}
	for _, test := range []struct {
		name, policy, rekey string
		list                bool
		label, note         string
	}{
		{"cosigned spending key", boundedmeta.Layer3PolicyMerkleAllowlist, boundary.RekeySpendingKey, false, "Spending key and cosigner", "cosigner's policy allows"},
		{"cosigned only these", boundedmeta.Layer3PolicyMerkleAllowlist, boundary.RekeyRefused, true, "Only these 2 addresses, spending key alone", "at any time"},
		{"cosigned only these timelock", boundedmeta.Layer3PolicyMerkleAllowlistTimelock, boundary.RekeyRefused, true, "Only these 2 addresses, spending key alone", "way around the lock"},
		{"plus cosigned", boundedmeta.Layer3PolicyMerkleAllowlist, boundary.RekeySpendingKey, true, "These 2, spending key alone; others need the cosigner", "needs both online keys"},
	} {
		t.Run(test.name, func(t *testing.T) {
			prepared := preparedAccount(test.policy, test.rekey, true, 11)
			if test.list {
				prepared.Bounded.RekeyList = true
				prepared.Parameters[boundedmeta.RekeyListEntriesParameter] = strings.Join(targets, ",")
			}
			if isTimelockPolicy(test.policy) {
				prepared.Parameters[unlockRoundParameter] = "50000000"
			}
			label, note := reviewRekey(prepared)
			if label != test.label || !strings.Contains(note, test.note) {
				t.Fatalf("rekey = %q, %q", label, note)
			}
			m := Model{viewState: ViewGenerateReview, width: 80, height: 23, standalone: true, forms: formsState{review: &prepared}}
			view := m.renderGenerateReview()
			if !strings.Contains(view, test.label) || !strings.Contains(view, "GENERATE") || strings.Contains(view, "Panel lines") {
				t.Fatalf("review is wrong or scrolls at 80x24:\n%s", view)
			}
		})
	}
}

// A refused account and an authority this client doesn't know must each say so,
// never read as an ordinary spending-key rekey.
func TestRekeySummaryNamesRefusedAndUnknownAuthorities(t *testing.T) {
	refused := preparedAccount(boundedmeta.Layer3PolicyFixedAllowlist, boundary.RekeyRefused, false, 2)
	if label, note := reviewRekey(refused); label != "None" || !strings.Contains(note, "No rekey path") {
		t.Fatalf("refused rekey = %q, %q", label, note)
	}
	unknown := preparedAccount(boundedmeta.Layer3PolicyFixedAllowlist, "admin_key", false, 2)
	if label, note := reviewRekey(unknown); !strings.Contains(label, "Unknown authority admin_key") || strings.Contains(label, "Spending key") || !strings.Contains(note, "cannot describe") {
		t.Fatalf("unknown rekey = %q, %q", label, note)
	}
	// A profile with no setting is not a refused one.
	missing := preparedAccount(boundedmeta.Layer3PolicyFixedAllowlist, "", false, 2)
	if label, note := reviewRekey(missing); !strings.HasPrefix(label, "Unknown authority") || !strings.Contains(note, "cannot describe") {
		t.Fatalf("missing rekey = %q, %q", label, note)
	}
}

func TestBoundaryPresetScreenFitsAt80x24(t *testing.T) {
	m := Model{viewState: ViewBoundaryPreset, width: 80, height: 24}
	view := m.renderBoundaryPreset()
	for _, want := range []string{"Allowlist", "Locked Allowlist", "Corridor", "Timelock", "Load boundary file"} {
		if !strings.Contains(view, want) {
			t.Errorf("preset screen lacks %q:\n%s", want, view)
		}
	}
	if strings.Contains(view, "Panel lines") {
		t.Errorf("preset screen scrolls at 80x24:\n%s", view)
	}
}

func TestPresetAsksOnlyForWhatItLeavesOpen(t *testing.T) {
	boundedaccount.RegisterClient()
	useRegistryKeyTypes(t)
	for _, test := range []struct {
		preset int
		want   []string
	}{
		{0, []string{"recipients"}},
		{1, []string{"recipients", boundary.ParameterRekeyTo}},
		{2, []string{"recipients", boundary.ParameterRekeyTo, boundary.ParameterCosigner}},
		{3, []string{boundary.ParameterUnlockRound, boundary.ParameterRekeyTo}},
	} {
		preset := boundary.Presets()[test.preset]
		m := Model{forms: formsState{boundaryKeyType: boundary.KeyTypeV1, boundaryPreset: &preset}}
		spec := m.paramSpecFor(boundary.KeyTypeV1)
		if spec == nil {
			t.Fatal("no form")
		}
		var got []string
		for _, param := range spec.Params {
			got = append(got, param.Name)
			if !param.Required {
				t.Errorf("%s: %s is optional", preset.Name, param.Name)
			}
		}
		if strings.Join(got, ",") != strings.Join(test.want, ",") {
			t.Errorf("%s fields = %v, want %v", preset.Name, got, test.want)
		}
	}
}

func TestPresetSubmissionCarriesItsFixedChoices(t *testing.T) {
	boundedaccount.RegisterClient()
	useRegistryKeyTypes(t)
	preset := boundary.Presets()[0]
	m := Model{viewState: ViewGenerateParams, forms: formsState{boundaryKeyType: boundary.KeyTypeV1, boundaryPreset: &preset}}
	m = m.initGenericLSigParamsForKeyType(boundary.KeyTypeV1)
	m.forms.genericLSigParams[boundary.ParameterRecipients] = types.Address{31: 7}.String()
	got, _, errText := m.submitParamModal(boundary.KeyTypeV1, m.paramSpecFor(boundary.KeyTypeV1), ViewGenerating,
		func(string, map[string]string, string) tea.Cmd { return nil })
	if errText != "" {
		t.Fatal(errText)
	}
	for name, value := range preset.Fixed {
		if got.forms.pendingGenerateParams[name] != value {
			t.Errorf("%s = %q, want %q", name, got.forms.pendingGenerateParams[name], value)
		}
	}
}

// Importing a reference from the form must finish the field and keep what the
// operator already typed.
func TestImportedCosignerFillsThePresetField(t *testing.T) {
	boundedaccount.RegisterClient()
	useRegistryKeyTypes(t)
	preset := boundary.Presets()[2]
	m := Model{viewState: ViewGenerateParams, forms: formsState{boundaryKeyType: boundary.KeyTypeV1, boundaryPreset: &preset}}
	m = m.initGenericLSigParamsForKeyType(boundary.KeyTypeV1)
	m.forms.genericLSigParams[boundary.ParameterRecipients] = "typed"
	m.cosigner.pendingKeyType = boundary.KeyTypeV1
	m.cosigner.pendingWitnessID = "WITNESS"

	next, _ := m.Update(KeyTypesMsg{KeyTypes: []protocol.KeyTypeInfo{{
		KeyType:        boundary.KeyTypeV1,
		PerKeyContract: true,
		CreationParams: []protocol.TemplateParamInfo{{Name: boundary.ParameterRecipients, Type: "address[]", Required: true}},
	}}})
	got := next.(Model)
	if got.forms.genericLSigParams[boundary.ParameterCosigner] != "WITNESS" {
		t.Fatalf("cosigner = %q", got.forms.genericLSigParams[boundary.ParameterCosigner])
	}
	if got.forms.genericLSigParams[boundary.ParameterRecipients] != "typed" {
		t.Fatalf("recipients = %q", got.forms.genericLSigParams[boundary.ParameterRecipients])
	}
	if got.cosigner.pendingWitnessID != "" {
		t.Fatal("the pending import was not consumed")
	}
}

func TestBoundaryFileBrowserStartsWhereApadminRuns(t *testing.T) {
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(directory)
	if dirs := fileBrowserDefaultDirs(browseBoundaryFile); len(dirs) != 1 || dirs[0] != directory {
		t.Fatalf("default dirs = %v, want %s", dirs, directory)
	}
}

func TestBoundaryFileFailureStaysOnTheFileRow(t *testing.T) {
	m := Model{viewState: ViewBoundaryPreset, forms: formsState{boundaryFile: filepath.Join(t.TempDir(), "missing.yaml")}}
	m.forms.boundaryPresetIndex = len(boundary.Presets())
	next, _ := m.handleBoundaryPresetKeys(tea.KeyMsg{Type: tea.KeyEnter})
	got := next.(Model)
	if got.viewState != ViewBoundaryPreset || got.forms.generateError == "" {
		t.Fatalf("view = %v, error = %q", got.viewState, got.forms.generateError)
	}
}

// useRegistryKeyTypes makes forms read the local provider, as they do before the
// daemon's list arrives.
func useRegistryKeyTypes(t *testing.T) {
	t.Helper()
	t.Cleanup(func() { setServerKeyTypes(nil) })
	setServerKeyTypes(nil)
}

// A template without a rekey-to list may name a parameter rekey_to. It is shown
// as that template's parameter, never as addresses that can take the account.
func TestDetailsShowAnUnlistedRekeyToAsAParameter(t *testing.T) {
	prepared := preparedAccount(boundedmeta.Layer3PolicyCustom, boundary.RekeySpendingKey, false, 0)
	prepared.Parameters[boundedmeta.RekeyListEntriesParameter] = "beneficiary-note"
	m := Model{viewState: ViewGenerateReviewDetails, width: 80, height: 400, forms: formsState{review: &prepared}}
	details := m.renderGenerateReviewDetails()
	if strings.Contains(details, "Rekey-to addresses") || !strings.Contains(details, "beneficiary-note") {
		t.Fatalf("details:\n%s", details)
	}
}
