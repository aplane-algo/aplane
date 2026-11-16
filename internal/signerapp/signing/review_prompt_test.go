// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/policy/policytest"
	signerapproval "github.com/aplane-algo/aplane/internal/signerapp/approval"
	"github.com/aplane-algo/aplane/internal/signerapp/txdesc"
	"github.com/aplane-algo/aplane/internal/txnreview"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// promptForReviewTest runs a request through the approval gate and returns
// the prompt the operator was sent.
func promptForReviewTest(t *testing.T, req signerapi.GroupSignRequest, plan *PlanResult, known map[string]bool) signerapproval.Prompt {
	t.Helper()
	return promptForReviewTestWith(t, req, plan, known, &policy.Config{TransactionTypes: policytest.AllowAllTypes()})
}

// promptForReviewTestWith is promptForReviewTest under the given policy.
func promptForReviewTestWith(t *testing.T, req signerapi.GroupSignRequest, plan *PlanResult, known map[string]bool, cfg *policy.Config) signerapproval.Prompt {
	t.Helper()
	var got *signerapproval.Prompt
	describe := DescribeTxnFunc(txdesc.DetailTxn)
	service := &Service{
		Approval: &ApprovalService{
			UserAutoApprove: userAutoApproveDefault(false),
			HasClient:       func() bool { return true },
			KnownAddresses:  func() map[string]bool { return known },
			RequestSigningApprovalPrompt: func(_ context.Context, prompt signerapproval.Prompt, _ time.Duration) (signerapproval.SignResponse, error) {
				got = &prompt
				return signerapproval.SignResponse{Approved: false}, nil
			},
		},
		Executor:                      &Executor{},
		GenerateTxnDescriptionFromTxn: describe,
		IsUnlocked:                    func() bool { return true },
		PolicyFor:                     fixedPolicy(cfg),
	}
	if _, err := service.signGroupWithPlanContext(context.Background(), req, nil, plan); err == nil {
		t.Fatal("signGroupWithPlanContext() error = nil, want the operator's rejection")
	}
	if got == nil {
		t.Fatal("no prompt was sent")
	}
	return *got
}

func reviewTestAddr(b byte) types.Address {
	var a types.Address
	for i := range a {
		a[i] = b
	}
	return a
}

// A group's prompt carries the review its description was printed from: every
// line of the review is in the text, its findings are the prompt's warnings,
// and it says which accounts are the signer's own.
func TestGroupPromptCarriesTheReviewItsTextWasPrintedFrom(t *testing.T) {
	own, other, third := reviewTestAddr(1), reviewTestAddr(2), reviewTestAddr(3)
	pay := types.Transaction{Type: types.PaymentTx}
	pay.Sender, pay.Receiver, pay.Amount, pay.Fee = own, other, 5_000_000, 1000
	closing := types.Transaction{Type: types.PaymentTx}
	closing.Sender, closing.Receiver, closing.CloseRemainderTo, closing.Fee = own, other, third, 1000

	req := signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{
		{AuthAddress: own.String()}, {AuthAddress: own.String()},
	}}
	plan := &PlanResult{
		AllTxns:            []types.Transaction{pay, closing},
		PassthroughIndices: map[int]bool{}, ForeignIndices: map[int]bool{},
		AuthKeyTypes: []string{"falcon1024", "falcon1024"},
	}
	prompt := promptForReviewTest(t, req, plan, map[string]bool{own.String(): true})

	review := prompt.Review
	if review == nil || !review.Group || len(review.Items) != 2 {
		t.Fatalf("review = %+v", review)
	}
	if !strings.HasPrefix(prompt.Description, "[GROUP APPROVAL]\n") || !strings.HasSuffix(prompt.Description, review.Text()) {
		t.Fatalf("the description is not the review printed:\n%s\n---\n%s", prompt.Description, review.Text())
	}

	// The findings in the review are the warnings beside the text.
	var fromReview []string
	for i, item := range review.Items {
		for _, finding := range item.Findings {
			fromReview = append(fromReview, fmt.Sprintf("Tx %d/%d: %s=%s critical=%t", i+1, len(review.Items), finding.Field, finding.Value, finding.Critical))
		}
	}
	var fromPrompt []string
	for _, v := range prompt.Violations {
		fromPrompt = append(fromPrompt, fmt.Sprintf("%s=%s critical=%t", v.Field, v.Value, v.Severity == signerapproval.ViolationSeverityCritical))
	}
	if len(fromReview) == 0 || strings.Join(fromReview, "\n") != strings.Join(fromPrompt, "\n") {
		t.Fatalf("review findings:\n%s\nprompt warnings:\n%s", strings.Join(fromReview, "\n"), strings.Join(fromPrompt, "\n"))
	}

	// The close is marked as its finding marks it.
	effects := review.Items[1].Details.Effects
	if len(effects) != 1 || effects[0].Kind != txnreview.EffectClose || effects[0].Severity != txnreview.SeverityDanger {
		t.Fatalf("closing effects = %+v", effects)
	}
	if got := review.Items[0].Details.Effects; len(got) != 1 || got[0].Severity != txnreview.SeverityNormal {
		t.Fatalf("payment effects = %+v", got)
	}

	want := []txnreview.Party{
		{Address: own.String(), Held: true, Signs: true, KeyType: "falcon1024"},
		{Address: other.String()},
		{Address: third.String()},
	}
	if len(review.Parties) != len(want) {
		t.Fatalf("parties = %+v", review.Parties)
	}
	for i, p := range review.Parties {
		if p != want[i] {
			t.Errorf("party %d = %+v, want %+v", i, p, want[i])
		}
	}
}

// A lone transaction's prompt carries the review too, and the transaction's
// findings in it are the prompt's warnings.
func TestSingleTransactionPromptCarriesTheReview(t *testing.T) {
	own, other := reviewTestAddr(1), reviewTestAddr(2)
	closing := types.Transaction{Type: types.PaymentTx}
	closing.Sender, closing.Receiver, closing.CloseRemainderTo, closing.Fee = own, own, other, 1000

	req := signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{{AuthAddress: own.String()}}}
	plan := &PlanResult{
		AllTxns:            []types.Transaction{closing},
		PassthroughIndices: map[int]bool{}, ForeignIndices: map[int]bool{},
	}
	prompt := promptForReviewTest(t, req, plan, map[string]bool{own.String(): true})

	review := prompt.Review
	if review == nil || review.Group || len(review.Items) != 1 {
		t.Fatalf("review = %+v", review)
	}
	if want := "[TXN APPROVAL]\n" + review.Items[0].Text(); prompt.Description != want {
		t.Fatalf("description:\n%s\nwant:\n%s", prompt.Description, want)
	}
	findings := review.Items[0].Findings
	if len(findings) != 1 || len(prompt.Violations) != 1 ||
		findings[0].Field != prompt.Violations[0].Field || findings[0].Message != prompt.Violations[0].Message {
		t.Fatalf("review findings %+v, prompt warnings %+v", findings, prompt.Violations)
	}
	if effects := review.Items[0].Details.Effects; len(effects) != 1 || effects[0].Kind != txnreview.EffectClose || effects[0].Severity != txnreview.SeverityDanger {
		t.Fatalf("effects = %+v", effects)
	}
}

// What a client put in a request reaches the operator's terminal escaped, in
// the review as in the text.
func TestPromptReviewIsEscaped(t *testing.T) {
	own := reviewTestAddr(1)
	pay := types.Transaction{Type: types.PaymentTx}
	pay.Sender, pay.Receiver, pay.Fee, pay.GenesisID = own, own, 1000, "net\x1b[2J"
	req := signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{
		{AuthAddress: "AUTH\x1b[H"}, {AuthAddress: "AUTH\u202e"},
	}}
	plan := &PlanResult{
		AllTxns:            []types.Transaction{pay, pay},
		PassthroughIndices: map[int]bool{}, ForeignIndices: map[int]bool{},
	}
	review := promptForReviewTest(t, req, plan, nil).Review
	for i, item := range review.Items {
		requireTerminalSafe(t, fmt.Sprintf("item %d", i), item.Label+item.Text())
		for _, note := range item.Notes {
			requireTerminalSafe(t, fmt.Sprintf("item %d note", i), note.Line())
		}
	}
	if note := review.Items[0].Notes[0].Value; note != `AUTH\x1b[H` {
		t.Fatalf("signing key note = %q", note)
	}
}

// Two accounts in one request that look alike are a warning beside the text,
// in a group's prompt and a lone transaction's, and in the review.
func TestPromptWarnsOfLookalikeAccounts(t *testing.T) {
	own, real := reviewTestAddr(1), reviewTestAddr(2)
	fake := real
	for i := 4; i < 28; i++ {
		fake[i] ^= 0xff
	}
	if real.String()[:6] != fake.String()[:6] {
		t.Fatalf("the test addresses do not look alike: %s %s", real, fake)
	}
	payTo := func(to types.Address) types.Transaction {
		txn := types.Transaction{Type: types.PaymentTx}
		txn.Sender, txn.Receiver, txn.Amount, txn.Fee = own, to, 1_000_000, 1000
		return txn
	}
	lookalikes := func(prompt signerapproval.Prompt) int {
		count := 0
		for _, v := range prompt.Violations {
			if v.Field == txnreview.LookalikeField {
				count++
				if v.Severity != signerapproval.ViolationSeverityWarning ||
					!strings.Contains(v.Message, real.String()) || !strings.Contains(v.Message, fake.String()) {
					t.Errorf("warning = %+v", v)
				}
			}
		}
		if got := len(prompt.Review.Findings); got != count {
			t.Errorf("the review has %d findings about the request, the prompt %d lookalike warnings", got, count)
		}
		// The parties the warning names are marked, and no others.
		for _, party := range prompt.Review.Parties {
			want := count > 0 && (party.Address == real.String() || party.Address == fake.String())
			if party.Lookalike != want {
				t.Errorf("party %s: lookalike = %t, want %t", party.Address, party.Lookalike, want)
			}
		}
		return count
	}

	group := promptForReviewTest(t,
		signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{{AuthAddress: own.String()}, {AuthAddress: own.String()}}},
		&PlanResult{
			AllTxns:            []types.Transaction{payTo(real), payTo(fake)},
			PassthroughIndices: map[int]bool{}, ForeignIndices: map[int]bool{},
		}, nil)
	if got := lookalikes(group); got != 1 {
		t.Fatalf("group prompt has %d lookalike warnings, want 1: %+v", got, group.Violations)
	}

	closing := payTo(real)
	closing.CloseRemainderTo = fake
	single := promptForReviewTest(t,
		signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{{AuthAddress: own.String()}}},
		&PlanResult{
			AllTxns:            []types.Transaction{closing},
			PassthroughIndices: map[int]bool{}, ForeignIndices: map[int]bool{},
		}, nil)
	if got := lookalikes(single); got != 1 {
		t.Fatalf("single prompt has %d lookalike warnings, want 1: %+v", got, single.Violations)
	}

	plain := promptForReviewTest(t,
		signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{{AuthAddress: own.String()}, {AuthAddress: own.String()}}},
		&PlanResult{
			AllTxns:            []types.Transaction{payTo(real), payTo(reviewTestAddr(9))},
			PassthroughIndices: map[int]bool{}, ForeignIndices: map[int]bool{},
		}, nil)
	if got := lookalikes(plain); got != 0 {
		t.Fatalf("unrelated accounts are called lookalikes: %+v", plain.Violations)
	}
}

// A rekey to an account this signer holds is a notice in the prompt, alone
// or in a group: its warning has notice severity and its text and review show
// an ordinary "Rekey to" line. A rekey to an address it holds no key for is
// still critical and loud.
func TestPromptShowsARekeyToAHeldKeyAsANotice(t *testing.T) {
	own, held, foreign := reviewTestAddr(1), reviewTestAddr(2), reviewTestAddr(3)
	known := map[string]bool{own.String(): true, held.String(): true}
	rekey := func(target types.Address) types.Transaction {
		txn := types.Transaction{Type: types.PaymentTx}
		txn.Sender, txn.Receiver, txn.RekeyTo, txn.Fee = own, own, target, 1000
		return txn
	}
	prompt := func(txns ...types.Transaction) signerapproval.Prompt {
		req := signerapi.GroupSignRequest{}
		for range txns {
			req.Requests = append(req.Requests, signerapi.SignRequest{AuthAddress: own.String()})
		}
		plan := &PlanResult{AllTxns: txns, PassthroughIndices: map[int]bool{}, ForeignIndices: map[int]bool{}}
		return promptForReviewTestWith(t, req, plan, known, &policy.Config{TransactionTypes: policytest.AllowAllTypes(), Rekeys: policy.RekeysAllow})
	}
	rekeyWarning := func(p signerapproval.Prompt) signerapproval.Violation {
		t.Helper()
		var found []signerapproval.Violation
		for _, v := range p.Violations {
			if strings.HasSuffix(v.Field, "RekeyTo") {
				found = append(found, v)
			}
		}
		if len(found) != 1 {
			t.Fatalf("rekey warnings = %+v, want one", found)
		}
		return found[0]
	}
	pay := types.Transaction{Type: types.PaymentTx}
	pay.Sender, pay.Receiver, pay.Amount, pay.Fee = own, held, 1_000_000, 1000

	for name, p := range map[string]signerapproval.Prompt{
		"alone":    prompt(rekey(held)),
		"in group": prompt(pay, rekey(held)),
	} {
		if v := rekeyWarning(p); v.Severity != signerapproval.ViolationSeverityNotice {
			t.Errorf("%s: rekey to a held key has severity %q, want notice", name, v.Severity)
		}
		if !strings.Contains(p.Description, "Rekey to: "+held.String()) || strings.Contains(p.Description, "REKEY TO") {
			t.Errorf("%s: the text shows the rekey loud:\n%s", name, p.Description)
		}
		item := p.Review.Items[len(p.Review.Items)-1]
		for _, effect := range item.Details.Effects {
			if effect.Kind == txnreview.EffectRekey && effect.Severity != txnreview.SeverityNormal {
				t.Errorf("%s: the rekey effect is %+v", name, effect)
			}
		}
	}

	loud := prompt(rekey(foreign))
	if v := rekeyWarning(loud); v.Severity != signerapproval.ViolationSeverityCritical {
		t.Errorf("rekey to a foreign address has severity %q, want critical", v.Severity)
	}
	if !strings.Contains(loud.Description, "REKEY TO: "+foreign.String()) {
		t.Errorf("the text does not show a foreign rekey loud:\n%s", loud.Description)
	}
}
