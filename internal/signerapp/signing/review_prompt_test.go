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
	var got *signerapproval.Prompt
	describe := DescribeTxnFunc(txdesc.DetailTxn)
	service := &Service{
		Approval: &ApprovalService{
			UserAutoApprove:               userAutoApproveDefault(false),
			GenerateTxnDescriptionFromTxn: describe,
			HasClient:                     func() bool { return true },
			KnownAddresses:                func() map[string]bool { return known },
			RequestSigningApprovalPrompt: func(_ context.Context, prompt signerapproval.Prompt, _ time.Duration) (signerapproval.SignResponse, error) {
				got = &prompt
				return signerapproval.SignResponse{Approved: false}, nil
			},
		},
		Executor:                      &Executor{},
		GenerateTxnDescriptionFromTxn: describe,
		IsUnlocked:                    func() bool { return true },
		PolicyFor:                     fixedPolicy(&policy.Config{TransactionTypes: policytest.AllowAllTypes()}),
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
