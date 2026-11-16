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
	"github.com/aplane-algo/aplane/internal/signerapp/chainread"
	"github.com/aplane-algo/aplane/internal/signerapp/txdesc"
	"github.com/aplane-algo/aplane/internal/txnreview"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// fakeReviewChain answers a review's read with view or err, or, with hang
// set, not until the read's deadline.
type fakeReviewChain struct {
	view    chainread.AccountsView
	err     error
	hang    bool
	calls   int
	genesis []byte
}

func (f *fakeReviewChain) ReadAccounts(ctx context.Context, genesisHash []byte, _ []types.Address) (chainread.AccountsView, error) {
	f.calls++
	f.genesis = genesisHash
	if f.hang {
		<-ctx.Done()
		return chainread.AccountsView{}, fmt.Errorf("%w: algod for network testnet: %w", chainread.ErrUnavailable, ctx.Err())
	}
	return f.view, f.err
}

// chainReviewCase is a sign request run through the gates with a chain
// reader, answered by the operator with a rejection when it is put to one.
type chainReviewCase struct {
	req         signerapi.GroupSignRequest
	plan        *PlanResult
	known       map[string]bool
	chain       *fakeReviewChain
	autoApprove bool
	cfg         *policy.Config
	timeout     time.Duration
}

// prompt is the prompt the operator was sent, or nil when none was.
func (c chainReviewCase) prompt(t *testing.T) *signerapproval.Prompt {
	t.Helper()
	cfg := c.cfg
	if cfg == nil {
		cfg = &policy.Config{TransactionTypes: policytest.AllowAllTypes()}
	}
	var got *signerapproval.Prompt
	service := &Service{
		Approval: &ApprovalService{
			UserAutoApprove: userAutoApproveDefault(c.autoApprove),
			HasClient:       func() bool { return true },
			KnownAddresses:  func() map[string]bool { return c.known },
			RequestSigningApprovalPrompt: func(_ context.Context, prompt signerapproval.Prompt, _ time.Duration) (signerapproval.SignResponse, error) {
				got = &prompt
				return signerapproval.SignResponse{Approved: false}, nil
			},
			Chain:              c.chain,
			ReviewChainTimeout: c.timeout,
		},
		Executor:                      &Executor{},
		GenerateTxnDescriptionFromTxn: DescribeTxnFunc(txdesc.DetailTxn),
		IsUnlocked:                    func() bool { return true },
		PolicyFor:                     fixedPolicy(cfg),
		// An approved request stops here, short of signing.
		BeforeExecute: func() (func(), *ServiceError) { return nil, unavailable("stopped before signing") },
	}
	_, _ = service.signGroupWithPlanContext(context.Background(), c.req, nil, c.plan)
	return got
}

// paymentReview is own paying other, signed with own's key, as a lone
// transaction and as a group of two.
func paymentReview(own, other types.Address, group bool) (signerapi.GroupSignRequest, *PlanResult) {
	pay := types.Transaction{Type: types.PaymentTx}
	pay.Sender, pay.Receiver, pay.Amount, pay.Fee = own, other, 5_000_000, 1000
	pay.GenesisHash = types.Digest{9, 9, 9}
	txns := []types.Transaction{pay}
	if group {
		second := pay
		second.Amount = 1_000_000
		txns = append(txns, second)
	}
	req := signerapi.GroupSignRequest{}
	plan := &PlanResult{AllTxns: txns, PassthroughIndices: map[int]bool{}, ForeignIndices: map[int]bool{}}
	for range txns {
		req.Requests = append(req.Requests, signerapi.SignRequest{AuthAddress: own.String()})
		plan.AuthKeyTypes = append(plan.AuthKeyTypes, "ed25519")
	}
	return req, plan
}

// The prompt says what the signer's node says of each account: its balance,
// who the chain says signs for it where that is another address, whether the
// signer holds that one, and where this request signs with a key the chain
// does not name. The text says the same as the review.
func TestPromptSaysWhatTheNodeSaysOfEachAccount(t *testing.T) {
	own, other, stage := reviewTestAddr(1), reviewTestAddr(2), reviewTestAddr(4)
	for _, group := range []bool{false, true} {
		req, plan := paymentReview(own, other, group)
		chain := &fakeReviewChain{view: chainread.AccountsView{Round: 77, Accounts: map[types.Address]chainread.AccountView{
			own:   {Authorizer: stage, Round: 77, MicroAlgos: 1_234_567_890},
			other: {Authorizer: other, Round: 78, MicroAlgos: 100_000},
		}}}
		prompt := chainReviewCase{req: req, plan: plan, chain: chain,
			known: map[string]bool{own.String(): true, stage.String(): true}}.prompt(t)
		if prompt == nil || prompt.Review == nil {
			t.Fatalf("group %t: no prompt", group)
		}
		if chain.calls != 1 || string(chain.genesis) != string(plan.AllTxns[0].GenesisHash[:]) {
			t.Errorf("group %t: %d reads, of genesis %x", group, chain.calls, chain.genesis)
		}
		review := prompt.Review
		if review.Chain == nil || review.Chain.Round != 77 || review.Chain.Unavailable != "" {
			t.Fatalf("group %t: chain = %+v", group, review.Chain)
		}
		want := map[string]txnreview.PartyChain{
			own.String():   {MicroAlgos: 1_234_567_890, Authorizer: stage.String(), AuthorizerHeld: true, OtherSigner: own.String()},
			other.String(): {MicroAlgos: 100_000},
		}
		for _, party := range review.Parties {
			if party.Chain == nil || *party.Chain != want[party.Address] {
				t.Errorf("group %t: %s chain = %+v, want %+v", group, party.Address[:6], party.Chain, want[party.Address])
			}
		}
		for _, line := range []string{
			"--- Accounts at round 77 ---",
			"1234.567890 ALGO · signed here with its ed25519 aplane key",
			"rekeyed to " + stage.String() + ", an address this signer holds an aplane key for",
			"this request signs with " + own.String() + ", a key the chain does not name for it",
			"0.100000 ALGO",
		} {
			if !strings.Contains(prompt.Description, line) {
				t.Errorf("group %t: the text lacks %q:\n%s", group, line, prompt.Description)
			}
		}
	}
}

// Nothing is read unless the request is put to an operator: not for one the
// user's auto-approve answers, nor one policy rejects.
func TestTheChainIsReadOnlyForAnOperator(t *testing.T) {
	own, other := reviewTestAddr(1), reviewTestAddr(2)
	for name, c := range map[string]chainReviewCase{
		"auto-approved":       {autoApprove: true},
		"rejected by policy":  {cfg: &policy.Config{}},
		"put to the operator": {},
	} {
		c.req, c.plan = paymentReview(own, other, true)
		c.chain = &fakeReviewChain{view: chainread.AccountsView{Round: 5}}
		prompt := c.prompt(t)
		if asked := prompt != nil; asked != (c.chain.calls == 1) || c.chain.calls > 1 {
			t.Errorf("%s: prompted %t, read the chain %d times", name, asked, c.chain.calls)
		}
		if name == "put to the operator" && prompt == nil {
			t.Errorf("%s: no prompt", name)
		}
	}
}

// A read that fails, or doesn't answer in time, leaves the prompt saying why,
// and the prompt is sent all the same.
func TestAFailedReadStillPrompts(t *testing.T) {
	own, other := reviewTestAddr(1), reviewTestAddr(2)
	for name, tc := range map[string]struct {
		chain *fakeReviewChain
		want  string
	}{
		"no algod":    {&fakeReviewChain{err: fmt.Errorf("%w: no algod is configured for network testnet", chainread.ErrUnavailable)}, "no algod is configured for network testnet"},
		"no answer":   {&fakeReviewChain{hang: true}, "the node did not answer within 50ms"},
		"every fails": {&fakeReviewChain{view: chainread.AccountsView{Failed: map[types.Address]error{own: fmt.Errorf("%w: read account: boom", chainread.ErrUnavailable)}}}, "read account: boom"},
	} {
		req, plan := paymentReview(own, other, true)
		start := time.Now()
		prompt := chainReviewCase{req: req, plan: plan, chain: tc.chain, timeout: 50 * time.Millisecond}.prompt(t)
		if prompt == nil {
			t.Fatalf("%s: no prompt", name)
		}
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Errorf("%s: the prompt took %s", name, elapsed)
		}
		if got := prompt.Review.Chain; got == nil || got.Unavailable != tc.want {
			t.Errorf("%s: chain = %+v, want unavailable %q", name, got, tc.want)
		}
		if !strings.Contains(prompt.Description, "Balances unavailable: "+tc.want) {
			t.Errorf("%s: the text does not say why:\n%s", name, prompt.Description)
		}
		for _, party := range prompt.Review.Parties {
			if party.Chain != nil {
				t.Errorf("%s: %s has a balance", name, party.Address[:6])
			}
		}
	}
}

// Each transaction this request signs is held to its sender's authorizer
// when it runs: the chain's, as the request's earlier rekeys leave it. A
// transaction signed with the key an earlier one rekeyed the account to is
// not called out; the rekeying transaction signed with that key already is.
func TestEachSignedTransactionIsHeldToTheAuthorizerWhenItRuns(t *testing.T) {
	own, other, next := reviewTestAddr(1), reviewTestAddr(2), reviewTestAddr(5)
	allowRekeys := &policy.Config{TransactionTypes: policytest.AllowAllTypes(), Rekeys: policy.RekeysAllow}
	for _, tc := range []struct {
		name        string
		firstSigner types.Address
		want        string
	}{
		{"the rekey signed with the chain's key", own, ""},
		{"the rekey signed with the new key", next, next.String()},
	} {
		req, plan := paymentReview(own, other, true)
		plan.AllTxns[0].RekeyTo = next
		req.Requests[0].AuthAddress = tc.firstSigner.String()
		req.Requests[1].AuthAddress = next.String()
		chain := &fakeReviewChain{view: chainread.AccountsView{Round: 5, Accounts: map[types.Address]chainread.AccountView{
			own: {Authorizer: own, Round: 5},
		}}}
		prompt := chainReviewCase{req: req, plan: plan, chain: chain, cfg: allowRekeys,
			known: map[string]bool{own.String(): true, next.String(): true}}.prompt(t)
		if prompt == nil {
			t.Fatalf("%s: no prompt", tc.name)
		}
		for _, party := range prompt.Review.Parties {
			if party.Address == own.String() && (party.Chain == nil || party.Chain.OtherSigner != tc.want) {
				t.Errorf("%s: own chain = %+v, want other signer %q", tc.name, party.Chain, tc.want)
			}
		}
	}
}

// Only a transaction the review says this request signs is held to its
// sender's authorizer, and any transaction's rekey moves the authorizer on.
func TestOtherSignersFollowTheReviewsPositions(t *testing.T) {
	own, next := reviewTestAddr(1), reviewTestAddr(5)
	rekey := txnreview.Effect{Kind: txnreview.EffectRekey, From: own.String(), To: next.String()}
	view := chainread.AccountsView{Accounts: map[types.Address]chainread.AccountView{own: {Authorizer: own}}}
	items := []txnreview.Item{
		{Position: txnreview.PositionPassthrough, Details: txnreview.Details{Sender: own.String(), Effects: []txnreview.Effect{rekey}}},
		{Position: txnreview.PositionSign, Details: txnreview.Details{Sender: own.String()}},
	}
	if got := otherSigners(items, view, []string{next.String(), next.String()}); len(got) != 0 {
		t.Errorf("after a passthrough's rekey: %v", got)
	}
	items[0].Details.Effects = nil
	if got := otherSigners(items, view, []string{next.String(), next.String()}); got[own.String()] != next.String() || len(got) != 1 {
		t.Errorf("with no rekey: %v", got)
	}
}

// The key a request signs each transaction with is its auth address, or the
// sender; a transaction this request doesn't sign has none, and a rotating
// spend none at all.
func TestSignersOf(t *testing.T) {
	a, b, c := reviewTestAddr(1), reviewTestAddr(2), reviewTestAddr(3)
	txns := []types.Transaction{{}, {}, {}}
	txns[0].Sender, txns[1].Sender, txns[2].Sender = a, b, c
	requests := []signerapi.SignRequest{{AuthAddress: c.String()}, {}, {AuthAddress: a.String()}}
	plan := &PlanResult{ForeignIndices: map[int]bool{2: true}, PassthroughIndices: map[int]bool{}}
	if got := signersOf(requests, txns, plan); strings.Join(got, ",") != c.String()+","+b.String()+"," {
		t.Errorf("signers = %v", got)
	}
	plan.Rotating = &rotatingPlanItem{}
	if got := signersOf(requests, txns, plan); got != nil {
		t.Errorf("a rotating spend's signers = %v", got)
	}
}
