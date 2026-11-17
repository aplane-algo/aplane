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

// The prompt carries each account's balance as the signer's node reports it,
// read once from the node the request's genesis hash names, and the text
// says the same as the review.
func TestPromptCarriesEachAccountsBalance(t *testing.T) {
	own, other := reviewTestAddr(1), reviewTestAddr(2)
	for _, group := range []bool{false, true} {
		req, plan := paymentReview(own, other, group)
		chain := &fakeReviewChain{view: chainread.AccountsView{Round: 77, Accounts: map[types.Address]chainread.AccountView{
			own:   {Authorizer: own, Round: 77, MicroAlgos: 1_234_567_890},
			other: {Authorizer: other, Round: 78, MicroAlgos: 100_000},
		}}}
		prompt := chainReviewCase{req: req, plan: plan, chain: chain, known: map[string]bool{own.String(): true}}.prompt(t)
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
		want := map[string]uint64{own.String(): 1_234_567_890, other.String(): 100_000}
		for _, party := range review.Parties {
			if party.MicroAlgos == nil || *party.MicroAlgos != want[party.Address] {
				t.Errorf("group %t: %s balance = %v, want %d", group, party.Address[:6], party.MicroAlgos, want[party.Address])
			}
		}
		for _, line := range []string{"--- Accounts at round 77 ---", "1234.567890 ALGO · signable", "0.100000 ALGO · not signable"} {
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
			if party.MicroAlgos != nil {
				t.Errorf("%s: %s has a balance", name, party.Address[:6])
			}
		}
	}
}

// Once the chain is read, an account is signable by apshell's rule: a
// rotating account the signer holds at any stage, any other account only
// where the signer holds an aplane key for the authorizer the chain names. A
// sender or payee rekeyed to a held key is signable; an account the signer
// holds that was rekeyed to another key is not. Until the chain is read, a
// sender this request signs for is signable.
func TestSignableFollowsApshellsRule(t *testing.T) {
	rekeyed, payee, auth, stranger := reviewTestAddr(1), reviewTestAddr(2), reviewTestAddr(6), reviewTestAddr(7)
	view := func(payeeAuthorizer types.Address) *fakeReviewChain {
		return &fakeReviewChain{view: chainread.AccountsView{Round: 9, Accounts: map[types.Address]chainread.AccountView{
			rekeyed: {Authorizer: auth, Round: 9, MicroAlgos: 1},
			payee:   {Authorizer: payeeAuthorizer, Round: 9, MicroAlgos: 2},
		}}}
	}
	for name, tc := range map[string]struct {
		chain     *fakeReviewChain
		payeeHeld bool
		rotating  bool
		want      bool // the payee's
	}{
		"payee rekeyed to a held key":        {chain: view(auth), want: true},
		"payee held, rekeyed to another":     {chain: view(stranger), payeeHeld: true, want: false},
		"payee held, not rekeyed":            {chain: view(payee), payeeHeld: true, want: true},
		"payee rotating, at a later stage":   {chain: view(stranger), payeeHeld: true, rotating: true, want: true},
		"unread, payee not held":             {chain: &fakeReviewChain{err: fmt.Errorf("%w: no algod is configured for network testnet", chainread.ErrUnavailable)}, want: false},
		"unread, payee held, rekeyed or not": {chain: &fakeReviewChain{err: fmt.Errorf("%w: no algod is configured for network testnet", chainread.ErrUnavailable)}, payeeHeld: true, want: true},
	} {
		req, plan := paymentReview(rekeyed, payee, true)
		for i := range req.Requests {
			req.Requests[i].AuthAddress = auth.String()
		}
		known := map[string]bool{auth.String(): true}
		if tc.payeeHeld {
			known[payee.String()] = true
		}
		if tc.rotating {
			plan.RotatingAddresses = map[string]bool{payee.String(): true}
		}
		plan.KnownAddresses = known
		prompt := chainReviewCase{req: req, plan: plan, chain: tc.chain, known: known}.prompt(t)
		if prompt == nil {
			t.Fatalf("%s: no prompt", name)
		}
		for _, party := range prompt.Review.Parties {
			want := tc.want
			if party.Address == rekeyed.String() {
				want = true // rekeyed to a held key, and signed here
			}
			if party.Signable != want {
				t.Errorf("%s: %s signable %t, want %t", name, party.Address[:6], party.Signable, want)
			}
		}
	}
}
