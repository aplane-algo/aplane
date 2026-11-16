// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/signerapp/chainread"
	"github.com/aplane-algo/aplane/internal/txnreview"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// ReviewChain reads a review's accounts from the signer's node.
type ReviewChain interface {
	ReadAccounts(ctx context.Context, genesisHash []byte, accounts []types.Address) (chainread.AccountsView, error)
}

// DefaultReviewChainTimeout bounds the read a review makes before its prompt.
const DefaultReviewChainTimeout = 2 * time.Second

func (s *ApprovalService) reviewChainTimeout() time.Duration {
	if s.ReviewChainTimeout > 0 {
		return s.ReviewChainTimeout
	}
	return DefaultReviewChainTimeout
}

// addChainState reads each of the review's accounts from the signer's node
// and adds what the node says: each balance, who the chain says signs for an
// account, and where this request signs with a key other than that one. It
// runs only once a request is to be put to an operator, after every gate,
// and what it reads decides nothing. A read that fails or runs past its
// deadline leaves the review saying why, and the prompt goes ahead.
//
// known is the set of addresses this signer holds an aplane key for, and
// signers the key address this request signs each transaction with, by
// position.
func (s *ApprovalService) addChainState(ctx context.Context, review *txnreview.Review, genesisHash []byte, known map[string]bool, signers []string) {
	if s == nil || s.Chain == nil || review == nil || len(review.Parties) == 0 {
		return
	}
	var addresses []types.Address
	for _, party := range review.Parties {
		if address, err := types.DecodeAddress(party.Address); err == nil {
			addresses = append(addresses, address)
		}
	}
	timeout := s.reviewChainTimeout()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	view, err := s.Chain.ReadAccounts(ctx, genesisHash, addresses)
	if err == nil && len(view.Accounts) == 0 {
		for _, failure := range view.Failed {
			err = failure
			break
		}
	}
	if err != nil {
		review.Chain = &txnreview.ChainRead{Unavailable: chainUnavailableReason(err, timeout)}
		return
	}
	review.Chain = &txnreview.ChainRead{Round: view.Round}

	otherSigner := otherSigners(review.Items, view, signers)
	for i := range review.Parties {
		party := &review.Parties[i]
		address, err := types.DecodeAddress(party.Address)
		if err != nil {
			continue
		}
		account, ok := view.Accounts[address]
		if !ok {
			continue
		}
		chain := &txnreview.PartyChain{MicroAlgos: account.MicroAlgos, OtherSigner: otherSigner[party.Address]}
		if account.Authorizer != address {
			chain.Authorizer = account.Authorizer.String()
			chain.AuthorizerHeld = known[chain.Authorizer]
		}
		party.Chain = chain
	}
}

// otherSigners finds, for each sender, the first key this request signs one
// of its transactions with that is not the sender's authorizer when that
// transaction runs: the chain's, as the request's earlier rekeys leave it.
// Only a transaction the review says this request signs is held to it;
// every transaction's rekeys move the authorizer on.
func otherSigners(items []txnreview.Item, view chainread.AccountsView, signers []string) map[string]string {
	authorizers := map[string]string{}
	for address, account := range view.Accounts {
		authorizers[address.String()] = account.Authorizer.String()
	}
	out := map[string]string{}
	for i, item := range items {
		sender := item.Details.Sender
		if i < len(signers) && signers[i] != "" && item.Position == txnreview.PositionSign {
			if current, ok := authorizers[sender]; ok && signers[i] != current && out[sender] == "" {
				out[sender] = signers[i]
			}
		}
		for _, effect := range item.Details.Effects {
			if effect.Kind == txnreview.EffectRekey && effect.To != "" {
				authorizers[effect.From] = effect.To
			}
		}
	}
	return out
}

// chainUnavailableReason says why the chain was not read, without the
// package's own prefix.
func chainUnavailableReason(err error, timeout time.Duration) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Sprintf("the node did not answer within %s", timeout)
	}
	return strings.TrimPrefix(err.Error(), chainread.ErrUnavailable.Error()+": ")
}

// signersOf is the key address this request signs each transaction with, by
// position: its auth address, or the sender itself. A transaction this
// request doesn't sign has none. Nor has a rotating spend: its stage key is
// not the request's auth address, and its flow reads the chain's authorizer
// itself and refuses to sign when it has changed.
func signersOf(requests []signerapi.SignRequest, txns []types.Transaction, plan *PlanResult) []string {
	if plan != nil && plan.Rotating != nil {
		return nil
	}
	out := make([]string, len(requests))
	for i, txReq := range requests {
		if i >= len(txns) || plan != nil && (plan.ForeignIndices[i] || plan.PassthroughIndices[i]) {
			continue
		}
		out[i] = txReq.AuthAddress
		if out[i] == "" {
			out[i] = txns[i].Sender.String()
		}
	}
	return out
}
