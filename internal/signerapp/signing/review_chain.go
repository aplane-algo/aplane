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
// and adds its balance. The chain's authorizer settles whether the review
// calls an account signable, by apshell's rule (cache.IsAccountSignable)
// less its authorization-kind check, which every spending key the signer
// holds passes: a rotating account the signer holds is signable at any
// stage, and any other account only when the signer holds an aplane key for
// its authorizer. The
// authorizer is not shown. The read runs only once a request is to be put to
// an operator, after every gate, and what it reads decides nothing. A read
// that fails or runs past its deadline leaves the review saying why, and the
// prompt goes ahead.
//
// known is the set of addresses this signer holds an aplane key for, and
// rotating those of them that are rotating accounts.
func (s *ApprovalService) addChainState(ctx context.Context, review *txnreview.Review, genesisHash []byte, known, rotating map[string]bool) {
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
	for i := range review.Parties {
		party := &review.Parties[i]
		address, err := types.DecodeAddress(party.Address)
		if err != nil {
			continue
		}
		if account, ok := view.Accounts[address]; ok {
			balance := account.MicroAlgos
			party.MicroAlgos = &balance
			party.Signable = rotating[party.Address] || known[account.Authorizer.String()]
		}
	}
}

// chainUnavailableReason says why the chain was not read, without the
// package's own prefix.
func chainUnavailableReason(err error, timeout time.Duration) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Sprintf("the node did not answer within %s", timeout)
	}
	return strings.TrimPrefix(err.Error(), chainread.ErrUnavailable.Error()+": ")
}
