// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package connect

import (
	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/signing"
)

// SignAndSubmitGroup signs and submits a transaction group using the active signer connection.
func (s *ConnectionState) SignAndSubmitGroup(
	txns []types.Transaction,
	authCache *cache.AuthAddressCache,
	algodClient *algod.Client,
	opts signing.SubmitOptions,
) ([]string, []types.Transaction, error) {
	client, err := s.signerClient()
	if err != nil {
		return nil, nil, err
	}
	return signing.SignAndSubmitViaGroup(txns, authCache, client, algodClient, opts)
}
