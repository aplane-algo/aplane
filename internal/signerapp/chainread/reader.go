// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package chainread gives the signer its own view of an account's on-chain
// authorizer. Only the rotating signing flow uses it: the ordinary /plan and
// /sign paths never read the chain.
//
// The node is chosen from the account's genesis hash through the signer's
// genesis-hash mapping and networks.<net>.algod, and its own genesis hash
// must match before any answer is trusted. A missing mapping, a missing algod
// entry, or a node on another network fails closed.
package chainread

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	apconfig "github.com/aplane-algo/aplane/internal/config"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// ErrUnavailable reports that the chain could not be read safely.
var ErrUnavailable = errors.New("chain read unavailable")

// AccountView is one read of an account's authorization state.
type AccountView struct {
	// Authorizer is the address whose signature the account requires: its
	// auth address, or the account itself when none is set.
	Authorizer types.Address

	// Round is the round the node reported the account at.
	Round uint64
}

// Reader reads account state from the node configured for a network.
type Reader struct {
	// Resolver maps genesis hashes to network tokens.
	Resolver func() apconfig.GenesisHashNetworkResolver

	// AlgodConfig returns the configured node for a network token.
	AlgodConfig func(network string) (*apconfig.AlgodNetworkConfig, error)

	// MakeClient builds an algod client.
	MakeClient func(server, token string) (*algod.Client, error)
}

// ReadAccount returns account's authorizer and the round of the read from the
// node serving genesisHash.
func (r Reader) ReadAccount(ctx context.Context, genesisHash []byte, account types.Address) (AccountView, error) {
	client, err := r.client(ctx, genesisHash)
	if err != nil {
		return AccountView{}, err
	}
	info, err := client.AccountInformation(account.String()).Exclude([]string{"all"}).Do(ctx)
	if err != nil {
		return AccountView{}, fmt.Errorf("%w: read account: %v", ErrUnavailable, err)
	}
	view := AccountView{Authorizer: account, Round: info.Round}
	if info.AuthAddr != "" {
		authorizer, err := types.DecodeAddress(info.AuthAddr)
		if err != nil {
			return AccountView{}, fmt.Errorf("%w: node returned an invalid auth address", ErrUnavailable)
		}
		view.Authorizer = authorizer
	}
	if view.Round == 0 {
		return AccountView{}, fmt.Errorf("%w: node returned no round", ErrUnavailable)
	}
	return view, nil
}

func (r Reader) client(ctx context.Context, genesisHash []byte) (*algod.Client, error) {
	if r.Resolver == nil || r.AlgodConfig == nil || r.MakeClient == nil {
		return nil, fmt.Errorf("%w: chain reader is not configured", ErrUnavailable)
	}
	network, ok := r.Resolver().NetworkForGenesisHashBytes(genesisHash)
	if !ok {
		return nil, fmt.Errorf("%w: no network is configured for the account's genesis hash", ErrUnavailable)
	}
	cfg, err := r.AlgodConfig(network)
	if err != nil || cfg == nil || cfg.Server == "" {
		return nil, fmt.Errorf("%w: no algod is configured for network %s", ErrUnavailable, network)
	}
	client, err := r.MakeClient(cfg.Server, cfg.Token)
	if err != nil {
		return nil, fmt.Errorf("%w: algod client for network %s: %v", ErrUnavailable, network, err)
	}
	versions, err := client.Versions().Do(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: algod for network %s: %v", ErrUnavailable, network, err)
	}
	if !bytes.Equal(versions.GenesisHash, genesisHash) {
		return nil, fmt.Errorf("%w: algod for network %s serves a different genesis hash", ErrUnavailable, network)
	}
	return client, nil
}
