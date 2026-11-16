// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package chainread gives the signer its own view of chain state: an
// account's on-chain authorizer, for the rotating signing flow; an asset's
// parameters, for an operator confirming it into the node's ASA set; and the
// balance and authorizer of each account a sign request touches, for the
// review an operator is asked to approve. /plan never reads the chain. /sign
// reads it for a rotating spend, and for a review only once the request is to
// be put to an operator; what it reads there is shown and decides nothing.
//
// The node is chosen from the genesis hash through the signer's
// genesis-hash mapping and networks.<net>.algod, and its own genesis hash
// must match before any answer is trusted. A missing mapping, a missing algod
// entry, or a node on another network fails closed.
//
// Where networks.<net>.indexer is configured, LookupLastRotation also reads
// a rotating account's newest outgoing rekey from that Indexer, chosen the
// same way, to propose the stage a search tries first. Its answer is a
// candidate only: the caller accepts a stage only when the address it
// derives from the seed is the authorizer its own algod reported.
package chainread

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	apconfig "github.com/aplane-algo/aplane/internal/config"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
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

	// MicroAlgos is the account's balance.
	MicroAlgos uint64
}

// AccountsView is one read of several accounts from one node.
type AccountsView struct {
	// Accounts are the accounts read, by address.
	Accounts map[types.Address]AccountView

	// Failed says why each account that was not read was not.
	Failed map[types.Address]error

	// Round is the earliest round among the reads.
	Round uint64
}

// maxParallelReads is how many account reads ReadAccounts has open at once.
const maxParallelReads = 8

// Reader reads account state from the node configured for a network.
type Reader struct {
	// Resolver maps genesis hashes to network tokens.
	Resolver func() apconfig.GenesisHashNetworkResolver

	// AlgodConfig returns the configured node for a network token.
	AlgodConfig func(network string) (*apconfig.AlgodNetworkConfig, error)

	// MakeClient builds an algod client.
	MakeClient func(server, token string) (*algod.Client, error)

	// IndexerConfig returns the Indexer configured for a network token, or
	// nil when there is none. Optional: nil means no stage lookup.
	IndexerConfig func(network string) *apconfig.IndexerNetworkConfig

	// IndexerTransport carries the Indexer's requests. nil, as in
	// production, means the package's own transport, with keep-alives off,
	// response headers capped and dial, TLS and header timeouts. A
	// RoundTripper set here bypasses all of those and is for tests. Either
	// way the lookup wraps it to refuse every response outside 2xx,
	// redirects among them; the body cap is enforced by the lookup's read of
	// the body, not by the transport.
	IndexerTransport http.RoundTripper

	// LookupTimeout bounds one LookupLastRotation. Zero means
	// DefaultLookupTimeout.
	LookupTimeout time.Duration

	// Pause, if set, keeps each network's Indexer from being asked again
	// for IndexerPauseAfterFailure after a lookup it failed. The daemon
	// shares one among every Reader it builds; nil means no pause.
	Pause *IndexerPause
}

// ReadAccount returns account's authorizer and the round of the read from the
// node serving genesisHash.
func (r Reader) ReadAccount(ctx context.Context, genesisHash []byte, account types.Address) (AccountView, error) {
	client, err := r.client(ctx, genesisHash)
	if err != nil {
		return AccountView{}, err
	}
	return readAccount(ctx, client, account)
}

// ReadAccounts reads each of accounts from the node serving genesisHash,
// checking that node once. It fails only when the node can't be used at
// all: an account whose own read fails is in Failed, and the rest are read.
func (r Reader) ReadAccounts(ctx context.Context, genesisHash []byte, accounts []types.Address) (AccountsView, error) {
	client, err := r.client(ctx, genesisHash)
	if err != nil {
		return AccountsView{}, err
	}
	view := AccountsView{Accounts: map[types.Address]AccountView{}, Failed: map[types.Address]error{}}
	var (
		mu    sync.Mutex
		wg    sync.WaitGroup
		slots = make(chan struct{}, maxParallelReads)
		seen  = map[types.Address]bool{}
	)
	for _, account := range accounts {
		if seen[account] {
			continue
		}
		seen[account] = true
		wg.Add(1)
		go func() {
			defer wg.Done()
			slots <- struct{}{}
			defer func() { <-slots }()
			read, err := readAccount(ctx, client, account)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				view.Failed[account] = err
				return
			}
			view.Accounts[account] = read
			if view.Round == 0 || read.Round < view.Round {
				view.Round = read.Round
			}
		}()
	}
	wg.Wait()
	return view, nil
}

func readAccount(ctx context.Context, client *algod.Client, account types.Address) (AccountView, error) {
	info, err := client.AccountInformation(account.String()).Exclude([]string{"all"}).Do(ctx)
	if err != nil {
		return AccountView{}, fmt.Errorf("%w: read account: %w", ErrUnavailable, err)
	}
	view := AccountView{Authorizer: account, Round: info.Round, MicroAlgos: info.Amount}
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

// ReadAsset returns asset assetID's parameters from the node serving
// genesisHash. The answer is trusted only because that node's own genesis
// hash matched first.
func (r Reader) ReadAsset(ctx context.Context, genesisHash []byte, assetID uint64) (models.AssetParams, error) {
	client, err := r.client(ctx, genesisHash)
	if err != nil {
		return models.AssetParams{}, err
	}
	asset, err := client.GetAssetByID(assetID).Do(ctx)
	if err != nil {
		return models.AssetParams{}, fmt.Errorf("%w: read asset %d: %w", ErrUnavailable, assetID, err)
	}
	if asset.Index != assetID {
		return models.AssetParams{}, fmt.Errorf("%w: node returned asset %d for asset %d", ErrUnavailable, asset.Index, assetID)
	}
	return asset.Params, nil
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
		return nil, fmt.Errorf("%w: algod for network %s: %w", ErrUnavailable, network, err)
	}
	if !bytes.Equal(versions.GenesisHash, genesisHash) {
		return nil, fmt.Errorf("%w: algod for network %s serves a different genesis hash", ErrUnavailable, network)
	}
	return client, nil
}
