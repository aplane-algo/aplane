// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/lsigresource"
)

// consensusValidationReuseWindow avoids repeating SuggestedParams calls inside
// one interactive transaction workflow. The short bound keeps the client from
// carrying a successful consensus check across a network upgrade.
const consensusValidationReuseWindow = 30 * time.Second

type consensusValidationCache struct {
	mu          sync.Mutex
	client      *algod.Client
	network     algodNetwork
	validatedAt time.Time
}

// setLocked records that client served params, which passed
// checkSupportedConsensus, now.
func (c *consensusValidationCache) setLocked(client *algod.Client, params types.SuggestedParams) {
	c.client = client
	c.network = algodNetworkOf(params)
	c.validatedAt = time.Now()
}

func (c *consensusValidationCache) clearLocked() {
	c.client = nil
	c.network = algodNetwork{}
	c.validatedAt = time.Time{}
}

// algodNetwork is the network an algod serves, as its suggested parameters
// name it, read in the same call that reports its consensus version.
type algodNetwork struct {
	genesisHash []byte
	genesisID   string
}

func algodNetworkOf(params types.SuggestedParams) algodNetwork {
	return algodNetwork{
		genesisHash: append([]byte(nil), params.GenesisHash...),
		genesisID:   params.GenesisID,
	}
}

func checkSupportedConsensus(version string) error {
	if _, err := lsigresource.ResolveConsensus(version); err != nil {
		return fmt.Errorf(
			"network consensus %q is unsupported by this APlane release; supported contracts: v42 and v43: %w",
			version, err,
		)
	}
	return nil
}

// ValidateAlgodNetwork verifies that algod is running a reviewed consensus
// contract (v42 or v43) and, when network is a reserved name, that it serves
// that network. Clients perform this live check; apsigner uses their shared
// compiled authorization contract and does not query algod.
func ValidateAlgodNetwork(ctx context.Context, network string, client *algod.Client) error {
	params, err := querySupportedAlgodConsensus(ctx, client)
	if err != nil {
		return err
	}
	return checkReservedNetwork(network, params.GenesisHash)
}

func querySupportedAlgodConsensus(ctx context.Context, client *algod.Client) (types.SuggestedParams, error) {
	if client == nil {
		return types.SuggestedParams{}, ErrNoAlgodClient
	}
	if ctx == nil {
		ctx = context.Background()
	}
	params, err := client.SuggestedParams().Do(ctx)
	if err != nil {
		return types.SuggestedParams{}, fmt.Errorf("query algod consensus: %w", err)
	}
	if err := checkSupportedConsensus(params.ConsensusVersion); err != nil {
		return types.SuggestedParams{}, err
	}
	return params, nil
}

// activeAlgodNetwork checks that the active algod runs a reviewed consensus
// contract and returns the network it serves. A read from the last
// consensusValidationReuseWindow is reused, the one that fetched suggested
// parameters for a transaction included, so it costs at most one algod call.
func (e *Core) activeAlgodNetwork(ctx context.Context) (algodNetwork, error) {
	if e == nil || e.AlgodClient == nil {
		return algodNetwork{}, ErrNoAlgodClient
	}
	client := e.AlgodClient
	now := time.Now()

	e.consensusValidation.mu.Lock()
	defer e.consensusValidation.mu.Unlock()
	// Only setLocked sets client, and only for parameters that passed
	// checkSupportedConsensus.
	if e.consensusValidation.client == client &&
		now.Sub(e.consensusValidation.validatedAt) < consensusValidationReuseWindow {
		return e.consensusValidation.network, nil
	}

	params, err := querySupportedAlgodConsensus(ctx, client)
	if err != nil {
		return algodNetwork{}, err
	}
	e.consensusValidation.setLocked(client, params)
	return e.consensusValidation.network, nil
}

func (e *Core) rememberAlgodConsensus(client *algod.Client, params types.SuggestedParams) error {
	if err := checkSupportedConsensus(params.ConsensusVersion); err != nil {
		e.consensusValidation.mu.Lock()
		if e.consensusValidation.client == client {
			e.consensusValidation.clearLocked()
		}
		e.consensusValidation.mu.Unlock()
		return err
	}
	if client == nil || e.AlgodClient != client {
		return nil
	}
	e.consensusValidation.mu.Lock()
	e.consensusValidation.setLocked(client, params)
	e.consensusValidation.mu.Unlock()
	return nil
}

func (e *Core) clearAlgodConsensusValidation() {
	e.consensusValidation.mu.Lock()
	e.consensusValidation.clearLocked()
	e.consensusValidation.mu.Unlock()
}
