// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/aplane-algo/aplane/internal/lsigresource"
)

// consensusValidationReuseWindow avoids repeating SuggestedParams calls inside
// one interactive transaction workflow. The short bound keeps the client from
// carrying a successful consensus check across a network upgrade.
const consensusValidationReuseWindow = 30 * time.Second

type consensusValidationCache struct {
	mu          sync.Mutex
	client      *algod.Client
	version     string
	validatedAt time.Time
}

func resolveSupportedConsensus(version string) (lsigresource.ConsensusProfile, error) {
	profile, err := lsigresource.ResolveConsensus(version)
	if err != nil {
		return lsigresource.ConsensusProfile{}, fmt.Errorf(
			"network consensus %q is unsupported by this APlane release; required contract: v42 (%s): %w",
			version, lsigresource.CurrentConsensusVersion, err,
		)
	}
	return profile, nil
}

// ValidateAlgodConsensus verifies that algod is running the sole consensus
// contract supported by this APlane release. Clients perform this live check;
// apsigner uses the corresponding compiled contract and does not query algod.
func ValidateAlgodConsensus(ctx context.Context, client *algod.Client) error {
	_, err := querySupportedAlgodConsensus(ctx, client)
	return err
}

func querySupportedAlgodConsensus(ctx context.Context, client *algod.Client) (string, error) {
	if client == nil {
		return "", ErrNoAlgodClient
	}
	if ctx == nil {
		ctx = context.Background()
	}
	params, err := client.SuggestedParams().Do(ctx)
	if err != nil {
		return "", fmt.Errorf("query algod consensus: %w", err)
	}
	if _, err := resolveSupportedConsensus(params.ConsensusVersion); err != nil {
		return "", err
	}
	return params.ConsensusVersion, nil
}

func (e *Core) validateAlgodConsensus(ctx context.Context) error {
	if e == nil || e.AlgodClient == nil {
		return ErrNoAlgodClient
	}
	client := e.AlgodClient
	now := time.Now()

	e.consensusValidation.mu.Lock()
	defer e.consensusValidation.mu.Unlock()
	if e.consensusValidation.client == client &&
		e.consensusValidation.version != "" &&
		now.Sub(e.consensusValidation.validatedAt) < consensusValidationReuseWindow {
		return nil
	}

	version, err := querySupportedAlgodConsensus(ctx, client)
	if err != nil {
		return err
	}
	e.consensusValidation.client = client
	e.consensusValidation.version = version
	e.consensusValidation.validatedAt = time.Now()
	return nil
}

func (e *Core) rememberAlgodConsensus(client *algod.Client, version string) error {
	if _, err := resolveSupportedConsensus(version); err != nil {
		if e != nil {
			e.consensusValidation.mu.Lock()
			if e.consensusValidation.client == client {
				e.consensusValidation.client = nil
				e.consensusValidation.version = ""
				e.consensusValidation.validatedAt = time.Time{}
			}
			e.consensusValidation.mu.Unlock()
		}
		return err
	}
	if e == nil || client == nil || e.AlgodClient != client {
		return nil
	}
	e.consensusValidation.mu.Lock()
	e.consensusValidation.client = client
	e.consensusValidation.version = version
	e.consensusValidation.validatedAt = time.Now()
	e.consensusValidation.mu.Unlock()
	return nil
}

func (e *Core) clearAlgodConsensusValidation() {
	if e == nil {
		return
	}
	e.consensusValidation.mu.Lock()
	e.consensusValidation.client = nil
	e.consensusValidation.version = ""
	e.consensusValidation.validatedAt = time.Time{}
	e.consensusValidation.mu.Unlock()
}
