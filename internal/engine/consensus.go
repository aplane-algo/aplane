// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"context"
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/aplane-algo/aplane/internal/lsigresource"
)

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
	if client == nil {
		return ErrNoAlgodClient
	}
	params, err := client.SuggestedParams().Do(ctx)
	if err != nil {
		return fmt.Errorf("query algod consensus: %w", err)
	}
	_, err = resolveSupportedConsensus(params.ConsensusVersion)
	return err
}
