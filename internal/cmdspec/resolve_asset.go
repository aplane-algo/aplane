// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package cmdspec

import (
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/asa"
)

type AssetMetadataResolver interface {
	ResolveMetadata(ref string) (asa.Metadata, error)
}

func ResolveAssetMetadata(network, ref string, resolver AssetMetadataResolver) (asa.Metadata, error) {
	if strings.EqualFold(strings.TrimSpace(ref), "algo") {
		return asa.Metadata{
			Network:  network,
			AssetID:  0,
			UnitName: "ALGO",
			Name:     "ALGO",
			Decimals: 6,
		}, nil
	}
	return resolver.ResolveMetadata(ref)
}

func ResolveAssetAmount(network, assetRef, amount string, resolver AssetMetadataResolver) (asa.Amount, error) {
	meta, err := ResolveAssetMetadata(network, assetRef, resolver)
	if err != nil {
		return asa.Amount{}, err
	}
	return asa.AmountFromDisplay(amount, meta)
}

func ResolveForeignAssetIDs(network string, refs []AssetRef, resolver AssetMetadataResolver) ([]uint64, error) {
	assetIDs := make([]uint64, 0, len(refs))
	for _, ref := range refs {
		meta, err := ResolveAssetMetadata(network, ref.String(), resolver)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve asset reference %q: %w", ref.String(), err)
		}
		if meta.AssetID == 0 {
			return nil, fmt.Errorf("invalid foreign asset reference %q: app-call foreign assets must be ASA IDs, not algo", ref.String())
		}
		assetIDs = append(assetIDs, meta.AssetID)
	}
	return assetIDs, nil
}
