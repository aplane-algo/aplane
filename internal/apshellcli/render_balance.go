// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"fmt"
	"sort"

	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/asa"
)

// showFullBalance shows ALGO + all ASA balances for an account.
func (r *REPLState) showFullBalance(result *apshellapp.BalanceDetails) error {
	r.printf("%s\n", r.app().FormatAddress(result.Address, ""))

	algoMeta, _ := r.app().ResolveAssetMetadata("algo")
	r.printf("  ALGO: %s\n", asa.FormatDisplayAmount(result.AlgoBalance, algoMeta))

	if len(result.Assets) > 0 {
		for _, asset := range result.Assets {
			meta := asa.Metadata{
				Network:  r.app().Network(),
				AssetID:  asset.AssetID,
				UnitName: asset.UnitName,
				Decimals: asset.Decimals,
			}
			r.printf("  %s: %s\n", asa.DisplayRef(meta), asa.FormatDisplayAmount(asset.Amount, meta))
		}
	}

	return nil
}

// showSingleAssetBalance shows balance for a specific asset.
func (r *REPLState) showSingleAssetBalance(result *apshellapp.BalanceDetails, assetRef string) error {
	isAlgo := assetRef == "algo" || assetRef == "ALGO"

	if isAlgo {
		algoMeta, _ := r.app().ResolveAssetMetadata("algo")
		r.printf("%s: %s\n", r.app().FormatAddress(result.Address, ""), asa.DisplayString(asa.AmountFromRaw(result.AlgoBalance, algoMeta)))
		return nil
	}

	meta, err := r.app().ResolveAssetMetadata(assetRef)
	if err != nil {
		return fmt.Errorf("unknown asset '%s': %w", assetRef, err)
	}
	asaID := meta.AssetID

	for _, asset := range result.Assets {
		if asset.AssetID == asaID {
			holdingMeta := asa.Metadata{
				Network:  r.app().Network(),
				AssetID:  asaID,
				UnitName: asset.UnitName,
				Decimals: asset.Decimals,
			}
			r.printf("%s: %s\n", r.app().FormatAddress(result.Address, ""), asa.DisplayString(asa.AmountFromRaw(asset.Amount, holdingMeta)))
			return nil
		}
	}

	r.printf("%s: 0 %s (not opted in)\n", r.app().FormatAddress(result.Address, ""), assetRef)
	return nil
}

// showMultiAccountBalances shows balances across multiple accounts.
// addresses: list of addresses to show balances for
// assetRef: optional asset filter (empty = ALGO)
// holdersOnly: if true, only show accounts with non-zero balance
func (r *REPLState) showMultiAccountBalances(balances []*apshellapp.BalanceDetails, assetRef string, holdersOnly bool) error {
	if len(balances) == 0 {
		return fmt.Errorf("no accounts found")
	}

	isAlgo := assetRef == "" || assetRef == "algo" || assetRef == "ALGO"
	var asaID uint64
	meta, _ := r.app().ResolveAssetMetadata("algo")

	if assetRef != "" && !isAlgo {
		var err error
		meta, err = r.app().ResolveAssetMetadata(assetRef)
		if err != nil {
			return fmt.Errorf("unknown asset '%s': %w", assetRef, err)
		}
		asaID = meta.AssetID
	}

	type accountBalance struct {
		name string
		raw  uint64
	}
	var results []accountBalance
	var totalRaw uint64

	for _, result := range balances {
		var balanceRaw uint64
		found := false

		if assetRef == "" {
			balanceRaw = result.AlgoBalance
			found = true
		} else if isAlgo {
			balanceRaw = result.AlgoBalance
			found = true
		} else {
			for _, asset := range result.Assets {
				if asset.AssetID == asaID {
					balanceRaw = asset.Amount
					found = true
					break
				}
			}
		}

		if found && (!holdersOnly || balanceRaw > 0) {
			results = append(results, accountBalance{
				name: r.app().FormatAddress(result.Address, ""),
				raw:  balanceRaw,
			})
			totalRaw += balanceRaw
		}
	}

	if len(results) == 0 {
		if holdersOnly {
			r.println("No accounts with non-zero balance found")
		} else {
			r.println("No accounts found")
		}
		return nil
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].raw > results[j].raw
	})

	for _, ab := range results {
		r.printf("%s: %s\n", ab.name, asa.DisplayString(asa.AmountFromRaw(ab.raw, meta)))
	}

	r.printf("\nTotal: %s across %d accounts\n", asa.DisplayString(asa.AmountFromRaw(totalRaw, meta)), len(results))
	return nil
}
