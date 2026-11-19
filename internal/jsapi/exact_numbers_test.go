// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package jsapi

import (
	"fmt"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// TestBalanceAndAssetInfoKeepLargeAmountsExact pins that balance() and
// assetInfo() return an amount past 2^53, such as a full-supply holding of
// a 10^19-unit token, with its exact value, and that a script can pass it
// back as an amount: sendAsset(a, b, id, balance(a).assets[id].amount) for
// such a holder must not be refused as a rounded number.
func TestBalanceAndAssetInfoKeepLargeAmountsExact(t *testing.T) {
	const (
		assetID    = uint64(4242)
		supply     = uint64(10_000_000_000_000_000_000)
		algoAmount = uint64(1)<<53 + 1
	)
	holder := types.Address{41}.String()
	_, api := assetTestAPI(t,
		models.Account{
			Address: holder, Amount: algoAmount, MinBalance: 200_000,
			Assets: []models.AssetHolding{{AssetId: assetID, Amount: supply}},
		},
		models.Asset{Index: assetID, Params: models.AssetParams{
			Creator: holder, Total: supply, Name: "Big", UnitName: "BIG",
		}})

	// microalgos() reads its argument as every amount is read, so it stands
	// for passing the value back.
	v, err := api.runtime.RunString(fmt.Sprintf(`(() => {
		const b = balance(%q);
		const held = b.assets["%d"].amount;
		const info = assetInfo(%d);
		return [typeof held, String(held), String(microalgos(held)),
			typeof b.algo, String(microalgos(b.algo)),
			typeof b.minBalance, String(b.minBalance),
			typeof info.total, String(microalgos(info.total)), typeof info.assetId].join("|") })()`,
		holder, assetID, assetID))
	if err != nil {
		t.Fatalf("script error = %v", err)
	}
	want := strings.Join([]string{
		"bigint", "10000000000000000000", "10000000000000000000",
		"bigint", "9007199254740993",
		"number", "200000",
		"bigint", "10000000000000000000", "number",
	}, "|")
	if got := v.String(); got != want {
		t.Fatalf("result = %s\nwant     %s", got, want)
	}
}
