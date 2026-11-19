// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package jsapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/engine"
)

// assetTestAPI returns a JS runtime whose network answers for one account
// and one asset.
func assetTestAPI(t *testing.T, account models.Account, asset models.Asset) (*engine.Engine, *API) {
	t.Helper()
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v2/accounts/" + account.Address:
			_ = json.NewEncoder(w).Encode(account)
		case fmt.Sprintf("/v2/assets/%d", asset.Index):
			_ = json.NewEncoder(w).Encode(asset)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(node.Close)

	eng, _, api := newTestAPI(t)
	client, err := algod.MakeClient(node.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	eng.AlgodClient = client
	eng.AsaCache = cache.LoadASACacheFromStore(cache.NewStore(t.TempDir()), "testnet")
	return eng, api
}

// TestAssetInfoReturnsFullMetadata pins that assetInfo() returns the fields
// it documents, total and the role addresses included, even for an asset
// whose unit name and decimals are already cached: the cache keeps only
// those.
func TestAssetInfoReturnsFullMetadata(t *testing.T) {
	creator := types.Address{51}.String()
	manager := types.Address{52}.String()
	_, api := assetTestAPI(t, models.Account{Address: creator}, models.Asset{
		Index: 777,
		Params: models.AssetParams{
			Creator: creator, Manager: manager, Total: 1_000_000, Decimals: 2,
			Name: "Token", UnitName: "TOK", Url: "https://example.test",
		},
	})

	// The second call finds the asset in the cache.
	for _, call := range []string{"first", "second"} {
		v, err := api.runtime.RunString(`(() => { const i = assetInfo(777);
			return [i.unitName, i.decimals, i.total, i.creator, i.manager, i.url].join("|") })()`)
		if err != nil {
			t.Fatalf("%s call: %v", call, err)
		}
		want := fmt.Sprintf("TOK|2|1000000|%s|%s|https://example.test", creator, manager)
		if got := v.String(); got != want {
			t.Fatalf("%s call: assetInfo() = %s, want %s", call, got, want)
		}
	}
}
