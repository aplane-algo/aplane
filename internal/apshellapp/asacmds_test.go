// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
)

// TestASAInfoReadsTheFullAssetFromTheNetwork pins that ASAInfo returns the
// asset's total supply and role addresses, also once its unit name and
// decimals are cached: the cache keeps only those, and answering from it
// showed "Total Supply: 0" and no creator.
func TestASAInfoReadsTheFullAssetFromTheNetwork(t *testing.T) {
	params := models.AssetParams{
		Creator: types.Address{71}.String(), Manager: types.Address{72}.String(),
		Reserve: types.Address{73}.String(), Freeze: types.Address{74}.String(),
		Clawback: types.Address{75}.String(), DefaultFrozen: true,
		Total: 10_000_000_000_000_000_000, Decimals: 6, Name: "Token", UnitName: "TOK", Url: "https://example.test",
	}
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/assets/777" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(models.Asset{Index: 777, Params: params})
	}))
	defer node.Close()
	client, err := algod.MakeClient(node.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	eng := engine.NewEngine("testnet", engine.WithAlgodClient(client),
		engine.WithASACache(cache.LoadASACacheFromStore(cache.NewStore(t.TempDir()), "testnet")))
	app := New(eng, config.DefaultConfig(), t.TempDir())

	want := ASAInfoDetails{
		AssetID: 777, UnitName: "TOK", Name: "Token", Decimals: 6, Total: params.Total,
		Creator: params.Creator, Manager: params.Manager, Reserve: params.Reserve,
		Freeze: params.Freeze, Clawback: params.Clawback, DefaultFrozen: true, URL: params.Url,
	}
	// The second call finds the asset in the cache.
	for _, call := range []string{"first", "second"} {
		result, err := app.ASAInfo(context.Background(), 777)
		if err != nil {
			t.Fatalf("%s ASAInfo() error = %v", call, err)
		}
		if result.Info != want {
			t.Fatalf("%s ASAInfo() = %+v\nwant %+v", call, result.Info, want)
		}
	}
}
