// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/cache"
)

func TestPluginAppCallInfo(t *testing.T) {
	if got := pluginAppCallInfo(types.Transaction{Type: types.PaymentTx}); got != nil {
		t.Fatalf("pluginAppCallInfo(payment) = %#v, want nil", got)
	}

	got := pluginAppCallInfo(types.Transaction{Type: types.ApplicationCallTx})
	if got == nil || got.Mode != "raw" || got.Method != "" {
		t.Fatalf("pluginAppCallInfo(app call) = %#v, want raw mode metadata", got)
	}
}

func TestZeroLocalSignerKeys(t *testing.T) {
	secretA := []byte{1, 2, 3}
	secretB := []byte{4, 5, 6}

	zeroLocalSignerKeys(map[string][]byte{
		"A": secretA,
		"B": secretB,
	})

	for i, b := range secretA {
		if b != 0 {
			t.Fatalf("secretA[%d] = %d, want 0", i, b)
		}
	}
	for i, b := range secretB {
		if b != 0 {
			t.Fatalf("secretB[%d] = %d, want 0", i, b)
		}
	}
}

func TestBuildPluginAssetContextStructuredAssets(t *testing.T) {
	assets := buildPluginAssetContext(map[uint64]cache.ASAInfo{
		20: {Name: "Second Token", UnitName: "DUP", Decimals: 6},
		10: {Name: "USDC", UnitName: "USDC", Decimals: 6},
		30: {Name: "dup", UnitName: "THIRD", Decimals: 2},
	})

	if len(assets) != 3 {
		t.Fatalf("assets len = %d, want 3", len(assets))
	}
	if assets[0].AssetID != 10 || assets[1].AssetID != 20 || assets[2].AssetID != 30 {
		t.Fatalf("assets sorted by ID = %+v", assets)
	}
	if assets[0].Name != "USDC" || assets[0].UnitName != "USDC" || assets[0].Decimals != 6 {
		t.Fatalf("assets[0] = %+v, want structured USDC metadata", assets[0])
	}
}
