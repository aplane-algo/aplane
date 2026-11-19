// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
)

const testAddress = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"

func TestBalanceSingleAccountRequiresAlgod(t *testing.T) {
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	app := New(eng, config.DefaultConfig(), t.TempDir())
	res, err := app.Balance(context.Background(), BalanceRequest{Args: []string{testAddress, "algo"}})
	if !errors.Is(err, engine.ErrNoAlgodClient) {
		t.Fatalf("Balance() error = %v, want %v", err, engine.ErrNoAlgodClient)
	}
	if res != nil {
		t.Fatalf("Balance() result = %#v, want nil on error", res)
	}
}

func TestBalanceRejectsTooManyArgs(t *testing.T) {
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	app := New(eng, config.DefaultConfig(), t.TempDir())
	if _, err := app.Balance(context.Background(), BalanceRequest{Args: []string{"a", "b", "c"}}); err == nil {
		t.Fatal("Balance() error = nil, want usage error")
	}
}

func TestBalanceResolvesSetModeWithoutAlgod(t *testing.T) {
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	cfg := config.DefaultConfig()
	eng.SetCache.Sets = map[string][]string{
		"team": {testAddress},
	}
	app := New(eng, cfg, t.TempDir())
	res, err := app.Balance(context.Background(), BalanceRequest{Args: []string{"@team"}})
	if err != nil {
		t.Fatalf("Balance() error = %v", err)
	}
	if res.Mode != BalanceModeMulti {
		t.Fatalf("Mode = %q, want %q", res.Mode, BalanceModeMulti)
	}
	if res.Asset.AssetID != 0 || res.Asset.UnitName != "ALGO" {
		t.Fatalf("Asset = %+v, want ALGO", res.Asset)
	}
}

// ALGO is named in any case: "Algo" shows ALGO balances, as "algo" does, in
// each mode of balance and in holders, rather than an asset no account holds.
func TestBalanceAndHoldersNameAlgoInAnyCase(t *testing.T) {
	f := newArgsFixture(t)
	ctx := context.Background()
	for _, args := range [][]string{{"Algo"}, {"@all", "Algo"}, {argsNative, "Algo"}, {argsNative, "aLGO"}} {
		res, err := f.app.Balance(ctx, BalanceRequest{Args: args})
		if err != nil {
			t.Fatalf("balance %v: %v", args, err)
		}
		if res.Asset.AssetID != 0 || res.Asset.UnitName != "ALGO" {
			t.Fatalf("balance %v shows %+v, want ALGO", args, res.Asset)
		}
	}

	res, err := f.app.Holders(ctx, []string{"Algo"})
	if err != nil {
		t.Fatalf("holders Algo: %v", err)
	}
	if res.Asset.AssetID != 0 || len(res.Addresses) == 0 || len(res.Balances) != len(res.Addresses) {
		t.Fatalf("holders Algo = %+v, want the funded accounts' ALGO", res)
	}

	if _, err := f.app.Balance(ctx, BalanceRequest{Args: []string{argsNative, "nosuchcoin"}}); err == nil ||
		!strings.Contains(err.Error(), "unknown asset 'nosuchcoin'") {
		t.Fatalf("balance of an unknown asset: %v, want it refused", err)
	}
}
