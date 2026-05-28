// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"errors"
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
	if res.AssetRef != "algo" {
		t.Fatalf("AssetRef = %q, want algo", res.AssetRef)
	}
}
