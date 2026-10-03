// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

func TestTransferPolicyV1CompilesRoute(t *testing.T) {
	treasury := types.Address{1}
	payroll := types.Address{2}
	blocked := types.Address{3}
	holder := types.Address{4}
	cfg := routingConfig(t, `{
  "format": "aplane.signer-policy.v1",
  "address_sets": {
    "treasury": {"mainnet": ["`+treasury.String()+`"]},
    "payroll": ["`+payroll.String()+`"]
  },
  "asset_sets": {"stablecoins": {"mainnet": ["asa:31566704"]}},
  "transfer_policy": {
    "enabled": true,
    "on_no_route": "reject",
    "blocked_destinations": ["`+blocked.String()+`"],
    "routes": [
      {"id": "treasury_algo_payroll", "networks": ["mainnet"], "sources": ["@treasury"], "assets": ["algo"],
       "destinations": ["@payroll"], "allow_close": true,
       "limits": {"mainnet": {"algo": {"review_above": "250000000", "reject_above": "1000000000"}}}},
      {"id": "stablecoin_recovery", "networks": ["*"], "sources": ["@treasury"], "asset_sources": ["`+holder.String()+`"],
       "assets": ["@stablecoins"], "destinations": ["@payroll"], "allow_clawback": true}
    ]
  }
}`)
	tp := cfg.TransferPolicy
	if tp == nil {
		t.Fatal("TransferPolicy = nil")
	}
	if !tp.Enabled {
		t.Fatal("TransferPolicy.Enabled = false, want true")
	}
	if got := tp.OnNoRoute; got != TransferOnNoRouteReject {
		t.Fatalf("TransferPolicy.OnNoRoute = %q, want %q", got, TransferOnNoRouteReject)
	}
	if got := tp.CloseOnNoRoute; got != TransferOnNoRouteReject {
		t.Fatalf("TransferPolicy.CloseOnNoRoute = %q, want %q", got, TransferOnNoRouteReject)
	}
	if got := tp.ClawbackOnNoRoute; got != TransferOnNoRouteReject {
		t.Fatalf("TransferPolicy.ClawbackOnNoRoute = %q, want %q", got, TransferOnNoRouteReject)
	}
	if got := len(tp.BlockedDestinations); got != 1 {
		t.Fatalf("blocked destinations length = %d, want 1", got)
	}
	if _, ok := tp.BlockedDestinations[blocked]; !ok {
		t.Fatalf("blocked destinations missing %s", blocked)
	}
	if got := len(tp.Routes); got != 2 {
		t.Fatalf("routes length = %d, want 2", got)
	}

	route := tp.Routes[0]
	if route.ID != "treasury_algo_payroll" {
		t.Fatalf("route ID = %q", route.ID)
	}
	if _, ok := route.Networks["mainnet"]; route.NetworkWildcard || len(route.Networks) != 1 || !ok {
		t.Fatalf("route networks = %v (wildcard %v), want [mainnet]", route.Networks, route.NetworkWildcard)
	}
	if got := route.Sources.Sets; len(got) != 1 || got[0] != "treasury" {
		t.Fatalf("route source sets = %v, want [treasury]", got)
	}
	if got := route.Destinations.Sets; len(got) != 1 || got[0] != "payroll" {
		t.Fatalf("route destination sets = %v, want [payroll]", got)
	}
	if !route.Assets.Algo || len(route.Assets.ASAIDs) != 0 {
		t.Fatalf("route assets = %+v, want algo only", route.Assets)
	}
	if !route.AllowClose || route.AllowClawback {
		t.Fatalf("route allow close/clawback = %v/%v, want true/false", route.AllowClose, route.AllowClawback)
	}
	if got := len(route.Limits); got != 1 {
		t.Fatalf("route limits networks = %d, want 1", got)
	}
	algo := route.Limits["mainnet"][TransferAssetRef{Algo: true}]
	if algo.ReviewAbove == nil || *algo.ReviewAbove != 250000000 {
		t.Fatalf("route review limit = %+v, want 250000000", algo)
	}
	if algo.RejectAbove == nil || *algo.RejectAbove != 1000000000 {
		t.Fatalf("route reject limit = %+v, want 1000000000", algo)
	}

	recovery := tp.Routes[1]
	if !recovery.NetworkWildcard {
		t.Fatal("recovery route NetworkWildcard = false, want true")
	}
	if got := recovery.Assets.Sets; len(got) != 1 || got[0] != "stablecoins" {
		t.Fatalf("recovery asset sets = %v, want [stablecoins]", got)
	}
	if got := recovery.AssetSources.Direct; len(got) != 1 || got[0] != holder {
		t.Fatalf("recovery asset sources = %v, want [%s]", got, holder)
	}
	if recovery.AllowClose || !recovery.AllowClawback {
		t.Fatalf("recovery allow close/clawback = %v/%v, want false/true", recovery.AllowClose, recovery.AllowClawback)
	}
	if len(recovery.Limits) != 0 {
		t.Fatalf("recovery limits = %v, want none", recovery.Limits)
	}
	if got := tp.AssetSets["stablecoins"].ByNetwork["mainnet"]; len(got) != 1 || got[0] != 31566704 {
		t.Fatalf("stablecoins set = %v, want [31566704]", got)
	}
}

func TestTransferPolicyV1CompilesPrefixedASAID(t *testing.T) {
	addr := types.Address{1}.String()
	cfg := routingConfig(t, `{
  "format": "aplane.signer-policy.v1",
  "transfer_policy": {"enabled": true, "on_no_route": "reject", "routes": [
    {"id": "asa_route", "networks": ["mainnet"], "sources": ["*"], "assets": ["asa:123"], "destinations": ["`+addr+`"]}
  ]}
}`)
	route := cfg.TransferPolicy.Routes[0]
	if got := route.Assets.ASAIDs; len(got) != 1 || got[0] != 123 {
		t.Fatalf("route ASA IDs = %+v, want [123]", got)
	}
}
