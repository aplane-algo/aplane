// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"
	"gopkg.in/yaml.v3"
)

func TestStoredTransferPolicyApplyCompilesRoute(t *testing.T) {
	treasury := types.Address{1}.String()
	payroll := types.Address{2}.String()
	blocked := types.Address{3}.String()
	stored := parsePolicyYAML(t, `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  blocked_destinations:
    - `+blocked+`
    - `+blocked+`
  address_sets:
    treasury:
      mainnet:
        - `+treasury+`
    payroll:
      - `+payroll+`
  asset_sets:
    stablecoins:
      mainnet:
        - 31566704
  routes:
    - id: treasury_algo_payroll
      networks: [mainnet]
      sources: ["@treasury"]
      assets: ["algo"]
      destinations: ["@payroll"]
      limits:
        review_above: 250000000
        reject_above: 1000000000
`)
	cfg, err := stored.Apply(DefaultConfig())
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if cfg.TransferPolicy == nil {
		t.Fatal("TransferPolicy = nil")
	}
	if !cfg.TransferPolicy.Enabled {
		t.Fatal("TransferPolicy.Enabled = false, want true")
	}
	if got := cfg.TransferPolicy.OnNoRoute; got != TransferOnNoRouteReject {
		t.Fatalf("TransferPolicy.OnNoRoute = %q, want %q", got, TransferOnNoRouteReject)
	}
	if got := cfg.TransferPolicy.CloseOnNoRoute; got != TransferOnNoRouteReject {
		t.Fatalf("TransferPolicy.CloseOnNoRoute = %q, want %q", got, TransferOnNoRouteReject)
	}
	if got := cfg.TransferPolicy.ClawbackOnNoRoute; got != TransferOnNoRouteReject {
		t.Fatalf("TransferPolicy.ClawbackOnNoRoute = %q, want %q", got, TransferOnNoRouteReject)
	}
	blockedAddr := types.Address{3}
	if got := len(cfg.TransferPolicy.BlockedDestinations); got != 1 {
		t.Fatalf("blocked destinations length = %d, want 1", got)
	}
	if _, ok := cfg.TransferPolicy.BlockedDestinations[blockedAddr]; !ok {
		t.Fatalf("blocked destinations missing %s", blockedAddr)
	}
	if got := len(cfg.TransferPolicy.Routes); got != 1 {
		t.Fatalf("routes length = %d, want 1", got)
	}
	route := cfg.TransferPolicy.Routes[0]
	if route.ID != "treasury_algo_payroll" {
		t.Fatalf("route ID = %q", route.ID)
	}
	if route.Limits == nil || route.Limits.ReviewAbove == nil || *route.Limits.ReviewAbove != 250000000 {
		t.Fatalf("route review limit = %+v, want 250000000", route.Limits)
	}
}

func TestStoredTransferPolicyMarshalRoundTrip(t *testing.T) {
	addr := types.Address{1}.String()
	stored := parsePolicyYAML(t, `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  close_on_no_route: review
  clawback_on_no_route: operator_default
  address_sets:
    treasury:
      - `+addr+`
  routes:
    - id: treasury_algo
      networks: [mainnet]
      sources: ["@treasury"]
      assets: ["algo"]
      destinations: ["self"]
      close:
        allow: true
`)
	data, err := MarshalStoredConfig(stored)
	if err != nil {
		t.Fatalf("MarshalStoredConfig() error = %v", err)
	}
	if strings.Contains(string(data), "schemaversion") {
		t.Fatalf("marshaled transfer policy used invalid field name:\n%s", data)
	}
	if !strings.Contains(string(data), "schema_version: 1") {
		t.Fatalf("marshaled transfer policy missing schema_version:\n%s", data)
	}
	if !strings.Contains(string(data), "close_on_no_route: review") {
		t.Fatalf("marshaled transfer policy missing close_on_no_route:\n%s", data)
	}
	if !strings.Contains(string(data), "clawback_on_no_route: operator_default") {
		t.Fatalf("marshaled transfer policy missing clawback_on_no_route:\n%s", data)
	}
	roundTrip, err := ParseStoredConfig(data)
	if err != nil {
		t.Fatalf("ParseStoredConfig(round trip) error = %v\nyaml:\n%s", err, data)
	}
	if _, err := roundTrip.Apply(DefaultConfig()); err != nil {
		t.Fatalf("Apply(round trip) error = %v\nyaml:\n%s", err, data)
	}
}

func TestStoredTransferPolicyUnknownFieldsFailClosed(t *testing.T) {
	if _, err := ParseStoredConfig([]byte(`
reject_foreign_rekeys: false
`)); err == nil {
		t.Fatal("ParseStoredConfig() error = nil, want unknown top-level policy field")
	}

	if _, err := ParseStoredConfig([]byte(`
transfer_policy:
  schema_version: 1
  enabled: true
  default: reject
  routes: []
`)); err == nil {
		t.Fatal("ParseStoredConfig() error = nil, want old default field rejected")
	}

	if _, err := ParseStoredConfig([]byte(`
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  surprise: true
`)); err == nil {
		t.Fatal("ParseStoredConfig() error = nil, want unknown transfer_policy field")
	}

	if _, err := ParseStoredConfig([]byte(`
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  routes:
    - id: bad
      networks: [mainnet]
      sources: ["*"]
      assets: ["algo"]
      destinations: ["*"]
      clawbck:
        allow: true
`)); err == nil {
		t.Fatal("ParseStoredConfig() error = nil, want unknown route field")
	}
}

func TestStoredTransferPolicyEnabledRequiresOnNoRoute(t *testing.T) {
	stored := parsePolicyYAML(t, `
transfer_policy:
  schema_version: 1
  enabled: true
  routes: []
`)
	if _, err := stored.Apply(DefaultConfig()); err == nil {
		t.Fatal("Apply() error = nil, want missing on_no_route failure")
	}
}

func TestStoredTransferPolicyValidation(t *testing.T) {
	addr := types.Address{1}.String()
	other := types.Address{2}.String()
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name: "schema version required",
			yaml: `
transfer_policy:
  enabled: true
  on_no_route: reject
`,
			wantErr: "schema_version is required",
		},
		{
			name: "unsupported schema version rejected",
			yaml: `
transfer_policy:
  schema_version: 2
  enabled: true
  on_no_route: reject
`,
			wantErr: "unsupported schema_version",
		},
		{
			name: "enabled required",
			yaml: `
transfer_policy:
  schema_version: 1
  on_no_route: reject
`,
			wantErr: "enabled is required",
		},
		{
			name: "invalid on no route rejected",
			yaml: `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: allow
`,
			wantErr: "invalid on_no_route",
		},
		{
			name: "invalid close on no route rejected",
			yaml: `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  close_on_no_route: allow
`,
			wantErr: "invalid close_on_no_route",
		},
		{
			name: "invalid clawback on no route rejected",
			yaml: `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  clawback_on_no_route: allow
`,
			wantErr: "invalid clawback_on_no_route",
		},
		{
			name: "duplicate route id rejected",
			yaml: `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  routes:
    - id: dup
      networks: [mainnet]
      sources: ["*"]
      assets: ["algo"]
      destinations: ["` + addr + `"]
    - id: dup
      networks: [mainnet]
      sources: ["*"]
      assets: ["algo"]
      destinations: ["` + addr + `"]
`,
			wantErr: "duplicate route id",
		},
		{
			name: "route id punctuation rejected",
			yaml: `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  routes:
    - id: bad.route
      networks: [mainnet]
      sources: ["*"]
      assets: ["algo"]
      destinations: ["` + addr + `"]
`,
			wantErr: "invalid route id",
		},
		{
			name: "route id first character rejected",
			yaml: `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  routes:
    - id: "-bad"
      networks: [mainnet]
      sources: ["*"]
      assets: ["algo"]
      destinations: ["` + addr + `"]
`,
			wantErr: "invalid route id",
		},
		{
			name: "missing networks rejected",
			yaml: `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  routes:
    - id: missing_networks
      sources: ["*"]
      assets: ["algo"]
      destinations: ["` + addr + `"]
`,
			wantErr: "networks is required",
		},
		{
			name: "missing sources rejected",
			yaml: `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  routes:
    - id: missing_sources
      networks: [mainnet]
      assets: ["algo"]
      destinations: ["` + addr + `"]
`,
			wantErr: "sources is required",
		},
		{
			name: "missing assets rejected",
			yaml: `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  routes:
    - id: missing_assets
      networks: [mainnet]
      sources: ["*"]
      destinations: ["` + addr + `"]
`,
			wantErr: "assets is required",
		},
		{
			name: "missing destinations rejected",
			yaml: `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  routes:
    - id: missing_destinations
      networks: [mainnet]
      sources: ["*"]
      assets: ["algo"]
`,
			wantErr: "destinations is required",
		},
		{
			name: "mixed wildcard and concrete networks rejected",
			yaml: `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  routes:
    - id: mixed_networks
      networks: ["*", mainnet]
      sources: ["*"]
      assets: ["algo"]
      destinations: ["` + addr + `"]
`,
			wantErr: `networks must be ["*"] or concrete tokens`,
		},
		{
			name: "unresolved address set rejected",
			yaml: `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  routes:
    - id: unresolved_addr_set
      networks: [mainnet]
      sources: ["@missing"]
      assets: ["algo"]
      destinations: ["` + addr + `"]
`,
			wantErr: "unresolved address set",
		},
		{
			name: "unresolved asset set rejected",
			yaml: `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  routes:
    - id: unresolved_asset_set
      networks: [mainnet]
      sources: ["*"]
      assets: ["@missing"]
      destinations: ["` + addr + `"]
`,
			wantErr: "unresolved asset set",
		},
		{
			name: "self source rejected",
			yaml: `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  routes:
    - id: self_source
      networks: [mainnet]
      sources: ["self"]
      assets: ["algo"]
      destinations: ["` + addr + `"]
`,
			wantErr: "self is not allowed in sources",
		},
		{
			name: "self asset source rejected",
			yaml: `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  routes:
    - id: self_asset_source
      networks: [mainnet]
      sources: ["*"]
      asset_sources: ["self"]
      assets: [123]
      destinations: ["` + addr + `"]
      clawback:
        allow: true
`,
			wantErr: "self is not allowed in asset_sources",
		},
		{
			name: "asset sources require clawback allow",
			yaml: `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  routes:
    - id: asset_sources_without_clawback
      networks: [mainnet]
      sources: ["*"]
      asset_sources: ["` + other + `"]
      assets: [123]
      destinations: ["` + addr + `"]
`,
			wantErr: "asset_sources requires clawback.allow:true",
		},
		{
			name: "clawback allow requires asset sources",
			yaml: `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  routes:
    - id: clawback_without_asset_sources
      networks: [mainnet]
      sources: ["*"]
      assets: [123]
      destinations: ["` + addr + `"]
      clawback:
        allow: true
`,
			wantErr: "clawback.allow:true requires asset_sources",
		},
		{
			name: "clawback destination self rejected",
			yaml: `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  routes:
    - id: clawback_self_destination
      networks: [mainnet]
      sources: ["*"]
      asset_sources: ["` + other + `"]
      assets: [123]
      destinations: ["self"]
      clawback:
        allow: true
`,
			wantErr: "self is not allowed in clawback route destinations",
		},
		{
			name: "invalid asset term rejected",
			yaml: `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  routes:
    - id: invalid_asset
      networks: [mainnet]
      sources: ["*"]
      assets: ["not-an-asset"]
      destinations: ["` + addr + `"]
`,
			wantErr: "invalid asset term",
		},
		{
			name: "zero asa id rejected",
			yaml: `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  routes:
    - id: zero_asa
      networks: [mainnet]
      sources: ["*"]
      assets: [0]
      destinations: ["` + addr + `"]
`,
			wantErr: `invalid asset term "0"`,
		},
		{
			name: "star network key rejected in asset set",
			yaml: `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  asset_sets:
    bad:
      "*": [123]
`,
			wantErr: "* is not a valid network key",
		},
		{
			name: "limits by network outside route network",
			yaml: `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  routes:
    - id: limited
      networks: [mainnet]
      sources: ["*"]
      assets: ["algo"]
      destinations: ["` + addr + `"]
      limits_by_network:
        testnet:
          reject_above: 1
`,
			wantErr: "limits_by_network[testnet] is not included",
		},
		{
			name: "route limit threshold order rejected",
			yaml: `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  routes:
    - id: bad_limits
      networks: [mainnet]
      sources: ["*"]
      assets: ["algo"]
      destinations: ["` + addr + `"]
      limits:
        review_above: 10
        reject_above: 9
`,
			wantErr: "reject_above must be greater than or equal to review_above",
		},
		{
			name: "limits by network threshold order rejected",
			yaml: `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  routes:
    - id: bad_network_limits
      networks: [mainnet]
      sources: ["*"]
      assets: ["algo"]
      destinations: ["` + addr + `"]
      limits_by_network:
        mainnet:
          review_above: 10
          reject_above: 9
`,
			wantErr: "limits_by_network[mainnet]: reject_above must be greater than or equal to review_above",
		},
		{
			name: "wildcard assets with limits rejected",
			yaml: `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  routes:
    - id: wildcard_limited_assets
      networks: [mainnet]
      sources: ["*"]
      assets: ["*"]
      destinations: ["` + addr + `"]
      limits:
        reject_above: 1
`,
			wantErr: "wildcard assets",
		},
		{
			name: "mixed unit limits rejected",
			yaml: `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  routes:
    - id: mixed
      networks: [mainnet]
      sources: ["*"]
      assets: ["algo", 123]
      destinations: ["` + addr + `"]
      limits:
        reject_above: 1
`,
			wantErr: "one asset unit",
		},
		{
			name: "wildcard network direct mixed unit limits rejected",
			yaml: `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  routes:
    - id: wildcard_network_mixed_direct_assets
      networks: ["*"]
      sources: ["*"]
      assets: ["algo", 123]
      destinations: ["` + addr + `"]
      limits:
        reject_above: 1
`,
			wantErr: "one asset unit",
		},
		{
			name: "asset set global limits cannot span different asa ids",
			yaml: `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  asset_sets:
    stablecoins:
      mainnet: [1]
      testnet: [2]
  routes:
    - id: global_asset_set_limit
      networks: ["*"]
      sources: ["*"]
      assets: ["@stablecoins"]
      destinations: ["` + addr + `"]
      limits:
        reject_above: 1
`,
			wantErr: "global limits cannot span asset sets",
		},
		{
			name: "close wildcard destination rejected",
			yaml: `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  routes:
    - id: close_all
      networks: [mainnet]
      sources: ["*"]
      assets: ["algo"]
      destinations: ["*"]
      close:
        allow: true
`,
			wantErr: "wildcard destinations",
		},
		{
			name: "blocked destination self rejected",
			yaml: `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  blocked_destinations: ["self"]
`,
			wantErr: "self is not valid",
		},
		{
			name: "blocked destination wildcard rejected",
			yaml: `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  blocked_destinations: ["*"]
`,
			wantErr: "* is not valid",
		},
		{
			name: "blocked destination address set rejected",
			yaml: `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  blocked_destinations: ["@bad"]
`,
			wantErr: "address sets are not valid",
		},
		{
			name: "blocked destination malformed address rejected",
			yaml: `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  blocked_destinations: ["not-an-address"]
`,
			wantErr: "invalid address",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stored := parsePolicyYAML(t, tc.yaml)
			_, err := stored.Apply(DefaultConfig())
			if err == nil {
				t.Fatal("Apply() error = nil")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Apply() error = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestStoredTransferPolicyCompilesPrefixedASAID(t *testing.T) {
	addr := types.Address{1}.String()
	stored := parsePolicyYAML(t, `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  routes:
    - id: asa_route
      networks: [mainnet]
      sources: ["*"]
      assets: ["asa:123"]
      destinations: ["`+addr+`"]
`)
	cfg, err := stored.Apply(DefaultConfig())
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	route := cfg.TransferPolicy.Routes[0]
	if got := route.Assets.ASAIDs; len(got) != 1 || got[0] != 123 {
		t.Fatalf("route ASA IDs = %+v, want [123]", got)
	}
}

func TestStoredTransferPolicyKeyOverrideInheritsRoutesWhenAbsent(t *testing.T) {
	baseDest := types.Address{1}.String()
	overrideBlocked := types.Address{2}.String()
	overrideKey := types.Address{10}.String()
	stored := parsePolicyYAML(t, `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  close_on_no_route: review
  clawback_on_no_route: operator_default
  routes:
    - id: base_route
      networks: [mainnet]
      sources: ["*"]
      assets: ["algo"]
      destinations: ["`+baseDest+`"]
key_overrides:
  `+overrideKey+`:
    transfer_policy:
      schema_version: 1
      enabled: true
      blocked_destinations:
        - `+overrideBlocked+`
`)
	cfg, err := stored.Apply(DefaultConfig())
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	override := cfg.ForKey(overrideKey).TransferPolicy
	if override == nil {
		t.Fatal("override TransferPolicy = nil")
	}
	if got := override.OnNoRoute; got != TransferOnNoRouteReject {
		t.Fatalf("override OnNoRoute = %q, want %q", got, TransferOnNoRouteReject)
	}
	if got := override.CloseOnNoRoute; got != TransferOnNoRouteReview {
		t.Fatalf("override CloseOnNoRoute = %q, want %q", got, TransferOnNoRouteReview)
	}
	if got := override.ClawbackOnNoRoute; got != TransferOnNoRouteOperatorDefault {
		t.Fatalf("override ClawbackOnNoRoute = %q, want %q", got, TransferOnNoRouteOperatorDefault)
	}
	if got := len(override.Routes); got != 1 || override.Routes[0].ID != "base_route" {
		t.Fatalf("override routes = %+v, want inherited base_route", override.Routes)
	}
	if _, ok := override.BlockedDestinations[types.Address{2}]; !ok {
		t.Fatal("override did not add blocked destination")
	}
}

func TestStoredTransferPolicyKeyOverrideMergesSetsAndReplacesRoutes(t *testing.T) {
	treasury := types.Address{1}.String()
	ops := types.Address{2}.String()
	vendors := types.Address{3}.String()
	baseBlocked := types.Address{4}.String()
	overrideBlocked := types.Address{5}.String()
	overrideKey := types.Address{10}.String()
	stored := parsePolicyYAML(t, `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  blocked_destinations:
    - `+baseBlocked+`
  address_sets:
    treasury:
      - `+treasury+`
    ops:
      - `+ops+`
  routes:
    - id: base_route
      networks: [mainnet]
      sources: ["@treasury"]
      assets: ["algo"]
      destinations: ["@ops"]
key_overrides:
  `+overrideKey+`:
    transfer_policy:
      schema_version: 1
      enabled: true
      blocked_destinations:
        - `+overrideBlocked+`
      address_sets:
        vendors:
          - `+vendors+`
      routes:
        - id: override_route
          networks: [mainnet]
          sources: ["@treasury"]
          assets: ["algo"]
          destinations: ["@vendors"]
`)
	cfg, err := stored.Apply(DefaultConfig())
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	base := cfg.TransferPolicy
	if got := len(base.Routes); got != 1 || base.Routes[0].ID != "base_route" {
		t.Fatalf("base routes = %+v", base.Routes)
	}
	if _, ok := base.BlockedDestinations[types.Address{4}]; !ok {
		t.Fatal("base blocked destinations missing base entry")
	}
	if _, ok := base.BlockedDestinations[types.Address{5}]; ok {
		t.Fatal("base blocked destinations unexpectedly include override entry")
	}
	override := cfg.ForKey(overrideKey).TransferPolicy
	if override == nil {
		t.Fatal("override TransferPolicy = nil")
	}
	if got := len(override.Routes); got != 1 || override.Routes[0].ID != "override_route" {
		t.Fatalf("override routes = %+v", override.Routes)
	}
	if _, ok := override.AddressSets["treasury"]; !ok {
		t.Fatal("override did not inherit treasury address set")
	}
	if _, ok := override.AddressSets["vendors"]; !ok {
		t.Fatal("override did not add vendors address set")
	}
	if _, ok := override.BlockedDestinations[types.Address{4}]; !ok {
		t.Fatal("override did not inherit base blocked destination")
	}
	if _, ok := override.BlockedDestinations[types.Address{5}]; !ok {
		t.Fatal("override did not add blocked destination")
	}
}

func TestStoredTransferPolicyKeyOverrideEmptyRoutesRoundTrips(t *testing.T) {
	baseDest := types.Address{1}.String()
	overrideKey := types.Address{10}.String()
	stored := parsePolicyYAML(t, `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  routes:
    - id: base_route
      networks: [mainnet]
      sources: ["*"]
      assets: ["algo"]
      destinations: ["`+baseDest+`"]
key_overrides:
  `+overrideKey+`:
    transfer_policy:
      schema_version: 1
      enabled: true
      routes: []
`)
	assertOverrideRoutesCleared := func(t *testing.T, stored *StoredConfig) {
		t.Helper()
		cfg, err := stored.Apply(DefaultConfig())
		if err != nil {
			t.Fatalf("Apply() error = %v", err)
		}
		override := cfg.ForKey(overrideKey).TransferPolicy
		if override == nil {
			t.Fatal("override TransferPolicy = nil")
		}
		if got := len(override.Routes); got != 0 {
			t.Fatalf("override routes len = %d, want explicit clear", got)
		}
	}
	assertOverrideRoutesCleared(t, stored)

	roundTrip, err := yaml.Marshal(stored)
	if err != nil {
		t.Fatalf("yaml.Marshal() error = %v", err)
	}
	reloaded := parsePolicyYAML(t, string(roundTrip))
	assertOverrideRoutesCleared(t, reloaded)
}

func parsePolicyYAML(t *testing.T, raw string) *StoredConfig {
	t.Helper()
	cfg, err := ParseStoredConfig([]byte(raw))
	if err != nil {
		t.Fatalf("ParseStoredConfig() error = %v", err)
	}
	return cfg
}
