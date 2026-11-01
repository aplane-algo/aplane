// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policycontext

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/asaset"
	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/noderole"
)

var updateDigests = flag.Bool("update-digests", false, "rewrite the digest fixtures from the current encoder")

var digestFixture = filepath.Join("..", "..", "test", "contracts", "policycontext", "v1", "digests.json")

type digestCase struct {
	Name            string            `json:"name"`
	Role            string            `json:"role"`
	RulesVersion    int               `json:"rules_version"`
	Networks        map[string]string `json:"networks"`
	Assets          []digestAsset     `json:"assets"`
	PolicySetSHA256 string            `json:"policy_set_sha256"`
	ContextSHA256   string            `json:"context_sha256"`
	SnapshotSHA256  string            `json:"snapshot_sha256"`
}

type digestAsset struct {
	GenesisHash string `json:"genesis_hash"`
	AssetID     uint64 `json:"asset_id"`
	Origin      string `json:"origin"`
	Decimals    uint64 `json:"decimals"`
	UnitName    string `json:"unit_name"`
	Name        string `json:"name"`
}

func (c digestCase) context(t *testing.T) *Context {
	t.Helper()
	networks := map[string]asaset.GenesisHash{}
	for token, hash := range c.Networks {
		g, err := asaset.ParseGenesisHash(hash)
		if err != nil {
			t.Fatal(err)
		}
		networks[token] = g
	}
	var assets []asaset.Asset
	for _, a := range c.Assets {
		g, err := asaset.ParseGenesisHash(a.GenesisHash)
		if err != nil {
			t.Fatal(err)
		}
		assets = append(assets, asaset.Asset{Identity: asaset.Identity{Genesis: g, AssetID: a.AssetID}, Origin: asaset.Origin(a.Origin), Decimals: a.Decimals, UnitName: a.UnitName, Name: a.Name})
	}
	table, err := asaset.NewTable(assets)
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := FromParts(noderole.Role(c.Role), networks, table, c.RulesVersion)
	if err != nil {
		t.Fatal(err)
	}
	return ctx
}

// The digest fixtures pin the canonical encoding: another implementation, or
// a later version of this one, must produce the same digests.
func TestDigestFixtures(t *testing.T) {
	data, err := os.ReadFile(digestFixture)
	if err != nil {
		t.Fatal(err)
	}
	var cases []digestCase
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) == 0 {
		t.Fatal("no digest cases")
	}
	for i := range cases {
		c := &cases[i]
		ctx := c.context(t)
		gotContext := ctx.SHA256()
		gotSnapshot := SnapshotSHA256(gotContext, c.PolicySetSHA256)
		if *updateDigests {
			c.ContextSHA256, c.SnapshotSHA256 = gotContext, gotSnapshot
			continue
		}
		if gotContext != c.ContextSHA256 || gotSnapshot != c.SnapshotSHA256 {
			t.Errorf("%s: context %s snapshot %s, want %s %s", c.Name, gotContext, gotSnapshot, c.ContextSHA256, c.SnapshotSHA256)
		}
	}
	if *updateDigests {
		out, err := json.MarshalIndent(cases, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(digestFixture, append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func sampleContext(t *testing.T, mutate func(*map[string]asaset.GenesisHash, *[]asaset.Asset, *noderole.Role, *int)) *Context {
	t.Helper()
	networks := map[string]asaset.GenesisHash{"mainnet": {1}, "private-dev": {2}}
	assets := []asaset.Asset{
		{Identity: asaset.Identity{Genesis: asaset.GenesisHash{1}, AssetID: 31566704}, Origin: asaset.OriginBuiltin, Decimals: 6, UnitName: "USDC", Name: "USDC"},
		{Identity: asaset.Identity{Genesis: asaset.GenesisHash{2}, AssetID: 7}, Origin: asaset.OriginOperator, Decimals: 2, UnitName: "XYZ", Name: "Example"},
	}
	role, version := noderole.RoleSigner, AdmissionRulesVersion
	if mutate != nil {
		mutate(&networks, &assets, &role, &version)
	}
	table, err := asaset.NewTable(assets)
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := FromParts(role, networks, table, version)
	if err != nil {
		t.Fatal(err)
	}
	return ctx
}

func TestDigestChangesWithMeaningOnly(t *testing.T) {
	base := sampleContext(t, nil).SHA256()
	for name, mutate := range map[string]func(*map[string]asaset.GenesisHash, *[]asaset.Asset, *noderole.Role, *int){
		"role": func(_ *map[string]asaset.GenesisHash, _ *[]asaset.Asset, r *noderole.Role, _ *int) {
			*r = noderole.RoleCosigner
		},
		"rules version": func(_ *map[string]asaset.GenesisHash, _ *[]asaset.Asset, _ *noderole.Role, v *int) { *v++ },
		"a token's chain": func(n *map[string]asaset.GenesisHash, _ *[]asaset.Asset, _ *noderole.Role, _ *int) {
			(*n)["private-dev"] = asaset.GenesisHash{3}
		},
		"another token": func(n *map[string]asaset.GenesisHash, _ *[]asaset.Asset, _ *noderole.Role, _ *int) {
			(*n)["other"] = asaset.GenesisHash{4}
		},
		"a token's name": func(n *map[string]asaset.GenesisHash, _ *[]asaset.Asset, _ *noderole.Role, _ *int) {
			delete(*n, "private-dev")
			(*n)["private-dev2"] = asaset.GenesisHash{2}
		},
		"decimals": func(_ *map[string]asaset.GenesisHash, a *[]asaset.Asset, _ *noderole.Role, _ *int) {
			(*a)[1].Decimals = 6
		},
		"unit name": func(_ *map[string]asaset.GenesisHash, a *[]asaset.Asset, _ *noderole.Role, _ *int) {
			(*a)[1].UnitName = "XYY"
		},
		"name": func(_ *map[string]asaset.GenesisHash, a *[]asaset.Asset, _ *noderole.Role, _ *int) {
			(*a)[1].Name = "Other"
		},
		"origin": func(_ *map[string]asaset.GenesisHash, a *[]asaset.Asset, _ *noderole.Role, _ *int) {
			(*a)[1].Origin = asaset.OriginBuiltin
		},
		"an asset's chain": func(_ *map[string]asaset.GenesisHash, a *[]asaset.Asset, _ *noderole.Role, _ *int) {
			(*a)[1].Genesis = asaset.GenesisHash{9}
		},
		"an asset more": func(_ *map[string]asaset.GenesisHash, a *[]asaset.Asset, _ *noderole.Role, _ *int) {
			*a = append(*a, asaset.Asset{Identity: asaset.Identity{Genesis: asaset.GenesisHash{2}, AssetID: 8}, Origin: asaset.OriginOperator})
		},
		"split across fields": func(_ *map[string]asaset.GenesisHash, a *[]asaset.Asset, _ *noderole.Role, _ *int) {
			(*a)[1].UnitName, (*a)[1].Name = "XY", "ZExample"
		},
	} {
		if got := sampleContext(t, mutate).SHA256(); got == base {
			t.Errorf("changing the %s left the digest unchanged", name)
		}
	}
	// Asset order in the input does not matter: the table is sorted.
	reordered := sampleContext(t, func(_ *map[string]asaset.GenesisHash, a *[]asaset.Asset, _ *noderole.Role, _ *int) {
		(*a)[0], (*a)[1] = (*a)[1], (*a)[0]
	})
	if reordered.SHA256() != base {
		t.Error("the digest depends on input order")
	}
}

func TestConfirmationDiagnosticsDoNotChangeTheDigest(t *testing.T) {
	networks, err := apconfig.NewGenesisHashNetworkResolver(nil)
	if err != nil {
		t.Fatal(err)
	}
	entry := asaset.Entry{
		Identity:              asaset.Identity{Genesis: asaset.GenesisHash{5}, AssetID: 1},
		UnitName:              "XYZ",
		Decimals:              2,
		Creator:               types.Address{1}.String(),
		ConfirmedAt:           time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NetworkAtConfirmation: "private-dev",
	}
	digest := func(e asaset.Entry) string {
		set, err := asaset.New([]asaset.Entry{e})
		if err != nil {
			t.Fatal(err)
		}
		ctx, err := New(noderole.RoleSigner, networks, set)
		if err != nil {
			t.Fatal(err)
		}
		return ctx.SHA256()
	}
	base := digest(entry)
	later := entry
	later.ConfirmedAt, later.NetworkAtConfirmation, later.Creator = later.ConfirmedAt.Add(time.Hour), "renamed", types.Address{2}.String()
	if digest(later) != base {
		t.Fatal("confirmation time, confirming token or creator changed the digest")
	}
}

func TestSnapshotDigestBindsBoth(t *testing.T) {
	a := SnapshotSHA256("c1", "p1")
	for _, other := range []string{SnapshotSHA256("c2", "p1"), SnapshotSHA256("c1", "p2"), SnapshotSHA256("c1p", "1"), SnapshotSHA256("p1", "c1")} {
		if other == a {
			t.Fatal("the snapshot digest does not bind both digests in order")
		}
	}
}

func TestNewContextResolvesTokensToChains(t *testing.T) {
	const custom = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	networks, err := apconfig.NewGenesisHashNetworkResolver(map[string]string{custom: "private-dev"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := New(noderole.RoleCosigner, networks, asaset.Empty())
	if err != nil {
		t.Fatal(err)
	}
	if g, ok := ctx.Chain("private-dev"); !ok || g.String() != custom {
		t.Fatalf("Chain(private-dev) = %s, %v", g, ok)
	}
	usdc, ok := ctx.Asset("mainnet", 31566704)
	if !ok || usdc.UnitName != "USDC" {
		t.Fatalf("Asset(mainnet, USDC) = %+v, %v", usdc, ok)
	}
	if _, ok := ctx.Asset("private-dev", 31566704); ok {
		t.Fatal("mainnet's USDC ID was found on a custom chain")
	}
	if _, err := New("nobody", networks, asaset.Empty()); err == nil {
		t.Fatal("New accepted an unknown role")
	}
}
