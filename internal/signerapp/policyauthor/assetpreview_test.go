// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyauthor

import (
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/asaset"
	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/policycontext"
)

const (
	previewGenesisA = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	previewGenesisB = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="
)

// previewNode is an export of a node mapping private-dev to genesis, with
// asset 9 confirmed on chain A as XYZ with 2 decimals.
func previewNode(t *testing.T, genesis string) *NodeContext {
	t.Helper()
	resolver, err := apconfig.NewGenesisHashNetworkResolver(map[string]string{genesis: "private-dev"})
	if err != nil {
		t.Fatal(err)
	}
	chainA, err := asaset.ParseGenesisHash(previewGenesisA)
	if err != nil {
		t.Fatal(err)
	}
	set, err := asaset.New([]asaset.Entry{{
		Identity:              asaset.Identity{Genesis: chainA, AssetID: 9},
		Name:                  "Example",
		UnitName:              "XYZ",
		Decimals:              2,
		Creator:               testAddress,
		ConfirmedAt:           time.Unix(1_700_000_000, 0),
		NetworkAtConfirmation: "private-dev",
	}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := policycontext.New(noderole.RoleSigner, resolver, set)
	if err != nil {
		t.Fatal(err)
	}
	return &NodeContext{Context: ctx, ExportedAt: time.Now(), Path: "export/.appolicy/node.json"}
}

func TestPreviewAssetStatuses(t *testing.T) {
	node := previewNode(t, previewGenesisA)
	for _, tt := range []struct {
		name    string
		node    *NodeContext
		network string
		term    string
		status  AssetStatus
		want    []string
	}{
		{"confirmed on the node", node, "private-dev", "asa:9", AssetInNodeSet,
			[]string{"asa:9 on private-dev: XYZ (Example), 2 decimals", "in the exported node's ASA set, confirmed on the node"}},
		{"a built-in in the node's set", node, "mainnet", "asa:31566704", AssetInNodeSet,
			[]string{"USDC", "6 decimals", "in the exported node's ASA set, built-in"}},
		{"absent from the node's set", node, "private-dev", "asa:10", AssetNotInNodeSet,
			[]string{"not in the exported node's ASA set", "apadmin asa add private-dev 10"}},
		{"a network the node does not map", node, "mainet", "asa:9", AssetUnresolved,
			[]string{`network "mainet" is not one the exported node maps`}},
		{"built-in without an export", nil, "mainnet", "asa:31566704", AssetBuiltin,
			[]string{"USDC", "6 decimals", "unverified without its export"}},
		{"unknown without an export", nil, "mainnet", "asa:77", AssetUnknown,
			[]string{"unknown asset, decimals unknown; amounts are in base units"}},
		{"a custom network without an export", nil, "private-dev", "asa:9", AssetUnresolved,
			[]string{"not a built-in network"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p, ok := PreviewAsset(tt.node, tt.network, tt.term)
			if !ok || p.Status != tt.status {
				t.Fatalf("PreviewAsset = %+v, %v; want status %d", p, ok, tt.status)
			}
			for _, want := range tt.want {
				if !strings.Contains(p.String(), want) {
					t.Fatalf("preview %q is missing %q", p.String(), want)
				}
			}
			if p.Status == AssetUnknown && p.DecimalsKnown {
				t.Fatal("an unknown asset claims known decimals")
			}
			if strings.Contains(p.String(), "live") {
				t.Fatalf("preview %q claims a live lookup", p.String())
			}
		})
	}
	for _, term := range []string{"algo", "*", "@usd", "not-an-asset"} {
		if _, ok := PreviewAsset(node, "mainnet", term); ok {
			t.Errorf("PreviewAsset(%q) previewed a term that names no specific asset", term)
		}
	}
}

// The same ID is a different asset, or none, on each chain, and a token
// remapped to another chain does not carry the old chain's metadata.
func TestPreviewAssetIdentityIsTheChain(t *testing.T) {
	mainnet, _ := PreviewAsset(nil, "mainnet", "asa:31566704")
	testnet, _ := PreviewAsset(nil, "testnet", "asa:31566704")
	if mainnet.Status != AssetBuiltin || testnet.Status != AssetUnknown || mainnet.Genesis == testnet.Genesis {
		t.Fatalf("one ID on two networks: %+v and %+v", mainnet, testnet)
	}
	remapped, _ := PreviewAsset(previewNode(t, previewGenesisB), "private-dev", "asa:9")
	if remapped.Status != AssetNotInNodeSet || remapped.Genesis != previewGenesisB || remapped.UnitName != "" {
		t.Fatalf("a remapped network reused another chain's metadata: %+v", remapped)
	}
}

func TestAssetPreviewsFollowTheFieldsNetwork(t *testing.T) {
	d, err := policy.ParseDraft([]byte(`{
  "asset_sets": {"usd": {"private-dev": []}},
  "transfer_policy": {"routes": [
    {"id": "one", "networks": ["private-dev"], "assets": []},
    {"id": "two", "networks": ["private-dev", "mainnet"], "assets": []},
    {"id": "any", "networks": ["*"], "assets": []},
    {"id": "none", "assets": []}
  ]}
}`))
	if err != nil {
		t.Fatal(err)
	}
	node := previewNode(t, previewGenesisA)
	setMember := EditSpec{Kind: EditTerms, Term: TermAssetRef, Pointer: "/asset_sets/usd/private-dev"}
	if got := setMember.AssetPreviews(d, node, "9"); len(got) != 1 || got[0].Status != AssetInNodeSet || got[0].Term != "asa:9" {
		t.Fatalf("set member: %+v", got)
	}
	single := EditSpec{Kind: EditTerms, Term: TermAsset, Pointer: "/transfer_policy/routes/0/assets"}
	if got := single.AssetPreviews(d, node, "algo, 9, *, @usd"); len(got) != 1 || got[0].Status != AssetInNodeSet {
		t.Fatalf("a one-network route: %+v", got)
	}
	for i, want := range map[int]string{1: "exactly one network", 2: "exactly one network", 3: "no network yet"} {
		spec := EditSpec{Kind: EditTerms, Term: TermAsset, Pointer: "/transfer_policy/routes/" + string(rune('0'+i)) + "/assets"}
		got := spec.AssetPreviews(d, node, "9")
		if len(got) != 1 || got[0].Status != AssetUnresolved || !strings.Contains(got[0].Reason, want) {
			t.Fatalf("route %d: %+v, want unresolved: %q", i, got, want)
		}
	}
}

func TestLimitAddNormalizesAndPreviewsItsAsset(t *testing.T) {
	d, err := policy.ParseDraft([]byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	add := limitAdd("Add a limit", "/limits", false)
	next, err := add.Apply(d, "mainnet 0031566704")
	if err != nil {
		t.Fatal(err)
	}
	if !next.At("/limits/mainnet/asa:31566704/review_above").Exists() {
		t.Fatalf("the limit was not stored under asa:31566704: %s", compact(next.Root()))
	}
	got := add.AssetPreviews(nil, "mainnet 31566704")
	if len(got) != 1 || got[0].Status != AssetBuiltin || got[0].UnitName != "USDC" {
		t.Fatalf("limit preview: %+v", got)
	}
	if got := add.AssetPreviews(nil, "mainnet 0"); len(got) != 1 || got[0].Status != AssetInvalid {
		t.Fatalf("an invalid limit asset was not shown: %+v", got)
	}
	if got := add.AssetPreviews(nil, "mainnet"); got != nil {
		t.Fatalf("a half-typed limit was previewed: %+v", got)
	}
	if got := add.AssetPreviews(nil, "mainnet algo"); got != nil {
		t.Fatalf("ALGO previewed as an asset: %+v", got)
	}
	if got := (AddAction{}).AssetPreviews(nil, "mainnet 9"); got != nil {
		t.Fatalf("an action without assets previewed one: %+v", got)
	}
}

func TestSummarizeAssetsCountsEveryProblem(t *testing.T) {
	node := previewNode(t, previewGenesisA)
	spec := EditSpec{Kind: EditTerms, Term: TermAssetRef, Pointer: "/asset_sets/usd/private-dev"}
	d, err := policy.ParseDraft([]byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	previews := spec.AssetPreviews(d, node, "9, 10, 11, 9")
	got := SummarizeAssets(previews)
	if !strings.Contains(got, "4 asset term(s), 2 with a problem") || !strings.Contains(got, "first: asa:10 on private-dev") {
		t.Fatalf("summary %q", got)
	}
	if got := SummarizeAssets(previews[:1]); got != "1 asset term(s), no problems" {
		t.Fatalf("summary %q", got)
	}

	// Terms the field does not accept count too, and keep their place.
	previews = spec.AssetPreviews(d, node, "9, 0, 18446744073709551616, nope, 9")
	got = SummarizeAssets(previews)
	if !strings.Contains(got, "5 asset term(s), 3 with a problem") || !strings.Contains(got, `first: "0": asset ID 0`) {
		t.Fatalf("summary of invalid terms %q", got)
	}
	for i, p := range previews {
		if p.Index != i {
			t.Fatalf("preview %d has index %d", i, p.Index)
		}
		if (i >= 1 && i <= 3) != (p.Status == AssetInvalid) {
			t.Fatalf("preview %d: %+v", i, p)
		}
	}
	routeAssets := EditSpec{Kind: EditTerms, Term: TermAsset, Pointer: "/asset_sets/usd/private-dev"}
	if got := routeAssets.AssetPreviews(d, node, "algo, , @usd, *"); got != nil {
		t.Fatalf("terms naming no specific asset were previewed: %+v", got)
	}
}

func TestTermIndexAt(t *testing.T) {
	for _, tt := range []struct {
		input string
		pos   int
		want  int
	}{
		{"77, 10458941", 0, 0},
		{"77, 10458941", 2, 0},
		{"77, 10458941", 3, 1},
		{"77, 10458941", 12, 1},
		{"", 0, 0},
		{"a,b,c", 5, 2},
	} {
		if got := TermIndexAt(tt.input, tt.pos); got != tt.want {
			t.Errorf("TermIndexAt(%q, %d) = %d, want %d", tt.input, tt.pos, got, tt.want)
		}
	}
}
