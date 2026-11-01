// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy_test

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/policy/policytest"
)

const refsAddr = "CEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEI7JH2AYM"

// A document naming networks and assets in every place a document can.
var everyReference = `{
  "limits": {"mainnet": {"algo": {"reject_above": "1"}, "asa:31566704": {"reject_above": "2"}}},
  "address_sets": {"ops": {"testnet": ["` + refsAddr + `"]}, "flat": ["` + refsAddr + `"]},
  "asset_sets": {"usd": {"mainnet": ["asa:31566704"], "private-dev": ["algo", "asa:9"]}},
  "transfer_policy": {"routes": [
    {"id": "one-net", "networks": ["mainnet"], "sources": ["*"], "assets": ["asa:31566704", "@usd"], "destinations": ["*"],
     "limits": {"mainnet": {"asa:31566704": {"review_above": "3"}}}},
    {"id": "two-nets", "networks": ["mainnet", "testnet"], "sources": ["*"], "assets": ["asa:5"], "destinations": ["*"]},
    {"id": "everywhere", "networks": ["*"], "sources": ["*"], "assets": ["algo", "@usd"], "destinations": ["*"]}
  ]}
}`

func decodeRefs(t *testing.T, doc string) (*policy.PolicyV1, *policy.Draft) {
	t.Helper()
	data := []byte(doc)
	decoded, err := policy.DecodePolicyV1(data, policy.DefaultKey, noderole.RoleSigner)
	if err != nil {
		t.Fatalf("decode: %v\n%s", err, doc)
	}
	draft, err := policy.ParseDraft(data)
	if err != nil {
		t.Fatal(err)
	}
	return decoded, draft
}

func TestReferencesListEveryLocation(t *testing.T) {
	doc, draft := decodeRefs(t, policytest.Signer(t, policy.DefaultKey, everyReference))
	refs := doc.References()

	var networks []string
	for _, n := range refs.Networks {
		networks = append(networks, n.Pointer+"="+n.Network)
	}
	for _, want := range []string{
		"/limits/mainnet=mainnet",
		"/address_sets/ops/testnet=testnet",
		"/asset_sets/usd/private-dev=private-dev",
		"/transfer_policy/routes/1/networks/1=testnet",
		"/transfer_policy/routes/0/limits/mainnet=mainnet",
	} {
		if !contains(networks, want) {
			t.Errorf("network references %v lack %s", networks, want)
		}
	}
	for _, n := range refs.Networks {
		if n.Network == "*" {
			t.Errorf("a wildcard network was listed as a token: %+v", n)
		}
	}

	var assets []string
	for _, a := range refs.Assets {
		assets = append(assets, a.Pointer+"="+a.Network+":"+strconv.FormatUint(a.AssetID, 10))
	}
	for _, want := range []string{
		"/limits/mainnet/asa:31566704=mainnet:31566704",
		"/asset_sets/usd/mainnet/0=mainnet:31566704",
		"/asset_sets/usd/private-dev/1=private-dev:9",
		"/transfer_policy/routes/0/assets/0=mainnet:31566704",
		"/transfer_policy/routes/0/limits/mainnet/asa:31566704=mainnet:31566704",
	} {
		if !contains(assets, want) {
			t.Errorf("asset references %v lack %s", assets, want)
		}
	}
	for _, a := range refs.Assets {
		if a.Pointer == "/transfer_policy/routes/1/assets/0" {
			t.Errorf("a direct term in a two-network route was listed as one network's asset: %+v", a)
		}
	}

	if len(refs.DirectRouteAssets) != 2 {
		t.Fatalf("direct route assets = %+v, want 2", refs.DirectRouteAssets)
	}
	if two := refs.DirectRouteAssets[1]; two.Route != "two-nets" || two.AssetID != 5 || len(two.Networks) != 2 || two.NetworkWildcard {
		t.Errorf("two-network direct term = %+v", two)
	}

	if len(refs.Routes) != 3 {
		t.Fatalf("routes = %+v", refs.Routes)
	}
	if r := refs.Routes[0]; r.AnyAsset || len(r.Sets) != 1 || r.Sets[0] != "usd" || len(r.DirectAssets) != 1 {
		t.Errorf("route one-net = %+v", r)
	}
	if r := refs.Routes[2]; !r.AnyAsset || !r.NetworkWildcard {
		t.Errorf("route everywhere = %+v", r)
	}

	assertPointersResolve(t, refs, draft)
}

// Every pointer names the token or asset it is listed for, in the fixtures
// as in the synthetic document.
func TestReferencePointersResolveInTheFixtures(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join("..", "..", "test", "contracts", "policy", "v1", "*.json"))
	if len(files) == 0 {
		t.Fatal("no fixtures")
	}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		draft, err := policy.ParseDraft(data)
		if err != nil {
			t.Fatal(err)
		}
		role := noderole.Role(draft.At("/role").Text())
		doc, err := policy.DecodePolicyV1(data, draft.At("/key").Text(), role)
		if err != nil {
			t.Fatalf("%s: %v", filepath.Base(file), err)
		}
		assertPointersResolve(t, doc.References(), draft)
	}
}

func assertPointersResolve(t *testing.T, refs policy.References, draft *policy.Draft) {
	t.Helper()
	for _, n := range refs.Networks {
		node := draft.At(n.Pointer)
		last := n.Pointer[strings.LastIndex(n.Pointer, "/")+1:]
		if !node.Exists() || (node.Kind() == "string" && node.Text() != n.Network) || (node.Kind() != "string" && last != n.Network) {
			t.Errorf("network pointer %s does not name %s", n.Pointer, n.Network)
		}
	}
	for _, a := range refs.Assets {
		node := draft.At(a.Pointer)
		want := "asa:" + strconv.FormatUint(a.AssetID, 10)
		last := a.Pointer[strings.LastIndex(a.Pointer, "/")+1:]
		if !node.Exists() || (node.Kind() == "string" && node.Text() != want) || (node.Kind() != "string" && last != want) {
			t.Errorf("asset pointer %s does not name %s", a.Pointer, want)
		}
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
