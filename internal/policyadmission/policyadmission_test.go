// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyadmission

import (
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/asaset"
	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/policy/policytest"
	"github.com/aplane-algo/aplane/internal/policycontext"
)

const customChain = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="

// nodeContext is a signer that knows the built-in networks plus
// private-dev, and has confirmed asset 9 on private-dev.
func nodeContext(t *testing.T) *policycontext.Context {
	t.Helper()
	networks, err := apconfig.NewGenesisHashNetworkResolver(map[string]string{customChain: "private-dev"})
	if err != nil {
		t.Fatal(err)
	}
	genesis, err := asaset.ParseGenesisHash(customChain)
	if err != nil {
		t.Fatal(err)
	}
	set, err := asaset.New([]asaset.Entry{{
		Identity:              asaset.Identity{Genesis: genesis, AssetID: 9},
		UnitName:              "XYZ",
		Decimals:              2,
		Creator:               "CEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEI7JH2AYM",
		ConfirmedAt:           time.Unix(1_700_000_000, 0),
		NetworkAtConfirmation: "private-dev",
	}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := policycontext.New(noderole.RoleSigner, networks, set)
	if err != nil {
		t.Fatal(err)
	}
	return ctx
}

func check(t *testing.T, sparse string) []Problem {
	t.Helper()
	doc, err := policy.DecodePolicyV1([]byte(policytest.Signer(t, policy.DefaultKey, sparse)), policy.DefaultKey, noderole.RoleSigner)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return Check(doc, nodeContext(t))
}

func rules(problems []Problem) string {
	var out []string
	for _, p := range problems {
		out = append(out, p.RuleID+"@"+p.Pointer)
	}
	return strings.Join(out, " ")
}

func TestAdmission(t *testing.T) {
	route := func(id, networks, assets string) string {
		return `{"id": "` + id + `", "networks": ` + networks + `, "sources": ["*"], "assets": ` + assets + `, "destinations": ["*"]}`
	}
	usd := `"asset_sets": {"usd": {"mainnet": ["asa:31566704"], "testnet": ["asa:10458941"]}}`
	tests := []struct {
		name   string
		sparse string
		want   string
	}{
		{"nothing named", `{}`, ""},
		{"known networks and assets",
			`{"limits": {"mainnet": {"asa:31566704": {"reject_above": "1"}}, "private-dev": {"asa:9": {"reject_above": "1"}}}}`, ""},
		{"an unknown network in limits",
			`{"limits": {"mainet": {"algo": {"reject_above": "1"}}}}`,
			RuleUnknownNetwork + "@/limits/mainet"},
		{"an unknown network in a network-keyed address set",
			`{"address_sets": {"ops": {"nowhere": ["CEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEI7JH2AYM"]}}}`,
			RuleUnknownNetwork + "@/address_sets/ops/nowhere"},
		{"an asset outside the set",
			`{"limits": {"private-dev": {"asa:10": {"reject_above": "1"}}}}`,
			RuleAssetNotInSet + "@/limits/private-dev/asa:10"},
		{"mainnet's USDC ID on another chain is not USDC",
			`{"limits": {"private-dev": {"asa:31566704": {"reject_above": "1"}}}}`,
			RuleAssetNotInSet + "@/limits/private-dev/asa:31566704"},
		{"a direct term in a single-network route",
			`{"transfer_policy": {"routes": [` + route("r", `["mainnet"]`, `["asa:31566704"]`) + `]}}`, ""},
		{"a direct term under two networks",
			`{"transfer_policy": {"routes": [` + route("r", `["mainnet", "testnet"]`, `["asa:31566704"]`) + `]}}`,
			RuleAmbiguousRouteAsset + "@/transfer_policy/routes/0/assets/0"},
		{"a direct term under every network",
			`{"transfer_policy": {"routes": [` + route("r", `["*"]`, `["asa:31566704"]`) + `]}}`,
			RuleAmbiguousRouteAsset + "@/transfer_policy/routes/0/assets/0"},
		{"a set covering the route's networks",
			`{` + usd + `, "transfer_policy": {"routes": [` + route("r", `["mainnet", "testnet"]`, `["@usd"]`) + `]}}`, ""},
		{"a set missing one of the route's networks",
			`{` + usd + `, "transfer_policy": {"routes": [` + route("r", `["mainnet", "private-dev"]`, `["@usd"]`) + `]}}`,
			RuleRouteNetworkUncovered + "@/transfer_policy/routes/0/assets"},
		{"two single-network sets covering together",
			`{"asset_sets": {"m": {"mainnet": ["asa:31566704"]}, "t": {"testnet": ["asa:10458941"]}}, "transfer_policy": {"routes": [` +
				route("r", `["mainnet", "testnet"]`, `["@m", "@t"]`) + `]}}`, ""},
		{"a wildcard route needs every node network",
			`{` + usd + `, "transfer_policy": {"routes": [` + route("r", `["*"]`, `["@usd"]`) + `]}}`,
			RuleRouteNetworkUncovered + "@/transfer_policy/routes/0/assets " + RuleRouteNetworkUncovered + "@/transfer_policy/routes/0/assets"},
		{"algo covers every network",
			`{` + usd + `, "transfer_policy": {"routes": [` + route("r", `["*"]`, `["algo", "@usd"]`) + `]}}`, ""},
		{"any asset covers every network",
			`{"transfer_policy": {"routes": [` + route("r", `["*"]`, `["*"]`) + `]}}`, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := rules(check(t, tc.sparse)); got != tc.want {
				t.Fatalf("problems = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestWildcardRouteNamesTheUncoveredNetworks(t *testing.T) {
	problems := check(t, `{"asset_sets": {"usd": {"mainnet": ["asa:31566704"], "testnet": ["asa:10458941"]}}, "transfer_policy": {"routes": [
		{"id": "payouts", "networks": ["*"], "sources": ["*"], "assets": ["@usd"], "destinations": ["*"]}]}}`)
	var text []string
	for _, p := range problems {
		text = append(text, p.Message)
	}
	joined := strings.Join(text, "\n")
	for _, want := range []string{`applies to betanet (through "*")`, `applies to private-dev (through "*")`} {
		if !strings.Contains(joined, want) {
			t.Fatalf("messages lack %q:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "mainnet (through") || strings.Contains(joined, "testnet (through") {
		t.Fatalf("a covered network was reported:\n%s", joined)
	}
}

func TestStoredAlertsAreBounded(t *testing.T) {
	ctx := nodeContext(t)
	var docs []policy.StoredDocument
	for i := 0; i < 100; i++ {
		data := []byte(policytest.Signer(t, policy.DefaultKey, `{"limits": {"mainet": {"algo": {"reject_above": "1"}}}}`))
		docs = append(docs, policy.StoredDocument{Key: policy.DefaultKey, Bytes: data})
	}
	alerts := StoredAlerts(docs, ctx)
	if len(alerts) != MaxStoredAlerts+1 || !strings.Contains(alerts[MaxStoredAlerts], "68 more policy document(s)") {
		t.Fatalf("alerts = %d lines, last %q", len(alerts), alerts[len(alerts)-1])
	}
	for _, a := range alerts {
		if len(a) > MaxAlertBytes {
			t.Fatalf("an alert is %d bytes", len(a))
		}
	}
}
