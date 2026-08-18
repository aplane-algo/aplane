// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package appresult

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/aplane-algo/aplane/internal/plugin/jsonrpc"
)

func TestStatusToMCPJSONShape(t *testing.T) {
	status := StatusToMCP(StatusView{
		Network:          "testnet",
		IsConnected:      true,
		ConnectionTarget: "localhost:11270",
		WriteMode:        true,
		ASACacheCount:    3,
		AliasCacheCount:  4,
		SetCacheCount:    5,
		SignerKeyCount:   6,
	}, true)

	data, err := json.Marshal(status)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	want := map[string]any{
		"network":           "testnet",
		"signer_connected":  true,
		"connection_target": "localhost:11270",
		"ssh_tunnel":        true,
		"write_mode":        true,
		"asa_cache_count":   float64(3),
		"alias_cache_count": float64(4),
		"set_cache_count":   float64(5),
		"signer_key_count":  float64(6),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("JSON shape mismatch\n got: %#v\nwant: %#v", got, want)
	}
}

func TestAliasesAndSetsToMCPJSONShape(t *testing.T) {
	aliases := AliasesToMCP([]AliasView{{
		Name:       "treasury",
		Address:    "ADDR1",
		IsSignable: true,
		KeyType:    "ed25519",
	}})
	sets := SetsToMCP([]SetView{{
		Name:      "ops",
		Addresses: []string{"ADDR1", "ADDR2"},
		Count:     2,
	}})

	aliasData, err := json.Marshal(aliases)
	if err != nil {
		t.Fatalf("Marshal aliases error = %v", err)
	}
	setData, err := json.Marshal(sets)
	if err != nil {
		t.Fatalf("Marshal sets error = %v", err)
	}

	var gotAliases []map[string]any
	if err := json.Unmarshal(aliasData, &gotAliases); err != nil {
		t.Fatalf("Unmarshal aliases error = %v", err)
	}
	var gotSets []map[string]any
	if err := json.Unmarshal(setData, &gotSets); err != nil {
		t.Fatalf("Unmarshal sets error = %v", err)
	}

	wantAliases := []map[string]any{{
		"name":        "treasury",
		"address":     "ADDR1",
		"is_signable": true,
		"key_type":    "ed25519",
	}}
	wantSets := []map[string]any{{
		"name":      "ops",
		"addresses": []any{"ADDR1", "ADDR2"},
		"count":     float64(2),
	}}

	if !reflect.DeepEqual(gotAliases, wantAliases) {
		t.Fatalf("alias JSON shape mismatch\n got: %#v\nwant: %#v", gotAliases, wantAliases)
	}
	if !reflect.DeepEqual(gotSets, wantSets) {
		t.Fatalf("set JSON shape mismatch\n got: %#v\nwant: %#v", gotSets, wantSets)
	}
}

func TestRemainingMCPProjectionJSONShapes(t *testing.T) {
	tests := []struct {
		name string
		got  any
		want string
	}{
		{
			name: "balance",
			got: BalanceToMCP(BalanceView{
				Address:     "ADDR1",
				Alias:       "alice",
				AlgoBalance: 1_250_000,
				AuthAddr:    "AUTH1",
				MinBalance:  100_000,
				Assets: []AssetBalanceView{{
					AssetID: 7, Amount: 1234, UnitName: "USDC", Decimals: 2, IsFrozen: true,
				}},
			}),
			want: `{"address":"ADDR1","alias":"alice","algo_balance":1250000,"algo_balance_display":"1.25","auth_addr":"AUTH1","min_balance":100000,"assets":[{"asset_id":7,"amount":1234,"amount_display":"12.34","unit_name":"USDC","decimals":2,"is_frozen":true}]}`,
		},
		{
			name: "accounts",
			got: AccountsToMCP([]AccountView{{
				Address: "ADDR1", Alias: "alice", Source: "signer", IsSignable: true, KeyType: "ed25519",
			}}),
			want: `[{"address":"ADDR1","alias":"alice","source":"signer","is_signable":true,"key_type":"ed25519"}]`,
		},
		{
			name: "participation",
			got: ParticipationToMCP(ParticipationView{
				Address: "ADDR1", IsOnline: true, IncentiveEligible: true,
				VoteKey: "VOTE", SelectionKey: "SELECT", StateProofKey: "STATE",
				VoteFirstValid: 10, VoteLastValid: 20, VoteKeyDilution: 5,
			}, true, "AUTH1"),
			want: `{"address":"ADDR1","is_online":true,"incentive_eligible":true,"vote_key":"VOTE","selection_key":"SELECT","state_proof_key":"STATE","vote_first_valid":10,"vote_last_valid":20,"vote_key_dilution":5,"is_rekeyed":true,"auth_addr":"AUTH1"}`,
		},
		{
			name: "asa info",
			got: ASAInfoToMCP(ASAInfoView{
				AssetID: 7, Name: "USD Coin", UnitName: "USDC", Decimals: 6,
				Total: 1_000_000, URL: "https://example.test", Creator: "CREATOR",
				Manager: "MANAGER", Reserve: "RESERVE", Freeze: "FREEZE",
				Clawback: "CLAWBACK", DefaultFrozen: true,
			}),
			want: `{"asset_id":7,"name":"USD Coin","unit_name":"USDC","decimals":6,"total":1000000,"url":"https://example.test","creator":"CREATOR","manager":"MANAGER","reserve":"RESERVE","freeze":"FREEZE","clawback":"CLAWBACK","default_frozen":true}`,
		},
		{
			name: "cached asas",
			got: CachedASAsToMCP([]ASAInfoView{{
				AssetID: 7, Name: "USD Coin", UnitName: "USDC", Decimals: 6,
			}}),
			want: `[{"asset_id":7,"name":"USD Coin","unit_name":"USDC","decimals":6}]`,
		},
		{
			name: "holders",
			got: HoldersToMCP("USDC", 6, []MCPHolderEntry{
				HolderEntryToMCP("ADDR1", "alice", 1_250_000, 6),
			}, 1_250_000),
			want: `{"asset":"USDC","decimals":6,"holders":[{"address":"ADDR1","alias":"alice","balance":1250000,"balance_display":"1.25"}],"total":1250000,"total_display":"1.25"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.got)
			if err != nil {
				t.Fatalf("Marshal() error = %v", err)
			}
			if got := string(data); got != tt.want {
				t.Fatalf("JSON shape mismatch\n got: %s\nwant: %s", got, tt.want)
			}
		})
	}
}

func TestPluginMarshalFiltersStructuredPayload(t *testing.T) {
	payload := Plugin{
		Plugin:  "swap",
		Success: true,
		Message: "ok",
		TxIDs:   []string{"TX1"},
		Data: map[string]any{
			"amount":       123,
			"localSigners": []any{"ADDR1"},
		},
		Presentation: &jsonrpc.Presentation{
			Title:   "Swap Quote",
			Summary: "1 route available",
			Sections: []jsonrpc.PresentationSection{{
				Kind:  "key_value",
				Title: "Quote",
				Items: []jsonrpc.PresentationItem{{Label: "Amount", Value: "123"}},
			}},
		},
		Steps: []PluginStep{{
			Message: "submitted",
			TxIDs:   []string{"TX1"},
		}},
	}

	payload.Data = FilterPluginData(payload.Data)
	data := Marshal(payload)

	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	want := map[string]any{
		"plugin":  "swap",
		"success": true,
		"message": "ok",
		"txids":   []any{"TX1"},
		"data": map[string]any{
			"amount": float64(123),
		},
		"presentation": map[string]any{
			"title":   "Swap Quote",
			"summary": "1 route available",
			"sections": []any{
				map[string]any{
					"kind":  "key_value",
					"title": "Quote",
					"items": []any{
						map[string]any{
							"label": "Amount",
							"value": "123",
						},
					},
				},
			},
		},
		"steps": []any{
			map[string]any{
				"message": "submitted",
				"txids":   []any{"TX1"},
			},
		},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("plugin JSON shape mismatch\n got: %#v\nwant: %#v", got, want)
	}
}
