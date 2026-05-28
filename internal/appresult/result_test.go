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
