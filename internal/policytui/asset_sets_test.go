// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policytui

import (
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/policy"
)

func TestTransferAssetSetRowsSortAndSummarize(t *testing.T) {
	sets := map[string]policy.StoredAssetSet{
		"usdc": {
			"testnet": []uint64{10458941},
			"mainnet": []uint64{31566704},
		},
		"eur": {
			"mainnet": []uint64{227855942},
		},
	}

	rows := transferAssetSetRows(sets)

	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2", len(rows))
	}
	if rows[0].Name != "eur" || rows[1].Name != "usdc" {
		t.Fatalf("row names = %q, %q; want eur, usdc", rows[0].Name, rows[1].Name)
	}
	if rows[1].NetworkCount != 2 || rows[1].ASAIDCount != 2 {
		t.Fatalf("usdc counts = networks %d ids %d, want 2/2", rows[1].NetworkCount, rows[1].ASAIDCount)
	}
	if rows[1].Preview != "mainnet:31566704 testnet:10458941" {
		t.Fatalf("usdc preview = %q", rows[1].Preview)
	}
}

func TestDefaultAssetSetsIncludeBuiltinUSDC(t *testing.T) {
	sets := defaultAssetSets()
	usdc := sets["usdc"]
	if usdc == nil {
		t.Fatal("default asset sets missing usdc")
	}
	if got := joinUint64s(usdc["mainnet"]); got != "31566704" {
		t.Fatalf("mainnet USDC IDs = %q, want 31566704", got)
	}
	if got := joinUint64s(usdc["testnet"]); got != "10458941" {
		t.Fatalf("testnet USDC IDs = %q, want 10458941", got)
	}
}

func TestAssetSetToEditRowsSortsNetworksAndIDs(t *testing.T) {
	set := policy.StoredAssetSet{
		"testnet": []uint64{20, 10},
		"mainnet": []uint64{3, 1},
	}

	rows := assetSetToEditRows(set)

	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2", len(rows))
	}
	if rows[0].Network != "mainnet" || rows[0].ASAIDs != "1,3" {
		t.Fatalf("row 0 = %+v, want mainnet 1,3", rows[0])
	}
	if rows[1].Network != "testnet" || rows[1].ASAIDs != "10,20" {
		t.Fatalf("row 1 = %+v, want testnet 10,20", rows[1])
	}
}

func TestEditRowsToAssetSetParsesAndDedupesIDs(t *testing.T) {
	rows := []assetSetEditRow{
		{Network: "testnet", ASAIDs: "10458941, asa:10458941, 999"},
		{Network: "mainnet", ASAIDs: "31566704"},
	}

	set, err := editRowsToAssetSet(rows)
	if err != nil {
		t.Fatalf("editRowsToAssetSet() error = %v", err)
	}

	if got := joinUint64s(set["testnet"]); got != "999,10458941" {
		t.Fatalf("testnet IDs = %q, want sorted deduped IDs", got)
	}
	if got := joinUint64s(set["mainnet"]); got != "31566704" {
		t.Fatalf("mainnet IDs = %q, want 31566704", got)
	}
}

func TestEditRowsToAssetSetRejectsInvalidShapes(t *testing.T) {
	tests := []struct {
		name string
		rows []assetSetEditRow
		want string
	}{
		{
			name: "empty",
			rows: nil,
			want: "at least one network",
		},
		{
			name: "wildcard network",
			rows: []assetSetEditRow{{Network: "*", ASAIDs: "1"}},
			want: "cannot use *",
		},
		{
			name: "empty ids",
			rows: []assetSetEditRow{{Network: "testnet"}},
			want: "at least one ASA ID",
		},
		{
			name: "zero id",
			rows: []assetSetEditRow{{Network: "testnet", ASAIDs: "0"}},
			want: "0 is not a valid ASA ID",
		},
		{
			name: "duplicate network",
			rows: []assetSetEditRow{
				{Network: "testnet", ASAIDs: "1"},
				{Network: "testnet", ASAIDs: "2"},
			},
			want: "duplicates network",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := editRowsToAssetSet(tc.rows)
			if err == nil {
				t.Fatal("editRowsToAssetSet() error = nil")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want containing %q", err, tc.want)
			}
		})
	}
}
