// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package asametadata

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/asa"
)

func TestMetadataByIDUsesBuiltinAsSignerCacheSeed(t *testing.T) {
	meta, err := NewStore(t.TempDir()).MetadataByID("testnet", 10458941, nil, false)
	if err != nil {
		t.Fatalf("MetadataByID() error = %v", err)
	}
	if meta.AssetID != 10458941 || meta.UnitName != "USDC" || meta.Decimals != 6 {
		t.Fatalf("metadata = %+v, want testnet USDC", meta)
	}
	if meta.Source != asa.SourceCache {
		t.Fatalf("Source = %q, want %q", meta.Source, asa.SourceCache)
	}
}

func TestFormatterRendersDisplayAmountWithAssetID(t *testing.T) {
	format := NewStore(t.TempDir()).Formatter()
	got, ok := format("testnet", 10458941, 2_000_000)
	if !ok {
		t.Fatal("Formatter() ok = false, want true")
	}
	if got != "2 USDC (ASA 10458941)" {
		t.Fatalf("Formatter() = %q, want %q", got, "2 USDC (ASA 10458941)")
	}
}

func TestSearchLocalMatchesUnitNameCaseInsensitiveAndSorted(t *testing.T) {
	dataDir := t.TempDir()
	store := NewStore(dataDir)
	for _, meta := range []asa.Metadata{
		{AssetID: 44, Name: "Second Duplicate", UnitName: "DUP", Decimals: 6},
		{AssetID: 11, Name: "First Duplicate", UnitName: "dup", Decimals: 2},
		{AssetID: 99, Name: "Different", UnitName: "OTHER", Decimals: 0},
	} {
		if err := store.SaveLocalMetadata("customnet", meta); err != nil {
			t.Fatalf("SaveLocalMetadata() error = %v", err)
		}
	}

	got, err := store.SearchLocal("customnet", "DuP")
	if err != nil {
		t.Fatalf("SearchLocal() error = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("SearchLocal() returned %d results, want 2: %+v", len(got), got)
	}
	if got[0].AssetID != 11 || got[1].AssetID != 44 {
		t.Fatalf("SearchLocal() asset order = [%d %d], want [11 44]", got[0].AssetID, got[1].AssetID)
	}
	if got[0].Network != "customnet" || got[0].Source != asa.SourceCache {
		t.Fatalf("SearchLocal() metadata = %+v, want cache-sourced customnet metadata", got[0])
	}
}
