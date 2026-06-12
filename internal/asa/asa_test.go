// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package asa

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/cache"
)

func TestBuiltinMetadataByRef(t *testing.T) {
	meta, ok := BuiltinMetadataByRef("testnet", "usdc")
	if !ok {
		t.Fatal("BuiltinMetadataByRef(testnet, usdc) = not found, want found")
	}
	if meta.AssetID != 10458941 {
		t.Fatalf("AssetID = %d, want 10458941", meta.AssetID)
	}
	if meta.Decimals != 6 {
		t.Fatalf("Decimals = %d, want 6", meta.Decimals)
	}
}

func TestBuiltinMetadataByRefUsesAliases(t *testing.T) {
	meta, ok := BuiltinMetadataByRef("mainnet", "akita")
	if !ok {
		t.Fatal("BuiltinMetadataByRef(mainnet, akita) = not found, want found")
	}
	if meta.AssetID != 523683256 || meta.UnitName != "AKTA" {
		t.Fatalf("BuiltinMetadataByRef(mainnet, akita) = %+v, want AKTA asset", meta)
	}
}

func TestResolverResolveIDNumeric(t *testing.T) {
	r := NewResolver("testnet", nil, nil)
	assetID, err := r.ResolveID("10458941")
	if err != nil {
		t.Fatalf("ResolveID() error = %v", err)
	}
	if assetID != 10458941 {
		t.Fatalf("ResolveID() = %d, want 10458941", assetID)
	}
}

func TestResolverResolveIDUsesCanonicalBuiltinsWithoutCache(t *testing.T) {
	r := NewResolver("mainnet", nil, nil)
	assetID, err := r.ResolveID("akita")
	if err != nil {
		t.Fatalf("ResolveID() error = %v", err)
	}
	if assetID != 523683256 {
		t.Fatalf("ResolveID(akita) = %d, want 523683256", assetID)
	}
}

func TestParseAndFormatDisplayAmount(t *testing.T) {
	meta := Metadata{Network: "testnet", AssetID: 10458941, UnitName: "USDC", Decimals: 6}
	raw, err := ParseDisplayAmount("0.9", meta)
	if err != nil {
		t.Fatalf("ParseDisplayAmount() error = %v", err)
	}
	if raw != 900000 {
		t.Fatalf("ParseDisplayAmount() = %d, want 900000", raw)
	}
	if got := FormatDisplayAmount(raw, meta); got != "0.9" {
		t.Fatalf("FormatDisplayAmount() = %q, want 0.9", got)
	}
}

// TestParseDisplayAmountRejectsIDOnly pins that a display amount is never
// parsed against unknown (defaulted-to-zero) decimals, which would silently
// under-send by 10^d. ID-only metadata must be rejected; a raw amount is fine.
func TestParseDisplayAmountRejectsIDOnly(t *testing.T) {
	meta := Metadata{Network: "testnet", AssetID: 31566704, Source: SourceIDOnly}
	if _, err := ParseDisplayAmount("5", meta); err == nil {
		t.Fatal("ParseDisplayAmount() error = nil, want rejection for unknown decimals")
	}
	if _, err := AmountFromDisplay("5", meta); err == nil {
		t.Fatal("AmountFromDisplay() error = nil, want rejection for unknown decimals")
	}
	// A raw base-unit amount needs no decimal interpretation and is allowed.
	if amt := AmountFromRaw(5, meta); amt.Raw != 5 {
		t.Fatalf("AmountFromRaw() = %d, want 5", amt.Raw)
	}
}

func TestResolverMetadataByIDUsesCache(t *testing.T) {
	asaCache := &cache.ASACache{
		Assets: map[uint64]cache.ASAInfo{
			123: {UnitName: "TOK", Name: "Token", Decimals: 2},
		},
	}
	r := NewResolver("testnet", asaCache, nil)
	meta, err := r.MetadataByID(123)
	if err != nil {
		t.Fatalf("MetadataByID() error = %v", err)
	}
	if meta.Source != SourceCache {
		t.Fatalf("Source = %q, want %q", meta.Source, SourceCache)
	}
	if meta.UnitName != "TOK" {
		t.Fatalf("UnitName = %q, want TOK", meta.UnitName)
	}
}
