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

// TestDisplayAmountThroughLoadedCache converts amounts the way a client does:
// load the cache from disk, resolve the reference, and parse the amount. A
// built-in entry with wrong decimals would convert by the wrong power of ten
// whatever the cache holds, because built-in entries win.
func TestDisplayAmountThroughLoadedCache(t *testing.T) {
	for _, tt := range []struct {
		name, ref, amount string
		cached            *cache.ASAInfo
		want              uint64
	}{
		{name: "AKTA from the table", ref: "akita", amount: "5", want: 5_000_000},
		{name: "EURS from the table", ref: "EURS", amount: "1.25", want: 1_250_000},
		{name: "AKTA with a correct cached entry", ref: "523683256", amount: "5",
			cached: &cache.ASAInfo{Name: "AKITA INU", UnitName: "AKTA", Decimals: 6}, want: 5_000_000},
		{name: "AKTA with a wrong cached entry", ref: "523683256", amount: "5",
			cached: &cache.ASAInfo{Name: "AKITA INU", UnitName: "AKTA", Decimals: 0}, want: 5_000_000},
	} {
		t.Run(tt.name, func(t *testing.T) {
			store := cache.NewStore(t.TempDir())
			if tt.cached != nil {
				seed := cache.LoadASACacheFromStore(store, "mainnet")
				seed.Assets[523683256] = *tt.cached
				if err := seed.SaveCache("mainnet"); err != nil {
					t.Fatal(err)
				}
			}
			loaded := cache.LoadASACacheFromStore(store, "mainnet")
			meta, err := NewResolver("mainnet", &loaded, nil).ResolveMetadata(tt.ref)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := ParseDisplayAmount(tt.amount, meta)
			if err != nil {
				t.Fatal(err)
			}
			if raw != tt.want {
				t.Fatalf("%s %s = %d base units, want %d", tt.amount, tt.ref, raw, tt.want)
			}
		})
	}
}
