// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package cache

import (
	"strings"
	"testing"
)

func init() {
	InitLogger()
}

func TestLoadASACacheFromStoreMergesBuiltinsAndOverridesWithCachedValues(t *testing.T) {
	store := NewStore(t.TempDir())

	cache := LoadASACacheFromStore(store, "testnet")
	if _, ok := cache.Assets[10458941]; !ok {
		t.Fatal("expected testnet builtin ASA 10458941 to be present")
	}
	cache.Assets[10458941] = ASAInfo{Name: "Custom USDC", UnitName: "USDC", Decimals: 9}
	cache.Assets[999999] = ASAInfo{Name: "Custom Token", UnitName: "CTKN", Decimals: 3}
	if err := cache.SaveCache("testnet"); err != nil {
		t.Fatalf("SaveCache() error = %v", err)
	}

	reloaded := LoadASACacheFromStore(store, "testnet")
	if got := reloaded.Assets[10458941]; got.Name != "Custom USDC" || got.Decimals != 9 {
		t.Fatalf("builtin override = %+v, want Custom USDC/9", got)
	}
	if got := reloaded.Assets[999999]; got.Name != "Custom Token" || got.UnitName != "CTKN" {
		t.Fatalf("custom cached token = %+v, want Custom Token/CTKN", got)
	}
}

func TestResolveASAReferenceMatchesIDsAndUnitNamesCaseInsensitively(t *testing.T) {
	cache := ASACache{
		Assets: map[uint64]ASAInfo{
			77: {Name: "Sample Token", UnitName: "UsDc", Decimals: 6},
		},
	}

	id, err := cache.ResolveASAReference("77", "testnet")
	if err != nil || id != 77 {
		t.Fatalf("ResolveASAReference(77) = (%d, %v), want (77, nil)", id, err)
	}
	id, err = cache.ResolveASAReference("usdc", "testnet")
	if err != nil || id != 77 {
		t.Fatalf("ResolveASAReference(usdc) = (%d, %v), want (77, nil)", id, err)
	}
	id, err = cache.ResolveASAReference("sample token", "testnet")
	if err != nil || id != 77 {
		t.Fatalf("ResolveASAReference(sample token) = (%d, %v), want (77, nil)", id, err)
	}
}

func TestResolveASAReferenceRejectsAmbiguousUnitOrName(t *testing.T) {
	cache := ASACache{
		Assets: map[uint64]ASAInfo{
			77: {Name: "Sample 1", UnitName: "USDC", Decimals: 6},
			88: {Name: "usdc", UnitName: "TWO", Decimals: 6},
		},
	}

	_, err := cache.ResolveASAReference("UsDc", "testnet")
	if err == nil {
		t.Fatal("ResolveASAReference() error = nil, want ambiguity error")
	}
	if !strings.Contains(err.Error(), "ambiguous") || !strings.Contains(err.Error(), "77, 88") {
		t.Fatalf("ResolveASAReference() error = %q, want sorted ambiguity details", err.Error())
	}
}

func TestResolveASAReferenceFallsBackToCanonicalAlias(t *testing.T) {
	cache := ASACache{}

	id, err := cache.ResolveASAReference("akita", "mainnet")
	if err != nil || id != 523683256 {
		t.Fatalf("ResolveASAReference(akita) = (%d, %v), want (523683256, nil)", id, err)
	}
}

func TestResolveASAReferencePrefersLocalCacheBeforeBuiltinAlias(t *testing.T) {
	cache := ASACache{
		Assets: map[uint64]ASAInfo{
			999999: {Name: "Local Akita", UnitName: "akita", Decimals: 6},
		},
	}

	id, err := cache.ResolveASAReference("akita", "mainnet")
	if err != nil || id != 999999 {
		t.Fatalf("ResolveASAReference(akita) = (%d, %v), want local cache asset 999999", id, err)
	}
}

func TestResolveBuiltinASAReferenceAndInfo(t *testing.T) {
	if id, ok := ResolveBuiltinASAReference("testnet", "USDC"); !ok || id != 10458941 {
		t.Fatalf("ResolveBuiltinASAReference(testnet, USDC) = (%d, %v), want (10458941, true)", id, ok)
	}
	if id, ok := ResolveBuiltinASAReference("mainnet", "akita"); !ok || id != 523683256 {
		t.Fatalf("ResolveBuiltinASAReference(mainnet, akita) = (%d, %v), want (523683256, true)", id, ok)
	}
	if id, ok := ResolveBuiltinASAReference("testnet", "10458941"); !ok || id != 10458941 {
		t.Fatalf("ResolveBuiltinASAReference(testnet, 10458941) = (%d, %v), want (10458941, true)", id, ok)
	}
	if _, ok := ResolveBuiltinASAReference("testnet", "not-a-builtin"); ok {
		t.Fatal("unexpected builtin resolution for unknown asset")
	}
	if unit, ok := BuiltinASAUnitName("testnet", 10458941); !ok || unit != "USDC" {
		t.Fatalf("BuiltinASAUnitName() = (%q, %v), want (USDC, true)", unit, ok)
	}
	if info, ok := BuiltinASAInfo("testnet", 10458941); !ok || info.Name != "USDC" {
		t.Fatalf("BuiltinASAInfo() = (%+v, %v), want USDC", info, ok)
	}
}
