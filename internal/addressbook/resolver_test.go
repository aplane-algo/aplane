// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package addressbook

import (
	"reflect"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/cache"
)

func TestResolveListAndSingle(t *testing.T) {
	addr1 := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"
	addr2 := "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBQ"

	aliasCache := &cache.AliasCache{Aliases: map[string]string{"alice": addr1, "bob": addr2}}
	setCache := &cache.SetCache{Sets: map[string][]string{"team": {addr1, addr2}, "single": {addr1}}}
	resolver := &Resolver{
		AliasCache:      aliasCache,
		SetCache:        setCache,
		SignerProvider:  func() []string { return []string{addr1} },
		AllProvider:     func() []string { return []string{addr1, addr2} },
		HoldersProvider: func(_ string) ([]string, error) { return []string{addr2}, nil },
	}

	list, err := resolver.ResolveList([]string{"alice", "@team"})
	if err != nil {
		t.Fatalf("ResolveList() error = %v", err)
	}
	if want := []string{addr1, addr1, addr2}; !reflect.DeepEqual(list, want) {
		t.Fatalf("ResolveList() = %#v, want %#v", list, want)
	}

	single, err := resolver.ResolveSingle("@single")
	if err != nil {
		t.Fatalf("ResolveSingle(@single) error = %v", err)
	}
	if single != addr1 {
		t.Fatalf("ResolveSingle(@single) = %q, want %q", single, addr1)
	}

	holder, err := resolver.ResolveSingle("@holders(usdc)")
	if err != nil {
		t.Fatalf("ResolveSingle(@holders) error = %v", err)
	}
	if holder != addr2 {
		t.Fatalf("ResolveSingle(@holders) = %q, want %q", holder, addr2)
	}
}

func TestResolveHoldersRequiresAssetRef(t *testing.T) {
	resolver := &Resolver{
		AliasCache: &cache.AliasCache{Aliases: map[string]string{}},
		SetCache:   &cache.SetCache{Sets: map[string][]string{}},
		HoldersProvider: func(assetRef string) ([]string, error) {
			t.Fatalf("holders provider called with %q", assetRef)
			return nil, nil
		},
	}

	_, err := resolver.ResolveList([]string{"@holders()"})
	if err == nil || !strings.Contains(err.Error(), "asset reference is required") {
		t.Fatalf("ResolveList(@holders()) error = %v, want missing asset", err)
	}

	_, err = resolver.ResolveSingle("@holders( )")
	if err == nil || !strings.Contains(err.Error(), "asset reference is required") {
		t.Fatalf("ResolveSingle(@holders( )) error = %v, want missing asset", err)
	}
}

func TestMultipleAddressError(t *testing.T) {
	addr1 := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"
	addr2 := "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBQ"
	resolver := &Resolver{
		AliasCache: &cache.AliasCache{Aliases: map[string]string{}},
		SetCache:   &cache.SetCache{Sets: map[string][]string{"team": {addr1, addr2}}},
	}

	_, err := resolver.ResolveSingle("@team")
	if err == nil {
		t.Fatal("ResolveSingle(@team) error = nil, want error")
	}
	if _, ok := err.(*MultipleAddressError); !ok {
		t.Fatalf("ResolveSingle(@team) error type = %T, want *MultipleAddressError", err)
	}
}
