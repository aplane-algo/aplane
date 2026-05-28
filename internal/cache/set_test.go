// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package cache

import (
	"reflect"
	"strings"
	"testing"
)

func TestSetCacheCreateOrUpdateSetResolvesAliasesAndPersists(t *testing.T) {
	store := NewStore(t.TempDir())
	cache := LoadSetCacheFromStore(store)
	aliasCache := &AliasCache{
		Aliases: map[string]string{
			"alice": aliasTestAddress(1),
		},
	}

	if err := cache.CreateOrUpdateSet("team", []string{"alice", aliasTestAddress(2)}, aliasCache); err != nil {
		t.Fatalf("CreateOrUpdateSet() error = %v", err)
	}

	got, err := cache.GetSet("team")
	if err != nil {
		t.Fatalf("GetSet() error = %v", err)
	}
	want := []string{aliasTestAddress(1), aliasTestAddress(2)}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("GetSet() = %#v, want %#v", got, want)
	}

	reloaded := LoadSetCacheFromStore(store)
	got, err = reloaded.GetSet("team")
	if err != nil {
		t.Fatalf("reloaded.GetSet() error = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("reloaded.GetSet() = %#v, want %#v", got, want)
	}
}

func TestSetCacheAddToSetDeduplicatesAndPersists(t *testing.T) {
	store := NewStore(t.TempDir())
	cache := LoadSetCacheFromStore(store)
	aliasCache := &AliasCache{
		Aliases: map[string]string{
			"alice": aliasTestAddress(1),
			"bob":   aliasTestAddress(2),
		},
	}

	cache.Sets["team"] = []string{aliasTestAddress(1)}
	if err := cache.AddToSet("team", []string{"alice", "bob", aliasTestAddress(2)}, aliasCache); err != nil {
		t.Fatalf("AddToSet() error = %v", err)
	}

	got, err := cache.GetSet("team")
	if err != nil {
		t.Fatalf("GetSet() error = %v", err)
	}
	want := []string{aliasTestAddress(1), aliasTestAddress(2)}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("GetSet() = %#v, want %#v", got, want)
	}
}

func TestSetCacheRemoveFromSetDeletesEmptySet(t *testing.T) {
	store := NewStore(t.TempDir())
	cache := LoadSetCacheFromStore(store)
	aliasCache := &AliasCache{
		Aliases: map[string]string{
			"alice": aliasTestAddress(1),
		},
	}

	cache.Sets["team"] = []string{aliasTestAddress(1)}
	if err := cache.RemoveFromSet("team", []string{"alice"}, aliasCache); err != nil {
		t.Fatalf("RemoveFromSet() error = %v", err)
	}
	if _, exists := cache.Sets["team"]; exists {
		t.Fatal("team set should be deleted when last address is removed")
	}

	reloaded := LoadSetCacheFromStore(store)
	if _, exists := reloaded.Sets["team"]; exists {
		t.Fatal("deleted empty set persisted unexpectedly")
	}
}

func TestSetCacheResolveAddressOrSet(t *testing.T) {
	cache := SetCache{
		Sets: map[string][]string{
			"team": {aliasTestAddress(1), aliasTestAddress(2)},
		},
	}
	aliasCache := &AliasCache{
		Aliases: map[string]string{
			"alice": aliasTestAddress(3),
		},
	}

	got, err := cache.ResolveAddressOrSet("@team", aliasCache)
	if err != nil {
		t.Fatalf("ResolveAddressOrSet(@team) error = %v", err)
	}
	want := []string{aliasTestAddress(1), aliasTestAddress(2)}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ResolveAddressOrSet(@team) = %#v, want %#v", got, want)
	}

	got, err = cache.ResolveAddressOrSet("alice", aliasCache)
	if err != nil {
		t.Fatalf("ResolveAddressOrSet(alice) error = %v", err)
	}
	if !reflect.DeepEqual(got, []string{aliasTestAddress(3)}) {
		t.Fatalf("ResolveAddressOrSet(alice) = %#v, want [%s]", got, aliasTestAddress(3))
	}
}

func TestSetCacheRejectsInvalidInputs(t *testing.T) {
	cache := SetCache{Sets: map[string][]string{}}
	aliasCache := &AliasCache{Aliases: map[string]string{}}

	tests := []struct {
		name        string
		fn          func() error
		errContains string
	}{
		{
			name:        "empty set name on create",
			fn:          func() error { return cache.CreateOrUpdateSet("", []string{aliasTestAddress(1)}, aliasCache) },
			errContains: "set name cannot be empty",
		},
		{
			name:        "empty addresses on create",
			fn:          func() error { return cache.CreateOrUpdateSet("team", nil, aliasCache) },
			errContains: "set must contain at least one address",
		},
		{
			name:        "reserved dynamic set on create",
			fn:          func() error { return cache.CreateOrUpdateSet("all", []string{aliasTestAddress(1)}, aliasCache) },
			errContains: "reserved",
		},
		{
			name:        "reserved dynamic set on add",
			fn:          func() error { return cache.AddToSet("signers", []string{aliasTestAddress(1)}, aliasCache) },
			errContains: "reserved",
		},
		{
			name:        "unresolvable address on add",
			fn:          func() error { return cache.AddToSet("team", []string{"unknown"}, aliasCache) },
			errContains: "failed to resolve 'unknown'",
		},
		{
			name:        "missing set on remove",
			fn:          func() error { return cache.RemoveFromSet("team", []string{aliasTestAddress(1)}, aliasCache) },
			errContains: "set 'team' does not exist",
		},
		{
			name:        "missing set on resolve",
			fn:          func() error { _, err := cache.ResolveAddressOrSet("@team", aliasCache); return err },
			errContains: "failed to resolve set",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fn()
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.errContains)
			}
			if !strings.Contains(err.Error(), tt.errContains) {
				t.Fatalf("error = %q, want substring %q", err.Error(), tt.errContains)
			}
		})
	}
}
