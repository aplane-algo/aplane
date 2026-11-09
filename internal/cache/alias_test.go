// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package cache

import (
	"reflect"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

func TestAliasCacheUpdateAliasPersists(t *testing.T) {
	store := NewStore(t.TempDir())
	cache := LoadAliasCacheFromStore(store)
	addr := aliasTestAddress(1)

	if err := cache.UpdateAlias("alice", addr, false); err != nil {
		t.Fatalf("UpdateAlias() error = %v", err)
	}

	if got := cache.Aliases["alice"]; got != addr {
		t.Fatalf("cache.Aliases[alice] = %q, want %q", got, addr)
	}

	reloaded := LoadAliasCacheFromStore(store)
	if got := reloaded.Aliases["alice"]; got != addr {
		t.Fatalf("reloaded alias = %q, want %q", got, addr)
	}
}

func TestAliasCacheUpdateAliasRejectsConflictingAliasWithoutForce(t *testing.T) {
	store := NewStore(t.TempDir())
	cache := LoadAliasCacheFromStore(store)
	addr1 := aliasTestAddress(1)
	addr2 := aliasTestAddress(2)

	if err := cache.UpdateAlias("alice", addr1, false); err != nil {
		t.Fatalf("UpdateAlias(initial) error = %v", err)
	}

	err := cache.UpdateAlias("alice", addr2, false)
	if err == nil {
		t.Fatal("expected conflict error, got nil")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("error = %q, want alias conflict", err.Error())
	}
	if got := cache.Aliases["alice"]; got != addr1 {
		t.Fatalf("cache.Aliases[alice] = %q, want original %q", got, addr1)
	}
}

func TestAliasCacheUpdateAliasForceReplacesExistingValue(t *testing.T) {
	store := NewStore(t.TempDir())
	cache := LoadAliasCacheFromStore(store)
	addr1 := aliasTestAddress(1)
	addr2 := aliasTestAddress(2)

	if err := cache.UpdateAlias("alice", addr1, false); err != nil {
		t.Fatalf("UpdateAlias(initial) error = %v", err)
	}
	if err := cache.UpdateAlias("alice", addr2, true); err != nil {
		t.Fatalf("UpdateAlias(force) error = %v", err)
	}

	if got := cache.Aliases["alice"]; got != addr2 {
		t.Fatalf("cache.Aliases[alice] = %q, want %q", got, addr2)
	}
	reloaded := LoadAliasCacheFromStore(store)
	if got := reloaded.Aliases["alice"]; got != addr2 {
		t.Fatalf("reloaded alias = %q, want %q", got, addr2)
	}
}

// Audit finding 2: an alias named like an address used to redirect that
// address everywhere it was resolved. An address now always resolves as
// itself, in either case, even with such an alias in the map.
func TestAliasCacheResolveAddressNeverRedirectsAnAddress(t *testing.T) {
	cache := AliasCache{
		Aliases: map[string]string{
			strings.ToLower(aliasTestAddress(1)): aliasTestAddress(2),
		},
	}

	for _, input := range []string{aliasTestAddress(1), strings.ToLower(aliasTestAddress(1))} {
		got, err := cache.ResolveAddress(input)
		if err != nil {
			t.Fatalf("ResolveAddress(%q) error = %v", input, err)
		}
		if got != aliasTestAddress(1) {
			t.Fatalf("ResolveAddress(%q) = %q, want the address itself %q", input, got, aliasTestAddress(1))
		}
	}
}

func TestAliasCacheRefusesAnAddressAsAName(t *testing.T) {
	cache := LoadAliasCacheFromStore(NewStore(t.TempDir()))
	for _, name := range []string{aliasTestAddress(1), strings.ToLower(aliasTestAddress(1))} {
		err := cache.UpdateAlias(name, aliasTestAddress(2), true)
		if err == nil || !strings.Contains(err.Error(), "is an Algorand address") {
			t.Fatalf("UpdateAlias(%q) error = %v, want the address-name refusal", name, err)
		}
	}
	if len(cache.Aliases) != 0 {
		t.Fatalf("aliases = %v, want none", cache.Aliases)
	}
}

// An address-named alias already in the cache, from an older version or
// planted to redirect the address, is ignored when the cache loads.
func TestLoadAliasCacheIgnoresAddressNamedAliases(t *testing.T) {
	cache := LoadAliasCacheFromStore(NewStore(t.TempDir()))
	if err := cache.UpdateAlias("alice", aliasTestAddress(3), false); err != nil {
		t.Fatalf("UpdateAlias(alice) error = %v", err)
	}
	cache.Aliases[strings.ToLower(aliasTestAddress(1))] = aliasTestAddress(2)
	if err := cache.SaveCache(); err != nil {
		t.Fatalf("SaveCache() error = %v", err)
	}

	reloaded := LoadAliasCacheFromStore(cache.store)
	if want := map[string]string{"alice": aliasTestAddress(3)}; !reflect.DeepEqual(reloaded.Aliases, want) {
		t.Fatalf("reloaded aliases = %v, want %v", reloaded.Aliases, want)
	}
	if got := reloaded.GetAliasForAddress(aliasTestAddress(2)); got != "" {
		t.Fatalf("GetAliasForAddress(target) = %q, want no label", got)
	}
}

func TestAliasCacheResolveAddressNormalizesRawAddress(t *testing.T) {
	cache := AliasCache{Aliases: map[string]string{}}
	addr := aliasTestAddress(3)

	got, err := cache.ResolveAddress(strings.ToLower(addr))
	if err != nil {
		t.Fatalf("ResolveAddress() error = %v", err)
	}
	if got != addr {
		t.Fatalf("ResolveAddress() = %q, want %q", got, addr)
	}
}

func TestAliasCacheRemoveAliasPersistsDeletion(t *testing.T) {
	store := NewStore(t.TempDir())
	cache := LoadAliasCacheFromStore(store)
	addr := aliasTestAddress(4)

	if err := cache.UpdateAlias("alice", addr, false); err != nil {
		t.Fatalf("UpdateAlias() error = %v", err)
	}
	if err := cache.RemoveAlias("alice"); err != nil {
		t.Fatalf("RemoveAlias() error = %v", err)
	}
	if cache.HasAlias("alice") {
		t.Fatal("alias should have been removed")
	}

	reloaded := LoadAliasCacheFromStore(store)
	if reloaded.HasAlias("alice") {
		t.Fatal("removed alias persisted unexpectedly")
	}
}

func aliasTestAddress(i byte) string {
	var addr types.Address
	addr[0] = i
	addr[31] = i + 1
	return addr.String()
}
