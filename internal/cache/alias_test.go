// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package cache

import (
	"reflect"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

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

// The cache loads as stored: the alias command refuses an address-named
// alias, and load does not filter one. Should the file hold one anyway, the
// address it is named for still resolves as itself.
func TestLoadAliasCacheDoesNotFilterAndAnAddressStillResolvesAsItself(t *testing.T) {
	cache := LoadAliasCacheFromStore(NewStore(t.TempDir()))
	cache.Aliases["alice"] = aliasTestAddress(3)
	cache.Aliases[strings.ToLower(aliasTestAddress(1))] = aliasTestAddress(2)
	if err := cache.SaveCacheLocked(); err != nil {
		t.Fatalf("SaveCacheLocked() error = %v", err)
	}

	reloaded := LoadAliasCacheFromStore(cache.store)
	if !reflect.DeepEqual(reloaded.Aliases, cache.Aliases) {
		t.Fatalf("reloaded aliases = %v, want %v", reloaded.Aliases, cache.Aliases)
	}
	if got, err := reloaded.ResolveAddress(aliasTestAddress(1)); err != nil || got != aliasTestAddress(1) {
		t.Fatalf("ResolveAddress(address) = %q, %v; want the address itself", got, err)
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

func aliasTestAddress(i byte) string {
	var addr types.Address
	addr[0] = i
	addr[31] = i + 1
	return addr.String()
}
