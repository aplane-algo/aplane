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

// An address-named alias already in the cache, from an older version or
// planted to redirect the address, is ignored when the cache loads.
func TestLoadAliasCacheIgnoresAddressNamedAliases(t *testing.T) {
	cache := LoadAliasCacheFromStore(NewStore(t.TempDir()))
	cache.Aliases["alice"] = aliasTestAddress(3)
	cache.Aliases[strings.ToLower(aliasTestAddress(1))] = aliasTestAddress(2)
	if err := cache.SaveCacheLocked(); err != nil {
		t.Fatalf("SaveCacheLocked() error = %v", err)
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

func aliasTestAddress(i byte) string {
	var addr types.Address
	addr[0] = i
	addr[31] = i + 1
	return addr.String()
}
