// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package cache

import (
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

func TestAliasCacheResolveAddressPrefersAliasOverRawAddress(t *testing.T) {
	cache := AliasCache{
		Aliases: map[string]string{
			strings.ToLower(aliasTestAddress(1)): aliasTestAddress(2),
		},
	}

	got, err := cache.ResolveAddress(aliasTestAddress(1))
	if err != nil {
		t.Fatalf("ResolveAddress() error = %v", err)
	}
	if got != aliasTestAddress(2) {
		t.Fatalf("ResolveAddress() = %q, want alias target %q", got, aliasTestAddress(2))
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
