// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package clientstate

import "testing"

func TestCacheChangesMarkFile(t *testing.T) {
	var changes CacheChanges
	for _, name := range []string{
		"alias_cache.json",
		"set_cache.json",
		"signer_cache.json",
		"testnet_asa_cache.json",
		"voi_mainnet_auth_cache.json",
	} {
		if !changes.markFile(name) {
			t.Fatalf("markFile(%q) = false, want true", name)
		}
	}

	if changes.Empty() {
		t.Fatal("changes.Empty() = true, want false")
	}
	if !changes.Alias || !changes.Set || !changes.Signer {
		t.Fatalf("common cache flags = alias:%v set:%v signer:%v, want all true", changes.Alias, changes.Set, changes.Signer)
	}
	if !changes.ASA["testnet"] {
		t.Fatalf("ASA changes = %#v, want testnet", changes.ASA)
	}
	if !changes.Auth["voi_mainnet"] {
		t.Fatalf("Auth changes = %#v, want voi_mainnet", changes.Auth)
	}
}

func TestCacheChangesIgnoreTempAndUnknownFiles(t *testing.T) {
	var changes CacheChanges
	for _, name := range []string{
		".cache_key",
		"alias_cache.json.tmp-123",
		"testnet_asa_cache.json.tmp-123",
		"not_a_cache.json",
		"_asa_cache.json",
	} {
		if changes.markFile(name) {
			t.Fatalf("markFile(%q) = true, want false", name)
		}
	}
	if !changes.Empty() {
		t.Fatalf("changes = %#v, want empty", changes)
	}
}
