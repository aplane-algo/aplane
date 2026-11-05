// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rest

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/keytypestate"
)

func TestKeyTypesHidesInternalProvidersWithStaleEnablement(t *testing.T) {
	ir := setupProductRuntime(t, false)
	for _, keyType := range []string{"aplane.falcon1024.v1", "aplane.ed25519.v1"} {
		if err := keytypestate.Put(ir.KeyPaths(), keytypestate.Record{KeyType: keyType, Source: keytypestate.SourceCompiled, State: keytypestate.StateEnabled}); err != nil {
			t.Fatal(err)
		}
	}
	resp, err := (Service{}).KeyTypes(ir)
	if err != nil {
		t.Fatal(err)
	}
	for _, info := range resp.KeyTypes {
		if info.KeyType == "aplane.falcon1024.v1" || info.KeyType == "aplane.ed25519.v1" {
			t.Fatalf("internal provider %s exposed for generation", info.KeyType)
		}
	}
}

func TestKeysKeepsExistingInternalProviderAccounts(t *testing.T) {
	ir := setupProductRuntime(t, true)
	keyTypes := map[string]string{
		"existing-falcon-account":  "aplane.falcon1024.v1",
		"existing-ed25519-account": "aplane.ed25519.v1",
	}
	ir.PublishSnapshot(map[string]string{
		"existing-falcon-account":  "falcon.key",
		"existing-ed25519-account": "ed25519.key",
	}, keyTypes)
	resp, err := (Service{}).Keys(ir)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Count != len(keyTypes) {
		t.Fatalf("inventory has %d accounts, want %d", resp.Count, len(keyTypes))
	}
	for _, key := range resp.Keys {
		if key.KeyType != keyTypes[key.Address] {
			t.Fatalf("inventory changed existing account: %+v", key)
		}
	}
}
