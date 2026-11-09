// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rest

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// A plain host is listed only once enabled, as a per-key type that names its
// cosigner and takes no boundary file.
func TestKeyTypesListsAPlainHostOnceEnabled(t *testing.T) {
	ir := setupProductRuntime(t, false)
	listed := func() map[string]signerapi.KeyTypeInfo {
		t.Helper()
		resp, err := (Service{}).KeyTypes(ir)
		if err != nil {
			t.Fatal(err)
		}
		infos := map[string]signerapi.KeyTypeInfo{}
		for _, info := range resp.KeyTypes {
			infos[info.KeyType] = info
		}
		return infos
	}
	for _, keyType := range []string{"aplane.falcon1024.v1", "aplane.ed25519.v1"} {
		if _, ok := listed()[keyType]; ok {
			t.Fatalf("%s listed before it was enabled", keyType)
		}
		if err := keytypestate.Put(ir.KeyPaths(), keytypestate.Record{KeyType: keyType, Source: keytypestate.SourceCompiled, State: keytypestate.StateEnabled}); err != nil {
			t.Fatal(err)
		}
		info, ok := listed()[keyType]
		if !ok || !info.PerKeyContract || info.BoundarySchema != "" || info.CosignerComponentKeyType == "" || info.MnemonicImport {
			t.Fatalf("%s = %+v, %v", keyType, info, ok)
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
