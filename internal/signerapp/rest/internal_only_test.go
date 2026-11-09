// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rest

import (
	"github.com/aplane-algo/aplane/internal/boundary"
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
	// The Falcon plain host is default-enabled; the Ed25519 one is opt-in.
	plainHost := func(keyType string, info signerapi.KeyTypeInfo, ok bool) {
		t.Helper()
		if !ok || !info.PerKeyContract || info.BoundarySchema != boundary.SchemaV1 || info.CosignerComponentKeyType == "" || info.MnemonicImport {
			t.Fatalf("%s = %+v, %v", keyType, info, ok)
		}
	}
	info, ok := listed()["aplane.falcon1024.v1"]
	plainHost("aplane.falcon1024.v1", info, ok)
	if _, ok := listed()["aplane.ed25519.v1"]; ok {
		t.Fatal("aplane.ed25519.v1 listed before it was enabled")
	}
	if err := keytypestate.Put(ir.KeyPaths(), keytypestate.Record{KeyType: "aplane.ed25519.v1", Source: keytypestate.SourceCompiled, State: keytypestate.StateEnabled}); err != nil {
		t.Fatal(err)
	}
	info, ok = listed()["aplane.ed25519.v1"]
	plainHost("aplane.ed25519.v1", info, ok)
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
