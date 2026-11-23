// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rest

import (
	"slices"
	"testing"

	"github.com/aplane-algo/aplane/internal/genstore/genstoretest"
	"github.com/aplane-algo/aplane/internal/keymgmt"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/keystore/keystoretest"
	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

const storeEnabledLibraryKeyType = "aplane.ed25519.v1"

// lockedRuntimeWithEnabledLibraryType builds a runtime over a store that
// enables a library key type, with the store locked and its paths unbound,
// as a signer that starts locked has them.
func lockedRuntimeWithEnabledLibraryType(t *testing.T, role noderole.Role) (*productruntime.Runtime, *keystore.FileKeyStore) {
	t.Helper()
	keyPaths := storepaths.NewPaths(t.TempDir())
	keyring, active := genstoretest.MintFirstAtomic(t, keyPaths, restTestPassphrase)
	keyring.Zero()
	if err := keytypestate.Put(genstoretest.BindActive(t, keyPaths, active), keytypestate.Record{
		KeyType: storeEnabledLibraryKeyType, Source: keytypestate.SourceCompiled, State: keytypestate.StateEnabled,
	}); err != nil {
		t.Fatalf("enable %s: %v", storeEnabledLibraryKeyType, err)
	}
	ks := keystore.NewAtomicFileKeyStoreForPaths(keyPaths)
	ir := productruntime.New(productruntime.Config{KeyStore: ks, KeyPaths: keyPaths, NodeRole: role})
	return ir, ks
}

func keyTypeNames(infos []signerapi.KeyTypeInfo) []string {
	names := make([]string, 0, len(infos))
	for _, info := range infos {
		names = append(names, info.KeyType)
	}
	slices.Sort(names)
	return names
}

// A locked signer cannot read the store's key type activations, and
// /keytypes (and the admin ListKeyTypes) answered 500 though the endpoint
// needs no unlock. It answers with the built-in key types for the node's
// role; what the store enables appears after unlock.
func TestKeyTypesWhileLockedListsTheBuiltInTypes(t *testing.T) {
	for _, role := range []noderole.Role{noderole.RoleSigner, noderole.RoleCosigner} {
		t.Run(string(role), func(t *testing.T) {
			ir, ks := lockedRuntimeWithEnabledLibraryType(t, role)

			resp, svcErr := Service{}.KeyTypes(ir)
			if svcErr != nil {
				t.Fatalf("KeyTypes(locked) error = %v", svcErr)
			}
			want := filterKeyTypesForNodeRole(keymgmt.GetValidKeyTypesWithActivated(nil), role)
			slices.Sort(want)
			if got := keyTypeNames(resp.KeyTypes); !slices.Equal(got, want) {
				t.Fatalf("KeyTypes(locked) = %v, want the built-in types %v", got, want)
			}
			if len(want) == 0 {
				t.Fatal("no built-in key types for the role; the test proves nothing")
			}

			if err := keystoretest.Unlock(ks, ir.KeyPaths(), restTestPassphrase); err != nil {
				t.Fatalf("Unlock(): %v", err)
			}
			resp, svcErr = Service{}.KeyTypes(ir)
			if svcErr != nil {
				t.Fatalf("KeyTypes(unlocked) error = %v", svcErr)
			}
			if role == noderole.RoleSigner && !keyTypesResponseContains(resp.KeyTypes, storeEnabledLibraryKeyType) {
				t.Fatalf("KeyTypes(unlocked) = %v, want the store-enabled %s", keyTypeNames(resp.KeyTypes), storeEnabledLibraryKeyType)
			}
		})
	}
}
