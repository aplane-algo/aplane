// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"net/http"
	"net/http/httptest"
	"testing"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"

	"github.com/aplane-algo/aplane/internal/crypto"
	apkeys "github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// /keys reports the valid_rekey_target each aplane key recorded when it was
// created; /keytypes reports the key type's declaration now. A generated
// ed25519 key records its type's true. A key record that says false reports
// false on /keys whatever its key type declares.
func TestInventoryReportsRecordedAndDeclaredValidRekeyTarget(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	generated := generateTestKey(t, server, "ed25519")

	recorded := algocrypto.GenerateAccount()
	if err := server.productRuntime().WithKeyring(func(kr *crypto.Keyring) error {
		payload := apkeys.NewEd25519Payload(recorded.PublicKey, recorded.PrivateKey)
		defer payload.ZeroSecrets()
		_, err := apkeys.SavePayload(mustActiveKeyPaths(t, server), payload, kr)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := reloadKeysForTest(server); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	server.handleKeys(w, requestWithIdentity(http.MethodGet, "/keys", nil))
	var keysResp signerapi.KeysResponse
	decodeResponse(t, w, &keysResp)
	got := map[string]bool{}
	for _, key := range keysResp.Keys {
		got[key.Address] = key.ValidRekeyTarget
	}
	if valid, ok := got[generated]; !ok || !valid {
		t.Fatalf("/keys valid_rekey_target for the generated ed25519 key = %v (listed %v), want true", valid, ok)
	}
	if valid, ok := got[recorded.Address.String()]; !ok || valid {
		t.Fatalf("/keys valid_rekey_target for the record that says false = %v (listed %v), want false", valid, ok)
	}

	w = httptest.NewRecorder()
	server.handleKeyTypes(w, requestWithIdentity(http.MethodGet, "/keytypes", nil))
	var typesResp signerapi.KeyTypesResponse
	decodeResponse(t, w, &typesResp)
	for _, info := range typesResp.KeyTypes {
		if info.KeyType == "ed25519" {
			if !info.ValidRekeyTarget {
				t.Fatal("/keytypes ed25519 valid_rekey_target = false, want its declaration true")
			}
			return
		}
	}
	t.Fatal("/keytypes does not list ed25519")
}
