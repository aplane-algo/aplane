// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keygen

import (
	"context"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto/cryptotest"
	apkeys "github.com/aplane-algo/aplane/internal/keys"
	nativeed25519 "github.com/aplane-algo/aplane/internal/signing/ed25519"
	nativefalcon "github.com/aplane-algo/aplane/internal/signing/falcon1024"
)

// A native aplane key records its key type's valid_rekey_target when it is
// created; both native key types declare true.
func TestNativeKeysRecordValidRekeyTarget(t *testing.T) {
	nativeed25519.RegisterClient()
	nativefalcon.RegisterClient()
	registerNativeValidatorForKeygenTest()
	paths, cleanup := setupTestKeystore(t)
	defer cleanup()
	kr := cryptotest.Keyring(t, testMasterKey)
	for _, tc := range []struct {
		keyType string
		gen     Generator
	}{
		{"ed25519", &Ed25519Generator{}},
		{nativefalcon.KeyType, &NativeFalconGenerator{}},
	} {
		result, err := tc.gen.GenerateRandom(context.Background(), paths, kr, tc.keyType, nil)
		if err != nil {
			t.Fatalf("%s: GenerateRandom() error = %v", tc.keyType, err)
		}
		keyJSON, err := apkeys.ReadDecryptedKeyJSONWithKeyring(result.KeyFiles.PrivateFile, kr)
		if err != nil {
			t.Fatal(err)
		}
		payload, err := apkeys.ParsePayload(keyJSON)
		if err != nil {
			t.Fatal(err)
		}
		payload.ZeroSecrets()
		if !payload.ValidRekeyTarget {
			t.Errorf("%s key recorded valid_rekey_target false, want its key type's true", tc.keyType)
		}
	}
}
