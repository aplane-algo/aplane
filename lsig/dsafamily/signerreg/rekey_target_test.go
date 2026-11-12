// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerreg

import (
	"context"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto/cryptotest"
	apkeys "github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/lsig/clientreg"
)

// A DSA LogicSig aplane key records its key type's valid_rekey_target when it
// is created: true for the Falcon plain host.
func TestDSALogicSigKeyRecordsValidRekeyTarget(t *testing.T) {
	clientreg.RegisterClient()
	paths, cleanup := setupTestKeystore(t)
	defer cleanup()
	kr := cryptotest.Keyring(t, testMasterKey)
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i + 7)
	}
	result, err := newTestGenerator().GenerateFromSeed(context.Background(), paths, seed, kr, "aplane.falcon1024.v1", nil)
	if err != nil {
		t.Fatalf("GenerateFromSeed() error = %v", err)
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
		t.Fatal("aplane.falcon1024.v1 key recorded valid_rekey_target false, want its key type's true")
	}
}
