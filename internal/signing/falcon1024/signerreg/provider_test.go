// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerreg

import (
	"bytes"
	"testing"

	"github.com/algorand/falcon"
	"github.com/aplane-algo/aplane/internal/signing"
	nativefalcon "github.com/aplane-algo/aplane/internal/signing/falcon1024"
)

func TestProviderSignsAndZeros(t *testing.T) {
	seed := bytes.Repeat([]byte{7}, nativefalcon.RecoveryEntropySize)
	publicKey, privateKey, err := falcon.GenerateKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	provider := &Provider{}
	material, err := provider.LoadKeyMaterial(signing.ProviderKey{Type: nativefalcon.KeyType, PrivateKey: privateKey[:]})
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("native Falcon provider test")
	signature, err := provider.SignMessage(material, message)
	if err != nil {
		t.Fatal(err)
	}
	if err := publicKey.Verify(signature, message); err != nil {
		t.Fatalf("signature verification: %v", err)
	}
	provider.ZeroKey(material)
	if material.Value != nil || material.Type != "" {
		t.Fatal("ZeroKey() retained key material")
	}
}
