// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keygen

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/algorand/falcon"
	"github.com/aplane-algo/aplane/internal/crypto/cryptotest"
	"github.com/aplane-algo/aplane/internal/keys"
	nativefalcon "github.com/aplane-algo/aplane/internal/signing/falcon1024"
)

var registerNativeValidatorForKeygenTestOnce sync.Once

func registerNativeValidatorForKeygenTest() {
	registerNativeValidatorForKeygenTestOnce.Do(func() {
		keys.RegisterNativePQKeyPairValidator(nativefalcon.Scheme, func(publicKey, privateKey []byte) error {
			var public falcon.PublicKey
			var private falcon.PrivateKey
			copy(public[:], publicKey)
			copy(private[:], privateKey)
			signature, err := private.SignCompressed([]byte("keygen-test"))
			if err != nil {
				return err
			}
			return public.Verify(signature, []byte("keygen-test"))
		})
	})
}

func TestNativeFalconGenerateAndRecover(t *testing.T) {
	registerNativeValidatorForKeygenTest()
	paths, cleanup := setupTestKeystore(t)
	defer cleanup()
	entropy := make([]byte, nativefalcon.RecoveryEntropySize)
	for i := range entropy {
		entropy[i] = byte(i)
	}
	gen := &NativeFalconGenerator{}
	result, err := gen.GenerateFromSeed(context.Background(), paths, entropy, cryptotest.Keyring(t, testMasterKey), nativefalcon.KeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	const expectedAddress = "XUCZPHDELTE5A76VAMSXKVISTYMWRBSPMRFLKWQCVYKWKMSVRVQUHGV2AA"
	if result.Address != expectedAddress {
		t.Fatalf("address = %s, want %s", result.Address, expectedAddress)
	}
	if result.Mnemonic != "" {
		t.Fatal("seed generation unexpectedly returned a mnemonic")
	}
}

func TestNativeFalconGenerateRandomReturnsRecoverableMnemonic(t *testing.T) {
	registerNativeValidatorForKeygenTest()
	paths, cleanup := setupTestKeystore(t)
	defer cleanup()
	gen := &NativeFalconGenerator{}
	result, err := gen.GenerateRandom(context.Background(), paths, cryptotest.Keyring(t, testMasterKey), nativefalcon.KeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(strings.Fields(result.Mnemonic)); got != nativefalcon.MnemonicWordCount {
		t.Fatalf("mnemonic words = %d, want %d", got, nativefalcon.MnemonicWordCount)
	}
}
